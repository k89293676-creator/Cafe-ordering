"""Payment provider integrations for owner-managed billing.

Owners configure their own payment gateway credentials (Stripe, Razorpay)
through the ``/owner/billing/payment-methods`` screen. Credentials are
encrypted at rest with Fernet (key derived from ``BILLING_ENCRYPTION_KEY``
or, as a fallback, the Flask ``SECRET_KEY``) so a database leak does not
expose live API keys in plaintext.

Design goals
------------

* **Pluggable** — every provider implements the same ``PaymentProvider``
  interface so routes don't branch on provider type.
* **Safe defaults** — unknown providers raise; missing credentials raise;
  test-mode keys are detected and surfaced to the UI so an owner cannot
  accidentally process live money in development.
* **Webhook integrity** — every provider verifies the incoming signature
  before we mutate any order. A failed verification returns 400 with no
  side effects.
* **No I/O at import time** — the heavy SDKs (``stripe``, ``razorpay``)
  are imported lazily so the app boots even if a particular provider
  is not installed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("stripe", "razorpay")
PROVIDER_LABELS = {"stripe": "Stripe", "razorpay": "Razorpay"}


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte url-safe-base64 Fernet key from any string secret.

    Fernet requires a 32-byte url-safe-base64-encoded key. We derive one
    deterministically from the configured secret so rotating the underlying
    secret simultaneously rotates the encryption key (decrypt fails loudly
    instead of silently returning garbage)."""
    if not secret:
        raise RuntimeError(
            "BILLING_ENCRYPTION_KEY (or SECRET_KEY) must be set to encrypt "
            "payment credentials."
        )
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet():
    from cryptography.fernet import Fernet  # local import keeps boot fast
    secret = os.environ.get("BILLING_ENCRYPTION_KEY") or os.environ.get("SECRET_KEY") or ""
    return Fernet(_derive_fernet_key(secret))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret for storage. Returns a url-safe-base64 token."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as exc:  # pragma: no cover — operational
        log.error("Failed to decrypt payment secret: %s", exc)
        raise RuntimeError(
            "Could not decrypt stored payment credential. "
            "Has BILLING_ENCRYPTION_KEY changed since it was saved?"
        ) from exc


def mask_secret(plaintext: str) -> str:
    """Public-safe representation of a key (last 4 chars only)."""
    if not plaintext:
        return ""
    s = plaintext.strip()
    if len(s) <= 8:
        return "•" * len(s)
    return f"{s[:4]}{'•' * (len(s) - 8)}{s[-4:]}"


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

@dataclass
class PaymentIntent:
    """Result of asking a provider to start a payment.

    ``client_secret`` is the value the customer-facing JS SDK needs.
    ``checkout_url`` is the hosted-page fallback for providers that
    prefer a redirect (or for headless/SMS flows)."""
    intent_id: str
    client_secret: str = ""
    checkout_url: str = ""
    amount_minor: int = 0
    currency: str = "INR"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookEvent:
    event_type: str
    intent_id: str
    status: str  # one of: succeeded, failed, pending, refunded, cancelled
    amount_minor: int = 0
    currency: str = "INR"
    raw: dict[str, Any] = field(default_factory=dict)


class PaymentProviderError(Exception):
    """Raised for any provider-side failure. Routes catch this and surface
    a friendly message instead of a 500."""


class PaymentProvider:
    name: str = ""
    public_key_label: str = "Publishable Key"
    secret_key_label: str = "Secret Key"
    webhook_secret_label: str = "Webhook Signing Secret"

    def __init__(self, public_key: str, secret_key: str, webhook_secret: str = "",
                 mode: str = "test"):
        self.public_key = (public_key or "").strip()
        self.secret_key = (secret_key or "").strip()
        self.webhook_secret = (webhook_secret or "").strip()
        self.mode = mode if mode in ("test", "live") else "test"

    # Subclasses implement -------------------------------------------------
    def test_connection(self) -> str:
        raise NotImplementedError

    def create_payment_intent(self, *, amount_minor: int, currency: str,
                              order_id: int, description: str,
                              customer_email: str = "",
                              customer_phone: str = "",
                              return_url: str = "") -> PaymentIntent:
        raise NotImplementedError

    def parse_webhook(self, payload_bytes: bytes, signature_header: str) -> WebhookEvent:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------

class StripeProvider(PaymentProvider):
    name = "stripe"
    public_key_label = "Publishable Key (pk_…)"
    secret_key_label = "Secret Key (sk_…)"
    webhook_secret_label = "Webhook Signing Secret (whsec_…)"

    def _client(self):
        try:
            import stripe  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise PaymentProviderError(
                "Stripe SDK is not installed on the server."
            ) from exc
        if not self.secret_key:
            raise PaymentProviderError("Stripe secret key is not configured.")
        stripe.api_key = self.secret_key
        return stripe

    def test_connection(self) -> str:
        stripe = self._client()
        try:
            acct = stripe.Account.retrieve()
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Stripe rejected the credentials: {exc}") from exc
        label = acct.get("business_profile", {}).get("name") or acct.get("email") or acct.get("id")
        return f"Connected to Stripe account: {label}"

    def create_payment_intent(self, *, amount_minor, currency, order_id, description,
                              customer_email="", customer_phone="", return_url=""):
        stripe = self._client()
        try:
            pi = stripe.PaymentIntent.create(
                amount=int(amount_minor),
                currency=(currency or "inr").lower(),
                description=description[:500],
                metadata={
                    "order_id": str(order_id),
                    "customer_email": customer_email[:128],
                    "customer_phone": customer_phone[:32],
                },
                automatic_payment_methods={"enabled": True},
            )
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Stripe could not create the payment: {exc}") from exc
        return PaymentIntent(
            intent_id=pi["id"],
            client_secret=pi.get("client_secret", ""),
            amount_minor=int(amount_minor),
            currency=currency,
            raw={"status": pi.get("status")},
        )

    def parse_webhook(self, payload_bytes, signature_header):
        stripe = self._client()
        if not self.webhook_secret:
            raise PaymentProviderError("Webhook secret not configured for Stripe.")
        try:
            event = stripe.Webhook.construct_event(
                payload_bytes, signature_header or "", self.webhook_secret,
            )
        except Exception as exc:  # noqa: BLE001 — covers SignatureVerificationError
            raise PaymentProviderError(f"Stripe webhook signature invalid: {exc}") from exc
        etype = event.get("type", "")
        obj = event.get("data", {}).get("object", {}) or {}
        intent_id = obj.get("id", "") or obj.get("payment_intent", "")
        status_map = {
            "payment_intent.succeeded": "succeeded",
            "payment_intent.payment_failed": "failed",
            "payment_intent.canceled": "cancelled",
            "charge.refunded": "refunded",
        }
        status = status_map.get(etype, "pending")
        return WebhookEvent(
            event_type=etype,
            intent_id=intent_id,
            status=status,
            amount_minor=int(obj.get("amount", 0) or 0),
            currency=(obj.get("currency") or "inr").upper(),
            raw=obj,
        )


# ---------------------------------------------------------------------------
# Razorpay
# ---------------------------------------------------------------------------

class RazorpayProvider(PaymentProvider):
    name = "razorpay"
    public_key_label = "Key ID (rzp_…)"
    secret_key_label = "Key Secret"
    webhook_secret_label = "Webhook Secret"

    def _client(self):
        try:
            import razorpay  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise PaymentProviderError(
                "Razorpay SDK is not installed on the server."
            ) from exc
        if not self.public_key or not self.secret_key:
            raise PaymentProviderError("Razorpay key id and secret are required.")
        return razorpay.Client(auth=(self.public_key, self.secret_key))

    def test_connection(self) -> str:
        client = self._client()
        try:
            # Cheapest authenticated read available: list 1 payment.
            client.payment.all({"count": 1})
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Razorpay rejected the credentials: {exc}") from exc
        kind = "live" if self.public_key.startswith("rzp_live_") else "test"
        return f"Connected to Razorpay ({kind} mode, key {mask_secret(self.public_key)})."

    def create_payment_intent(self, *, amount_minor, currency, order_id, description,
                              customer_email="", customer_phone="", return_url=""):
        client = self._client()
        try:
            order = client.order.create({
                "amount": int(amount_minor),
                "currency": (currency or "INR").upper(),
                "receipt": f"order_{order_id}",
                "notes": {
                    "order_id": str(order_id),
                    "customer_email": customer_email[:128],
                    "customer_phone": customer_phone[:32],
                    "description": description[:200],
                },
            })
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Razorpay could not create the order: {exc}") from exc
        return PaymentIntent(
            intent_id=order["id"],
            client_secret="",  # Razorpay uses key_id + order_id on the client
            amount_minor=int(amount_minor),
            currency=currency,
            raw={"status": order.get("status"), "key_id": self.public_key},
        )

    def parse_webhook(self, payload_bytes, signature_header):
        if not self.webhook_secret:
            raise PaymentProviderError("Webhook secret not configured for Razorpay.")
        expected = hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, (signature_header or "").strip()):
            raise PaymentProviderError("Razorpay webhook signature invalid.")
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise PaymentProviderError(f"Razorpay webhook payload not JSON: {exc}") from exc
        etype = event.get("event", "")
        payload = event.get("payload", {}) or {}
        payment = (payload.get("payment", {}) or {}).get("entity", {}) or {}
        rzp_order = (payload.get("order", {}) or {}).get("entity", {}) or {}
        intent_id = payment.get("order_id") or rzp_order.get("id") or ""
        status_map = {
            "payment.captured": "succeeded",
            "payment.authorized": "pending",
            "payment.failed": "failed",
            "refund.processed": "refunded",
            "order.paid": "succeeded",
        }
        status = status_map.get(etype, "pending")
        return WebhookEvent(
            event_type=etype,
            intent_id=intent_id,
            status=status,
            amount_minor=int(payment.get("amount") or rzp_order.get("amount") or 0),
            currency=(payment.get("currency") or rzp_order.get("currency") or "INR").upper(),
            raw=event,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "stripe": StripeProvider,
    "razorpay": RazorpayProvider,
}


def build_provider(provider_name: str, *, public_key: str, secret_key: str,
                   webhook_secret: str = "", mode: str = "test") -> PaymentProvider:
    cls = _PROVIDERS.get((provider_name or "").lower())
    if not cls:
        raise PaymentProviderError(
            f"Unsupported payment provider: {provider_name!r}. "
            f"Supported: {', '.join(SUPPORTED_PROVIDERS)}."
        )
    return cls(public_key=public_key, secret_key=secret_key,
               webhook_secret=webhook_secret, mode=mode)


def detect_mode_from_key(provider_name: str, public_key: str, secret_key: str) -> str:
    """Best-effort guess at whether the keys are test- or live-mode.

    Used purely to surface a warning in the UI so an owner doesn't
    process live charges with what they think are test keys."""
    sk = (secret_key or "").lower()
    pk = (public_key or "").lower()
    if provider_name == "stripe":
        if sk.startswith("sk_live_") or pk.startswith("pk_live_"):
            return "live"
        if sk.startswith("sk_test_") or pk.startswith("pk_test_"):
            return "test"
    if provider_name == "razorpay":
        if pk.startswith("rzp_live_"):
            return "live"
        if pk.startswith("rzp_test_"):
            return "test"
    return "unknown"
