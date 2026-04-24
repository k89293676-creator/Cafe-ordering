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

SUPPORTED_PROVIDERS = ("stripe", "razorpay", "cashfree")
PROVIDER_LABELS = {"stripe": "Stripe", "razorpay": "Razorpay", "cashfree": "Cashfree"}

# UI-facing setup guidance per provider — keeps the template free of
# vendor-specific copy and lets ops update instructions without touching
# Jinja. Steps render as an ordered list on /owner/billing/payment-methods.
PROVIDER_GUIDES: dict[str, dict] = {
    "stripe": {
        "summary": "Cards, Apple Pay, Google Pay. Best for international.",
        "dashboard_url": "https://dashboard.stripe.com/apikeys",
        "webhook_url": "https://dashboard.stripe.com/webhooks",
        "key_id_label": "Publishable Key (pk_…)",
        "secret_label": "Secret Key (sk_…)",
        "events": ["payment_intent.succeeded", "payment_intent.payment_failed", "charge.refunded"],
        "steps": [
            "Open the Stripe API keys page and copy your Publishable and Secret keys.",
            "Paste them below, choose Test or Live mode, and click Verify & Save.",
            "Once verified, copy the Webhook URL shown for this provider.",
            "In Stripe → Developers → Webhooks, add an endpoint with that URL and subscribe to the listed events.",
            "Copy the resulting signing secret (whsec_…) back into the Webhook Secret field and save again.",
        ],
    },
    "razorpay": {
        "summary": "UPI, cards, netbanking, wallets. Default for India.",
        "dashboard_url": "https://dashboard.razorpay.com/app/website-app-settings/api-keys",
        "webhook_url": "https://dashboard.razorpay.com/app/webhooks",
        "key_id_label": "Key ID (rzp_…)",
        "secret_label": "Key Secret",
        "events": ["payment.captured", "payment.failed", "refund.processed", "order.paid"],
        "steps": [
            "In Razorpay → Settings → API Keys, generate a new key pair and copy both values.",
            "Paste them below, pick Test (rzp_test_) or Live (rzp_live_) mode, and click Verify & Save.",
            "After verification, copy the Webhook URL shown for this provider.",
            "Open Settings → Webhooks → Add new webhook, paste the URL, enter your own secret, and tick the listed events.",
            "Paste that same secret back into the Webhook Secret field here and save again.",
        ],
    },
    "cashfree": {
        "summary": "UPI, cards, netbanking. Lower fees in India for high volume.",
        "dashboard_url": "https://merchant.cashfree.com/merchants/pg/developers/keys",
        "webhook_url": "https://merchant.cashfree.com/merchants/pg/developers/webhooks",
        "key_id_label": "App ID",
        "secret_label": "Secret Key",
        "events": ["PAYMENT_SUCCESS_WEBHOOK", "PAYMENT_FAILED_WEBHOOK", "REFUND_STATUS_WEBHOOK"],
        "steps": [
            "In Cashfree Dashboard → Developers → API Keys, copy your App ID and Secret.",
            "Choose Sandbox (TEST) or Production (LIVE) and click Verify & Save below.",
            "After verification, copy the Webhook URL shown for this provider.",
            "Add it under Developers → Webhooks; Cashfree will display the signing secret only once.",
            "Paste that secret into the Webhook Secret field here and save again.",
        ],
    },
}


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

    def fetch_payment_status(self, intent_id: str) -> WebhookEvent:
        """Re-fetch an intent's authoritative status directly from the PSP.

        Used by the reconciliation pipeline to recover from missed/late
        webhooks: if a row sits in 'pending' for too long, we ask the
        provider for ground truth and update locally. Subclasses must
        return a WebhookEvent with the same status vocabulary as
        parse_webhook (succeeded / failed / cancelled / refunded /
        pending / processing).
        """
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
        """Create a Stripe Checkout Session.

        We use Checkout Sessions instead of bare PaymentIntents because:
        * Stripe hosts the entire payment UI — no PCI scope on our side.
        * Apple Pay / Google Pay / Link work automatically.
        * The customer just clicks a link; no SDK code on our page.
        * The same session URL works on desktop and mobile.

        The session id (cs_…) is the canonical ``intent_id`` we store and
        match webhooks against.
        """
        stripe = self._client()
        success_url = return_url or "https://example.com/success"
        # Stripe requires the literal {CHECKOUT_SESSION_ID} placeholder so
        # the success page can confirm exactly which session paid.
        if "{CHECKOUT_SESSION_ID}" not in success_url:
            sep = "&" if "?" in success_url else "?"
            success_url = f"{success_url}{sep}session_id={{CHECKOUT_SESSION_ID}}"
        try:
            session = stripe.checkout.Session.create(
                mode="payment",
                payment_method_types=["card"],
                line_items=[{
                    "price_data": {
                        "currency": (currency or "inr").lower(),
                        "product_data": {"name": description[:120] or f"Order #{order_id}"},
                        "unit_amount": int(amount_minor),
                    },
                    "quantity": 1,
                }],
                success_url=success_url,
                cancel_url=return_url or success_url,
                customer_email=customer_email[:128] or None,
                client_reference_id=str(order_id),
                metadata={
                    "order_id": str(order_id),
                    "customer_phone": customer_phone[:32],
                },
                payment_intent_data={
                    "description": description[:500],
                    "metadata": {"order_id": str(order_id)},
                },
            )
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Stripe could not create the payment: {exc}") from exc
        return PaymentIntent(
            intent_id=session["id"],
            client_secret="",  # Checkout Sessions don't expose a client_secret.
            checkout_url=session.get("url", "") or "",
            amount_minor=int(amount_minor),
            currency=currency,
            raw={"status": session.get("status"),
                 "payment_status": session.get("payment_status"),
                 "payment_intent": session.get("payment_intent")},
        )

    def fetch_payment_status(self, intent_id: str) -> WebhookEvent:
        """Authoritative status lookup. Handles both Checkout Session ids
        (cs_…) and bare PaymentIntent ids (pi_…) so legacy rows created
        before the Checkout Session migration still reconcile correctly."""
        stripe = self._client()
        if intent_id.startswith("cs_"):
            try:
                obj = stripe.checkout.Session.retrieve(intent_id)
            except Exception as exc:  # noqa: BLE001
                raise PaymentProviderError(
                    f"Stripe could not fetch session {intent_id}: {exc}") from exc
            payment_status = (obj.get("payment_status") or "").lower()
            session_status = (obj.get("status") or "").lower()
            if payment_status == "paid":
                status = "succeeded"
            elif session_status == "expired":
                status = "failed"
            elif session_status == "complete":
                status = "succeeded"
            elif payment_status == "unpaid" and session_status == "open":
                status = "pending"
            else:
                status = "pending"
            return WebhookEvent(
                event_type=f"checkout.session.{session_status or 'unknown'}",
                intent_id=obj.get("id", intent_id),
                status=status,
                amount_minor=int(obj.get("amount_total", 0) or 0),
                currency=(obj.get("currency") or "inr").upper(),
                raw=dict(obj),
            )
        try:
            pi = stripe.PaymentIntent.retrieve(intent_id)
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(
                f"Stripe could not fetch intent {intent_id}: {exc}") from exc
        status_map = {
            "succeeded": "succeeded",
            "canceled": "cancelled",
            "requires_payment_method": "failed",
            "processing": "processing",
            "requires_action": "pending",
            "requires_confirmation": "pending",
            "requires_capture": "pending",
        }
        status = status_map.get(pi.get("status", ""), "pending")
        return WebhookEvent(
            event_type=f"payment_intent.{pi.get('status', '')}",
            intent_id=pi.get("id", intent_id),
            status=status,
            amount_minor=int(pi.get("amount", 0) or 0),
            currency=(pi.get("currency") or "inr").upper(),
            raw=dict(pi),
        )

    def parse_webhook(self, payload_bytes, signature_header):
        """Parse + signature-verify a Stripe webhook.

        Handles both the Checkout Session lifecycle (preferred since we
        switched ``create_payment_intent`` to sessions) and bare
        PaymentIntent events (still emitted for sessions but pointing
        at the underlying intent — and used by legacy rows). We always
        report the *session id* as ``intent_id`` when we recognise a
        session-scoped event so the OnlinePayment lookup in the route
        finds the row we created in ``create_payment_intent``.
        """
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

        # Checkout Session events come first because they're the primary
        # lifecycle signal for hosted-checkout payments.
        if etype.startswith("checkout.session."):
            payment_status = (obj.get("payment_status") or "").lower()
            session_status = (obj.get("status") or "").lower()
            if etype == "checkout.session.completed":
                # ``complete`` + payment_status=paid → success. For async
                # payments (e.g. bank debit) payment_status is 'unpaid'
                # initially and resolves via async_payment_succeeded.
                status = "succeeded" if payment_status == "paid" else "pending"
            elif etype == "checkout.session.async_payment_succeeded":
                status = "succeeded"
            elif etype == "checkout.session.async_payment_failed":
                status = "failed"
            elif etype == "checkout.session.expired":
                status = "failed"
            else:
                status = "pending" if session_status != "complete" else "succeeded"
            return WebhookEvent(
                event_type=etype,
                intent_id=obj.get("id", ""),  # cs_…
                status=status,
                amount_minor=int(obj.get("amount_total", 0) or 0),
                currency=(obj.get("currency") or "inr").upper(),
                raw=obj,
            )

        # PaymentIntent / charge events — legacy and refund flows.
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

    def fetch_payment_status(self, intent_id: str) -> WebhookEvent:
        client = self._client()
        try:
            order = client.order.fetch(intent_id)
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(
                f"Razorpay could not fetch order {intent_id}: {exc}") from exc
        # status: created | attempted | paid
        status_map = {"paid": "succeeded", "attempted": "pending",
                      "created": "pending"}
        status = status_map.get(order.get("status", ""), "pending")
        return WebhookEvent(
            event_type=f"order.{order.get('status', '')}",
            intent_id=order.get("id", intent_id),
            status=status,
            amount_minor=int(order.get("amount", 0) or 0),
            currency=(order.get("currency") or "INR").upper(),
            raw=dict(order),
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

class CashfreeProvider(PaymentProvider):
    """Cashfree Payment Gateway (PG v3 REST API).

    No SDK dependency — Cashfree's REST surface is small enough that
    using ``requests`` keeps the dependency footprint smaller and avoids
    pulling in their full PG SDK on the server."""

    name = "cashfree"
    public_key_label = "App ID"
    secret_key_label = "Secret Key"
    webhook_secret_label = "Webhook Secret"

    def _base_url(self) -> str:
        return ("https://api.cashfree.com/pg" if self.mode == "live"
                else "https://sandbox.cashfree.com/pg")

    def _headers(self) -> dict:
        if not self.public_key or not self.secret_key:
            raise PaymentProviderError("Cashfree App ID and Secret Key are required.")
        return {
            "x-api-version": "2023-08-01",
            "x-client-id": self.public_key,
            "x-client-secret": self.secret_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> str:
        import requests  # local import — requests is already in the stack
        try:
            # Cheapest authenticated probe: fetch a clearly-bogus order id;
            # auth failure returns 401, missing-resource returns 404 — both
            # mean the credentials parsed correctly.
            r = requests.get(f"{self._base_url()}/orders/__healthcheck__",
                             headers=self._headers(), timeout=10)
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Could not reach Cashfree: {exc}") from exc
        if r.status_code == 401:
            raise PaymentProviderError("Cashfree rejected the App ID / Secret pair.")
        if r.status_code in (200, 404):
            return f"Connected to Cashfree ({self.mode} mode)."
        raise PaymentProviderError(
            f"Cashfree returned HTTP {r.status_code}: {r.text[:200]}"
        )

    def create_payment_intent(self, *, amount_minor, currency, order_id, description,
                              customer_email="", customer_phone="", return_url=""):
        import requests
        # Cashfree expects amounts in major units, not paise.
        amount_major = round(int(amount_minor) / 100.0, 2)
        payload = {
            "order_id": f"order_{order_id}_{int(amount_minor)}",
            "order_amount": amount_major,
            "order_currency": (currency or "INR").upper(),
            "order_note": description[:200],
            "customer_details": {
                "customer_id": f"cust_{order_id}",
                "customer_phone": (customer_phone or "9999999999")[:15],
                "customer_email": customer_email[:128] or "guest@example.com",
            },
            "order_meta": {
                "return_url": return_url,
                "notify_url": "",
            },
        }
        try:
            r = requests.post(f"{self._base_url()}/orders",
                              json=payload, headers=self._headers(), timeout=15)
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(f"Cashfree request failed: {exc}") from exc
        if r.status_code >= 400:
            raise PaymentProviderError(
                f"Cashfree could not create the order ({r.status_code}): {r.text[:300]}"
            )
        data = r.json()
        return PaymentIntent(
            intent_id=data.get("order_id", payload["order_id"]),
            client_secret=data.get("payment_session_id", ""),
            checkout_url=data.get("payment_link", ""),
            amount_minor=int(amount_minor),
            currency=currency,
            raw=data,
        )

    def fetch_payment_status(self, intent_id: str) -> WebhookEvent:
        import requests
        try:
            r = requests.get(
                f"{self._base_url()}/orders/{intent_id}",
                headers=self._headers(), timeout=10,
            )
        except Exception as exc:  # noqa: BLE001
            raise PaymentProviderError(
                f"Cashfree could not fetch order {intent_id}: {exc}") from exc
        if r.status_code == 404:
            return WebhookEvent(event_type="order.not_found", intent_id=intent_id,
                                status="failed", amount_minor=0, currency="INR",
                                raw={"http_status": 404})
        if r.status_code >= 400:
            raise PaymentProviderError(
                f"Cashfree fetch failed ({r.status_code}): {r.text[:200]}")
        data = r.json() or {}
        status_map = {"PAID": "succeeded", "ACTIVE": "pending",
                      "EXPIRED": "failed", "CANCELLED": "cancelled",
                      "TERMINATED": "failed"}
        status = status_map.get((data.get("order_status") or "").upper(), "pending")
        amount_minor = int(round(float(data.get("order_amount", 0) or 0) * 100))
        return WebhookEvent(
            event_type=f"order.{data.get('order_status', '')}",
            intent_id=data.get("order_id", intent_id),
            status=status, amount_minor=amount_minor,
            currency=(data.get("order_currency") or "INR").upper(),
            raw=data,
        )

    def parse_webhook(self, payload_bytes, signature_header):
        if not self.webhook_secret:
            raise PaymentProviderError("Webhook secret not configured for Cashfree.")
        # Cashfree v3: signature = base64(HMAC-SHA256(secret, timestamp + raw_body))
        timestamp = (signature_header.split(",", 1)[0]
                     if signature_header and "," in signature_header else "")
        sig = signature_header.split(",", 1)[1] if "," in (signature_header or "") else (signature_header or "")
        signed = (timestamp + payload_bytes.decode("utf-8", errors="replace")).encode("utf-8")
        expected = base64.b64encode(
            hmac.new(self.webhook_secret.encode("utf-8"), signed, hashlib.sha256).digest()
        ).decode("ascii")
        if not hmac.compare_digest(expected, sig.strip()):
            raise PaymentProviderError("Cashfree webhook signature invalid.")
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise PaymentProviderError(f"Cashfree webhook payload not JSON: {exc}") from exc
        etype = event.get("type", "")
        data = event.get("data", {}) or {}
        order = data.get("order", {}) or {}
        payment = data.get("payment", {}) or {}
        status_map = {
            "PAYMENT_SUCCESS_WEBHOOK": "succeeded",
            "PAYMENT_FAILED_WEBHOOK": "failed",
            "PAYMENT_USER_DROPPED_WEBHOOK": "cancelled",
            "REFUND_STATUS_WEBHOOK": "refunded",
        }
        status = status_map.get(etype, "pending")
        amount_major = float(payment.get("payment_amount") or order.get("order_amount") or 0)
        return WebhookEvent(
            event_type=etype,
            intent_id=order.get("order_id", "") or payment.get("cf_payment_id", ""),
            status=status,
            amount_minor=int(round(amount_major * 100)),
            currency=(order.get("order_currency") or "INR").upper(),
            raw=event,
        )


_PROVIDERS = {
    "stripe": StripeProvider,
    "razorpay": RazorpayProvider,
    "cashfree": CashfreeProvider,
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
    if provider_name == "cashfree":
        # Cashfree app IDs frequently end with "TEST" or contain it.
        if "test" in pk or "sandbox" in pk:
            return "test"
        if pk and "test" not in pk:
            return "live"
    return "unknown"
