"""Food-aggregator integration framework (Swiggy, Zomato, Uber Eats).

The actual partner APIs (``Swiggy POS Integration`` and ``Zomato POS
Integration``) require a signed merchant agreement and are not openly
published, so the providers here implement the documented webhook
*payload shapes* and the documented merchant-side acknowledgement
endpoints. Owners paste the partner-issued credentials, and the
aggregator pushes orders to our ``/aggregators/webhook/<platform>``
URL — exactly the pattern Swiggy/Zomato use for every other POS.

Design mirrors ``lib_payments``:

* ``AggregatorPlatform`` — abstract base with ``test_connection``,
  ``parse_webhook`` (signature-verified) and ``acknowledge_order``.
* Concrete providers: ``SwiggyPlatform``, ``ZomatoPlatform``,
  ``UberEatsPlatform``.
* ``build_aggregator(name, ...)`` factory.
* ``PLATFORM_GUIDES`` — UI copy and dashboard links per platform.

Webhook signatures use HMAC-SHA256 of the raw body with the partner's
secret. We refuse signatures whose timestamp is older than five
minutes to neutralise replay attacks.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

SUPPORTED_PLATFORMS = ("swiggy", "zomato", "ubereats")
PLATFORM_LABELS = {
    "swiggy": "Swiggy",
    "zomato": "Zomato",
    "ubereats": "Uber Eats",
}

# Replay-protection window — events older than this are rejected even
# if the signature is valid, in case a partner key is briefly leaked.
REPLAY_WINDOW_SECONDS = 5 * 60

PLATFORM_GUIDES: dict[str, dict] = {
    "swiggy": {
        "summary": "India's largest food-delivery aggregator. Push-based POS integration.",
        "dashboard_url": "https://partner.swiggy.com",
        "credential_label": "Partner API key",
        "secret_label": "Partner secret",
        "merchant_id_label": "Restaurant ID",
        "events": ["NEW_ORDER", "ORDER_CANCELLED", "ORDER_EDIT", "RIDER_ASSIGNED"],
        "steps": [
            "In Swiggy Partner Dashboard, request POS API access for your restaurant.",
            "Once approved, copy your Restaurant ID, API key and signing secret.",
            "Paste them below and click Verify & Save.",
            "Share your Webhook URL (shown after saving) with Swiggy partner support so they enable push delivery.",
            "Place a test order from staging — it should appear under Aggregator Orders here within seconds.",
        ],
    },
    "zomato": {
        "summary": "Zomato POS Integration — receives orders, accepts/rejects via API.",
        "dashboard_url": "https://www.zomato.com/business",
        "credential_label": "Client ID",
        "secret_label": "Client secret",
        "merchant_id_label": "Outlet ID (res_id)",
        "events": ["new_order", "order_cancellation", "rider_assigned", "order_status_update"],
        "steps": [
            "Email pos-integration@zomato.com to request a sandbox merchant onboarding.",
            "Zomato will issue a Client ID, Client Secret and your Outlet (res_id).",
            "Paste them below and click Verify & Save.",
            "Send the Webhook URL shown here back to your Zomato integration manager.",
            "Use Zomato's order-injection sandbox to push a test order and confirm it lands here.",
        ],
    },
    "ubereats": {
        "summary": "Uber Eats Marketplace API. OAuth client-credentials with webhook events.",
        "dashboard_url": "https://developer.uber.com/dashboard",
        "credential_label": "Client ID",
        "secret_label": "Client secret",
        "merchant_id_label": "Store UUID",
        "events": ["orders.notification", "orders.cancel", "orders.scheduled.notification"],
        "steps": [
            "In Uber Developer Dashboard, create an Eats Marketplace app.",
            "Add the eats.store and eats.order scopes and obtain Client ID / Secret.",
            "Paste them below along with the Store UUID provided by Uber.",
            "Configure the webhook URL shown here under Webhooks → Add Endpoint.",
            "Verify with Uber's sandbox order-trigger tool.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AggregatorOrderEvent:
    """Normalised representation of any incoming aggregator event.

    The webhook handler turns the platform-specific payload into this
    uniform shape so the rest of the application doesn't need to know
    which aggregator the order came from."""
    event_type: str           # "new_order" | "cancelled" | "edited" | "rider_assigned" | "status_update"
    external_order_id: str    # platform-side ID (used for dedupe + ack)
    status: str               # "placed" | "cancelled" | "edited" | "ready" | "delivered" | "rejected"
    customer_name: str = ""
    customer_phone: str = ""
    items: list[dict] = field(default_factory=list)  # [{"name", "qty", "price_minor", "notes"}]
    subtotal_minor: int = 0   # in paise/cents
    total_minor: int = 0
    currency: str = "INR"
    pickup_eta_minutes: int = 0
    rider_name: str = ""
    rider_phone: str = ""
    notes: str = ""
    raw: dict = field(default_factory=dict)


class AggregatorError(Exception):
    """Any platform-side or signature failure."""


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class AggregatorPlatform:
    """Abstract base — concrete platforms implement the four hooks below."""

    name = "base"
    credential_label = "API key"
    secret_label = "Secret"
    merchant_id_label = "Merchant ID"

    def __init__(self, *, api_key: str, secret: str, merchant_id: str,
                 webhook_secret: str = "", mode: str = "test"):
        self.api_key = (api_key or "").strip()
        self.secret = (secret or "").strip()
        self.merchant_id = (merchant_id or "").strip()
        self.webhook_secret = (webhook_secret or self.secret or "").strip()
        self.mode = (mode or "test").lower()

    # -- Implement in subclass --------------------------------------------------
    def test_connection(self) -> str:
        raise NotImplementedError

    def parse_webhook(self, payload_bytes: bytes,
                      headers: dict) -> AggregatorOrderEvent:
        raise NotImplementedError

    def acknowledge_order(self, *, external_order_id: str,
                          action: str, reason: str = "") -> dict:
        """``action`` is 'accept' | 'reject' | 'ready' | 'food_ready'."""
        raise NotImplementedError

    # -- Shared helpers --------------------------------------------------------
    def _verify_hmac(self, payload_bytes: bytes, signature_header: str,
                     timestamp_header: str = "") -> None:
        """HMAC-SHA256(secret, [timestamp + '.' +] body) == signature.

        Used by Swiggy and Zomato (Uber Eats overrides). Constant-time
        compare. Replay window enforced when a timestamp is provided."""
        if not self.webhook_secret:
            raise AggregatorError(f"{self.name} webhook secret is not configured.")
        if not signature_header:
            raise AggregatorError(f"{self.name} webhook missing signature header.")

        if timestamp_header:
            try:
                ts = int(timestamp_header)
            except ValueError:
                raise AggregatorError(f"{self.name} webhook timestamp not numeric.")
            skew = abs(int(time.time()) - ts)
            if skew > REPLAY_WINDOW_SECONDS:
                raise AggregatorError(
                    f"{self.name} webhook timestamp outside replay window ({skew}s)."
                )
            signed = f"{ts}.".encode("ascii") + payload_bytes
        else:
            signed = payload_bytes

        expected = hmac.new(
            self.webhook_secret.encode("utf-8"), signed, hashlib.sha256
        ).hexdigest()
        provided = signature_header.strip().lower()
        # Some partners prefix the algo name (e.g. "sha256=...").
        if "=" in provided:
            provided = provided.split("=", 1)[1]
        if not hmac.compare_digest(expected, provided):
            raise AggregatorError(f"{self.name} webhook signature invalid.")


# ---------------------------------------------------------------------------
# Swiggy
# ---------------------------------------------------------------------------

class SwiggyPlatform(AggregatorPlatform):
    name = "swiggy"
    credential_label = "Partner API key"
    secret_label = "Partner secret"
    merchant_id_label = "Restaurant ID"

    def _base_url(self) -> str:
        return ("https://partner-api.swiggy.com/v2"
                if self.mode == "live"
                else "https://partner-api-stg.swiggy.com/v2")

    def _auth_headers(self) -> dict:
        if not self.api_key:
            raise AggregatorError("Swiggy partner API key not configured.")
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Restaurant-Id": self.merchant_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> str:
        import requests
        if not self.merchant_id:
            raise AggregatorError("Swiggy Restaurant ID is required.")
        try:
            r = requests.get(
                f"{self._base_url()}/restaurant/{self.merchant_id}/status",
                headers=self._auth_headers(), timeout=10,
            )
        except Exception as exc:
            raise AggregatorError(f"Could not reach Swiggy: {exc}") from exc
        if r.status_code in (200, 404):
            # 404 still proves the credential parsed; the restaurant id may
            # belong to a sibling environment. 200 is the happy path.
            return f"Connected to Swiggy ({self.mode} mode)."
        if r.status_code in (401, 403):
            raise AggregatorError("Swiggy rejected the partner credentials.")
        raise AggregatorError(
            f"Swiggy returned HTTP {r.status_code}: {r.text[:200]}"
        )

    def parse_webhook(self, payload_bytes, headers):
        sig = headers.get("X-Swiggy-Signature") or headers.get("X-Signature") or ""
        ts = headers.get("X-Swiggy-Timestamp") or ""
        self._verify_hmac(payload_bytes, sig, ts)
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise AggregatorError(f"Swiggy payload not JSON: {exc}") from exc
        etype = (event.get("event_type") or event.get("eventType") or "").upper()
        order = event.get("order") or event.get("data") or {}
        items = []
        for it in order.get("order_items", order.get("items", [])):
            items.append({
                "name": it.get("name") or it.get("item_name", "Item"),
                "qty": int(it.get("quantity", 1)),
                "price_minor": int(round(float(it.get("total", it.get("price", 0))) * 100)),
                "notes": it.get("instructions", ""),
            })
        cust = order.get("customer") or {}
        status_map = {
            "NEW_ORDER": "placed", "ORDER_PLACED": "placed",
            "ORDER_CANCELLED": "cancelled", "ORDER_EDIT": "edited",
            "RIDER_ASSIGNED": "rider_assigned", "ORDER_DELIVERED": "delivered",
        }
        return AggregatorOrderEvent(
            event_type=status_map.get(etype, "status_update"),
            external_order_id=str(order.get("order_id")
                                  or order.get("orderId")
                                  or event.get("order_id") or ""),
            status=status_map.get(etype, "placed"),
            customer_name=cust.get("name", "Swiggy customer"),
            customer_phone=cust.get("mobile", ""),
            items=items,
            subtotal_minor=int(round(float(order.get("net_total", 0)) * 100)),
            total_minor=int(round(float(order.get("order_total",
                                                   order.get("total", 0))) * 100)),
            pickup_eta_minutes=int(order.get("pickup_eta_minutes", 0) or 0),
            rider_name=(order.get("delivery_partner") or {}).get("name", ""),
            rider_phone=(order.get("delivery_partner") or {}).get("mobile", ""),
            notes=order.get("instructions", ""),
            raw=event,
        )

    def acknowledge_order(self, *, external_order_id, action, reason=""):
        import requests
        action_map = {
            "accept": "ACCEPTED", "reject": "REJECTED",
            "ready": "FOOD_READY", "food_ready": "FOOD_READY",
        }
        body_status = action_map.get(action, action.upper())
        body = {"order_id": external_order_id, "status": body_status,
                "reason": reason or ""}
        try:
            r = requests.post(
                f"{self._base_url()}/restaurant/{self.merchant_id}/orders/{external_order_id}/status",
                json=body, headers=self._auth_headers(), timeout=12,
            )
        except Exception as exc:
            raise AggregatorError(f"Swiggy ack failed: {exc}") from exc
        if r.status_code >= 400:
            raise AggregatorError(
                f"Swiggy refused ack ({r.status_code}): {r.text[:200]}"
            )
        return r.json() if r.text else {"ok": True}


# ---------------------------------------------------------------------------
# Zomato
# ---------------------------------------------------------------------------

class ZomatoPlatform(AggregatorPlatform):
    name = "zomato"
    credential_label = "Client ID"
    secret_label = "Client secret"
    merchant_id_label = "Outlet ID (res_id)"

    def _base_url(self) -> str:
        return ("https://pos-api.zomato.com/v3"
                if self.mode == "live"
                else "https://pos-api-staging.zomato.com/v3")

    def _auth_headers(self) -> dict:
        if not self.api_key or not self.secret:
            raise AggregatorError("Zomato client_id and secret are required.")
        # Basic auth — Zomato POS uses the client id / secret pair directly.
        token = base64.b64encode(
            f"{self.api_key}:{self.secret}".encode("utf-8")
        ).decode("ascii")
        return {
            "Authorization": f"Basic {token}",
            "X-Res-Id": self.merchant_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> str:
        import requests
        if not self.merchant_id:
            raise AggregatorError("Zomato Outlet ID (res_id) is required.")
        try:
            r = requests.get(
                f"{self._base_url()}/restaurants/{self.merchant_id}",
                headers=self._auth_headers(), timeout=10,
            )
        except Exception as exc:
            raise AggregatorError(f"Could not reach Zomato: {exc}") from exc
        if r.status_code in (200, 404):
            return f"Connected to Zomato ({self.mode} mode)."
        if r.status_code in (401, 403):
            raise AggregatorError("Zomato rejected the client credentials.")
        raise AggregatorError(
            f"Zomato returned HTTP {r.status_code}: {r.text[:200]}"
        )

    def parse_webhook(self, payload_bytes, headers):
        sig = (headers.get("X-Zomato-Signature")
               or headers.get("X-Webhook-Signature") or "")
        ts = headers.get("X-Zomato-Timestamp") or ""
        self._verify_hmac(payload_bytes, sig, ts)
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise AggregatorError(f"Zomato payload not JSON: {exc}") from exc
        etype = (event.get("event") or event.get("event_type") or "").lower()
        order = event.get("order") or event
        items = []
        for it in order.get("order_items", order.get("items", [])):
            items.append({
                "name": it.get("name") or it.get("dish_name", "Item"),
                "qty": int(it.get("quantity", 1)),
                "price_minor": int(round(float(it.get("total_cost",
                                                      it.get("price", 0))) * 100)),
                "notes": it.get("special_instructions", ""),
            })
        status_map = {
            "new_order": "placed", "order_placed": "placed",
            "order_cancellation": "cancelled", "order_cancelled": "cancelled",
            "rider_assigned": "rider_assigned",
            "order_status_update": "status_update",
            "order_delivered": "delivered",
        }
        return AggregatorOrderEvent(
            event_type=status_map.get(etype, "status_update"),
            external_order_id=str(order.get("order_id") or event.get("order_id") or ""),
            status=status_map.get(etype, "placed"),
            customer_name=order.get("user_name") or order.get("customer_name", "Zomato customer"),
            customer_phone=order.get("user_phone") or order.get("customer_phone", ""),
            items=items,
            subtotal_minor=int(round(float(order.get("subtotal", 0)) * 100)),
            total_minor=int(round(float(order.get("total_cost",
                                                   order.get("net_amount", 0))) * 100)),
            pickup_eta_minutes=int(order.get("preparation_time", 0) or 0),
            rider_name=(order.get("rider") or {}).get("name", ""),
            rider_phone=(order.get("rider") or {}).get("contact", ""),
            notes=order.get("instructions", ""),
            raw=event,
        )

    def acknowledge_order(self, *, external_order_id, action, reason=""):
        import requests
        action_map = {
            "accept": "accepted", "reject": "rejected",
            "ready": "food_ready", "food_ready": "food_ready",
        }
        body = {"order_id": external_order_id,
                "status": action_map.get(action, action),
                "reason": reason or ""}
        try:
            r = requests.post(
                f"{self._base_url()}/orders/{external_order_id}/status",
                json=body, headers=self._auth_headers(), timeout=12,
            )
        except Exception as exc:
            raise AggregatorError(f"Zomato ack failed: {exc}") from exc
        if r.status_code >= 400:
            raise AggregatorError(
                f"Zomato refused ack ({r.status_code}): {r.text[:200]}"
            )
        return r.json() if r.text else {"ok": True}


# ---------------------------------------------------------------------------
# Uber Eats
# ---------------------------------------------------------------------------

class UberEatsPlatform(AggregatorPlatform):
    name = "ubereats"
    credential_label = "Client ID"
    secret_label = "Client secret"
    merchant_id_label = "Store UUID"

    def _base_url(self) -> str:
        return "https://api.uber.com/v1/eats"

    def _token(self) -> str:
        """OAuth2 client_credentials. Cached in memory for the request only.
        Long-running daemons should add Redis-backed caching; for our
        request-per-event model the cost of one extra HTTP call per
        webhook is negligible (single-digit ms)."""
        import requests
        if not self.api_key or not self.secret:
            raise AggregatorError("Uber Eats client_id and secret are required.")
        try:
            r = requests.post(
                "https://login.uber.com/oauth/v2/token",
                data={"client_id": self.api_key,
                      "client_secret": self.secret,
                      "grant_type": "client_credentials",
                      "scope": "eats.store eats.order"},
                timeout=10,
            )
        except Exception as exc:
            raise AggregatorError(f"Uber OAuth failed: {exc}") from exc
        if r.status_code != 200:
            raise AggregatorError(
                f"Uber OAuth rejected ({r.status_code}): {r.text[:200]}"
            )
        return r.json().get("access_token", "")

    def test_connection(self) -> str:
        token = self._token()
        if not token:
            raise AggregatorError("Uber returned an empty access token.")
        return f"Connected to Uber Eats ({self.mode} mode)."

    def parse_webhook(self, payload_bytes, headers):
        sig = headers.get("X-Uber-Signature") or ""
        # Uber's signature is HMAC-SHA256 over the body (no timestamp prefix).
        self._verify_hmac(payload_bytes, sig, timestamp_header="")
        try:
            event = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise AggregatorError(f"Uber payload not JSON: {exc}") from exc
        etype = (event.get("event_type") or "").lower()
        meta = event.get("meta") or {}
        order = event.get("resource") or event
        items = []
        for it in order.get("cart", {}).get("items", order.get("items", [])):
            items.append({
                "name": it.get("title") or it.get("name", "Item"),
                "qty": int(it.get("quantity", 1)),
                "price_minor": int(it.get("price", {}).get("unit_price",
                                          {}).get("amount_e5", 0)) // 1000 if isinstance(it.get("price"), dict)
                                else int(round(float(it.get("price", 0)) * 100)),
                "notes": it.get("special_instructions", ""),
            })
        status_map = {
            "orders.notification": "placed",
            "orders.scheduled.notification": "placed",
            "orders.cancel": "cancelled",
            "orders.release": "rejected",
        }
        return AggregatorOrderEvent(
            event_type=status_map.get(etype, "status_update"),
            external_order_id=str(meta.get("resource_id") or order.get("id", "")),
            status=status_map.get(etype, "placed"),
            customer_name=(order.get("eater") or {}).get("first_name", "Uber customer"),
            customer_phone="",
            items=items,
            subtotal_minor=int(round(float(order.get("payment", {})
                                                 .get("subtotal", 0)) * 100)),
            total_minor=int(round(float(order.get("payment", {})
                                              .get("total", 0)) * 100)),
            pickup_eta_minutes=int(order.get("preparation_time", 0) or 0),
            notes=order.get("special_instructions", ""),
            raw=event,
        )

    def acknowledge_order(self, *, external_order_id, action, reason=""):
        import requests
        token = self._token()
        body_action = {"accept": "accept", "reject": "deny",
                       "ready": "ready_for_pickup", "food_ready": "ready_for_pickup"}
        body = {"reason": {"explanation": reason or ""}} if action == "reject" else {}
        path = body_action.get(action, action)
        try:
            r = requests.post(
                f"{self._base_url()}/orders/{external_order_id}/{path}",
                json=body,
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
                timeout=12,
            )
        except Exception as exc:
            raise AggregatorError(f"Uber ack failed: {exc}") from exc
        if r.status_code >= 400:
            raise AggregatorError(
                f"Uber refused ack ({r.status_code}): {r.text[:200]}"
            )
        return r.json() if r.text else {"ok": True}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PLATFORMS = {
    "swiggy": SwiggyPlatform,
    "zomato": ZomatoPlatform,
    "ubereats": UberEatsPlatform,
}


def build_aggregator(name: str, *, api_key: str, secret: str,
                     merchant_id: str, webhook_secret: str = "",
                     mode: str = "test") -> AggregatorPlatform:
    name = (name or "").lower().strip()
    if name not in _PLATFORMS:
        raise AggregatorError(f"Unknown aggregator platform: {name!r}")
    return _PLATFORMS[name](
        api_key=api_key, secret=secret, merchant_id=merchant_id,
        webhook_secret=webhook_secret, mode=mode,
    )
