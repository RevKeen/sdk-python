"""
RevKeen Webhook Utilities for Python SDK

This file is automatically bundled with the generated SDK.
It provides webhook signature verification and event construction.

Example:
    ```python
    from revkeen import Webhooks, WebhookSignatureVerificationError

    # Flask example
    @app.route('/webhook', methods=['POST'])
    def webhook():
        payload = request.get_data(as_text=True)
        signature = request.headers.get('revkeen-signature', '')
        webhook_secret = os.environ['REVKEEN_WEBHOOK_SECRET']

        try:
            event = Webhooks.construct_event(payload, signature, webhook_secret)

            if event['type'] == 'invoice.paid':
                invoice = event['data']['object']
                # Handle invoice paid...
            elif event['type'] == 'subscription.created':
                subscription = event['data']['object']
                # Handle subscription created...

            return jsonify({'received': True})
        except WebhookSignatureVerificationError as e:
            return jsonify({'error': str(e)}), 400
    ```
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union


# Default tolerance for timestamp validation (5 minutes)
WEBHOOK_TOLERANCE_IN_SECONDS = 300

# Type definitions for webhook events
WebhookEventType = Literal[
    # Invoice events
    "invoice.created",
    "invoice.updated",
    "invoice.finalized",
    "invoice.sent",
    "invoice.paid",
    "invoice.voided",
    "invoice.payment_failed",
    "invoice.overdue",
    # Subscription events
    "subscription.created",
    "subscription.updated",
    "subscription.renewed",
    "subscription.canceled",
    "subscription.paused",
    "subscription.resumed",
    "subscription.trial_ending",
    "subscription.trial_ended",
    "subscription.past_due",
    # Payment events
    "payment.succeeded",
    "payment.failed",
    "payment.refunded",
    "payment.disputed",
    "payment.captured",
    # Customer events
    "customer.created",
    "customer.updated",
    "customer.deleted",
    "customer.payment_method.attached",
    "customer.payment_method.detached",
    # Checkout events
    "checkout.session.completed",
    "checkout.session.expired",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
    # Order events
    "order.created",
    "order.updated",
    "order.paid",
    "order.canceled",
    "order.fulfilled",
    # Plan/Product events
    "plan.created",
    "plan.updated",
    "plan.deleted",
    "product.created",
    "product.updated",
    "product.deleted",
    # Price events
    "price.created",
    "price.updated",
    "price.deleted",
]


class WebhookEventData(TypedDict, total=False):
    """Webhook event data structure"""
    object: Any
    previous_attributes: Optional[Dict[str, Any]]


class WebhookEvent(TypedDict, total=False):
    """Webhook event structure (Stripe-compatible)"""
    id: str
    object: Literal["event"]
    type: str  # WebhookEventType
    created: int
    livemode: bool
    api_version: str
    account: Optional[str]
    data: WebhookEventData
    request: Optional[Dict[str, Any]]


@dataclass
class WebhookHeaders:
    """
    Webhook headers sent with each delivery

    Attributes:
        signature: X-Revkeen-Signature header (HMAC signature, format: t=xxx,v1=yyy)
        version: X-Revkeen-Version header (API version date, e.g., "2026-01-01")
        account: X-Revkeen-Account header (Merchant account ID)
        event_id: X-Revkeen-Event-Id header (Unique event identifier)
        timestamp: X-Revkeen-Timestamp header (Unix timestamp as string)
    """
    signature: str
    version: Optional[str] = None
    account: Optional[str] = None
    event_id: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class ParsedSignature:
    """Parsed webhook signature components"""
    timestamp: int
    signatures: List[str]


class WebhookSignatureVerificationError(Exception):
    """Exception thrown when webhook signature verification fails"""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def extract_webhook_headers(
    headers: Dict[str, Union[str, List[str], None]]
) -> WebhookHeaders:
    """
    Extract webhook headers from request headers

    Works with various web frameworks (Flask, Django, FastAPI, etc.)

    Args:
        headers: Dictionary of HTTP headers (case-insensitive)

    Returns:
        WebhookHeaders object with extracted values

    Raises:
        WebhookSignatureVerificationError: If signature header is missing

    Example:
        ```python
        # Flask
        headers = extract_webhook_headers(dict(request.headers))

        # Django
        headers = extract_webhook_headers(request.headers)

        # FastAPI
        headers = extract_webhook_headers(dict(request.headers))
        ```
    """
    def get_header(name: str) -> Optional[str]:
        # Try exact match first, then lowercase
        for key in [name, name.lower()]:
            value = headers.get(key)
            if value is not None:
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        return None

    signature = get_header("X-Revkeen-Signature") or get_header("x-rk-signature")
    if not signature:
        raise WebhookSignatureVerificationError(
            "Missing webhook signature header (X-Revkeen-Signature or x-rk-signature)"
        )

    return WebhookHeaders(
        signature=signature,
        version=get_header("X-Revkeen-Version"),
        account=get_header("X-Revkeen-Account"),
        event_id=get_header("X-Revkeen-Event-Id"),
        timestamp=get_header("X-Revkeen-Timestamp"),
    )


class Webhooks:
    """
    Webhook utilities for RevKeen SDK

    Example:
        ```python
        from revkeen import Webhooks

        event = Webhooks.construct_event(
            payload=request.get_data(as_text=True),
            signature=request.headers['revkeen-signature'],
            secret=os.environ['REVKEEN_WEBHOOK_SECRET']
        )
        ```
    """

    TOLERANCE_IN_SECONDS = WEBHOOK_TOLERANCE_IN_SECONDS

    @staticmethod
    def construct_event(
        payload: str,
        signature: str,
        secret: str,
        tolerance: Optional[int] = None,
    ) -> WebhookEvent:
        """
        Constructs and verifies a webhook event from a raw payload

        Args:
            payload: The raw request body as a string
            signature: The signature header value (revkeen-signature header)
            secret: Your webhook secret (starts with rk_wh_)
            tolerance: Tolerance in seconds for timestamp validation (default: 300)

        Returns:
            The verified webhook event

        Raises:
            WebhookSignatureVerificationError: If verification fails

        Example:
            ```python
            # Flask example
            @app.route('/webhook', methods=['POST'])
            def webhook():
                event = Webhooks.construct_event(
                    payload=request.get_data(as_text=True),
                    signature=request.headers.get('revkeen-signature', ''),
                    secret=os.environ['REVKEEN_WEBHOOK_SECRET']
                )
                print(f"Received event: {event['type']}")
                return jsonify({'received': True})
            ```

            ```python
            # Django example
            from django.http import JsonResponse
            from django.views.decorators.csrf import csrf_exempt
            from django.views.decorators.http import require_POST

            @csrf_exempt
            @require_POST
            def webhook(request):
                event = Webhooks.construct_event(
                    payload=request.body.decode('utf-8'),
                    signature=request.headers.get('revkeen-signature', ''),
                    secret=settings.REVKEEN_WEBHOOK_SECRET
                )
                # Handle event...
                return JsonResponse({'received': True})
            ```

            ```python
            # FastAPI example
            from fastapi import Request, HTTPException

            @app.post('/webhook')
            async def webhook(request: Request):
                body = await request.body()
                event = Webhooks.construct_event(
                    payload=body.decode('utf-8'),
                    signature=request.headers.get('revkeen-signature', ''),
                    secret=os.environ['REVKEEN_WEBHOOK_SECRET']
                )
                # Handle event...
                return {'received': True}
            ```
        """
        # Verify the signature
        Webhooks.verify_signature(payload, signature, secret, tolerance)

        # Parse and return the event
        try:
            event = json.loads(payload)
        except json.JSONDecodeError as e:
            raise WebhookSignatureVerificationError(
                f"Invalid JSON payload: {e}"
            )

        # Basic validation
        if not all(key in event for key in ("id", "type", "data")):
            raise WebhookSignatureVerificationError(
                "Invalid event structure: missing required fields"
            )

        return event

    @staticmethod
    def construct_event_with_headers(
        payload: str,
        headers: WebhookHeaders,
        secret: str,
        tolerance: Optional[int] = None,
    ) -> WebhookEvent:
        """
        Constructs and verifies a webhook event with header metadata

        This method extracts version information from headers and merges it
        with the event payload for a richer event object.

        Args:
            payload: The raw request body as a string
            headers: WebhookHeaders object extracted from request
            secret: Your webhook secret (starts with rk_wh_)
            tolerance: Tolerance in seconds for timestamp validation (default: 300)

        Returns:
            The verified webhook event with header metadata

        Raises:
            WebhookSignatureVerificationError: If verification fails

        Example:
            ```python
            # Flask example with version headers
            @app.route('/webhook', methods=['POST'])
            def webhook():
                headers = extract_webhook_headers(dict(request.headers))
                event = Webhooks.construct_event_with_headers(
                    payload=request.get_data(as_text=True),
                    headers=headers,
                    secret=os.environ['REVKEEN_WEBHOOK_SECRET']
                )

                print(f"API Version: {event.get('api_version')}")
                print(f"Account: {event.get('account')}")
                return jsonify({'received': True})
            ```
        """
        # Verify the signature using the header
        Webhooks.verify_signature(payload, headers.signature, secret, tolerance)

        # Parse the event
        try:
            event = json.loads(payload)
        except json.JSONDecodeError as e:
            raise WebhookSignatureVerificationError(
                f"Invalid JSON payload: {e}"
            )

        # Basic validation
        if not all(key in event for key in ("id", "type", "data")):
            raise WebhookSignatureVerificationError(
                "Invalid event structure: missing required fields"
            )

        # Merge header metadata into event if not already present
        if "api_version" not in event and headers.version:
            event["api_version"] = headers.version
        if "account" not in event and headers.account:
            event["account"] = headers.account

        return event

    @staticmethod
    def verify_signature(
        payload: str,
        signature: str,
        secret: str,
        tolerance: Optional[int] = None,
    ) -> bool:
        """
        Verifies a webhook signature

        Args:
            payload: The raw request body as a string
            signature: The signature header value
            secret: Your webhook secret
            tolerance: Tolerance in seconds (default: 300)

        Returns:
            True if the signature is valid

        Raises:
            WebhookSignatureVerificationError: If verification fails
        """
        tolerance = tolerance or WEBHOOK_TOLERANCE_IN_SECONDS

        # Check if signature header exists
        if not signature:
            raise WebhookSignatureVerificationError(
                "Missing webhook signature header"
            )

        # Parse signature header
        parsed = Webhooks._parse_signature_header(signature)

        # Check timestamp tolerance (prevent replay attacks)
        current_time = int(time.time())
        time_diff = abs(current_time - parsed.timestamp)

        if time_diff > tolerance:
            raise WebhookSignatureVerificationError(
                f"Timestamp outside tolerance window ({time_diff}s > {tolerance}s). "
                "The webhook might be a replay attack, or your server's clock might be out of sync."
            )

        # Generate expected signature
        signed_payload = f"{parsed.timestamp}.{payload}"
        expected_signature = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Compare signatures using constant-time comparison
        signature_valid = any(
            hmac.compare_digest(expected_signature, sig)
            for sig in parsed.signatures
        )

        if not signature_valid:
            raise WebhookSignatureVerificationError(
                "Signature verification failed. "
                "Ensure you're using the correct webhook secret and the raw request body."
            )

        return True

    @staticmethod
    def _parse_signature_header(header: str) -> ParsedSignature:
        """
        Parses a webhook signature header
        Format: "t={timestamp},v1={signature}"

        Args:
            header: The signature header

        Returns:
            Parsed signature components

        Raises:
            WebhookSignatureVerificationError: If header format is invalid
        """
        timestamp: Optional[int] = None
        signatures: List[str] = []

        for part in header.split(","):
            key_value = part.split("=", 1)
            if len(key_value) != 2:
                continue

            key, value = key_value

            if key == "t":
                try:
                    timestamp = int(value)
                except ValueError:
                    pass
            elif key == "v1":
                signatures.append(value)

        if timestamp is None or not signatures:
            raise WebhookSignatureVerificationError(
                "Invalid signature header: missing timestamp or signature"
            )

        return ParsedSignature(timestamp=timestamp, signatures=signatures)


# Convenience function for direct import
def construct_event(
    payload: str,
    signature: str,
    secret: str,
    tolerance: Optional[int] = None,
) -> WebhookEvent:
    """
    Constructs and verifies a webhook event from a raw payload

    This is a convenience function that delegates to Webhooks.construct_event().
    See that method for full documentation.

    Args:
        payload: The raw request body as a string
        signature: The signature header value (revkeen-signature header)
        secret: Your webhook secret (starts with rk_wh_)
        tolerance: Tolerance in seconds for timestamp validation (default: 300)

    Returns:
        The verified webhook event

    Raises:
        WebhookSignatureVerificationError: If verification fails
    """
    return Webhooks.construct_event(payload, signature, secret, tolerance)


def construct_event_with_headers(
    payload: str,
    headers: WebhookHeaders,
    secret: str,
    tolerance: Optional[int] = None,
) -> WebhookEvent:
    """
    Constructs and verifies a webhook event with header metadata

    This is a convenience function that delegates to Webhooks.construct_event_with_headers().
    See that method for full documentation.

    Args:
        payload: The raw request body as a string
        headers: WebhookHeaders object extracted from request
        secret: Your webhook secret (starts with rk_wh_)
        tolerance: Tolerance in seconds for timestamp validation (default: 300)

    Returns:
        The verified webhook event with header metadata

    Raises:
        WebhookSignatureVerificationError: If verification fails
    """
    return Webhooks.construct_event_with_headers(payload, headers, secret, tolerance)


def verify_signature(
    payload: str,
    signature: str,
    secret: str,
    tolerance: Optional[int] = None,
) -> bool:
    """
    Verifies a webhook signature

    This is a convenience function that delegates to Webhooks.verify_signature().
    See that method for full documentation.

    Args:
        payload: The raw request body as a string
        signature: The signature header value
        secret: Your webhook secret
        tolerance: Tolerance in seconds (default: 300)

    Returns:
        True if the signature is valid

    Raises:
        WebhookSignatureVerificationError: If verification fails
    """
    return Webhooks.verify_signature(payload, signature, secret, tolerance)


__all__ = [
    # Main class
    "Webhooks",
    # Exceptions
    "WebhookSignatureVerificationError",
    # Types
    "WebhookEvent",
    "WebhookEventData",
    "WebhookEventType",
    "WebhookHeaders",
    # Convenience functions
    "construct_event",
    "construct_event_with_headers",
    "extract_webhook_headers",
    "verify_signature",
    # Constants
    "WEBHOOK_TOLERANCE_IN_SECONDS",
]
