"""ExA Cup automatic login (ExA Cup repo: docs/NFS-ONLINE.md).

The ExA Cup api signs a short-lived ticket for a signed-in ExA Cup account;
the launcher hands it to the client plugin, which puts it in the game's
`auth` as the password. A valid ticket logs the player in as their ExA Cup
account (created on first use), so nobody types a name or password and no
reusable password ever crosses the wire.

Ticket: ``exa1.<b64url(JSON {"u": user id, "p": persona, "e": expiry})>.<b64url(sig)>``
with ``sig = HMAC-SHA256(secret, "exa1." + <payload part>)``. The secret is
shared by the api (NFSMW_LOGIN_SECRET) and this server (EXA_LOGIN_SECRET).
A ticket may be used again until it expires (the game retries a login).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass

PREFIX = "exa1."
PERSONA_RE = re.compile(r"^[A-Za-z0-9_-]{3,15}$")
MIN_SECRET_LENGTH = 32


@dataclass(frozen=True)
class ExaTicket:
    user_id: str
    persona: str

    @property
    def account_name(self) -> str:
        """Stable per ExA Cup account, whatever its username becomes."""
        return "x" + hashlib.sha256(self.user_id.encode("utf-8")).hexdigest()[:24]

    def fallback_personas(self) -> tuple[str, ...]:
        """Other names to try when the persona is taken by another account."""
        tag = hashlib.sha256(("persona:" + self.user_id).encode("utf-8")).hexdigest()
        return (f"{self.persona[:11]}_{tag[:3]}", f"ExA_{tag[:8]}")


def looks_like_ticket(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_ticket(token: str, secret: bytes, now: float | None = None) -> ExaTicket | None:
    """The ticket's account when its signature is ours and it has not expired."""
    if not looks_like_ticket(token) or not secret:
        return None
    body, sep, signature = token[len(PREFIX):].partition(".")
    if not sep or not body or not signature:
        return None
    try:
        given = _b64decode(signature)
        payload = json.loads(_b64decode(body))
    except (binascii.Error, ValueError):
        return None
    expected = hmac.new(secret, (PREFIX + body).encode("ascii", errors="replace"), hashlib.sha256).digest()
    if not hmac.compare_digest(given, expected):
        return None
    if not isinstance(payload, dict):
        return None
    user_id, persona, expiry = payload.get("u"), payload.get("p"), payload.get("e")
    if not isinstance(user_id, str) or not user_id or len(user_id) > 128:
        return None
    if not isinstance(persona, str) or not PERSONA_RE.match(persona):
        return None
    if not isinstance(expiry, int) or isinstance(expiry, bool):
        return None
    if expiry < (time.time() if now is None else now):
        return None
    return ExaTicket(user_id=user_id, persona=persona)


def secret_from_env() -> bytes | None:
    """EXA_LOGIN_SECRET, or None (tickets off) when unset or too short."""
    value = os.environ.get("EXA_LOGIN_SECRET", "").strip()
    return value.encode("utf-8") if len(value) >= MIN_SECRET_LENGTH else None
