"""Most Wanted authentication adapter using the shared U2-derived core.

Only the profile/wire differences belong here.  The listener and full MW login
flow will be connected after U2 capture-contract tests are green.
"""

from __future__ import annotations

from classic.accounts.credentials import CredentialStore
from classic.accounts.identity import IdentityStore
from classic.exa_ticket import secret_from_env
from classic.protocols.auth import (
    ClassicActiveSessionRegistry,
    ClassicAuthProfile,
    ClassicAuthService,
)

_FROM_ENV = object()


MOST_WANTED_AUTH_PROFILE = ClassicAuthProfile(
    game_id="most_wanted",
    auth_payload_length=130,
    persona_payload_length=116,
    tos_value=3,
    last_login="2005.12.8 15:51:38",
    persona_last_login="2006.12.8 15:51:58",
    persona_previous_login="2006.12.8 16:51:40",
    birth_date="20030520",
    fallback_email="",
)


def create_auth_service(
    credentials: CredentialStore,
    identities: IdentityStore,
    *,
    active_sessions: ClassicActiveSessionRegistry | None = None,
    verify_passwords: bool = True,
    auto_enroll: bool = False,
    # ExA Cup hardening: off. Upstream left in-game `acct` on whatever the
    # config said, so anyone could create unlimited accounts, and `acct` on an
    # existing name answered whether a password was right without counting
    # the failure (a password oracle past AUTH_FAILURE_LIMIT). Accounts come
    # from the operator (the CLI, or ExA Cup's account bridge).
    allow_create: bool = False,
    allow_password_reset: bool = False,
    # ExA Cup automatic login: EXA_LOGIN_SECRET unless a test passes its own.
    ticket_secret: bytes | None | object = _FROM_ENV,
) -> ClassicAuthService:
    return ClassicAuthService(
        credentials,
        identities,
        profile=MOST_WANTED_AUTH_PROFILE,
        active_sessions=active_sessions,
        verify_passwords=verify_passwords,
        auto_enroll=auto_enroll,
        allow_create=allow_create,
        allow_password_reset=allow_password_reset,
        ticket_secret=secret_from_env() if ticket_secret is _FROM_ENV else ticket_secret,  # type: ignore[arg-type]
    )
