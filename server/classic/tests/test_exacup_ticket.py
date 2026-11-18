"""ExA Cup automatic login (classic/exa_ticket.py, ExA Cup repo docs/NFS-ONLINE.md)."""

import base64
import hashlib
import hmac
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from common.accounts import SQLiteAccountDatabase
from classic.accounts.credentials import CredentialStore
from classic.accounts.identity import IdentityStore
from classic.accounts.sqlite_backend import SQLiteCredentialStore, SQLiteIdentityStore
from classic.exa_ticket import ExaTicket, verify_ticket
from classic.games.most_wanted.auth import create_auth_service as create_mw_auth_service
from classic.protocols.auth import ClassicActiveSessionRegistry, ClassicAuthContext

SECRET = b"s" * 48


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_ticket(user_id: str, persona: str, expiry: int, secret: bytes = SECRET) -> str:
    """What the ExA Cup api issues (apps/api/src/lib/nfsmw.ts)."""
    body = _b64(json.dumps({"u": user_id, "p": persona, "e": expiry}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret, ("exa1." + body).encode(), hashlib.sha256).digest())
    return f"exa1.{body}.{sig}"


class TicketVerifyTests(unittest.TestCase):
    def test_a_good_ticket_names_its_account(self) -> None:
        later = int(time.time()) + 600
        ticket = verify_ticket(make_ticket("user-1", "Racer_01", later), SECRET)
        self.assertEqual(ticket, ExaTicket(user_id="user-1", persona="Racer_01"))
        self.assertEqual(ticket.account_name, "x" + hashlib.sha256(b"user-1").hexdigest()[:24])

    def test_a_forged_expired_or_odd_ticket_is_refused(self) -> None:
        later = int(time.time()) + 600
        good = make_ticket("user-1", "Racer", later)
        self.assertIsNone(verify_ticket(make_ticket("user-1", "Racer", later, secret=b"o" * 48), SECRET))
        self.assertIsNone(verify_ticket(good[:-2] + ("AA" if good[-2:] != "AA" else "BB"), SECRET))
        self.assertIsNone(verify_ticket(make_ticket("user-1", "Racer", int(time.time()) - 1), SECRET))
        self.assertIsNone(verify_ticket(make_ticket("user-1", "no spaces!", later), SECRET))
        self.assertIsNone(verify_ticket(make_ticket("user-1", "ab", later), SECRET))
        self.assertIsNone(verify_ticket("exa1.only-one-part", SECRET))
        self.assertIsNone(verify_ticket("not-a-ticket", SECRET))
        self.assertIsNone(verify_ticket(good, b""))


class TicketLoginTests(unittest.TestCase):
    """On the production store (SQLite: persona names are unique across accounts)."""

    def setUp(self) -> None:
        self._dir = TemporaryDirectory()
        root = Path(self._dir.name)
        database = SQLiteAccountDatabase(root / "accounts.sqlite3", root / "users")
        self.credentials = SQLiteCredentialStore(database)
        self.credentials.create_account("someone", "pw-someone", persona="Taken", email="")
        self.service = create_mw_auth_service(
            self.credentials,
            SQLiteIdentityStore(database, token_factory=lambda: "classic-session-token."),
            active_sessions=ClassicActiveSessionRegistry(),
            auto_enroll=True,  # the private test's setting: tickets must never use it
            ticket_secret=SECRET,
        )

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _login(self, password: str, conn: str = "c1", name: str = "anything"):
        return self.service.login(
            {"NAME": name, "PASS": password, "PSES": "Public Key"},
            ClassicAuthContext(connection_id=conn, client_ip="203.0.113.9", mask="Public Key"),
        )

    def test_the_first_ticket_creates_the_account_and_the_next_reuses_it(self) -> None:
        later = int(time.time()) + 600
        first = self._login(make_ticket("user-7", "Driver7", later), conn="c1")
        self.assertTrue(first.accepted, first.reason)
        account_name = "x" + hashlib.sha256(b"user-7").hexdigest()[:24]
        account = self.credentials.resolve_account(account_name)
        self.assertIsNotNone(account)
        self.assertEqual(account.persona, "Driver7")
        self.service.active_sessions = ClassicActiveSessionRegistry()
        again = self._login(make_ticket("user-7", "Driver7", later), conn="c2")
        self.assertTrue(again.accepted, again.reason)

    def test_a_taken_name_gets_a_suffix_instead_of_failing(self) -> None:
        reply = self._login(make_ticket("user-8", "Taken", int(time.time()) + 600))
        self.assertTrue(reply.accepted, reply.reason)
        account = self.credentials.resolve_account("x" + hashlib.sha256(b"user-8").hexdigest()[:24])
        self.assertNotEqual(account.persona, "Taken")
        self.assertTrue(account.persona.startswith("Taken_"))

    def test_a_bad_ticket_is_refused_and_enrolls_nothing(self) -> None:
        reply = self._login(make_ticket("user-9", "Nobody", int(time.time()) - 5))
        self.assertFalse(reply.accepted)
        self.assertEqual(reply.reason, "ticket_invalid")
        self.assertIsNone(self.credentials.resolve_account("anything"))
        self.assertIsNone(self.credentials.resolve_account("x" + hashlib.sha256(b"user-9").hexdigest()[:24]))

    def test_a_banned_account_cannot_come_back_with_a_ticket(self) -> None:
        later = int(time.time()) + 600
        self.assertTrue(self._login(make_ticket("user-10", "Bad", later), conn="c1").accepted)
        account_name = "x" + hashlib.sha256(b"user-10").hexdigest()[:24]
        self.credentials.set_banned(account_name, True)
        self.service.active_sessions = ClassicActiveSessionRegistry()
        reply = self._login(make_ticket("user-10", "Bad", later), conn="c2")
        self.assertFalse(reply.accepted)
        self.assertEqual(reply.reason, "banned")

    def test_tickets_are_off_without_a_secret(self) -> None:
        service = create_mw_auth_service(
            CredentialStore(),
            IdentityStore(token_factory=lambda: "t."),
            active_sessions=ClassicActiveSessionRegistry(),
            ticket_secret=None,
        )
        reply = service.login(
            {"NAME": "x", "PASS": make_ticket("u", "Someone", int(time.time()) + 60), "PSES": "Public Key"},
            ClassicAuthContext(connection_id="c", client_ip="203.0.113.9", mask="Public Key"),
        )
        self.assertFalse(reply.accepted)
        self.assertEqual(reply.reason, "ticket_off")


if __name__ == "__main__":
    unittest.main()
