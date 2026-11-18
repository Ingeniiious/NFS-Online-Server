"""ExA Cup hardening on top of upstream (docs/NFS-ONLINE.md in the ExA Cup repo).

H1: an uppercase MW callback may act as a logged-in player only from that
player's own connection, or from a socket that is not logged in and shares the
player's IP. H2/H3: in-game `acct` is off for Most Wanted, so it neither
creates accounts nor answers whether a password is right.
"""

import unittest

from classic.accounts.credentials import CredentialStore
from classic.accounts.identity import IdentityStore
from classic.games.most_wanted.auth import create_auth_service as create_mw_auth_service
from classic.lobby.models import ClassicPreloginContext
from classic.lobby.router import _mw_callback_allowed, _mw_callback_route
from classic.protocols.auth import ClassicActiveSessionRegistry, ClassicAuthContext
from classic.protocols.password import make_password_token


def _ctx(connection_id: str, ip: str, *, logged_in: bool = False) -> ClassicPreloginContext:
    auth = ClassicAuthContext(connection_id=connection_id, client_ip=ip)
    if logged_in:
        auth.account = object()  # any account: the guard only asks "is one set"
    return ClassicPreloginContext(auth=auth, authenticated=logged_in)


class MostWantedCallbackGuardTests(unittest.TestCase):
    def test_the_players_own_connection_may(self) -> None:
        player = _ctx("p", "198.51.100.7", logged_in=True)
        self.assertTrue(_mw_callback_allowed(player, player))

    def test_a_side_socket_from_the_players_ip_may(self) -> None:
        player = _ctx("p", "198.51.100.7", logged_in=True)
        side = _ctx("side", "198.51.100.7")
        self.assertTrue(_mw_callback_allowed(side, player))

    def test_a_stranger_may_not(self) -> None:
        player = _ctx("p", "198.51.100.7", logged_in=True)
        stranger = _ctx("x", "203.0.113.9")
        self.assertFalse(_mw_callback_allowed(stranger, player))

    def test_another_logged_in_player_may_not_even_from_the_same_ip(self) -> None:
        player = _ctx("p", "198.51.100.7", logged_in=True)
        neighbour = _ctx("n", "198.51.100.7", logged_in=True)
        self.assertFalse(_mw_callback_allowed(neighbour, player))

    def test_no_address_on_either_side_is_never_a_match(self) -> None:
        player = _ctx("p", "", logged_in=True)
        side = _ctx("side", "")
        self.assertFalse(_mw_callback_allowed(side, player))

    def test_the_race_host_may_admit_and_release_a_guest(self) -> None:
        host = _ctx("h", "198.51.100.1", logged_in=True)
        guest = _ctx("g", "203.0.113.2", logged_in=True)
        host_side = _ctx("hs", "198.51.100.1")
        for command in ("GJOI", "GLEA"):
            self.assertTrue(_mw_callback_allowed(host, guest, host, command))
            self.assertTrue(_mw_callback_allowed(host_side, guest, host, command))

    def test_the_race_host_may_not_chat_rank_or_touch_personas_as_a_guest(self) -> None:
        host = _ctx("h", "198.51.100.1", logged_in=True)
        guest = _ctx("g", "203.0.113.2", logged_in=True)
        for command in ("MESG", "RANK", "CPER", "DPER", "GSTA", "AUXI"):
            self.assertFalse(_mw_callback_allowed(host, guest, host, command), command)

    def test_each_route_is_named_for_the_log(self) -> None:
        host = _ctx("h", "198.51.100.1", logged_in=True)
        host_side = _ctx("hs", "198.51.100.1")
        guest = _ctx("g", "203.0.113.2", logged_in=True)
        guest_side = _ctx("gs", "203.0.113.2")
        stranger = _ctx("x", "192.0.2.50")
        self.assertEqual(_mw_callback_route(guest, guest, host, "GSTA"), "own")
        self.assertEqual(_mw_callback_route(guest_side, guest, host, "GSTA"), "side")
        self.assertEqual(_mw_callback_route(host, guest, host, "GJOI"), "host")
        self.assertEqual(_mw_callback_route(host_side, guest, host, "GJOI"), "host-side")
        self.assertIsNone(_mw_callback_route(stranger, guest, host, "GJOI"))
        self.assertIsNone(_mw_callback_route(host, guest, host, "MESG"))

    def test_a_stranger_cannot_use_the_host_path(self) -> None:
        host = _ctx("h", "198.51.100.1", logged_in=True)
        guest = _ctx("g", "203.0.113.2", logged_in=True)
        stranger = _ctx("x", "192.0.2.50")
        self.assertFalse(_mw_callback_allowed(stranger, guest, host, "GJOI"))
        self.assertFalse(_mw_callback_allowed(stranger, guest, None, "GJOI"))


class MostWantedAccountCreationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.credentials = CredentialStore(salt_factory=lambda size: b"\x31" * size)
        self.credentials.create_account("driver", "right", persona="Racer", email="")
        self.service = create_mw_auth_service(
            self.credentials,
            IdentityStore(token_factory=lambda: "classic-session-token."),
            active_sessions=ClassicActiveSessionRegistry(),
        )

    def _acct(self, name: str, password: str):
        return self.service.create_account(
            {"NAME": name, "PERS": name, "PASS": make_password_token(password, "Public Key"), "PSES": "Public Key"},
            ClassicAuthContext(connection_id="c", client_ip="203.0.113.9", mask="Public Key"),
        )

    def test_acct_creates_nothing(self) -> None:
        reply = self._acct("newcomer", "anything")
        self.assertFalse(reply.accepted)
        self.assertEqual(reply.reason, "create_disabled")
        self.assertIsNone(self.credentials.resolve_account("newcomer"))

    def test_acct_does_not_say_whether_a_password_is_right(self) -> None:
        right = self._acct("driver", "right")
        wrong = self._acct("driver", "wrong")
        self.assertEqual((right.accepted, right.reason), (False, "create_disabled"))
        self.assertEqual((wrong.accepted, wrong.reason), (False, "create_disabled"))
        self.assertEqual(right.frames, wrong.frames)


if __name__ == "__main__":
    unittest.main()
