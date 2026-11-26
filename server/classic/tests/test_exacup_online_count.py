"""ExA Cup: the runtime status's player count (players signed in to a game's lobby)."""

from __future__ import annotations

import unittest
from threading import RLock
from types import SimpleNamespace

from classic.app import ClassicOnlineApplication


class OnlineCountTests(unittest.TestCase):
    def test_counts_only_signed_in_players_with_a_persona(self) -> None:
        peers = {
            1: SimpleNamespace(authenticated=True, persona_selected=True),
            2: SimpleNamespace(authenticated=True, persona_selected=False),   # still choosing a persona
            3: SimpleNamespace(authenticated=False, persona_selected=False),  # never signed in
            4: SimpleNamespace(authenticated=True, persona_selected=True),
        }
        prelogin = SimpleNamespace(_connections_lock=RLock(), _connections=peers)
        self.assertEqual(ClassicOnlineApplication._online_count(prelogin), 2)

    def test_an_empty_lobby_is_zero(self) -> None:
        prelogin = SimpleNamespace(_connections_lock=RLock(), _connections={})
        self.assertEqual(ClassicOnlineApplication._online_count(prelogin), 0)


if __name__ == "__main__":
    unittest.main()
