
from __future__ import annotations
import unittest
from src.command_authority import Command, CommandAuthority, FireStatus

class CmdTests(unittest.TestCase):
    def setUp(self):
        self.auth = CommandAuthority(b"secret", half_life_s=10)
        self.cmd = Command("c1", "ACS", "NOOP", {"n": 1})

    def test_fire_in_window(self):
        tok = self.auth.mint(self.cmd, now=100.0)
        r = self.auth.fire(self.cmd, tok, now=105.0)
        self.assertEqual(r.status, FireStatus.FIRED)

    def test_expired(self):
        tok = self.auth.mint(self.cmd, now=100.0)
        r = self.auth.fire(self.cmd, tok, now=200.0)
        self.assertEqual(r.reason, "EXPIRED")

    def test_replay(self):
        tok = self.auth.mint(self.cmd, now=100.0)
        self.auth.fire(self.cmd, tok, now=101.0)
        r = self.auth.fire(self.cmd, tok, now=102.0)
        self.assertEqual(r.reason, "TOKEN_REPLAY")

if __name__ == "__main__":
    unittest.main()
