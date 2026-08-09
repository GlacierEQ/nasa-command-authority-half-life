
"""Command authority half-life — expiring telecommand grants."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FireStatus(str, Enum):
    FIRED = "FIRED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class Command:
    command_id: str
    subsystem: str
    opcode: str
    args: dict


@dataclass(frozen=True)
class AuthorityToken:
    token_id: str
    command_digest: str
    not_before: float
    not_after: float
    mac: str


@dataclass(frozen=True)
class FireReceipt:
    status: FireStatus
    reason: str | None
    command_id: str
    token_id: str
    fingerprint: str


class CommandAuthority:
    def __init__(self, secret: bytes, half_life_s: float = 5.0):
        if half_life_s <= 0:
            raise ValueError("half_life_s must be positive")
        self._secret = secret
        self._half_life = half_life_s
        self._seq = 0
        self._used: set[str] = set()

    def command_digest(self, cmd: Command) -> str:
        return digest({"id": cmd.command_id, "sub": cmd.subsystem, "op": cmd.opcode, "args": cmd.args})

    def mint(self, cmd: Command, now: float) -> AuthorityToken:
        self._seq += 1
        tid = f"tok-{self._seq}"
        cd = self.command_digest(cmd)
        nb, na = now, now + self._half_life
        body = f"{tid}|{cd}|{nb}|{na}"
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return AuthorityToken(tid, cd, nb, na, mac)

    def _mac_ok(self, tok: AuthorityToken) -> bool:
        body = f"{tok.token_id}|{tok.command_digest}|{tok.not_before}|{tok.not_after}"
        exp = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(exp, tok.mac)

    def fire(self, cmd: Command, tok: AuthorityToken, now: float) -> FireReceipt:
        reason = None
        status = FireStatus.REFUSED
        if tok.token_id in self._used:
            reason = "TOKEN_REPLAY"
        elif not self._mac_ok(tok):
            reason = "BAD_MAC"
        elif self.command_digest(cmd) != tok.command_digest:
            reason = "COMMAND_MISMATCH"
        elif now < tok.not_before or now > tok.not_after:
            reason = "EXPIRED"
        else:
            status = FireStatus.FIRED
            self._used.add(tok.token_id)
        body = {
            "status": status.value,
            "reason": reason,
            "command_id": cmd.command_id,
            "token_id": tok.token_id,
        }
        return FireReceipt(status, reason, cmd.command_id, tok.token_id, digest(body))
