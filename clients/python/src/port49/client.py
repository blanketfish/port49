"""Identity, mint, sweep and retry over the port49 CLI (design §17; decision 46)."""

import json
import time
from dataclasses import dataclass, field

from . import _run
from .errors import (BrokerRefused, Denied, DeviceFault, KeyUnavailable, MFARequired, NoAgent, Port49Error, SessionOver,
                     Temporary)

# The CLI's codes (spec §12) to their classes; any other is a Port49Error (no_token and
# agent_error are that on purpose: nothing a caller does differently).
CLASSES = {
    "no_agent": NoAgent, "agent_too_old": NoAgent,
    "session_over": SessionOver, "credential_revoked": SessionOver,
    "per_login_mfa_required": MFARequired,
    "touch_timeout": KeyUnavailable, "key_locked": KeyUnavailable, "key_absent": KeyUnavailable,
    "broker_refused": BrokerRefused,
    "broker_unavailable": Temporary,
    "revocation_running": Temporary, "connection_changed": Temporary,
}

# The codes that are an outage or a busy moment, not an answer: the only ones retried. A key or
# PIN failure, a deny, a broker_refused and a touch_timeout are never run again unasked.
RETRIED = {"revocation_running", "connection_changed", "broker_unavailable"}


@dataclass(frozen=True)
class Token:
    device: str
    address: str
    platform: str
    username: str
    login: str = field(repr=False)
    enable: "str | None" = field(default=None, repr=False)
    expires_at: "str | None" = None
    session_expires_at: "str | None" = None

    @classmethod
    def of(cls, item, device=None):
        return cls(item.get("device") or device or "", item.get("address", ""), item.get("platform", ""),
                   item.get("username", ""), item["login"], item.get("enable") or None, item.get("expires_at"),
                   item.get("session_expires_at"))


@dataclass(frozen=True)
class Refusal:
    device: str
    verdict: "str | None"
    reason: "str | None"
    error: "str | None"
    detail: str
    per_login_mfa: "dict | None" = None

    def exception(self):
        return error_for({"device": self.device, "verdict": self.verdict, "reason": self.reason,
                          "error": self.error, "detail": self.detail, "per_login_mfa": self.per_login_mfa})


@dataclass
class MintResults:
    tokens: dict
    refused: dict

    def without_tokens(self):
        """A copy with each token None (the device names stay): what pickle and copy of an error keep."""
        return MintResults({d: None for d in self.tokens}, dict(self.refused))

    def raise_for_refused(self):
        for r in self.refused.values():
            raise r.exception()


def answer(ran):
    """The one JSON object the CLI printed, or None. Never quoted in an error: it may hold a token."""
    try:
        obj = json.loads(ran.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def error_for(obj, device=None):
    device = obj.get("device") or device
    detail = _run.printable(obj.get("detail") or "")
    verdict, reason = obj.get("verdict"), obj.get("reason")
    if verdict and verdict != "permit":
        if reason == "per_login_mfa_required" or obj.get("per_login_mfa"):
            # The condition the CLI's per_login_mfa_required code names: one class for both, a
            # Workload's refused item and an Agent's failure alike (pre-flight M7).
            return MFARequired("per_login_mfa_required", detail, device, requirement=obj.get("per_login_mfa"),
                               reason=reason)
        return Denied(reason or verdict, detail, device, reason=reason, verdict=verdict)
    code = obj.get("error") or "agent_error"
    # A code that is not one of the CLI's is the broker's own fault code for this device (its item
    # says "error", "detail"); no_token is per-device too. agent_error is the agent's, not a device's.
    cls = CLASSES.get(code, Port49Error if code == "agent_error" else DeviceFault)
    if cls is MFARequired:
        return MFARequired(code, detail, device, requirement=obj.get("per_login_mfa"))
    return cls(code, detail, device)


def failed(ran, device, what):
    """The error for a run that printed no answer."""
    words = ran.stderr_tail.strip().splitlines()
    return Port49Error(f"exit_{ran.code}", words[-1] if words else f"{what} exited {ran.code}", device)


def refusal_of(err, device):
    """What a sweep keeps of a per-device failure: a deny, or a second factor this device wants."""
    if isinstance(err, MFARequired):
        if err.reason:  # the broker's deny
            return Refusal(device, "deny", err.reason, None, err.detail, err.requirement or None)
        return Refusal(device, None, None, err.code, err.detail, err.requirement or None)
    if isinstance(err, DeviceFault):
        return Refusal(device, None, None, err.code, err.detail)
    return Refusal(device, err.verdict, err.reason, None, err.detail)


class Agent:
    """A person's tokens, through the agent `port49 login` started."""

    def __init__(self, port49="port49", socket=None, attempts=3, timeout=None, stderr=None):
        self.port49, self.socket, self.attempts, self.timeout, self.stderr = port49, socket, attempts, timeout, stderr
        self._sleep = time.sleep

    def _argv(self, *args):
        argv = [self.port49, *args]
        if self.socket:
            argv[2:2] = ["--socket", self.socket]
        return argv

    def identity(self):
        ran = _run.run(self._argv("identity", "--json"), timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if ran.code != 0 or obj is None:
            raise failed(ran, None, "port49 identity")
        return obj

    def token(self, device, enable=False, ttl=None):
        args = ["token", "--json"] + (["--enable"] if enable else []) + (["--ttl", f"{int(ttl)}s"] if ttl else [])
        argv = self._argv(*args) + ["--", device]
        for attempt in range(self.attempts):
            got = self._once(argv, device)
            if isinstance(got, Token):
                return got
            if got.code not in RETRIED or attempt + 1 == self.attempts:
                raise got
            self._sleep(2 ** attempt)
        raise Port49Error("agent_error", "no attempts were made", device)

    def _once(self, argv, device):
        """One run: a Token or an exception (not raised). The answer, which may hold a token,
        stays in this frame, so no traceback of the caller's can carry it in its locals."""
        ran = _run.run(argv, timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if ran.code == 0 and obj and obj.get("verdict") == "permit" and obj.get("login"):
            return Token.of(obj, device)
        if obj is None or ran.code == 0:
            return failed(ran, device, "port49 token")
        return error_for(obj, device)

    def tokens(self, devices, enable=False, ttl=None):
        """One mint per device, in turn. What belongs to one device is collected: a deny, a second
        factor it wants, a fault the broker had deciding it. Anything else stops the run, and the
        error's .results holds the tokens minted so far."""
        res = MintResults({}, {})
        for d in devices:
            try:
                res.tokens[d] = self.token(d, enable, ttl)
            except (Denied, MFARequired, DeviceFault) as e:
                res.refused[d] = refusal_of(e, d)
            except Port49Error as e:
                e.results = res
                raise
        return res
