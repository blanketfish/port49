"""Identity, mint, sweep and retry over the port49 CLI (design §17; decision 46)."""

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from . import _run
from .errors import (BrokerRefused, Denied, DeviceFault, Final, KeyUnavailable, MFARequired, NoAgent, Port49Error,
                     SessionOver, Temporary)

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
        obj = json.loads(ran.stdout)
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


def _by_exit(ran, what):
    """The error for a workload run that printed no answer: by its exit code (75 temporary, 77 final)."""
    err = failed(ran, None, what)
    return (Temporary if ran.code == 75 else Final if ran.code == 77 else Port49Error)(err.code, err.detail, None)


def _sweep_of(obj):
    """(MintResults, stopped code or None) of a `workload token --format json` object. A null list is
    an empty one. Raises KeyError, TypeError or AttributeError on a shape that is not the CLI's."""
    res = MintResults(
        {it["device"]: Token.of(it) for it in obj.get("results") or [] if it.get("login")},
        {r["device"]: Refusal(r["device"], r.get("verdict"), r.get("reason"), r.get("error"),
                              _run.printable(r.get("detail") or ""), r.get("per_login_mfa"))
         for r in obj.get("refused") or []})
    if "stopped" not in obj:
        return res, None
    stop = obj["stopped"]
    return res, stop if isinstance(stop, str) and stop else "agent_error"


class Workload:
    """A machine's tokens: `port49 workload token`, which reads the certificate and key at every run
    (design §17). The CLI pages, retries within its deadline under one Idempotency-Key per page, checks
    the broker's CRL and proves a touch with touch_key. It runs the CLI once and never again: a page
    in flight when the deadline ran out may already be minted, and a new run has a new Idempotency-Key
    (decision 46 ruling 11).

    A run that stopped before it finished (the CLI's `stopped` key) never returns: it raises the class of
    its code with what was minted on .results and the devices it left in .results.refused."""

    def __init__(self, broker, broker_ca, cert, key, touch_key=None, broker_crl=None, port49="port49",
                 deadline=None, timeout=None, stderr=None):
        self.port49, self.timeout, self.stderr = port49, timeout, stderr
        self.flags = ["--broker", broker, "--broker-ca", broker_ca, "--cert", cert, "--key", key]
        if touch_key:
            self.flags += ["--touch-key", touch_key]
        if broker_crl:
            self.flags += ["--broker-crl", broker_crl]
        if deadline:
            self.flags += ["--deadline", f"{int(deadline)}s"]

    def identity(self):
        ran = _run.run([self.port49, "workload", "identity", *self.flags, "--json"], stdin=subprocess.DEVNULL,
                       timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if ran.code != 0 or obj is None:
            raise _by_exit(ran, "port49 workload identity")
        return obj

    def tokens(self, devices=None, scope=None, enable=False, ttl=None, purpose=None):
        if (devices is None) == (scope is None):
            raise ValueError("name devices or a scope, not both")
        if devices is not None:
            devices = list(dict.fromkeys(devices))
            # The CLI trims a name and skips one starting with "#": it would come back renamed or not at all.
            if not devices or any(not d or d != d.strip() or d.startswith("#") or any(c in d for c in "\r\n")
                                  for d in devices):
                raise ValueError("devices must be a non-empty list of names, none empty, padded with whitespace, "
                                 "starting with # or holding a line break")
        flags = ["--enable"] if enable else []
        flags += ["--ttl", f"{int(ttl)}s"] if ttl else []
        flags += ["--purpose", purpose] if purpose else []
        res = MintResults({}, {})
        err = self._once(flags, devices, scope, res)
        if err is not None:
            err.results = res
            raise err
        return res

    def _once(self, flags, devices, scope, res):
        """The one run, its answer merged into res: the error to raise, or None. The answer, which
        may hold tokens, stays in this frame, so no traceback of the caller's can carry it in its
        locals."""
        argv = [self.port49, "workload", "token", *self.flags, "--format", "json", *flags]
        with tempfile.TemporaryDirectory(prefix="port49-") as tmp:
            if scope is not None:
                argv += ["--scope", scope]
            else:
                path = os.path.join(tmp, "devices")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("".join(d + "\n" for d in devices))
                argv += ["--devices-file", path]
            ran = _run.run(argv, stdin=subprocess.DEVNULL, timeout=self.timeout, stderr=self.stderr,
                           oversize_hint="; write the tokens with --out instead, or split the sweep into smaller ones")
        obj = answer(ran)
        if obj is None:
            return _by_exit(ran, "port49 workload token")
        try:
            got, stop = _sweep_of(obj)
        except (KeyError, TypeError, AttributeError):
            return Port49Error(f"exit_{ran.code}", "port49 workload token printed an answer that is not its own")
        res.tokens, res.refused = got.tokens, got.refused
        if stop is not None:
            # What the stop left is in refused under its code, with no verdict of the broker's.
            left = [r for r in res.refused.values() if r.error == stop and not r.verdict]
            detail = next((r.detail for r in left if r.detail), "") or f"the run stopped: {stop}"
            return CLASSES.get(stop, Port49Error)(stop, detail, None)
        if ran.code == 75:
            return Temporary("exit_75", "the broker did not answer every device by the deadline; what was minted "
                             "is in .results", None)
        return None
