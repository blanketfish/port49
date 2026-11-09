"""The library's exceptions (decision 46 ruling 11). None carries the CLI's
stdout, and str(), repr() and args hold only the CLI's code, its printable
detail, and the device.

The one attribute that holds tokens is .results, set on the error of a run that
stopped part way (Agent.tokens, Workload): the tokens minted so far, for the
caller's use in this process. It never reaches str or repr, and pickle and copy
leave the tokens out of it (__reduce__): a rebuilt exception keeps the device
names and the codes, with None for each token."""


def clean(text):
    """text with every non-printable character (C0 and C1 controls, DEL, newline, ESC) made '?': a
    device name, code, reason or detail comes from inventory or the CLI's JSON, and a message that
    reaches a terminal must not carry an escape sequence or forge a line."""
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _rebuild(cls, args, state):
    e = cls.__new__(cls)
    Exception.__init__(e, *args)
    e.__dict__.update(state)
    return e


class Port49Error(Exception):
    def __init__(self, code, detail="", device=None):
        self.code, self.detail, self.device = code, detail, device
        super().__init__(str(self))

    def __reduce__(self):
        state = dict(self.__dict__)
        results = state.get("results")
        if results is not None:
            # An object with no without_tokens() is not known to be free of tokens: dropped whole.
            scrub = getattr(results, "without_tokens", None)
            state["results"] = scrub() if scrub else None
        return _rebuild, (type(self), self.args, state)

    def __str__(self):
        where = f"{self.device}: " if self.device else ""
        return clean(f"port49: {where}{self.detail or self.code}")


class NotInstalled(Port49Error):
    """The port49 CLI is not there."""


class NoAgent(Port49Error):
    """No agent answers (no_agent), or it predates this port49 (agent_too_old): run port49 login."""


class SessionOver(Port49Error):
    """The agent's session ended (session_over) or was revoked (credential_revoked)."""


class Denied(Port49Error):
    """The broker denied the device; reason is its §5.7 code."""

    def __init__(self, code, detail="", device=None, reason=None, verdict=None):
        self.reason, self.verdict = reason, verdict
        super().__init__(code, detail, device)

    def __str__(self):
        said = f"port49: {self.device}: {self.verdict or 'deny'} {self.reason or self.code}"
        return clean(said + (f": {self.detail}" if self.detail else ""))


class MFARequired(Port49Error):
    """The device asks for a second factor that could not be given here: the CLI's
    per_login_mfa_required, or the broker's deny for it (reason kept)."""

    def __init__(self, code, detail="", device=None, requirement=None, reason=None):
        self.requirement, self.reason = requirement or {}, reason
        super().__init__(code, detail, device)

    def __str__(self):
        accept = ", ".join(self.requirement.get("accept", [])) or "a second factor"
        return clean(f"port49: {self.device}: asks for {accept} at each login, and it could not be given here "
                     f"({self.detail or self.code}); a person must give it, so an agent stops here and asks one: at "
                     f"a terminal, a person's `port49 ssh {self.device}` proves it, and the proof covers their "
                     f"port49 agent's further logins for its reuse_for; a workload's proof is a person's touch on its "
                     f"touch_key")


class KeyUnavailable(Port49Error):
    """The key timed out waiting for a touch, is locked, or is gone."""


class BrokerRefused(Port49Error):
    """The broker refused a proof with a 4xx, or its certificate was refused (its CRL): not retried."""


class Temporary(Port49Error):
    """Nothing was sent to mint with, or the broker could not answer by the deadline: run again."""

    def __init__(self, code, detail="", device=None, results=None):
        self.results = results
        super().__init__(code, detail, device)


class DeviceFault(Port49Error):
    """The broker could not decide this one device (device_unconfigured, attribute_too_long,
    attribute_unsafe, broker_error) or minted it no token (no_token): the other devices are unaffected."""


class Final(Port49Error):
    """A workload run that cannot mint until someone acts (exit 77 with no answer)."""


class HostKeyError(Port49Error):
    """A host key that is not the one filed for the device, or that cannot be checked."""
