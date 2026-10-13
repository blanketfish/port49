"""The library's exceptions (decision 46 ruling 11). None carries a token or
the CLI's stdout: only the CLI's code, its printable detail, and the device."""


class Port49Error(Exception):
    def __init__(self, code, detail="", device=None):
        self.code, self.detail, self.device = code, detail, device
        super().__init__(str(self))

    def __str__(self):
        where = f"{self.device}: " if self.device else ""
        return f"port49: {where}{self.detail or self.code}"


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
        return said + (f": {self.detail}" if self.detail else "")


class MFARequired(Port49Error):
    """The device asks for a second factor that could not be given here: the CLI's
    per_login_mfa_required, or the broker's deny for it (reason kept)."""

    def __init__(self, code, detail="", device=None, requirement=None, reason=None):
        self.requirement, self.reason = requirement or {}, reason
        super().__init__(code, detail, device)

    def __str__(self):
        accept = ", ".join(self.requirement.get("accept", [])) or "a second factor"
        return (f"port49: {self.device}: asks for {accept} at each login, and it could not be given here "
                f"({self.detail or self.code}); run `port49 token {self.device}` at a terminal, and one proof "
                f"covers this agent's further logins for its reuse_for")


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
