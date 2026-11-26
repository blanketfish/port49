---
title: Tokens, receipts and contexts
description: What a token, a receipt and a context are, and how a device login uses each.
---

# Tokens, receipts and contexts

A device login touches three stored records. The broker writes the token at mint, and port49d writes the
receipt and the login context at redemption.

## The session

The person's session lasts hours, stays with the agent and is never sent to a device. The device token is
minted from it automatically, so no long-lived credential is ever pasted into a device. The agent holds one
mutual-TLS connection to the broker while the network is up, and the broker does not close an authenticated
connection for being idle.

- The end time is fixed at login from `max_session_age`. Reconnects do not move it.
- A dropped connection does not end the session. The agent dials again at its next request with the same
  certificate and key and its random session ID, so the broker sees one session.
- A reconnect is another use of the key, so a hardware key asks for its PIN or a touch again. The broker
  turns TLS session resumption off.
- Each new connection gets a fresh `auth_time`, and a context's end is `auth_time` plus `max_session_age`.
  A context minted after a reconnect can outlast the end the agent states, and so can a device-side ceiling
  counted from it.
- The session ends at its end time, on a revocation, when the broker stops trusting the certificate, or when
  the agent exits.

## The token

A token is an opaque handle: exactly 30 letters and digits, with no prefix and no separator, like
`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (a stand-in, not a value). It carries no claims. The identity, the groups
and the device it is valid for live in the store, so deleting a token ends it at once.

- One device. The token is stored under `(nas, username)`: the device (the NAS, in TACACS+ terms) and the
  device-facing username. port49d names the device from the connection's source address, through the
  inventory, never from anything the device sends. A token cut for another device is `device_mismatch`,
  which does not occur in normal operation, so alert on it.
- One use. Redemption is an atomic match-and-delete. A cap on the set of tokens (`candidate_cap_reached`)
  refuses a mint, never a redemption.
- Short TTL, per subject. `token_ttl` is 30 to 900 seconds, set per subject in
  [policy](../reference/config/policy.md). A longer TTL widens replay for an unspent token, so size it to
  the sweep.
- Encrypted at rest with a key held by the broker and port49d, so a store dump alone yields no credential.
  See [Secrets](../operate/secrets.md).
- Expiry is read on port49d's clock. Keep every broker and port49d host on NTP; the
  [requirements](../reference/requirements.md#clocks) say what skew does.

An `enable` login gets a pair: a login token and an enable token, both bound to the device, both single use,
sharing a TTL.

## The receipt

Devices retry, so port49d leaves a receipt when it redeems a token: the decision and the context it created,
keyed by `(nas, username, credential_sha256)`. The key holds a hash of what was presented, the token for PAP
and ASCII and the exchange for CHAP. A byte-identical retransmission gets the stored decision
(`receipt_replayed`) and the same context. A different password for the same user is judged on its own.

A receipt is a sliding window. Each presentation it answers extends it by `receipt_idle_ttl` (default
15 minutes), up to `receipt_max_age` (default 2 hours) from the first redemption. A presentation past either
bound is a plain FAIL on the wire, as a wrong password is, and the log says `token_spent`. Interactive logins
present once and never slide. The receipt key does not include the line (`port`), so a spent token replays on
that device over any transport until the window ends. The two keys, in the
[port49d configuration reference](../reference/config/port49d.md), bound a leaked spent token, so keep them
short. [Reason codes](../reference/reason-codes.md) lists what else `token_spent` covers.

Client libraries differ in how often they authenticate. On EOS, pyeapi authenticated once per task (10 `authorize_session` records for ten tasks, [the arista_eos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-arista_eos.md)).
On NX-OS, NAPALM's `nxos` driver made 23 for ten tasks, all in one context ([the cisco_nxos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-cisco_nxos.md)).

!!! warning "Unmeasured"
    Whether any other client library, or any other platform, authenticates more or fewer times per task
    is unknown ([L15](../reference/lab-register.md#l15), open). Do not size `receipt_idle_ttl` on a count you have not measured for your
    own client.

## The login context

A context is "this principal's authorization on this device". port49d creates it only on a successful
redemption, keyed `(nas, username)`. A session port49 did not authenticate has no context, so it is denied.
It records the principal, the groups, the privilege, the compiled policy for this device, the credential that
authorized it, the session clock and a revocation mark. The device never sends the credential, so the context
is the only place port49d can learn who it is talking to.

- **Keyed on the username, not the line.** `port` and `rem_addr` are recorded for the log and accounting and
  are part of no key, because a device does not present the same `port` at login and at authorization.
- **Logging in again joins it.** A second login by the same principal under the same username on
  the same device keeps the context, only raises privilege, and never shortens a window already
  granted.
- **It belongs to one principal.** A login by anyone else under that username starts a
  fresh context and logs the replacement (`session.replaced_ctx_id`). Usernames are unique per
  subject, so this happens only if that check was bypassed.
- **It ends** when its session ceiling (a role's `max_session_age`, counted from the person's
  authentication) passes, when it sits idle past `context_idle_ttl`, or when it is
  [revoked](revocation.md). If the broker is unreachable past `session.staleness_ceiling`, port49d denies
  `context_stale` and keeps the context, so recovery resumes it.
- **It is sealed.** Every field the authorizer trusts is encrypted and bound to its `(nas, username)` key, so
  a store write cannot raise a privilege, lift a revocation or move a record to another device. A writer to the store can still
  put back a record port49 sealed earlier, so protect store write access.

!!! warning "Session control stops at the device"
    TACACS+ has no server-to-device disconnect. Everything above stops port49 from authorizing. It
    does not close a connection. A platform that asks port49 only at login never asks again, so a ceiling
    or a revocation reaches a context nobody reads there. Junos is one, unless its
    `authorization-time-interval` is set. [Revocation](revocation.md) has what was measured.
