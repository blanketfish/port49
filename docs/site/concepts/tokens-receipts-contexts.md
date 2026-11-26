---
title: Tokens, receipts and contexts
description: What a token, a receipt and a context are, and how a device login uses each.
---

# Tokens, receipts and contexts

A device login touches three stored records. Each answers one question.

| Record | Question it answers | Written by | Lives |
|---|---|---|---|
| Token | May this one login on this one device proceed? | the broker, at mint | until spent or its `token_ttl` ends |
| Receipt | Is this a retransmission of a login already accepted? | port49d, at redemption | a sliding window, with a hard cap |
| Login context | Who is logged in here, and what may they do? | port49d, at redemption | until the session ends, is revoked or goes idle |

## The session

The person's session lasts hours, stays with the agent and is never sent to a device. The device token is
minted from the session automatically, lasts 30 to 900 seconds and is used once. One long-lived credential
pasted into devices would be a password with an expiry date, and a session with no per-device token would
need a certificate interaction for every device.

The agent holds one mutual-TLS connection to the broker while the network is up, and the broker does not
close an authenticated connection for being idle.

- The end time is fixed at login from `max_session_age`. Reconnects do not move it.
- A dropped connection does not end the session. The agent dials again at its next request with the same
  certificate and key, and every request carries the agent's random session ID, so the broker sees one
  session.
- A reconnect is another use of the key. A hardware key asks for its PIN or a touch again, because the
  broker turns TLS session resumption off.
- The broker stamps each new connection with a fresh `auth_time`, and a context's end is `auth_time` plus
  `max_session_age`. A context minted after a reconnect can therefore outlast the end the agent states, and
  so can a device-side ceiling counted from it.
- The session ends at its end time, on a revocation, when the broker stops trusting the certificate, or
  when the agent exits.

## The token

A token is an opaque handle: exactly 30 letters and digits, with no prefix and no separator, like
`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (a stand-in, not a value). It carries no claims. The identity, the groups
resolved at mint time and the device it is valid for live in the store, so deleting a token ends it at
once.

- One device. The token is stored under `(nas, username)`: the device (the NAS, in TACACS+ terms) and
  the device-facing username. port49d names the device from the connection's source address, through the
  inventory, never from anything the device sends. A token presented at another device is not there. Its
  first six characters are a keyed tag of the device, so port49d can tell a token cut for another device
  from one that expired. That is `device_mismatch`, which does not occur in normal operation, so alert on it.
- One use. Redemption is an atomic match-and-delete inside the set of tokens for that key. A cap on the
  set (`candidate_cap_reached`) refuses a mint, never a redemption, so a runaway client is told to stop
  while every token it already holds still works.
- Short TTL, per subject. `token_ttl` is set per subject in
  [policy](../reference/config/policy.md). An interactive login needs about a minute, and a batch job needs
  a window matching its run. A longer TTL widens replay for an unspent token, so size it to the sweep.
- Encrypted at rest. Tokens and contexts are sealed with a key held by the broker and port49d, so a store
  dump alone yields no credential. See [Secrets](../operate/secrets.md).
- Expiry is read on port49d's clock. Keep every broker and port49d host on NTP; the
  [requirements](../reference/requirements.md#clocks) say what skew does.

An `enable` login has no principal to type a name for, so the broker mints a pair: a login token and an
enable token, both bound to the device, both single use, sharing a TTL.

## The receipt

Devices retry, and a retry that found no token would fail intermittently. So port49d leaves a receipt
when it redeems a token: the decision and the context it created, keyed by
`(nas, username, credential_sha256)`. The key holds a hash of what was presented, the token for PAP and
ASCII and the exchange for CHAP. A byte-identical retransmission gets the stored decision
(`receipt_replayed`) and the same context. A different password for the same user finds nothing and is
judged on its own merits.

A receipt is a sliding window. Each presentation it answers extends it by `receipt_idle_ttl` (default
15 minutes), up to `receipt_max_age` (default 2 hours) from the first redemption. A presentation past
either bound is a plain FAIL on the wire, exactly as a wrong password is, and the log says `token_spent`.
Interactive logins present once and never slide. A client that re-presents the same credential does. The
keys are in the [port49d configuration reference](../reference/config/port49d.md).

How many times a client library authenticates differs between libraries. On EOS, pyeapi authenticated once per task (10 `authorize_session` records for ten tasks, [the arista_eos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-arista_eos.md)).
On NX-OS, NAPALM's `nxos` driver made 23 for ten tasks, all in one context ([the cisco_nxos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-cisco_nxos.md)).

!!! warning "Unmeasured"
    Whether any other client library, or any other platform, authenticates more or fewer times per task
    is unknown ([L15](../reference/lab-register.md#l15), open). Do not size `receipt_idle_ttl` on a count you have not measured for your
    own client.

The receipt key does not include the line (the device's `port`), so a spent token replays on that device
over any transport until the window ends. `receipt_idle_ttl` and `receipt_max_age` are the bound on a
leaked spent token, so keep them as short as your automation allows. [Reason codes](../reference/reason-codes.md)
lists what else `token_spent` covers.

## The login context

A context is "this principal's authorization on this device". port49d creates it only on a successful
redemption, keyed `(nas, username)`. A session port49 did not authenticate has no context, so it is denied.

It records the principal, the groups, the privilege, the compiled policy for this device, the credential
that authorized it (certificate fingerprint, issuer and serial, or the OIDC `sid` and `sub`), the session
clock and a revocation mark. Authorization requests carry only `user`, `port`, `rem_addr` and the privilege
level, and the device never sends the credential, so the context is the only place port49d can learn who it
is talking to.

- **Keyed on the username, not the line.** `port` and `rem_addr` are recorded for the log and for
  accounting and are part of no key, because a device does not present the same `port` at login and at
  authorization.
- **Logging in again joins it.** A second login by the same principal under the same username on
  the same device keeps the context, only raises privilege, and never shortens a window already
  granted.
- **It belongs to one principal.** A login by anyone else under that username starts a
  fresh context and logs the replacement (`session.replaced_ctx_id`). Usernames are unique per
  subject, so this happens only if that check was bypassed.
- **It ends** when its session ceiling (a role's `max_session_age`, counted from the person's
  authentication) passes, when it sits idle past `context_idle_ttl`, or when it is revoked. See
  [Revocation](revocation.md). If the broker is unreachable past `session.staleness_ceiling`, port49d
  denies `context_stale` and keeps the context, so recovery resumes it.
- **It is sealed.** Every field the authorizer trusts is encrypted and bound to its `(nas, username)`
  key, so a store write cannot raise a privilege, lift a revocation or move a record to another device.
  A writer to the store can still put back a record port49 sealed earlier, which the design document lists
  exactly. Treat store write access as a privilege to protect.

!!! warning "Session control stops at the device"
    TACACS+ has no server-to-device disconnect. Everything above stops port49 from authorizing. It
    does not close a connection. A platform that asks port49 only at login never asks again, so a ceiling
    or a revocation reaches a context nobody reads there. Junos is one, unless its
    `authorization-time-interval` is set. [Revocation](revocation.md) has what was measured.
