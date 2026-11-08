---
title: Tokens, receipts and contexts
description: What a token, a receipt and a context are, and how a device login uses each.
---

# Tokens, receipts and contexts

A device login touches three stored records. Each exists to answer one question.

| Record | Question it answers | Written by | Lives |
|---|---|---|---|
| **Token** | May this one login on this one device proceed? | the broker, at mint | until spent or its `token_ttl` ends |
| **Receipt** | Is this a retransmission of a login already accepted? | port49d, at redemption | a sliding window, with a hard cap |
| **Login context** | Who is logged in here, and what may they do? | port49d, at redemption | until the session ends, is revoked or goes idle |

## Two credentials, two lifetimes

The person's **session** is the held connection described in [Concepts](index.md): hours long, held by the
agent, never sent to a device. The **device token** is minted from it automatically, lasts between 30 and
900 seconds, and is used once. A single long-lived credential pasted into devices would be a password
with an expiry date, and a session with no per-device token would need a certificate interaction for
every device. Two credentials avoid both.

## The token

A token is an opaque handle: exactly 30 letters and digits, with no prefix and no separator, like
`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (a stand-in, not a value). It carries no claims. The identity, the groups resolved
from the directory at mint time and the device it is valid for all live in the store, which is why
deleting a token ends it at once.

- **One device.** The token is stored under `(nas, username)`: the device (the NAS, in TACACS+ terms) and
  the device-facing username. A token presented at another device is simply not there.
  The first six characters are a keyed tag of the device, so port49d can tell a token cut for another
  device from one that expired. That is `device_mismatch`, and it does not occur in normal operation,
  so it is worth alerting on.
- **One use.** Redemption is an atomic match-and-delete inside the set of tokens for that key. The
  set holds only unspent, unexpired tokens, usually one. A cap on the set (`candidate_cap_reached`)
  refuses a *mint*, never a redemption, so a runaway client is told to stop while every token it
  already holds still works.
- **Short TTL, per subject.** `token_ttl` is a subject's setting in policy ([policy reference](../reference/config/policy.md)), not a global: an interactive login needs about a
  minute, a batch job walking thousands of devices needs a window matching its run. A longer TTL widens
  replay only for an *unspent* token, but it also keeps that many recoverable secrets in the store for
  that long, so size it to the sweep.
- **Encrypted at rest.** CHAP makes port49d recompute a digest from the plaintext token, so the store
  must hold it recoverably. Tokens and contexts are therefore sealed with a key held by the broker and
  port49d, not by the store. A store dump alone yields no credential. See
  [Secrets](../operate/secrets.md) for where the key lives.
- **Expiry is the store's.** The broker writes a relative TTL; presence means valid, absence means
  expired or spent. No clock comparison between broker and port49d decides a login.

An `enable` login has no principal to type a name for, so the broker mints a **pair**: a login token
and an enable token, both bound to the device, both single use, sharing a TTL. Tools that already have an
enable or secret field take the pair unchanged.

## The receipt

Devices retry. A TCP reset between port49d's read and its reply, or a slow store, makes the device send
the same login again. If redeeming deleted the token and nothing else, the retry would find nothing and
the login would fail intermittently.

So when port49d redeems a token it leaves a **receipt**: the decision it made and the context it
created, keyed by `(nas, username, credential_sha256)`. The key holds a hash of what was *presented*.
For PAP and ASCII that is the token; for CHAP it is the exchange, which proves possession without
carrying it. A byte-identical retransmission finds its own receipt and gets the stored decision
(`receipt_replayed`) and the same context, not a second one. A different password for the same user
finds nothing and is judged on its own merits.

A receipt is a sliding window, not a fixed one. Each presentation it answers extends it by
`receipt_idle_ttl` (default 15 minutes), up to `receipt_max_age` (default 2 hours) from the first
redemption. A presentation past either bound is a plain FAIL on the wire, exactly as a wrong password
is, and the log says `token_spent`. Interactive logins present once and never slide; a client that
re-presents the same credential does, with no flag to set. The keys are in the
[port49d configuration reference](../reference/config/port49d.md).

How many times a client library authenticates differs between libraries. On EOS, pyeapi authenticated once per task (10 `authorize_session` records for ten tasks, [the arista_eos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-arista_eos.md)).
On NX-OS, NAPALM's `nxos` driver made 23 for ten tasks, all in one context ([the cisco_nxos note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L15-clients-cisco_nxos.md)).

!!! warning "Unmeasured"
    Whether any other client library, or any other platform, authenticates more or fewer times per task
    is unknown ([L15](../reference/lab-register.md#l15), open). Do not size `receipt_idle_ttl` on a count you have not measured for your
    own client.

`token_spent` also covers a receipt whose context no longer exists (it was replaced or reclaimed), and
a token brought back by a store restore. The device simply prompts again. See
[Reason codes](../reference/reason-codes.md) for each meaning.

Because the receipt key no longer includes the line, a spent token replays on that device over any
transport until the window ends. `receipt_idle_ttl` and `receipt_max_age` are therefore the bound on a
leaked *spent* token. Keep them as short as your automation allows.

## The login context

A context is "this principal's authorization on this device". port49d creates it **only** on a
successful redemption, keyed `(nas, username)`. A session port49 did not authenticate has no context, so
it is denied: there is nothing to authorize it on.

The context records the principal, the groups, the privilege, the compiled policy for this device, the
credential that authorized it (certificate fingerprint, issuer and serial, or the OIDC `sid` and `sub`),
the session clock and a revocation mark. Authorization requests carry only `user`, `port`, `rem_addr`
and the privilege level; the device never sends the credential, so the context is the only place port49d
can learn who it is talking to.

- **Keyed on the username, not the line.** `port` and `rem_addr` are recorded for the log and for
  accounting and are part of no key, because a device does not present the same `port` at login and at
  authorization. A second login by the same principal under the same username on the same device
  **joins** the live context rather than replacing it: it keeps the context, raises privilege only, and
  never shortens a window already granted.
- **Another principal's login replaces it**, and the replace is logged.
- **It ends** when its session ceiling (a role's `max_session_age`, counted from the person's
  authentication) passes, when it sits idle past `context_idle_ttl`, or when it is revoked. See
  [Revocation](revocation.md). If the broker is unreachable past `session.staleness_ceiling`, port49d
  denies `context_stale` and keeps the context, so recovery resumes it.
- **It is sealed.** Every field the authorizer trusts is encrypted and bound to its `(nas, username)`
  key, so a store write cannot raise a privilege, lift a revocation or move a record to another device.
  What a writer to the store can still do is put back a record port49 sealed earlier. The design document
  lists that residual replay exactly; treat store write access as a privilege to protect.

!!! warning "Session control stops at the device"
    TACACS+ has no server-to-device disconnect. Everything above stops port49 from *authorizing*; it
    does not close a connection. A platform that asks port49 only at login never asks again, so a ceiling
    or a revocation reaches a context nobody reads there. Junos is one, unless its
    `authorization-time-interval` is set. [Revocation](revocation.md) has what was measured.
