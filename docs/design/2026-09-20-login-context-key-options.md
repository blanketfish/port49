# Login-context key — what the wire actually gives us

**Date:** 2026-09-20. **Status:** decision memo for the owner. Nothing here changes a spec or
design sentence; it proposes the change and prices it.

> **Corrected 2026-09-23.** This memo said two concurrent vEOS sessions both reported `vty4` at
> authorization. The 2026-09-22 vEOS run shows two concurrent sessions on **different** vtys from
> session authorization onward — `alice02` on `vty4`, `alice03` on `vty6`, 15:57:48–15:57:55 — and
> both on `ssh` at authentication (`tests/lab/logs/decisions-arista_eos.jsonl`, git-ignored; the
> records are quoted in §1). The conclusion stands: `ssh` at the authentication START is what the
> context would have to be keyed on, and it separates nothing. The N9Kv observations are unchanged.

Every device-behavior statement below is marked **measured** (with the note or log file) or
**unmeasured**. Nothing is asserted from vendor documentation.

---

## 1. Evidence: what differs between two concurrent sessions

The question the key has to answer is narrow: **at the moment port49 must look up a context —
the authorization request — what field tells session A from session B?** A field only counts
if it is present in *both* the authentication START (where the context is created) and the
authorization request (where it is read).

### arista_eos — vEOS-lab 4.32.2F

Measured from `tests/lab/logs/decisions-arista_eos.jsonl` (2026-09-17 run, 64 records) and
`tests/lab/results/L1-arista_eos.md`.

| candidate | authen START | author request | acct START | acct STOP | unique per concurrent session? |
|---|---|---|---|---|---|
| `port` | `ssh` | `ssh` **or** `vty<n>` | `ssh` | `ssh` or `vty<n>` | **not at authentication** — both concurrent sessions reported `ssh` there; from session authorization onward each has its own vty (`vty4`, `vty6`; corrected 2026-09-23) |
| `rem_addr` | `172.100.100.1` | same | same | same | **no** — one jump host, identical for both |
| `user` | present | present | present | present | yes in the lab *by construction* (one username per login); no in production |
| `task_id` | absent | absent | `8`,`10`,`11`… | pairs with its START | yes — device-unique and monotonic, **but accounting only** |
| `session_pid`-like AV | absent | absent | absent | absent | EOS sends none |
| TACACS `session_id` | **unmeasured** | **unmeasured** | **unmeasured** | **unmeasured** | see gap below |
| TCP connection / source port | **unmeasured** | | | | see gap below |
| timing adjacency | authen→author ~70–230 ms apart (measured from record timestamps) | | | | orders, does not identify |

**Two things in that table are not in the committed L1 note and change the conclusion.**

1. **`port` is not stable for a session's life on vEOS.** It is `ssh` during authentication
   and the first exec accounting START, and becomes `vty<n>` once a vty is allocated. Measured:
   `alice02`, `alice03` and `alice06` each show `ssh` at `redeem` and a vty at
   `authorize_session`. Two *concurrent* sessions get **different** vtys, stable from
   `authorize_session` onward — the 2026-09-22 run, `tests/lab/logs/decisions-arista_eos.jsonl`:

   | time | event | user | port |
   |---|---|---|---|
   | 15:57:48.801 | redeem | alice02 | `ssh` |
   | 15:57:49.002 | authorize_session | alice02 | `vty4` |
   | 15:57:53.817 | redeem | alice03 | `ssh` |
   | 15:57:54.020 | authorize_session | alice03 | `vty6` |
   | 15:57:54.988 | escalate | alice03 / alice02 | `vty6` / `vty4` |
2. **The instability is what breaks the lookup today.** All twelve session authorizations in
   that log are shown below, and the correlation is exact — every session that changed to
   `vty4` was denied, every session that stayed `ssh` matched:

   | sessions | ports seen | `authorize_session` outcome |
   |---|---|---|
   | alice01, alice04, alice05, alice07, alice08, longpw30/64/128/138 (9) | `ssh` only | `permit` / `context_matched` |
   | alice02, alice03, alice06 (3) | `ssh` then `vty4` | **`deny` / `context_missing`** |

   The three that failed are exactly the three sessions held open — the two L1 concurrent
   sessions and the L5 idle session. That the vty is allocated only for a persisting session
   is an *inferred* mechanism; the correlation itself is measured.

   `tests/lab/results/L1-arista_eos.md` reports "Stability for the life of a session:
   stable … across 2 sessions and 4 records carrying a ctx_id". That filter — *records
   carrying a ctx_id* — selects precisely the records whose lookup succeeded, so the test
   cannot observe the instability that makes a lookup fail. The note is not wrong about what
   it measured; it measured the wrong set.

### juniper_vjunos-router 23.4R2-S2.1 and juniper_vsrx 21.4R3.15

Measured from `tests/lab/logs/decisions-juniper_vjunos-router.jsonl` (67 records),
`decisions-juniper_vsrx.jsonl` (35 records), `tests/lab/results/L1-*.md`, `L6-*.md`,
`L10-*.md`, and my own parse of `tests/lab/evidence/L1-juniper_vsrx.pcap`,
`L1-juniper_vjunos-router.pcap`, `L6-juniper_vsrx.pcap`. Both images answer identically.
(Those three were read out of `tests/lab/captures/` at the time. The redacted copies in
`tests/lab/evidence/` are committed and hold the same packets, so the parse is reproducible;
nothing this memo measures is in a credential field.)

| candidate | authen START | author request | acct START | acct STOP | unique per concurrent session? |
|---|---|---|---|---|---|
| `port` | `""` | `""` | `0`, `1`, or `non-tty` | same value as its START | **at login, no** — one key for the whole device. **In accounting, yes** |
| `rem_addr` | `172.100.100.1` | `172.100.100.1` | sometimes `""` or `Unknown host - non-tty` | varies | **no** |
| `user` | present | present | present | present | as EOS |
| `task_id` | absent | absent | `1` for login, `2` for the command | `1` | **no** — `task_id` restarts at 1 *per session*; two concurrent sessions both sent `task_id=1` |
| `session_pid` AV | absent | absent | `14656` / `14689` | same | **yes** — unique and stable, **but accounting only** |
| TACACS `session_id` | new value | **a different new value** | new per record | new per record | per-*exchange*, see below |
| TCP connection | new connection per exchange, no single-connect | | | | per-exchange |
| timing adjacency | authen→author ~1 ms, consecutive ephemeral source ports | accounting batched 1.8–4.4 s later | | | orders, does not identify |

**What `session_id` can and cannot do — measured, not assumed.** Parsing the TACACS+ headers
out of `L1-juniper_vsrx.pcap`: every exchange arrives on its own TCP connection, the
single-connect flag is clear on every request, and each connection carries exactly one
`session_id`. The authentication for one login and the authorization for that same login are
1 ms apart and carry **different** `session_id`s:

```
172.100.100.22:59672 → :49   AUTHEN sid=0xd826b957 seq_no=1, then seq_no=3
172.100.100.22:59676 → :49   AUTHOR sid=0xab534ff4 seq_no=1
```

So `session_id` links the packets *within* one authentication exchange (START and its
CONTINUE — this is what makes ASCII login work at all) and links nothing across exchanges.
It cannot join an authentication to an authorization, nor either to an accounting record.

**Junos accounting carries a real per-session discriminator; login does not.** Measured, two
concurrent sessions on vJunos:

```
07:37:06.687 start user=alice02 port='0' session_pid=14656 task_id=1
07:37:06.688 start user=alice03 port='1' session_pid=14689 task_id=1
07:37:21.704 stop  user=alice03 port='1' session_pid=14689 task_id=1 elapsed_time=15
07:37:26.710 stop  user=alice02 port='0' session_pid=14656 task_id=1 elapsed_time=20
```

`port` (`0` vs `1`) and `session_pid` both separate them, and both are stable start-to-stop.
Neither appears in the authentication or authorization exchange, where `port` is `""`.

**And the device reuses its identifier immediately.** One millisecond after alice02's logout
on `port='0'`, alice04 logs in on `port='0'` (vJunos, 07:37:26.710 → .711; vSRX shows the
same within one millisecond at 08:16:22.757). `session_pid` differs across that boundary
(14656 → 14695), `port` does not.

### Gaps — stated, not guessed

- **No EOS capture exists on this machine.** `tests/lab/captures/` holds only `juniper_*`
  files; the EOS run was on the previous host and captures are git-ignored. So EOS
  `session_id`, its TCP/single-connect behavior, and its source-port pattern are
  **unmeasured**. Covered by re-running `PORT49_LAB_PLATFORMS=eos make lab` — L1's capture
  answers all three.
- **No platform in the lab performed an `enable` exchange.** The `$enab{level}$` username,
  and whether `rem_addr` distinguishes concurrent sessions there, are **unmeasured** — that
  is register entry **L3**, plan 3.
- **Console, eAPI, NX-API and NETCONF are unmeasured** for every field above (L1's own
  caveat; eAPI/NX-API are **L7**, plan 3). **PAP is unmeasured** (L8's caveat).
- **`rem_addr` has only ever been measured with one client address.** Every lab login comes
  from the harness at `172.100.100.1`, so "not unique" is measured, but *how often* two real
  operators share a bastion address is not.

### The one-line summary of section 1

> Across every platform and exchange measured, **the set of wire fields that both identify a
> session and appear in both the authentication START and the authorization request is
> empty.** Every session discriminator that exists — Junos `port`/`session_pid`, EOS
> `task_id` — lives only in accounting, which §5.6 row 7 already demotes to advisory and
> which arrives 1.8–4.4 s late on Junos (measured, L6). EOS's `vty<n>` separates concurrent
> sessions from session authorization onward but is `ssh` at the authentication START that
> would have to write the context (corrected 2026-09-23).

No better choice of key from existing fields fixes this. That is what makes it a design
decision rather than a bug.

---

## 2. What a key must satisfy

From `docs/design/2026-08-23-policy-engine-spec.md` §5.1.1, §5.6, §5.8, §13; and
`docs/design/2026-08-21-port49-design.md` lines 237, 528–535, 616, 763, 1153–1154.

1. **Creatable at redemption, readable at command time.** §5.1.1: "the port … does not exist
   until the device opens the authentication exchange. **The broker therefore cannot write
   login context.**" The whole content-addressed-blob indirection exists to serve that one
   sentence.
2. **The username was deliberately excluded.** Design line 616 and spec line 1678: "the
   `enable` exchange arrives as a separate authentication whose username is frequently
   `$enab15$` rather than the principal, so a key containing the username cannot resolve it."
   This is the single reason, and it serves one platform behavior that is **unmeasured** (L3).
3. **The receipt protects against a lost REPLY, not against replay by a stranger.** Design
   lines 520–535: devices retransmit, so delete-on-read makes logins flaky. The receipt is
   keyed `(nas, port, username)` and *carries* a credential hash, checked after lookup,
   because "without it the receipt authorizes by `(nas, port, user)` alone, so for its
   lifetime anyone on that line supplying that username with *any* password would be
   admitted." With `port` constant or empty, "that line" is the device's entire SSH service.
4. **Junos never makes a second request.** §13 decision 21: the ceiling, revocation, username
   binding and the in-session warning all act at the next authorization request, "and Junos
   never makes one." Measured (L10, both images): Junos sends exactly one
   `authorize_session` with `service=junos-exec` and no per-command request at all. So on
   Junos the context is *only* ever used to answer that one request and to attribute
   accounting — a context collision there costs attribution, not authorization.
5. **API transports already strain the same assumption.** §13 decision 15 is provisional on
   L1 and L7 and asks what happens "when `port` is constant across API sessions", proposing
   `(nas, port, rem_addr)` as the candidate. The measurement overtakes the question: `port`
   is already constant or empty across *SSH* sessions, and `rem_addr` is measured identical
   for concurrent sessions, so the proposed candidate is unsafe on the path we can see.
6. **§5.8 pairs exec START with STOP by `task_id`** because "context is already keyed on
   `(nas, port)`, so device-local uniqueness suffices." Measured false on Junos: `task_id`
   restarts at `1` per session.

---

## 3. Recommendation

> **Key the login context on `(nas, username)`. Keep `port` as a recorded attribute of the
> context — logged, used for accounting annotation — and never as part of any key. Key the
> receipt on `(nas, username, credential_sha256)`.**

One key, no per-platform rule, because section 1 shows no platform supplies anything better.

Three claims, in order of how much they matter at 3am:

**(a) It removes the measured mutual lockout.** Today two operators on one device destroy each
other's authorization: bob's login overwrites alice's context, alice's next command is denied
`username_mismatch` *and deletes bob's context*, and bob's next command is `context_missing`
(final-review, "Behavior under a constant or empty `port`", item 2 — demonstrated through the
real server). Under `(nas, username)` they never share a slot.

**(b) It removes the measured EOS lookup failure.** Three of twelve session authorizations in
the committed EOS log were denied `context_missing` purely because the device said `ssh` at
login and `vty4` at authorization. Dropping `port` from the key makes those three match.

**(c) It makes the receipt do what the design says it does.** Design line 534 claims the
credential hash makes "a genuine retransmission … the only thing that replays." Today the
hash is checked *after* a lookup that ignores it, so alice's second login presents a fresh
valid token, finds alice's first receipt, and is answered **FAIL `credential_mismatch`** with
a failure-delay strike — the fresh token left unspent (final-review item 3; the lab config
works around it with one username per login). Putting the hash *in* the key makes the design
sentence structurally true: a byte-identical retransmission finds its own receipt and replays;
a genuinely new login finds nothing and redeems normally.

### Worked example — two operators, one Junos device and one EOS device, concurrently

Values are the measured ones (vSRX `08:15:57`–`08:16:22`; vEOS `04:12:41`–`04:13:00`), with
alice02/alice03 read as two operators, `alice` and `bob`.

| # | event | context table after | receipt table after | decision log |
|---|---|---|---|---|
| 1 | alice redeems on vsrx1, `port=""` | `(vsrx1, alice)` → ctx `MMEQS2CV`, port recorded `""` | `(vsrx1, alice, h_a)` → ctx `MMEQS2CV` | `redeem permit token_redeemed` |
| 2 | vsrx1 asks session authz, `service=junos-exec`, `port=""` | unchanged | unchanged | `authorize_session deny service_unsupported` (plan 1 accepts only `service=shell`; plan 5's adapter fixes this — unrelated to the key) |
| 3 | bob redeems on vsrx1, `port=""`, 2 s later | **`(vsrx1, alice)` and `(vsrx1, bob)` both live** | two receipts | `redeem permit token_redeemed` — *today this overwrites alice* |
| 4 | vsrx1 accounting arrives 1.8 s late, batched: `alice port=0 session_pid=28759`, `bob port=1 session_pid=28769` | each annotates its own row, matched on username | — | `account start attribution=resolved` ×2 — *today both are `unattributed`* |
| 5 | alice redeems on leaf1, `port="ssh"` | `(leaf1, alice)` → ctx, port recorded `ssh` | `(leaf1, alice, h_a')` | `redeem permit token_redeemed` |
| 6 | leaf1 asks session authz — **`port` has become `vty4`** | found; `(leaf1, alice)` does not mention port | — | `authorize_session permit context_matched` — *today `deny context_missing`* |
| 7 | bob does the same on leaf1, also `vty4` as this run recorded it (a concurrent second session in the 2026-09-22 run got `vty6`; see the correction note at the top) | `(leaf1, bob)` separate | — | `permit context_matched` — *today both alice and bob are locked out* |
| 8 | alice runs `show version` on leaf1 | unchanged | — | `authorize_command permit permit_dominates` |

### The bad day

- **The store is down mid-session.** Unchanged by this proposal: `GetContext` fails, the
  handler answers ERROR `store_unavailable` rather than a PASS it cannot back up, and every
  operator must log in again when it returns. The key does not help or hurt here. Worth
  saying plainly because it is the failure operators will actually hit.
- **The device reuses an identifier.** Measured: vJunos frees accounting `port=0` and hands
  it to the next login one millisecond later. Under this proposal `port` is not a key, so
  nothing collides — but the §5.8 accounting annotation must stop pairing on `(nas, port,
  task_id)`. It should pair on the platform's own session discriminator: `session_pid` on
  Junos (measured unique and stable across that reuse, 14656 → 14695), `task_id` on EOS
  (measured device-unique and monotonic). That is per-platform, so it belongs with the plan 5
  adapters.
- **A second login arrives while the first is still running commands.** Same operator, same
  device: one context slot, overwritten with an identical-content context under a new
  `ctx_id`. Benign — same principal, same privilege, same blob — but the operator's older
  session now logs the newer `ctx_id`, so a log reader cannot tell the two shells apart. That
  is the residual cost, and it is unavoidable: section 1 says no wire field distinguishes
  them. It should be *logged* at the overwrite (today nothing is) so the 3am reader sees
  "second login by alice on ls01, context replaced" rather than silence.
- **The `enable` exchange is where this proposal is genuinely narrower.** On `$enab{level}$`
  platforms the wire username is not the principal, so `(nas, "$enab15$")` finds nothing. The
  fallback is a secondary index `(nas, rem_addr) → contexts`, which §5.6 already requires to
  match for exactly this case — and which **must refuse rather than guess when it resolves to
  more than one context**, because `rem_addr` is measured identical for two concurrent lab
  sessions. An operator escalating from a shared bastion while a colleague is logged into the
  same device would be denied and told why. That is fail-closed and explicable, but it is a
  real regression against the design's intent, and it rests on L3, which is unmeasured.

### What it costs

**Spec** (`2026-08-23-policy-engine-spec.md`): §1 line 184; §5.1.1 line 359 and the "broker
cannot write login context" reasoning that follows it; §5.6 overwrite table rows 1, 4 and 5
(lines ~928–933); §5.6 line 1678 (the MUST); §5.8 line 1397. **Design**
(`2026-08-21-port49-design.md`): lines 237 and 1154 (object table), 528–535 (the receipt),
616 and 763 (the keying rationale), 1153 (the store record table: `token`, `receipt`, `login
context`, `contexts_by_principal` all change key shape).

**A simplification falls out, worth weighing.** `token` is already keyed `(nas, username)`
(design line 1153). If the context is too, then §5.1.1's premise — the key is unknowable at
mint — dissolves, and with it the reason the broker cannot write context directly. I am **not**
proposing the broker write context in this memo (the daemon still creates it at redemption,
and the blob indirection earns its keep for sharing and for revocation). But the constraint
should stop being stated as a fact about the protocol, because it stops being one.

**Decisions.** **15** should be re-cut, not merely un-provisioned: its proposed
`(nas, port, rem_addr)` for API contexts is measured unsafe for SSH, and under `(nas,
username)` an API transport with reusable tokens needs no separate context key at all. **21**
is unaffected. **No new decision reopens**; the L1 row stays open for NX-OS, IOS-XE and every
non-SSH transport.

**Plan 2** (`docs/superpowers/plans/2026-09-06-02-token-model.md`) is the plan that builds
this and must change before it is executed:
- `store.ContextKey{NAS, Port}` → `{NAS, Username}`; `store.ReceiptKey{NAS, Port, Username}`
  → `{NAS, Username, CredentialSHA256}` (the hash moves from the record into the key).
- The enable lookup the README states as `(nas, port) → context → bound username → candidate
  set` becomes the `(nas, rem_addr)` secondary index, with an explicit ambiguity refusal and
  its own reason code (new code, so spec §5.7's table first).
- `contexts_by_principal` / `contexts_by_sid` / `contexts_by_cert` entries change from
  `(nas, port)` to `(nas, username)`.
- The §5.8 `task_id` binding and `foreign_session` annotation must be re-specified against a
  per-platform discriminator; the plan currently inherits "device-local uniqueness suffices",
  measured false on Junos.

---

## 4. Alternatives considered

**Keep `(nas, port)` and accept the collisions.** Cheapest, and nothing fails *open* — every
collision ends in a deny or a lost attribution (final-review's own conclusion). It loses on
measured evidence: two operators on one device lock each other out of command authorization
on every platform in the lab, three of twelve EOS session authorizations in the committed log
are already denied `context_missing`, and one user cannot log in twice inside `receipt_ttl`.
"Fails closed" is not a defence when the closed state is the normal operating state.

**`(nas, port, rem_addr)` — decision 15's own candidate.** It keeps the username out of the
key, so the `$enab15$` path survives intact, and it is the smallest edit to the existing
design. It loses twice on measurement: both concurrent lab sessions reported
`rem_addr=172.100.100.1`, so it does not discriminate behind a bastion; and it still carries
`port`, so it does not fix the vEOS `ssh`→`vty4` instability that is *already* denying real
logins.

**A per-platform rule — use the device's session discriminator where one exists** (Junos
`session_pid`, EOS `task_id`, a real tty on IOS-XE if L1 finds one). This is the version that
would actually be *correct* per session, and it is why I checked for these fields. It loses on
a hard fact: measured, every one of those fields appears **only in accounting**, never in the
authentication or the authorization exchange. A context must be created at login and read at
command time; accounting is advisory by §5.6 row 7, arrives 1.8–4.4 s late on Junos (L6), and
on a session-only platform arrives after the only authorization request has already been
answered. The information exists but not where the lookup happens.

**TACACS+ `session_id` as the key.** Ruled out by direct measurement rather than by
reasoning: the authentication and the authorization for one login arrive on two TCP
connections 1 ms apart bearing two different `session_id`s
(`0xd826b957` vs `0xab534ff4`, `L1-juniper_vsrx.pcap`). It links a START to its CONTINUE and
nothing else.

---

## 5. What to measure next

Ordered by how much the recommendation leans on it.

1. **Re-run L1 on vEOS with the capture, on this host, and record `port` at *every* exchange —
   not only the authentication START.** This is the highest-value check and it is cheap. It
   confirms the `ssh`→`vty4` transition from a capture rather than from the decision log, and
   it fixes the note's filter: report the `port` on every record for a session, including the
   ones whose `ctx_id` is empty. The current test's method cannot see the instability it
   would be measuring. *Also closes the EOS `session_id` / single-connect / TCP gap in one
   run, since no EOS capture exists on this machine.*
2. **L3 — the `enable` exchange on an IOS-XE `$enab{level}$` platform** (Catalyst 9000v 17.12
   or C8000v 17.13, both listed as on hand). Record the wire username, `port`, and `rem_addr`,
   with **two concurrent sessions from two different source addresses and again from one**.
   This is the only measurement that prices the enable regression in section 3.
3. **Two operators from two different client addresses, every platform.** Every `rem_addr`
   measurement in the lab uses one harness address, so "rem_addr does not discriminate" is
   measured only for the shared-bastion case. This bounds how much the `(nas, rem_addr)`
   secondary index can be relied on.
4. **L1 for NX-OS (Nexus 9300v 10.4(2)F) and IOS-XE over SSH.** Does `port` carry a real
   tty/vty; is it unique per concurrent session; **is it the same value at authentication and
   at authorization time**. That last clause is the new one and should be added to the L1
   claim text — it is the question vEOS answered "no" to and nobody was asking.
5. **L7 plus the API half of L1** — eAPI and NX-API per-request AAA: what `port` and
   `rem_addr` arrive on each HTTP request, and whether a per-request context is created at
   all. Decision 15 cannot be settled without it.
6. **Junos `session_pid` durability** — whether it is unique across a reboot or a pid wrap,
   and whether it ever appears outside accounting. Only matters if the §5.8 annotation is
   re-specified onto it, which section 3 proposes.
