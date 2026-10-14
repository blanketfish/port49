# L60 — ser8 (partial)

**Partial: L60 stays open.** This note records every cell read so far: (a), (c) and the touch
timeout half of (d) in the plan 9c session, and (b), (c)'s certificate order, (d), (e), (e2), (f)
and the cost of `GET /status` in the session with Ryan at the key on 2026-10-14. Still open:
(g), which needs plan 9e, and the two (c) items that need other hardware (under "Open cells").
Every claim they cover stays *provisional on L60*.

- **Date measured:** 2026-10-13 (the plan 9c session that began 2026-10-12) and 2026-10-14
  (03:12–03:54Z, run by `tests/lab/l60/RUNBOOK.md`: the import through (f)'s lockout at commit
  `4006e7ac`, the certificate order at `b23964f6`, which adds that cell and leaves the earlier
  cells' code unchanged)
- **Platform:** beehive, the SER8 lab machine: Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, pcscd
  reached by the lab user through a polkit rule (no sudo)
- **Token:** YubiKey 5C Nano FIPS, firmware 5.4.3 (serial recorded locally). Slots made by Ryan with
  `ykman piv keys generate`, ECCP256: 9a PIN once, touch never; 9c PIN once, touch always; 9e PIN
  once, touch default
- **Module:** libykcs11 from the `ykcs11` package 2.7.2-1, `/usr/lib/x86_64-linux-gnu/libykcs11.so`,
  loaded by port49's purego PKCS#11 layer (`internal/hwkey/pkcs11`)
- **Roots:** Yubico's PIV root, `https://developers.yubico.com/PKI/yubico-piv-ca-1.pem`
- **Capture:** `tests/lab/l60/probe_test.go`, the attestation probe as it ran (build tag
  `l60probe`, so it never builds in `make test`; its header says how it ran), and the touch probes
  `tests/lab/l60/touch_test.go` and `touch2_test.go`, built and run the same way; their numbers
  below are copied from their output at the time. The probes' output names the device serial and
  is kept locally, not here. The touch probes read the PIN from Ryan's own terminal with echo off;
  no PIN, PUK or management key was typed into the Claude session or written to any file.
  The 2026-10-14 cells are the gated tests in `tests/lab/l60/` (`cells_*_test.go`), each run as
  `go test -tags hwkey_dlopen ./tests/lab/l60/ -run '^TestL60<Cell>$'` with its `PORT49_L60_*`
  gate (the certificate order with `-tags hwkey,hwkey_dlopen`, for its test hook), against an
  in-process broker and the lab client CA the harness makes. Their observations went to a local
  log, serial masked, from which the figures below are copied. PIN prompts were counted by Ryan at
  the terminal, except where noted. The PIN reached the key only at port49's own prompt, typed by
  Ryan, or from a `pin-source` file Ryan made themselves (mode 0600). The harness passed that
  file's path to port49, and in (e)'s last step port49's opener, inside the test process, read it
  and logged in once; tries stayed 3 of 3.

## Claim

Spec §15 L60: a YubiKey's PIV applet through libykcs11 under purego. This note covers:
- cell (a): `C_Initialize`/`C_Finalize` with the token present;
- cell (b): `port49 login --key` on 9a, the PIN asked once, the refresh;
- cell (c): the attestation objects, their chain and their policies, and the certificate order
  with an imported certificate;
- cell (d): the touch timeout (decision 45 ruling 14 says about 15s), and `hardware_key_touch`
  through `port49 token`;
- cell (e): the unplug;
- cell (e2): a second process's login and token;
- cell (f): a wrong PIN, the `pin-source` guard, and the lockout;
- the cost of `GET /status`.

## Observation

### (a) Initialize and finalize with the token present

`TestLibykcs11InitFinalizeUnderPurego`, five rounds of `C_Initialize` (`CKF_OS_LOCKING_OK`, no
callbacks) and `C_Finalize` in one process, one slot with the token: no crash, thread count 6
before, 6 between, 6 after.

### (c) The attestation objects, with no login

A read-only session, no `C_Login`, lists four certificate objects:

| object | CKA_ID | issuer |
|---|---|---|
| f9, "X.509 Certificate for PIV Attestation" | `0x19` | Yubico's PIV root, directly: no intermediate on firmware 5.4.3 |
| slot 9a attestation ("YubiKey PIV Attestation 9a") | `0x01` | the f9 certificate |
| slot 9c attestation | `0x02` | the f9 certificate |
| slot 9e attestation | `0x04` | the f9 certificate |

- `pivattest.Verify` passes for all three slot attestations against the f9 certificate and the
  root.
- Each slot certificate's issuer is byte for byte the f9 certificate's subject, which `pivattest`
  requires.
- All three carry the same device serial (…41482.3.7), which the broker's per-login proof compares.
- Touch policy (…41482.3.8): 9a reads 1 (never), 9c reads 2 (always), 9e reads 1 (the default,
  never). PIN policy reads 2 (once) on all three.
- A slot attestation has the same CKA_ID as its slot's key; port49's `Certificate()` skips it by
  its subject CN.

**Certificate order (2026-10-14, `TestL60COrder`).** Slot 9a then held an imported lab
certificate (CN alice@example.com, issued by the lab client CA) beside its attestation. One
read-only session, opened by port49's own opener on slot 9a, with no login and nothing written,
lists five certificate objects in this `C_FindObjects` order:

| # | CKA_ID | CKA_LABEL | subject CN |
|---|---|---|---|
| 0 | `0x01` | X.509 Certificate for PIV Authentication | alice@example.com (the imported certificate) |
| 1 | `0x19` | X.509 Certificate for PIV Attestation | Yubico PIV Attestation (f9) |
| 2 | `0x01` | X.509 Certificate for PIV Attestation 9a | YubiKey PIV Attestation 9a |
| 3 | `0x02` | X.509 Certificate for PIV Attestation 9c | YubiKey PIV Attestation 9c |
| 4 | `0x04` | X.509 Certificate for PIV Attestation 9e | YubiKey PIV Attestation 9e |

- The imported certificate and the slot's attestation share CKA_ID `0x01`. libykcs11 lists the
  imported one first.
- port49's `Certificate()`, which `port49 login --key` uses with no `--cert`, picks the imported
  certificate, and its key is slot 9a's key. The pick does not lean on the order: `Certificate()`
  drops attestations before it takes the first certificate with the key's CKA_ID
  (`internal/hwkey/pkcs11/signer.go`, `withoutAttestations`).
- `Certificates()` returns all five, in the listed order.
- `mfatouch.Chain` builds the same chain from the listed order and from its reverse, with the touch
  key on 9c and the session key on 9a, and the other way round. Each time the links are the touch
  slot's attestation, f9, and the session slot's attestation; the imported certificate is never
  taken for an attestation.

Firmware 5.4.3 gave the same chain as on 2026-10-13: f9 issued by Yubico's PIV root directly.

### (d), the timeout half: an untouched 9c sign

Two probes on the 9c key (touch always), after one PIN login on the session. `ykman piv info`
showed 3 of 3 PIN tries left after each.

| probe | sign | result | time |
|---|---|---|---|
| 1 | touched | signed, verifies | 8.993s (Ryan's wait) |
| 1 | untouched | `C_Sign` → `CKR_USER_NOT_LOGGED_IN` (0x101) | 14.38s |
| 2 | untouched | `C_Sign` → `CKR_USER_NOT_LOGGED_IN` | 14.391s |
| 2 | touched, same session, right after the timeout | signed with no PIN, verifies | 8.355s |
| 2 | touched | signed, verifies | 7.993s |

So the token stays logged in after a touch timeout, and libykcs11 reports the timeout as
`CKR_USER_NOT_LOGGED_IN`. Probe 1 also showed port49's Signer of that day reading it as a locked
key ("needs its PIN"); the rule that followed reads a not-logged-in that took 5s or more as a touch
timeout (spec decision 45 ruling 14).

### (d), through port49 (2026-10-14, `TestL60D`)

`port49 login` with 9a as the session key and 9c (touch always) as the touch key: the PIN was asked
once. Then `port49 token`, with the broker's `touch_devices` scope requiring `hardware_key_touch`
on `leaf_touch` and nothing on the control device:

| mint | exit | time | port49's words |
|---|---|---|---|
| control (no second factor asked) | 0 | 11ms | none |
| `leaf_touch`, touched | 0 | 13.465s (Ryan's wait) | "leaf_touch asks for a second factor at each login … touch your key now" |
| `leaf_touch`, untouched | 1 | 14.401s | the same, then "hwkey: no touch within 15s; touch the key when it blinks and try again" |
| `leaf_touch`, touched right after the timeout | 0 | 9.693s | the same as the touched mint; no PIN asked |

`GET /status` read `touch_key_state=present` before, after the timeout and at the end, and PIN
tries stayed 3 of 3. The timeout reads as a touch timeout, not as a locked key, through port49's own
path (decision 45 ruling 14 holds).

### (b) `port49 login --key` on slot 9a (`TestL60B`)

- **Control, the lab's file key:** the login exited 0 in 113ms, and a refresh exited 0 in 9ms.
- **Slot 9a, with the token's own certificate (no `--cert`):** the login exited 0 in 9.658s, which
  includes Ryan typing the PIN. The PIN was asked once. The agent connected, and `GET /status`
  read `key_state=present`, with key_ref `pkcs11:id=%01?module-path=…/libykcs11.so`. Then:
  - a refresh exited 0 in 84ms with no PIN;
  - a mint exited 0 in 11ms;
  - PIN tries read 3 of 3 before and after.

### (e2) A second login and mint beside a running agent (`TestL60E2`, run twice)

The first run's log ends after B's login: it was stopped there and the cell run again from the
start. The second-login and token figures below are from both runs; every figure about A and B
together is from the second run alone.

- **A second `port49 login` to agent A's socket:** "already logged in to …; refreshing", exit 0,
  81–85ms. The 85ms is too quick for a PIN entry, and the session transcript shows no PIN prompt.
  Ryan's count at the terminal read 1 on both runs, so the 0 is from the timing and the
  transcript.
- **A `port49 token` beside A:** exit 0 in 10–13ms.
- **A and B together:** a second agent B logged in on its own socket (the PIN asked once). A and B
  then ran side by side:
  - A refreshed after B's login, and B refreshed.
  - After B stopped, A refreshed again.
  - Every refresh took 80–82ms, with no PIN.
- PIN tries stayed 3 of 3. Two agents' PIV logins on one token coexist.

### (e) The unplug (`TestL60E`)

With agent A logged in on 9a, Ryan pulled the key:

- **The status lagged at first.** `GET /status` still read `key_state=present` right after the
  pull, until something used the key.
- **A mint on the held connection** exited 0 in 12ms, and again after the refresh below. The
  broker connection is not torn down by the pull.
- **`port49 refresh`** exited 1 in 11ms: "insert your key; your session goes on until … (tokens are
  still minted on the held connection while it stays up)". After it, `GET /status` read
  `key_state=absent`.
- **Re-inserted,** the status read `key_state=locked`.
- **`port49 login`** said "already logged in; refreshing", asked the PIN once and exited 0. The
  status then read `present`, and a refresh exited 0 in 85ms.
- **The return code of a physical pull:** a `C_Sign` on a logged-in session, the key pulled during
  it, gave `CKR_DEVICE_REMOVED (0x32)`. port49 read that as "the key is not present", and the
  state went from `present` to `absent`, then to `locked` once re-inserted.
- PIN tries stayed 3 of 3.

### (f) One wrong PIN, and the `pin-source` guard (`TestL60F`)

1. **Before:** the guard probe (a `pin-source` login with no terminal) saw neither flag. The file's
   PIN was sent and taken.
2. **One wrong PIN typed at `port49 login`:** exit 1, one prompt and no second attempt. Tries went
   from 3 of 3 to 2 of 3. port49's words show libykcs11 set `CKF_USER_PIN_COUNT_LOW`, not
   `CKF_USER_PIN_FINAL_TRY`.
3. **The guard after it:** exit 2 in 523ms, holding the file's PIN back.
4. **A correct PIN typed at the terminal** (the `pin-source` reference given, port49 asked anyway):
   exit 0.
5. **The guard after that:** the file's PIN was sent and taken. A typed success clears
   `CKF_USER_PIN_COUNT_LOW` (final re-review N1 holds). Tries ended at 3 of 3.

### (f), the lockout (`TestL60FLock`, by Ryan's choice)

Agent A was logged in on 9a. Then three wrong PINs were typed at `port49 login` in a second
process:

| wrong PIN | exit | port49's words | flags read | A's refresh after it |
|---|---|---|---|---|
| 1 | 1 | "fewer tries are left" | `COUNT_LOW` | exit 1, "your key needs its PIN: run `port49 login`"; status `locked` |
| 2 | 1 | "one try is left before the key locks" | `FINAL_TRY` | the same |
| 3 | 1 | "the key's PIN is blocked; unblock it with its PUK (ykman piv access unblock-pin) before trying again" | blocked | the same |

- **After the third:**
  - **A fresh `port49 login`** prompted for the PIN, then refused with the blocked message (exit 1,
    21.751s).
  - **`port49 login` to A's socket** prompted for the PIN, then said "refreshing the running
    agent's session: your key needs its PIN: run `port49 login`" (exit 1). It never named the
    block.
  - **Tries** read 0 of 3.
- **Recovery:** Ryan ran `ykman piv access unblock-pin` with the PUK, and tries went back to 3 of
  3. A new `port49 login` asked the PIN once and exited 0, and a refresh exited 0 in 81ms.

### The cost of `GET /status` (`TestL60Status`, 50 calls per agent)

| agent | median | p95 | max |
|---|---|---|---|
| the lab's file key | 100µs | 170µs | 550µs |
| slot 9a | 110µs | 320µs | 510µs |
| slot 9a with 9c as the touch key | 190µs | 400µs | 510µs |

Reading the attestations on each call costs well under a millisecond.

## Findings

- **F1. A wrong PIN typed in another process logs a running agent off the key.** One wrong PIN at
  a second `port49 login` (lockout table, row 1) left agent A's PIV session not logged in: A's
  next refresh said "your key needs its PIN", and the status read `locked`. The cause is
  inferred, not captured: the log holds port49's words, not the return code behind them. They
  are what port49 says for `CKR_USER_NOT_LOGGED_IN` (`classify`, `signer.go`), and the refresh
  took 10ms, against about 80ms for a real sign. The two processes share nothing in port49, so the
  likely cause is the token's: the PIV applet's login state does not survive another process's
  failed `C_Login`. A second process's correct PIN in (e2) left A logged in. A later run should
  record A's error code after the wrong PIN, as (e) does for the pull.
  It wants an operator note: a mistyped PIN anywhere on the machine sends the running agent back to
  `port49 login`.
- **F2. port49 prompts for a blocked PIN, and a login to a running agent never says "blocked".**
  With tries at 0, `port49 login` still asked for the PIN before refusing. `port49 login` against
  A's socket said only "needs its PIN". The fix is to read `CKF_USER_PIN_LOCKED` before the prompt
  and to name the block in both paths.

## Open cells

- (c) a newer firmware's chain depth (an intermediate between f9 and the root), and a YubiKey Bio's
  policy bytes: both need a token this lab does not have.
- (g) `issued_key_store: pkcs11` on 9e: the certificate issued, nothing written to the token. This
  needs plan 9e.
