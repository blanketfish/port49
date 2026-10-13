# L60 — ser8 (partial)

**Partial: L60 stays open.** This note records the cells read so far. The rest need Ryan at the key
and port49's own paths end to end (plan 9c Task 16); every claim they cover stays *provisional on
L60*.

- **Date measured:** 2026-10-13 (the plan 9c session that began 2026-10-12)
- **Platform:** beehive, the SER8 lab machine: Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, pcscd
  reached by the lab user through a polkit rule (no sudo)
- **Token:** YubiKey 5C Nano FIPS, firmware 5.4.3 (serial recorded locally). Slots made by Ryan with
  `ykman piv keys generate`, ECCP256: 9a PIN once, touch never; 9c PIN once, touch always; 9e PIN
  once, touch default
- **Module:** libykcs11 from the `ykcs11` package 2.7.2-1, `/usr/lib/x86_64-linux-gnu/libykcs11.so`,
  loaded by port49's purego PKCS#11 layer (`internal/hwkey/pkcs11`)
- **Roots:** Yubico's PIV root, `https://developers.yubico.com/PKI/yubico-piv-ca-1.pem`
- **Capture:** `tests/lab/l60/probe_test.go`, the attestation probe as it ran (build tag
  `l60probe`, so it never builds in `make test`; its header says how it ran). The touch probes
  were scratch test binaries whose source was not kept; their numbers below are copied from their
  output at the time. The probes' output names the device serial and is kept locally, not here.
  No PIN, PUK or management key was typed into the harness or written to any file it read.

## Claim

Spec §15 L60: a YubiKey's PIV applet through libykcs11 under purego. This note covers cell (a)
(`C_Initialize`/`C_Finalize` with the token present), most of cell (c) (the attestation objects,
their chain and their policies) and the touch timeout half of cell (d) (decision 45 ruling 14 says
about 15s).

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

Not read: what `pkcs11.Signer.Certificates()` returns (the probe called the module directly), and
a slot holding an imported certificate beside its attestation.

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

## Open cells

- (b) `port49 login --key` on 9a: the PIN asked once, the agent connects and refreshes; control,
  the lab's file key.
- (c) the rest: `Certificates()` through port49; a slot holding its imported certificate beside its
  attestation, which certificate the token lists first, and a touch proof from such a token
  (`mfatouch.Chain` no longer depends on the order); a newer firmware's chain depth; a YubiKey
  Bio's policy bytes.
- (d) the rest: `port49 token` on a device under `hardware_key_touch` with a touch, and with none
  (port49's words), against a control with no requirement.
- (e) the unplug: a mint on the held connection, `port49 refresh` saying to insert the key, the
  session surviving, then after re-insertion `GET /status` saying `locked`, `port49 login` asking
  the PIN and the refresh working; which return code a physical pull gives.
- (e2) a `port49 login` and `port49 token` in a second terminal leave the agent's PIV login in
  place.
- (f) one wrong PIN: the message, one try fewer, no second attempt; whether libykcs11 sets
  `CKF_USER_PIN_COUNT_LOW` and `CKF_USER_PIN_FINAL_TRY` after it, which the `pin-source` guard
  reads.
- (g) `issued_key_store: pkcs11` on 9e: the certificate issued, nothing written to the token.
- The cost of `GET /status` reading the attestations on each call.
