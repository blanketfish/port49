# L86 — ser8

**Closed.** All four cells passed on a real YubiKey on 2026-11-01. The run found two product bugs and
three harness bugs, all fixed on this branch before the passing runs (under "Bugs the run found").

- **Date measured:** 2026-11-01, 19:04–19:44Z, run by `tests/lab/L86-runbook.md` with Ryan at the key
- **Platform:** beehive, the SER8 lab machine: Ubuntu 26.04.1 LTS, kernel 7.0.0-38-generic
- **Token:** YubiKey 5C Nano FIPS, firmware 5.4.3 (operator-reported from ykman; serial recorded
  locally, masked here). The slots are L60's, made by Ryan with `ykman piv keys generate`, ECCP256:
  9a PIN once, touch never (session key, cells a, b, d); 9c PIN once, touch always (touch key, every
  cell); 9e PIN once (the issued key, cell c). libykcs11's CKA_IDs: 9a `01`, 9c `02`, 9e `04`
- **Module:** libykcs11 from the `ykcs11` package 2.7.2-1, `/usr/lib/x86_64-linux-gnu/libykcs11.so`,
  loaded by port49's purego PKCS#11 layer
- **Roots:** Yubico's PIV root (`yubico-piv-ca-1.pem`, L60's)
- **Identity provider (cell c):** the lab Keycloak, compose project `port49laboidc`, image pinned by
  digest, realm `port49-lab`, sign-in as `alice` (`alice@corp.example.com`)
- **Build:** `make l86-build`'s two binaries (`port49`, `l60.test`, `-tags hwkey_dlopen`, static).
  Cell (a) ran on 18aa2893 as built (its path, a lab-CA certificate on 9a, touches none of the
  fixes); (b) on the build with the harness wiring fix only; the passing (d) on the build
  with both product fixes; the passing (c) on the build with every commit of this branch. The lab
  builds were made on the pre-rename base (18aa2893); the branch is the same changes replayed onto
  the blanketfish module path (c56ea3b6), with the import paths the only difference
- **Capture:** the harness's observation lines, serial masked, in `~/.cache/port49-l60/observations.log`
  on beehive (this run's lines extracted to `L86-observations.txt` beside it), and the in-process
  broker's decision log per cell, `decisions-<cell>.jsonl`, in the same directory (event, verdict and
  reason only are quoted below; no token, challenge or signature). Figures below are copied from
  those lines. The PIN was typed only at port49's own prompt; PIN prompts and touches were counted
  by Ryan at the terminal

## Results

| Cell | Verdict | Observed |
|---|---|---|
| (a) two calls 5 s apart | **PASS** | PIN asked once at login. Call 1 touched: exit 0 in 9.06 s. Call 2 untouched: the key blinked again (Ryan: yes), and it failed after 14.39 s with `hwkey: no touch within 15s`, exit 1. Call 3 touched: exit 0 in 10.66 s. Each call took its own touch. |
| (b) no touch | **PASS** | Exit 1 after 14.38 s, `no touch within 15s; touch the key when it blinks and try again`; `port49 revoke --list` then showed `no revocation is in force`. |
| (c) the OIDC path | **PASS** | `port49 login --oidc` signed in at Keycloak as `user:alice@corp.example.com` and the broker issued a certificate for the key in slot 9e (decision log: `issue permit`); PIN asked once. The admin call then asked one touch: exit 0 in 9.72 s, decision log `admin_touch deny admin_touch_required` (the challenge), `admin_touch permit`, then the revoke's own record. |
| (d) key pulled | **PASS** | With the key pulled, the call refused in 19 ms with `insert your key; your session goes on until …`, exit 1, and the broker's log grew by no admin record (0; 0 `admin_touch_refused`). |

The untouched timeout was 14.38–14.39 s in every run, matching L60's 14.4 s.

## Bugs the run found

Each fix was written test first, the test failing on the bug the run showed.

1. **Product: an issued certificate could not prove a touch.** The first passing login in (c) was
   followed by `the broker refused the touch: … a bearer token cannot prove`, in 12 ms, no blink.
   `adminGate` took any caller carrying an OIDC assertion as a bearer, and a certificate the broker
   issues carries its sign-in's assertion. A bearer is now an assertion with no sign-in; the
   connection must still present a verified client certificate.
2. **Product: a pulled touch key was found only after sending.** The first (d) run printed `insert
   your key`, but the broker had logged `admin_touch admin_touch_required`: the request had gone.
   The PKCS#11 signer reported the state it last saw. The agent now probes the touch key's token
   (`C_GetSlotList` with token present, `C_GetTokenInfo`; no login, no PIN) before the first admin
   request.
3. **Harness: the in-process broker was not wired as port49d wires it** (no `Broker.Wire`), so its
   listener read an issued certificate by its email SAN and closed the connection: the first (c)
   run's agent got EOF after the handshake.
4. **Harness: a typed-ahead line answered a question.** (c) asked the PIN count twice, its first
   answer a stray newline. The harness now discards typed-ahead input before it asks.
5. **Harness: (c) checked for a line it cannot get.** It wanted login's `the key is the one
   issued_key names, on your token`, which login prints only when it chose the store itself; the cell
   pins `issued_key_store: pkcs11`, which refuses rather than falls back. The cell now judges the
   token's key by its one PIN prompt. The run that failed only on that check showed the same path
   working (exit 0, one touch).

Also changed: the sign-in prompt named the identity provider's issuer URL on the line before the
authorization address, and Ryan opened it first. It now names the provider by host, so the address
is the line's one link.

## Not measured here

- Whether slot 9e was written to: cell (c) does not read the token's objects, so L60 cell (g) ("the
  certificate issued, nothing written to the token") stays open.
- The nonce in (c)'s three authorization addresses was the same each time. That is by design: login
  sends `api.IssuanceNonce` of the issued key's public key (decision 43 ruling 3), the same key each
  run; state and the PKCE challenge differed every run.
