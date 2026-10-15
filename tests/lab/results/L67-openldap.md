# L67 — openldap

- **Date measured:** 2026-10-15
- **Platform:** openldap, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** @(#) $OpenLDAP: slapd 2.5.13+dfsg-5 (Feb  8 2023 01:56:12) $; image `port49lab/openldap:bookworm` (port49lab/openldap@sha256:97a5675eb2ba0c2e0cab3af491868b8ce4bff272a9adb7dc3addaa1a5911a9af), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `b6b75d1475e53a4b68d4c98d4d64378c6b256cf7`, `go test -tags lab ./tests/lab/ -run '^TestL67$'`. History: a first run at `f60d1d9158073c3cde55def7d7d2d67b17bf9177` passed cells a-f and the memory half of g, and failed g's etcd half on a harness readiness fault (`port49 token` got `store_unavailable` because the test minted before the broker's mints opened). Commit b6b75d14 waits for the broker's `policy: mints open:` line; every cell passed in this full re-run, and this note and its evidence are wholly from it.
- **Capture:** `tests/lab/evidence/L67-openldap.json`: one JSON line per check, sign-in, count and CLI run: the check's kind (`l67_ok`, `l67_refused`, `l67_ldap`, ...), the LDAP result code, the diagnostic data (AD's code, or ppolicy's error), and the directory's failed-password or connection count. There are no search lines, and the wire is LDAPS, so a pcap would be encrypted.
- **Credentials:** none appear here or in the evidence. The people's password is generated for each run from `crypto/rand`, held in memory and written to the evidence as `<alice's password>`; no TOTP secret or code, token or key is printed or kept.

## Claim

A person's simple bind and port49's directory-password sign-in (plan 9e; policy engine spec §13 decision 47 rulings 6 and 7, D2 and D5; §15 L67): (a) `CheckPassword` binds a person over LDAPS and over StartTLS, and what a wrong password answers; (b) an unauthenticated bind is what RFC 4513 §5.1.2 warns it is, and `CheckPassword` with an empty password never opens a connection; (c) what a bind answers for an expired, a must-change, a disabled and a locked account, with the right password and with a wrong one, and whether the state shows without the password; (d) the directory's failed-password count after six sign-ins with a wrong password through a broker at port49's default limits (the sixth throttled, no bind) and after nine across a window boundary against the directory's lockout threshold of ten; (e) a wrong code is refused before the directory is asked; (f) the creation time the sign-in reads; and (g) the sign-in end to end, `login --directory` enrolling, `token` minting, and the directory stopped, on the compose stack's broker on etcd and on port49d on the memory store.

## Observation

### How this directory was configured

- `olcSecurity: tls=1` (every operation must be under TLS), set after the seed was loaded over ldapi.
- `olcTLSVerifyClient: try`: a client certificate is requested and verified when presented.
- `olcAuthzRegexp: "^cn=port49-broker,o=port49 lab$" -> cn=port49,ou=Svc,dc=corp,dc=example,dc=com`.
- The `memberof` overlay with `olcMemberOfRefInt: TRUE`; the seed was loaded with `ldapadd` so the overlay ran.
- `cn=port49` has read access to everything; anonymous has none beyond the root DSE and authentication.

**L67 changes that configuration:** the entrypoint, with `LAB_L67` set, sets `olcSecurity: ssf=56` in place of `tls=1` (TLS and the local ldapi socket meet ssf 56, plain LDAP does not; the test flips `olcPPolicyUseLockout` over ldapi), and loads the `ppolicy` overlay with a default policy (`pwdLockout TRUE`, `pwdMaxFailure 10`) and `olcPPolicyUseLockout TRUE`. The (UseLockout FALSE) rows are measured with that setting flipped over ldapi.

The people's password is generated for each run (24 characters from `crypto/rand`) and held in memory; the evidence writes `<alice's password>` wherever it would have been. Every cell's first row is its positive control. "Failed count" is the directory's own: `pwdFailureTime` values on OpenLDAP, `badPwdCount` on Samba and the DC. The lockout threshold is 10 on all three (OpenLDAP: `pwdMaxFailure 10`, `pwdFailureCountInterval 600`, `pwdLockout TRUE`, `olcPPolicyUseLockout TRUE`; AD: threshold 10, observation window and duration 10 minutes).

| cell | observed |
|---|---|
| a. control | `the broker's bind found alice on localhost:10636 over LDAPS` |
| a. right password, LDAPS | `ok` |
| a. wrong password, LDAPS | `refused (LDAP result 49)` |
| a. control | `the broker's bind found alice on localhost:10389 over StartTLS` |
| a. right password, StartTLS | `ok` |
| a. wrong password, StartTLS | `refused (LDAP result 49)` |
| b. raw unauthenticated bind | `refused: ldap (LDAP result 53)` |
| b. control | `a real bind moved the connection count 19 -> 20 (reading it costs 0)` |
| b. CheckPassword(..., "") | `empty_password; connections 20 -> 20` |
| c. control, expired | `the directory reports it, and no other state: failed 0, locked false, expired true, disabled false, must_change false` |
| c. expired, right password | `CheckPassword: refused (LDAP result 49, data password_expired); raw: LDAP result 49, ppolicy error 0` |
| c. expired, wrong password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c. control, must change | `the directory reports it, and no other state: failed 0, locked false, expired false, disabled false, must_change true` |
| c. must change, right password | `CheckPassword: refused (LDAP result 0, data change_after_reset); raw: LDAP result 0, ppolicy error 2` |
| c. must change, wrong password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c. control, disabled | `the directory reports it, and no other state: failed 0, locked false, expired false, disabled true, must_change false` |
| c. disabled, right password | `CheckPassword: refused (LDAP result 49, data account_locked); raw: LDAP result 49, ppolicy error 1` |
| c. disabled, wrong password | `CheckPassword: refused (LDAP result 49, data account_locked); raw: LDAP result 49, ppolicy error 1` |
| c. control, locked | `the directory reports it, and no other state: failed 10, locked true, expired false, disabled false, must_change false` |
| c. locked, right password | `CheckPassword: refused (LDAP result 49, data account_locked); raw: LDAP result 49, ppolicy error 1` |
| c. locked, wrong password | `CheckPassword: refused (LDAP result 49, data account_locked); raw: LDAP result 49, ppolicy error 1` |
| c. control | `alice's right password: ok` |
| c (UseLockout FALSE). control, locked | `the directory reports: failed 10, locked true, expired false, disabled false, must_change false` |
| c (UseLockout FALSE). locked, right password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c (UseLockout FALSE). locked, wrong password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c (UseLockout FALSE). control, disabled | `the directory reports: failed 0, locked false, expired false, disabled true, must_change false` |
| c (UseLockout FALSE). disabled, right password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c (UseLockout FALSE). disabled, wrong password | `CheckPassword: refused (LDAP result 49); raw: LDAP result 49, ppolicy present no error` |
| c (UseLockout FALSE). sign-in, locked person | `1: 401 sign_in_refused; 2: 401 sign_in_refused; 3: 401 sign_in_refused; 4: 401 sign_in_refused; 5: 401 sign_in_refused; 6: 429 sign_in_throttled` |
| d. control | `carol's failed count before: 0, not locked` |
| d. six wrong passwords, defaults | `1: 401 sign_in_refused, directory count 1; 2: 401 sign_in_refused, directory count 2; 3: 401 sign_in_refused, directory count 3; 4: 401 sign_in_refused, directory count 4; 5: 401 sign_in_refused, directory count 5; 6: 429 sign_in_throttled, directory count 5` |
| d. control, not locked | `after six: failed 5, locked false, expired false, disabled false, must_change false` |
| d. nine across a boundary (2m0s window) | `1: 401, count 1; 2: 401, count 2; 3: 401, count 3; 4: 401, count 4; 5: 401, count 5; 6: 401, count 6; 7: 401, count 7; 8: 401, count 8; 9: 401, count 9` |
| d. after nine | `failed 9, locked false, expired false, disabled false, must_change false; the directory's threshold is 10, a margin of 1` |
| d. control, the tenth | `failed 10, locked true, expired false, disabled false, must_change false` |
| e. control | `right password, right code: 200` |
| e. a wrong code | `401 sign_in_refused; the directory's failed count 0 -> 0` |
| f. control | `the directory's own creation time of alice is 2026-10-15T03:34:20Z; SignInEntry read 2026-10-15T03:34:20Z` |
| f. CreatedAt | `2026-10-15T03:34:20Z, 1s before the fixture was logged loaded` |
| g. memory, control | `a sign-in before init-enrollments: 503 enrollment_store_lost; enrollments.json exists: false` |
| g. memory, login --directory | `exit 0; enrolled true; password: / code from your authenticator (empty if you have none yet): / Enroll your second factor: scan this with your authenticator app, or type the key / confirm by 2026-10-15T03:49:00.971Z / first code from your authenticator: / port49: signed in with your directory password as user:alice@corp.example.com; your certificate from https://127.0.0.1:46327 is valid until 2026-10-15T15:39:01Z / port...` |
| g. memory, token leaf1 | `exit 0; minted true` |
| g. memory, token with the directory stopped | `exit 0; minted true` |
| g. memory, login --directory --sign-in with the directory stopped | `exit 1; password: / code from your authenticator (empty if you have none yet): / port49 login: the broker did not sign you in: the directory did not answer, so no one can sign in with a password now; anyone already signed in keeps working until their certificate ends (directory_unavailable)` |
| g. etcd, control | `a sign-in before init-enrollments: 503 enrollment_store_lost` |
| g. etcd, mint gate | `opened 24s after the broker restart (this wait: 21s, for the broker's policy: mints open: line)` |
| g. etcd, login --directory | `exit 0; enrolled true; password: / code from your authenticator (empty if you have none yet): / Enroll your second factor: scan this with your authenticator app, or type the key / confirm by 2026-10-15T03:50:54.587Z / first code from your authenticator: / port49: signed in with your directory password as user:alice@corp.example.com; your certificate from https://127.0.0.1:8449 is valid until 2026-10-15T15:40:54Z / port4...` |
| g. etcd, token leaf1 | `exit 0; minted true` |
| g. etcd, token with the directory stopped | `exit 0; minted true` |
| g. etcd, login --directory --sign-in with the directory stopped | `exit 1; password: / code from your authenticator (empty if you have none yet): / port49 login: the broker did not sign you in: the directory did not answer, so no one can sign in with a password now; anyone already signed in keeps working until their certificate ends (directory_unavailable)` |

