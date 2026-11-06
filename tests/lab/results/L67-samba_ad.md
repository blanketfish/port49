# L67 — samba_ad

- **Date measured:** 2026-11-06
- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** Samba Version 4.17.12-Debian; image `port49lab/samba:bookworm` (port49lab/samba@sha256:286e7ab9ff5e36d14a007252184fae0bcc7cbcf1cf7677313b4bb2d93746338d), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2`, `go test -tags lab ./tests/lab/ -run '^TestL67$'`
- **Capture:** `tests/lab/evidence/L67-samba_ad.json`: one JSON line per check, sign-in, count and CLI run: the check's kind (`l67_ok`, `l67_refused`, `l67_ldap`, ...), the LDAP result code, the diagnostic data (AD's code, or ppolicy's error), and the directory's failed-password or connection count. There are no search lines, and the wire is LDAPS, so a pcap would be encrypted.
- **Credentials:** none appear here or in the evidence. The people's password is generated for each run from `crypto/rand`, held in memory and written to the evidence as `<alice's password>`; no TOTP secret or code, token or key is printed or kept.

## Claim

A person's simple bind and port49's directory-password sign-in (plan 9e; policy engine spec §13 decision 47 rulings 6 and 7, D2 and D5; §15 L67): (a) `CheckPassword` binds a person over LDAPS and over StartTLS, and what a wrong password answers; (b) an unauthenticated bind is what RFC 4513 §5.1.2 warns it is, and `CheckPassword` with an empty password never opens a connection; (c) what a bind answers for an expired, a must-change, a disabled and a locked account, with the right password and with a wrong one, and whether the state shows without the password; (d) the directory's failed-password count after six sign-ins with a wrong password through a broker at port49's default limits (the sixth throttled, no bind) and after nine across a window boundary against the directory's lockout threshold of ten; (e) a wrong code is refused before the directory is asked; (f) the creation time the sign-in reads; and (g) the sign-in end to end, `login --directory` enrolling, `token` minting, and the directory stopped, on the compose stack's broker on etcd and on port49d on the memory store.

## Observation

### How this directory was configured

- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again under the setting that permits SASL over TLS, each row naming the value in force.
- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).
- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.
- `port49` is an ordinary domain user with its default rights.

The people's password is generated for each run (24 characters from `crypto/rand`) and held in memory; the evidence writes `<alice's password>` wherever it would have been. Every cell's first row is its positive control. "Failed count" is the directory's own: `pwdFailureTime` values on OpenLDAP, `badPwdCount` on Samba and the DC. The lockout threshold is 10 on all three (OpenLDAP: `pwdMaxFailure 10`, `pwdFailureCountInterval 600`, `pwdLockout TRUE`, `olcPPolicyUseLockout TRUE`; AD: threshold 10, observation window and duration 10 minutes).

| cell | observed |
|---|---|
| a. control | `the broker's bind found alice on localhost:20636 over LDAPS` |
| a. right password, LDAPS | `ok` |
| a. wrong password, LDAPS | `refused (LDAP result 49, data 52e)` |
| a. control | `the broker's bind found alice on localhost:20389 over StartTLS` |
| a. right password, StartTLS | `ok` |
| a. wrong password, StartTLS | `refused (LDAP result 49, data 52e)` |
| b. raw unauthenticated bind | `refused: ldap (LDAP result 49, data 52e)` |
| b. control | `a real bind moved the connection count 70 -> 71 (reading it costs 0)` |
| b. CheckPassword(..., "") | `empty_password; connections 71 -> 71` |
| c. control, expired | `the directory reports it, and no other state: failed 0, locked false, expired true, disabled false, must_change false` |
| c. expired, right password | `CheckPassword: refused (LDAP result 49, data 532); raw: LDAP result 49, data 532, ppolicy absent` |
| c. expired, wrong password | `CheckPassword: refused (LDAP result 49, data 52e); raw: LDAP result 49, data 52e, ppolicy absent` |
| c. control, must change | `the directory reports it, and no other state: failed 0, locked false, expired false, disabled false, must_change true` |
| c. must change, right password | `CheckPassword: refused (LDAP result 49, data 773); raw: LDAP result 49, data 773, ppolicy absent` |
| c. must change, wrong password | `CheckPassword: refused (LDAP result 49, data 52e); raw: LDAP result 49, data 52e, ppolicy absent` |
| c. control, disabled | `the directory reports it, and no other state: failed 0, locked false, expired false, disabled true, must_change false` |
| c. disabled, right password | `CheckPassword: refused (LDAP result 49, data 533); raw: LDAP result 49, data 533, ppolicy absent` |
| c. disabled, wrong password | `CheckPassword: refused (LDAP result 49, data 52e); raw: LDAP result 49, data 52e, ppolicy absent` |
| c. control, locked | `the directory reports it, and no other state: failed 10, locked true, expired false, disabled false, must_change false` |
| c. locked, right password | `CheckPassword: refused (LDAP result 49, data 775); raw: LDAP result 49, data 775, ppolicy absent` |
| c. locked, wrong password | `CheckPassword: refused (LDAP result 49, data 775); raw: LDAP result 49, data 775, ppolicy absent` |
| c. control | `alice's right password: ok` |
| d. control | `carol's failed count before: 0, not locked` |
| d. six wrong passwords, defaults | `1: 401 sign_in_refused, directory count 1; 2: 401 sign_in_refused, directory count 2; 3: 401 sign_in_refused, directory count 3; 4: 401 sign_in_refused, directory count 4; 5: 401 sign_in_refused, directory count 5; 6: 429 sign_in_throttled, directory count 5` |
| d. control, not locked | `after six: failed 5, locked false, expired false, disabled false, must_change false` |
| d. nine across a boundary (2m0s window) | `1: 401, count 1; 2: 401, count 2; 3: 401, count 3; 4: 401, count 4; 5: 401, count 5; 6: 401, count 6; 7: 401, count 7; 8: 401, count 8; 9: 401, count 9` |
| d. after nine | `failed 9, locked false, expired false, disabled false, must_change false; the directory's threshold is 10, a margin of 1` |
| d. control, the tenth | `failed 10, locked true, expired false, disabled false, must_change false` |
| e. control | `right password, right code: 200` |
| e. a wrong code | `401 sign_in_refused; the directory's failed count 0 -> 0` |
| f. control | `the directory's own creation time of alice is 2026-11-06T07:53:11Z; SignInEntry read 2026-11-06T07:53:11Z` |
| f. CreatedAt | `2026-11-06T07:53:11Z, 6s before the fixture was logged loaded` |
| g. memory, control | `a sign-in before init-enrollments: 503 enrollment_store_lost; enrollments.json exists: false` |
| g. memory, offline init | `the running broker took the new store 30s after init-enrollments (its recheck is every 30s)` |
| g. memory, login --directory | `exit 0; enrolled true; password: / code from your authenticator (empty if you have none yet): / Enroll your second factor: scan this with your authenticator app, or type the key / confirm by 2026-11-06T08:08:02.093Z / first code from your authenticator: / port49: signed in with your directory password as user:alice@corp.example.com; your certificate from https://127.0.0.1:40203 is valid until 2026-11-06T19:58:02Z / port...` |
| g. memory, token leaf1 | `exit 0; minted true` |
| g. memory, token with the directory stopped | `exit 0; minted true` |
| g. memory, login --directory --sign-in with the directory stopped | `exit 1; password: / code from your authenticator (empty if you have none yet): / port49 login: the broker did not sign you in: the directory did not answer, so no one can sign in with a password now; anyone already signed in keeps working until their certificate ends (directory_unavailable)` |

**Not measurable here:**

- g: the etcd half (the compose stack's broker on etcd) runs against OpenLDAP only; samba_ad's end-to-end run is the memory-store half

