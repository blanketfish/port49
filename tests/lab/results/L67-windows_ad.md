# L67 — windows_ad

- **Date measured:** 2026-10-15
- **Platform:** windows_ad, Windows Server 2025 Standard Evaluation as a KVM VM in `dockurr/windows`, on `tests/lab/directory/windows/compose.yaml` (no network device)
- **Image version:** Microsoft Windows Server 2025 Standard Evaluation (ServerStandardEval), build 26100.32230; ISO `26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso` (SHA-256 `7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51`); image `dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea`
- **Run:** commit `f60d1d9158073c3cde55def7d7d2d67b17bf9177`, `PORT49_LAB_L67_WINDOWS=1 go test -tags lab ./tests/lab/ -run '^TestL67Windows$'`
- **Capture:** `tests/lab/evidence/L67-windows_ad.json`: one JSON line per check, sign-in, count and CLI run: the check's kind (`l67_ok`, `l67_refused`, `l67_ldap`, ...), the LDAP result code, the diagnostic data (AD's code, or ppolicy's error), and the directory's failed-password or connection count. There are no search lines, and the wire is LDAPS, so a pcap would be encrypted.
- **Credentials:** none appear here or in the evidence. The people's password is generated for each run from `crypto/rand`, held in memory and written to the evidence as `<alice's password>`; no TOTP secret or code, token or key is printed or kept.

## Claim

A person's simple bind and port49's directory-password sign-in (plan 9e; policy engine spec §13 decision 47 rulings 6 and 7, D2 and D5; §15 L67): (a) `CheckPassword` binds a person over LDAPS and over StartTLS, and what a wrong password answers; (b) an unauthenticated bind is what RFC 4513 §5.1.2 warns it is, and `CheckPassword` with an empty password never opens a connection; (c) what a bind answers for an expired, a must-change, a disabled and a locked account, with the right password and with a wrong one, and whether the state shows without the password; (d) the directory's failed-password count after six sign-ins with a wrong password through a broker at port49's default limits (the sixth throttled, no bind) and after nine across a window boundary against the directory's lockout threshold of ten; (e) a wrong code is refused before the directory is asked; (f) the creation time the sign-in reads; and (g) the sign-in end to end, `login --directory` enrolling, `token` minting, and the directory stopped, on the compose stack's broker on etcd and on port49d on the memory store.

## Observation

### How this directory was configured

- Windows Server 2025 Standard Evaluation, installed unattended by `dockurr/windows` from the pinned ISO into a KVM VM (6 GB, 4 vCPUs), and promoted to the first DC of a new forest `corp.example.com` by `Install-ADDSForest` with this build's defaults.
- Set up only over OpenSSH (installed by Windows, started by `oem/install.bat`) as the domain's Administrator. The Windows firewall is off and Windows Update disabled, so the build measured is the ISO's. Ports are published on 127.0.0.1 only.
- L42's fixture, made by `scripts/seed.ps1` with global security groups; the second `netops-oncall` is renamed in, as on Samba.
- SASL EXTERNAL is measured over StartTLS on `ldap://dc1.corp.example.com:30389`, port49's own `start_tls` connection. [MS-ADTS] 5.1.1.2: on the LDAPS port the DC authenticates the connection as the client certificate's identity at the handshake and rejects an EXTERNAL bind there; over StartTLS it maps the certificate when an EXTERNAL bind follows. One LDAPS EXTERNAL row is kept as an observation, with what the run read of that connection: its result code, and WhoAmI with no bind.
- LDAPS serves a certificate from the lab CA (`localhost`, `dc1.corp.example.com`, 127.0.0.1), placed in the NTDS service's own store; the lab CA is in the DC's Root store.
- The URIs name the DC, `dc1.corp.example.com`, which the test process alone resolves to 127.0.0.1, so port49's GSSAPI bind asks for `ldap/dc1.corp.example.com`, an SPN the DC keeps itself. `ldap/localhost`, added to `DC1$` as on Samba, left the account within minutes twice, with no 4742 event naming who removed it. The client `krb5.conf` reaches the KDC at 127.0.0.1:30088 over TCP.
- `port49` is an ordinary domain user, AES only; its keytab is made with `ktpass` (AES256-SHA1, `-mapuser CORP\port49`), which also sets its UPN. `ktpass` takes the password on its own command line inside the VM, the one place a secret is on a command line.
- AD CS: an enterprise root CA `corp-L44-CA` on the DC, `OfflineRouter` published for requests whose subject the harness supplies, and the DC's `KerberosAuthentication` certificate enrolled for PKINIT. The lab users CA and six quirk CAs, each CN holding one character (a comma, a backslash, a slash, a plus, an inner quote, a leading space), are in the DC's Root store and in NTAuth; a quirk CA that failed to publish makes its rows INVALID.
- Each KB5014754 block starts with a control, `control-ski`: alice's AD CS certificate under the strong `X509:<SKI>` mapping, which no part of the claim is about. A block whose control got no TGT is INVALID.
- Each `LdapEnforceChannelBinding` change reboots the DC, and the next cell waits for LDAPS. Restarting NTDS after setting 2 instead was followed, once, in an earlier run on its own fresh DC, by `lsass.exe` crashing (an access violation in `ntdsai.dll` 15 seconds after NTDS came back) and Windows restarting the VM; whether the restart or the binds under 2 that followed set it off was not separated. The DC's boot is read before and after the cells under 2, and a change makes them INVALID.
- The KDC is stopped for one EXTERNAL cell (OR-1) and started again by a task the stop registered; the next cell repeats the mapped bind to show the DC recovered.
- Alice's `User` certificate is requested as alice over WinRM with CredSSP, under a session configuration only she may use; all of it is removed after, and her password for it is made on the DC, used once and replaced. `enroll_as` first registers `WSMAN/DC1` and `WSMAN/dc1.corp.example.com` on `DC1$` (this build's WinRM had registered none, and without them CredSSP refuses the DC as a target); they stay on the lab DC.
- During the KB5014754 table only, `UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = 1` on the KDC: the harness's own CAs publish no CRL, and revocation is no part of the claim. Removed after.
- LDAP interface diagnostics at level 2 (`16 LDAP Interface Events`), so the DC logs bind and channel-binding events.
- PKINIT's client is MIT Kerberos (`kinit` from Fedora 43's `krb5-workstation` and `krb5-pkinit`, the versions its image recorded are in the facts table) on the project network, with `pkinit_kdc_hostname`, as MIT documents for an Active Directory KDC. MIT 1.22 or later is required: Windows Server 2025's KDC answers FFDH PKINIT without MS-PKCA's `paChecksum2` with KDC error 79 ("Checksum must be included"), and MIT added the field in 1.22 (krb5 commit 310793b); MIT 1.20 (Debian stable's, measured on an earlier L44 DC of this build) failed every cell with it; 1.21 lacks the commit.

### Running it again

- From a worktree pinned at the commit under test: `PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$' -count=1 -v -timeout 240m`. It needs `/dev/kvm`, Docker with Compose v2.24.4+, 6 GB of RAM and 66 GiB free; a fresh run takes 1.5 to 2.5 hours. Windows Setup can be watched at `http://127.0.0.1:8006`.
- The evaluation ISO is cached in `PORT49_LAB_ISO_DIR` (default `~/.cache/port49-lab/iso`), checked by size and SHA-256 on every run, and never committed or redistributed.
- `PORT49_LAB_WINDOWS_KEEP` leaves the DC and its secrets up; `PORT49_LAB_WINDOWS_REUSE` runs on a kept DC. Both are for developing the harness: a note from a reused DC says so and never closes L44.
- Under `tests/lab/logs/windows`, `windows.env`, `secrets.json`, `port49.keytab`, `broker-adcs-key.pem` and `pkinit/*-key.pem` hold secrets: never print them. The run removes them unless `PORT49_LAB_WINDOWS_KEEP` is set.
- Never print the project's resolved compose file or inspect its containers: both show the Administrator's password from the environment.

The people's password is generated for each run (24 characters from `crypto/rand`) and held in memory; the evidence writes `<alice's password>` wherever it would have been. Every cell's first row is its positive control. "Failed count" is the directory's own: `pwdFailureTime` values on OpenLDAP, `badPwdCount` on Samba and the DC. The lockout threshold is 10 on all three (OpenLDAP: `pwdMaxFailure 10`, `pwdFailureCountInterval 600`, `pwdLockout TRUE`, `olcPPolicyUseLockout TRUE`; AD: threshold 10, observation window and duration 10 minutes).

| cell | observed |
|---|---|
| a. control | `the broker's bind found alice on dc1.corp.example.com:30636 over LDAPS` |
| a. right password, LDAPS | `ok` |
| a. wrong password, LDAPS | `refused (LDAP result 49, data 52e)` |
| a. control | `the broker's bind found alice on dc1.corp.example.com:30389 over StartTLS` |
| a. right password, StartTLS | `ok` |
| a. wrong password, StartTLS | `refused (LDAP result 49, data 52e)` |
| b. raw unauthenticated bind | `SUCCEEDED, as RFC 4513 §5.1.2 warns; WhoAmI authzId "" (empty is anonymous)` |
| b. control | `a real bind moved the connection count 130 -> 132 (reading it costs 1)` |
| b. CheckPassword(..., "") | `empty_password; connections 132 -> 133` |
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
| f. control | `the directory's own creation time of alice is 2026-10-15T03:01:12Z; SignInEntry read 2026-10-15T03:01:12Z` |
| g. memory, control | `a sign-in before init-enrollments: 503 enrollment_store_lost; enrollments.json exists: false` |
| g. memory, login --directory | `exit 0; enrolled true; password: / code from your authenticator (empty if you have none yet): / Enroll your second factor: scan this with your authenticator app, or type the key / confirm by 2026-10-15T03:27:34.443Z / first code from your authenticator: / port49: signed in with your directory password as user:alice@corp.example.com; your certificate from https://127.0.0.1:33387 is valid until 2026-10-15T15:17:34Z / port...` |
| g. memory, token leaf1 | `exit 0; minted true` |
| g. memory, token with the directory stopped | `exit 0; minted true` |
| g. memory, login --directory --sign-in with the directory stopped | `exit 1; password: / code from your authenticator (empty if you have none yet): / port49 login: the broker did not sign you in: the directory did not answer, so no one can sign in with a password now; anyone already signed in keeps working until their certificate ends (directory_unavailable)` |

**Not measurable here:**

- g: the etcd half (the compose stack's broker on etcd) runs against OpenLDAP only; windows_ad's end-to-end run is the memory-store half
- b: the DC's connection count (ConnectionsAccepted) counts the whole server, including the ssh that reads it; "unchanged" is judged against the least cost of 5 reads, 1, and is best-effort
- f: the seed's time is not independently known on windows_ad, so "within a minute of the seed" is not measured; only that CreatedAt is the directory's own creation time (the control row)

