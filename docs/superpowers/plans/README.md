# Plan roadmap

One plan per design §19 step group, written one at a time (see `CLAUDE.md`). This file is
the standing brief for each plan: what it builds, which spec sections it implements, what
earlier plans hand it, what it must leave for later, and which lab register entries close in
it. When writing plan N, start here, then read the cited sections, then the previous plan.

**Every plan's PR body carries an "Operator-facing notes" section**: a short list of what an
operator will see change — new commands, config keys, reason codes, metrics, device behaviour.
Plan 13 builds the user and admin documentation from these.

Status: **1 merged 2026-09-21** (PR #2); **2 merged 2026-09-22** (PR #4;
fifteen tasks, reviewed per task and whole-branch); **3 merged 2026-09-23** (PR #8, below);
**lab 2026-09-24 merged** (PR #9); **4 merged 2026-09-24** (PR #10;
`2026-09-23-04-policy-engine.md`, twenty-three tasks plus a lab fold, reviewed per task and
whole-branch; the five calls in PR #10's "Questions for Ryan" were decided 2026-09-24 and
built on `feature/gate-rulings`: `operator` renders as level 15 on EOS and NX-OS, a level or
ceiling raise and a regex-constrained widening fail `port49 policy diff`, a refused mint always
does, a policy with no tests is reported `no_tests`, and a `lab:` block announces itself at
start; PR #11); **4b merged 2026-09-24** (PR #12;
`2026-09-24-04b-live-policy.md`, eight tasks: one docs, six code, one docs; reviewed per task
and whole-branch;
its three "Questions for Ryan" were decided security-first: delete unspent tokens whose answer
changed, rewrite every live context on every reload, leave a quarantined device's contexts);
**5a merged 2026-09-24** (PR #13; `2026-09-24-05a-platform-adapters.md`, eighteen tasks: one
docs, fifteen code, one lab, one lab-and-docs; reviewed per task, then a final whole-branch
review, one fix wave and two scoped re-reviews; L22 closed, and the EOS, NX-OS and IOS-XE
adapters `verified: containerlab`); plan 5 is split at the seam below. **5b written 2026-09-24,
revised 2026-09-25** after its pre-flight review and the owner's ruling of that day (decision 26)
(`2026-09-24-05b-projection-capabilities.md`, twenty tasks: one docs, three lab, fourteen code,
one lab, one lab-and-docs), **executed 2026-09-25, and Task 19**, the differential lab test, **on 2026-09-29**, and amended in flight with decision 27 and four lab tasks (3b,
L26b, L26c, the L26 rerun); reviewed per task and whole-branch; **merged 2026-09-29** (PR #14). It closed L23, L24, L26 and L26b;
Task 19, run 2026-09-29, closed L9, L10 and L12; L25 and the new L26c stay open (Plan 5b — As
built, below). **6a written 2026-09-30, revised the same day** after its pre-flight review
(`2026-09-30-06a-bundle-in-process.md`, twenty-two tasks: one docs, one lab, eighteen code, one
lab, one lab-and-docs; plan 6 is split at the seam below, and three owner decisions are listed at
its top), and **executed 2026-09-30** on `feature/bundle-in-process`, reviewed per task and
whole-branch, with a final fix wave. It closed L27 and L28 and opened L29 and L30 (Plan 6a — As
built, below); **merged 2026-09-30 (PR #15)**. **6b written 2026-09-30, revised the same day** after
its pre-flight review (`2026-09-30-06b-inventory-service.md`, twenty-two tasks: one docs, one lab,
seventeen code, two lab, one lab-and-docs); it splits again at the source, leaving the NetBox and
Nautobot connectors and the webhook trigger to plan 6c, and three owner decisions are listed at its
top. **Executed 2026-09-30** on `feature/inventory-service`, reviewed per task and whole-branch,
with a fix wave; Task 20's midnight nights were dropped by the owner's ruling. It closed L29 and
L30, and spec §14's quarantine through a sync passed on four images; it opened L31, slow Cisco
break-glass with single-connection on (Plan 6b — As built, below); **merged 2026-09-30 (PR #17)**. Next,
`fix/breakglass-reset`, which closes L31: **written 2026-09-30** (`2026-09-30-06b1-breakglass-reset.md`, seven tasks: one docs, three code, one lab harness, one lab run, one lab-and-docs; no owner decisions); **executed 2026-09-30** on `fix/breakglass-reset`, closing L31 (Fix `fix/breakglass-reset` — As built, below); **merged 2026-09-30 (PR #18)**. **6c written 2026-10-01** (`2026-10-01-06c-inventory-connectors.md`, seventeen tasks after its pre-flight review the same day: one docs, thirteen code, two lab, one lab-and-docs; no owner decisions, fourteen rulings where spec §10 was silent, recorded as decision 31; it opens L32 and L33); **executed 2026-10-01** on `feature/inventory-connectors`, reviewed per task and whole-branch (MERGE, 0/0/8), with a fix wave, closing L32 and L33 (Plan 6c — As built, below); **merged 2026-10-01 (PR #19)**. Plan 7 is **split into 7a–7h** (below, with one owner decision,
D1, the shared store's backend, which 7a–7c do not need); **7a written 2026-10-01**
(`2026-10-01-07a-revocation-and-broker-limits.md`, thirteen tasks: one docs, ten code, one lab,
one docs; no owner decision, ten rulings recorded as decision 32; revised the same day after its
pre-flight review: one critical, seven important and twenty-two minor fixed, one minor rebutted);
**executed 2026-10-01** on `feature/revocation-and-broker-limits`, reviewed per task and
whole-branch (FIX FIRST 0/1/9, then a fix wave and a MERGE re-review), with a lab-driven fix: the first lab run found the
agent surviving a revocation, and the listener now answers a revoked caller `credential_revoked`
(Plan 7a — As built, below); **merged 2026-10-01 (PR #20)**. **7b written 2026-10-01**
(`2026-10-01-07b-session-lifetime-and-cert-status.md`, thirteen tasks: one docs, ten code, one lab,
one lab-and-docs; twelve rulings recorded as decision 33; one owner decision, D-7b-1, whether a
certificate whose revocation status cannot be established is refused (ruled refuse) and whether
certificate status is required (ruled required, with an explicit `disabled`); it opens L34; revised the same day after its pre-flight review: two critical, thirteen important and
twenty-two minor fixed, one minor rebutted in part; its re-check's three important and five minor
fixed the same day); **executed 2026-10-01** on `feature/session-lifetime-and-cert-status`,
reviewed per task, closing L34 with `cisco_iosxe` the one platform that shows the ceiling warning,
and measuring L2 on five images (open: Junos cannot show it) (Plan 7b — As built, below); final
review done 2026-10-02 (one important: a token outlived its ceiling, fixed in the fix wave);
**merged 2026-10-02 (PR #21)**. **7c written 2026-10-02**
(`2026-10-02-07c-api-and-authorization.md`, fourteen tasks: one docs, eleven code, one lab, one
docs; no owner decision, ten rulings recorded as decision 34, decision 32 amended first by the
owner's answer on the revocations volume; no register row); **executed 2026-10-02** on
`feature/api-and-authorization`, reviewed per task and as a whole branch, the HTTP revocation's
shapes measured on vEOS, the N9Kv, the C8000V and vJunos-router (Plan 7c — As built, below);
final review: one important fixed (a slow revocation resent and reported as not done), re-review
clean; **merged 2026-10-02 (PR #22, merge c485e03)**, and `make test` (with the labpcap audit)
passes on main. **7d written 2026-10-02** (`2026-10-02-07d-shared-store.md`, sixteen tasks in two merges: 7d-1, Tasks 1–8, the etcd backend passing every `storetest` property, the login's one step and the lifted suite; 7d-2, Tasks 9–16, the guard, the config, the identities and roles, port49d on etcd, the crypt alarm, the agent's one connection, the lab and the docs; one owner decision, OD-1, the Go floor to 1.26, recommended accept; sixteen rulings recorded as decision 35; it opens and closes L35). **7d-1 merged 2026-10-02** (PR #24, merge fe23595): Tasks 1–8 plus 4b, 6b and 7b. It delivers:
- the etcd backend;
- the crypt sealing layer, with the Logins witness and the revision-ordered Ledger, including the snapshot-restore regression witness;
- the re-index and sweep;
- `storetest` across memory, crypt, etcd and crypt-over-etcd.

The final review found two important issues, both fixed:
- An unparseable lookup key stopped the refresh fleet-wide.
- A wrong encryption key would have revoked every session; a context under an unknown key is now never revoked.

The re-review also fixed r-m1: a refresh that skips anything keeps `port49_policy_refresh_pending` set. The flake fixes merged first, as PR #23.

Carried to Task 12: `ledger.Seal()` needs a test, and must be called only after the start's re-index. Carried to 7d-2: a `{}` answer on the admin socket to `port49 revoke` still exits 0.

**7d-2 executed and merged 2026-10-03 as PR #25** (merge 9282085; base 06d0821;
Tasks 8b–16 plus a new Task 13b, each reviewed). It delivers:
- the guard: a hard timeout on every store call, three pools with a circuit each, and going
  dark;
- `store:` in `port49d.yaml`, and every packet's store deadline;
- an etcd identity and role per component, checked at every start, and `port49d store-roles`;
- port49d on etcd: one per keyspace behind a fenced hold, every standing mark applied at the
  start, live sessions kept across a restart, and going dark in-process when the store is gone;
- the crypt alarm;
- a ledger keyed on each write, so an earlier version of a context put back while port49d
  runs is denied (Task 13b, Ruling T12-g);
- the agent's one connection.

L35 is measured and closed on five images. The lab's snapshot restore found a ledger bug, fixed
in 79812ef (Plan 7d — As built, below). **7e written 2026-10-03** (`2026-10-03-07e-broker-process.md`, twenty-three tasks in two merges (eighteen, and 8a, 15a, 15b, 15c and 15d): 7e-1, Tasks 1–10 and 8a, the store a fleet of processes shares (a sealed write sequence and a high-water ledger per key, the context and marks feeds, the ledger record the daemon cannot write, `superseded` in the store, the decision-log emits under the hold, two carried fixes); 7e-2, Tasks 11–18 and 15a–15d, `port49-broker`, port49d on etcd with no broker inside, one runner per keyspace, the revocations file retired on etcd, and the lab; nineteen rulings recorded as decision 36; one question for Ryan, OR-1, `port49 revoke`'s default socket, closed by Ryan 2026-10-03 as recommended (unchanged); it opens L37 and L38 and measures them with L36); **7e-1 executed 2026-10-03** on `feature/broker-process`, each task reviewed (Plan 7e — As built, below). **7e-2 executed 2026-10-04** on `feature/broker-split`, each task reviewed, L36, L37 and L38 closed and L40 opened (Plan 7e — As built, "7e-2", below); **merged 2026-10-05** as PR #27, merge 6438e26. **7f written 2026-10-05** (`2026-10-05-07f-go-dark-and-context-cache.md`, ten tasks: the container shape (image, compose stack on etcd, CI smoke test), the lab on the compose stack with L39 (a), one docs, three code for go-dark on store health checks (N failures, M passes; the idle gap closed), two code for the context cache, one lab (L41, opened by it), one docs; nine rulings recorded as decision 37; two questions for Ryan, OR-1 the health defaults and OR-2 keeping close-and-wait, each with a recommendation, both approved by Ryan 2026-10-05 as recommended); **7f executed 2026-10-05** on `feature/go-dark-and-context-cache`, each task reviewed, L39 (a) measured and L41 opened and closed (Plan 7f — As built, below); **merged 2026-10-05** as PR #28, merge 0cd6926. **7g written 2026-10-05** (`2026-10-05-07g-the-directory.md`, nineteen tasks: one docs, fifteen code, two lab, one docs; twenty rulings recorded as decision 38; three questions for Ryan, each with a recommendation: OR-1 the defaults (`session.staleness_ceiling` 4h, `directory.grace` 4h, `broker.refresh_interval` 5m), OR-2 GSSAPI through go-ldap and gokrb5 (pure Go), OR-3 Samba AD standing in for Windows Server AD in the lab; it opens L42 and L43); **7g pre-flight 2026-10-05**, READY WITH FIXES (2 Critical, 17 Important, 17 Minor), every finding applied to the plan: a refusal is stored and never served from grace, a principal is one entry's alone and pinned to its immutable id (`port49 directory forget` is the operator's way out for an entry re-created), and OR-3 split so L42 and L43 close on OpenLDAP and Samba AD while a new L44 (Windows Server AD) stays open until measured. **7g executed 2026-10-05 to 2026-10-06** on `feature/the-directory` (base `ad4edff`), each task reviewed, L42 and L43 closed on OpenLDAP and Samba AD and L44 (Windows Server AD) left open for the SER8 box (Plan 7g — As built, below); **merged 2026-10-06** as PR #29, merge e16f4bb. **Ryan answered 2026-10-06:** OR-1 (the 4h/4h/5m defaults), OR-2 (GSSAPI through gokrb5), PF7g-g (the bind hold-off) and OR-3 (L44 on SER8, after a usage reset, not before 2026-10-06 15:00) approved; PF7g-i (the composition rule) confirmed. L44 stays open. **7h written 2026-10-06** (`2026-10-06-07h-oidc-and-trust-domains.md`, seventeen tasks: one docs, thirteen code, two lab (the Keycloak harness, then the run with an end-to-end on vEOS), one docs; twenty rulings recorded as decision 39; three questions for Ryan, each with a recommendation: OR-1 JOSE in-house on the standard library (no new module), OR-2 the defaults (`clock_skew` 60s, `max_token_age` 2h, `jwks_refresh_interval` 1h, `jwks_max_age` 24h), OR-3 hosted providers as their own row, L47; it opens L45 (the logout token Keycloak sends) and L46 (`prompt=login`, `auth_time`, `nonce` on Keycloak), and L47 (both on Entra ID and Okta), which stays open). **7h pre-flight 2026-10-06**, READY WITH FIXES (2 Critical, 13 Important, 23 Minor), every finding applied to the plan: a machine verifier takes listed clients with a pinned `sub` and refuses a person's delegated token (ruling 21), each human verifier names its `principal_domains` so no second issuer mints another's people (ruling 22), `principal_claim` is required with no default (ruling 23), an owner record keeps every principal of a `sub` (ruling 24), and Task 3 gains Project Wycheproof's vectors, an algorithm × key-type matrix and fuzz targets; decision 39 now has twenty-four rulings, and OR-1 stays Ryan's, recommended in-house. **7h executed 2026-10-06 to 2026-10-07** on `feature/oidc-and-trust-domains` (base `2614adc`), each task reviewed. L46 is closed on Keycloak 26.4.7, and L45 is measured but open: an administrator's sign-out over two sessions sent one `sid`, and ruling 13 options A/B wait on Ryan. L47 is open. The final review's Critical, a burst of back-channel logouts losing all but the first, is fixed by `Connection: close` (Plan 7h — As built, below). **Merged 2026-10-07** as PR #30, merge 86e058a. OR-1 to OR-3 approved by Ryan 2026-10-07 as built, and ruling 13 option B approved the same day. **L44 plan written 2026-10-06** (`2026-10-06-07g-l44-windows-server-ad.md`, eight tasks: five harness (the 7g harness extended for a third platform, the Windows helpers, the compose project and fifteen PowerShell steps, the DC's bring-up with a feasibility gate, the measurement), one lab, one defect path (7a quoting `<I>`, 7b the serial's sign byte, 7c an EXTERNAL result 1, each only if the run calls for it), one docs; Windows Server 2025 Evaluation (26100.32230) as a KVM VM in `dockurr/windows` 6.06, both pinned, set up over SSH, the DC's own mapping measured by MIT PKINIT and by EXTERNAL under each KB5014754 value; eight rulings R1–R8 in the plan; three questions for Ryan, each with a recommendation: OR-1 count an EXTERNAL result 1 as a refusal if Windows answers it, OR-2 close L44 on 2025 alone, OR-3 document and carry GSSAPI channel binding; the root LV needs about +80 GB first; it touches no 7h code). **L44 run 2026-10-07** on SER8 (runs 6–8; run 8 clean on a fresh DC): 7a and 7b fire, GSSAPI against AD needs the AP option mutual-required (a port49 defect, 7d), and EXTERNAL is measured over StartTLS, since AD refuses it on LDAPS ([MS-ADTS] 5.1.1.2). A DC whose KDC is down answers 49, as an unmapped certificate does (OR-1, with Ryan). **Fix wave merged 2026-10-07:**
- PR #32: 7d, GSSAPI mutual-required.
- PR #33: the marks-lift durability fix.
- PR #34: 7a, 7b and 7e, the `issuer_serial` quoting; `\` and `/` are measured as unquoted.
- PR #35: ruling 13 B, a logout carrying both `sid` and `sub`.
- PR #36: L44 OR-1, a per-DC refusal on EXTERNAL.
- PR #37: M5, the Windows DC in UTC.
- PR #38: the L45 follow-up run.
- PR #39: a `sub` logout's refusal names the time a login is taken from.

**L44 is closed on Windows Server 2025** (Task 8, 28bb29e; L44 — As built, below). **L45 is closed on Keycloak 26.4.7** (PR #38): one sign-out ended both sessions, and eight back-to-back logouts all arrived. L47 is open. **8 written 2026-10-07** (`2026-10-07-08-workload-certificates.md`, fifteen tasks):
- Two docs tasks, ten code, one example (`examples/oxidized`) and two lab.
- Decision 40 holds the rulings. It opens L48 (step-ca) and L49 (Oxidized end to end), and L50 for plan 8b.
- **8 pre-flight 2026-10-07:** READY WITH FIXES (1 Critical, 6 Important, 19 Minor), every finding applied to the plan.
  - Decision 16's mapping of a workload certificate to its directory groups is deferred to a named plan 8b, limited to machine-scoped group subjects, not withdrawn.
  - One `certificate_status` block.
  - Minting by `scope` goes to plan 9.
  - No questions for Ryan.
- **8 executed 2026-10-07 to 2026-10-08** on `feature/workload-certificates` (base `f789c3f`), each task reviewed. L48 (step-ca 0.30.2) and L49 (Oxidized on five images) closed, with the example corrected to them. The lab drove ruling 17 (a CRL scoped to a distribution point, per RFC 5280), and ruling 7 now separates an OCSP outage from an uncovered status. It also found the broker's first-takeover purge window, a plan 7e bug (Plan 8 — As built, below). **Merged 2026-10-08** as PR #40, merge 21dda4c.

The purge-window fix merged as PR #41 (fc89f47): port49-broker's mint gate is closed at a start
until a takeover judges its bundle; no new §5.7 reason (it reuses the gate's `store_unavailable`).
Carried to the pre-beta review: `internal/broker/member.go`'s bind-refusal 503 details say "the
agent retries", which it does not. L51 (SSH keys offered before the password) opened 2026-10-09
and closed the same day on five platforms (PR #42), which also opened L52 (a C8000V skipping its
TACACS+ method). **8b merged 2026-10-09** (PR #43, bb948e5). **8b written 2026-10-09** (`2026-10-09-08b-workload-directory.md`, eight tasks, six
rulings Q1–Q6 recorded as decision 41); **8b executed 2026-10-09** on `feature/workload-directory`
(base `df198b2`), each task reviewed and whole-branch reviewed (0 Critical, 2 Important, 6 Minor,
fixed or parked), closing L50 (Plan 8b — As built, below). **9a merged 2026-10-09** (PR #44,
d81cf75), built on `feature/sweeps-and-ssh` (base `40cbb23`; Plan 9a — As built, below), each task
reviewed and whole-branch reviewed (0 Critical, 1 Important, 8 Minor, fixed or carried), closing
L53 and L54. Next: 9b–11. 12–13 not yet.
**9 split into 9a–9d, and 9a written 2026-10-09** (`2026-10-09-09a-sweeps-and-ssh.md`, nine tasks:
one spec, five code, one example, one lab, one docs). It covers mint by `scope` with no enumeration
oracle, `port49 workload token --scope`, the per-user config file, pinned host keys with `port49
devices trust`, `port49 ssh` over the operator's OpenSSH with a one-time askpass, the in-session
ceiling warning, and the Netmiko example. Decision 42 holds its fourteen rulings. Its five
pre-flight questions, Q1–Q5, were ruled as recommended on 2026-10-09 (Plan 9, below), and it opens
L53 and L54. Pre-flight review 2026-10-09: 0 Critical, 10 Important, 17 Minor, all folded in; the
OpenSSH floor rose to 8.5 on a container measurement
(`tests/ssh-compat/2026-10-09-openssh-askpass.md`). 9b–9d are outlined under "Plan 9".
**9b written 2026-10-09, rewritten 2026-10-10** on Ryan's direction of that day
(`2026-10-09-09b-oidc-public-client.md`, thirteen tasks: one spec, ten code, one lab, one docs). The
2026-10-09 draft held the provider's tokens in the agent; the rewrite makes design §7's issued
certificate v1. `port49 login --oidc` signs in at the provider (PKCE S256 over a loopback redirect,
`prompt=login`, a pasted address on a host with no browser, no device grant), generates a key on the
host, and the broker issues a short-lived client certificate for it from its own issuing CA (`POST
/v1/certificate`; the sign-in's `nonce` names the key, and its `sid` travels in the certificate).
The agent then runs the certificate path unchanged, so a refresh and a new agent's extension are key
signatures, and pre-flight D1 dissolves. A broker that issues takes a person's ID token nowhere else;
its CA is made by `init-issuer`, rotated with overlap, and never stops a start. The client's config
moves to `~/.port49`, under a root-owned `/etc/port49/config.yaml` the install ships, so a new user's
first login is `port49 login` and the sign-in (Ryan's no-toil rule); the broker sends its CA
bundle and each agent keeps it, so a rotation of the broker's CA asks nothing of users. Decision 43
holds its twenty-five rulings; three questions (Q1 when 7h's bearer path for people retires, Q2 where the
lifetime is set, Q3 the held key reused across agents), each ruled as recommended on 2026-10-10 by
the controller under Ryan's standing grant. It opens
L55 (Keycloak as the client meets it) and L56 (issued certificates end to end on vEOS). 9e, a
directory-password sign-in issuing the same certificate, is added to Plan 9.
**9b executed 2026-10-11** on `feature/oidc-public-client` (base `48a67a3`), each task reviewed,
closing L55 (Keycloak 26.4.7) and L56 (vEOS 4.31.2F) on 2026-10-11 (Plan 9b — As built, below);
L47 stays open. **9b1 written 2026-10-11, executed 2026-10-12** on `feature/junos-groups-and-junoscript`
(Plan 9b1 — As built, below), on Ryan's four rulings of that day, slotted before 9c
(`2026-10-11-09b1-junos-groups-and-junoscript.md`, eleven tasks: one spec, one lab harness, one
lab run before code, six code, one lab run and close, one docs). Set 1.2.0 adds a per-user
`junoscript` deny where a deny sits beneath a sent Junos bit, so that subject projects instead of
failing closed and loses only NETCONF; `devices check-config` reads configuration groups, names a
group that widens a template, and takes `--batch`. Decision 44 holds its ten rulings; the
controller ruled the security narrowing of Ryan's services ruling (J-Web and JET/gRPC stay
findings, REST as measured) at pre-flight. On Ryan's ruling after pre-flight, a readonly with a
deny beneath `show **` projects too (ruling 10: `xml-mode` closed by the entry deny, `save`
measured into the tree, one factored alternative, carved allows, the narrow shape kept where
its bits reach every allow). It opens and closes L57 and L58, closes L26c, and opens L59 for what
no cell measured.
**9c written 2026-10-12** (`2026-10-12-09c-hardware-keys-and-per-login-mfa.md`, seventeen tasks: one
spec, one macOS spike, eleven code, two lab, one gated code, one docs). The key moves into
hardware behind the agent's one `crypto.Signer`: PKCS#11 through purego, TPM 2.0 through go-tpm,
the Secure Enclave built without a Mac, experimental and opt-in (Ryan's ruling, 2026-10-12; gate SE1
is a check a Mac user runs).
`port49 login --oidc` generates its key in the TPM by default (`issued_key_store: auto`). The key
unplugged never ends a session. `per_login_mfa` takes four levels (`defaults:`, a role, a scope by
attribute, a scope by `name`), the strictest winning as an intersection; a proof is a touch on an
attested always-touch slot of the session key's own token or a fresh IdP sign-in with MFA, posted to
`POST /v1/mfa` against the mint's challenge and reused for `reuse_for` within one agent session; a
reload adding a requirement revokes nothing, and a refresh needs a proof. The agent checks the
broker certificate against its CRL (`broker_crl: check`). SoftHSM2 and swtpm run under `make
test-hw` and a new `hwkeys` workflow. Decision 45 holds its twenty-six rulings; it opens L60 (a
YubiKey on the SER8, Ryan present, placed late), L61 (Keycloak's `amr`), L62 (the SER8's TPM) and L63
(the Secure Enclave).
**9c executed 2026-10-12 to 2026-10-13** on `feature/hardware-keys-and-per-login-mfa` (base
`e8d3e1a`), each code task reviewed (Plan 9c — As built, below). L61 closed; L60 half measured on a
YubiKey 5C Nano FIPS, so it stays open; L62 open. The Secure Enclave (Tasks 2 and 14) is built,
experimental and opt-in, cross-compiled and vetted for darwin in CI, and run on no Mac: L63 stays
open, marked needs testing on macOS.
**9d written 2026-10-13** (`2026-10-13-09d-openssh-host-keys-and-python-clients.md`, thirteen tasks:
one spec, one OpenSSH container measurement (gate G1, the floor), eight code, two lab, one docs) on
Ryan's rulings of 2026-10-10. Host keys become OpenSSH's: `port49 ssh` passes
`StrictHostKeyChecking=accept-new` (the operator's own `yes` stands, `no` never passes) and the
inventory name as `HostKeyAlias` (the operator's own stands), read through `ssh -G`, and nothing
else about host keys; `port49 devices trust`, `internal/hostkeys` and the pins file go (no admin
reason survived), which ends 9b's group-writable `~/.config` refusal and makes 9a's I-1 moot. The
Python library (`clients/python`, Python 3.10+) drives the CLI rather than the API, so the
per-login proof, PINs, hardware keys and the broker CRL check stay in one implementation;
`port49 token --json` and `workload token --format json` say why a mint failed, as JSON; Netmiko
takes accept-new under the inventory name in the operator's known_hosts. The Ansible lookup is
`port49.client.token`. Decision 46 holds its seventeen rulings; L53 and L54 stay closed (claims
amended), and it opens L64 (`port49 ssh` under accept-new, a reload included), L65 (Python and
Netmiko) and L66 (the Ansible lookup).
**9d pre-flight 2026-10-13**, READY WITH FIXES (1 Critical, 8 Important, 18 Minor), every finding
applied to the plan: the Python client drops any key an `@revoked` line or `RevokedHostKeys` names
and checks a first contact's key before authentication (Netmiko's `key_policy`), and refuses a
`KnownHostsCommand` it cannot run; both clients refuse an ssh_config that keeps no host keys under
accept-new; the askpass answers the prompt naming the operator's alias; the Python client checks
decision 42 ruling 8's name rule before minting; `--format json` prints `"results": []`, never
`null`, and the Python tests are fed the CLI's own bytes; gate G1 is measured in the attack's
shape (a server offering only Ed25519 against a filed ECDSA key) by a standalone 8.5p1 harness;
and the docs say what Ansible's address keying leaves open, never recommending
`host_key_auto_add` under `ssh_type: paramiko`, which rewrites `~/.ssh/known_hosts` without its
`@revoked` and `@cert-authority` lines.
**9d executed 2026-10-13 to 2026-10-14** on `feature/openssh-host-keys-and-python-clients` (base
`b898e1c4`), each code task reviewed (Plan 9d — As built, below). G1 passed on OpenSSH 8.5p1 to
10.2p1, so the 8.5 floor stands. L64, L65 and L66 are closed on all five platforms. Ansible's
`network_cli` address keying stays an open gap; Ryan ruled 2026-10-15 to close it in the lookup (plan 9f, `2026-10-16-09f-network-cli-host-keys.md`). L66
showed the pre-flight's paramiko guess above wrong (spec ruling 15 corrected): libssh is the
`ssh_type` that accepted a changed key under `host_key_auto_add`.
**9e written 2026-10-14** (`2026-10-14-09e-directory-password-sign-in.md`, fifteen tasks), on Ryan's
rulings of that day: D1–D11 as recommended, D7 as a sealed file on the memory store that fails
closed when lost (`enrollment_store_lost`, never a reopened window), D12 a separate enrollment
store handle that can point at a global etcd. The global and regional split itself is plan 11a.
**9e pre-flight 2026-10-14**, 5 Critical, 15 Important, 14 Minor, every finding applied to the plan.
**9e executed 2026-10-14 to 2026-10-15** on `feature/directory-password-sign-in` (base `7c7bdf84`),
each task reviewed (Plan 9e — As built, below). **L67 is closed** on OpenLDAP, Samba AD and Windows
Server 2025 AD (2026-10-15), and the lab corrected ruling 7 (a state is named only past a right code
or when the directory's refusal proves the password). **9e merged 2026-10-15** (PR #10, merge
`4bacd553`) after the final review (0 Critical, 2 Important: every replica now rechecks a lost
enrollment store every 30s, and a broker-side search fault answers `directory_unavailable`) and a
re-review. **L62 closed 2026-10-15** (PR #9, the SER8's TPM, `tests/lab/results/L62-ser8.md`).
Next, on Ryan's rulings of 2026-10-15: a small
fix branch for issues #5 and #8, then a small plan that closes the `network_cli` address-keying gap
(both under 9e's Carried, below). **The fix branch merged 2026-10-16** (PR #14, `647f5e30`;
also #11, `port49 token` retries `store_unavailable` for up to 30s). **9f written and executed
2026-10-16** (`2026-10-16-09f-network-cli-host-keys.md`, four tasks, each reviewed; Plan 9f — As
built, below): the lookup checks `network_cli` host keys before it mints, measured as L66 (e3) to
(e3d) on arista_eos.
**9g written 2026-10-16** (`2026-10-16-09g-junos-view-configuration.md`, seven tasks: one lab
cell first, gate G1 (L68); one spec; three code; one lab run through the broker; one docs). It
builds Ryan's ruling of 2026-10-15 ("Ruled 2026-10-15 (Ryan)", below). Where a readonly (or an
operator, gated separately by L68's row O) permits
`show configuration` under a deny beneath `show`, the reply sends `view view-configuration` and
denies the rest of view-configuration's reach that the grant leaves undecided. For `show **` less
`show security **` that is `monitor **`, in a 173-byte `deny-commands`. Nothing after Task 1
starts unless L68 passes on both images. A refused probe running in row P is a live 1.2.0 hole,
reported for Ryan. It ships as **set 1.3.0, not 1.2.0**: the controller ruled on 2026-10-16 that
1.2.0 is released and frozen, and the behaviour is the one Ryan ruled. Set 1.3.0 is 1.2.0 plus
`juniper_junos`'s `deny_reach_bits: [view-configuration]`. Set 1.2.0 already renders this reply
to a grant that writes `deny: [monitor **]` itself. Where the added denies would pass 255 bytes,
the reply falls back to the 1.2.0-style one, and CI warns `projection_reach_deny_overflow`
(controller's ruling). Decision 48 holds its rulings. It opens and closes L68. **9g pre-flight
2026-10-16**: 0 Critical, 8 Important, 11 Minor, every finding applied to the plan. Among them:
- L68 gains an operator row, the exec channel, `show cli authorization`, configuration-mode entries
  and an scp reading;
- a STOP note is written only for a run that is otherwise valid;
- the budget fallback's recursion is guarded;
- Task 6 gates `show configuration` running;
- the plan ends with operator notes.
**9g executed 2026-10-16** on `feature/junos-view-configuration`, each task reviewed (Plan 9g — As
built, below); L68 closed.
**10 written 2026-10-16** (`2026-10-16-10-kubernetes-path.md`, twelve tasks: one spec, seven code,
one example, one lab harness, one lab run, one docs; sixteen rulings recorded as decision 49 by
its Task 1; two questions for Ryan, each with a recommendation: Q1 one service account name in
several clusters (refused; name accounts per region), Q2 TokenReview for a deleted account's
immediate effect (not built; `port49 revoke --principal` closes the 2h window). It opens L69
(kind) and L70 (managed clusters, left open).
**10 executed 2026-10-16** on `feature/kubernetes-path` (rebased onto main `02ca1ce8`), each task reviewed
(Plan 10 — As built, below). Ryan's Q1 ruling reversed the plan's recommendation: clusters may
share a namespace, and each k8s verifier is named by a required `cluster:`. Q2 stands: no
TokenReview. L69 closed on kind (v0.29.0, Kubernetes v1.33.1); L70 (managed clusters) stays open.
**11 written 2026-10-16** (`2026-10-16-11-tls-listener.md`, fourteen tasks: one spec, nine code, two
lab harnesses, one lab run, one docs; nineteen rulings recorded as decision 50 by its Task 1; two
questions for Ryan, each with a recommendation: Q1 the images that carry an RFC 9887 client
(fetch C8000V 17.18 first), Q2 one host serving both listeners (keep the start notice). It opens
L71 (which lab images carry a client; every lab image predates the vendors' documented floors), L72
(port49 against reference clients, closed in the plan) and L73 (device behaviour, open until Q1's
images).
**11 executed 2026-10-17** on `feature/tls-listener`, each task reviewed (Plan 11 — As built,
below). Q2 stands: one host may serve both listeners, with the start notice. Q1 is pending with
Ryan: TACACS+ over TLS arrives in Junos 26.2R1 on routing and switching platforms, not SRX, and an
image of it and of C8000V 17.18.1 or later is to be fetched. L71 and L72 closed; L73 open.
**11a written 2026-10-17** (`2026-10-17-11a-directory-and-session-stores.md`, twenty-two tasks;
decision 51; Ryan's rulings of 2026-10-17 as R1–R10 and R13; Q1, a back-channel logout's reach across
regions, ruled by the team lead as R26: logout records in the directory store). **11a pre-flight
2026-10-17** (2 Critical, 9 Important, 20 Minor), applied on the team lead's rulings: directory pins
with no lease, one set of encryption keys checked at start (R27), a sealed directory snapshot a
process restarted during a cut serves from to the staleness ceiling (R19), a runner that takes over
during a cut (R29), one cluster named twice refused (R28), no migration (R25), L75 as code; one
minor not taken, ledgered as R30. **Re-review 2026-10-17** (1 Important, 4 Minor), applied: port49d
serves the union of every marks snapshot and writes only its own, a broker's pins and logouts in a
record it cannot read, a heal-time key fault exits 1, only the heal's load lifts the ceiling, and a
forget re-run after a directory restore. It opens L74 and L75.
**11a executed 2026-10-19** on `feature/directory-and-session-stores` (Plan 11a — As built, below); L74
and L75 closed.
**L73 measured 2026-10-18** (`2026-10-17-l73-device-tls.md`; branch `test/l73-junos`): vJunos-router
26.2R1.7, C8000V 17.18.02, N9Kv 10.6(2)F and cEOS-lab 4.36.3M, all ten cells each; L71 addenda for
those four, IOL-XE 17.18.02 (no client) and XRd 26.1.1 (lists `tls`); L73 closed (vJunos-switch
skipped; SRX unmeasured; a full L73 row on XRd 26.1.1 goes to the qualification-suite plan).
**L76 measured 2026-10-18** (`2026-10-17-l76-srlinux.md`; branch `test/l76-srlinux`): Nokia SR Linux
26.7.2-519 over TACACS+, cells (a)-(l); L76 closed. Inputs to a `nokia_srlinux` adapter and plan 12's
SR Linux reference config:
- priv-lvl maps to the local roles at or below it, and priv-lvl 1 gets `p49-read` only (h); each local
  role must list `services [ cli ]` or the login is refused.
- `priv-lvl-authorization false` (the default) sends port49 no authorization request, so port49's
  privilege and role answer is never asked for (i). The YANG says that is full admin; the run measured
  only reads. The reference config sets it true.
- A port49 deny falls through to local with `exit-on-reject` at its default (d). With it true (l),
  break-glass is **refused while port49 is up and denies it**, and still logs in through local with a
  wrong shared secret or with port49 stopped; the reference config sets it knowing that cost.
- The second exec channel of one login is accounted at priv-lvl 15 on port `unknown`, even for a
  priv-lvl 1 user (c, h); the session table shows `p49-read` on both channels and a checkpoint write is
  refused on both (k), so the accounting is not shown to add authority for a write.
- Accounting is per CLI command, start and stop, with no exec session records (c); port49 redacts the
  word after `authentication` in `show system aaa authentication` (c).
- After a port49 restart the device asked again within 1 s, and health checks open connections that carry
  no payload and write no records (g).

**11b written 2026-10-19** (`2026-10-19-11b-qualification-suite.md`, twenty-three tasks: one spec, thirteen
code, five lab, two CI, two docs; decision 52 written by its Task 1). Its pre-flight review (5 Critical, 14
Important, 14 Minor) is applied as revision 1 the same day. The team lead ruled Q1 (the SR Linux job runs on
dispatch and release tags) and Q2 (an L78 result showing no lockout on vJunos leaves the Junos rule
unmeasured and L78 open for hardware Junos; decision 48 ruling 4 is provisional on L78). It builds mock
devices from closed lab evidence, `make lab-regress` and `make qual-vet` (Plan 11b, below).
**11b executed 2026-10-21** on `feature/qualification-suite` (Plan 11b — As built, below): eleven
platforms vetted, L79 closed, L80 opened and closed, L78 measured and still open for hardware Junos.
**12a written 2026-10-24, revised 2026-10-25 after its pre-flight** (`2026-10-24-12a-server-hardening.md`,
sixteen tasks: one spec, fourteen code, one docs; decision 53, rulings 1–12, written by its Task 1). Plan 12 is split into 12a (server code), 12b (deployment
artifacts, release, publishing) and 12c (reference configurations, alarms, lab rows), each merged before
the next is written (team lead, 2026-10-24). It covers:
- `secret_ref` (`env:` and `file:` only; a secret store reaches port49 as a file its agent renders: Ryan, 2026-10-25) in place of every `*_env` secret key;
- the key sets moved into the policy file, bounded by port49d.yaml's `key_secret_refs`, and a reload
  waiting on a secret file retried every 30 s;
- one YAML document per file;
- the source-of-truth client's egress proxy;
- the global connection cap, shedding at Accept;
- the etcd floor at start;
- the broker start surviving a compaction;
- the issuing-CA record (the key stays on each broker's disk: Ryan);
- the fence's ancestor walk.

It opens no lab row. **12a executed 2026-10-26 and 2026-10-27** on `feature/12a-server-hardening` (Plan 12a — As built, below);
**merged 2026-10-27** (PR #35). **12b written 2026-10-27** (`2026-10-27-12b-deployment-release.md`, seventeen tasks: one
spec, two code, two CI, seven artifact-and-smoke, four lab, one docs; decision 54, rulings 1–14, written by its Task 1). It builds
the systemd, container and Kubernetes shapes as peers, each with a CI smoke test, plus the tag-only release (packages, image,
chart, PyPI, Galaxy), `make test`/`make vet` in CI, the in-place key rewrite warning, and lab rows L82–L85.
**12b executed 2026-10-27 to 2026-10-30** on `feature/12b-deployment-release` (Plan 12b — As built, below; draft PR #36). Lab states: TODO(L82), TODO(L83), TODO(L85), TODO(L86).

**2b merged 2026-09-23** (PR #7; `2026-09-23-02b-context-join.md`, nine tasks, reviewed
per task and whole-branch): a second login by the same principal joins the live context
instead of replacing it, stored privilege is raise-only, and accounting attribution gets a
metric. PR #7's body lists three fail-closed follow-ups (one uniform "login into a revoked
result" check after `JoinContext`) for plan 3 to pick up.
**3 merged 2026-09-23** (PR #8; `2026-09-23-03-vertical-slice.md`, eighteen tasks:
thirteen code, three lab, two docs; reviewed per task and whole-branch; first real
certificate-to-device login measured on vEOS). It closes PR #7's first two follow-ups and carries the third to plan 7; its
"Questions for Ryan" section has three open calls.

---

## Plan 1 — Protocol core (§19 step 1) — `2026-09-06-01-protocol-core.md`

RFC 8907 wire, key trial, admission from a file inventory, per-source limits, in-memory
store, authentication/authorization/accounting handlers, decision log, config, `port49d`
binary, containerlab harness. Closes L1 (SSH transport only), L2, L5, L6, L8, L10.

## Plan 2 — Token model (§19 step 2) — `2026-09-22-02-token-model.md`

**Rewritten 2026-09-22 and executed on `feature/token-model`.** The 2026-09-06 draft assumed the `(nas, port)`
login-context key, which the lab showed breaks every measured vendor; the key is now
`(nas, username)` (spec §13 decision 15). The rewrite is against the real tree on
`feature/lab-l4-fallthrough` and carries every ruling in
`2026-09-20-plan-2-revision-notes.md`, the owner's 2026-09-21 ones included
(`contexts_by_principal` stays unencrypted, and why). **Fix round 1 applied 2026-09-22** after
review: **fifteen TDD tasks, sixteen commits**. The spec §5.8 edit for `system` attribution is
committed before the code that reads it, and now also carries §13 decision 15's record that the
`(nas, rem_addr)` enable index is deferred while `enable_username: enab` is refused at load.

**Builds:** the full token semantics on top of plan 1's store interface and handlers.

- Token format with the **device tag**: `tag ‖ secret`, `tag = base62(HMAC(k, device_id))[:6]`,
  24 random characters; daemon compares its own tag before any store access; `device_mismatch`
  under PAP/ASCII/HTTP, `token_not_found` under CHAP. Design §8 "Device binding".
- **Encryption at rest** for tokens, receipts, login context, and the idempotency record,
  with a key shared by broker and daemon and a two-key rotation window. Design §8.
- **Sliding receipt, not a `reusable` flag** (owner, 2026-09-21: "Bob shouldn't need to
  know"). Each re-presentation of the same `(nas, username, credential_sha256)` extends the
  receipt by `receipt_idle_ttl`, up to an absolute `receipt_max_age` from first redemption;
  a presentation past either is FAIL on the wire and `token_spent` in the log (the §5.7 row
  landed with decision 15's rewrite on 2026-09-22; the plan adds only the Go constant);
  revocation deletes the principal's receipts, so receipts are indexed by principal.
  **Defaults ruled 2026-09-22: 15 min idle, 2 h absolute** (Ansible linear strategy over a
  large fleet is the sizing case, L15). Decision 15's text is already replaced.
- **Device-generated accounting under another user** (Junos root RPC in production, NX-OS
  `admin` with `task_id=vsh.bin.$port`) must not trip `foreign_session`: a per-platform rule
  attributing them `system`, which needed a spec §5.8 sentence. **Ruling R1 (Task 11) reversed
  the "ships empty" plan on measured evidence, and spec §5.8 now carries the packet dump behind
  it**: `juniper_junos` ships **`root`** (`internal/platform/platform.go:213-216`).
  `tests/lab/evidence/L1-juniper_vsrx.pcap`, the committed capture behind
  `tests/lab/results/L1-juniper_vsrx.md`, holds three accounting records under `user=root`,
  `port=non-tty`, carrying their own `session_pid`, with no authentication and no authorization
  exchange for root anywhere in the file — vSRX's own alarm machinery writing accounting for a
  session port49 was never asked to authenticate. Without the row a stock vSRX with nothing
  wrong reports sessions port49 did not authenticate. **Every other platform ships empty**,
  including `juniper_vjunos-router` (the same decode of its capture finds no root records, so
  the behaviour is image-specific) and `cisco_nxos` (the `vsh.bin` observation is
  production-only and still has no note). Plan 5 fills the rest, from notes.
- **Refuse at mint any username canonicalization would change**: `Canonical` folds U+0130 onto
  `i`, so two directory names could share one `(nas, username)` context — and it also strips
  `DOMAIN\` and truncates at `@`, which an ASCII-only guard would let through, minting a token
  under a key no redemption can address. `Canonical` moves to `internal/username` so the minter
  can enforce it without importing the daemon that imports the minter.
- **Enable tokens**: mint pair with `kind`. No measured platform sends `$enab{level}$` (L3
  closed): vEOS and IOS-XE send the operator's own username with `service=enable`, NX-OS 10.x
  has no enable. The lookup is therefore the ordinary `(nas, username)` context; an enable
  START must update `privilege` in place and keep `ctx_id` (plan 1 replaces it, measured);
  candidate set filtered to `kind: enable`; `token_kind_mismatch`;
  `enable: none | auto | token`; `rem_addr` binding on enable. `$enab{level}$` becomes an
  explicit `platforms.<name>.enable_username: enab` option **refused at load** until a
  `tests/lab/results/` note shows a device sending it, which is also what keeps
  `enable: auto` inside §5.6's restriction. No `(nas, rem_addr)` index is built, so no new
  reason code is minted for it. Spec §7, §5.6.
- **Candidate-set cap** (order of eight) refusing the mint, never the redemption. Design §8.
- **Full store record set**: `blob`, `contexts_by_principal`, `contexts_by_sid`,
  `contexts_by_cert`, `active_principals`, idempotency record, failure counters; atomic
  remove-and-write-receipt; the race loser reads the receipt and answers PASS. Design §12.
- **Login context in full**: the §5.1.1 shape (`refreshed_at`, `revoked_at`, `auth_time`,
  `session_expires`, `session_discriminator`, `accounting_state`), the teardown rows that
  still have content — 1, 2, 3, 3a, 6, 7; **row 5 is withdrawn and row 4 has no path without
  the `(nas, rem_addr)` index** — and the checks in the §5.3 pseudocode (username, revoked,
  expired, stale, privilege). Accounting annotation binds the **platform's own** session
  discriminator (`session_pid` on Junos, `task_id` elsewhere — `task_id` restarts at 1 per
  session on Junos, L1), sets `closing`, and flags `foreign`. Spec §5.1.1, §5.3, §5.6, §5.8.
- A **mint function** callable in-process (no broker yet) that plan 3's minimal broker wraps.
- **`context_idle_ttl` is absolute, not idle.** Plan 1 sets it at `PutContext` and never
  extends it; `GetContext` does not touch it. Spec §5.6 says activity SHOULD extend it.
  **Ruled in the rewrite: it becomes a true idle TTL and keeps its name** — a key named
  `context_idle_ttl` that measures absolute age lies in its own name, and `session_expires` is
  already the absolute clock. The extension goes through a new TTL-only store method,
  `TouchContext(ctx, key, ttl)`, which writes the expiry and nothing else: re-`PutContext`ing the
  record read at the top of the request would discard a concurrent revocation permanently, on the
  daemon's highest-frequency path. It runs only when the remaining life is below half the TTL, so
  the common command costs no store write, and nothing is deferred to plan 7 for it.

**Hands to plan 3** (as executed, not as planned — each of these is built and tested with no
caller, so plan 3's broker is a transport over an existing core rather than new mechanism):

- **`session.Manager` is built and wired in `cmd/port49d/main.go:215` and nothing calls it.**
  `Refresh`, `RevokeByPrincipal`, `RevokeBySid` and `RevokeByCert` are complete and tested, so
  `/v1/refresh`, `/v1/logout` and `/v1/tokens/revoke` are HTTP over them.
- **`(*token.Minter).Mint(ctx, token.Request) (token.Result, error)`** — the in-process mint
  `POST /v1/tokens` wraps. `reusable` is gone, the kind is chosen by `WithEnable` plus the
  subject's mechanism, and **idempotency is keyed `(principal, device, key)`**, not on the
  header key alone (Task 12 C1: design §17 sends one key for a device *list*, and unscoped,
  device two is handed device one's token, tagged for the wrong device and refused on every
  attempt).
- **Encryption at rest and its two-key read window**, with the
  `port49_crypt_open_failures_total{record}` counter (`token`, `receipt`, `context`,
  `idempotency`) already emitted.
- **`session.staleness_ceiling` defaults to 0, so the `context_stale` check is dead in the
  shipping binary** until something calls `Refresh` on a schedule (spec §5.1.3). **Plan 3 did not
  wire it** (plan 3, Decided 14): the slice reads its policy once and its store dies with the
  process, so a refresh has nothing to carry. Plan 7 wires the schedule and sets the default in the
  same change — a ceiling with no refresher denies every context the moment it is set.

**Leaves for later:** the broker API and its authorization (plan 7); blobs' compiled content
(plan 4, the engine produces them; plan 2 stores opaque bytes by hash).

**Owed by plan 3 or plan 7 — each is documented in the code and now on the roadmap, because a
package comment is not where the next plan looks:**

- **Revocation does not delete the principal's unredeemed tokens** (`internal/session/session.go:14-21`;
  design §1182 assigns it to the broker). A token minted before a revocation still redeems into
  a fresh context with no `revoked_at` on it, by §5.6 row 1's unconditional overwrite. The
  operator sees a revocation that marked every context and deleted every receipt, then a PERMIT
  on a device they thought they had closed, with no log line joining the two. **This is the
  largest remaining hole in revocation.** Plan 7.
- **`crypt_open_failures_total{record="token"}` must become a key-rotation alarm before the
  first rotation.** `Candidates` drops a token it cannot open with a nil error, so the metric is
  the only witness that a rotation retired a key too early
  (`internal/store/crypt/crypt.go:216-231`). Plan 7 with the rest of the alarms, or plan 6 with
  key rotation reporting, whichever lands first.
- **`foreign` has a metric** since plan 2b (`port49_accounting_attributions_total{attribution}`,
  ruled with no rate limit). Nothing further is owed here.
- **Deferred from Task 13 and Task 9, all three settled and none of them work for plan 2:**
  an `ErrPartial` sentinel and the `Refresh`/`mark` `firstErr` asymmetry — `mark` returns the
  refs it touched *and* the first error, `Refresh` returns a count and an error, and plan 7
  owns the broker's error contract, which is where the shape should be decided once
  (`internal/session/session.go:176-220`). And **no compare-and-set on `PutContext` is
  needed**: the lost-update window that asked for one was on `escalate`, and the final review's
  C1 closed it with the narrow setters instead — `SetPrivilege` and `TouchContext`. Every
  writer of a live context now writes through a setter that names its fields.
**Lab:** none close here; L8 (password length) may need re-checking with the 30-character
tagged token. Plan 2 does move the harness off written secrets — `lab.seed_tokens` loses
`secret:`/`kind:`, the daemon mints the pairs and writes them to a `0600` `lab.seed_token_file`,
and `tests/lab/labcreds` reads that file — so the next lab deploy is the first on minted tokens.

## Plan 3 — Vertical slice (§19 step 3) — `2026-09-23-03-vertical-slice.md`

**Builds:** the first real identity reaching a real device with no shared password.

- A **minimal broker**: x509 client-certificate validation against one trust anchor over a
  **held mTLS connection**, literal-identity subjects, a file-backed policy with roles and
  grants and no scopes beyond `all_devices`, mint via plan 2, `/v1/tokens` and `/v1/config`
  only. Design §7 (certificate path), §17 "Minting", spec §13 decision 17.
- The **agent** `port49 login` and `port49 token` commands over that connection. Design §8
  "Two credentials, two lifetimes".
- **Borrowed ahead in simplest form** (say so in the plan): a hand-written admission snapshot
  and key group (plan 6), one blob written and read (plan 4), one platform's session
  attributes (plan 5).
- **eAPI / NX-API per-request authentication** measured in the lab with reusable tokens.
  Images for this are on hand (plan 1 Task 15 lists them with their vrnetlab kinds): Nexus
  9300v 10.4(2)F for NX-API and the L7 question; Catalyst 9000v 17.12 and C8000v 17.13 for
  IOS-XE, where the `$enab15$` enable path (L3) lives; vEOS for eAPI (image tagged 4.32.2F,
  running 4.31.2F).

**Inherits from the 2026-09-20/22 lab stretch (PR #3):** L3 is closed (no platform sends
`$enab{level}$`; NX-OS 10.x has no enable) and the `$enab15$` enable path is gone. L4 is
measured over SSH on all five images and stays open on `deadtime`, the other transports and
authorization fall-through; L7 is measured per request on eAPI and NX-API and stays open on its
cookie clause. So the lab list above is mostly done. What this plan still
owns: the first end-to-end run with a real credential. The sliding receipt is no longer an
open question — plan 2 shipped it as `receipt_idle_ttl` (15m) and `receipt_max_age` (2h), and
`receipt_ttl` is refused by name at config load — but **the agent's reconnect behaviour is
still part of this plan's design**: an agent minting a fresh token on each reconnect removes
most of the idle-gap problem the client matrix showed (L15), and the bounds are the fallback
rather than the answer. **Lab:** the API-transport half of L1 and the eAPI `/login` flow by
hand.

**Lab, as run:** the slice end to end on vEOS (`tests/lab/results/slice-arista_eos.md`); L7's eAPI
`/login` clause measured on vEOS (`L7-login-arista_eos.md`); L7 was left open on NX-API's
`nxapi_auth` cookie and closed 2026-09-24 when that was measured by hand
(`L7-nxapi-cookie-cisco_nxos.md`), so decision 15 no longer waits on L7 — what it still names as
unmeasured is HTTP keep-alive and an idle-gap playbook run (spec §13); L1's RESTCONF
clause measured on IOS-XE (`L1-restconf-cisco_iosxe.md`), and L1 open on the console.

## Plan 4 — Policy engine (§19 step 4) — `2026-09-23-04-policy-engine.md`

Spec §3 (normalization), §4 (grammar, pipeline stages), §5.1–§5.5 (mint resolution, blob
compilation, refresh, credential identity, scopes and `attached_roles`, version comparison),
§5.4 (dominance), §5.7 (decision log in full, replay), §6 (privilege levels, attribute
layering, substitution at session authorization), §11 (the complete example as a test
corpus), §12 (`explain`, policy tests, access review, `grants remove --subject`), §14
"Matching and precedence" and "Decision log" assertions. Replaces plan 1's `author.Lab`
with the real `Authorizer`. Produces the compiled blob plan 2 stores.

**The accounting spool needs a sink that can fail.** Plan 1's at-least-once guarantee ends at
`decision.Emitter.Emit`, which returns nothing: the spool deletes its `.draining` file whether
or not the sink took the records. With stdout as the sink that is academic. Whichever plan
first gives the decision log a real sink — this one owns the log in full, but it travels with
the sink if it lands later — must give the spool a sink interface that returns an error, and
the spool must not advance `drainOffset` past a refusal. Without both, the durability contract
is enforced up to the last hop and not across it.

**Carried from the 2026-09-24 lab branch:** `author.Decision.Error`, which makes
`Handler.Handle` answer a refusal ERROR, exists only for the lab's fault switch
(`lab.fault_file`, `author.LabFault`). When this plan replaces `author.Lab`, the real `Authorizer`
must never set it — a store outage stays FAIL `store_unavailable`, because an ERROR at command
authorization permits everything under IOS-XE `if-authenticated` and falls through to local RBAC
on the N9Kv (`tests/lab/results/L4-error-*.md`). Remove the field with `author.Lab`, or keep it and
the fault switch lab-only and say so.

**Carried from plan 3:**

- **Compare the blob's `Platform` with the device's platform at authorization.** Unreachable
  while the broker and the daemon share one inventory, so the slice does not check it; it
  becomes reachable when they stop sharing one.
- **A `GetBlob` store error answers `store_unavailable`** once the store is remote.

**As built:** the executor is `internal/engine` (the blob format and the one evaluator the
daemon, `port49 policy replay` and `port49 explain` all run) and the authoring side is
`internal/policy`; plan 3's `internal/blob`, `author.Blob` and `internal/broker/policy` are gone.
`author.Engine` is the daemon's authorizer. `author.Lab` survives only as the lab's instrument
for seeded contexts, behind an optional `lab:` block (plan 4, Decided 12). The accounting spool
drains to a `decision.Sink` and stops at a refused record. Authorization answers
`store_unavailable` FAIL, as plans 1–3 did, until L4 measures authorization fall-through (plan 4,
Question 3, owner's ruling 2026-09-24). A device that fails a joint policy-and-inventory check is
quarantined, not the policy refused: named at start, refused at mint `device_quarantined`, and
closed at once without a reply by the daemon, never held silent, because the lab measured a
silent server at about 5 s a command (spec §10, decision 20). Quarantine is time-scoped: a
device is quarantined only while its check fails, so a grant's expiry schedules an entry from
that instant (warned at start), and the daemon asks per connection and per packet with the
current time. `port49 policy test` carries the
shadowed-deny report and `port49 policy diff` the effective-permission diff and the
privilege-expansion gate (spec §12), and replay re-derives a session's attributes.

**Hands to plan 5:**

- `internal/platform/dialect.go` is borrowed ahead and is plan 5's to replace with the layered
  adapters: `pipe_authorized` is false on EOS, NX-OS and IOS-XE (measured,
  `tests/lab/results/L2-*.md`); `expands_abbreviations` is true on EOS, NX-OS and IOS-XE, set
  from L21 (closed 2026-09-24, interactive SSH; other transports unmeasured), and false on Junos
  and the generic adapter; entity classes are names from spec §8 and the lab configs, unverified against a device;
  only `arista_eos` renders levels. `operator` renders as `priv-lvl=15` there and carries ceiling
  number 15 on `cisco_nxos` (decided 2026-09-24, spec §6 and decision 23; the role-ceiling results
  below); IOS-XE's `operator` is still unrendered and is this plan's.
- **The owner's level definitions (2026-09-24), binding on the adapters:** `readonly` is show and
  info only; `operator` is non-disruptive state changes and no configuration (`clear counters`
  yes, `clear bgp *` no); `admin` is everything. The device role is the ceiling, and port49's
  command rules draw the line inside it.
- **Three lab runs, added to spec §15 L4's *To measure* by plan 4 (owner's rulings 2026-09-24),
  measured 2026-09-24 in the lab run merged as PR #9:** authentication `ERROR` does not give
  break-glass anywhere measured, and an authorization `ERROR` is dangerous (NX-OS falls to its
  local role checks and runs the command; IOS-XE `if-authenticated` runs everything), so FAIL
  stands (`tests/lab/results/L4-error-*.md`); only an unreachable port49 gives break-glass,
  which is plan 6's go-dark below.
- **Role ceiling, measured 2026-09-24** (`tests/lab/results/ceiling-*.md`): on IOS-XE levels 1
  and 7 refuse `clear counters`, `clear ip bgp *` and `configure` in the parser, and level 7 with
  `privilege exec level 7 clear counters` is the `operator` rung, so the device can enforce it; on
  EOS level 1 refuses all three and `network-operator` at 15 runs all three (L16 found the role binds only
  under local authorization); on NX-OS every role runs all three. **On EOS and NX-OS the
  `operator` rung is port49's per-command policy alone.** *Decided 2026-09-24:* `operator` renders
  as level 15 on both, with port49's rules the only fence, and a device method list must not fall
  back to `none` or `if-authenticated` (spec §6, §8, decision 23). IOS-XE level 7 with `privilege
  exec level 7 ...` in the reference config is this plan's adapter work.
- **L21**, added by plan 4, closed 2026-09-24 (`tests/lab/results/L21-*.md`): all three
  per-command platforms send resolved words over SSH; other transports are unmeasured.
- The dead-rule and fallback-exposure intersection checks of spec §12 are this plan's; plan 4
  built the shadowed-deny report, the effective-permission diff and the privilege-expansion gate,
  because it is the plan that switched to dominance (plan 4, Question 4, owner's rulings
  2026-09-24; listed in its section).
- Opening the pull request `port49 grants remove` prepares: plan 4 edits the file (printed, or
  `--write`), and plan 5 opens the review (owner's ruling 2026-09-24).
- The offline tools (`port49 explain`, `policy test`, `access review`, `grants remove`) load a
  policy without config's resolved `EnableUsernames`, so CI cannot see a `platforms:`
  enable-username override the daemon applies. Harmless while `config.Load` refuses such an
  override; plan 5's to close when its adapters bring the overrides (plan 4 pre-flight, N5).
- **When adapters become editable (review M8, 2026-09-24):** the policy diff reads which reply
  attributes bear privilege (`Dialect.PrivilegeAttributes`, `InertAttributes`) from the new
  version's dialect today, which is sound only while the table is built in. Once an operator can
  edit an adapter, judge `BearsPrivilege` under the stricter of the before and after dialects, so
  listing an attribute inert in the same change cannot hide its own edit, and gate any edit to an
  adapter's privilege-bearing or inert lists as a privilege change in its own right.
- Operator-supplied entity-class patterns, when adapters bring them, must be checked for `(?-i)`
  where a deny uses them: plan 4 refuses a deny regex that turns case-insensitivity off, because
  a case-sensitive deny can be walked past by case (spec §4), and permits keep the opt-in.
- **Decided 2026-09-24** (spec §12): a privilege raise — the device privilege the session reply
  gives, the ceiling, the level under either order, or `enable` switched on — fails `port49 policy
  diff` unless a session test (`level:`, `max_privilege:`, `priv_lvl:`, `enable:`) in the new
  policy asserts it; a regex-constrained widening fails unless a permit test shows it or an
  `acknowledge:` entry names the removed deny with a reason; a newly refused mint always fails.
  The reserved levels keep their order, and a ceiling caps the level on every platform. A policy
  with no tests passes `policy test` with `report: no_tests`, and `port49d` prints a `LAB MODE`
  line at start when its config has a `lab:` block (design §13).

**Hands to plan 6:** quarantine is applied by `port49d` when it loads the policy
(`policy.checkDevices`); plan 6 publishes it in the bundle, `admission: quarantined`, from the
inventory service (spec §10, decision 20). `security_log` is accepted and emits nothing until a
sync can change a scope's membership. `bundle` on every blob and record is the policy file's
`sha256:` until versioned bundles replace it. The remote store brings continuing active logins
from a replica's warm context cache through a store outage (design §12).

**Go-dark on a store outage (owner's ruling 2026-09-24; plan 6 or 7, whichever brings the
remote store):** `port49d` health-checks the store, closes its TACACS+ listener after N
consecutive failures and reopens it after M successes, with that hysteresis. The lab showed that
only an unreachable port49 gives break-glass: an authentication `ERROR` does not, and an
authorization `FAIL` refuses break-glass's commands (`tests/lab/results/L4-error-*.md`). The
listener must be closed, so a device sees connection refused and moves on at once, never held
silent, which costs about 5 s a command on IOS-XE, EOS and NX-OS. A per-username break-glass list
was rejected (every site's break-glass account differs). Operator note: NX-OS with `deadtime 1`
refuses token logins for about a minute after port49 returns.

**Hands to plan 7:** group subjects load, and are evaluated by name in the offline tools, but mint
for no one until the directory resolves membership; `api:` rights are validated and reported, not
enforced; `max_session_age` per role is refused at load by name; `/v1/explain` over the API (the
offline `port49 explain` exists). Policy reload is plan 4b's.

## Plan 4b — Live policy (spec §5.1.3)

The owner's core goal (2026-09-24): **a policy change reaches every live session without anyone
logging out.** Today a policy edit needs a `port49d` restart, and a restart ends every live login
context and every unspent token (plan 3, Question 3).

- **Reload trigger:** a watch on `broker.policy_file` and `SIGHUP`, both.
- **Validate or keep the old:** the new file is loaded against the current inventory exactly as
  at start. A file that does not load leaves the running policy in force, logged with the error
  and counted (`port49_policy_reloads_total{outcome}`); nothing half-applies.
- **Atomic swap:** the broker's policy and the daemon's quarantine list change in one step, so
  no mint sees one version's policy and another's quarantine.
- **The joint check re-runs on every reload:** the new policy's quarantine schedule (the
  time-scoped entries, grant expiries included) replaces the old one whole, so a fix releases a
  device and a new failure quarantines one without a restart, and its connections close as plan
  4's do.
- **Refresh of live contexts (spec §5.1.3):** each principal with a live context is re-resolved
  against the new policy, a new blob is written where the result differs, and `blob_hash` is
  updated in each of that principal's live contexts; a principal left with no grant has its
  contexts revoked (`revoked_at`). A policy-removed grant therefore reaches an
  active session on its next command, **with no logout**. Blobs are immutable, so a replica's
  cached copy of the old one is never wrong, only no longer referenced.
- Carried here from plan 7: `(*broker.Broker).Server` returns an error instead of panicking, now
  that a reload path exists.

Plan 7 keeps the scheduled refresh through `active_principals` for directory changes, and the
`staleness_ceiling` default that goes with it.

**As built** (`2026-09-24-04b-live-policy.md`): `policy.Live` holds the policy in force; the
broker mints from it and the daemon asks it about quarantine at every packet, so one swap changes
both. `port49d` reads `broker.policy_file` every `broker.policy_watch_interval` (default 5s) and
loads the bytes two agreeing reads saw, and loads at once on `SIGHUP`. The file is checked on the
descriptor it was read from: a file that does not load, or that anyone but `port49d`'s user or
root could have written — the file, or the directory holding it, group- or world-writable or owned
by anyone else — is refused whole (at start `port49d` does not start), said once per distinct
content, counted (`port49_policy_reloads_total{outcome}`) and alarmed
(`port49_policy_file_refused`). A mint holds the policy from its first resolution to its last
token write, and not while its response is written. A hold is never nested, and its store calls
are bounded by `holdTimeout` (10s; past it the rest of the batch is refused `store_unavailable`),
so a store that stops answering cannot hold a reload, and every mint queued behind it.

`(*broker.Broker).Refresh` carries the policy in force into every live context through
`store.SetContextPolicy`, the fifth narrow setter and the first that is a compare-and-set. It
compares `PolicyRev`, a revision only policy-relevant writes bump (join, revoke, privilege,
ceiling, enable, blob), so accounting traffic on a busy session cannot starve it. A principal with
no grant left on the device has the context revoked through `SetRevokedAt`, which writes the mark
alone and keeps the later of two, so no racing write can hold a withdrawn grant in force. A
context the policy in force cannot be resolved or compiled for is revoked too (`refresh deny
blob_unavailable`, the process log naming the `ctx_id`), and so is one that cannot be opened
(sealed under a key past the two-key window): its record names the device and the key's
username and no principal, since the owner is sealed and the index may be stale. A context on a
device quarantined now is left as it is, with one `refresh deny device_quarantined` record per
context per bundle, not one per pass. Every change is a `refresh` decision record (spec §5.7).
The refresh also deletes the unspent tokens a superseded policy minted that the policy in force
would not mint identically; a superseded policy's tokens are judged at the start of its span and
at every grant expiry inside it. A pass judges everything at one instant (`RefreshReport.At`) and
goes round again at once if a grant expired while it ran.

`port49d` runs the refresh at every reload and every grant expiry (scheduled from
`RefreshReport.At`), a settle pass 30s after each for a login in flight across the swap or the
expiry, and every 30s after a store error until one completes. `port49_policy_refresh_pending`
is 1 from a swap or an expiry until its settle pass completes, and while any retry is owed. A
context still changing after every compare-and-set attempt is left for the retry and the pass
goes on; a revocation never waits on it. The inventory is not reloaded: a reload after an
inventory edit says so (plan 6). `run` takes a context, so a test can stop it, and the end-to-end
test of `port49d` with no `lab:` block that plan 4 carried here drives a live edit through a real
login. `SIGHUP` no longer ends `port49d`.

**Hands to plan 6:** the snapshot refresh (spec §10) swaps an inventory under a live policy. It
must re-run the joint checks against the new inventory and call `Refresh` exactly as a policy
reload does, since a device leaving a scope is a narrowing like any other; `Refresh` already
revokes a context on a device inventory no longer names. Reloading the inventory itself is plan
6's: today a reload after an inventory edit only says a restart is needed. The token supersede
walks principals × devices × superseded policies × expiry instants, compiling each answer (plan
12 measures it at fleet size). With the remote store:
- **Unindexed contexts are invisible to the refresh** (4b pre-flight N4). An `IndexContext` can
  fail, and a login whose index write failed is invisible to the policy refresh as it is to
  revocation (`authen`, the `index_error` record). Close it, or at least extend the
  `index_error` wording to name the policy refresh too.
- **The refresh's store calls are bounded only by the caller's context** (4b Task 5, M4). A
  local store answers at once; a remote one can hang a pass, and with it every later reload,
  since `port49d` runs one pass at a time. Give each store call its own deadline.
- **Decision-log emits under a hold are not context-bounded** (4b Task 4). A mint writes its
  records while it holds the policy, so a stalled log sink stalls a swap. Harmless with a local
  file; bound it before the log can be remote.
- **The settle pass assumes redeem-to-write is under 30s** (4b final review m3). A login that
  spent a token before the supersede and writes its context after the settle pass keeps the
  superseded answer until the next reload or expiry, and the pending gauge reads 0. With the
  memory store this is immediate. The daemon's per-packet store calls use the connection's
  context with no deadline. Give them one that is well under `settleAfterReload`.
- **What the broker remembers grows with the policy's history** (4b final review m10). A file
  rewritten on a schedule, such as a templater stamping the time, reloads on that schedule.
  Every load writes one `refresh` record per live context and a new blob, held in the store for
  `max_session_age` and in `b.blobsSeen` for good. `b.superseded` holds one instant per
  (device, username) ever superseded. Both are bounded by memory today; bound them before the
  store is shared.

**Hands to plan 7:** the scheduled directory refresh is `Refresh`'s context pass with group
membership re-read; a policy refresh does not stamp `refreshed_at`, because nothing about the
directory was re-verified, so the staleness ceiling still waits on plan 7's scheduler. Revoking
by principal, `sid` or certificate should also delete tokens (roadmap, plan 3's hole), as the
policy refresh already does for a withdrawn grant. **A candidate reload guard** (4b Task 6, M3):
a reload that fails the joint check for most devices applies anyway and quarantines them live,
as spec §10 and decision 20 require; the CI gate (`port49 policy diff` fails on a newly
quarantined device) is today's only guard. An optional guard that refuses a reload quarantining
more than a configured share of the fleet is plan 7's to weigh. **Revocation records must name the
contexts they could not reach** (decision 21; 4b final review I1). The policy refresh
already counts contexts on session-only platforms (`RefreshReport.Unreached`), says so on its
summary line, and names each `ctx_id` in the process log. Revocation by identity adds the
record field, a §5.7 edit first, and the refresh should use it too.

**Hands to plan 12:** the policy file check covers the file, the directory holding it, and the
directory holding every symlink on the path. It does not cover ACLs or other ancestor
directories. The deployment docs must say that the path to the policy file is the deployment's
to protect, since whoever can write it decides every operator's access within seconds. The mode
of a directory holding a link, never the file's own directory, is excused on a read-only mount
(`fstatfs`). That is how a ConfigMap or Secret mount passes: its 0777 root is mounted read-only
(`tests/lab/results/configmap-mounts.md`). The excuse trusts whoever writes the mount's source,
so the deployment docs must say: do not mount the policy from FUSE, or from a host path others
can write (re-review n1). They must also say to use `fsGroup` or `defaultMode: 0444` for a
non-root `port49d`, and that an edit takes about 55 s to reach the pod. **`inventory_file`'s path
is the deployment's to protect exactly as `broker.policy_file`'s is** (plan 6a, pre-flight C2):
since plan 6a it is read behind the same fence, with a broker, and it decides scope membership,
capture addresses and key pins within seconds.
**The refresh's cost** (4b final review I3): one `mintedBy` compile measured 17.8 µs on the
fixture's three-role policy. The token scan runs principals × devices × instants for each
superseded policy, so 500 principals by 5,000 devices is about 45 s per instant per prior, and
a real policy compiles slower. The context pass now runs first, both loops stop when cancelled,
and a settle pass or retry no longer compares the policy in force with itself. Measure the
rest at fleet size here.

## Plan 5 — Platform adapters (§19 step 5)

**Split into 5a and 5b (2026-09-24),** because the brief below and every plan-4 hand-off is more
than 25 tasks. The seam is the kind of platform:

- **Plan 5a — `2026-09-24-05a-platform-adapters.md`. As built (merged 2026-09-24, PR
  #13):** The
  adapters as data and every platform that authorizes per command: the built-in adapters as files
  in a pinned set (`platforms/1.0.0/`; a policy that pins none renders with 1.0.0 forever),
  operator overrides in the policy file's `platforms:` block (merge per key, `replace`,
  `based_on`), EOS, NX-OS and IOS-XE rendering under a new decision 25 (a level is a device level
  and a device role; `operator` gets admin's level and readonly's role on EOS and NX-OS, and
  `priv-lvl=7` on IOS-XE with its reference configuration), IOS-XE's closed attribute list
  (anything else quarantines), redaction (built in, unpinned, before the spool), N5, the
  adapter-edit gate and the stricter `BearsPrivilege`, the `(?-i)` check on operator classes,
  `port49 platform list/show/export/upgrade`, the dead-rule and fallback-exposure reports, `port49
  devices check-config` (plan 2b's owed check), `grants remove --pr`, and a lab task that
  measures each adapter's reply level by level (new register row L22) and three candidate inert
  attributes.

  Where it differs from the plan's Decided list: L22 (`tests/lab/results/L22-*.md`, closed
  2026-09-24) measured every level on every platform as rendered and operator's configuration
  change refused at fallback on all three, so the EOS, NX-OS and IOS-XE adapters ship `verified:
  containerlab`, and any `platforms:` block over one of them clears it (`platform list` prints
  `—`, `policy diff` reports the change, `platform export <name>` leaves the key out so the
  block pastes back). Inert as measured: `home-directory`, `idletime` and `timeout` on EOS and
  NX-OS. IOS-XE lists nothing inert: it refused the session for `home-directory`, and a refused
  session there locks out SSH, so `idletime` and `timeout`, measured inert and now accepted
  (`accepted_attributes: [priv-lvl, idletime, timeout]`, not Decided 6's `priv-lvl` alone), are
  held bearing. Both are numbers everywhere: a placeholder in either is refused at load, and a
  value that is not a plain decimal 0 to 65535 quarantines the device, and so on IOS-XE does
  either attribute sent in the mandatory `=` form (`idletime=30`): only the optional `*` form,
  `idletime*30` and `timeout*480`, was measured there. `fallback`
  entries say what L22 measured: EOS operator names the commands that still ran, NX-OS operator
  and IOS-XE have none (IOS-XE refused a token session every command at 7 and 15). Beyond the
  plan: an operator's fallback text is kept apart as `fallback_note`, a block's `unreachable`
  rules are kept apart from the set's as the operator's (`unreachable_note`), a change to the generic adapter is gated (`platform: generic`), an
  `acknowledge:` entry names the sha256 of the value it covers and a stale one is reported, a
  load error quotes no rule text, and `grants remove --pr` targets the repository the push URL
  names. Carried: Junos's inert list and every Junos spelling to 5b (L10, L12, both open); L22's
  inert candidates (`home-directory`, `idletime`, `timeout`) re-measured beside readonly's reply
  (`priv-lvl=1`, network-operator) on EOS and NX-OS to 5b, since beside admin's a raise is
  invisible (5a final review M3); a replay-verifiable blob whose rules redaction hides, and a
  `based_on:` variant's wire facts, to plan 6 (below), which lifts the load's refusal of
  `based_on: juniper_junos` once port49d reads a variant's session service, exec-record commands
  and system users (5a final review M8).
- **Plan 5b — the session-only half and capability inference; written after 5a merges.** Junos's
  projection under decision 22 (`bits`, `bit_delivery`, `command_projection`, `local-user-name`
  templates, the generator constraints and the refused shape), gated on L12 and L9, with its own
  containerlab differential tests and `platform export` of the reference classes; decision 21's
  class `idle-timeout` from `max_session_age`; spec §9's capability inference (`port49 devices
  capabilities`, the supports-versus-observed matrix, accounting reconciliation); and an NX-OS
  `vsh.bin` system user if a note measures it. 5a leaves Junos rendering nothing, as today, so 5b
  reworks nothing 5a builds.

  **Written 2026-09-24** as `2026-09-24-05b-projection-capabilities.md`. The lab measures L9, L12,
  L23, L24 and L25 first (Tasks 2–4), and the new platform set 1.1.0 takes its values from those
  notes (Task 14, with a fail-closed branch for every outcome). The projection ships in 1.1.0, so
  an unpinned policy still gets nothing on Junos. Each reply is proven not to let the device run
  what port49 denies before it is sent, against a model in which the bits are a union and only
  measured carve-outs subtract. **Revised 2026-09-25:** a composition that cannot be proven gets
  that subject alone a fail-closed reply (`deny-commands=^.*$` and only the proven allows),
  recorded `projection_fail_closed`, and `policy test` and `policy diff` fail on it (decision 26,
  the owner's ruling, replacing the device quarantine). `policy test` also fails on any
  quarantine; a projected reply is gated by what the device can do under it; `remote` and `p49-*`
  are reserved usernames. Bits reach the device as `user-permissions` over the bitless
  `p49-remote` template, which L12 measured applied on both images (branch C); `local_user_name`
  stays an adapter choice. `port49 platform export --classes` renders
  the reference classes as a replace with decision 21's `idle-timeout`, and `devices check-config
  --config` holds a device to them. `port49 devices capabilities` reads the decision log,
  qualified by a new `account_gap` record. Task 19 is the differential test.

### Plan 5b — As built

Executed 2026-09-25 on `feature/session-projection`, every task but Task 19, which ran on
2026-09-29 (`feature/projection-differential`, merged into it). The plan was amended
in flight: decision 27 (Junos matches keywords only) and the lab tasks it needed, 3b (the keyword
tree, L26; keyword abbreviations, L9; NETCONF, L12), L26b (keyword proof by deny enforcement),
L26c (RPC reach from a projected CLI) and a rerun of L26. Task 15 did not run (L25 not
reproduced). Task 19 passed on both images after two review rounds added shapes the plan
missed (the capability reply with one and two keyword denies, bits short of `all`) and a
commit-checker step (`L12-projection-juniper_*.md`).

- **Set 1.1.0 is frozen and the default.** It is 1.0.0's EOS, NX-OS and IOS-XE files unchanged
  (branch K: L23 found all three candidates inert) and `juniper_junos` projected. `DefaultSet` is
  1.1.0 and `UnpinnedSet` stays 1.0.0, so an unpinned policy renders Junos as before.
  `TestEveryReleasedSetIsFrozen` holds 1.1.0 value for value, and
  `TestReleasedKeywordTreesAreFrozen` holds its keyword tree by sha256
  (`platforms/keywords/1.1.0/juniper_junos.yaml`, `aa144089…0168`). **The Junos adapter is
  `verified: containerlab`**: Task 19's differential passed on both images before the merge, so
  it was set on 1.1.0 and the `released` entry changed with it, as 5a did for 1.0.0.
- **Task 14's branches, as the notes read:**
  - B: `DenyMatchesExpanded` true (`L9-abbreviations-juniper_*.md`: no abbreviation of a
    keyword deny ran on either image).
  - B2: the rendered deny shape ` *… *(\|.*)?` is enforced, so `ere.go` is unchanged.
  - C: `bit_delivery: user_permissions`. L12 measured it applied over a bitless template, both
    bits of a two-bit value, per session. So there are no level templates: every session lands
    in `p49-remote`, and `user-permissions` carries the bits.
  - D: `bits` is the measured reach, the same on both images.
  - E: `carve_outs` is `view-configuration`'s `show configuration **` out of `view`. `show log
    **`, `show firewall **` and `show policer **` join it on completion evidence only. None
    leaves a deny off the wire in 1.1.0: over RPC even `show configuration **` is provisional on
    L26c, so its deny is sent and fails closed beneath `view` (final review I-3).
  - F, G: a template user commits with no uid, and one with no authentication refuses a local
    login, so nothing is locked.
  - H: L24's class `idle-timeout` closed idle sessions on both images, so the export's
    `idle-timeout` from `session.max_session_age_default` stands.
  - I: a malformed deny opened the session and refused `show version`.
  - J: `deny-commands` never reaches configuration mode, so a configuration-statement deny fails
    closed (`configuration_deny`).
  - L: every request carried `priv_lvl` 1, so the levels stay `{readonly: 1, operator: 15, admin:
    15}`.
  - M: `rpcServicesOff` is on (below).
  - Not A: Junos is projected.
- **`JunosFacts` is `{CaseSensitive: false, DenyMatchesExpanded: true, DenyBindsRPCs: false}`.**
  Case is not measurable, because the CLI refuses upper case itself. `DenyBindsRPCs: false` and
  option C are **provisional on L26c** (open), the conservative reading. L26c measured, with
  `netconf ssh` still configured, that `xml-mode netconf` opens NETCONF inside a projected CLI
  session; that a native RPC the probed deny did not name (`<get-software-information/>`) ran
  there; that the deny did bind a `<command>` RPC; and that RPC reach is bounded above by the
  bits. It did not observe a native RPC passing a deny that named what it reached, and whether
  the services allowlist is sufficient is unmeasured. So under option C (the owner's ruling until
  their device results) port49 assumes a deny beneath a sent bit or the baseline is not a
  boundary. The composition falls to the narrow shape, whose `deny-commands .*` refuses both entry points, or
  gets the fail-closed reply (`refused_shape`, naming RPC reach). **The realistic readonly still
  fails closed** on 1.1.0, now for three reasons: its baseline denies overflow 255 bytes, `save`
  cannot be proven a keyword, and port49 treats the denies beneath `view` as guarding the CLI only
  (option C). What does project:
  `permit: [show **]` alone as the narrow shape, a narrow grant of a few show commands, and an
  admin `permit: [**]` with a deny no bit but `all` reaches (decision 26).
- **Decision 27's keyword tree.** L26 walked `show` on both images (136 nodes and 755 keywords on
  vJunos-router, 118 and 668 on vSRX, no bound hit), and then again. vJunos-router's rerun
  reproduced its tree byte for byte. The vSRX rerun, under the hardened classifier, dropped one
  false keyword (`show rsvp interface`, the classifier's doing) and gained two its first run left
  out (`show interfaces terse extensive`, `show system processes detail`), which shows the walk is
  not reproducible there. So `tests/lab/cmd/junos-keywords` intersects every committed run (three
  trees) and refuses a merge missing one: 528 keywords. L26b's overlays add the seven proven by deny enforcement (`show cli`,
  `host`, `ingress-replication`, `policy`, `task`, `set cli`, `exit`), for 535. What it proves
  for the spec's denies:
  - `deny show configuration **` and `deny show chassis hardware **` are keyword denies, though
    either beneath a sent `view` still fails closed until L26c closes (option C);
  - §11's `deny show chassis cluster **` is not (vJunos-router has no `cluster`), nor is `deny
    show route summary`;
  - no `show configuration` hierarchy is a keyword, and a hierarchy deny is not enforced (L26b).
- **Reference classes and rollout.** `port49 platform export --policy <candidate> --inventory
  <file> --classes --config port49d.yaml juniper_junos` prints `device_config`, then each
  template class and user as a `delete` and its `set` lines. A redacted `device_config` line is
  printed as a `#` comment, with a count on stderr, so loading the export never overwrites the
  TACACS+ secret. `port49 devices check-config --policy <candidate> --inventory <file> --device
  <name> --config port49d.yaml <capture>` holds a device to the set the policy pins, so it runs
  against the candidate policy that pins 1.1.0. The capture must be `show configuration |
  display set | display inheritance | except "^set groups "`, and any other input is refused.
  It fails on a missing reference line, on any line under a template class or user that the
  reference does not write, on a management service outside the allowlist, and on any capture
  holding a group definition or an `apply-groups` line. The order is: load the classes on every
  device, check each against the candidate policy, then deploy the policy that moves the pin.
- **Decision 26's fail-closed reply.** A composition the projection cannot carry gets that
  subject alone `deny-commands=^.*$` and only the allows port49 proved, recorded
  `authorize_session` permit `projection_fail_closed`, with the blob's `fail_closed` giving why.
  `policy test` fails on it (`projection_refused`, `projection_overflow`) and on any quarantine,
  now or at a later expiry. `policy diff` fails on it, and on a projected reply that lets the
  device do more without a `reply:` test. `remote` and `p49-*` are reserved usernames.
- **`port49 devices capabilities`** reads the decision log offline and prints the
  supports-versus-observed matrix and any unauthorized tier. It exits 1 on a contradiction;
  "never seen" is a note. A window in which the spool dropped records (`account_gap`, per stage)
  reads "possibly", and does not page. `policy test` reports `unenforced_rules` for rules a
  platform neither asks about nor renders.
- **NX-OS system task: not landed.** L25's note found no sudo prompt on the N9Kv, so there was
  nothing to cancel and no `admin` record, and Task 15 did not run.
- **Lab register.**
  - Closed: L23; L24 (both Junos images); L26, and L26b, a new row; and, by Task 19 on
    2026-09-29, L9, L10 and L12, so decision 22 is no longer provisional.
  - Open: L25 (not reproduced); and L26c, a new row (RPC reach; a rerun is owed; the owner's SRX
    hardware results are in `L26c-operator-juniper_srx.md`, without a capture).

**Operator-facing notes (for the pull request body).**
- **Upgrade every daemon before pinning set 1.1.0.** A daemon that does not ship 1.1.0 refuses
  a policy that pins it, so a mixed fleet of daemons splits on the pin.
- **Before deploying a policy that pins 1.1.0**, with that candidate policy in hand
  (`port49 platform upgrade --policy policy.yaml --inventory inventory.yaml --to 1.1.0 --write`
  writes it; do not deploy it yet):
  1. Print the classes from the candidate: `port49 platform export --policy policy.yaml
     --inventory inventory.yaml --classes --config /etc/port49/port49d.yaml juniper_junos >
     classes.set`, and load them on every Junos device with `load set terminal` and `commit`.
  2. On each device, save the output of `show configuration | display set | display
     inheritance | except "^set groups "`, and nothing else, to a file, say `srx-fw-04.set`.
  3. Check it against the candidate: `port49 devices check-config --policy policy.yaml
     --inventory inventory.yaml --device srx-fw-04 --config /etc/port49/port49d.yaml
     srx-fw-04.set`. Without `--config` it exits 2, saying the platform is projected and to pass
     `--config`. With `--config` against a policy that does not pin 1.1.0 it exits 2 and prints
     the usage block: check against the candidate that pins 1.1.0.
  4. Only when every device passes, deploy the policy.

  **A class replace does not prove a template; `check-config` does.** It fails on a missing
  reference line and on anything extra under a template, such as a class `allow-commands` or a
  template password. **A device whose configuration uses groups is refused outright**: the check
  refuses any capture holding a group definition or an `apply-groups` line, since it cannot tell
  whether a group's statements were expanded (whether `display inheritance` drops them is
  unmeasured; Task 19).
- **Management services: only the CLI's.** A projected Junos device passes `check-config` only
  where nothing under `system services` is on but `ssh` and `telnet`. Under `ssh` only its
  transport options are allowed (ciphers, limits, `port`, `root-login`, `no-tcp-forwarding`, and
  the like), and under `telnet` only `authentication-order`, `connection-limit` and
  `rate-limit`; `sftp-server`, `tcp-forwarding` and any unknown statement fail. `rest`,
  `web-management` and `extension-service` fail wherever they appear. So NETCONF, the XML API,
  REST, J-Web, JET/gRPC/gNMI and `outbound-ssh` are off, because over NETCONF a native RPC ran
  past every wire deny (`L12-netconf-juniper_*.md`). Whether that is enough is unmeasured (L26c).
- **On 1.1.0 a Junos capability reply needs `xml-mode` permitted, so most broad grants fail
  closed and only narrow grants project** (option C, provisional on L26c, and borne out on SRX
  hardware). A capability reply
  (bits, and no `deny-commands .*`) leaves `xml-mode` and `op` runnable. In the lab (L26c,
  still open), `xml-mode netconf` opened NETCONF inside a projected CLI session, and a native
  RPC the session's deny did not name ran there, within the bits' reach. Whether such an RPC
  passes a deny that names what it reads is not yet measured in the lab, so port49 assumes it
  does; on SRX hardware (23.4R2-S8.7, operator-reported, `L26c-operator-juniper_srx.md`)
  `<get-configuration/>` did, and no deny naming `xml-mode` refused it. It
  sends a capability reply only where the grant permits everything its bits reach, `xml-mode`
  included, and does not treat a deny beneath a permitted bit as a boundary. Such a subject
  gets the narrow shape or the fail-closed reply, and `policy test` names it. A measurement can
  only relax this.
- **You cannot deny a single `show configuration` hierarchy on Junos.** A deny naming one (`show
  configuration system`) is not enforced by the device (L26b), so port49 refuses it as an
  argument deny. Deny all of `show configuration`, or none of it; and on 1.1.0 denying all of it
  under `view` still fails closed until L26c closes, since no carve-out leaves the deny off the
  wire and a deny beneath a sent bit is not a boundary (option C).
- **`deny-commands` cannot keep the configuration from a user who holds `view-configuration`.**
  From any CLI session such a user can run `xml-mode netconf` and send `<get-configuration/>`,
  which returns the whole configuration (secrets masked) past a deny of `show configuration`
  (SRX hardware, operator-reported). To withhold the configuration, withhold the bit. port49
  never relies on such a deny: that composition fails closed.
- **`port49 devices capabilities` output goes to cron mail, and its redaction is best effort.**
  A password typed as a command may appear in an example line.
- **The Junos adapter is `verified: containerlab`.** Task 19's differential ran every shape set
  1.1.0 renders on vJunos-router and vSRX, none wider than port49 permits.
- The notes already in the plan's "Operator-facing notes" stand where they do not contradict the
  ones above: a new set; per-subject fail-closed with `projection_fail_closed`; `policy test` fails
  on a quarantine; reserved usernames; the new adapter keys and reports; `policy diff`'s
  `projection:` lines; `explain`; `account_gap`. One is superseded: the deny beneath a permit no
  longer fails closed for want of L9, which measured it. It fails closed for assumed RPC reach,
  as above.

**Carried, for later plans.**
- **A `junoscript` deny may lift option C.** On SRX hardware (operator-reported,
  `L26c-operator-juniper_srx.md`), `deny-commands "junoscript"`, sent by TACACS+ or set on the
  class, refused `xml-mode netconf` while other commands ran, and refused that user's NETCONF
  sessions on port 830 too (`unknown command: xml-mode`). **port49 will not send it by default.**
  The owner ruled on 2026-09-30 that humans run Ansible over NETCONF under their own accounts, so
  a `junoscript` deny on human classes would break that automation. Option C stays. At most, the
  deny could be an explicit per-grant opt-in for grants whose holders never use NETCONF. The lab
  confirmation on both images (branch `lab/junoscript-deny`) records the behavior that ruling
  rests on.
- **Revisit `check-config`'s NETCONF-off requirement.** On SRX hardware `xml-mode` opens NETCONF
  with the service off (`L26c-operator-juniper_srx.md`), so turning the service off doesn't close
  RPC reach. Under option C a capability reply goes out only where the grant permits everything
  the bits reach, so RPC reach over the NETCONF service may already be bounded the same way.
  Fleets that automate over NETCONF can't pass the check today. Settle it in the lab before
  relaxing anything.
- **Carried from Task 19** (it ran and closed L9, L10 and L12; these were never its test's):
  - `DenyMatchesExpanded` re-measured;
  - the uid range and the class `idle-timeout` upper bound;
  - whether `set version` and `apply-groups` lines survive `display inheritance | except`;
  - ssh TCP forwarding's default;
  - whether a deny binds `scp` and the SSH exec channel.
- **The owner's device measurements:**
  - answered on SRX hardware, without a capture (`L26c-operator-juniper_srx.md`): a deny naming
    `xml-mode` does not bind, a `junoscript` deny does (see the carried item above), and
    `<get-configuration/>` reaches past a deny beneath `view-configuration`; `op` is unmeasured;
  - the L26c rerun (review I-1, I-4), with only the allowlist's services on, which closes
    whether the allowlist is sufficient and so option C's provisional marker;
  - the bitless (baseline) session's RPC reach, which Task 14 counts as a carve-out;
  - the L26d probes (the short `*`-form deny and allow, and whether wire and class lists merge),
    which safety checks stopped.
- **The device-class deny-list design** (the owner's production approach). Exported `p49-*`
  classes would carry the level's class-level deny list, which no 255-byte limit binds. The
  exported classes would carry denies only, never a broad allow, since a class allow beats every
  deny. The generator's proof would count the class list beside the wire's.
- **Wire measurements:**
  - `deny-configuration` (and `-regexps`) over the wire, which would let a configuration
    statement be denied in configuration mode and lift decided item 6;
  - the `-regexps` family's rendering, since its deny precedence is measured (L12);
  - where branch M disabled NETCONF, whether an RPC-level deny (deny-commands on RPC names, or a
    class setting) can bind NETCONF, so it can be enabled again.
- **The keyword capture:**
  - grow its seed list where a fleet's denies fail as unproven;
  - capture the tree per fleet release and hardware family (A-M5);
  - prove keywords outside `show` with a mechanism that runs nothing, so a deny under `request`,
    `clear` or `monitor` can be sent;
  - make `junos-keywords` refuse a committed image left off the command line (kw-merge M4).
- A way to declare a deny class-resident, the deny overflow's workaround in policy.
- A bit's reach per child word, not the literal `W **` upper bound, once a lab proves a path has
  no hidden subcommands (Task 3 ruling (a)).
- Task 3b's deferred minors: the harness does not wait on `^U` (M2), and the notes' capture
  counts run below their pcaps (M6).
- **Scale, for plan 12:**
  - `engine.Contains`, `MayMeet` and the rest compile both rules per call, and only the
    per-composition cache bounds the load; measure it at 10k devices;
  - `devices capabilities` reads a whole log into memory;
  - an `account_gap` count held in memory is lost on a restart.
- vJunosEvolved is unmeasured. L25 is still open.
- **Before the branch is pushed:** strip the credential values commit a4c4738's L26c notes
  carried from history (redacted in ba4f7c8). The rest is done in the final fix wave:
  `labcreds.NoteLeaks` and `TestResultsNotesCarryNoCredentials` fail on a Junos
  `encrypted-password`/`plain-text-password-value` value, a `$1$`/`$5$`/`$6$`/`$8$`/`$9$` hash or a
  lab default password in any results note, naming file and line only, and every notes writer
  passes what it writes through `labcreds.RedactNote`.
- **Parked for the final wave** (per-task review minors), done there unless named here: the
  flaky `TestPAPLoginThenAuthorizeThenAccount` did not reproduce (`-count=200 -race`, final
  review); the `-race` load test near its bound, Task 12's M2–M6 and 12b's M-F2 (the backstop's
  mixed-case non-ASCII gap) stay open.

Spec §8 in full: built-in adapters, entity classes, user overrides and layering, pinned
platform set, `redact` patterns (accounting redaction was deferred from plan 1 and MUST land
here), `capability`/`bits`/`bit_delivery`, the **Junos projection** under decision 22
(bits first, regexes second, refused shape), differential testing in containerlab,
`port49 platform export`. Spec §9 capability inference. **Lab:** L9, L11 and L12, all closed
(L9 and L12 by plan 5b's Task 19, 2026-09-29).

**Inherits from the lab (PR #3), per platform — a wrong or extra reply attribute is fatal,
not ignored:**
- **NX-OS**: send `shell:roles`, never `priv-lvl`. The role wins over `priv-lvl` in both
  directions, the role alone suffices, and `priv-lvl` with no role silently picks a role by a
  per-release mapping (0/1/6 → `vdc-operator`, 15 → `network-admin`). An unknown role name
  silently becomes `network-operator`; two roles are a union; a misnamed attribute is
  rejected outright. Custom roles by name work (L16). `network-operator` cannot run bare
  `show interface` (prompts for sudo; `show interface *` works) and the cancelled sudo writes
  an accounting record under `admin` with `task_id=vsh.bin.$port`. **Nothing port49 sends ends
  a session here**: an attribute this device does not understand is ignored under EITHER flag,
  mandatory included, so a wrong attribute is invisible rather than fatal and the RFC 8907 §8.2
  flag buys an adapter no signal at all. Two more entries in the privilege-to-role table, both
  reached with no role in the reply: no attributes at all gives `vdc-operator`, and an
  out-of-range `priv-lvl=99` gives `network-operator` (L18).
- **vEOS**: send the **bare** `roles=<name>` **and** `priv-lvl=N` together — one role name, no
  quotes. The bare attribute is applied under either flag; `shell:roles*` is ignored and a
  mandatory `shell:roles=` or an optional `cisco-av-pair*` **refuses the session**. A role with
  no `priv-lvl` beside it lands the operator at level 1, where they cannot even read their own
  role — the opposite of the NX-OS rule, so the two platforms need different replies. The value
  is taken literally: quotes are kept as part of the name, and an unknown role is echoed back
  rather than degraded. An OPTIONAL `priv-lvl*N` **is** applied on 4.31.2F. Under
  `aaa authorization commands ... local` the delivered role is real privilege (`network-operator`
  is refused `configure`, `network-admin` is not, an unknown name is refused), so port49's
  per-command answer is the only control **while port49 is in the command path** and the role is
  the control when it is not (L16). **On the §8.2 question vEOS is the conformant one**: an
  OPTIONAL attribute it does not read is ignored and a MANDATORY one ends the session, whatever
  the name — an invented attribute does both — so the flag is a working switch here and
  `cisco-av-pair*` is an exception to that rule rather than the rule. A `priv-lvl` value the
  device cannot use is DROPPED rather than clamped: `priv-lvl=99` lands the operator at level 1,
  the same as sending nothing (L18).
- **IOS-XE**: kills the session on any unrecognised attribute, optional included; `priv-lvl`
  only (L3/L16 notes). L18 extends that to a second foreign spelling, an invented attribute and
  an out-of-range `priv-lvl=99` — seven of ten variants refused, all `% Authorization failed.`
  **And the cost is the device, not the session:** after a run of refused authorizations this
  image stops answering SSH for about a minute, refusing connections at the authentication
  layer **without sending port49 a packet**, so nothing in the decision log says it happened and
  break-glass is refused with everyone else. An adapter for this platform must send exactly what
  the device reads and nothing else; there is no cheap mistake here.
- **Junos**: `platforms.juniper_junos.session_services` (default `[junos-exec]`; production
  fleets use `tacplus-options service-name`, e.g. `junos-exec-fw`; the name never selects
  policy). The emitted reference config MUST include `tacplus-options strict-authorization`:
  without it a port49 denial is advisory (login completes, class from the `remote` template);
  with it the denial refuses SSH and NETCONF while break-glass still gets in with port49 down
  (L17). `authorization-time-interval` (min 15 min) re-authorizes but a denial does not end
  the session: revocation cannot reach a live Junos session. `enhanced-accounting` adds the
  client source `Port` to the login record. Accounting `service` stays `shell` whatever the
  session service is; `session_pid` is the per-session discriminator. **Attributes, measured on
  both images and agreeing cell for cell (L18):** `local-user-name=<template>` **is applied**
  under either flag — the session leaves the `remote` template for the class the reply names —
  and `user-permissions` did nothing over a template whose class carried bits, mandatory,
  optional, or sent beside `local-user-name`. L12 later measured it applied over a bitless
  template, both bits of a two-bit value, per session, so set 1.1.0 sends it over `p49-remote`
  (`tests/lab/results/L12-juniper_*.md`; branch C); L12 stays open for the differential. A template name the device does not have degrades silently
  to the default `remote` template. Everything Junos does not understand is ignored under either
  flag, so nothing port49 sends can end a Junos session by attribute. No variant produced a
  per-command authorization request, on either image, in any of 26 sessions — decision 21's
  shape, confirmed.
- **From the 2026-09-24 lab (`tests/lab/results/ceiling-*.md`, `L4-error-*.md`, `L21-*.md`):**
  the device enforces a ceiling only through the privilege level. IOS-XE and vEOS at level 1
  refuse `clear counters`, `clear ip bgp *` and `configure` in the parser without asking port49;
  IOS-XE level 7 is level 1 until the reference config assigns it commands (`privilege exec
  level 7 clear counters` gives exactly the operator rung); vEOS `network-operator` at 15 ran
  `clear counters`, had `clear ip bgp *` authorized (`% BGP inactive`: no BGP on that image) and
  entered `configure`, and every NX-OS role, `network-operator` included, ran all three — with
  `network-operator` also changing configuration (not typed under the other roles, nor on vEOS) —
  while command authorization points at port49. So the operator rung is port49's per-command
  policy there, not the role. The reference configs must be written for a store outage, which is not
  the break-glass case (only an unreachable port49 is), and the N9Kv `deadtime` trades the 5s
  silent-server penalty for a minute of refused token logins. All three per-command platforms
  send resolved words (L21, closed): `expands_abbreviations: true` for them over SSH, and
  interface arguments differ (IOS-XE `GigabitEthernet`, `1`; EOS/NX-OS one word).
- Device-generated accounting under another user (Junos root RPC in production, NX-OS
  `admin`/`vsh.bin`) is real and must not be treated as a foreign session (plan 2 rule).

**Inherits from plan 1:** a Junos session authorization is **permitted and carries no
attributes**. Plan 1 answered every one of them `service_unsupported` until 2026-09-21,
because `author.Handle` required `service=shell` while L10 measured Junos sending
`service=junos-exec`; it now reads the platform's `session_services` list (spec §5.2, §8),
which defaults to `[junos-exec]` for `juniper_junos` and is settable for a fleet that has run
`set system tacplus-options service-name`. So the envelope is recognised and the decision log
shows `permit context_matched` for Junos. **The attributes are this plan's whole remaining
job there**: the session-only projection — class, `local-user-name`, `user-permissions`, the
`allow-commands` / `deny-commands` regexes — is decision 22, gated on L12, and plan 1 sends
none of it.

**Owed from plan 2b (context join):** a configuration check that **warns when a port49-served
username exists as a device-local account** on the device (spec §5.6, "Local account names MUST
NOT collide"). Such an account's commands arrive under the same username and match the port49
context at its highest granted level; `foreign` attribution is the only detection until this check
exists.

**Owed from plan 4 (owner's rulings 2026-09-24):** spec §12's dead-rule and fallback-exposure
intersection checks, which need the level and role data this plan's adapters bring. Plan 4 built
the shadowed-deny report, the effective-permission diff and the privilege-expansion gate, because
it is the plan that replaced deny-overrides with dominance. Also: opening the pull request `port49
grants remove` prepares (plan 4 delivers the file edit). The rest of what plan 4 hands this
plan — the borrowed dialect table, the role-ceiling results and the `operator` rendering on EOS
and NX-OS decided 2026-09-24, the owner's level definitions, the `(?-i)` check on entity classes — is under plan
4's "Hands to plan 5".

**Possible later, not planned:** per-window contexts on the platforms that give a window its own
stable identifier — EOS `vty<n>`, bound at session authorization
(`tests/lab/results/L1-arista_eos.md`; again 2026-09-22), and IOS-XE `tty<n>`
(`tests/lab/results/L1-cisco_iosxe.md`). The `(nas, username)` join is the design of record; this
would refine it per platform and needs its own ruling first.

## Plan 6 — Inventory service (§19 step 6)

Spec §10: file inventory in full, NetBox and Nautobot connectors, the versioned bundle,
`bundle/diff`, bounded-change safety, **quarantine** (silence, not FAIL — decision 20),
admission snapshot refresh in the daemon, key rotation reporting (`keys status`,
`keys diagnose`, unvalidated-source report), device records, address-added-as-security-event.
Design §10 "Device inventory".

**Owed from plan 5a (owner's ruling 2026-09-24):** a blob whose rule text carries a value the
redaction patterns hide is logged with that text redacted and `"redacted": true` (spec §5.8), so
`port49 policy replay` reports every record naming it `unverifiable`. Verification comes back
when replay can take the verbatim blob from outside the log: from the versioned bundle this plan
publishes, from the store, or from `--policy <file>`, checked against the hash the log carries.
Also owed: a `based_on:` variant's wire facts. port49d keys `session_services`, the exec records'
commands and the system users by platform name, so 5a refuses `based_on: juniper_junos` at load
(spec §8; 5a final review M8). This plan carries those facts to a variant and lifts the refusal.

**Split into 6a and 6b (2026-09-30).** The seam is the bundle's source:

- **Plan 6a — `2026-09-30-06a-bundle-in-process.md`. Written 2026-09-30; executed 2026-09-30
  (as built, below); merged 2026-09-30 (PR #15).**
  Everything that
  consumes a bundle, with the bundle built in port49d from `inventory_file` and
  `broker.policy_file`: `bundle.ID` (a content hash) and `bundle.Parse`; the loaded policy as the
  one pointer that carries admission, devices, quarantine and policy (new decision 28); key groups
  moved into the policy file; a device no group admits refused on its own, never the daemon
  (`admission_refused`); the inventory file watched and reloaded, bounded
  (`inventory.max_removed_percent`), with the refresh after it and an inventory-only swap leaving
  unchanged contexts alone; `inventory_change` records for addresses added and `security_log` scope
  changes; scopes pinned by `name`; `retire_after`, `device.key_ref`/`key_version` on every
  validated record, `port49 keys status`, `keys show` and `keys diagnose` (over a 0600 admin
  socket); `policy test --config`; `port49 inventory diff`; `based_on:` variants read, and
  redacted, as their base; `policy replay --policy --inventory` for a redacted blob. Two lab rows,
  both new: L27 (what NetBox and Nautobot return, recorded as fixtures for 6b) and L28 (what a
  device does on a key miss, and a rotation end to end). Owner decisions at the plan's top: a
  device-level key-group tie refuses the device; `keys diagnose` over a local socket; and, for 6b,
  whether port49d takes the policy from the service. Revised after its pre-flight review: the
  inventory file is read behind the policy file's write fence; the key-group move is safe in every
  order; `SIGHUP` re-reads the bound; the broker refuses to mint for a refused device
  (`device_unknown`); a test on an absent device fails CI and never a reload; a policy reload is held to
  the same bound as an inventory reload, and `policy diff` fails on a newly refused device.
- **Plan 6b — `2026-09-30-06b-inventory-service.md`. Written 2026-09-30; executed 2026-09-30
  (as built, below); merged 2026-09-30 (PR #18).**
  `cmd/port49-inventory` with the §10 API over mutual TLS (read and sync rights), the file connector,
  three of the four sync triggers (10-minute schedule, `port49 inventory sync`, startup), bounded
  change per source in the service, the signed bundle document and its sequence number, port49d's
  30 s pull with ETag, the persisted last good bundle, the shared mirror (a mounted directory), and
  cold-start readiness; owner decision 3's mismatch alarm; `SIGHUP` and a refused load trying both
  sources together (6a m7); the write fence moved to `internal/fence`. Lab: L29 (the reload case
  through syncs, and the midnight case as four scheduled runs), spec §14's quarantine through a sync,
  and L30 recorded as fixtures for 6c. Owner decisions at its top: every copy of the bundle signed
  (ed25519) and verified; the mirror a directory, not an object-store API; nothing the service sends
  assigns a key, and the pin tier moves into the reviewed policy as a key group matching a device name
  (revised after the pre-flight review: a `/32` group is tier 3 and is not a pin).
- **Fix `fix/breakglass-reset` — `2026-09-30-06b1-breakglass-reset.md`. Written 2026-09-30.** Right after 6b merges, before 6c. Closes **L31** (spec §15;
  `tests/lab/results/L31-breakglass-cisco-singleconnection.md`). With single-connection on,
  IOS-XE and NX-OS wait out their 5 s timeout after a reset that follows their request, so
  break-glass costs 16–21 s on a refused or quarantined device and 30–41 s on a removed one. Give
  the unadmitted, refused and quarantined paths (`internal/daemon/server/conn.go:233-238`,
  `:261-262`) L28's shape: record the first connection, reset it at once, and refuse the source's
  next connections at Accept for a short window. The unadmitted path takes a `keyMiss`-style close
  in place of `backoff`. Refused and quarantined, which take no strike by spec, get a strike-free
  window checked beside `Holding` (`server.go:119`) and cleared at every reload, so a fix or
  re-admission takes effect at once. Retries inside the window are counted, not recorded, so spec
  §10's "one record per connection" for the quarantine close and the `conn.go` comment change with
  it. Lab: IOS-XE and NX-OS with single-connection on, removed, refused and quarantined, against
  port49d stopped; the run closes L31. **Executed 2026-09-30**, closing L31 (As built, below). What
  shipped differs from this text in three places: the window is not cleared at a reload but
  re-checked at every Accept against the admission and policy in force, which covers a quarantine
  that ends without a reload too; the lab bar is the rekeyed control (a key miss) plus 1.5 s, with
  port49d stopped measured beside it; and vEOS ran as a no-regression check.
- **Plan 6c — `2026-10-01-06c-inventory-connectors.md`. Written 2026-10-01; executed 2026-10-01
  (as built, below).** Written after 6b and
  `fix/breakglass-reset` merged, against L27's and L30's fixtures; the rulings it made where spec §10
  is silent are at its top and become spec §13 decision 31, and it opens L32 (the connectors as
  built, through two kinds of TLS proxy) and L33 (webhooks to port49-inventory over TLS, and a NetBox
  and a Nautobot synced to vEOS). Version detection by `/api/status/`, GraphQL first, the REST fallback (`?depth=1` on
  Nautobot 2.x, following `next` as L30 finds it), the slug alias table, filters and maps, source
  credentials by `secret_env`, and the authenticated webhook trigger (HMAC-SHA512 of the body; a delivery
  only triggers a sync, so its order orders nothing and its `timestamp` is read for freshness alone,
  plan 6c ruling 2); every `Fetch` returning within
  `sync_timeout`; and `port49 inventory export --service … [--from N]`, so the offline tools keep an
  `--inventory` when no source is a file. Split from 6b because the connectors
  are the contributable surface and hold the only source-of-truth credentials, and two of their facts
  (L30) were unmeasured when 6b was written. **From L30, as measured** (spec §15; `L30-netbox.md`,
  `L30-nautobot.md`): follow `next` only when its scheme, host and port are the configured base's
  (every product builds `next` from the host the request arrived under), or rebuild it from the
  base; read GraphQL's `errors` before `data` even on HTTP 200 (NetBox 4.7.1 answers an unknown
  argument that way, with no names); take the status spelling per product and version (`"ACTIVE"`
  on NetBox 3.7, `"active"` on 4.x, `{"name": "Active"}` on Nautobot); page GraphQL by
  `pagination: {offset, limit}` on NetBox 4.x and `limit`/`offset` on Nautobot, and not at all on
  NetBox 3.7; and expect no `cluster` or `software_image_files` on a Nautobot 3.2.6 device, which
  otherwise answered as 2.4.43 did, so no separate 3.x profile is indicated. Its lab run syncs a
  NetBox and a Nautobot to a device end to end.

**Go-dark on a store outage is plan 7's**, with the remote store (plan 4's "Hands to plan 6": "plan
6 or 7, whichever brings the remote store"; plan 6 builds none), and so are the warm context
cache, plan 4b's remote-store items, and the `crypt_open_failures_total{record="token"}` alarm.

### Plan 6a — As built

Executed 2026-09-30 on `feature/bundle-in-process`, twenty-two tasks, each reviewed; the ledger is
`.superpowers/sdd/2026-09-30-06a-bundle-in-process/progress.md`. What differs from the plan's
text, task by task:

- **Task 3.** A device whose `transport` is `tls`, or neither `tcp` nor `tls`, refuses that device
  alone (`refused_transport`), not the inventory file; spec §10 was edited to say so.
  `admission.Resolve` decides one device (transport, then key group), and the admit step adds
  only the unknown-key check.
- **Task 4.** A refused entry never carries a `KeyRef`: the daemon and the config read a non-empty
  `KeyRef` as admitted, so a refusal names the undefined key in its text instead.
- **Tasks 7, 10, 12.** A bundle that admits none of a non-empty inventory is refused at start
  **and at both reloads**, the inventory's and the policy's, whatever
  `inventory.max_removed_percent` says, in the same words, naming `stop port49d` as the deliberate
  path. A quarantined device counts as admitted for the bound.
- **Task 11a** (added by the pre-flight review) fenced the inventory file at start; Task 12 fenced
  it at every reload, keeping the last good inventory and raising `port49_inventory_file_refused`.
- **Task 12.** The key-group move done in the wrong order (deleted from the inventory first) and
  followed by a restart refuses the start, naming the fix: a device sees the same fallback whether
  port49d is down or admits nothing, and the refusal is louder.
- **Task 14.** A key version ends at `retire_after` **even on an open connection**: each packet is
  judged at its own time, and the first past the date is refused. The plan had the version last
  the connection's life; a busy single-connect connection never idles out, so that had no bound.
  Spec §10 and Decided 7 were amended. `port49_key_version_devices` counts only since start (spec
  §10 says so, with an uptime-gated alert example), and the process collector is exported for it.
- **Task 15.** `key_ref` is constrained to `^[a-z][a-z0-9_]{0,63}$` wherever one is written,
  since every report prints it; YAML decode errors in port49d.yaml and the inventory print the
  line and a category only (`internal/yamlfault`); a missing environment variable is named by its
  key, not its variable; the clock is injected. Three fix rounds, each closing a path by which a
  pasted secret could reach output.
- **Task 16.** The other-uid refusal test (`TestAnotherUIDIsRefused`) needs root; the controller
  ran it with `sudo -n` and it passed. Non-root CI skips it.
- **Task 17.** A scope pinning a name the inventory lacks is a **warning** in `policy test`, not a
  failure: onboarding a device before it is in inventory is legitimate.
- **Task 18.** An unknown field is reported by line. Without `--config`, `inventory diff` warns
  that key_refs are unchecked and does not fail on it, and its admit-none check uses `policy
  test`'s. Under `--new-policy`, security marks are per step, and a two-file change that stops
  half-applied in one order exits 1.
- **Task 19** fixed a leak in the plan's code: when a record's `redacted` mark has been edited out
  of the log, a divergence printed the verbatim blob's rule text, secret included. Against a blob
  from the files, replay now prints only the log's side, and its output goes through the loaded
  policy's redaction.
- **Task 20** took **branch H** (below). A packet past `retire_after` on an open connection is
  closed as a first-packet miss is, with a strike and a reset.
- **Final review and fix wave** (`final-review.md`, `fixwave-report.md` beside the ledger).
  - **I1: a reload ends an open connection whose admission it withdrew.** Every packet looks its
    source up again in the admission in force, beside the quarantine and `retire_after` checks.
    A device refused, removed, renamed, moved to another `key_ref`, or given another platform or
    `based_on:` base (re-review R1) is reset at its next packet, with no reply and no strike, and one `unvalidated` record, reason `device_unknown`, diagnosis
    `admission_refused`, `unadmitted_source` or the new `admission_withdrawn`
    (`port49_connection_events_total{event="admission_closed"}`). Spec §10's "in-flight
    connections complete against the snapshot they began with" was amended as Task 14 amended
    Decided 7: a busy single-connect connection has no end, and a device moved off a compromised
    key kept speaking it. How a device takes the reset is L29's, which gained the reload case.
  - port49d.yaml, at start and at `SIGHUP`, and the inventory at start with no broker, are read as
    regular files only, non-blocking and bounded (`config.ReadRegular`): a named pipe at either
    path hung the start, or blocked the reloader and with it shutdown.
  - The admin socket is stale only when its dial is refused (`ECONNREFUSED`); any other dial
    error, such as another uid's socket (`EACCES`), refuses the start and removes nothing.
  - A swap forgets the `port49_key_version_devices` marks, and the packets held for
    `keys diagnose`, of devices the new bundle no longer admits under the `key_ref` they were seen
    on (a re-keyed device's held packet is kept).
  - An inventory fault names the file once.
  - Tests added: reverting to the inventory in force clears `port49_inventory_file_refused`; the
    refused device's start line, admitted count and gauge; both session-side replay guards (each
    fails with its guard removed); `policy diff`'s 20-line cap; a key group's bad `cidr` printed
    by position. `TestProjectionLoadTime` skips under `-race`, as the engine's timed tests do.

**Owner decisions, as ruled** (the anti-escalation defaults; Ryan may override): 1, a key-group tie
that exists only against the inventory refuses that device alone; 2, `keys diagnose` over a 0600
`SO_PEERCRED` Unix socket, off by default; 3, for 6b, port49d keeps its own policy file and takes
only the inventory from the service. **Key groups:** where both files carry them, the policy's win
and a notice names the inventory's as ignored.

**L28 took branch H.** The hold stalled break-glass on all four images (`L28-held-*.md`: three
commands 25–28 s on EOS, NX-OS and IOS-XE, 5.9 s on vJunos-router). port49d now strikes a key
miss and resets it at once, and refuses a source inside its backoff at Accept with a reset
(`key_miss_closed`, `held_refused`). A FIN was tried first and still cost the C8000V its own 5 s
timeout (`L28-fin-cisco_iosxe.md`), so the close is a reset. Break-glass is now at port49d-stopped
times on all four (`L28-*.md`). One record per strike; attempts refused inside a backoff leave
only the `held_refused` count. Accepted in review: a strike from a device's address resets that
address's connections for up to 5 s (denial of service, not escalation; spec §10 says so).

**Rows:** L27 and L28 closed 2026-09-30. L29 opened: what a device does when port49d resets an open
connection, at its key version's `retire_after` (a run across midnight UTC) or after a reload
withdrew its admission (a `SIGHUP` between two commands); split from L28, which measured first
packets only. L30 opened in the fix wave for L27's unmeasured parts: a non-null pagination `next`,
and Nautobot 3.x. Both are plan 6b's.

**Carried, for later plans:**

- **Plan 6b:** the object-store mirror, the persisted last good bundle and cold-start readiness;
  the bundle document and its integer sequence; owner decision 3's policy-hash mismatch notice and
  alarm; `SIGHUP` trying the combined bundle when both files changed, so a whole-fleet re-address
  does not deadlock and an intermediate bundle revokes nothing the final one admits (final review
  m7; until then the operator notes give the make-before-break order); **L29** (6b is the next
  plan with a device lab run, spec §14's quarantine through a sync, and its syncs make the reload
  case routine), and with it why the C8000V's liveness probe reached port49d only at its second or
  third attempt in L28 (Task 21 review m4); **L30**, L27's gaps: a non-null pagination `next` and
  Nautobot 3.x (Docker Hub has a 3.2 line); and L27's findings: Nautobot 1.6's `Api-Version` is `1.2`, so detect by `/api/status/`; Nautobot
  2.x REST at default depth names no related object, so read `?depth=1` or GraphQL; Nautobot
  delivers webhooks out of change order, so order by the body's `timestamp`.
- **Plan 7:** go-dark on a store outage, the warm context cache, and plan 4b's remote-store items.
  The `crypt_open_failures_total{record="token"}` alarm, which plan 2 handed to "plan 6 with key
  rotation reporting, or plan 7", goes to plan 7: it guards the encryption-at-rest rotation, not
  the device keys 6a reports on (M11).
- **Plan 12:** `secret_ref:` resolvers, and the key sets moving into the policy repository with
  them; `key_ref` as a device label in per-device-pin deployments (unchanged, and now on
  `port49_key_version_devices` and `port49_key_retirement_seconds` too); the write fence's
  unchecked ancestor directories and ACLs, now for `inventory_file` as well as the policy file;
  running `TestAnotherUIDIsRefused` in CI with root; measuring, at fleet size, the inventory-only
  refresh's blob comparison (one blob read and two decodes per live context, which a per-pass cache
  would cut; Task 11, M2).
- **Later, unassigned:** seeding `port49_key_version_devices` from the decision log at start, so a
  restart does not blank it (spec §10). The offline tools (`port49 policy test`, `policy diff`,
  `inventory diff`) still read the inventory with a plain read: a named pipe there hangs the tool, not
  port49d.
- **Where the final review's carries went:** Task 12 m1 (an open connection kept its admission),
  fixed as I1; Task 12 m2 (the revert test), Task 10 (the gauge and start lines), Task 19 (two
  replay guards) and Task 17 (the cap), tested; Task 12 m3 (`SIGHUP`'s unfenced read) and Task
  11a (`config.Load`'s pre-fence read), fixed; Task 16's stale detection, fixed; Task 16's
  non-root CI, plan 12 (above); final review m6, m9 and m10, fixed; m7, plan 6b (above); m8, L30.

### Plan 6b — As built

Executed 2026-09-30 on `feature/inventory-service`, each task reviewed, then a whole-branch review,
a fix wave and a scoped re-review; the ledger is
`.superpowers/sdd/2026-09-30-06b-inventory-service/progress.md`, with `final-review.md` and
`fixwave-report.md` beside it. A conflict scan before Task 1 ruled twenty mismatches between tasks
(F1–F20) and patched the plan on `main`, so each brief carried its fix. What differs from the plan's
text, task by task:

- **Conflict scan.** A cold start takes the copy published later (`published_at`), not the higher
  sequence (F1). The fetcher is joined at shutdown and says nothing when its context ends (F8). A
  cold-start copy that does not open sets `port49_inventory_bundle_refused` (F19). Lab tasks run
  `make test && make vet` before committing (F17).
- **Task 4.** `bundle.Open` refuses a document whose `sources` lists name a device that fails the
  inventory's name check, without echoing it, so the one choke point closes log injection; the
  syncer lists only names that pass.
- **Task 5.** port49-inventory.yaml refuses a second YAML document. port49d.yaml's loader does not;
  that is carried to plan 12.
- **Task 8.** The service reads its state behind the fence, a link in a file's own name refused
  (`fence.ReadNoLink`), because `state_dir` is the sequence's trust anchor: a planted older signed
  document could otherwise roll it back. The mirror is trusted by signature alone
  (`fence.ReadSigned`: no link in its name, a regular file, capped), so a ConfigMap-link mirror
  mount is refused, which fails closed. The rollback floor includes `published.json`.
- **Task 9.** `Restore` refuses a start rather than publish below a copy: a `state_dir` copy it
  cannot open, and, with `state_dir` empty, a mirror copy it cannot open. Beside a good `state_dir`
  a bad mirror is said and shows as `port49_inventory_mirror_behind`. `WriteMirror` never lowers the
  mirror's sequence, and the service rewrites a mirror that differs from its sealed bundle at start
  and at every pass, not only at a publish. The per-source `interval` was kept, as spec §10 has it,
  reversing pre-flight Minor 2.
- **Task 10.** Review found a URI SAN beginning `user:` impersonating an email identity: it is
  refused. A nil trust anchor is refused rather than falling back to the system roots, and
  `inventory.Server` returns an error. `readers` and `syncers` match exactly, `*` is not a wildcard,
  and a `user:` entry with an upper-case letter refuses the config, since callers' emails are
  matched lower-cased.
- **Task 12.** The client dials with a fresh, fully verified TLS config per connection, so a CA
  rotation needs no signal; text from a peer's certificate in a TLS error is sanitized before it is
  printed; the diff URL is built with `RawQuery`. `port49 inventory sync` waits as long as a sync
  may take (`sync_timeout`); every ask port49d makes has its 30 s deadline (F16).
- **Task 13.** Every path under `inventory.service` is absolute, `state_dir` and `mirror_dir` may
  not overlap either way, and the URL is strict `https`.
- **Task 14.** A copy published more than 5 minutes ahead of port49d's clock is refused, and judged
  again as the clock advances. The persisted copy is read through `fence.Read`, the mirror's through
  `OpenSignedFile`.
- **Task 15.** Review found that a `SIGHUP` could apply a held document signed by a key it had just
  removed: every apply now opens the document under the verify keys in force at that moment, through
  one `openDocument`. Documents are ordered by (`published_at`, `sequence`), so an older document
  replayed from before a service reset is refused.
- **Task 17.** The combined check runs in `reload` after the verify keys are re-read, through
  `openDocument`. A policy that fails to parse while an inventory is settled is said with it, and the
  inventory is tried again once a policy loads.
- **Task 19.** A phase counts only when port49d's `device_unknown` record and the capture both show
  a connection open across the change. The capture is read against the instant port49d applied the
  reload, not the sync's start, and an idle connection open before it counts. NX-OS's
  single-connection line is typed as its `?` offers (`key 0 <key> single-connection`). A mid-run
  `make build` in the shared worktree invalidated one vJunos run, so every device run since builds
  in a pinned, detached worktree.
- **Task 20** was built and reviewed, and its four overnight runs were dropped (owner decisions,
  below). `TestL29Midnight` stays in `tests/lab/`, gated by `PORT49_L29_MIDNIGHT`, and unused.
- **Final review** (FIX FIRST: no critical, three important, nine minor; all seven security
  invariants held) **and fix wave**, re-reviewed MERGE:
  - **I1: a correctly followed signing-key rotation left the old key's signature in force** on a
    stable fleet, so dropping the old key took TACACS+ down at the next port49d restart. The
    service now re-seals a bundle another key signed as the next sequence, at start and after every
    sync that does not publish, and says when the old key can go (decision 30's rotation order).
  - **I2: cold start persisted the newer copy before the policy accepted it,** so a restart during
    a re-address crash-looped. port49d now takes the newest copy its policy loads, bounds the
    mirror's copy against the persisted one by its own `max_removed_percent`, falls back to the
    other copy with a line, and persists only after the broker is built.
  - **I3: a hung mirror mount hung the service silently.** Mirror reads and writes run under a
    10 s deadline outside the sync lock, `mirror_behind` is 1 before the read, and the metrics
    listener, `/healthz` and `/readyz` (503) bind before `Restore`.
  - Minors: the service's `policy_file` behind the fence; the next sequence is above both the
    history and the last publication, so a Save that failed halfway no longer wedges the service;
    a clock stepped back publishes 1 s after the last publication, said; a refused document counts
    `port49_inventory_fetches_total{outcome="refused"}`, not `unchanged`, and a `SIGHUP` counts it
    once; two pre-6b server tests wait out their own teardown; the operator notes say to protect
    `ca_file`; the plan-12 carry below. Folded in after the re-review: two overlapping mirror calls
    no longer read a slow mirror as hung (N1).

**Owner decisions, as ruled:** 1, every copy of the bundle signed (ed25519) and verified, the
service's own state and mirror against its own `verify_key_files`; 2, the mirror a mounted
directory, not an object-store API; 3, nothing the service sends assigns a key, and a pin is a
policy key group matching the device's name, at tier 1 (a `/32` group is tier 3). **Ryan,
2026-09-30:** Task 20's midnight nights are dropped. The device sees the same TCP reset from
`retire_after` as from a reload, which Task 19 measured, and port49d's reset at the date is tested
in code with an injected clock (`internal/daemon/server/server_test.go`). L29 was reworded to say
so.

**Rows:** **L29 closed** 2026-09-30 on all four images (`L29-reload-*.md`). The session survives
the reset everywhere. Where port49d no longer serves the device, break-glass logs in: in up to
2.1 s on vEOS and vJunos-router, and up to 30 s on the C8000V and 41 s on the N9Kv. Where it still
serves the device under a new name or platform, its FAIL is final on EOS, NX-OS and IOS-XE.
vJunos-router held a connection open across some changes only: its committed note (the run at
6fcce47) measures removed and refused; earlier runs, observed in the lab log and not register
evidence, varied in which phases held one open. **L30 closed** 2026-09-30 (`L30-netbox.md`,
`L30-nautobot.md`), with which of `Host` and `X-Forwarded-Host` a product reads, and a proxied
`next` followed, named as unmeasured outside its question. **Spec §14's quarantine through a sync
passed** on all four (`quarantine-sync-*.md`). **L31 opened** (closed since by `fix/breakglass-reset`, as built below): with single-connection on, break-glass on
IOS-XE and NX-OS costs 16–41 s after a de-admitted device's reset (`L31-breakglass-cisco-singleconnection.md`). The C8000V's
liveness probe again reached port49 only at its second or third attempt before two of six phases
(30 s, 54 s); why is still not established.

**Carried, for later plans:**

- **Plan 6c:** the connectors, the webhook trigger, `Fetch` within `sync_timeout`, and `port49
  inventory export` (Plan 6c, above), written against L27 and L30 as measured: `next` followed only
  to the configured base's scheme, host and port; GraphQL `errors` read even on HTTP 200; the status
  spelling per product; Nautobot 3.2.6 dropping `cluster` and `software_image_files`.
- **Plan 12:** port49d.yaml's loader, and `config.InventoryServiceOf`, ignore a second YAML
  document (Plan 12, above).
- **`fix/breakglass-reset` (above), L31:** break-glass on the N9Kv and the C8000V took 17–41 s
  after a reload removed or refused the device, and 16.7 s and 20.3 s through a quarantine sync.
  The cause is analysed in `L31-breakglass-cisco-singleconnection.md`: with single-connection on,
  a reset after the request is waited out, and those paths never refuse the retries at Accept.
  Done: closed 2026-09-30 (below).
- **Later, unassigned:** the C8000V's slow liveness probe (above).

### Fix `fix/breakglass-reset` — As built

Executed 2026-09-30 on `fix/breakglass-reset`, each task reviewed; the ledger is
`.superpowers/sdd/2026-09-30-06b1-breakglass-reset/progress.md`. A pre-flight review revised the
plan first (8ee966f). The window is cleared by re-asking admission and the policy at Accept, not
at a reload, which covers a quarantine that ends without one, and it counts as its own event,
`declined_refused`, not `held_refused`.

- **Task 1 (docs):** spec §10's "A declined source is refused at Accept, and takes no strike", the
  refused-device, quarantine and reload paragraphs, a §14 bullet, and design §11 (e2d9765,
  26d666d; review minors 4573df8).
- **Task 2 (limits):** `Decline`, `Declined` and `Undecline`, a decline window on the strike's
  schedule and settings that is never a strike (6729c45, 9fd5c7e).
- **Task 3 (server):** an unadmitted source closes as a key miss does: record, strike, reset at
  once, never held; its retries are refused at Accept as `held_refused` (2db70ee).
- **Task 4 (server):** refused, quarantined, and reload-refused or removed connections record,
  reset at once and open a decline window; Accept re-asks admission and the policy inside it, and
  counts refusals as `declined_refused` (9e19e94). A quarantine landing between Accept's re-ask and
  `Undecline` fails closed (34b770a).
- **Task 5 (lab harness):** `TestL31BreakGlass` (dfec85f). Its review found the premises counted
  from the token login, not the break-glass interval, and a refused break-glass scored as a pass;
  both were fixed against the brief (b998ae9), and the runs were pinned there.
- **Task 6 (lab):** L31 on the N9Kv, the C8000V and vEOS with single-connection on (cfd34fd).
  Break-glass removed, refused and quarantined took 2.62, 2.58 and 2.61 s on the N9Kv against the
  control's 2.61 s, 1.28, 1.78 and 1.78 s on the C8000V against 1.28 s, and 0.33, 0.32 and 0.32 s
  on vEOS against 0.34 s; every declined phase's retries were refused at Accept.
- **Task 7 (docs):** **L31 closed** (spec §15), with the §10 sentences, the L29 and L31 notes and
  the `conn.go` quarantine comment giving the measured times; this section.

**Carried:** the C8000V's slow liveness probe (Plan 6b, above), still unassigned. vJunos-router did
not run L31: it was unaffected before the fix, and the fix only adds refusals at Accept.

**Follow-up, unassigned (final review M4):** the per-NAS cap's refusal at Accept
(`internal/daemon/server/server.go`, `refused_cap`) closes with a FIN, not a reset. This predates
this branch and is not a regression. A FIN that comes before the device writes is unmeasured on
IOS-XE and NX-OS with single-connection on, and L28 found the C8000V waits out a FIN that follows
its request. The default cap of 32 makes it unlikely for one device. Either reset before the close
at the cap, or add a lab register row and measure it first.

### Plan 6c — As built

Executed 2026-10-01 on `feature/inventory-connectors`, seventeen tasks, each reviewed; merged 2026-10-01 (PR #19,
merge 888b1d5) after a whole-branch review (MERGE, 0/0/8), its fix wave, and one last fix (943f225, final
re-review N1: a source is given the bundle's names only after a cut-short fetch returns); the ledger is
`.superpowers/sdd/2026-10-01-06c-inventory-connectors/progress.md`, with each task's brief, report
and review beside it. A pre-flight review revised the plan first (three important, seventeen minor;
the plan's "Revised after the pre-flight review"). What differs from the plan's text, task by task:

- **Task 1 (docs; e8ec237, 81c5b65).** Interface addresses are added to the primary addresses, never
  used in place of them, and `addresses.primary` defaults to true (review I1; ruling 10, spec §10
  and decision 31 amended). Design §17 names the webhook as the one inbound call without a workload
  identity, and says the secret is never sent with a delivery.
- **Task 2 (`internal/sot` client; d0bedc0, d9fe335).** The client refuses any request whose scheme
  or host is not the base's, so the token reaches `url` alone; a transport error keeps its cause and
  never prints the query; idle connections expire at 90 s.
- **Task 3 (profiles; 167127f, 0c2e60e).** Under a `profile:` override a release reads as measured
  only when the override is the profile detection would pick, and the said line names the override.
- **Task 4 (`sottest.Server`; 68664e9, 4d37cb9, b9c18eb, b1407e5).** The replay answers only the
  fields a query selects, each stack's ids in its own form (Nautobot UUIDs, NetBox numbers), L30's
  refusal texts word for word, and the recorded `name` filters over GraphQL and REST `?name=`; every
  shape no run recorded is marked so.
- **Task 5 (GraphQL; 1337890, ef45646).** A status error names the request under the `url`'s path
  prefix; `page_size` below 1 is refused; a page that begins with the device the page before began
  with fails as "ignored the offset", and a repeat fails at the page that holds it.
- **Task 6 (REST; fcd48cd, bd89f94).** `next` is always rebuilt on the base, its path and query kept,
  and said only when its origin differed; a `next` on another path is refused; a `next` dropping
  `depth=1` where the profile needs it is refused; the loop check compares the path and the sorted
  query.
- **Task 7 (mapping; db11f8e, e92fc6f).** `addrOf` drops no address for its prefix length (a
  `10.255.0.0/16` loopback is a real device's address); it refuses only a zone, and unmaps
  IPv4-mapped IPv6.
- **Task 8 (`sot.Source`; 94c1a17, 2b9582a).** Every removal is confirmed (ruling on Task 5's I-1):
  at most 256 names gone from a source's last read are each asked for by REST `?name=`, and one
  still there and in scope makes the read inconsistent; past 256, the list is read once more, whole,
  and taken only when both reads list the same names, else the sync fails ("the list changed between
  two reads"), and a failure keeps the last read. A `?name=` answer naming another device fails the
  read (an ignored filter cannot confirm anything). The detect note names a `profile:` override.
- **Task 9 (config; 42ed46f, 6d334b8).** `platform_aliases` refuses two keys equal in lower case, and
  `filter: {status: []}` is refused; `sot.ProfilesOf` lists the profiles a product takes.
- **Task 10 (`Fetch` within `sync_timeout`; 6642ce7, 631258a, ea40177).** A fetch is abandoned 5 s
  past `sync_timeout`; `port49_inventory_source_hung` clears when the abandoned call returns, not at
  the next sync; a caller's cancel (shutdown) is not a hang and waits for nothing; a complete answer
  inside the 5 s grace is used, as spec §10 allows. `port49_inventory_generic_platform_devices`
  counts the bundle in force.
- **Task 10a (bounds; 29eab03, c3dad62).** Both removal bounds, the service's and port49d's, count a
  device left with no address only if the old inventory admitted it, and a test holds the two to the
  same count.
- **Task 11 (the webhook handler; ea9c93a, 9b23238, 79d59cf).** A known and an unknown source name
  are answered alike up to the HMAC compare, the unknown one checked against a random decoy key, so
  neither the answer nor the bytes read tell them apart; a declared length over 1 MiB gets
  413 before any read; a replay entry lives until its timestamp plus 5 minutes, in wall time; a
  refusal line is re-armed by an accepted delivery at most once per 5-minute window, with an owed
  re-arm so a refusal after a deferred re-arm is still said once.
- **Task 12 (the listener; 0e0364d, 89eed09).** The webhook listener is capped at 64 connections, a
  bind error names `webhook_listen`, and a request in flight at shutdown is waited for. A delivery
  that arrives as shutdown begins is accepted and triggers nothing, and after that the connection is
  refused; the `503 {"error":"shutting_down"}` the handler holds is never sent (final review M1, which
  corrected this line, L33's notes and spec §15).
- **Task 13 (`inventory export`; a238518, afe4b5e).** It verifies before it writes; `?sequence=`
  takes canonical decimal only; `State.At` refuses a history file holding another sequence; a
  failed write to standard output exits 1; a symlinked `--out` is said as one; the header names the
  service's scheme and host only. `--from 0` is a usage error.
- **Task 14 (lab, L32; a50c993, 0f7cd70, e8bbe15, eb862a4, f2c43b6).** A third proxy,
  `proxy_plain` (a bare `proxy_pass`), was added in review, since neither planned proxy made any
  release name another origin; through it every release named its internal `http://<svc>:8080`, and
  the connector rebuilt `next` on `url` and said so. L32 found GraphQL's `id` selectable, a string,
  on all five releases, so the GraphQL list is keyed by `id` (e8bbe15), as REST's is, and the run was
  repeated; the name-based offset-ignored check is kept.
- **Task 15 (lab, L33; c8a63d8, 76de80e, 1c0b8d1, 6f96ab2, 0b4886f).** Beside the 401, a delivery
  answered 503 by a stand-in listener (port49-inventory itself never answers a delivery 503) was
  measured, and each release's retry setting read from its source. `run.sh`'s e2e mode selected no platform and both device runs wrote one capture name; both
  were fixed and the device runs repeated.
- **Task 16 (docs; e60f6a3, 101ce68).** L32 and L33 closed; spec §10's three "§15 L32's/L33's"
  sentences replaced by the measured answers; this section.
- **Final review** (MERGE: 0 critical, 0 important, 8 minor) **and fix wave**:
  - **M1:** port49-inventory never answers a delivery 503 at shutdown (above, Task 12); the as-built,
    spec §10 and §15 and L33's notes said it did, and were corrected (lab rule 4).
  - **M2:** a source confirms a removal against the names the bundle in force holds for it, given by
    the syncer before each fetch (`inventory.Confirmer`), not its own last read: a refused or
    abandoned read is no baseline, and a restart confirms against the restored bundle (71969a5).
  - **M3:** notes of single devices are bounded apart from the source's own, so they cannot silence
    a rebuilt `next` or a fallback; **M4:** the hung gauge's comment says it falls when a running
    sync ends (71969a5).
  - **M5:** `Webhooks.Secrets` holds `sot.Secret`, redacted however printed (89068bb).
  - **M6:** the L33 runs check the service's log for the API token as well as the webhook secret
    (d16d501).
  - **M7:** `internal/printsafe.Line` replaces the two printable-line copies, and `bundle.names`
    builds on `nameList` (8fa9637).
  - **M8:** the raw L33 captures are copied to the main checkout before the worktree is removed
    (the controller's step).

**Rulings, as made** (spec §13, decision 31; the plan's "Rulings where the spec is silent"): all
fourteen stand, with these amendments, each the option that denies more. Ruling 6: a list must
equal REST's `count` before and after it (pre-flight I1), and every removal is confirmed or read
twice (Task 8). Ruling 7: `next` is always built on the base (Task 6). Ruling 3: every 401 has one
body and a known source name is not told from an unknown one (pre-flight M9, Task 11). Ruling 10:
interface addresses are additive (Task 1). Ruling 12: the generic-platform line is said at each
publication that changes the set (pre-flight M6). Ruling 13: a complete answer inside the grace is
used (Task 10).

**Rows:** **L32 closed** 2026-10-01 (`L32-netbox.md`, `L32-nautobot.md`): every release builds `next`
from `X-Forwarded-Host` when sent, from `Host` otherwise, and takes `https` only from
`X-Forwarded-Proto`; the connector as built read all 120 devices through three proxies over GraphQL
and REST on all five releases, rebuilding `next` on `url` where a bare proxy left it naming the
upstream. **L33 closed** 2026-10-01 (`L33-netbox.md`, `L33-nautobot.md`,
`L33-e2e-netbox-arista_eos.md`, `L33-e2e-nautobot-arista_eos.md`): every release delivered over TLS
under a private CA; a change published in 2.4–2.7 s from NetBox and 3.6–4.1 s from Nautobot, and
reached port49d's reload on vEOS in 2.5–5.0 s and 4.5–7.0 s; no release sends a delivery refused 401,
or answered 503 by a stand-in listener, again by default.

**Operator notes** (for plan 13's docs, beside the plan's "Operator-facing notes"):

- `HTTPS_PROXY` is ignored by design: the service dials each source directly, so a source reachable
  only through an egress proxy is unsupported until plan 12.
- A webhook refused is not sent again by any measured release at its defaults (NetBox
  `RQ_RETRY_MAX` 0; Nautobot none). The source's `interval` sync is the backstop: size it to how long
  a change may wait.
- A webhook that arrives as port49-inventory shuts down is accepted and triggers nothing, or is
  refused at connect; it is never answered 503. By the same retry settings it is not sent again
  (the restart case follows from those settings; no run measured it). The startup sync, which reads
  every source, covers it.
- `port49 inventory export` without `--from` accepts an older genuine bundle; the header names its
  sequence.

**Carried, for later plans:**

- **Plan 12:** `token_secret_ref:` and `webhook_secret_ref:` with the `secret_ref:` resolvers; the
  service honouring an outbound HTTP proxy for its sources (it dials each source directly).
- **Later, unassigned:** tags as an attribute, once the spec gives a multi-valued attribute a shape;
  server-side GraphQL filters, once a lab run records each release's filter arguments; a GraphQL list
  above a server cap and a list changing between pages, which the count check turns into a failed
  sync rather than a silent loss but no run measured; further connectors (Infrahub, Ansible
  inventory), which take the same `inventory.Source`.

**Follow-ups, unassigned (not blocking):** plain HTTP on `webhook_listen` is refused (400) but
counted on no metric (Task 12 review M3); a `SIGTERM` during the 5 s fetch grace of a sync already
past its deadline waits it out, at most 5 s (Task 10 N1); L32's record could hold whether `next`'s
host resolves, so the note quotes it rather than the controller's reading (Task 14 M-R1).

## Plan 7 — Broker in full (§19 step 7)

Design §7 (OIDC public client with PKCE, certificate-to-directory mapping, directory
integration, trust domain by verifier lists), §10 (server pool, pre-warm, grace, replication
lag), §17 (the whole API surface, idempotency, batch mint, **`api:` rights** default
self-only, `/v1/refresh` with `prompt=login` and the cert-path signed-nonce refresh,
`/v1/logout` back-channel), spec §5.1.3 (scheduled refresh through `active_principals`),
§5.1.4 (revocation by `sid`, `sub`, CRL/OCSP), §5.6 session lifetime (ceiling warning,
grace window, `max_session_age` minimum across roles), the staleness ceiling end to end.

**Carried from plan 3:** a store two processes can reach, before the broker leaves `port49d`
(design §19 step 2); the scheduled refresh and the `staleness_ceiling` default, together; PR #7's
third follow-up — a join racing another principal's replace under one username can lose its sid or
certificate index entry (revocation by principal still reaches it); the certificate-to-directory
mapping replacing the slice's declared `username:`; go-dark on a store outage, if plan 6 has not
built it (plan 4's "Hands to plan 6"). Also owed by plan 3's reviews:

- An **atomic put-if-absent idempotency reservation**. Two concurrent requests under one key
  with different bodies can both pass the pre-check today, and the minter's read, mint and
  `PutIdempotency` are three steps, not one.
- **Per-source limits or admission on the broker listener.** One client reconnecting every 30s
  can keep all of `broker.MaxConns` (256) slots full.
- A **counter for broker TLS handshake failures**.
- A **per-principal cap on held broker connections**, beside the per-source one. Any
  certificate the anchor signs can open all 256 slots and hold them for `max_session_age`,
  locking every other operator out of `port49 login`.
- **A revocation must reach the held connection.** Plan 4b makes a policy edit live: removing
  a subject's grant revokes that principal's contexts with no restart and no logout. Revocation
  by principal or by certificate (spec §5.1.4) is this plan's, and it must also
  refuse mints on, or close, that principal's held broker connections; otherwise a token
  minted after the revocation lifts it (decision 15).

**Carried from plan 6a:** go-dark on a store outage, the warm context cache, plan 4b's
remote-store items, and the `crypt_open_failures_total{record="token"}` alarm (Plan 6a — As
built, "Carried").

**Split into 7a–7h (2026-10-01).** Plan 7 is the largest step group, and one platform-critical
choice in it is not made by the design: which shared store backs the broker once it leaves
`port49d` (design §12 lists Redis, Valkey, DynamoDB, etcd and an RDBMS as pluggable and picks none).
That is **Decision D1** below, for Ryan. The split is ordered by dependency first and security value
second, so that the three sub-plans that do not touch the store's backend come first and D1 has
until 7c merges to be made. Every sub-plan is separately mergeable and leaves `make test` green.

- **Plan 7a — `2026-10-01-07a-revocation-and-broker-limits.md`. Written 2026-10-01.** The carried
  security debts that need no backend: an **atomic idempotency reservation** (put-if-absent per
  device, the whole batch reserved before its first mint, a concurrent duplicate answered `409
  idempotency_in_progress`); a **broker listener that does its own TLS handshakes**, so every
  failure is counted by reason (`port49_broker_tls_handshake_failures_total{reason}`), with a
  **per-source cap on connections not yet authenticated** (reset at accept) and a **per-principal
  cap on held connections** (the oldest closed for the newest, so a laptop's dead connections never
  lock its owner out); and **revocation that reaches everything**: a standing mark by principal or
  by certificate (issuer, serial) checked at every mint, before and after its token writes, that
  closes the held connections it names (and, from the listener's in-memory copy, refuses them as
  they bind), deletes the unspent tokens through a new token index (plan 2's "largest remaining
  hole in revocation"), marks the live contexts twice and deletes the receipts, names the contexts
  it cannot reach, and is one `revoke` record (a new §5.7 event). An operator revokes
  and lifts with `port49 revoke` over the admin socket; the marks are kept in
  `broker.revocations_file` (its directory fenced, created at the first start beside a marker, a
  missing or unreadable file refusing every later start), so a restart forgets none. The store interface gains the reservation,
  the token index and the marks, each with a `storetest` property every backend must pass; no
  backend is built. Lab: revocation end to end on vEOS, the N9Kv, the C8000V and vJunos-router.
- **Plan 7b — session lifetime and certificate status.** `/v1/refresh` on the certificate path
  (the signed-nonce challenge over the held connection, `auth_time` the broker's verification time,
  decision 17); `max_session_age` per role, composed as the minimum (lifting plan 4's load
  refusal); the ceiling warning in `server_msg` and the grace window's sweep; CRL (and OCSP)
  checking of client certificates at mint, feeding 7a's certificate marks (spec §5.1.4); the
  refresh's per-context records naming unreached contexts as 7a's revoke record does (decision 21).
  Lab: L2's open truncation length and IOS-XE, which the warning rests on.
- **Plan 7c — `2026-10-02-07c-api-and-authorization.md`. Written 2026-10-02.** `api:` rights
  enforced (`revoke_others`, `explain_others`; `sync`, `keys_show` and `replay` ruled reserved, no
  broker endpoint guarding them; no right widens a mint or `RefreshSession`; self-only by default,
  design §17); `POST /v1/tokens/revoke`: `mine` (the caller's own tokens deleted by ID and its own
  contexts marked by compare-and-set, no standing mark), another principal under `revoke_others`
  through 7a's `Revoke` (origin `api <caller>`), or a (device, username); `GET /v1/identity`;
  `POST /v1/explain` (an unknown device answered as one with no grant); `/healthz` and `/readyz` on
  the broker, readiness never the store's; plan 4b's candidate reload guard ruled on (a policy
  reload newly quarantining or refusing more than `inventory.max_removed_percent` of the devices in
  service is refused); `port49d init-revocations`, a start never creating the file (decision 32
  amended); `port49 identity`, `port49 explain` and `port49 revoke --mine`/`--via-agent` over the
  agent; a new `store.DeleteToken` with a `storetest` property. Lab: the HTTP revocation's shapes on
  the four images 7a measured. **As built:** "Plan 7c — As built", below.
- **Plan 7d — `2026-10-02-07d-shared-store.md`. Written 2026-10-02.** The shared store (D1 = etcd). The backend D1 chooses, implementing every store method
  with its atomicity and passing every `storetest` property, 7a's included; store-native mutual-TLS
  authentication per component (design §17); a hard timeout and a circuit breaker on every store
  call, and pool separation between token and context operations (design §12); plan 4b's
  remote-store items (a deadline on each refresh and per-packet store call; the settle pass's
  redeem-to-write assumption; unindexed contexts invisible to the refresh); PR #7's third follow-up,
  a replace, its unindex and its index made one atomic operation; the
  `crypt_open_failures_total{record="token"}` alarm. **As built:** "Plan 7d — As built", below.
- **Plan 7e — `2026-10-03-07e-broker-process.md`. Written 2026-10-03.** The broker as its own process. `cmd/port49-broker`, and `port49d` serving
  TACACS+ with no broker inside; `b.superseded` and `b.blobsSeen` moved into the store and bounded
  (4b final review m10); decision-log emits under the policy hold bounded (4b Task 4); one refresh
  runner across broker replicas; `broker.revocations_file` retired if D1's backend persists. Lab:
  the slice on the split deployment. **As built:** "Plan 7e — As built", below.
- **Plan 7f — `2026-10-05-07f-go-dark-and-context-cache.md`. Written 2026-10-05.** Go-dark and the warm context cache. The owner's ruling of 2026-09-24: `port49d`
  health-checks the store and closes its TACACS+ listener after N failed checks, reopening after M;
  **its Task 1 (Ryan, 2026-10-03):** the container shape, pulled forward from plan 12, before 7f's
  own work. It ships:
  - a minimal image holding the static binaries, non-root;
  - one compose file: port49d, port49-broker, a three-member etcd with client-cert auth, and a
    named volume per broker for `broker.state_dir`;
  - a CI smoke test: `compose up`, then a device login, then a restart, and the broker's state
    is kept.

  It closes L39's Docker half. From then on every plan's lab runs on it, and a plan that changes a
  config changes the compose file in the same plan. Kubernetes stays plan 12's, after plan 10.
  the per-replica read-through cache of contexts and blobs, TTL in seconds, served past its TTL
  through an outage and alarmed (design §12). Lab: a new register row, what each image does when
  port49d closes its listener mid-session, beside port49d stopped. **As built:** "Plan 7f — As
  built", below.
- **Plan 7g — `2026-10-05-07g-the-directory.md`. Written 2026-10-05.** The directory. LDAP and Active Directory group resolution with design §10's server
  pool (priority, sticky selection, circuit breaker, failback hysteresis, site awareness), nested
  groups by configuration, SASL EXTERNAL, GSSAPI or simple bind; the certificate-to-directory mapping
  replacing the slice's declared `username:` (strong, or issuer-pinned weak, ambiguity failing
  closed); group subjects minting; pre-warm and grace; the scheduled refresh through
  `active_principals` stamping `refreshed_at`, and the `staleness_ceiling` default, in one change.
  Lab: a new register row for nested-group resolution on OpenLDAP and Samba AD.
  As written: L42 (nested groups) and L43 (binds) on OpenLDAP and Samba AD, and L44 (the same
  AD claims on Windows Server AD) opened and left open for the SER8 box.
- **Plan 7h — `2026-10-06-07h-oidc-and-trust-domains.md`. Written 2026-10-06.** OIDC and trust domains. The verifier lists `identity.humans` and
  `identity.machines` (decision 16); OIDC ID and access tokens validated against the provider's
  JWKS; `/v1/config`'s issuer and client id; `prompt=login` refresh with `auth_time` from the
  assertion; `POST /v1/logout` back-channel by `sid` or `sub`, as 7a's marks by `sid`; `amr` and `acr`
  recorded. The agent's OIDC public client stays plan 9's. Lab: a new register row for the logout
  token a provider sends. Pre-flight 2026-10-06 applied (`planfix-report.md` in its ledger): pinned
  machine clients, per-verifier `principal_domains`, a required `principal_claim`, owner records
  holding every principal.

Order: 7a–7c do not depend on D1, and are the ones a stolen laptop or an abusive caller needs
first. 7d–7f need D1's backend. 7g and 7h integrate external identity systems, are the largest,
and each brings its own lab row. If D1 is still open when 7c merges, 7g may move ahead of 7d; it
needs no store change.

**Decision D1, for Ryan: which shared store does 7d build?** The design requires atomic
match-and-delete with TTL, an atomic remove-and-write, compare-and-set on contexts, and
reachability from every daemon (§12), and leaves the product open. The options, against what
port49 needs most (a redeemed token never comes back, and a revocation mark is never lost):

1. **etcd (recommended).** Raft: every acknowledged write survives a leader failover, so a
   redemption, a reservation and a revocation mark never roll back. Transactions give every
   compare-and-set the store needs, leases give TTL, and client authentication is mutual TLS with
   per-component roles (design §17's internal interfaces). Throughput is thousands of writes a
   second, above the §5 target of ~170 authentications a second. Costs: a lease per expiry
   bucket to keep lease churn down, an 8 GiB soft size limit (port49's records are small), and
   every write crosses to the leader.
2. **Valkey or Redis.** The fastest, and Lua scripts make each operation atomic. Replication is
   asynchronous: a failover can lose an acknowledged write, so a redeemed token can be redeemed
   again and a revocation mark can vanish. `WAIT` narrows that and does not close it. Acceptable
   only with the replay window documented, which is what design §13 already says of regional
   replication.
3. **PostgreSQL.** Serializable transactions and row locks; widely operated. TTL becomes a sweeper's
   job, and connection counts need a pooler at fleet scale.
4. **DynamoDB.** Conditional writes and transactions fit well, but it is one cloud's, and most network
   teams run port49 on premises.

Recommendation: etcd first, the interface kept pluggable, and a Valkey backend later only with its
replay window stated. 7a builds nothing that depends on this: its store methods are added to the
interface and the memory store, with `storetest` properties the chosen backend must pass.

### Plan 7a — As built

Executed 2026-10-01 on `feature/revocation-and-broker-limits`, thirteen tasks and one lab-driven
fix (fixA), each reviewed; merged 2026-10-01 (PR #20, merge bf96a46) after the fix wave's re-review
said MERGE. Two non-blocking follow-ups from that re-review: R1, `storetest` should say when it skips
the holderless-record case for a store that is not a `storetest.Planter` (7d's backend test must
implement Planter); R2, `Agent.Mint` after Done returns a bare `ErrSessionOver` rather than the
recorded reason; the ledger is
`.superpowers/sdd/2026-10-01-07a-revocation-and-broker-limits/progress.md`, with each task's brief,
report and review beside it. A pre-flight review revised the plan first (one critical, seven
important, twenty-two minor fixed at 1ac1665; M8 rebutted: a retransmission with no live context
answers `token_spent` and never replays a receipt, spec §5.6). What differs from the plan's text,
task by task:

- **Task 1 (docs; d0aedba, 9cb67bc).** The report events are renumbered around `revoke`; a
  retransmission whose receipt a revocation deleted is answered `token_not_found` (§5.1.4, §5.6, the
  `token_not_found` row); `revocation_lifted` is worded by decision 15 (a certificate's mark does not
  keep a context revoked); decision 32 names the fallback for an unwritable mark; decision 21 gives
  the `revoke` record's `unreached` to 7a and a refresh's to 7b.
- **Task 2 (idempotency reservation; 9d6e56f, 2038c3c, 2e6a662).** A reservation or completion with
  no holder is refused, and a completion expecting the empty holder conflicts, so a holderless record
  is never taken over; a pending record reads back through the sealing layer without opening; the
  lease's expiry is a `storetest` property of its own (`IdempotencyLeaseExpires`), since
  `IdempotencyReservesOnce` runs on a fixed clock.
- **Task 3 (the batch reserves; aabd43c, 4a8d154).** Controller ruling: each device's hold is renewed
  by a compare-and-set on its holder before its mint (one minute per device, not per batch), so a
  batch longer than the lease never lets a retry mint the same device; a lapsed or taken hold
  answers the whole request `409 idempotency_in_progress`, and the same CAS takes over an abandoned
  replay. A refused reservation is given back on its own context; the agent honours `Retry-After`
  up to 5 s. A completed record from before 7a (no holder) that is abandoned is answered 409 until
  it expires (bounded, fails safe).
- **Task 4 (token index; 8d4685a, 0576543).** A blank certificate key (no issuer, no serial, no
  `|`) is never indexed; a mint with no principal is refused (`ErrNoPrincipal`); the index outlives
  its token by a minute so a skewed clock cannot drop it first. Controller ruling: fix round 1
  (tests and a one-line guard, each mutation-checked by the implementer) was accepted on the
  report without a reviewer re-review; cost if wrong, a gap the final review would catch.
- **Task 5 (marks; 333548d, 2120e54).** `PutRevocation` refuses a malformed mark (an unknown kind,
  an empty key, a certificate key missing its issuer or serial), a deviation accepted in review and
  a `storetest` property; a well-formed mark that nothing names is still written, with Ruling 4's
  warning. A list's order within a kind is pinned. Controller ruling: the minors were accepted on
  the implementer's report (tests only, and one shared blank-key helper); cost if wrong, a test
  that measures less than it says.
- **Task 6 (the listener; b6a9b33, df8c834, 3381730).** The accept loop starts at the first `Accept`,
  so marks fed before `Serve` are in place before any connection binds; a mark that lands
  mid-handshake is refused at bind; the per-source isolation is a committed test (a second loopback
  address).
- **Task 7 (mint checks; 83f5e5c, 2efadc0, 0b53496).** The after-write check runs on both exits
  that follow writes (the 200 and a mid-batch `409`); a mint refused after its writes records `deny
  credential_revoked` for each device it minted, with `index_error` when the delete failed (spec §5.7,
  2efadc0), and `capability` does not count those tokens; a replay is refused to a revoked caller;
  when the second mark read fails, each written key is superseded (amending ruling 6).
- **Task 8 (`Revoke`, `Lift`; 2dd8723, a9727f0, 21185e9).** `normal()` refuses `user:` alone and a
  serial empty after `0x`/`-`; an all-digit serial is flagged (it may be openssl's decimal); an
  issuer with a control or format character is refused. The listener is told and held connections
  closed before the file is saved; Revoke and Lift are serialised by a one-slot semaphore that gives
  up at the caller's deadline, so a hung store cannot block every later revocation. A key is counted
  only if it held tokens; a certificate revocation says the principal's other certificates lost
  their tokens on those devices too. A context on a device the policy in force no longer lists is
  counted unreached.
- **Task 9 (port49d; 8cac758, d545bfb, 1da0f2d).** A save runs under a 5 s deadline in a one-slot
  writer that catches the file up after a hung write and lowers `port49_revocations_file_failed` only
  when every mark in force is written; a file laid down by hand gets its `.created` marker at the
  next start (else a later loss read as a first install). Marks are restored into, and saved from,
  `brk.Store`. With a listener in front, a principal marked across a restart was closed at bind (the
  test asserted that until fixA, below).
- **Task 10 (admin socket; 7209348, d579122, 19e1cff).** Controller ruling: a caller's hang-up
  cancels only the wait for the revocation slot; once a revocation or lift holds it, every step runs
  detached under `Broker.RevokeTimeout` (= `admin.OpTimeout`, 60 s), so a dropped SSH session never
  leaves a revocation half done. Unknown request keys are refused; a failed list names what failed.
  Controller ruling: the review's five minors were accepted on the implementer's report (#4
  mutation-checked); cost if wrong, a fix that does less than its report says.
- **Task 11 (`port49 revoke`; 021d408, eaa735c, 616bb5c).** Controller ruling: the client waits
  `RevokeWait + 5s` (140 s) for a revoke or lift, longer than the plan's 70 s, so the operator sees
  the report of a revocation still running. A failure after the request was sent prints "port49d did
  not answer … the revocation may be in force — check `port49 revoke --list`". `--cert` takes one
  certificate, PEM or DER, refuses a file holding a private key or more than one certificate, caps
  the read at 1 MiB, and prints the subject and issuer quoted. The client never half-closes.
- **Task 12 (lab; 2957904, 9e257ae, a85c58e, 5ccd2ef, ebb10d4, e4326e6, 64a9996).** The first runs at
  2957904 found that on vEOS, the N9Kv and the C8000V **the agent survived the revocation**: the
  listener closed the reconnect at bind without answering, and the agent read the hang-up as one that
  does not end a session. That contradicted spec §5.1.4 and the pre-flight's I4 (those first notes
  were overwritten before commit; the finding is recorded here and in bfd482a's message). Ruling (a)
  fixed it (fixA, below), and all four images were rerun. On IOS-XE the refusal prints only the
  `server_msg`; the test was taught that (9e257ae). The review's tightenings (each report names one
  held connection closed, and on Junos the session not reached; the `show version` line quoted; a
  revoked operator's `port49 login` refused) were measured in a full rerun at e4326e6 (64a9996).
  Controller ruling: the rerun was not re-reviewed, since the harness was reviewed and approved and
  the rerun only produced the evidence its tightened checks gate; cost if wrong, a note that says
  more than its run showed, which the final review re-read.
- **fixA (bfd482a, fe556d3, 504cb53, 1b46f56; most of its broker code in 9e257ae).** The listener
  completes the handshake of a marked certificate or principal, reads one bounded request (4 KiB of
  headers, the body drained, 5 s), answers `401 credential_revoked` with the mint path's body and the
  mark's own time, records it as `mint deny credential_revoked` (principal and fingerprint), and
  closes; it never reaches a handler or the store, and is never held or charged to the principal's
  cap. The agent's `Connect` reads the reason, so `port49 login` prints "… was revoked at …". Spec
  §5.1.4 and design §17 say so (1b46f56). **9e257ae is mislabelled:** "test(lab): read IOS-XE's FAIL
  text…" also carries most of fixA's broker code, swept in by a `git commit -am` in the shared
  worktree; history is left as is by ruling, and lab commits since name their paths. Found and fixed
  in passing: a cold-start clock race in port49d, where a clock step between two copies' readings
  could take the older bundle (504cb53; one clock reading per pass).
- **Task 13 (docs; this section).** Spec §5.6's retransmission sentence names the deleted-receipt
  exception; decision 32 amended (below); `tests/lab/README.md`'s `chmod go-w` covers
  `tests/lab/logs`, the lab's `revocations_file` directory, which the fence refuses group-writable;
  the plan's operator notes no longer say a revoked operator's login succeeds.
- **Final review and fix wave.** The whole-branch review of 1ac1665..6279776 ran: FIX FIRST, 0
  Critical, 1 Important, 9 Minor (`final-review.md` in the ledger's directory). It found no path by
  which a revoked principal or certificate keeps access beyond the residuals the spec names. The
  fix wave:
  - **I1 (8776e1b).** `port49 revoke --cert` sent the serial as bare hex, so a certificate whose hex
    serial is all digits (sequential CAs issue 10, 11, …) was flagged as a decimal copied by hand,
    and the report told the operator to lift a correct revocation. `--cert` now sends `0x<hex>`
    (a minus sign kept in front), and the hint for a hand-typed all-digit serial says to revoke
    again with `--cert FILE` first and only then lift, so no gap is left without a mark.
  - **fixA N1 (abee45d).** `refuse` says (or holds back) the line before it counts the failure.
  - **Task 3 M7 (8f19fa3).** A test that `Mint` waits by the broker's `Retry-After`.
  - **Task 7 N1 and N2 (c0b914c).** A replay the after-write check refuses writes no device deny:
    `token.Result.Replayed` (never stored) marks it, and `unmint` deletes and supersedes its key
    without one; §5.7 says so. A test pins `capability`'s re-permit after a double deny.
  - **M9 (e75c462, cbed56a, df086a7).** A revoked session's error no longer says to run `port49
    login` ("the session is over: this principal was revoked at …; … (port49 revoke --lift)",
    through the agent socket too; the lab notes, run at e4326e6, show the old text, and the lab
    test's match, "the session is over" and " was revoked at ", holds for both). `PutIdempotency` and `GetIdempotency` leave `store.Store`:
    tests read a record with `storetest.Peek` and write one by reserving and completing it, and
    the holderless-record case runs on a store that is a `storetest.Planter` (the memory store's
    test is one). The `Broker` comment names every optional field.
  - **M5–M8 and the rest of M9 (docs).** "Task 10 N1" is struck from this entry (a controller
    error; there was no such item); Ruling 4 is restated below; the omitted controller rulings are
    added above; §5.7 says a `revoke` record is written per revocation or lift that takes force
    and a failed or refused one writes none (rewording, as the review recommends); the plan's
    Ruling 10, its "What the operator sees" and its §5.1.4 text say a revoked login is refused,
    marked revised.

  Accepted, not to be fixed: Task 8/9 M2 (a hung disk keeps minted tokens redeemable up to 5 s
  longer, behind the save deadline). Left for Ryan: Task 9 M1 and decision 15's cost on a
  certificate's mark (below).

**Rulings, as made** (spec §13, decision 32; the plan's ten rulings): all stand, with these
amendments, each the option that denies more. Ruling 5 and ruling 10: a marked connection is
answered `credential_revoked` as it binds, recorded, and closed, not closed unanswered; a revoked
operator's `port49 login` is refused at its first request, not admitted until its first mint (lab,
fixA; decision 32 amended in this task, citing `tests/lab/results/revoke-*.md`). Ruling 6: when the
second mark read fails, the written keys are superseded (Task 7). Ruling 8: a hand-laid file is
given its marker; a save runs under a deadline and catches up (Task 9). Ruling 9: a hang-up cancels
only the wait for the slot (Task 10). Ruling 4 stands as written: a well-formed mark that no
subject names is still written, with a warning to check the spelling; the store refuses only a
malformed one (an unknown kind, an empty key, a certificate key missing its issuer or serial;
Task 5).

**Lab (Task 12).** No register row: the device behaviours rest on the slice, L4 and L17 notes.
Revocation end to end at e4326e6, all four PASS (`tests/lab/results/revoke-<platform>.md`, captures
`tests/lab/evidence/revoke-<platform>.pcap`): **vEOS 4.31.2F** (`revoke-arista_eos.md`): the next
command refused "% Authorization denied … this session was revoked"; **N9Kv 10.4(2)F**
(`revoke-cisco_nxos.md`): refused "Error: AAA authorization failed"; **C8000V 17.13.01a**
(`revoke-cisco_iosxe.md`): refused, the device printing only the `server_msg`; **vJunos-router
23.4R2-S2.1** (`revoke-juniper_vjunos-router.md`): the session kept what it had at login, and both
reports named `srx1 (slice01)` not reached. On every image an unspent token was refused
`token_not_found`, both agents ended on `401 credential_revoked` with one `mint deny` each, a revoked
`port49 login` was refused "revoked at", and a login after the lift worked.

**Operator notes** (for plan 13's docs, beside the plan's "Operator-facing notes", which are amended
for the revoked login):

- After revoking a stolen certificate, also close that user's sessions on the devices: under
  decision 15 the context is shared per (principal, device), so the owner's next login re-admits a
  still-open device shell; Junos keeps what it had at login anyway, and the report names the
  sessions it did not reach.
- `port49_revocations_file_failed` at 1: run the revoke again; do not restart port49d while it is
  raised, or the restart forgets the unsaved mark.
- A revocations file laid down by hand on a read-only volume refuses the start (port49d cannot write
  its marker).
- `port49 revoke --cert FILE` takes the leaf alone (it refuses a bundle), PEM or DER, and refuses a
  file holding a private key. Prefer it to `--cert-serial`: an all-digit `--cert-serial` is read as
  hex and the report warns that it may be a decimal copied from `openssl x509 -text`; if so, revoke
  again with `--cert FILE`, then lift the first. `--cert` never draws that warning.
- A revoked operator sees "the session is over: this principal was revoked at …" from `port49
  login` and `port49 token`; logging in again does not help until an operator lifts it.
- Exit codes: 0 done, 1 refused or unreachable, 2 usage, 3 in force but incomplete or unsaved. "port49d
  did not answer — the revocation may be in force" means check `port49 revoke --list` before
  retrying.
- A revoked caller's broker connection is answered `credential_revoked`; port49d says it on stderr
  (rate-limited), counts it (`revoked_refused`, `port49_decisions`) and writes a `mint deny` record.

**Decisions for Ryan (answered 2026-10-02, all as recommended):**

- **D1**, the shared store's backend: **etcd** (7d).
- **Task 9 review M1:** an unmounted or empty revocations volume that passes the fence looks like a
  first install, so port49d creates an empty file and starts with no marks, saying so in one stderr
  line. **Ruled: require an explicit one-time init instead of creating the file.** This changes
  decision 32 (and pre-flight C1); carried to plan 7c.
- **Decision 15's cost on a certificate's mark:** the owner's next login re-admits the stolen
  certificate's still-open device shell (operator notes, above). **Accepted**, as decision 15
  already does; the operator notes tell the responder to close the device session.

**Carried, for later plans:**

- **7b:** the refresh records' `unreached` field (decision 21); CRL and OCSP feeding the certificate
  marks.
- **7c:** the HTTP revocation over `Broker.Revoke`; self-revocation's shape (a principal revoking its
  own tokens without a standing mark).
- **7d:** `storetest.IdempotencyReservesOnce` (and `IdempotencyLeaseExpires`), `TokenIndex` and
  `RevocationMarks` for the chosen backend; whether `broker.revocations_file` stays once the store
  persists; the revocation's residual window (a redemption that removed its token before the delete
  and writes its context after the second pass), closed atomically in the store.
- **7e:** the listener and the marks in the separate broker process.

### Plan 7b — As built

Executed 2026-10-01 on `feature/session-lifetime-and-cert-status` (base 0fc2761), thirteen tasks,
each reviewed per task; the ledger is
`.superpowers/sdd/2026-10-01-07b-session-lifetime-and-cert-status/progress.md`, with each task's
brief, report and review beside it. A pre-flight review revised the plan first (two critical,
thirteen important and twenty-two minor fixed at 196aba0, M8 rebutted in part; its re-check's three
important and five minor fixed at 0fc2761). What differs from the plan's text, task by task:

- **Task 1 (docs; 52c5ac0, aa407ee).** §17 had no error-code list, so the new codes got an Errors
  paragraph. The review added an OCSP `revoked` answer as a marking origin (`ocsp <responder>`), the
  `refresh` meanings of `trust_domain_unresolved` and `credential_revoked` in §5.7, and the held
  connection's own ceiling at `session.max_session_age_default` in §5.6 and decision 33.
- **Task 2 (`max_session_age`; 0ba650f, 0b1c50e).** `SessionAge` gains `Never`: a zero
  `SessionAge` takes the default, never `never`, so a value nobody set fails closed. `port49
  explain` says `session.max_session_age_default (no role names a finite one)`.
- **Task 3 (the mint's ceiling; f3faa9e, d8fcd1e).** An idempotent replay keeps its tokens' original
  `session_expires_at`, and a record whose tokens are past their ceiling is minted again, not
  replayed (`token.Result.SessionExpiresAt`). The per-device test was rebuilt so one device's
  ceiling differs from the other's. Controller ruling: the connection keeps the default ceiling, so
  a role longer than the default still re-authenticates the connection at the default (Ruling 1, as
  intended).
- **Task 4 (the store; 7ca5b26, 5c5605c).** A context with no `auth_time` given a finite ceiling by
  policy gets one in the distant past, so it is denied `session_expired` (fail closed; a `storetest`
  property). The grace check uses the authorizer's predicate. A refresh of a `never` context past
  any cutoff is pinned to succeed.
- **Task 5 (the policy refresh; 691008e, 17b780d, 8dae9e3).** A context with no `auth_time` is
  written at every policy refresh, and so fails closed. A quarantined record on a session-only
  platform also carries `unreached`. §5.1.3 and §5.7 say the refresh moves `session_expires` only
  earlier.
- **Task 6 (warning, grace; dadd556, 87836c5).** The blob's TTL is bumped on permits, not only on a
  touch (the Task 3 review's carry), throttled to once per half idle TTL per hash on each replica
  (50 permits, one write). `main.go` sets `Broker.CeilingWarning`, which nothing set before, so
  `ceiling_warning_seconds` was always 0. A delete that loses its compare-and-set counts as
  `conflict`, not as a store error. The warning matches the peer's own platform name, so an
  inventory variant is warned only if listed by its own name.
- **Task 7 (`/v1/refresh`; 4443480, 2334ece, ff2405d).** A refresh's store errors are recorded
  `refresh deny store_unavailable` and counted `store_error`. The marks are read again after the
  extension, and a mark found then is answered `credential_revoked`. A 503 after the connection was
  renewed sends `Retry-After: 10` and says some sessions may have been extended. Controller ruling:
  every consumed nonce is paced, except an expired one, so an agent retrying after a stale nonce is
  not made to wait. A context `refreshContext` revoked for a fault is reported `revoked`, not
  `not_judged`.
- **Task 8 (the agent; 915dbd6, 495d74b).** Controller ruling: `port49 login` refreshes a running
  agent only when its broker and its certificate's fingerprint match the flags. Otherwise it exits 1
  naming the running agent's broker. The agent never moves its own deadline on a 503. A refresh
  whose connection drops or is swapped is tried once on a new connection.
- **Task 9 (`certstatus`; 8a9a11d, 6521fd2, df78f0b).** Retries back off from 30s again after a
  recovery (the plan's code waited a full `refresh_interval`). OCSP signatures are verified by hand,
  so an intermediate's own embedded certificate works. A list with no `NextUpdate` is fresh for
  `refresh_interval` from its `ThisUpdate`, not from its load. An empty chain is Unknown. From the
  review: the whole OCSP CertID is matched (name hash, key hash and serial); SHA-1 signatures on
  CRLs and OCSP are refused (controller ruling; SHA-1 stays allowed as the CertID hash); a caller
  hanging up never poisons the shared OCSP answer; a CRL must name `issuer_file`'s subject byte for
  byte, and says so when the names differ only in encoding; a CRL dated more than 5m ahead is
  refused.
- **Task 10 (refusals and marks; a726c33, 152aab3).** The queued revocation runs after the 401 is
  written, so the client reads its answer before the connection closes. A standing mark makes a
  replayed CRL entry a no-op. A refusal while queued is queued once. The status check and the mark
  check are decided under `bind`'s one lock (a mark wins over a 503). The `allow` line is limited
  per class of failure, so no responder text keys it. The agent's 503 message no longer repeats
  itself.
- **Task 11 (port49d; 56839bb, 4cf1945, 68d86e3).** The `Checker` is built in `cmd/port49d`, not
  on `config.CertificateStatusConfig`: config → certstatus → inventory (`WriteAtomic`) → config is
  an import cycle. The start line prints before the first fetch, and a list coming into force says
  `CRL <name> loaded (next update …)`. `disabled: true` beside any other key is refused. An
  `issuer_file` must be a CA; an OCSP `responder` must be http(s).
- **Task 12 (lab; e13250d, 4bd3100, 6dece62, 1330674, ec50053, 52a81e7, d73ca51, 6791b73).** The
  vSRX prompt is `srx1`, its configured host-name, not its node name; the harness waited for the
  wrong one (ec50053). NX-OS ran at 4bd3100 and vJunos-router's session run at 6dece62, the rest at
  ec50053; the commits between change only how the test reads and writes notes. The step 7 and 8
  refresh quotes in the session notes are rebuilt from the recorded cells and marked so; the
  harness now keeps the raw refresh output (`tests/lab/evidence/session-refresh-<platform>.txt`).
- **Task 13 (38c43fd, caffec6, 0b09d54, and this section).** `cisco_iosxe` alone joins
  `ceilingWarningOn`. L34 closes; L2 stays open, its N9Kv clause corrected (rule 4). §5.6 and
  decision 33 say what L34 found.
- **Final review and fix wave.** The final review (`final-review.md`) found one important issue: a
  login token outlived its session ceiling, so a token minted just before the ceiling opened a Junos
  shell just after it, which ran until logout (decision 21). The fix wave clamps a token's expiry to
  its ceiling at mint and refuses a token past its ceiling at redeem, FAIL `session_expired` (§5.6,
  §5.7, decision 33). From its minors: no test failure message prints a token (`api.MintItem`,
  `token.Result` and `store.Token` print with their tokens withheld); a session refresh no longer
  moves `port49_context_refreshes_total`, and its "still changing" line says to run `port49
  refresh` again; a policy refresh keeps its blob as long as the context; `port49 refresh` says
  `revoked, not extended (see 'port49 revoke --list' and the refresh record)`; a CRL's first load
  is told in bulk, and the queue line reads "N CRL entries are being checked against what is in
  use"; `session.Manager.Refresh` takes a grace cutoff and never resumes a context past it. Handed
  to it and done: `Mint` refuses a finite ceiling with a zero `AuthTime` (Task 3 M-3), the stale
  comment on `TestARefreshIsRateLimited`, and the over-long lines and §17 wording from Task 13's
  re-review. The re-review said MERGE with nothing open; merged 2026-10-02 (PR #21, merge
  513e4bd). The ten raw captures were copied into main's `tests/lab/captures/` after the merge,
  and `make test` (with the labpcap audit) passes on main.

**Rulings, as made** (spec §13, decision 33; the plan's twelve rulings): all stand. Ruling 4's
allow-list holds `cisco_iosxe` alone, from L34. Ruling 6 is amended by Task 7 (an expired nonce is
not paced) and Task 8 (`port49 login` refreshes only its own agent). Ruling 9 is amended by Task 9:
SHA-1 signatures are never trusted, the whole CertID is matched, and a CRL's issuer name must equal
`issuer_file`'s subject byte for byte.

**D-7b-1** (refuse or allow when status cannot be established; certificate status required):
**answered 2026-10-02, as ruled**: `refuse` by default, `allow` available, the key required with
`disabled: true` as the opt-out.

**Lab (Task 12)**, all five images on beehive, 2026-10-01 (`tests/lab/results/L34-*.md`, `L2-*.md`,
`session-*.md`; captures `tests/lab/evidence/session-<platform>.pcap`):

- **IOS-XE 17.13.01a.** L34: the warning shown before the prompt at login and with `show version`'s
  output, inside a 2m warning window; still a permit. L2: a denial shown in full, 64–1000 bytes.
  Session: the ceiling denial, the grace-window refresh that resumed, and "session ended" after it,
  each printed as port49 wrote it.
- **vEOS-lab 4.31.2F (image tagged 4.32.2F).** L34: not shown; still a permit. L2: shown in full,
  64–1000 bytes. Session: as IOS-XE, each message after the device's `% Authorization denied for
  command …:`.
- **NX-OS 10.4(2)F.** L34: not shown; still a permit. L2: never shown. Session: the ceiling and
  the end were enforced, and the device printed only `Error: AAA authorization failed
  AAA_AUTHOR_STATUS_METHOD=16(0x10)`.
- **vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15.** L34: not shown at login; no command reply exists.
  L2: not measurable; a session denial shows nothing and does not stop the login. Session: `show
  version` ran past the ceiling and past the grace window (decision 21); the refresh said "not
  reached: the device keeps its own session", and past the window "past the grace window, not
  resumed".
- Every image: `port49 token` printed its stderr warning inside the window.

**Operator notes** (for the pull request body and plan 13's docs; the plan's "Operator-facing
notes", amended):

- **Breaking: `broker.certificate_status` is required** whenever a broker is configured. To choose
  not to check, write `disabled: true` and nothing else beside it; any other key next to it is
  refused. port49d says it is disabled at every start.
- **What to name.** Your CA's CRLs (`file:` or `url:`), each with `issuer_file:`, the CA
  certificate that signs it, which must be your `client_ca_file` anchor or signed by it. Add an
  OCSP `responder` (or `use_aia: true`) if you have one, with `hash: sha1` for a responder that
  knows no SHA-256 CertID.
  - `issuer_file` must be the CA certificate itself, the one your clients chain to. A re-issued copy
    of it (same key, another certificate) does not match: every certificate under it has an
    unknown status, refused `503` under the default `on_unavailable: refuse`.
  - The CRL's issuer name must be byte for byte your CA certificate's subject. A CRL whose issuer
    is the same name encoded differently (UTF8String for PrintableString) is refused, and the
    message says so; the CA must encode its CRL issuer as its certificate's subject.
  - An intermediate CA: also name the root's CRL (`issuer_file` = your `client_ca_file`), or an
    OCSP responder the root signs for. port49d checks each CA in the chain and says at start when
    nothing covers one.
  - Keep `client_ca_file` and each `issuer_file` root-owned and not group- or other-writable.
    port49d does not check this yet.
- **What is never trusted.** A CRL that does not verify against its `issuer_file`, or one that is
  scoped (partitioned, delta, an unknown critical extension), is never used; watch
  `port49_crl_loads_total{outcome="refused"}`. A CRL or OCSP answer signed with SHA-1 is not
  trusted: the status is unknown ("signed with … SHA1, which port49 does not trust"), with no
  override. SHA-1 is accepted only as the OCSP CertID hash.
- **What is refused and what is marked.** A certificate a CRL or OCSP revokes, or one under a
  revoked issuing CA, is refused at login, mint and refresh. If it still holds something (a
  connection, a device session, an unspent token), port49d revokes it as `port49 revoke --cert`
  would: `port49 revoke --list` shows origin `crl <name>`. A `certificateHold` entry is refused
  while listed and never marked. Lift a CRL-origin mark only after the CA delists the certificate:
  while it is listed, the mark comes back at the next restart or the certificate's next use.
- **`on_unavailable: refuse` (the default; D-7b-1, confirmed).** A CRL past its next update, or an OCSP
  responder down, answers new logins, mints and refreshes for that issuer `503
  certificate_status_unavailable` with `Retry-After: 60`, recorded `<event> deny
  trust_domain_unresolved`. No agent session ends, live device sessions run to their ceiling, and
  break-glass is unaffected. `allow` keeps logins working through an outage and lets a certificate
  revoked during it in until the CRL returns.
- **Loading.** At first start a `url:` source says `CRL <name> (not loaded yet)` until its first
  fetch; that is normal. A list coming into force, or recovering, says `CRL <name> loaded (next
  update …)`. A failed load is retried from 30s with backoff. Verified lists are kept beside
  `revocations_file` (`crl-<name>.der`) and serve across a restart until their next update; back
  them up with it. Alert on `time() - port49_crl_next_update_timestamp_seconds > -3600` and on
  `port49_cert_status_unavailable_total`.
- **New: `max_session_age` per role.** A duration (at least `1m`) or `never`. A session on a device
  ends at the least of its roles' (a role naming none takes `session.max_session_age_default`), and
  `port49 explain` shows it. Shortening a role reaches live sessions at the next policy refresh;
  lengthening it, or `never`, at each operator's next `port49 refresh` or login.
- **New: `port49 refresh`.** It re-authenticates on your held broker connection and extends every
  live device session your policy still grants: no reconnect, and the candidate configuration stays
  intact. It prints one line per device: extended to when, revoked (`revoked, not extended (see
  'port49 revoke --list' and the refresh record)`: the policy, a revocation mark or a broker fault),
  past the grace window (log in again there), not extended this time (run it again), or not reached
  (Junos keeps its own session). One refresh per connection per 10s.
  - `port49 login` with an agent already running for the same broker and certificate says
    `port49: already logged in to <broker>; refreshing` and refreshes. With another broker or
    certificate it exits 1 naming the running agent's broker.
  - With today's PEM key files a refresh proves you hold the key file, not that you are at the
    keyboard; a script running `port49 refresh` in a loop keeps sessions alive indefinitely. Keep
    key files readable only by their owner; a hardware key (plan 9) adds the touch.
- **The warning.** Within `session.ceiling_warning` (default 30m) of the end:
  - On IOS-XE port49 adds `port49: session ends in Nm - run 'port49 refresh'` to every permitted
    reply in that window. The lab (a 2m window) saw IOS-XE print it before the prompt at login and
    with `show version`'s output, so a script that reads command output on IOS-XE should expect
    that line near a session's end.
  - EOS, NX-OS and Junos show nothing (L34). There, `port49 token` is the warning: `port49: your
    session on <device> ends at <time> (in Nm); run 'port49 refresh'` on stderr, `--json` included.
    It does so on every platform.
  - `session.ceiling_warning_platforms` adds a platform at your own risk (unmeasured). A platform
    variant is listed by its own name. `0s` turns the server_msg warning off.
- **Past the end.** Commands are refused `session expired - run 'port49 refresh' (or 'port49
  login') within Nm to resume` for `session.grace_window` (default 10m), and a refresh in that
  window resumes them. After it the session is deleted: `session ended - get a new token ('port49
  token') and log in again`. NX-OS prints only its own `Error: AAA authorization failed`, with no
  hint to refresh. Junos keeps its session past the ceiling and the grace window (decision 21):
  close it on the device.
- **A token ends at the ceiling.** A token expires at `token_ttl` or at the device's session
  ceiling, whichever is first; `port49 token --json`'s `expires_at` shows which. A login with a
  token past its ceiling fails on every platform (`redeem deny session_expired`), Junos included:
  run `port49 refresh`, then `port49 token` again.
- **Clocks.** CRL and OCSP freshness follow port49d's clock, so an NTP step forward can make a fresh
  list stale. `port49 token`'s warning follows the laptop's clock.
- **New metrics.** `port49_broker_connection_events_total{event}` gains `status_unavailable_refused`
  (`revoked_refused` stays for revoked certificates and principals, so a CA outage does not read as
  revocations); `port49_session_refreshes_total{outcome}` (`extended`, `revoked`, `past_grace`,
  `not_judged`, `refused`, `store_error`, `too_soon`); `port49_ceiling_warnings_total`;
  `port49_cert_status_checks_total{source,result}`; `port49_crl_loads_total{crl,outcome}`;
  `port49_crl_next_update_timestamp_seconds{crl}`; `port49_cert_status_unavailable_total`.
- **New records.** `refresh permit grants_matched` per extended session, with `auth_time` and
  `session_expires`; `refresh deny session_expired` past the grace window; `refresh deny
  trust_domain_unresolved` for a signature that did not verify or a status not established; `refresh
  deny credential_revoked`; `refresh deny store_unavailable`; `mint deny session_expired` per device
  already past its ceiling; `mint deny trust_domain_unresolved`; `redeem deny session_expired`, with
  `session.session_expires`, for a login with a token past its ceiling; `unreached: true` on refresh
  records for session-only platforms.
- **API.** `POST /v1/refresh/challenge` and `POST /v1/refresh`, on the held connection only, with
  `refresh_challenge_missing` (401) and `refresh_too_soon` (429); `503
  certificate_status_unavailable` with `Retry-After`; `GET /v1/config` gains
  `ceiling_warning_seconds`; mint items gain `session_expires_at`, and a `session_expired` item
  carries a detail.

**Unassigned follow-ups:**

- Fence `client_ca_file` and every `issuer_file` together (owner, no group or other write), as
  `policy_file` is fenced. Fencing `issuer_file` alone buys nothing: a swapped file fails closed.
- `Checker` lives in `cmd/port49d` because of the import cycle above; moving `inventory.WriteAtomic`
  to a leaf package would let it return to `config`.

**After the merge:** copy the ten raw captures from the feature worktree's `tests/lab/captures/`
(archived at `/mnt/images/port49-captures-7b-t12-2026-10-01/`) into main's, or main's labpcap
audit fails.

**Carried, for later plans:**

- **7c:** the HTTP revocation, and `api:` rights over `RefreshSession`'s self-only rule. Also from 7a (Ryan, 2026-10-02): an empty or missing revocations volume requires an explicit one-time init (`port49d init-revocations` or similar) instead of being created at start (amends decision 32).
- **7g:** the `staleness_ceiling` default and the scheduled refresh.
- **7h:** the OIDC refresh: `prompt=login`, `auth_time` from the assertion, `sid` re-indexing.
  `session.Manager.Refresh` now takes a grace cutoff (the refresh time less
  `session.grace_window`) and refuses a zero one.
- **9:** the hardware key's touch on refresh, and a PKCS#1 v1.5 mapping for tokens without PSS.
- **12:** the Junos `idle-timeout` classes rendered from a per-role ceiling rather than the default,
  and `port49 policy diff` reporting a changed ceiling (pre-flight M11).

### Plan 7c — As built

Executed 2026-10-02 on `feature/api-and-authorization` (base 7c0ce7c), fourteen tasks, each
reviewed per task; the ledger is
`.superpowers/sdd/2026-10-02-07c-api-and-authorization/progress.md`, with each task's brief,
report and review beside it. A pre-flight review revised the plan first
(nine important and twenty minor, fixed at 7c0ce7c); one further ruling came out of the conflict
scan (M14's side effect, below). What differs from the plan's text, task by task:

- **Task 1 (docs; a65aedd, 28c3832, 6c89938).** The conflict scan's ruling went into decision 34
  and §5.1.3 both: the net exemption counts only devices the inventory held before the reload, so
  padding the inventory cannot pass the guard. From the review: §12's admin-socket `port49 revoke`
  states its exit codes (0 done; 1 not in force, or no answer; 3 in force but unfinished or
  unsaved; 2 usage), and the HTTP forms spell out the same four; §10's policy-reload bound counts
  new refusals and new quarantines together; §5.1.4 says a retransmission after a
  self-revocation is answered `token_not_found` (the plan says `token_spent` at its lines 177,
  681 and 3264; the code, the spec and the tests say `token_not_found`, ruling I3-carry); §14 says
  nine decision events, and its replay agreement checks only a principal or certificate `revoke`.
- **Task 2 (init-revocations; bc0e90f, e413948, 65c817a, 6bd75ba, ca4c215, 088fc57).** Three
  drifts from the plan's text, each in spec §12 and decision 32 (088fc57):
  - **File before marker.** Init writes the empty file, then its marker (the plan says the marker
    first). A crash between the two leaves a file with no marker, which the next start loads and
    marks; the reverse order would leave a false "revocations were lost".
  - **A relative path is refused**, exit 1 (the plan says it warns): it would resolve against the
    shell's directory, not port49d's. A start still takes a relative path, as before.
  - **A raced init says so**: a file that appears while init runs is refused, exit 1, "another
    init-revocations is running or has just run; nothing written".
  - A directory root owns, asked by anyone else, gets "if a volume should be mounted there, it is
    not; mount it", never a `sudo -u root` line (e413948). The lab harness writes
    `{"revocations": []}` only when no file is there, so it never truncates one a running port49d
    holds (ca4c215).
- **Task 3 (vocabulary; 5010a3f, ed06f3d).** As planned. `HasRight`'s test pins a misspelt right,
  an empty one, an unknown one and a group subject, each refused.
- **Task 4 (`/v1/identity`; e9a9c73, d524ecd).** `refuseRevoked`, left with no caller, was folded
  into `refuseRevokedAs`. A test pins that identity lists only unexpired grants.
- **Task 5 (`/healthz`, `/readyz`; 7252a2c, 3a43135).** The test mints on a store that fails and
  sees `503 store_unavailable` while `/readyz` stays `200 serving`, and runs both probes over a nil
  store. `TestRunAnswersDrainingBeforeTheBrokerCloses` pins `503 draining` on the broker listener
  before shutdown. The probes are HTTPS on `broker.listen` with no client certificate, separate
  from the TACACS+ `/readyz` on the metrics listener (review note, operator notes below).
- **Task 6 (`store.DeleteToken`; dcfc675, 477217a, d3daca6, 7c88ca6).** Controller ruling: it keeps
  7a's token index entries. The index maps a principal to a `(device, username)` key, not to a
  token, so pruning could hide a second live token under the same key from a revocation; a stale
  entry costs one `DeleteTokens` on that key. A new property, `DeleteTokenRacesRedeem`, races it
  against a redeem and a put, 200 rounds, with no resurrection.
- **Task 7 (`RevokeOwn`, `RevokeKey`; 72972e6, 44fb23e).** `RevokeKey` deletes the receipts of every
  owner it read across its two passes, not only the last (kept by the review). A key where nothing
  was found says so. `RevokeOwn`'s comment says `token_not_found`, as above.
- **Task 8 (`POST /v1/tokens/revoke`; 4409fc2, 9f22972, 6753049).** Controller ruling (from Task 7
  M4): one self or key revocation in flight per caller principal (`holdOwnRevoke`); a second is
  `503 revocation_busy` at once, with `Retry-After: 5`, nothing revoked and no record (spec
  §5.1.4, design §17, 9f22972). Trailing bytes after the body are 400. A mark that cannot be
  written is `503 store_unavailable` with `Retry-After: 10`, and its text says what to do with no
  `admin_socket` (remove the grants from `broker.policy_file`) or with one (the socket's path).
- **Task 9 (`POST /v1/explain`; c810410, 384aabe, d701522).** The review found a timing oracle: the
  hidden values were worked out before the no-grant check, 1.14 ms against 28 ns, so an unknown
  device could be told from a known one with no grant. They are now worked out after it and
  memoized per policy; the remaining gap (380 ns against 27 ns) cannot be told apart over HTTP.
  Beyond the brief: `RenderWithoutAttributes`, so a session explain never returns attributes; a
  revoked target is answered from the mark, without reading the policy; a policy fault writes the
  `explain` record with `mint_error: broker_error`; a body over 16 KiB is 400.
- **Task 10 (the reload guard; 604eade, 83ea48e, d0b0cbb, 82099cd, 6b91cd8).** Four rulings from
  two review rounds, each in §5.1.3, §10 and decision 34:
  - **A combined reload is judged on its policy's effect** (I1): against the policy in force over
    the new inventory, so an inventory change's own quarantines stay decision 20's; a policy in
    force that does not parse over the new inventory counts every device (fail closed).
  - **The numerator counts only devices in service under the policy in force** (I2).
  - **A release never offsets a refusal** (M1): newly refused devices over the bound are refused
    whatever the reload releases, since a refusal deletes tokens a revert does not bring back.
  - **That refusal bound is plan 6a's**, over the devices admitted, quarantined ones included
    (R1), so a policy that refuses quarantined devices is still bounded.
  - Shares print rounded up, so 1 of 3 prints 34% (M2, R2, `CheckFrom` too). The restart warning
    is added only to a bound's refusal, not to the admit-none one, which a start also refuses.
  - The L31 harness edit (`max_removed_percent: 100` in its quarantined phase) was only checked by
    `go vet -tags lab`, not run in the lab; the next L31 run confirms it.
- **Task 11 (the agent; b7560c6, d6f9070).** Every coded 503 (`revocation_busy`,
  `store_unavailable`, `certificate_status_unavailable`) becomes an `agent.APIError` carrying its
  code, detail and `RetryAfter`, and reaches the CLI as `…; retry in Ns`; the plan's
  `unavailable` path would have turned `revocation_busy` into a 502. A broker 410 relayed through
  the socket is clamped to 502, since 410 is the agent's own session end. A broker 404 with no API
  code is `not_supported`, naming the broker as older. The socket refuses trailing data. Mint and
  refresh are unchanged.
- **Task 12 (the CLI; 7c6368d, 5c2025e).** Controller rulings: a terminal is detected by the
  `TCGETS` ioctl on Linux (`golang.org/x/sys` becomes a direct dependency), not by
  `ModeCharDevice`, under which `/dev/null` counts as a terminal and a cron job would be asked
  `[y/N]`, read EOF and revoke nothing; other systems keep the mode check. The question names the
  principal; the subject is printed on the `target:` line after the broker answers, since it is
  not known before. `--yes` outside `--via-agent --principal`, and `--socket` in an agent form, are
  usage errors (exit 2).
- **Task 13 (lab; 0529b92, 1af6f72, 9bfb710, 4a6a769).** All four images pass, run at 9bfb710.
  From the review: a row for the re-login session's next command after the key revocation, the
  Junos rows worded as measured, and the reach of the key and principal reports checked both ways.
- **Task 14 (this section).** No lab note contradicts §5.1.4's "Over HTTP, as built" or decision 34,
  so no doc is corrected under lab rule 4. Spec §10's reload-bound paragraphs, over-wide since
  d0b0cbb, are rewrapped.
- **Final review (b5e0317, 8ea6131, 5590f4b, and the docs after them).** I1: the agent waited 30 s
  on a revocation and resent it on any transport failure, so a slow store turned a mark that
  stood into `revocation_busy`, "nothing was revoked". It now waits past the broker's worst case
  (`api.RevokeSlotWait` + `admin.OpTimeout` + `admin.PersistTimeout` + 10 s), never resends a
  revocation once its writing began, and says an unanswered one may be in force. M1: `--mine`
  with a key reads only the caller's own indexes, so its time says nothing of another's session.
  M2: naming your own principal says first that no mark was made. M4: `/readyz`'s `503
  starting` is not seen in practice (below). M5: design §17 lists explain's `500 broker_error`.
  M3 is carried: spec §5.7 says a mark that could not be written writes no `revoke` record, and a
  record for it is a spec change, not a fix.

**Rulings, as made** (spec §13, decision 34; the plan's ten rulings): Rulings 1, 5 and 7 stand as
written. Ruling 2 stands, its retransmission answered `token_not_found` (I3-carry). Ruling 3 gains
the per-caller bound on self and key revocations (Task 8). Ruling 4 stands, with one exception
made in Task 8: neither busy answer writes a record. Ruling 6 gains: session attributes are never
returned, and a no-grant answer works out nothing a granted one does (Task 9). Ruling 8 is
amended by the conflict scan (padding never offsets) and by Task 10's I1, I2, M1 and R1 above.
Ruling 9 is amended by Task 2: the file before the marker, a relative path refused, a raced init
refused. Ruling 10 stands: no register row opens or closes.

**Lab (Task 13)**, four images on beehive, 2026-10-02, run at 9bfb710
(`tests/lab/results/api-revoke-*.md`; captures `tests/lab/evidence/api-revoke-<platform>.pcap`,
the redacted copies passing the labpcap audit on the branch). On every image: carol, with no right,
was refused 403 by principal and by key, and alice's next command ran; `--mine`'s unspent token
was refused `token_not_found`, the agent kept running, and a token minted after it logged in at
once; bob's key revocation ended alice's re-login, and she logged in again at once; bob's
principal revocation was listed `api user:bob@slice.port49.test`, ended alice's agent on `401
credential_revoked`, and a lift on the admin socket let her back; all six `revoke` records (by
`self`, `key`, `principal` × reason) were written.

- **vEOS-lab 4.31.2F (image tagged 4.32.2F)** (`api-revoke-arista_eos.md`). `--mine` and the key
  revocation each refused the next command: `% Authorization denied for command 'show version':
  port49: this session was revoked - log in again`. Pre-flight I1, measured: the session `--mine`
  refused ran `show version` again after alice's re-login (decision 15's join).
- **N9Kv 10.4(2)F** (`api-revoke-cisco_nxos.md`). As vEOS; the device printed only `Error: AAA
  authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`. I1 re-admission measured.
- **C8000V 17.13.01a** (`api-revoke-cisco_iosxe.md`). As vEOS; the device printed `port49: this
  session was revoked - log in again`. I1 re-admission measured.
- **vJunos-router 23.4R2-S2.1** (`api-revoke-juniper_vjunos-router.md`). Not reached per command,
  as 7a found: every open session ran `show version` throughout, and the `--mine`, key and
  principal reports each named `srx1 (slice01)` not reached. The re-admission is not observable
  there. The capture is 1768 packets against the first run's 568: the device and SSH client
  retried TACACS+ around the refused old-token login (task 13 review M5); no claim rests on the
  count.

**Operator notes** (for the pull request body and plan 13's docs; the plan's "Operator-facing
notes", amended by what was built):

- **Breaking: port49d no longer creates `broker.revocations_file`.**
  - **First install.** Run, once, as the user port49d runs as (the owner of the file's directory):

    ```
    sudo -u port49 port49d init-revocations --config /etc/port49/port49d.yaml
    ```

    The subcommand comes first (`port49d --config X init-revocations` is a usage error, exit 2).
    It reads only `broker.revocations_file` from the config, so no secret needs to be in the
    environment, and it refuses a path that is another file port49d uses. It prints `port49d:
    created broker.revocations_file <path> with no revocations, and its marker <path>; …` and
    exits 0.
  - **What its exit 1 means.**
    - `… belongs to <user>, and this runs as uid N: … run as <user>, e.g. sudo -u <user> port49d
      init-revocations --config <cfg>`: run it as that user. Root is refused too: a root-written
      0600 file is one port49d cannot read. It never chowns.
    - `… belongs to root, and this runs as uid N: if a volume should be mounted there, it is not;
      mount it`: the volume did not mount, or the directory must be given to port49d's user.
    - `broker.revocations_file "<p>" is relative: it must be absolute`: give an absolute path in
      `port49d.yaml`. A start still accepts a relative one, resolved against port49d's working
      directory (`/` under systemd unless `WorkingDirectory=` is set).
    - `… exists and does not load (…); init never replaces it`: restore it, or fix it by hand.
    - `… is missing, and its marker <path> says port49d held revocations here: init never
      re-creates a lost file`: restore it from backup (below).
    - `… appeared while this ran: another init-revocations is running or has just run; nothing
      written`: run it once more to see `already initialized`.
  - **Once, at install, never on a start path.** By hand or as a one-off job. Never in an init
    container or an `ExecStartPre=`: wrapped to tolerate its refusal there, it would re-create the
    file on the next empty volume, the hazard this change removes. Run again, it prints `…is
    already initialized; nothing written` and exits 0, so an idempotent provisioning step needs no
    `|| true`.
  - **What a start does.** A missing file refuses every start: `broker.revocations_file <path>:
    does not exist: if port49d has run here before, the volume holding it is missing or empty:
    mount it or restore the file; only on a first install, run 'port49d init-revocations' once,
    as port49d's user, with the same --config`.
    So an unmounted or empty volume never starts port49d with no revocations.
  - **Upgrading.** An install that already has the file changes nothing; a start writes the marker
    beside it if it has none.
  - **After a loss.** Restore the file from backup. With its marker there, a start says `is
    missing, and its marker says port49d held revocations here`. Writing `{"revocations": []}` by
    hand (0600, port49d's user) is the deliberate way to start empty.
- **Upgrade: agents and brokers older than this release.** An agent lives for `max_session_age`,
  and one started by the old `port49` has no `identity`, `explain` or `revoke` route; the new CLI
  says ``your agent (started before this port49) does not carry this command; run `port49
  login` again``. A new CLI against an old port49d gets `not_supported: the broker at <url> does
  not serve /v1/…: it runs a port49d older than this port49`.
- **New: `port49 identity [--json] [--socket PATH]`.** It prints whom the broker resolves you to:
  principal, subject, groups, unexpired grants by scope, `api:` rights, and until when this
  connection lasts (`connection_ends_at`, from `max_session_age` at authentication); a device's
  own session ceiling may end a session sooner. `--json` prints the broker's answer. Exit 0, or 1
  with `no agent at <socket>; run 'port49 login'` or the broker's refusal. Each call writes an
  `identity` record, so do not put it in a shell prompt.
- **New: `port49 explain --device D [--command "LINE"] [--principal P]`**, with no
  `--policy`/`--inventory`.
  - **What it does.** It asks the broker through your agent, from the policy in force, and prints
    what the offline form prints, redacted, with no session attributes. For a denied command it
    names every role in the policy whose permits would match (what to ask for), never who holds
    one. A device the inventory lacks is answered exactly as one with no grant.
  - **Another principal.** `--principal` naming someone else needs `api: [explain_others]`;
    without it: `refused: explaining another principal needs the api: explain_others right`, exit
    1.
  - **Offline only.** `--subject` and `--show-attributes` are usage errors (exit 2) over the
    broker.
  - **Dashboards.** `explain` records carry hypothetical verdicts: a panel of denials, or of
    `port49_decisions_total{verdict="deny"}`, should filter `event!="explain"`.
- **New: `port49 revoke --mine [--device D --username U]`.**
  - **What it does.** It ends your own live sessions and deletes your unspent tokens (one device
    with `--device` and `--username`), and your receipts everywhere, so a client retransmitting a
    spent token anywhere is refused `token_not_found`.
  - **No lock.** It leaves no mark and closes no agent: `port49 token` and a login work at once
    after it (measured on four images). Use it when a token leaked.
  - **Close a stranger's session first.** Your next login on a device re-admits every session open
    there under your username, a stranger's on your leaked token included (measured on vEOS, the
    N9Kv and the C8000V). If anyone else used your token, close their session on the device, or
    ask an operator to revoke your principal, before you log in there again. The report says so.
  - **Junos sessions** keep what they had at login and are named `not reached` in the report;
    close them on the device.
- **New: `port49 revoke --via-agent --principal P [--yes]`** (needs `api: [revoke_others]`).
  - **What it does.** The admin socket's standing mark, from your laptop, through your agent. On a
    terminal it asks `revoke P everywhere? It is a standing mark: … [y/N]` first; anything but `y`
    or `yes`, EOF included, exits 1 with `nothing was revoked`. `--yes` skips the question, and is
    a usage error with any other form. Off a terminal (cron, `</dev/null`) it does not ask. It then
    prints `target: P (subject S)`, or `(no subject in the policy in force names it)`, so a typo of
    a real colleague's address is seen at once.
  - **Your own principal makes no mark.** Named as P, it is `--mine`: your sessions end, and
    nothing stands against you. The report's first line says `this is your own principal: no mark
    was made; to lock it, ask an operator to use port49d's admin socket (<path>)`. If your own
    certificate leaked, that is the step: an operator runs `port49 revoke --principal P` there.
  - **The record.** `port49 revoke --list` and the `revoke` record name you as `origin: api <you>`.
  - **Lifting** stays the admin socket's, as does `--cert`; the report names the socket. With no
    `admin_socket` configured, the mark is still made, and the report and port49d's start line
    (`port49d: broker: no admin_socket: …`) say lifting it needs port49d stopped, the entry
    removed from `broker.revocations_file`, and a start.
  - **Watch for a burst.** Alert on
    `rate(port49_revocations_total{by="principal",outcome=~"applied|partial"}[5m])` above your
    normal: a compromised `revoke_others` certificate can mark every human. Revoke that
    certificate on the admin socket, then lift the marks it made during the burst, and only those:
    a mark the same principal made before the compromise (a departed employee, a leaked
    principal) is legitimate and must stay. Until a bulk lift exists:
    - Read `port49 revoke --list` first, and find when the burst began, from the alert or the
      `revoke` records (`origin: api user:oncall@example.com`).
    - Set `t` to just before it, in UTC as `--list` prints it. The filter keeps only marks at or
      after `t` (`$4` is the `since` time; RFC 3339 in UTC compares as text).
    - Run it on port49d's host, as port49d's user or root: `--list` and `--lift` are the admin
      socket's.

    ```
    port49 revoke --list | awk -v t=2026-10-02T03:00:00Z \
      '$1 == "principal" && $4 >= t && /\(api user:oncall@example\.com\)$/ {print $2}' |
      while read -r p; do port49 revoke --lift --principal "$p"; done
    ```
- **New: `port49 revoke --via-agent --device D --username U`** (needs `api: [revoke_others]`).
  - **What it does.** It ends whatever holds that key, with no mark, so the owner can log in again;
    revoke the principal to stop that. It prints `target:` with the owner it found. The owner's
    next login there re-admits any session still open on it: close it on the device. A key where
    nothing was found says `nothing was found under D (U)`.
  - **Without the right** it is refused 403, never narrowed to your own sessions there: `refused:
    ending a (device, username) whoever holds it needs the api: revoke_others right, …; for your
    own session there, use --mine --device D --username U`, exit 1.
  - **Not in `--list`.** A self or key revocation leaves no mark; `--list` says so on stderr, and
    the decision log's `revoke` records (`revocation.by` `self` or `key`) name each.
- **What the agent forms exit with, and what each error means.** 0 done; 1 refused, unreachable
  (nothing revoked) or unanswered (it may be in force, below); 3 in force but incomplete, or a
  standing mark not saved; 2 usage. Over the
  agent `--agent-socket` names your agent; `--socket` (port49d's admin socket) is a usage error
  there.
  - `refused: revoking another principal needs the api: revoke_others right`: your subject does
    not declare it. Ask for it, or ask an operator to use the admin socket.
  - ``the broker at <url> did not answer the revocation (…); it may be in force — check `port49
    revoke --list` (on port49d's host) and port49d's log before retrying``: the request was sent
    and no answer came within the broker's worst case (85 s: the 10 s wait for the slot, the 60 s
    run, the 5 s save, a margin), or the connection dropped after it was sent. The agent never
    sends a revocation twice. For `--mine` or a key it says `it may have run — check port49d's
    decision log (event revoke)`, since neither leaves a mark for `--list`. `your agent at
    <socket> did not answer …` is the same for an agent that dropped the request. Look before you
    run it again: a second run behind a slow first one is `revocation_busy`.
  - `the broker is unavailable just now: revocation_busy: …; retry in 5s`: another revocation or
    lift held the slot for 10 s, or your own `--mine` or key revocation is still running. This
    request revoked nothing. If an earlier run of yours went unanswered, it may be the one
    running: check as above before you run it again.
  - `the broker is unavailable just now: store_unavailable: the revocation could not be recorded,
    so nothing was revoked; …; retry in 10s`: the store refused the mark. Retry; the text names
    the admin socket, or, with none configured, says to remove the principal's grants from
    `broker.policy_file` meanwhile.
  - `no agent at <socket>; run 'port49 login'`, and the session-over lines, as for `port49 token`.
- **`api:` rights now mean something.**
  - **What they unlock.** `revoke_others` and `explain_others` act on other people. `sync`,
    `keys_show` and `replay` are reserved and grant nothing yet.
  - **What no right does.** No right lets anyone mint or refresh for another principal.
  - **The gate.** A right gained fails `port49 policy diff` unless a test asserts the subject's
    whole `api:` list, as before. Every subject with `api:` is in the CI report.
- **New: the policy reload guard.**
  - **What is refused.** A policy edit that would take more than `inventory.max_removed_percent`
    (default 10) of the devices in service out of service, by refusing admission or by
    quarantining, is refused. So is one that newly refuses admission to more than that share of the
    devices admitted, whatever it releases elsewhere. `port49_policy_file_refused` goes to 1, and
    the policy in force keeps serving. The line names each device and cause, redacted, with the
    share rounded up (`the new policy takes 5 of 20 devices in service out of it (25%), more than
    inventory.max_removed_percent (10%): …`).
  - **The refused file is still on disk.** The line ends `the refused file is still on disk and is
    NOT what is serving: a restart of port49d would load it with no such bound, so revert or fix
    it now`. A pod rescheduled, a crash or the next deploy loads it and takes those devices out of
    service. Revert or fix it at once.
  - **A combined policy-and-inventory reload** is judged on the policy's effect alone: devices the
    inventory change moves into a quarantined scope are the inventory's, as before. When the guard
    fires on the policy, the line begins `broker.policy_file <path>:`; with both read from files,
    it ends `the refused files are still on disk …`.
  - **Small fleets.** One quarantined device of three is 34%. Raise the bound and send `SIGHUP`
    for a deliberate change, then lower it again: the same bound holds inventory syncs.
  - **A refused edit keeps any grant it withdrew.** `port49 revoke` cuts a principal off whatever
    the file says.
  - **What is never refused** on the combined count: a reload after which at least as many of the
    devices the inventory already held are in service as before, such as an incident fix that
    releases many and quarantines a few. Devices the same reload adds never count toward that.
- **New broker endpoints.**
  - `GET /v1/identity`, `POST /v1/explain` and `POST /v1/tokens/revoke`, each authenticated as
    `/v1/tokens` is.
  - `GET /healthz` (`200 ok`) and `GET /readyz` (`200 serving`; `503 draining: port49d is
    shutting down` from the signal on), with no certificate and no record. Before the broker
    serves there is no answer: the connection is refused until port49d binds `broker.listen`, and
    waits in the moment between the bind and serving. The code's `503 starting` is not seen in
    practice. `/readyz` stays 200 through a store outage, by design (design §12); watch the alarms
    instead.
  - **Probe them over HTTPS with no client certificate** on `broker.listen` (kubelet `scheme:
    HTTPS`). A plain-HTTP or TCP probe fails the TLS handshake and logs a `handshake_*` line and
    counts `port49_broker_tls_handshake_failures_total` every period. They are not the TACACS+
    `/readyz` on the metrics listener.
  - **New API errors:** `403 api_right_missing`; `503 revocation_busy` (`Retry-After: 5`); `400
    bad_request` for a `sid` (until plan 7h), trailing bytes, or an explain body over 16 KiB.
- **New records.**
  - `identity permit grants_matched` and `identity deny no_grants_matched`.
  - `explain <the answer>`, with `explain.asked_by` and `explain.asked_by_fingerprint`, the
    `policy.bundle` that answered, `explain.command: true` when one was asked and never the
    command; on a broker fault, `explain.mint_error: broker_error` with no verdict.
  - `revoke deny api_right_missing`, naming the target (or the key) and the caller in `origin`.
  - `revoke` with `by: self` or `by: key`, `device` and `username`, and `origin: api <principal>`;
    `saved` only on a standing mark.
  - A record about someone other than the caller carries no `auth`: `auth` and `principal` always
    describe one credential, so a join of fingerprint to principal stays true.
  - A call refused before it is read, or as its connection binds, is recorded under its own
    event, with the mint's reasons. A busy answer writes no record.
- **Metrics.** `port49_revocations_total{by}` gains `self` and `key`.
  `port49_decisions_total{event}` counts `identity` and `explain`.

**Unassigned follow-ups:**

- A bulk lift, `port49 revoke --lift --origin "api <principal>"`, so recovery from a mass
  revocation by a compromised `revoke_others` certificate is one command, not one lift per victim
  (pre-flight M19; the shell loop above until then). It takes a `--since` as well, so a lift
  never reaches a mark the same origin made before the compromise (task 14 review I1).
- `internal/agent`'s `TestAnExpiredHangUpDuringARefreshEndsTheSession` (7b code) failed once in a
  Task 10 mutation run across `./...`; 200 plain runs and 15 package runs under `-race` did not
  reproduce it. Task 11's first `make test` also reported one failure it could not attribute,
  not seen in five reruns. Watch for it.
- The next L31 run confirms the quarantined phase's reload applies under
  `max_removed_percent: 100` (Task 10's harness edit, vet-checked only).

**After the merge:** main's `tests/lab/labpcap` test fails until this branch merges: the raw
captures are already in main's `tests/lab/captures/`, and their redacted evidence arrives with the
merge. Run `make test` on main after the merge to see it pass.

**Carried, for later plans:**

- **7d:** `storetest.DeleteTokenRemovesOne` and `DeleteTokenRacesRedeem` on the etcd backend. Its
  M-2 case puts a token already expired; etcd may refuse that put, in which case use a
  clock-advancing constructor. `DeleteToken` keeps 7a's index entries (Task 6 ruling); the
  property does not assert whether a deleted token's stale entry stays, so a backend may prune it
  only where that cannot hide a second live token under the key. The self-revocation's
  compare-and-set on the backend's `SetContextPolicy`. The agent's single held connection (final
  review): a `port49 token` started behind a slow revocation (up to 85 s) still gives up at 30 s
  and says the broker is unreachable; a second connection for revocations is a design change. It
  fails safe and predates 7c, but a remote store makes it likely.
- **Spec, unassigned:** a `revoke` record for a mark that could not be written (final review M3).
  Spec §5.7 says such a mark writes none today, so only port49d's stderr shows it during a store
  outage.
- **7e:** `/healthz` and `/readyz` on the broker's own process. The revocations file's init in the
  broker's deployment, run once at install and never on a start path. A reload guard at start,
  against the last bundle in force, so a restart cannot load a file the guard refused (pre-flight
  I4). The per-caller self/key bound (`holdOwnRevoke`) and the revocation slot are per process;
  with replicas, a caller holds one per replica.
- **7g:** rights held through a group subject (`HasRight` refuses one today, pinned by ed06f3d).
- **7h:** `/v1/tokens/revoke` by `sid` (400 today); `/v1/logout`.
- **12:** the deployment's `port49d init-revocations` step: once, at install, by hand or as a
  one-off job, as port49d's user, and never in an init container or `ExecStartPre=` (a tolerated
  failure there re-creates the file on the next empty volume, the hazard decision 32's amendment
  removes); the small-fleet note on the reload guard; the guard at start, as for 7e; the broker's
  readiness probe as HTTPS with no client certificate.

### Plan 7d — As built

Executed in two merges from `2026-10-02-07d-shared-store.md`, each task reviewed. The ledger is
`.superpowers/sdd/2026-10-02-07d-shared-store/progress.md`, with each task's brief, report and
review beside it. `7d2-carries.md` records what each task handed a later one. A pre-flight review
and two re-checks revised the plan before Task 1 (ef549e4). Tasks 4b, 6b, 7b and 13b were added
during execution. 7d-1's Task 8 Step 6 section was not written at its merge, so 7d-1 is recorded
here from the ledger. What differs from the plan's text, task by task:

**7d-1** (`feature/shared-store`, base ef549e4; merged 2026-10-02, PR #24, merge fe23595):

- **Task 1 (docs; 2f37031, f371f37).** Two clauses moved to Task 8b, because only 7d-2 builds
  them: the once-per-process ledger, and "cannot lift a revocation by principal or certificate"
  holding only under the daemon's role.
- **Task 2 (the lifted suite; feed70c).** 44 subtests on memory and crypt.
- **Task 3 (`SwapLogin`, `PurgeTokens`; a7d3d89, 7eb5054).** A racing property pins the mark
  check to the write inside `SwapLogin` (review I1).
- **Task 4 (the login's one step; 8022d26, 300a222, 8f656a8, 2062739, c9d40c3).** A join that
  errors wrote a `FailReceipt`, as an interim fail-closed step. Two known-gap tests pinned a
  revoked certificate replaying PASS. 300a222's spec amendment was reverted (2062739) by
  ruling I4: the spec was right, and 4b restores it.
- **Task 4b (the seal, the ledger, the marks; 60e0ec4, b0dafc9, 909c42a, ef31e69, 5f6aa9d,
  19277e9, 98c7d9d).** Beyond the plan, a sealed `Logins` witness: the last 8
  `credential_sha256` prefixes. It is the commit proof a replay needs, which a store writer
  cannot fake. An unwitnessed replay is `token_spent`. Both known-gap tests flipped. Task 5
  found a ledger defect: under concurrent writes, "last" could be recorded out of commit
  order. It was fixed on `fix/ledger-order` and cherry-picked (0c304ad, 19a47c4).
- **Task 5 (the etcd foundation; 2fef779, 6432b92, be47fc8, 78cc867, eec9c57).**
  - `Backend.RaceRounds` per backend, and `make test-race`.
  - Race properties for `IndexToken` and `ExtendReceipt` (review I1).
  - prometheus, x/crypto and x/sys bumped.
- **Task 6 (contexts on etcd; 355c506, 78275f2, c3ba62a).** Sealed writes return their commit
  revision (c3ba62a), ahead of Task 6b.
- **Task 7 (the indexes on etcd; c78380e, 98b6999, 3f7a0d9, 749af0c, 12f9315, 98c06fe).** An
  `x/` record that does not decode no longer stops anything (review I-1, overriding the plan's
  `TestAnUndecodableIndexRecordIsAnError`):
  - a revocation over-reaches it;
  - `ActivePrincipals` and the sweep skip it and count it
    (`port49_store_index_records_undecodable_total`);
  - the sweep never deletes what it cannot decode.
- **Task 6b (new: the ledger by revision; 17fcab3, 38856a8, f2c0aee, 4bc961c).**
  - The ledger orders writes by commit revision, so two first logins on an empty key are not
    denied.
  - A regression witness stops a snapshot restore under a running port49d from admitting a
    stale record over a new session (review C1).
- **Task 7b (the re-index; ff5c3fb, d2f4a56, 4d4c531, c375955, 858f7f0, b76b703, 0fa66d9,
  2ade09f).**
  - One garbled `c/` no longer aborts the refresh: it is deleted at the revision read.
  - A rotated sid is written into the sealed record (`ContextRefresh.Sid`), so the re-index
    compares sids exactly.
  - Deleted `ip/` and `is/` lookup entries are found too.
- **Task 8 (idempotency on etcd, every property; 79dcd46, f978801, 57ef6fe, c73f05b,
  2ec6ca5).** 57 subtests each on memory, etcd and crypt-over-etcd.
- **Flakes.** Five were fixed first and merged as PR #23. One was a production fix: the refresh
  challenge retries a reset on a held connection.
- **Final review (ecec515, a9cf678, 2e3901b, bd4ae7f; docs 42ceb9a–81b9c98).**
  - F-1: an unparseable lookup entry is said, counted, skipped and swept.
  - F-2: a context under a key port49d does not hold is never revoked.
  - r-m1: a refresh that skips anything keeps `port49_policy_refresh_pending` at 1.

**7d-2** (`feature/shared-store-daemon`, base 06d0821; merged as PR #25, 9282085):

- **Task 8b (docs; ee4ff27, then 910b213, 8a49560, 41fd152, 6e43436, 707e828, 82deff5,
  f63df64, 37dbd0e, e4eb512, 1218c9a, 952d6ed, 0931755, 413f63a, 1d928e3, 90e4775,
  1751e4e).** The docs follow 7d-1's code over the plan's text. A context under a key not held
  is denied, never revoked (a9cf678), so decision 35 and the operator note say the start leaves
  it, not that it "ends" it. Four review rounds reshaped the hold:
  - `hold_ttl` is 10s to 60s, refused below 10s. clientv3's keepalive loop ticks every 500ms,
    so a healthy lease of 5–8s can report under half its TTL.
  - The fence loses an answered read only when it reports under half of `hold_ttl`, judged at
    its send. The judgement is a pure `judge`, tested by table.
  - The round trip a hold survives, to the etcd leader, is the least of three bounds:
    `call_timeout` binds at the defaults.
  - `etcdutl snapshot restore --bump-revision 1000000000 --mark-compacted` was confirmed in
    v3.6.15's source and recommended.

  Rulings T12-a, c and d came out of this review (below).
- **Task 9 (the guard; c03cc30, 3628986, 4753190, 2644adb).**
  - A caller's deadline while it waits for a slot is `saturated`, not `canceled`, so a full
    pool never reads as devices going away.
  - A caller already past its deadline is `deadline`, counts toward the circuit, and never
    reaches the store (review I1).
  - The circuit gauge is set from the pool's state under its lock.
  - An open circuit and a refused run are each told once (review M1).
  - `TestRefusalsGoDark` uses four refusals, so the gap check is pinned.
  - The etcdtest hung proxy and the cluster retry are exercised (7d-1's Task 5 review M3).
- **Task 10 (the config; c7d67c8, 74b79b9).**
  - `hold_ttl`'s floor is 10s, per Task 8b; the brief's 5s was stale.
  - An endpoint with user information, a path, a query or a fragment is refused at load,
    naming only its index. The first cut echoed the endpoint, password included (review I1).
  - Store file paths must be absolute.
  - `start_timeout: 0` decodes bare (`StartTimeoutSet` is `*zeroDuration`, not the plan's
    `*time.Duration`).
  - Every refusal carries `config: `.
- **Task 11 (identities and roles; 6377394, 38bb2ab, 86adb77, 2df619b).**
  - `CheckIdentity` also reads the daemon's own grants (`UserGet`, `RoleGet`). It refuses any
    grant on `id/`, `tp/` or `tc/`, and any write outside the nine families. The probes alone
    passed a daemon grant widened onto `rv/`, `meta/hold` or `id/` (review I1).
  - Ruling T11-a: a certificate CN of `root` is refused, at load and by `CheckIdentity`, as is
    a user holding etcd's root role.
  - An identity whose etcd user cannot be named is refused.
  - `ErrNotSeparated` reads "a store identity reaches past its role".
  - `store-roles` prints the residual, and says to check an existing role with `etcdctl role
    get` first.
- **Task 12 (port49d on etcd; 1d8cd0b, db6c12b, 5739e76, 01da5d1, 5abcd36, c1d2f65, ab106b1,
  5b459a8, c47be85, 4c37a54, 0f75e02, fb28ba4, ace3fd9, d8f8f5c, 6c3a3ff, 793df0a, 709e579,
  f054682).**
  - **Signatures the plan does not list:**
    - `guard.WrapRev`: `crypt.Wrap` takes a `store.RevStore`, so the plan's
      `crypt.Wrap(guard.Wrap(…))` did not compile;
    - `broker.ErrLeftUnderUnheldKey` and `ErrPrincipalUnvisited`, exported;
    - the process's one ledger, passed to `openStores`, `runOnce` and
      `startOnPersistentStore`, which returns `(refreshOwed, error)`;
    - the start's hold-or-open decision, the pure `startLeftBy`;
    - `reloader.startLeft`.
  - `refreshContexts` returns what it left by precedence: an unvisited principal, then a busy
    context, then an unheld key.
  - `session.mark` returns an outage over an earlier unreadable context (M-B9).
  - The plan's end-to-end tests lacked the exec session authorization; `loginSession` adds it.
  - `TestAStartSealsTheLedgerOnceItHasReadTheStore` pins where `Seal` is called (7d-1 m-7).
  - Ruling T12-e: `Hold` waits a third of `hold_ttl` after the lock.
  - From the review: `Hold` grants its lease under the caller's ctx, capped at a third of
    `hold_ttl`, and bounds its TryLock and holder write the same way. It lets go with a 1s
    bound, and says when it leaves the lease to expire.
- **Task 13 (the crypt alarm; bbf39d5, f0082bb, cf4d0b2, e95edfa, 2df6bb2).**
  - The start's warning says the sessions are denied until a start holds the key, not that
    the start ends them.
  - A key id outside `[A-Za-z0-9._-]{1,64}` prints as `?` (`crypt.LineKeyID`). Config still
    accepts such an id (spec follow-up, below).
  - Ruling T13-a: an undecodable `meta/seal_keys` is said, gauged 1 and overwritten, and the
    start goes on.
  - The check is bounded at four times `call_timeout`.
  - Ruling T13-b: the alarm is per process. It is kept across a store-gone re-entry and gauged
    while that run waits.
  - An empty key id is called corrupt.
  - One sayer serves every sealing layer, pinned by a test.
  - bbf39d5 pins 7d-1's untested change: the session refresh reports a context under an
    unheld key `not_judged`.
- **Task 13b (new, Ruling T12-g; 87c4d21, c043526, e4e32ac, f46ee39).**
  - Every context seal carries a fresh random `write_id` (form 3), and the ledger is keyed on
    it, so an earlier version of the same context put back while port49d runs is denied.
  - A form-2 record does not open: it is denied, then revoked by the refresh as tampered.
  - Ruling T13b-a: the refresh still revokes a context the ledger denies, after a restore too.
  - Review I-1: a read that raced a write of the same context is read again, up to twice
    (`Ledger.stale`), and `revokeUnopened` reads once more before it revokes. A re-index pass
    that meets the race leaves that context for the next pass.
- **Task 14 (the agent; 05cfecb, 8a9b75a, 98505fc, 92161a7).**
  - 05cfecb takes the unassigned carry: an admin-socket answer naming nothing exits 1 as
    unanswered. `admin.Response` has no `by`, so "naming nothing" is no `error` and no `text`.
  - 8a9b75a is a WIP commit, kept, from redoing `agent.go` edits that a `git checkout` lost.
  - 92161a7: a revocation behind a running one says it was not sent.
- **Task 15 (the lab; b3ce65d, b193375, 79812ef, a6ebda6, 4f62284, 0eee340, 2a340f6;
  3159dbc from 79812ef's review).**
  - **Harness fixes:**
    - replies are matched on the device port, session and sequence;
    - a redeem answered ERROR is recorded `deny store_unavailable`;
    - IB1's dark check is re-run after the settle;
    - an INVALID cell is re-measured (Ruling T15-a); none was.
  - **A code bug, fixed with a unit test in 79812ef.** After a `--bump-revision` restore, a
    login's write compared on the restored record's low revision and committed above the
    ledger's last, and the ledger dropped it. So the first login after the restore was denied
    on its own context. Design §12 was right and the code wrong (CLAUDE.md lab rule 4).
    The fix's own review hardened it in 3159dbc: such a write becomes the last only if it was
    sent after the last write ended. That closes a write whose reply came late, across two
    restores, being placed over a later write the store holds.
  - **Docs corrected by the notes (2a340f6).** The listeners close when the hold is lost, not
    after `hold_ttl`. IOS-XE refuses an open session's command once port49d is dark.
- **Task 16 (this section; the docs).** Spec §15's Junos `authorization-time-interval` note
  is now the memory store's. On etcd the store keeps the contexts across a restart, and the
  note says L35 did not measure the re-authorization. 13b's two nits are fixed: the
  `reindex.go` comment names `errReadAgain`, and a design §8 line is rewrapped. Every other
  drift a task report names was fixed in that task's own docs commits.

**Rulings, as made** (spec §13, decision 35; the plan's rulings 1–18 and OD-1):
- **Stand as written:** 1–7, 9, 13, 15, 16 and 18, and OD-1 (Go 1.26).
- **Ruling 8 (the guard)** gains Task 9's two deadline outcomes.
- **Ruling 10 (identities)** gains the grant read and the `root` refusal (T11-a).
- **Ruling 11 (the hold)** is amended:
  - by Task 8b: `hold_ttl` is 10s to 60s, and an answered read is lost under half, judged
    at its send;
  - by T12-b: one ledger per process, kept across a store gone;
  - by T12-e: a new holder waits a third of `hold_ttl` before it serves.
- **Ruling 12 (the start)** tells three outcomes apart:
  - T12-a: a context under an unheld key opens the start, and the pending gauge stays 1;
  - T12-c: a principal whose lookup failed holds the start, as an outage does;
  - T12-d: a busy context opens the start, and is retried at once.
- **Ruling 14 (the crypt alarm)** is amended:
  - the warning says denied, never ended;
  - T13-a: an undecodable seal-key record never refuses a start;
  - T13-b: the alarm is per process.
- **Ruling 17 (the seal and the ledger)** is amended:
  - T12-g: the ledger is keyed on a sealed write ID, so a runtime put-back of the same
    context is denied (Task 13b). This had been proposed for 7e; Ryan ruled to fix it now,
    2026-10-03.
  - T13b-a: a denied context is still revoked by the refresh.
  - 79812ef and 3159dbc: a write sent after the last ended, which commits above it after a
    revision bump, is the last.

The controller's rulings in 7d-1 are each in the ledger:
- C1: every mark applied at the start;
- I12 and CA1: the whole-context seal, and the token's trusted fields sealed;
- IA1, with I1's `Seal`: the ledger;
- the `Logins` witness (4b review I1);
- the exact-revision ledger and its restore witness (6b);
- an undecodable index record over-reached, never fatal (Task 7 I-1);
- the rotated sid sealed (7b);
- F-1 and F-2.

**Lab (Task 15)**, five images on beehive, 2026-10-03, run at 0eee340 from a pinned worktree with
`hold_ttl` 60s (`tests/lab/results/L35-*.md`; captures `tests/lab/evidence/L35-*.pcap`). Every
step-3 cell was valid on its first hang. With the store hung, every reply came in 500–502ms in
the capture (`call_timeout`), so `packet_deadline`'s 2s default stands.

| image | store hung: command / login | break-glass, store hung | dark after | dark: open session / break-glass | listening again; the session |
|---|---|---|---|---|---|
| vEOS-lab 4.31.2F (tagged 4.32.2F) | FAIL, port49's text / ERROR, refused | logs in; its command FAIL | 12s | runs / logs in | 56s; same `ctx_id`, permit |
| N9Kv 10.4(2)F | FAIL, AAA error / ERROR twice, refused | logs in; its command FAIL | 25s | runs / logs in | 38s; same `ctx_id`, permit |
| C8000V 17.13.01a | FAIL, prints nothing / ERROR, refused | refused (ERROR is final) | 20s | **refused `% Authorization failed.`** / logs in | 1m27s; same `ctx_id`, permit |
| vJunos-router 23.4R2-S2.1 | session runs on / ERROR, refused | logs in (`password`) | 17s | runs / logs in | 55s; runs |
| vSRX3 21.4R3.15 | session runs on / ERROR, refused | logs in (`password`) | 14s | runs / logs in | 53s; runs |

On every image a restart on the same store kept the open session, and refused a token minted
before it `token_not_found`. Listening again waits for the lost hold's lease (60s) to expire,
then a third of `hold_ttl`.

The IOS-XE dark row contradicts `quarantine-cisco_iosxe.md`, where an open session's `show
privilege` ran with port49d stopped. The two runs differ in the command and in what came before
(a hung store's FAIL). Design §12 now states what was measured, and a run to settle the
difference is carried to 7e.

**The restore** (`L35-restore-*.md`), on vEOS, the N9Kv and the C8000V, with etcd 3.6.15:
- `store-roles`' 21 lines run as printed under etcdctl, and port49d starts under the roles
  they make.
- `--bump-revision 1000000000 --mark-compacted` reused no revision.
- port49d said nothing through the 8.1s restore and stayed listening.
- The session written since the snapshot was denied `store_unavailable`. The next refresh pass
  revoked it (counted failed), and the device still showed `store_unavailable` after that.
- A new login after the restore was admitted, after 79812ef.

**Operator notes** (for the pull request bodies and plan 13's docs; the plan's "Operator-facing
notes", amended by what was built).

7d-1's, as PR #24 carried them, still hold, with one change from Task 13b. port49d remembers the
write it last made at each device and username, not only the `ctx_id`. So an earlier version of
the same session, written back, is denied too: `store_unavailable`, counted as
`port49_crypt_open_failures_total{record="context"}`, until the next login.

7d-2's:

- **New: `store:` in `port49d.yaml`.** `backend: memory` stays the default.
  - **Turning on etcd.** Set `backend: etcd` with `store.etcd`:
    - **endpoints:** `https` only, with `ca_file`. An endpoint with a user, a password, a path
      or a query is refused at load, and the error names only its index.
    - **a client certificate each for `daemon` and `broker`.** The CN is the etcd user, and
      neither may be `root`. The key files are owned by port49d's user, mode 0600, not
      symlinks, and every path is absolute.

    `admin_socket` must be set too. Run `port49d store-roles --config …` and apply its output
    once, as etcd's root. Its 21 lines run as printed under etcdctl 3.6.15.
  - **Knobs and defaults:**
    - `call_timeout` 500ms, `bulk_timeout` 30s;
    - `packet_deadline` 2s, at most 2s: Junos times out at about 3s (L13). Measured with a
      hung store, every reply came in about 500ms (L35);
    - `breaker`: 5 failures and 5s open;
    - `max_in_flight`: 64 token, 128 context, 4 bulk;
    - `lease_grace` 5m;
    - `start_timeout` 30s. A bare `0` waits forever;
    - `hold_ttl` 15s, from 10s to 60s. A shorter hold can drop on a healthy etcd, so it is
      refused;
    - `sweep_interval` 10m.
- **etcd itself.** Run three or five members in the devices' region, with:
  - client-certificate auth and auth enabled;
  - `--auto-compaction-mode=periodic --auto-compaction-retention=1h`, and defragmentation;
  - a quota above the live records;
  - **every call answered well under `call_timeout` (500ms).** That is the binding bound at
    the defaults. The hold itself survives a round trip to the etcd leader of about 0.83s at
    `hold_ttl` 10s and 1.25s at 15s. Past any of them port49d closes every listener: dark,
    never two port49d on one keyspace. A cross-site etcd raises `call_timeout`,
    `packet_deadline` and `hold_ttl` together.
- **The roles.**
  - **etcd replaces a grant on the same range; it does not add to it.** Re-running an older
    `store-roles` output, or granting by hand, can silently change a role.
  - port49d's start reads the daemon's grants and refuses one that reaches past its role ("a
    store identity reaches past its role").
  - Check an existing role with `etcdctl role get` before you apply anything.
- **Who may write etcd.** The daemon's client certificate can write tokens, receipts, contexts
  and the index. With it alone, a thief can replay records port49 sealed, never forge them.
  - **While port49d runs**, a session record put back is denied, an earlier version of the
    same session included. A `revoke --mine` or key revocation that answers `incomplete`
    holds while port49d runs, but may not be sealed into the record yet: run it again.
  - **Across a port49d restart**, a record put back while port49d was stopped is taken:
    - another login's, which is impersonation until that session's ceiling or its device's
      next login;
    - or an earlier version of the session's own, which undoes a `revoke --mine`.

  Protect the daemon's key like the encryption key. After a suspected theft, have etcd stop
  trusting that certificate before port49d next restarts: a new CN, granted the daemon's role,
  and the old user deleted.
- **Backups.**
  - **Back etcd up** as you would the revocations file.
  - **Protect every snapshot as the store itself.** It holds who is logged into which device
    (the plaintext index; design §8).
  - **Restore with port49d stopped.** Use `etcdutl snapshot restore --bump-revision 1000000000
    --mark-compacted`, which reused no revision when measured (L35).
    - A restore rolls the marks back too: a revocation added since the snapshot is gone from
      etcd, and one lifted since is back.
    - The start puts the revocations file's marks back into etcd, and applies every mark to the
      restored sessions. It purges every unspent token, so a token redeemed since the snapshot
      cannot be redeemed again.
    - Then run `port49 revoke --lift` again for any revocation lifted since the snapshot.
  - **What a restored snapshot brings back.** It brings back the contexts it held.
    - One ended by a principal or certificate revocation is denied again at once, by the
      marks.
    - One ended by `port49 revoke --mine`, or by `(device, username)`, is live again until its
      idle TTL. Revoke it again after a restore.
  - **Restored under a running port49d,** port49d sees the rollback as records put back.
    - Every session written since the snapshot is denied `store_unavailable`, and the next
      refresh pass revokes it.
    - **The device still shows `store_unavailable` after that pass, not a revocation** (L35).
      The user logs in again, and that login is admitted.
    - A port49d restart before the pass admits those sessions again.
- **One port49d per keyspace until plan 7e.**
  - A second one waits, is not ready, and names the holder every 30s.
  - On Kubernetes use `strategy: Recreate`.
  - Never delete `meta/hold` by hand: stop the port49d that holds it. A port49d that takes the
    keyspace waits a third of `hold_ttl` before it serves, so a deleted key never serves two
    while etcd answers both.
- **What a restart does now.**
  - Live sessions survive. Every standing revocation is applied to them first, so a mark added
    to the file with port49d stopped takes effect before it serves. Each is then carried onto
    the policy in force, and the next command is answered from the kept context. Measured on
    all five images (L35).
  - Unspent tokens are purged (`port49d: store: purged N unspent token(s) …`), so run `port49
    token` again. A retried `port49 token` with the same idempotency key mints afresh.
    - **The replay's caveat.** That relies on this port49d's clock. If port49d moves to a host
      whose clock is behind the old one's, a replay inside the skew can still be answered from
      before.
    - **A pending reservation.** One a stopped port49d left blocks its key for up to a minute.
  - **Editing `broker.revocations_file` with port49d stopped no longer lifts a mark on etcd:**
    the store's copy comes back. Lift with `port49 revoke --lift` on the admin socket.
  - **Junos re-authorization on etcd (§15 L36, measured on both Junos images).** On the memory
    store a restart denied every live Junos session's next re-authorization
    (`authorization-time-interval`). On etcd the contexts survive: with the interval at 15 minutes
    a restarted port49d answered the open session's re-authorization `PASS_ADD` from the kept
    context, and a session revoked before its first re-authorization was denied at it (`FAIL`,
    `credential_revoked`). The device did not end the session on the denial: its next command
    printed an error. Revocation reaches a Junos session at its first re-authorization, up to
    the interval after login. Whether a later one comes is unmeasured (§15 L40); until then
    treat a session past its first re-authorization as not reached.
- **What an etcd outage does.**
  - **At start:** nothing listens, and `/readyz` says `waiting for the store`. Devices use their
    local method, and break-glass works. port49d waits up to `start_timeout`, then exits 1. With
    `0` it waits for as long as it takes.
  - **While running:**
    - Commands are refused `store_unavailable` within `packet_deadline`, and at once after the
      circuit opens (`port49_store_circuit_open` 1). Break-glass logs in where the device falls
      through on ERROR: on vEOS and the N9Kv its commands are then refused, and Junos
      authorizes no command with port49. IOS-XE refuses break-glass outright (L4, L35).
    - **The listeners close.** They close when port49d loses its hold (12–25s into a hang at
      `hold_ttl` 60s, measured), or when a pool's circuit stays open for `hold_ttl`.
      - port49d resets every held TACACS+ connection and says why.
      - `/readyz` is 503 meanwhile. port49d does not exit.
      - Devices fall to local, and break-glass logs in on all five images.
    - **On IOS-XE, dark means break-glass.** An open session's commands are refused (`%
      Authorization failed.`) until port49d listens again. vEOS, the N9Kv and Junos run them
      under local authorization.
    - **Listening again.** port49d waits for etcd itself, then serves again, and sessions resume
      on their contexts. That takes the lost hold's lease to expire, plus a third of `hold_ttl`:
      38s to 1m27s at 60s, measured. Meanwhile it says `keyspace … is still held by this
      port49d's last run (its hold was lost when the store stopped answering); waiting up to
      hold_ttl (…) for its lease to expire`: that is port49d waiting on itself, so do not stop
      it. If that start fails for another reason (a policy file caught half-written), it says
      so and tries again every 5s; it does not exit.
    - **Keep `Restart=on-failure` anyway.** It still restarts port49d after a crash, or after a
      cold start that exits 1 (a configuration fault, or `start_timeout`).
    - **Metrics between runs.** `/healthz`, `/readyz` and `/metrics` are unbound for the drain
      and the next config load (seconds), and the counters restart. Give a Kubernetes liveness
      probe a failure window over 30s.
  - **A store slow but up** does the same once its token or context calls keep missing their
    deadlines. So does etcd refusing every such call (a role removed): a steady run of
    refusals, not two an hour apart.
  - **Slow scans** (the refresh's, a large purge) open only the bulk pool's circuit
    (`port49_store_circuit_open{pool="bulk"}` 1, and a line saying logins and commands are
    unaffected). port49d keeps serving. Alert on it, and size `bulk_timeout`.
  - **A wrong token's FAIL** arrives at the failure delay even with a slow store. The store's
    time is inside the delay, so it is at most 2s at the defaults.
- **Certificates.**
  - Each start prints each client certificate's expiry, and
    `port49_store_client_cert_expiry_timestamp_seconds{component}` carries it.
  - An expired or untrusted certificate is named, never reported as etcd not answering.
  - A certificate that does not parse is refused, naming both of its files.
  - After an outage, a renewed certificate file is picked up without a restart.
- **New metrics:**
  - `port49_store_calls_total{component,pool,outcome}`, `port49_store_call_seconds{component,pool}`
    and `port49_store_circuit_open{component,pool}`. The pools are `token`, `context` and
    `bulk`; the outcomes include `deadline`, `saturated` and `refused`;
  - `port49_store_keyspace_held`, `port49_store_client_cert_expiry_timestamp_seconds{component}`
    and `port49_crypt_store_key_unknown`;
  - port49d now reports 7d-1's `port49_contexts_reindexed_total`,
    `port49_contexts_reindex_failures_total` and
    `port49_store_index_records_undecodable_total`.

  Alert on any of:
  - a circuit open;
  - any increase of `port49_contexts_reindexed_total`: an index record was deleted in etcd, and
    the context it hid has been re-indexed (each sweep, `sweep_interval`);
  - any increase of `port49_crypt_open_failures_total{record="context"}` with the key held: a
    record altered in etcd, or another login's, or an earlier version of a session, written
    back;
  - `port49_store_keyspace_held` 0 while port49d runs;
  - a client certificate within 30 days of expiry;
  - `port49_crypt_store_key_unknown` 1;
  - any `increase(port49_crypt_open_failures_total{record="token"}[10m])`.
- **Key rotation across a restart.** Keep `encryption.previous` until the old key's records
  expire.
  - **The warning.** A start that finds the store last written under a key it does not hold
    says so. It names the key id, printed as `?` if it is outside `[A-Za-z0-9._-]{1,64}`, and
    sets `port49_crypt_store_key_unknown` to 1.
  - **The alarm lasts only for that process.** The next start records its own keys, so the
    warning and the gauge clear even if sessions sealed under the lost key are still live.
    From then on `port49_crypt_open_failures_total` and the unopenable-record lines are the
    only witnesses.
  - **The unopenable-record lines.** A record that will not open is named by its key id on
    stderr, once per 10 minutes.
  - **An unreadable `meta/seal_keys`** is said, raises the alarm, and is overwritten. The start
    goes on.
- **A wrong `PORT49_ENC_V1` never revokes.** Sessions sealed under a key port49d does not hold
  are denied `store_unavailable`.
  - The re-index and the refresh say each one by device and username, count it
    (`port49_contexts_reindex_failures_total`, the refresh's `failed`), and leave it.
    `port49_policy_refresh_pending` stays 1.
  - Fix the key and restart, and those sessions answer again.
  - A record that fails authentication is tampered and is still revoked. So is another login's
    record or an earlier version of the session written back.
- **A session record that does not decode** (a `c/` value garbled in etcd) is unreadable, as
  one that will not open is.
  - The next login on that device and username replaces it.
  - The refresh and the re-index delete it at the revision they read, since nothing can revoke
    or use it.
  - It is said by its key alone, never its value.
- **A `port49 token`, refresh, identity or explain behind a slow `port49 revoke`** now says
  `your revocation sent at … is still running on the broker; nothing was minted; run port49
  token again once port49 revoke reports` (exit 1). It no longer says `the broker … is
  unreachable`.
- **A revocation behind another running one** says `an earlier revocation still held the
  connection; this one was not sent` (exit 1). Nothing was sent, so run it again.
- **`port49 revoke` on the admin socket now exits 1 on an answer that names nothing.** It says
  ``port49 revoke: port49d did not answer (its answer named no revocation); the revocation may
  be in force — check `port49 revoke --list` and port49d's log before retrying`` (`lift` for a
  lift), as the agent forms already did. port49d never sends one.
- **New command: `port49d store-roles [--config FILE]`.**

**Unassigned follow-ups:**

- 7c's M3, unchanged: a `revoke` record for a mark that could not be written.
- The bulk lift (7c), unchanged.
- **New: Ruling 17's residual, as Task 13b left it.** With a stolen daemon store credential:
  - **Across a restart, impersonation.** Another login's context put back while port49d was
    stopped is taken as that key's at the start. It holds until its sealed ceiling, if it has
    one, or the key's next login.
  - **Across a restart, rollback.** An earlier version of a key's own context put back while
    port49d was stopped undoes a revocation that leaves no mark (self or key). The start's
    refresh judges its policy.
  - **While port49d runs** (narrowed by Task 13b from any earlier version): the write before
    one in flight or of unknown outcome, put back, is admitted until a later write lands at
    the key. A self or key revocation whose seal failed after its plaintext mark landed is
    held by the ledger's revocation floor (final review I-1); across a restart it is that
    mark alone, so its `incomplete` answer says to run it again.
  - A deleted token put back for a holder of its secret, until its sealed expiry.
  - A receipt's sliding bound stretched to its sealed cap.
  - A context kept alive past its idle TTL: to its sealed ceiling if it has one, and
    indefinitely under `max_session_age: never`.
  - A context hidden from the index until the next sweep re-indexes it. Meanwhile a revocation
    by sid does not reach it.

  Closing it needs two things. One is a revocation record the daemon's role cannot write, for
  every kind: a spec change to decision 34. The other is a sealed freshness check that holds
  across restarts: Task 13b's write ID holds only within one process's ledger, so this needs a
  write sequence the broker's role keeps per key, which 7e's shared ledger could become.
- **Spec follow-up (7e or later):** config refuses an encryption key id outside the seal-key
  charset. Today such an id prints as `?` (Task 13).
- `TestStartClusterRetriesAPortTaken` (etcdtest) failed once under load: its one retry hit a
  taken port again (the pick-then-bind race). A retry until a deadline would settle it.
- Lab hygiene: beehive's root filesystem filled during Task 15 and killed port49d at setup
  (ENOSPC). Check free space before a lab run.

**After the merge:** the raw L35 captures are only in the 7d-2 worktree's `tests/lab/captures/`.
Copy `tests/lab/captures/L35-*` to the main checkout before removing the worktree, or the
labpcap audit fails.

**Carried, for later plans:**

- **7e:**
  - `b.superseded`, `b.blobsSeen` and `quarantineRecorded` move into the store, with m10's
    bound on `b.superseded`.
  - More than one port49d per keyspace: the hold becomes per broker process, and the daemons
    hold none.
  - The listener's marks and the daemon's (`store.Marks`) are shared across replicas, through
    a watch on the marks family.
  - The ledger (`crypt.Ledger`) is shared across replicas or replaced, since per process it
    would deny another replica's logins (re-check IA1). Since Task 13b it is keyed on write
    IDs.
  - `broker.revocations_file` is retired.
  - One refresh runner.
  - The decision-log emits under a policy hold are bounded (4b Task 4).
  - IOS-XE's refusal once port49d went dark (`L35-cisco_iosxe.md`), against `quarantine-cisco_iosxe.md`'s
    `show privilege` that ran with port49d stopped: L38 settled that neither the command nor the
    session's last answer changes the refusal; why quarantine's ran is unexplained.
- **Lab, unassigned:** §15 L40 (open), whether a Junos session is re-authorized more than once
  (L36 measured the first re-authorization after login only).
- **7f:**
  - Go-dark proper: the N-failures/M-passes listener control replaces Ruling 11's coarse
    close-and-wait.
  - The idle-detection gap (L37, measured 2026-10-04): an idle port49d on a hung store goes dark
    about 2 minutes in at `hold_ttl` 60s (circuit open 43–50s, listeners closed 1m43s–2m0s), because the
    probe needs five failed pings, a sixth of `hold_ttl` apart, to open the circuit; under load it
    should be about `hold_ttl` plus a probe period (about 70s; derived from the guard's rule, not measured). IOS-XE is locked out for all of it (its
    break-glass `ERROR` is final). A probe that re-pings at `breaker.open_for` cadence after one
    failure is the mitigation to weigh, Ryan's and 7f's call.
  - The warm context cache.
- **12:**
  - The etcd deployment artifacts: the members, compaction, the quota, and the roles applied
    from `port49d store-roles`.
  - `call_timeout`, `bulk_timeout` and `packet_deadline` sized against load.
  - The store alarms, a client certificate's expiry among them.

### Plan 7e — As built

Executed from `2026-10-03-07e-broker-process.md`, each task reviewed. The ledger is
`.superpowers/sdd/2026-10-03-07e-broker-process/progress.md`, with each task's brief, report
and review beside it. A pre-flight review, a re-check and a final check revised the plan before
Task 1 (716b857). Task 8a was added by the pre-flight (the feed fence). What differs from the
plan's text, task by task:

**7e-1** (`feature/broker-process`, base `b508ba0`):

- **Task 1 (docs, decision 36; 11ac5e2).** As planned. Design §15's exports list gains the four
  7e gauges in Task 11 (review m-1).
- **Task 2 (etcdtest; c21f04f, c92827d).** `StartCluster` retries a taken port until a
  deadline, and a failed attempt stops at once (Ruling T2-a).
- **Task 3 (config; a85c22e).** An encryption key id outside the seal-key charset is refused at
  load. Task 13 routes the broker's keys through the same check.
- **Task 4 (records after the policy; a316fd0, b329bd4, 6bfc362, d7c0662, a4e5215).** A mint's
  records, and a session refresh's (Ruling T4-a), are written once it lets go of the policy.
  One blob record per hash per request (review I1).
- **Task 5 (`superseded` in the store; ca282ba, 6130540, 3e692eb).** The local copy is pruned
  once a minute; the daemon is probed against writing `sp/`. Carried to 7e-2's docs: broker
  replicas need NTP-synced clocks; an undecodable `meta/superseded_all` is deleted, and the next
  start rewrites it.
- **Task 6 (`Seen`, `Ping`; 5f1d17d, f98cd2f, 83ff587).** Every context-client response feeds
  `Seen` (`sawKV`), deletes, indexes and meta included (Ruling T6-a).
- **Task 7 (the sealed sequence and the ledger; f8b057f, dc320bd, bcde669, 3f66a33).** The
  revocation floor is `revoked(k, at, seen)`, held through `max(hw, seen-1)`, in place of the
  plan's pending floor, which revoked every user's next login after the upgrade (Ruling T7-a).
  The unopenable sayer is keyed by (record, key id, kind), so the upgrade's line never silences
  a put-back's.
- **Task 8 (the context feed; 972fefe, 864531a).** `Ledger` gains `SetBase`, `Seed`,
  `ObserveFollowed`, `Dirty`/`Redirty`; a rescan's seed is `seedFollowed`, which makes no entry
  below the base. A floor-only entry counts as no mark. Watch events feed `Seen`.
- **Task 8a (new: the feed fence; 3bd92b7, 08b095f, b2260b1, 618bff3).** `crypt.Fence`,
  `crypt.Fenced` and `ErrFeedBehind`: a context read waits, within `call_timeout`, for the feed
  to pass the record's revision. A waiting read's progress request is made again for each new
  watch. Parked (R-1): `askAgain` may reach etcd before the new watch registers; that read then
  waits out `call_timeout`, failing closed. Task 17 revisits it if L37 sees it.
- **Task 9 (the marks feed; 3677a78, 30e0554, 04a2c71, 88f03c3, a3464a3, 7f98f81, 49fc71d,
  1147a0e).** `WatchRevocations`' callback is `fn(r, lifted, rev)`, and `FollowMarks` advances
  per event (Ruling T9-a). A reload never lifts a mark whose store write has not landed
  (`Marks.Pend`, `Unrecorded`; T9-b); such a mark closes no held connection (spec §5.1.4, T9-d)
  and reaches this listener once the store has it. `port49_revocations_in_force` follows the
  feed (T9-c). An undecodable mark stands by its key on a load as on a watch (T9-e).
- **Flake fix (f6e5a26).** A product bug: on `credential_revoked` the agent's close cut the 410
  answer, so the client said "no agent". It shuts down within 5s after stopping.
- **Task 10 (the ledger record; 267f73a, 782f2d5).**
  - `store.LedgerMark` gains `FloorSeq`, the sequence the floor holds through: `Dirty` writes it,
    and `Seed` takes the floor where the key's mark is at or below it (review C1). `lw/` keeps it
    as `floor_seq`, and a mark above it clears the floor there, as in the ledger.
  - The plan's put-back test needed a second subject sharing alice's username, which spec §2
    refuses. bob is a second identity of alice's subject instead: same username, other
    principal.
  - `KeepLedger` writes what it still owes once when it stops, within 2s, so a graceful stop
    leaves its last round in the record.
  - `TestAStartSealsTheLedgerOnceItHasReadTheStore` deletes `lw/` with the context, so the base
    still judges the put-back alone.
  - Review fix round 1:
    - A floor-only mark (`seq` 0) seeds its floor and no mark, so the key's next login gives it a
      lease again (I-1).
    - A seeded key the ledger holds as the record does is owed nothing, and
      `store.LedgerSink.PutLedgerMarks` returns how many marks landed, so a failed write owes
      only the rest (I-2).
    - A stop that cannot write says how many marks it leaves (M-1).
    - An undecodable `lw/` key names its remedy (M-4).

**Interfaces 7e-1 changed, for 7e-2's tasks:**
- `store.FollowMarks(ctx, feed, m, from, on, up, rescanned func() error, logf)`: a `rescanned`
  that fails refuses the reload, and is a failed watch tried again in a second (re-review 1
  C-2). port49d's hook puts back the revocations file's marks, and a reload without them would
  lift each for good.
- `store.MarkFeed.WatchRevocations(ctx, after, fn func(r Revocation, lifted bool, rev uint64),
  progress func(rev uint64))`. Both etcd watches ask for progress notifications, and
  `FollowMarks` and `crypt.FollowContexts` resume a re-watch from the last progress as well as
  the last change, so a reconnect within the compaction retention never reloads (final review
  I-1).
- `store.LedgerMark{Key, Seq, RevokedAt, FloorSeq, Until}`.
- `crypt.KeepLedger(ctx, l, sink, every, report, logf)`, with the stop's last write.
- `store.LedgerSink.PutLedgerMarks(ctx, ms) (int, error)`: how many of `ms`, from the first,
  landed before an error.
- `crypt.Ledger`: `SetBase`, `Base`, `Seed`, `ObserveFollowed`, `Dirty`, `Redirty`, `Pending`,
  `Fence`.
- `crypt.Fence` (`Attach`, `Followed`, `SetUp`, `Up`, `At`, `Asks`, `Wait`), `crypt.Fenced`,
  `crypt.ErrFeedBehind`.
- `store.Marks.Pend` and `Unrecorded`.
- `store.Marks.Count(fn func(principal, cert int))`: `port49_revocations_in_force`'s one source
  (T9-c), told under the marks' lock after every change. Set it before the first `Set` or
  `LoadMarks`, or the gauge reads 0. `countRevocations` is gone.
- `broker.Broker.Say`: `MarkChanged`'s lines (a held connection closed, a lift a reload found)
  go through it. Nil sends them to the process log, not port49d's stderr.
- port49d's `startOnPersistentStore(ctx, brk, st, e, cfg, &marks, m)`: it lost `ledger`. The
  base is set by `LoadLedger` in `openStores`, and `Ledger.Seal` is gone.
- port49d's `restoreRevocations(ctx, st, path)`: it lost `m`.
- port49d's `persister(st, path, held, enforced, m)`: `held` is the file's marks as the start
  read them, and `enforced` this process's marks; a file mark the store lacks is kept while
  `enforced` holds it. `putBackFileMarks(ctx, st, path, enforced)` is the marks feed's hook before
  a reload (final review C-1).
- port49d's `unopenableSayer(keys, out, now) func(record, keyID string, why error)`: keyed by
  (record, key id, kind), every line hard-prefixed `port49d:`. port49-broker cannot use it
  unchanged.
- `crypt.Fence.OnTimeout(fn)`, told each `ErrFeedBehind` (`port49_store_fence_timeouts_total`).
- port49d's `stores.keep`, run and joined by `runOnce` beside `stores.follow`.
- The test fixtures: `etcdRunServerWith(t, policyBody, others)`; `sharedUsernamePolicy`, where
  bob is a second identity of alice's subject, not a second subject (spec §2); `mintAs`;
  `waitForLedgerSeq`; `etcdtest.Proxy.Drop`, which ends every stream as a member restart does;
  and `etcdtest.Options.ProgressNotify`. Task 14 Step 7 must split `etcdRunServerWith` too.

**7e-1's operator notes, as built:**
- **Re-apply `port49d store-roles` before upgrading.** It prints one more grant: the daemon's
  read on `lw/`. Without it the start stops with `the daemon's role cannot read lw/, the ledger
  record: apply port49d store-roles (plan 7e)`. The start check also refuses a daemon role that
  can write `lw/`, or read or write `sp/`.
- **Upgrading from 7d on etcd ends every live session once.** A context 7d sealed does not open
  under 7e: it is denied `store_unavailable`, replaced at the user's next login, and revoked by
  the next refresh. Each node says it once per 10 minutes as the upgrade. Rolling back to 7d
  ends sessions again.
- **A context put back in etcd while port49d was stopped is denied after the restart** at every
  key the ledger record (`lw/`) holds a later write for. A revocation's floor is kept there too,
  through every sequence it held. The record trails by at most a second, and a graceful stop
  writes what is owed. A stop that cannot write says `stopping with N ledger mark(s) not
  written to the ledger record`.
  - A revocation at a key with no mark (each form-3 context at the upgrade) leaves an `lw/` key
    with no lease. It gets one at the key's next login. One that never sees a login again stays,
    at most one per (device, username).
  - An `lw/` key that does not decode stops the start, naming the key. Delete that key as etcd's
    root to start without its mark, accepting a put-back at that one key.
- **A context read waits for port49d's watch on the store** (the feed fence): milliseconds
  normally. With the watch stopped and etcd answering, new sessions are denied
  `store_unavailable`, `port49_store_feed_up{feed="contexts"}` is 0, and the line says `the
  context feed stopped`. **Run etcd 3.5.8 or later** (3.4.24 on 3.4; etcd #15220).
- **After an etcd restore under a running port49d,** the next login is admitted, and a session
  written since the snapshot is denied until its next login, as 7d measured.
  - A mark the restore lost is put back from `broker.revocations_file` before the marks feed
    reloads, and said: `port49d: broker: N revocation(s) in broker.revocations_file … were
    missing from the store (an etcd restore?) and are put back; lift any lifted on purpose with
    port49 revoke --lift`. A mark this port49d lifted, or saw lifted, is not put back. A lift
    made on another port49d while this one's marks feed was down cannot be told from a loss,
    and is put back: lift it again.
  - A put-back that fails (the broker's circuit open through the restore) reloads nothing: the
    marks feed is down, `port49_store_feed_up{feed="marks"}` 0, and the line says `the marks
    feed stopped (broker: putting broker.revocations_file …'s marks back into the store before
    the marks reload: …; the marks are not reloaded until they are back)`. It is tried again
    every second, and the stop and the compaction are said once per run of failures.
  - While the marks feed is down, mints and refreshes still read the store's marks, and a
    revoked principal's contexts and tokens are revoked in the store, so logins are still
    refused. Held connections are not closed by a mark made elsewhere, and lifts made elsewhere
    do not reach this port49d until it follows the store again. A file that does not load keeps
    the feed down until it loads, or until the next revoke or lift here rewrites it.
  - A mark the reload lifts (one not in this port49d's file) is said by its key: `broker: a
    reload of the marks found the revocation of … lifted: lifted on a broker process while the
    marks feed was down, or lost by an etcd restore; revoke it again unless it was lifted on
    purpose`.
- **A port49d restarted soon after a lift made on another port49d may put that mark back**,
  fleet-wide: its revocations file lags lifts made elsewhere. `port49 revoke --lift` it again.
  7e-2 retires the file on etcd (Ruling 12), and this note with it.
- **Each feed says each stop and each return:** `store: the context feed stopped (…)` (or the
  marks feed) at every stop, and `store: the context feed follows the store again` at the first
  change or progress after one. Both watches ask etcd for progress notifications, so a reconnect
  within the compaction retention resumes without a reload, and a rescan means a real gap.
- **The upgrade** also logs, per live context, `broker: refresh: the context for "…" on "…", …,
  will not open (crypt: a context sealed by an earlier port49 (form 3, not 4)); revoking it`,
  beside the once-per-10-minutes `crypt: a context sealed by an earlier port49 (form 3) does
  not open: expected once after the 7e upgrade` line. Both are expected, once.
- **Rolling back to 7d** prints, per key id once per 10 minutes, 7d's `a context failed
  authentication under key id "…", or is not the one this port49d last wrote there: it was
  altered or is corrupt`, and 7d's start refresh revokes every 7e context as tampered, one
  `broker: refresh: … will not open …; revoking it` line each. That is the rollback, not an
  attack: rolling forward again finds those contexts revoked, and users log in once more.
- **`port49 refresh` and `port49 token`** now say the broker's `credential_revoked` reason
  instead of `no agent at …; run 'port49 login'`, and an ending agent waits up to 5s for its
  in-flight socket calls (f6e5a26).
- **`port49_revocations_in_force`** counts the marks this process enforces, following the
  store's marks feed, not the file's count at the start and at each persist.
- **A stalled decision-log sink no longer holds a policy reload**, nor the mints behind it.
- **New config refusal:** an `encryption` key `id` outside `A-Z a-z 0-9 . _ -` (1 to 64).
- **New metrics:** `port49_store_feed_up{feed}` (0 for longer than `hold_ttl` is an alarm; both
  labels read 0 from when a run on etcd begins waiting for the store),
  `port49_store_feed_rescans_total{feed}` (alert on any increase), `port49_ledger_pending`
  (above 0 for a minute is an alarm: the record cannot be written), `port49_ledger_behind` (1 is
  an alarm: the keeper's context feed is down). Both ledger gauges read 0 once the keeper stops.
  `port49_store_fence_timeouts_total` counts context reads denied because the context feed had
  not delivered the record's revision in time: rising with `feed_up` 1 and etcd answering, the
  feed lags; it is not the store (final review M-4).

**7e-2** (`feature/broker-split`, base `d06a391`, 2026-10-04): the two processes. Task by task; two
plan-amendment commits (`670bb7a`, amending 7e-2 to 7e-1 as built, and `1bb593d`, the pre-flight's
fixes) precede Task 11:

- **Task 11 (docs, decision 36's 7e-2 part; cd4b520, 509eb9b).** Differs from the plan's text:
  - §12 says `port49-broker`'s one subcommand is `revoke --offline`, not "no subcommand";
  - the stale "the hold not held while port49d runs" alarm is replaced by the keyspace-held-sum
    alarm, since no port49d holds the keyspace now;
  - the spec's other "until plan 7e" clause (store-roles' stolen-daemon-key paragraph) is
    rewritten as decision 35's is;
  - two more revocations-file statements in the design (the failure matrix, the record table)
    now say the memory store only;
  - review fix round: §13 has one restore answer, the runner's bounds are named, and decision
    35's "a start on etcd" carries the decision 36 amendment.
- **Task 12 (port49d's code into `internal/port49d`; e7b2d00).** `Main(args) int` with a
  `FlagSet` in place of `os.Exit`; `cmd/port49d` is a shim. The 244 test names are the same
  before and after. `git log --follow` does not reach `main.go`'s earlier history (it shows as
  a modification of the shim).
- **Task 13 (two configurations; ee5dcd2, 1bf4cc3, e3d98d3, ad69c38, 9bb5fec).**
  - `port49d.yaml` refuses `key_refs` and `broker.state_dir`, as well as a `broker:` block on
    etcd; `port49-broker.yaml` refuses `store.etcd.daemon`, `policy:` beside `broker:`, and
    each key a broker has no use for, naming it.
  - `broker.state_dir` is fenced at load: absolute, an existing directory, writable by no group
    or other user, never inside or around `inventory.service`'s `state_dir` or `mirror_dir`.
  - Fourteen etcd tests built on the 7d shape were skipped until Task 14 rewrote them
    (Ruling T13-a); none is skipped now.
- **Task 14 (port49d on etcd with no broker; 04d481f, cdef83f, d39416b, fd8cde7, 2a2b16b,
  8e313f8, e3bb99a, 84c0c90, f935ef6).**
  - `Marks.Keep` holds a mark in force through a reload that lacks it. The reproducing tests
    ran first: without `keep` the daemon's gauge fell from 2 to 1 on a restore, and to 0 after
    a store gone (Ruling A-1, P-1).
  - The daemon's keep line says how a kept mark is released: revoke it again on port49-broker,
    then lift it with `port49 revoke --lift`, or restart. The plan's "or a lift this feed
    delivers" cannot work: a lift of a mark the store lacks is `ErrNotRevoked`, and nothing is
    written.
  - The split branch is `openDaemon`; `pruneLoop` runs on the split daemon, since the sweep that
    pruned its ledger is the broker's. A reloader with no broker keeps one prior, not every
    policy it loaded. `store.etcd.broker` with no broker in the process is refused.
  - The marks load in `openDaemon` is bounded by `bulk_timeout`.
- **Task 15 (`port49-broker`, the runner; 8f1958f, 3854c95, bcbdae5, a0d038e, 9226966, 439cd58,
  b9fd336, ebed469, b0d01e4, 3b4478e, bd7570d, cd06ed0, 24eeb4d, eb6203f, 1af9b7c, 0764d08).**
  - `run` also selects on the duties ending: a takeover that fails for good lets go of the hold
    and takes it again after 5s. `meta/judged` is written under the duties' context, so a
    non-runner never writes it.
  - **The cross-process floor** (Ruling T15-a). A session's own record, put back after the
    runner revoked an older put-back, was admitted by a running port49d. The floor is now
    `min(hw, R-1)`, `R` being the revision of the plaintext `revoked_at` write: a record that
    landed before it is denied, a login after it is admitted. The plan's `seq > R` does not
    hold (`seqFor` gives `seq == R`; reproduced).
  - A symbolic link as `broker.state_dir` is refused as one. The writer refuses `marks.json`,
    `witness.json` and the directory owned by anyone but the process's uid or root.
- **Task 15a (policy across replicas, the guard at a start; c7fc3c8, 92d6388, aa0fbf9, 9ebd86a,
  2177ef2, 8daae43, 972e76a).**
  - Every `port49d:` prefix in a shared path is the running process's (`procOf`); no
    package-global, since the fleet tests run both in one process.
  - A replica serving another bundle than `meta/judged` names marks `meta/judged` in doubt
    itself and mints nothing until the mark lands (the mint gate). The runner marks it at every
    swap of its own too.
  - The guard fails closed on a read error. A policy that admits no device is refused by
    `loadPolicy` before the guard runs; `quarantiningLeaf1` is the test's refused file.
  - Readiness never follows the gate (design §12: a store fault is an alarm, never readiness).
    A fix round that made `/readyz` 503 while the gate was shut was withdrawn for that reason
    (re-review 3, I-4); the gauge `port49_broker_mint_gate_closed` is the alarm.
- **Task 15b (the marks copy, revoking with every broker down; 9f4e941, 8eab80c, 7a8c624,
  290dd85).**
  - The copy is fed from the watch (`copyingFeed`), not from `FollowMarks`' `on`: a revocation
    or lift made on the replica itself never reaches `on`.
  - Every replica keeps what its copy holds and the store lost, at its start as well as at a
    reload (`keepCopied`), so a restarted non-runner does not admit a principal at its listener
    while the runner's put-back keeps failing.
  - The takeover's put-back runs before the re-index (the plan's order panicked a test with no
    broker).
  - `port49-broker revoke --offline` loads the policy and writes the origin `offline uid <n>`,
    added to spec decision 34's list of origins. An entry in the copy the replica does not
    understand is kept raw and written back unchanged.
- **Task 15c (the restore witness; c6a62f9, ab3076e, b351d95, fd18968, b3b60e1).** An unreadable
  `witness.json` is moved aside and purges once, and the unread state is saved so a restart
  before the purge still owes it. Review fixed the purge's order. The restore runbook deletes
  the unspent tokens before any process starts and restores on loopback only until both
  deletes land (design §13; spec decision 36 names the token delete).
- **Task 15d (new: port49d's restore guard; 79e09c5, 97a4838, d7c705a, 56324c1, 29b4a40).**
  Ruling 19. port49d reads `meta/witness` through the guard and refuses a token redemption
  `store_unavailable` while the store is older than it followed, until the runner's purge
  writes `meta/purged`. A read that fails refuses too. A refused `meta/purged` write leaves the
  witness record alone, so a restart does not release the guard over unpurged tokens.
  `port49_redemption_restore_guarded` is 1 while it stands. No new reason code.
- **Task 16 (the fleet end to end, `store-roles` for two files; 8b10c83, 84e7f55, 4d9a123,
  450f8b1, 2d56958).** Five fleet tests ran green at first and found no defect. The daemon's
  role reads five keys of `meta/` and no more (`seal_keys`, `witness`, `purged`,
  `judged_bundle`, `ping`): the policy text in `meta/judged` stays the broker's, so the skew
  gauge compares `meta/judged_bundle`, the bundle's name alone (Ruling T16-a). The gauge reads
  1, not 0, where no bundle has been judged yet. The L35 tests were ported to the split in
  Task 17.
- **Task 17 (lab; 107a41e, 87d7b73, 0cff0d0, 2a74f88, 20fb9fa, c855c3a, 229eb4b, f3f2f11,
  58d0bd1, 1c52903, 651e185).** L36, L37 and L38 closed, run on the five images from pinned
  worktrees. Differs from the plan's text:
  - IOS-XE sticks to the last server it used, so L37's cells 3 and 4 ask A with B stopped;
  - a Junos session sends no TACACS+ per command, so L37 cell 2 on Junos is a fresh login
    through B, and L36 revokes a second session instead of the first;
  - the dark wait is bounded by `darkBound` (125.5s at `hold_ttl` 60s), not 7d's 12s;
  - the L35 re-check needs `PORT49_LAB_L35_ENTRY=L35-recheck`, or it would overwrite the
    closed note, and the harness refuses to;
  - review cut every claim to what its note says. L40 was opened for what L36 did not measure.
- **Task 18 (this section; b5fc4a7, 65c0a18, 69b41e7, and the docs commit).** The wording sweep
  is code (below), and this section.
  - `internal/bundle`'s refusals name `port49d` in three phrases (`RaiseBound`, `KeyRefsFile`,
    `StopFleet`, exported). On port49-broker they now read `port49-broker.yaml`, and "stop
    every port49d (port49-broker serves no device)". A reload keeps "send SIGHUP", which
    re-reads `inventory.max_removed_percent` from `port49-broker.yaml` as port49d's does
    (tested). The refusal at a held start says "restart port49-broker, which reads it at its
    start (a SIGHUP is not read until the start has passed)", because that is true there.
  - `broker.Revoke`'s busy and refused-write errors said "or stop port49d" and "this port49d
    denies"; on port49-broker they say "stop every port49d (port49-broker serves no device)"
    and "this port49-broker denies". The API's lift hint names the serving process's admin
    socket.
  - Each changed message is tested for both processes.

**The rulings as made, against Rulings 1–19 and OR-1** (decision 36 records each):
- **Rulings 1, 2, 3, 9, 10, 15, 16:** as planned.
- **Ruling 4 (the ledger record):** as planned. T15-a closed one more case (the floor `min(hw,
  R-1)` above). The residual stands, exactly: a key written within the keeper's lag and put
  back inside it; a key written while no runner ran, put back before a runner recorded it; a
  key written while the runner's own context feed was down; the same three for a process
  whose watch was compacted. Not closed: tokens put back, a receipt's sliding bound, the idle
  clock and the index. Closing those needs a revocation record the daemon's role cannot write
  for every kind, a spec change to decision 34.
- **Ruling 5 (the marks across processes):** amended by A-1: a mark a reload finds missing
  stays in force on port49d, which cannot put it back and says so by name. Spec decision 36's
  "applies the difference" is amended for port49d. Ryan's rule of 2026-10-03 was that a
  deviation needs data, or a glaring gap; the reproducing tests failed first, so A-1 rests on
  both.
- **Ruling 6 (the runner):** as planned, with the settle pass keeping the priors until it runs.
- **Ruling 7 (a purge only when the bundle changed hands unjudged):** as planned, plus a
  replica marks `meta/judged` in doubt at every swap and the runner at its own (Task 15a,
  I-1 to I-3).
- **Ruling 8 (the settle pass):** as planned; its cost is named in the notes below.
- **Ruling 11 (port49d holds no hold, and probes the store):** as planned; L37 measured it.
- **Ruling 12 (the revocations file retired on etcd):** as planned; every replica keeps what
  its copy holds and the store lost, at a start as well as a reload (Task 15b).
- **Ruling 13 (the admin sockets, revoking with every broker down):** as planned; the offline
  origin is `offline uid <n>` (T15b-a).
- **Ruling 14 (`store-roles` reads both files):** as planned; the daemon's `meta/` read is five
  keys, not the prefix (T16-a).
- **Ruling 17 (the guard at a start):** as planned; a read error holds the start (fails
  closed).
- **Ruling 18 (the restore witness):** as planned; an unreadable record purges once (T15c-a).
- **Ruling 19 (new, Task 15d):** port49d refuses redemption while the store is older than it
  followed.
- **Rulings made during execution:** A-1 (above); T13-b and T15-b, a group-writable
  `broker.state_dir` is refused even on a volume the kubelet makes group-writable for
  `fsGroup` (another pod sharing the GID could write `marks.json`), so Kubernetes needs the
  recipe below; T15c-b and T15c-c, the runbook's token delete and the Task 15d guard; T17's
  dark time is by design (decision 36: the runner holds, and an idle port49d goes dark after
  the probe opens its circuit and `hold_ttl` passes).
- **OR-1 (`port49 revoke`'s default socket), closed by Ryan on 2026-10-03 ("use your best
  judgement"), made:** it keeps port49d's socket as its default, and on etcd port49d's socket
  names the broker's, and exits 1. Nothing is left under "Open for Ryan".

**The deployment consequences 7e-2 adds, for each of plan 12's three shapes** (roadmap,
"Deployment shapes"; L39 stays open):

| | systemd | containers | Kubernetes |
|---|---|---|---|
| `broker.state_dir` | a directory on the host, kept across restarts and backed up with the broker's host. `StateDirectory=` passes as it is | a named volume per broker, owned by the user the container runs as, 0700 | a volume per replica that outlives the pod (a StatefulSet's `volumeClaimTemplates`), never an `emptyDir`. No `fsGroup`, or `fsGroupChangePolicy: OnRootMismatch`; an initContainer as root makes a 0700 subdirectory the broker uses (`install -d -m 0700 -o <uid> -g <uid> …/state`) |
| where each admin socket is reached | on its host: `port49 revoke --socket <the broker's admin_socket>`; port49d's own socket answers `keys diagnose`. Two port49d on one host have a socket each | inside the container: `docker exec <broker container> port49 revoke --socket …`. The image must carry `port49` | inside the pod: `kubectl exec <broker pod> -- port49 revoke --socket …` |
| port49d replicas replace one at a time, the new beside the old | a second unit starts beside the first (its own `listen`, `admin_socket`, `metrics_listen` and spool), then the first stops | a second container starts beside the first, then the first stops | a rolling update with a surge, never `Recreate` |

Each shape's port49d must see the device's true source address (design §13; L39 measures it).
The same recipe holds for each: a `broker.state_dir` that is group-writable, owned by another
uid, or a link is refused at the start, and the line says which.

**The lab, per image** (`tests/lab/results/L36-*`, `L37-*`, `L38-*`, all closed 2026-10-04;
the pinned runs are in each note). L37 cell 1 is a login through A with B stopped; 2, A stopped
and the open session's next command answered by B; 3, the broker stopped; 4, a revocation on
port49-broker; 5, the store hung (`hold_ttl` 60s, `darkBound` 125.5s).

| image | 1 | 2 | 3 | 4 | 5, circuit open / listeners closed (A; B) | break-glass after 5 |
|---|---|---|---|---|---|---|
| vEOS-lab 4.31.2F | `permit` | B answered, same `ctx_id`, `PASS_ADD` 3ms | session ran; `token_redeemed` | `credential_revoked` on A and on B | 50.4s / 2m0.4s; 49.4s / 1m49.4s | logged in |
| N9Kv 10.4(2)F | `permit` | B answered, same `ctx_id`, `PASS_ADD` 3ms | session ran; `token_redeemed` | `credential_revoked` on A and on B | 50.4s / 2m0.4s; 49.4s / 1m49.3s | logged in |
| C8000V 17.13.01a | `permit` | B answered after two refused connections to A, same `ctx_id` | session ran; `token_redeemed` | `credential_revoked` on A and on B | 44.9s / 1m54.8s; 43.6s / 1m53.8s | logged in |
| vJunos-router 23.4R2-S2.1 | login, `show version` | no TACACS+ sent by the device (decision 21); a fresh login through B: `token_redeemed` | session ran; `token_redeemed` | a token minted before it, through B: `token_not_found` | 50.4s / 1m50.3s; 42.9s / 1m52.8s | logged in |
| vSRX3 21.4R3.15 | login, `show version` | as vJunos | as vJunos | as vJunos | 50.4s / 2m0.3s; 42.9s / 1m43s | logged in |

L38 (C8000V 17.13.01a): with both port49d replicas stopped, `show privilege` and `show version`,
each typed first and second in a session, after a permit and after a `FAIL store_unavailable`
(four cells, confirmed by a record and on the wire), were all refused `% Authorization failed.`
The device opened three connections per command, every one refused, and sent no payload. Why
`quarantine-cisco_iosxe.md`'s `show privilege` ran is unexplained.

L36 (vJunos-router and vSRX3, `authorization-time-interval 15`): 15m0s after login, with A
restarted, the device re-authorized the open session and A answered `PASS_ADD` from the
context the store kept. A second session, revoked 1s after its login, was denied at its first
re-authorization (`FAIL`, record `deny credential_revoked`, 1ms) and the device left the session
open: its next `show version` printed an 83-byte error. L40 is open: nothing here says whether
a second re-authorization ever comes.

**7e-2's operator notes, as built.** Each is what an operator sees and does.

*New binary and migration.*
- **`port49-broker`** runs beside `port49d` from `port49-broker.yaml`. Any number of each run
  on one keyspace.
- **Migrating a 7d etcd deployment.**
  - port49d.yaml with a `broker:` block is refused. Move the block, with `store.etcd.broker`,
    into `port49-broker.yaml`; there add `key_refs:` (the names of your `keys:`, no secrets)
    and `broker.state_dir`, remove `broker.revocations_file`, and keep `encryption:`, the
    inventory and `admin_socket`.
  - In port49d.yaml add `policy: {file: <the same policy file>, watch_interval: 5s}` and remove
    `store.etcd.broker`. The marks are already in etcd: every 7d start put the file's there.
  - Run `port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml` and apply
    its output. On the 7d file alone it still works, and says to move the broker's identity.
  - A 7e-2 port49d refused on its config can be rolled back to the 7e-1 binary, which still
    reads the 7d file.
- **Set the same `broker.policy_file` content and `broker.policy_watch_interval` on every
  broker.**

*The mint gate.* **What you see:** after a policy edit reaches a broker, its mints answer 503
`store_unavailable` for one store round trip and `port49_broker_mint_gate_closed` reads 1; the line
says `marking the bundle last judged in doubt against this replica's (<bundle>); nothing that
mints is served until it lands, trying again every <wait>`. `/readyz` stays 200, because a
store fault is an alarm and never readiness (design §12). **What to do:** alert on the gauge
at 1 for longer than a minute. That means the store does not answer, or refuses, the broker's
write to `meta/judged`; look at the store and at the broker's etcd role (`port49d store-roles`).
Users cannot mint on that broker meanwhile, but sessions, revocations and the other brokers go
on. It is never an admission.

*A stale-policy replica.* **What you see:** a broker whose policy file lags the others (an edit
not yet rolled out, a file nobody updated) keeps minting under the file it has, until it
reloads. `port49_policy_bundle_matches_runner` reads 0 on it, and it says so. The skew is bounded
only by how long that file stays stale: not by a token's life. **What to do:** alert on the
gauge at 0 for twice `broker.policy_watch_interval` on a broker, and on a port49d for its
settle delay and one `policy.watch_interval` more; fix the file on that host. Right after a
rollout the gauge is 0 until the runner's settle pass, which is expected. Meanwhile the next
takeover purges every unspent token, since no bundle is judged while a replica serves another;
and a context a stale replica's token made is carried by the full pass the replica asks for
when it reloads. On port49d the gauge reads 1 where no bundle has been judged yet.

*An idle port49d goes dark late.* **What you see:** the store hangs and no device is asking.
port49d's probe (one read every `hold_ttl`/6, through the feed fence) opens its circuit after
five failures and it closes its listeners `hold_ttl` later: measured, 1m43s to 2m0s into the
hang at `hold_ttl` 60s, and about 31s at the 15s default (derived from the same rule, not
measured). Until then a device is answered `FAIL store_unavailable` at once. **IOS-XE is locked
out for all of it, a break-glass login too** (its authentication `ERROR` is final, L4/L35); after
the listeners close, break-glass logs in, and an open session's command is refused
`% Authorization failed.` (L38). vEOS, the N9Kv and both Junos images log break-glass in
once the listeners close (L37). **What to do:** nothing shortens it today; keep a console
path to IOS-XE devices. Plan 7f replaces the probe, and carries the gap.

*After an etcd restore: the guard and the runbook.*
- **What you see on a port49d that ran across the restore:** it refuses every token login
  `store_unavailable`; `port49_redemption_restore_guarded` is 1; its line says `meta/witness is
  at revision N, below the M this port49d followed: the store was restored from a snapshot, …;
  every token redemption is refused (store_unavailable) until a broker runner's purge is
  done`. Sessions already open, revocations and the admin socket go on. **A device whose
  authentication `ERROR` is final (IOS-XE, L4) refuses break-glass too while the guard
  stands**, and unlike a hung store a guarded port49d never goes dark, so the lockout lasts as
  long as the guard: keep a console path to IOS-XE devices, and alarm on
  `port49_redemption_restore_guarded` at 1 for longer than it takes to start the brokers.
  **What to do:** start the brokers. When a runner's purge is done it says `the broker runner's
  purge after the restore is done; token redemptions are served again`, and users mint again.
  **If no runner says that line** (its purge landed before this port49d's first read, or a
  first runner with no `witness.json` found `meta/judged` intact because runbook step 3 was
  skipped, so it purged nothing and wrote no `meta/purged`), there are two ways out: delete
  the restored tokens as etcd's root (`etcdctl del --prefix <prefix>v1/t/`) and then restart
  this port49d; or stop every port49-broker, delete `meta/judged`, and start them, so a takeover
  purges and writes `meta/purged`. **Never restart the port49d before the restored tokens are
  deleted:** a restart forgets the drop and redeems them. A port49d started after the
  restore cannot tell; the runbook's token delete covers it. Token logins refused
  `store_unavailable` with the gauge at 0 and `restore_read` errors rising mean port49d cannot
  read `meta/witness`.
- **The runbook** (design §13), in this order:
  1. stop every broker;
  2. restore with `--bump-revision` and `--mark-compacted`, the restored members serving
     clients on loopback only (without those flags, restart every port49d too once the first
     runner has said which marks it put back, never before);
  3. there, as etcd's root: `etcdctl del --prefix <prefix>v1/t/` (a restore brings back every
     token redeemed since the snapshot, and a port49d that reaches the store first would redeem
     it again), then `etcdctl del <prefix>v1/meta/judged` and `etcdctl del
     <prefix>v1/meta/judged_bundle`; only then restart the members on their usual client URLs;
  4. while every broker is still stopped, revoke again every revocation made with every
     broker down since the snapshot: `sudo -u <port49-broker's user> port49-broker revoke
     --offline --config … --principal <p>` (as that user, never root: a state directory the
     broker's user owns is refused to root, and it is never to be chowned to root), or
     `etcdctl put` as root. No broker saw it, so no copy holds it. The offline tool also
     stands its mark in that host's `broker.state_dir/marks.json`; `etcdctl put` leaves no
     copy. Revoked before any broker starts, a broker without the mark never mints for the
     principal, and a port49d restarted at any later step follows the mark from the store;
  5. start the brokers, one whose `broker.state_dir` survived first: a broker whose
     `state_dir` was lost or is new, started first after a `--bump-revision` restore, means a
     forgotten `etcdctl del` is never caught.
  The first runner puts back the marks the restore lost, says how many (naming up to 20), and
  purges the unspent tokens. Lift again anything it put back that was lifted on purpose.
- **A forgotten `etcdctl del` still purges.** Each broker records the latest `meta/witness` it
  saw in `broker.state_dir/witness.json`. A runner that finds the store's witness below it says
  `the store was restored from a snapshot`, naming both revisions, and purges every unspent
  token. A replica with no `witness.json` says it cannot tell; one whose file cannot be read
  moves it aside (`witness.json.bad-<time>`) and purges once. A snapshot taken within about a
  second of the last witness (two, if a broker was killed rather than stopped) is not caught.
  After a restore without `--bump-revision`, a later takeover by another broker may purge once
  more and say the store was restored. The witness purges at the first takeover, not before: a
  port49d serving meanwhile is what the guard and the token delete close.
- **Meanwhile each port49d that ran across the restore keeps the marks it lost in force** and
  names them (`… are missing from the store as its marks feed reloads (…) and stay in force
  here (to release one lifted on purpose, revoke it again on port49-broker, then lift it with
  port49 revoke --lift, or restart this port49d): …`). Each broker that is not the runner keeps
  what its copy holds and names it, so its listener refuses those principals until the put-back
  arrives. A runner whose put-back fails (its store circuit open through the restore) does
  not reload its marks: `port49_store_feed_up{feed="marks"}` is 0 and the line says `… the
  marks are not reloaded until they are back`, tried again every second. Mints and refreshes
  still read the store's marks, so logins are refused; a held connection on that replica is
  not closed by a mark made elsewhere.
- **A lift can be undone.** A lift made while one broker was stopped, or offline with every
  broker down, is put back by that broker's copy when it takes over, and the line names the
  mark. Lift it again while every broker runs (`port49 revoke --lift`). A mark's origin is
  `offline uid <n>` when `port49-broker revoke --offline` made it.
- **A copy that does not decode** is moved aside (`marks.json.bad-<time>`) and the replica
  starts with an empty copy filled from the store: marks the store had already lost before that
  start cannot be put back from it. The line says so, and gives the way back: if etcd was
  restored before the start, stop the replica, repair the moved-aside file and move it back, or
  revoke again each mark another process's "missing from the store" line names. Entries the
  replica does not understand are kept in the file unchanged.
- **After the runbook deletes `meta/judged`,** the first broker start has no judged bundle for
  the reload guard, and says so: check the policy file on every broker host before starting.
  A keyspace judged for the first time purges the unspent tokens at its first takeover.
- **A `meta/superseded_all` that does not decode** fails idempotent replays: delete it as
  etcd's root, and the next purge writes it again.

*`broker.state_dir`.* Keep it across restarts, and back it up with each broker; it holds the
replica's copy of the marks (`marks.json`) and its record of the restore witness. It must be the
directory itself, owned by the user port49-broker runs as (or root), and writable by no group or
other user; a start refuses a symbolic link (point it at the target), a group-writable
directory, and a `marks.json` or `witness.json` owned by another uid or not a regular file,
and says why. A `witness.json` restored from an older backup only weakens the check; it never
purges wrongly. Kubernetes' recipe is in the table above: the default `fsGroupChangePolicy:
Always` makes every directory in the volume group-writable at each mount, so the next start
is refused.

*Running more than one of each.*
- **A second port49d serves beside the first.** List several on each device and replace them
  one at a time; 7d's `Recreate` advice is withdrawn.
- **A login in flight while another process starts** can be denied `store_unavailable` once on
  the process that started. The next login is admitted.
- **`port49_store_keyspace_held`** is 1 on the one port49-broker running the start, the sweep
  and the policy refresh. Alert on its sum over the brokers being 0 for twice `hold_ttl`.
- **Keep every broker host's clock synchronised (NTP).** A replica whose clock runs behind can
  answer an idempotent replay with a token another replica's revocation or refresh deleted:
  its login fails `token_not_found`. Availability only.

*Tokens and policy edits.* A broker rollout keeps everyone's tokens: the runner that takes
over purges unspent tokens only when it finds a policy in force that no runner judged. A token
minted in the moment of such a purge fails `token_not_found`, and `port49 token` works again.
**A policy edit's settle pass deletes more than its first pass.** At max(30s, 2 ×
`broker.policy_watch_interval` + 5s) after a replica swaps in an edit, the runner judges the
tokens again, so one a slower replica minted under the replaced policy is deleted. It deletes
every unspent token minted since the first pass for each (principal, device) whose answer the
edit changed, including tokens minted under the new policy. Availability only.

*Revoking.* Revocation lives on port49-broker's admin socket: `port49 revoke --socket <its
admin_socket>`, on the broker's host, container or pod. `port49 revoke`'s default stays
port49d's socket (OR-1); on etcd a revocation sent there says which socket to use and exits 1.
port49d's socket answers `keys diagnose`; the broker's says to use port49d's. With every
broker down: `sudo -u <port49-broker's user> port49-broker revoke --offline --config
/etc/port49/port49-broker.yaml --principal <p>` on a broker host (as that user, so it can write
the state directory it owns; never chown that directory to root); with none, as etcd's root `etcdctl put
<prefix>v1/rv/principal/<p> '{"kind":"principal","key":"<p>","at":"<now>","origin":"etcdctl"}'`.
Either way every port49d denies the session's next command. The offline tool also stands the
mark in that host's `broker.state_dir/marks.json` (and drops a lifted one), and says so; the
etcdctl path leaves no copy, and an etcd restore from before either loses it until it is revoked
again, before any broker starts (runbook, above). A broker that is busy says `or stop
every port49d`, never port49-broker.

*Other.*
- **A broker restart on a policy file the reload guard refuses** stays not ready (`/readyz` 503)
  and takes no hold until the file is fixed; it says the guard's reason and
  `port49_policy_file_refused` is 1. To apply a deliberate large removal, raise
  `inventory.max_removed_percent` in `port49-broker.yaml` and restart port49-broker, then lower it
  again.
- **With every broker stopped,** open sessions run on, a token already minted logs in, and a
  policy edit changes admission at once and live sessions when a broker returns (L37).
- **New alarms:** `port49_broker_mint_gate_closed` 1 for a minute; `port49_policy_bundle_matches_runner`
  0 as above; `port49_redemption_restore_guarded` 1; `port49_ledger_behind` 1 on the runner;
  `port49_store_keyspace_held` summed 0. The daemon's alarm for its own hold is gone.
- **Floor-only `lw/` records** (a key revoked with no context mark) persist leaseless, at most
  one per (device, username) (7e-1, Task 10).

*Upgrading to 7e-2.*
- **From 7d on etcd:** everything in "Migrating" above, and 7e-1's two notes (the sessions end
  once; `port49d store-roles` is re-applied).
- **From 7e-1 on etcd:** the daemon's role is narrower. The 7e-1 `store-roles` output granted
  `port49_daemon` read on `meta/` by prefix, and 7e-2's port49d refuses to start on it
  (`allowed reading <prefix>v1/meta/judged`). Revoke that grant, then apply the new output:
  `etcdctl role revoke-permission port49_daemon <prefix>v1/meta/ --prefix=true`, then
  `port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml`.
- A keyspace never judged by a 7e-2 runner has no `meta/judged_bundle`: the port49d skew
  gauge reads 1 until the first runner judges. Not an alarm in the first minutes.
- **Rolling back** to 7e-1 is possible while port49d is still on the 7d file; to 7d it ends
  every session again (7e-1's note).

**Interfaces 7e-2 added:** `internal/port49d.Main` and `BrokerMain` (`cmd/port49d` and
`cmd/port49-broker` are shims); `config.LoadBroker`, `Config.Role`, `Config.Policy`,
`Config.KeyRefs`, `BrokerConfig.StateDir`; `store.Marks.Keep`; `etcd.Store.Judged`,
`PutJudged`, `PutBundle`, `DeleteBundle`, `Bundles`, `Witness`, `PutWitness`, `FollowWitness`,
`JudgeInDoubt`, `PutJudgedSince`, `BundlesAt`, `JudgedBundle`, `PutPurged`, `RestoreRead`, `Holder`,
`PutRefreshOwed`, `RefreshOwed`, `ClearRefreshOwed`; `authen.Handler.WithRedeemGuard`;
`guard.Config.Proc`; the gauges `port49_broker_mint_gate_closed`, `port49_redemption_restore_guarded`
and `port49_policy_bundle_matches_runner` in `metrics.Metrics`;
`broker.Broker.RefreshTokens`, `Proc`, `MintGate`, `Say`; `bundle.RaiseBound`, `KeyRefsFile`,
`StopFleet`; the runner and its `markscopy`, `witness` and `restoreguard`; the lab's split
harness (`startSplit`).

**Carried, for later plans:**
- **7f:**
  - the idle go-dark gap (above, L37): a probe that re-pings at `breaker.open_for` after one
    failure is the mitigation to weigh;
  - go-dark proper and the warm context cache, as before;
  - the container shape (Task 1), with a compose test that restarts a broker and keeps its
    `broker.state_dir`.
- **12:**
  - the three shapes' artifacts and tests (roadmap, "Deployment shapes"), each proving a
    restart keeps `broker.state_dir` accepted;
  - the store alarms, now including `port49_broker_mint_gate_closed` and
    `port49_redemption_restore_guarded`.
- **Unassigned follow-ups:**
  - **Ruling 4's residual,** named exactly in the rulings above.
  - **The per-replica self/key bound and revocation slot** (7c's carry). Each replica bounds its
    own callers, so N replicas allow N at once: a rate bound, not a security boundary, since
    every revocation is idempotent. A shared bound needs one more store record per call.
  - **`putBackFileMarks` and `withHeld`** are kept for the memory store's file, which no marks
    feed has called since Task 14. Remove them if the file never returns to etcd.
  - **Gaps in the restore guard** (Ruling 19): a port49d started after the restore has followed
    nothing and cannot tell; a redemption can arrive in the second between the store
    answering again and the next read (closing it needs the redemption transaction to compare
    `meta/witness`, which changes `RedeemAndReceipt` across the store layers); a runner that
    purges before a port49d's first read leaves it guarded until the next purge or a restart.
    The runbook's token delete covers all three.
  - **A copy's extra fields** on a readable entry are lost at the rewrite; the revocation
    survives.
  - **Per-image device behaviour not measured:** a Junos session's re-authorization after the
    first (L40, open). The vJunos-router's first run (a note in `L36-juniper_vjunos-router.md`) is
    one observation with no capture; it asserts nothing here.
  - **7c's M3** (a `revoke` record for a mark that could not be written) and the bulk lift stay
    unassigned, as the carries table said.

### Plan 7f — As built

Executed from `2026-10-05-07f-go-dark-and-context-cache.md` on `feature/go-dark-and-context-cache`
(base `6299148`), each task reviewed. The ledger is
`.superpowers/sdd/2026-10-05-07f-go-dark-and-context-cache/progress.md`, with each task's brief,
report and review beside it. A pre-flight review (2 critical, 10 important, 20 minor) revised the
plan before Task 1 (6299148). What differs from the plan's text, task by task:

- **Task 1 (the container shape; 4982f8c, 879b3eb).** The build host had no BuildKit client, so
  `COPY --chmod` failed; the Dockerfile makes the three writable directories 0700 in the build
  stage and carries each with `COPY --chown=65532:65532`, which builds under both builders, and
  the smoke test asserts the mode. `etcd-init` and `port49d` carry `pull_policy: never` rather
  than a second `build:` of one tag (a race on the classic builder). The setup staging is a
  tmpfs, emptied at exit; the README gains a first-build note. CI's BuildKit build was not run
  here.
- **Task 2 (L39 (a); 5ee1137, 438f364, 93f9471, c02a1b5, fac5dda).** The first run was invalid:
  both proxy modes showed the compose gateway as the source. The cause was the lab's own
  containerlab masquerade rule, which rewrites DNAT'd traffic leaving by the compose bridge, so
  an off-host device never matched. The harness inserts a `nat POSTROUTING RETURN` for the
  device's subnet toward the compose subnet and purges it after (Ruling T2-a); the re-run passes
  in both modes. The claim says only what was measured (below).
- **Task 3 (spec and design; 36dc632, cc64764).** Decision 37 states the health defaults as a
  requirement, not a result; L41 is opened.
- **Task 4 (config; ec7314b, 006cb34).** `store.etcd.health` and `store.etcd.context_cache`. The
  `interval >= call_timeout` check lives in port49d's own store check, not the shape check the
  brief named, which would have refused a broker with `call_timeout` above 1s (Ruling T4-a).
- **Task 5 (the check; 2899c32).** `PingToken`, `watch`, `passes`, `WithRequireLeader` on both
  pings. Survival at the defaults, five runs each: a killed leader's worst run of failed checks
  was 1; one member hung with its connection alive, 2 (4 to 7 of about 18 checks failed). Neither
  reaches `close_after`, so OR-1 holds with no escalation (Ruling 3).
- **Task 6 (go dark; d27d55a, 783c832, 816fe99).** A check cut short by the run ending is not a
  failed check. The restore-guard test needed `close_after` 60, because a restore now keeps etcd
  away for longer than 5s; a sibling at the defaults proves dark, rebind, and a restored token
  still refused until the purge (Ruling T6-a). The cold-start test uses the `open_after` maximum,
  60, not the brief's 600.
- **Task 7 (the cache; f9bdc84, aea763e, e35bf1b, bce0ee7).** Review found the circuit and
  fence timeouts could serve stale past the TTL while etcd answered. `Fence.Behind()` now
  records a feed behind from the moment a read waits on the fence, and clears when the feed
  passes it. An undecodable change evicts what it cannot name; `max_entries` is bounded. The
  etcdtest cluster's restart no longer closes a halted member twice, and retries `EADDRINUSE`.
- **Task 8 (authorization through the cache; e6f1bce, 397090b).** `authz.Engine.Store` also reads
  the cached handle. port49d on etcd has no context revocation writer (the broker's are the
  broker's), so Task 7's carry of routing port49d's own revocation writes was moot. The
  revocation tests pin eviction, not the mark, including a markless revocation (the owner's own
  form). `make compose-smoke` passed at e6f1bce (56s).
- **Task 9 (L41; 9620e03, ebb6f32, 8aed1fc).** Closed on five images. The vEOS image tagged
  4.32.2F reports 4.31.2F; the note says both. Review scoped two sentences that over-claimed
  (design §12's refusal, the spec's dark time against 5.5s).
- **Task 10 (this section).**

**The rulings, as made** (decision 37; Rulings 1–9 of the plan). All nine stood as written. The
two questions for Ryan were answered 2026-10-05 ("yep sounds good, keep going"):

- **OR-1, the health defaults `interval` 1s, `close_after` 5, `open_after` 3:** approved as
  recommended. Task 5's survival runs are the tested reason; none reached 5.
- **OR-2, keep close-and-wait:** approved as recommended. The next run re-reads its files, so a
  certificate renewed or roles applied while dark are picked up with no restart (7d Ruling 12).

Rulings made during execution: PF-a, every pre-flight fix applied to the plan text first; PF-b,
the health state is process-level, the failure gauge carried across runs; PF-c,
`WithRequireLeader` on both pings; PF-d, the compose example ships `context_cache` commented
out and the cache is off for L41; T2-a, T4-a, T5-a, T6-a above.

**Operator notes, as built:**

- **Upgrading.** A port49d config whose `store.etcd.call_timeout` is above 1s now fails to load
  until `store.etcd.health.interval` is raised to at least `call_timeout`. The broker is
  unaffected: it refuses `health` and `context_cache` outright.
- **Go-dark.** Every listener closes within `close_after` × `interval` + `call_timeout` (5.5s at
  the defaults) of the store stopping, idle or loaded: measured 4.8 to 5.5s on five images
  (L41). It was about 2 minutes for an idle port49d at `hold_ttl` 60s. IOS-XE's break-glass
  lockout on a store fault shrinks to that window; nothing port49 answers changes. After the
  store returns, port49d listens again after `open_after` passes in a row, measured 3.5s later.
  Break-glass works while it is dark. The next run re-reads its configuration at a store gone,
  so an edit to `store.etcd.health` or `store.etcd.context_cache`, the policy or the certs,
  made without a restart, takes effect at the next outage.
- **A restore (design §13's runbook) now takes port49d dark** for its duration: the checks fail
  and the listeners close after `close_after` failures, and it listens again after `open_after`
  passes. The restore guard is unchanged: restored tokens are still refused until the runner
  purges.
- **The context cache** is off unless `store.etcd.context_cache.ttl` is set, and the compose
  example ships it commented out. When on, a revocation reaches a cached session at feed speed;
  a hit is also refused while the feed is behind a read (that read goes to the store); through a
  true outage a cached context is served past its TTL only until the listeners close, which
  go-dark bounds to `close_after` × `interval` + `call_timeout` while the health checks fail
  (when the context pool's circuit is open or its slots are refused while etcd answers, the
  bound is `hold_ttl`; the feed's evictions still apply). A failed write through the cache
  (`TouchContext`, `SetPrivilege`) evicts that session's entry, so it stops being served stale
  at once. That is counted
  `port49_context_cache_lookups_total{outcome="stale"}` and said once:
  `serving cached login contexts past store.etcd.context_cache.ttl`. Alert on any increase.
  Dark with etcd healthy: look at `port49_store_fence_timeouts_total`.
- **New metrics:** `port49_store_health_checks_total{outcome}`; `port49_store_health_failures`
  (page on `>= close_after`, held through the outage and resolved at reopen; an
  `increase(port49_store_health_checks_total{outcome="fail"}[10m])` above your threshold is a
  ticket, not a page: `close_after` × `interval` is shorter than any scrape interval, so
  nothing warns before the close); `port49_context_cache_lookups_total{outcome}`;
  `port49_context_cache_entries`.
- **New config refusals:** the health and cache bounds; a `context_cache:` block with no `ttl`;
  either block in `port49-broker.yaml`.
- **Removed:** 7e Ruling 11's probe, and its two-minute idle go-dark.
- **The container shape.** An image (uid 65532; `port49d`, `port49-broker`, `port49`,
  `port49-inventory`) and a compose stack in `deploy/compose`: three etcd members with
  client-certificate auth and port49's roles, one configuration volume per component (no
  container holds both etcd identities; the device key is port49d's alone), and a named
  `broker.state_dir` volume per broker, 0700 and owned by 65532. Never `--scale` the broker.
  CI brings it up, logs a device in, recreates it, and checks the session, a token minted
  before, and `broker.state_dir` were kept.
- **L39 (a), measured; the row stays open.** Through a published Docker port, an off-host
  device's source is kept (modelled with a RETURN rule on the lab host), with the userland proxy
  on and off; a device on another Docker network on the same host is masqueraded to the compose
  gateway and refused `device_mismatch`. A connection docker-proxy itself relays is unmeasured
  (the kernel's DNAT carried both modes). (b) and (c) are plan 12's.
- **L41, closed** on five images (`tests/lab/results/L41-*.md`): dark in 4.8 to 5.5s, listening
  again 3.5s after the store returns, break-glass works while dark. One thing stays recorded, not
  measured: a device that never asks again after the listener returns.

**Interfaces 7f added:** `health` (`every`, `timeout`, `closeAfter`, `openAfter`, `check`) and
`healthState`; `storeCheck`; `passes`; `etcd.Store.PingToken`; `crypt.Cached`,
`crypt.CacheConfig` and `Fence.Behind`; `Ledger.changed`, `rescanned`, `attach`;
`config.EtcdHealth`, `EtcdContextCache`, `HealthSet`, `ContextCacheSet`; the four metrics
above; the lab's `startCompose`.

**Carried, for later plans:**
- **12:**
  - the systemd and Kubernetes shapes, each with its CI test (roadmap, "Deployment shapes");
    the container shape's install page;
  - L39 (b) and (c): Kubernetes behind a Service with `externalTrafficPolicy` `Cluster` and
    `Local`, and with host networking;
  - the alert for `port49_context_cache_lookups_total{outcome="stale"}` and
    `port49_store_health_failures`.
- **Unassigned follow-ups:**
  - **The restore guard's IOS-XE lockout.** A port49d that ran across a restore refuses token
    logins until the purge, and IOS-XE treats the `ERROR` as final, break-glass included.
    Nothing assigned.
  - **A device that never asks again** after the listener returns (L41, recorded not measured).
  - **No port49d end-to-end test of the fence-behind refusal;** the crypt unit test covers it
    (Task 8 review M-3), for the final review.
  - **`passes` is entered only after a store gone,** never at a cold start (Task 5 review M-3).
  - **Counters restart at each dark** (the per-run registry, 7d's known cost; Ruling 2).

### Plan 7g — As built

Executed from `2026-10-05-07g-the-directory.md` on `feature/the-directory` (base `ad4edff`, 63
commits at `fb94981` before this one), each task reviewed, most through several fix rounds. The
ledger is `.superpowers/sdd/2026-10-05-07g-the-directory/progress.md`, with each task's brief,
report and review beside it. A pre-flight review (2 critical, 17 important, 17 minor) revised the
plan before Task 1 (`c4132fa`), and the pin's escape was added after it (`ad4edff`). What differs
from the plan's text, task by task:

- **Task 1 (spec and design; a95b9fc, 35d16ee).** Review fixed eight Important and seven Minor
  findings: the pass takes `user:` principals only and machine principals are exempt; the session
  refresh writes `refreshed_at`; `context_stale` has its own row; readiness never follows the
  directory. Task 19 fixed the residual nits (the `refreshed_at` field comment
  now reads "last verification", design §12's active-login cell carries the OR-1 tag, three
  over-width lines rewrapped).
- **Task 2 (reasons and record fields; d5396e9).** As written.
- **Task 3 (the stamp; ee309a0, 6b2a12a).** `Token.VerifiedAt` rides the seal (a round-trip
  test was missing), a stamp evicts 7f's cache entry, and `Join`'s `RefreshedAt` is the login's.
- **Task 4 (config; f0493b5, 9699846).** `broker.directory` and `broker.refresh_interval`. A
  server `uri` with userinfo is refused at load and no error echoes one (PF7g-c); the simple bind
  keeps `password_env`, the variable by name (PF7g-d); `site_env` naming the password's variable is
  refused, since it would log the password as the site; unreadable bind files stop the start at
  load, not at the first bind.
- **Task 5 (the membership record; 283d91f, 6cfa32b, aadb0f1, 561a93f, 1490676).** Five rounds.
  `DeleteMembership` leaves a tombstone in the record and a `PutMembership` verified before it is
  dropped, one CAS in etcd (PF7g-e): `forget` cannot lose to an in-flight re-verification. The
  record opens with the principal asked for, so a copy under another key opens as nothing (the
  critical finding). The mapping-key index is a claimant set, registered before the record is
  written (PF7g-f): a key is answered only when exactly one claimant has a live, unrefused record
  listing it, so a refused key stays refused and an ambiguous one heals only to its sole claimant.
  Claimants are not pruned on claim (a prune cannot tell a gone record from one about to be
  written); stale ones are filtered at read and lapse with the key.
- **Task 6 (the pool; ad859df, a400a60, 907e61f, 3599969, 7fb4146).** Servers are logged and
  labelled `host:port` (`Server.Label()`, default port added; two servers with one label are refused
  at load). A refused bind starts a pool-wide bind hold-off (PF7g-g, below), which departs from
  design §10; the first refusal does not double it, a repeat does. `Run`'s context is the pool's
  lifecycle: no `Close`, and `Run` closes every bound connection on return.
- **Task 7 (the connection; e1a760f, c83717e, 9005f88, ec8bf0b).** `ldap://` without `start_tls`
  is refused before any dial. A bind keeps the LDAP result code and drops the server's diagnostic.
  gokrb5 flattens its errors to text, so `kerberosRefused` classifies by root-cause tags (pinned
  by tests against a fake KDC; re-run them on a gokrb5 upgrade): a KDC refusal wraps
  `ErrBindRefused`, an unreachable KDC is a fault. A bind holds no lock across the KDC and obeys
  its deadline; `LoadCredentials` refuses at start a principal without a realm, a keytab with no
  key for it, or a `krb5_conf` with no KDC.
- **Task 8 (the mapping; 7cadadc, 11dd432).** Review found that `subject_dn` keys built from
  unescaped DN parts let `alice,OU=admins` bind as alice in grace. Keys and `dn:` ids are now
  built from a canonical DN (each RDN sorted, every RFC 4514 metacharacter and NUL escaped,
  exported as `directory.CanonicalDN`). A principal or username is bytes 0x21-0x7E before any case
  folding; `cn` reads the DER subject and one CN only; a malformed `otherName` fails closed;
  `entryUUID` wins over `objectGUID`. The brief's `sidExtension` test helper omitted the `[0]`
  EXPLICIT wrapper and was fixed (the parser was right). `ValidPin` is exported and config load
  uses it.
- **Task 9 (nested groups; 0eb5f67, c6af69a).** A total-node bound of 2000 and visited sets keyed
  on the canonical DN. `max_depth` truncation is exact: one probe asks whether the last frontier
  has an unvisited parent, so a chain that ends at `max_depth` is not "truncated". `membersOf`
  returns `(dns, capped, cut, err)`; a failing walk returns no groups (a partial result on error
  was a real bug the new tests found).
- **Task 10 (the resolver; 70f9aad, de9ec67, 62b8da4, b3c4bc4).** The mapping and both uniqueness
  searches are one pool `Do`. Only `ErrUnavailable` reaches grace; a refusal is written as a
  stored refusal that grace never overrules. On a store read error at a refusal the record carries
  an unmatchable pin, `unread:` (PF7g-h, below). Pre-warm counts distinct users. Spec §5.7's
  `identity_ambiguous` row also covers a uniqueness search that does not return the entry itself.
- **Task 11 (group subjects; b630ca7, 136ac32, c6089cf, 2ad0ca2, b029248).** `Subject.groupDN` is
  a canonical-form string, so `policy` imports `directory`. A group subject needs a `user:`
  principal. A directory answer with no username is refused (`ErrNoUsername`, mapped to
  `identity_unmapped`); the declared-username fallback is for replay only. The composition ceiling
  rule is PF7g-i (below).
- **Task 12 (the bind; 19b597c, 17ceb7b, 13c37ab).** The principal is mapped at bind and pinned to
  the held connection. A refresh acts as the pinned principal and reads the marks on the pinned
  principal, the legacy email-SAN principal and the key. A connection with no pin under a directory
  is 503 `directory_unavailable` (session kept), never a re-map. `CloseHeld` matches the legacy
  principal. `directory.ForTestsStaticResolver` is the test resolver.
- **Task 13 (mint, explain, identity, revoke, forget; 35e754b, 878d0e1, a2e1b3d, b14a62b,
  74f848d).** `storedMemberOf`: revocation answers read the stored membership and never ask a
  server. Explaining another principal the directory refuses answers 200 with that principal's
  reason in the body; explaining oneself with a refused membership is the caller's refusal (401,
  connection closed). Records name the caller. `port49 directory forget` normalizes its principal;
  the brief's "run it twice" text is gone (PF7g-e). The forget record is emitted without being
  counted as a decision.
- **Task 14 (the policy pass; e8d939a, 0b86155).** The pass judges a member by its stored
  membership. A past-grace, unrefused membership keeps its last-verified username and drops only
  its groups, so an identity-held context is kept, not revoked `identity_unmapped`, in a long
  outage. A store deadline fails the pass; it is not "unverified".
- **Task 15 (the scheduled refresh; 5f8d9df, b967e28).** `RefreshDirectory` verifies with no
  policy held and judges and writes under the hold per principal. `storedMember` applies the
  declared-username check within and past grace (`Resolver.DeclaredBy`). A collided member's
  unspent tokens are cleared at once, in both passes. The scheduled pass passes `sameSource`, so an
  inventory-only swap rewrites nothing. One principal's non-outage directory error leaves that
  principal unverified and the pass continues. `Narrowed` is also set on a widening, which costs a
  re-mint and never revokes (a test pins it). `DefaultStalenessCeiling` is 4h.
- **Task 16 (wiring; e621114, b20f47e).** Both processes open the directory; `Declared` is the
  live policy's declared usernames. The scheduled pass runs in every minting process, a
  directory-less one included (the 4h default would otherwise deny it `context_stale`). The
  grace end-to-end test uses the real clock (about 8s). `policyEnv` now refuses a human subject
  with no `username` on a broker with no directory, and one that declares a `username` on a
  broker with one.
- **Task 17 (L42, L43; a1fe9e9, 4786b4b, 1deabaa, 03f868f, 8668ee2, 19895d1).** Phase 1 built the
  harness and Phase 2 measured it, after an Opus review of each. Deviations: the OpenLDAP seed is
  loaded by `ldapadd` over `ldapi`; Samba needed the SPN `ldap/localhost` and an `acl_xattr`
  setting for the container; the second Samba `netops-oncall` is renamed in after creation. Samba
  GSSAPI over LDAPS is measured under both `ldap server require strong auth` settings (Task 17's
  ruling). Rule 4 corrected design §10 and decision 38 items 6 and 8 (below).
- **Task 18 (end to end; 38197d0, 3c92b5e, b1df1d4, 31f8709, f8f049d, 175d7c3, 77f01e6, f5b4d06,
  fb94981).** The run found a port49 defect: go-ldap returns no results and no error from a
  search on a connection it has marked closing, which the resolver read as "no such entry", so a
  stopped directory answered `identity_unmapped`, revoked an open session and stored refusals
  grace never overrules. A close before, between or during a search is now a fault, judged per
  page (b1df1d4, 77f01e6; 0 of 30000 probes truncated, also under `-race`). The `context_stale`
  `server_msg` blamed the broker alone and now names both causes (f5b4d06). The brief's recovery
  bound (`refresh_interval` + 30s) was wrong; see the operator notes. EOS (4.31.2F, tagged
  4.32.2F) and vJunos-router (23.4R2-S2.1) pass.
- **Task 19 (this section).**

**The rulings, as made** (decision 38; Rulings 1–20 of the plan). They stood, with these changes,
each recorded in the spec or the design:

- Ruling 3 gained the pin's escape (`ad4edff`, PF7g-b): `port49 directory forget <principal>`.
- Ruling 5 gained PF7g-i.
- Design §10's pool text carries PF7g-g.
- Decision 38 items 6 and 8, and design §10, on GSSAPI and EXTERNAL against AD, were corrected by
  L43's results (rule 4).

**Ryan's answers, 2026-10-06.** The build used each recommendation; Ryan's word follows.

- **OR-1, the defaults** `session.staleness_ceiling` 4h, `directory.grace` 4h,
  `broker.refresh_interval` 5m: **approved by Ryan.** The "provisional on OR-1" tags are lifted.
- **OR-2, GSSAPI through go-ldap and gokrb5 (pure Go):** **approved by Ryan.** A gokrb5 upgrade
  must re-run the classification tests of Task 7.
- **OR-3, Windows Server AD (L44):** **approved by Ryan**, to run on SER8 with a Windows Server
  evaluation image after a usage reset (not before 2026-10-06 15:00). Under register rule 3, L42
  and L43 closed on OpenLDAP and Samba AD, and **L44 stays open** until that run.
- **PF7g-g, the per-server bind hold-off: approved by Ryan.** It deviates from design §10, which
  says a refusal opens no breaker and fails over. With N servers there are N binds per query and
  per 30s check on one service account, and AD keeps the account locked after the password is
  fixed. A refused bind starts a pool-wide hold-off of 1m doubling to 15m, with one probe bind
  per step; each server also has its own refusal backoff, and a probe goes to the best-ranked
  server that has not refused, so one bad DC does not lock the pool. Queries with no bound
  connection fail at once, `directory_unavailable`, and grace serves. The cost: up to 15m of
  grace after a password is fixed.
- **PF7g-i, the composition rule (a spec §5.1 change): confirmed by Ryan.** A member of several
  group subjects holds the union of their grants; the composed `enable` ceiling is the highest
  over subjects whose own `enable` offers escalation. An `enable: none` subject contributes only
  the level it holds without enabling (the lesser of its roles' level and its cap) and never
  creates a ceiling. Without this, a subject (`enable: none`, max admin) and another (`token`,
  max operator) composed to token-to-admin, which neither grants alone.

**Rulings made during execution.** PF7g-a, every pre-flight finding applied to the plan text
first. PF7g-b, the pin's escape. PF7g-c, a `uri` with userinfo is refused at load. PF7g-d, the
simple bind keeps `password_env`; c's "files only" clause is withdrawn. PF7g-e, the forget race is
closed in the store by a tombstone. PF7g-f, the mapping-key index is a claimant set. PF7g-g, i,
above. PF7g-h, on a store read error at a refusal the pin is unmatchable (`unread:`), so mallory
cannot bind as alice and the real alice is held refused until `forget`: security over
availability. Task 17, Samba GSSAPI measured under both strong-auth settings. Task 14, keep the
last-verified username past grace. Task 15, one principal's error does not end the pass. Task 6,
fix round 4 stayed with the Sonnet implementer instead of escalating (the model split).

**Operator notes, as built** (the plan's notes, corrected):

- **Upgrading: the staleness ceiling is on.** `session.staleness_ceiling` defaults to 4h
  (OR-1, approved by Ryan 2026-10-06).
  - **What it does.** Every minting process's scheduled pass re-verifies every live principal
    every `broker.refresh_interval` (5m) and stamps `refreshed_at`, a directory-less broker's
    included. A session whose principal has not been verified for 4h is denied `context_stale` at
    its next command, with a `server_msg` that says the broker is unreachable or cannot verify the
    person's directory membership. It resumes at the next pass after the cause clears.
  - **The opt-out.** `staleness_ceiling: 0s` turns it off, said at every start.
  - **Upgrade order.** Upgrade every broker before port49d. A new port49d (4h default) beside an
    old broker that never stamps `refreshed_at` denies every session 4h after its login. If the
    order cannot be kept, set `staleness_ceiling: 0s` on port49d until the brokers are new.
  - **At 3am, at the ceiling.** Live sessions are denied `context_stale` by a reachable port49d,
    so break-glass does not help on them. The escapes: `session.staleness_ceiling: 0s` and a
    port49d restart, or stop port49d so devices fall back to break-glass (L4). Alert at half the
    ceiling, `time() - port49_directory_refresh_last_complete_timestamp_seconds > ceiling / 2`.
  - **A grace mint near the ceiling** opens a session whose `refreshed_at` is the membership's
    verification, so it can go `context_stale` minutes after it opens, as designed.
  - **Recovery.** After the directory returns, a session resumes within `refresh_interval` +
    `circuit_breaker.probe_interval` + 30s (the health-check tick) at the longest: a server whose
    breaker opened is tried again by the probe, so the first good pass can be a probe interval
    late. The lab measured 1m12s with a 3m ceiling.
  - **A quarantined device's contexts are not stamped.** After a quarantine longer than the
    ceiling lifts, they can be stale for up to one interval. Harmless: the daemon answers nothing
    from a quarantined device meanwhile.
- **Upgrading: principals change with a directory.**
  - A human principal is `user:` + the entry's `principal_attribute`, no longer the email SAN.
    A `user:` identity subject declares no `username:` (refused at load); on a broker with no
    directory a human subject must declare one.
  - Revocation marks made before the change still apply: a certificate is checked against the
    principal its email SAN gave as well as the mapped one. Marks made from now on name the
    mapped principal.
  - **The first scheduled pass after a directory is turned on revokes every live session
    `identity_unmapped`** when `principal_attribute` differs from the email SAN: each session's
    principal is the legacy one, and `Verify` finds no entry for it. That pass also stores a 24h
    refusal for each legacy principal; its pin is empty, so it blocks no one. People log in
    again.
  - **`port49 policy check` does not know the broker's mode** (`DirectoryUnknown`), so CI can pass
    a policy a directory broker (a human `username`) or a directory-less one (no human
    `username`) refuses at reload. Check the mode in the pipeline until a flag exists.
- **Directory hygiene, required.**
  - `principal_attribute` and `username_attribute` must be writable only by directory
    administrators (on OpenLDAP, remove `by self write` on `mail`). Two entries holding one value
    are both refused (`identity_ambiguous`, `username_collision`), so a self-edit can lock a
    colleague out until fixed, but never make one person another.
  - Both attributes need a **case-insensitive equality matching rule**. port49 searches for the
    value to check it is one entry's alone, and a rule that is case-sensitive can miss the entry
    itself. At a bind that search not returning the entry itself is `identity_ambiguous`; at a
    re-check (`Verify`, which searches the lower-cased value) it finds nothing and answers
    `identity_unmapped`, so the scheduled pass revokes the session under that code. A principal
    and username are printable ASCII only.
  - A principal is pinned to the entry it was verified on (`objectGUID` or `entryUUID`): another
    entry later given the same value is refused `identity_unmapped` for as long as the record
    lives (`max(grace, 24h)` after its last verification). An OU move keeps the pin; where the
    directory returns neither id the pin is the DN. A deleted and re-created entry is refused the
    same way, and **so is every user after a directory is restored from scratch**, which changes
    every `entryUUID`: run `forget` for each.
- **`port49 directory forget <principal>`, the pin's way out.** A rehire, or an entry restored
  without its tombstone, has a new id and is refused `identity_unmapped`, and each refusal renews
  the record. The refusal line names the command. Once you have confirmed the new entry is the
  same person, run it on the broker's admin socket (`--socket <its admin_socket>`; the broker's
  uid or root). It deletes the principal's membership, pin included, and writes a
  `directory_forget` record naming your uid and the old entry id. The next bind pins the new
  entry. It grants nothing and needs no directory. A re-verification already in flight cannot
  re-pin the old entry: the delete leaves a tombstone. A principal with no stored record answers
  not found, and nothing is written. If the store write fails the command says so: run it again.
- **A refusal when the store could not be read.** If the store cannot be read at the moment a
  refusal is written, the pin cannot be read either. The record is written with an unmatchable
  pin and the line says so: the principal is held refused, the real person included, until
  `forget`.
- **A principal you explain is verified and pinned.** `explain_others` verifies and pins the
  principal it names, so a **typo stores a 24h refusal** for a name that never existed (and
  verifying a real principal for the first time pins its entry). The refusal is `forget`-able.
- **New: `broker.directory`.** As the plan listed it:
  - **Servers:** `servers` (`uri`, `priority`, `site`, `start_tls`), `site` or `site_env`
    (default `PORT49_SITE`), `ca_file`. Servers rank same-site first, then by descending
    `priority`, then in file order. A `uri` carries no userinfo.
  - **`bind`:** `external` with `tls_cert_file`/`tls_key_file`; `gssapi` with
    `keytab_file`/`principal`/`krb5_conf`; or `simple` with `bind_dn`/`password_env` (the
    variable's name; the password is never in the file).
  - **Where to search:** `base_dn`, `groups_base_dn`, `user_filter`, `group_filter`.
  - **Attributes:** `principal_attribute`, `username_attribute`, `group_name_attribute`,
    `member_attribute`.
  - **`certificate_mapping`:** `kind`, `attribute`, `allow_weak`, `issuers`.
  - **Nesting:** `nested_groups` (required: `in_chain`, `recursive` or `direct`), `max_depth`.
    The walk stops at 2000 groups.
  - **Timing:** `query_timeout`, `health_check` (`timeout` has **no lower bound**: a tiny or
    negative value fails every probe, opens every breaker and the pool is dark, failing closed),
    `circuit_breaker`, `failback`. The `failback.stability_window` default (5m) is not OR-1's.
  - **Outages:** `grace`, `prewarm`.
- **Nested groups need the right mode per directory** (L42).
  - **OpenLDAP needs `recursive`.** `in_chain` answers an empty set with no error (it fails
    closed), and `memberOf` is direct-only. Samba AD answers `in_chain` in full, loop included.
  - **Windows Server AD answers `in_chain` in full too** (L44, 2025): alice's three groups, carol's
    one and dave's two loop groups, in 5 to 6ms with no error. `memberOf` lists direct groups only.
    `recursive` returns the same sets; `direct` returns direct groups only (alice got `g-leaf`
    alone, so a grant on `netops-oncall` would deny her). Use `in_chain`.
  - Group names must be unique: a name that matches several groups is dropped and counted
    (`port49_directory_group_names_ambiguous`). The walk's log line says `revisits` (loops or
    diamonds), not loops. A walk cut by `max_depth` or the node bound is counted in
    `port49_directory_walks_truncated_total`, and pre-warm goes on to the next group.
- **The binds** (L43). Always over TLS; plain LDAP needs `start_tls`.
  - **OpenLDAP:** `external` (mapped by `olcAuthzRegexp`) and `simple` over LDAPS are accepted;
    plain LDAP simple is refused (13).
  - **Samba AD refuses SASL EXTERNAL** (LDAP result 1, operations error). port49 reads result 1
    as a server fault, not a refusal, so **it opens every breaker**: the pool is dark and grace
    serves. Use `simple` or `gssapi` on Samba.
  - **Samba GSSAPI needs `ldap server require strong auth = allow_sasl_over_tls`.** Under `yes` it
    is refused (8) after the KDC issued the tickets.
  - **Windows Server AD: use `external` over `ldap://` with `start_tls: true`** (L44, 2025). Over
    `ldaps://` the DC rejects EXTERNAL with 7 ([MS-ADTS] 5.1.1.2); over StartTLS it maps the
    broker's certificate through `altSecurityIdentities` (port49's `X509:<I>...<SR>...` form) and
    binds it. A 49 means the certificate is not mapped **or that DC's KDC is not answering** (the
    two answer alike): the query fails over to the next DC at once. At 3am, check in this order:
    1. **One DC answers 49 while the others bind:** check that DC's KDC (its Kerberos service).
       The broker log says `directory: <server> refused the bind (external) ...; queries go to
       the next server`.
    2. **Every DC answers 49** (`port49_directory_bind_holdoff_seconds` above 0; the log says
       `no server is bound for ...`): check the broker certificate. Its account's
       `altSecurityIdentities` must hold port49's `X509:<I>...<SR>...` value (L44 e2: with none,
       49), and its issuing CA must be in NTAuth (L44 e3: a CA in Root alone, 49).
    3. **7:** the `uri` is `ldaps://`; switch to `ldap://` with `start_tls: true`.
  - **Windows `gssapi`** is accepted as installed, and refused (49) under
    `LdapEnforceChannelBinding = 2`: **port49 sends no channel binding token.** On a DC that
    enforces it, use `external` or `simple` (both accepted under 2). A 49 to `gssapi` on every DC:
    check `LdapEnforceChannelBinding` (2 refuses it), and that the `uri` host is the DC's own
    FQDN: an `ldap/localhost` SPN added to the DC's account did not stay (twice, within minutes).
    "GSSAPI with channel binding" is a hardening feature carried to the pre-beta review (OR-3).
  - **Windows `simple`** is accepted over LDAPS; plain LDAP is refused (8, strong auth required).
  - **A new Server 2025 forest's defaults differ from an upgraded 2022 domain's**: signing
    enforcement, and channel binding "when supported" against "never" (Microsoft's documentation;
    not measured). L44 measured a new 2025 forest alone (OR-2): a 2022 domain was not measured.
    On the lab DC plain-LDAP simple was refused (8, signing enforced), and `ldapserverintegrity`
    was 1. `StrongCertificateBindingEnforcement` and `LdapEnforceChannelBinding` were absent as
    installed, and the KDC's outcomes were the same with enforcement absent, 1 and 2. Read
    `LdapEnforceChannelBinding` on each DC before choosing `gssapi`.
  - **Writing `altSecurityIdentities` by hand** for an issuer whose RDN holds `\` or `/`: write
    the value as it is, unquoted; the DC's KDC refused the quoted one. An RDN holding a comma, a
    plus sign or an inner quote, or starting with a space, is quoted (inner quote doubled).
  - **Upgrading from an earlier build:** the symptom is `identity_unmapped`. An `issuer_serial`
    lookup for an issuer whose RDN holds `\` or `/` now uses the raw value, not the quoted one. An
    `altSecurityIdentities` entry holding the old quoted value never matched at the KDC, so
    rewrite it unquoted. Against a build from before 7a, 7a also quotes a comma, a plus sign, an inner
    quote and a leading space, and 7b adds the `00` sign byte to a serial whose top bit is set:
    a value written for an earlier build may differ there too. The upgrade impact is nil only
    because port49 is unreleased. A key held in the grace cache under the old value misses until
    the principal is refreshed.
  - The password and the keytab are never logged.
- **A refused bind holds off every bind, except under `external`** (PF7g-g; Task 6). A rotated
  bind password or an expired bind certificate is a refusal by the server (LDAP 49, 48, 8, 13 or 7; a KDC refusal),
  not a down server: queries fail over only to servers already bound, grace serves, and the broker
  says the refusal hourly per server with the result code. The pool holds off every bind for 1m,
  doubling to 15m, one probe bind per step. With N servers all refusing, at most N+4 binds fail
  in the first 30 minutes, then one per 15 minutes; a single misconfigured DC is retried at most
  4 an hour once another accepts. **Exempt the service account from lockout, or set its threshold
  above N+4 per 30 minutes.** After you fix the credential the next probe succeeds within the
  current step, up to 15m; restarting the broker clears it. `port49_directory_bind_holdoff_seconds`
  is the time left. Under `external` a refusal holds off that server alone and the query fails
  over; the pool holds off only once every server whose breaker is not open has refused and none
  is bound (L44 OR-1, PR #36; spec §13 decision 38 item 9). `port49_directory_bind_holdoff_seconds`
  above 0 under `external` therefore means every DC refused.
- **Every breaker open.** Queries are refused at once until the next probe, up to
  `circuit_breaker.probe_interval` plus `health_check.interval` (90s at the defaults) after the
  DCs return. Grace serves meanwhile. A cancelled caller is held up to `query_timeout` plus the
  store budgets, so a burst of cancelled callers is not a hang.
- **New: `broker.refresh_interval`** (5m, approved: OR-1).
- **New reason codes:** `identity_unmapped`, `identity_ambiguous` (alert on it),
  `directory_unavailable`, `composition_refused`. New record fields: `policy.subjects`,
  `auth.directory`, and the `directory_forget` event.
- **New metrics.** Alert on:
  - `port49_directory_lookups_total{outcome="ambiguous"}` increasing;
  - `time() - port49_directory_refresh_last_complete_timestamp_seconds > 3 × refresh_interval`
    (and at half the ceiling, above);
  - `port49_directory_server_up == 0` for a while;
  - `port49_directory_group_names_ambiguous > 0`.
- **The diff:** a changed `group:` now fails `port49 policy diff` until a session test names the
  subject.
- **Group subjects mint** for their members (nested per `nested_groups`). A member of several
  subjects holds the union of their grants, the least `token_ttl` and the most demanding
  `enable`; the composed ceiling is PF7g-i's. A combination a joint check refuses is
  `composition_refused` on that device.
- **`/v1/identity`** answers the subjects, groups, username, and the membership's `verified_at`
  and source.
- **A directory outage.**
  - **Logins.** New logins and mints continue from the membership verified within
    `directory.grace` (4h, approved: OR-1), held in the store, so a broker restart keeps
    them (checked on the compose stack). A person the directory refused before the outage
    (deleted, ambiguous, a username taken) stays refused through it. Past grace: 503
    `directory_unavailable`.
  - **Live sessions** continue until the ceiling; a past-grace member keeps the last username, so
    the session is not revoked in a long outage. **That holds for 24h.** The stored membership
    lives `max(grace, 24h)` from its last write and an outage writes nothing, so past 24h a broker
    restart or any policy reload revokes every directory session (`identity_unmapped` or
    `no_grants_matched`), whatever `staleness_ceiling` is set to, `0s` included. Carried to the
    pre-beta review.
  - **A removed member's tokens.** A member removed from a group who holds a token and no context
    is not reached by the scheduled pass; the exposure is bounded by `token_ttl` +
    `refresh_interval`. `port49 revoke` cuts someone off at once.
  - **Revocation.** `port49 revoke` works throughout and needs no directory; revoking your own
    sessions never asks it.
  - **A stopped directory** is a fault, not "no such person": a close before, between or during a
    search is judged per page. A defect that read it as `identity_unmapped` was found by the
    end-to-end run and fixed.
  - **Readiness** never follows the directory: a broker with every DC down stays ready.
- **Lab:** L42 and L43 **closed** on OpenLDAP and Samba AD, 2026-10-05
  (`tests/lab/results/L42-openldap.md`, `L42-samba_ad.md`, `L43-openldap.md`, `L43-samba_ad.md`).
  L44, Windows Server AD, **closed** 2026-10-07 on Windows Server 2025 alone
  (`tests/lab/results/L44-windows_ad.md`; "L44 — As built", below). The `issuer_serial` and `sid`
  rows on Samba show only that port49's form finds the attribute it wrote; the DC's own
  acceptance is L44's, and its answer to the quoting question this bullet once carried (Windows
  quotes a `,` in `<I>`) is that port49's form had to quote it: fixed in 7a. The end-to-end on the compose stack (a nested grant, a
  removal, grace to the ceiling, recovery) ran on EOS and vJunos-router
  (`tests/lab/results/directory-e2e-*.md`); it is not a register row.

**Interfaces 7g added:** `directory.Resolver` (`Map`, `Verify`, `Current`, `Stored`, `DeclaredBy`,
`Prewarm`), `directory.Answer`, `Source`, `Pool` (`Do`, `Check`, `Run`), `Server.Label`,
`Credentials`/`LoadCredentials`, `Dialer`, `Refusal`, `CanonicalDN`, `ValidPin`, `IsUser`,
`ErrNotUser`, `ForTestsStaticResolver`, `ForTestsFuncResolver`; `store.Membership` (with
`Refused`), `MapKey`, `PutMembership`, `GetMembership`, `DeleteMembership`,
`RefuseMapKeys`, `MembershipByKey`, `MembershipPrincipals`, `TombstoneFloor`, `StampRefreshed`,
`ContextPolicy.RefreshedAt`, `Token.VerifiedAt`; `policy.Member`, `ResolveMember`, `HasRightOf`,
`SubjectsOf`, `ExplainMember`, `ErrCompositionRefused`, `ErrNoUsername`; `broker.BindMap`,
`CertIdentity`, `callerOf`, `memberFor`, `storedMember`, `storedMemberOf`, `passJudge`,
`RefreshDirectory`, `Forget`; `decision.EventDirectoryForget`, `decision.Forget`,
`admin.Server.Forget`, `adminForget`, `directoryCmd`; `config.DefaultStalenessCeiling`,
`StalenessOff`; the metrics above and `port49_directory_bind_holdoff_seconds`.

**Carried, for later plans:**
- **7h:** OIDC principals resolve groups through `Resolver.Verify` (`user:` + the claim the
  deployment names), and `/v1/logout`.
- **8:** the workload verifier calls `Resolver.Map` for a workload certificate's directory entry,
  where decision 16 allows one.
- **12:** the directory alerts, and the systemd and Kubernetes shapes' keytab and `PORT49_SITE`:
  - `port49_directory_refresh_last_complete_timestamp_seconds` older than 3 × `refresh_interval`;
  - any increase of `port49_directory_lookups_total{outcome="ambiguous"}`;
  - `port49_directory_server_up == 0`;
  - `port49_directory_group_names_ambiguous > 0`.

**Open for the final review** (parked, not fixed here):
- **(a)** A startup warning when `nested_groups: in_chain` meets a root DSE without the AD
  capability `1.2.840.113556.1.4.800` (OpenLDAP answers empty with no error today). Measured
  (L44): `1.2.840.113556.1.4.800` is advertised by Windows Server 2025 AD (yes), Samba AD (yes)
  and OpenLDAP (no); a warning keyed on it would tell `in_chain`'s directories apart (the two
  that answer it advertise it; the one that answers empty does not). The warning stays parked.
- **(b)** Samba's EXTERNAL result 1 is classified a fault, so it opens every breaker; `Refusal`
  was not widened. Consider wording that names the mechanism. Measured (L44): a Windows DC
  answers EXTERNAL with 49 for an unmapped certificate (e2, the same certificate with no
  `altSecurityIdentities`; e3, a certificate from a CA in Root but not in NTAuth) and with 49
  for a mapped one while its KDC is stopped (e5; valid, since the mapped bind succeeded with the
  KDC up before and after it). That is the all-49 case (OR-1's branch (iii), as the brief and
  Ryan named it): the two get one code (49 here, not 1), and Ryan approved a per-DC refusal on
  EXTERNAL (PR #36): no 7c ran, and `Refusal` was not widened.
- `port49 policy check` could take `--directory on|off`.
- The etcd claimant read has no single-revision `WithRev` read (Task 5 n1).
- Stray gssapi goroutines are bounded at about servers × (10s or the deadline), only when the
  caller's context is shorter than `query_timeout` (Task 7); a ctx-aware slot channel would end
  them.
- `held` is per grant, not per subject: an odd policy can be locked out, never escalated; the
  `notCounted` note is untested (Task 11).
- After a collision, for up to 15m each pass deletes tokens the declaring subject mints under that
  username (Task 15 P5); a fail-closed nuisance. There is no unlabeled count of unverified
  principals, every pass reads every stored membership, and a removed member with a token and no
  context is not reached by the scheduled pass (m-2).
- Past 24h of directory outage the membership record expires and a restart or reload revokes
  every directory session (final review M-2); the fix is to keep a live context's `c.Username`
  when no record is stored, or to renew the record's lease, not its `VerifiedAt`, while the
  directory is silent. Docs say so now; the code is carried to the pre-beta review.
- `Narrowed` is set on a widening too (Task 14 M-2); it costs a re-mint.
- `duties` has no test of its own beyond the etcd one (Task 16); `ldapClient` is exercised by the
  lab only.

### L44 — As built

Plan `2026-10-06-07g-l44-windows-server-ad.md`. **L44 closed 2026-10-07** on Windows Server 2025
Standard Evaluation, build 26100.32230 (`tests/lab/results/L44-windows_ad.md`, from the confirm
run at e612b71: 1904s, no INVALID cell). Every Task 6 cell was measured. Task 7's parts landed on
`fix/` branches, each beside its own re-run; Task 8 is the `docs/l44-close` branch.

- **Tasks 1–3 (the harness's pure helpers, the compose project and setup scripts).** `478a47b`,
  `bdfd79c`, `7ccb7cf`. No secret reaches a log, the evidence or a note: a unit test scans the
  scripts, and a guard test pins that lab code never runs `docker inspect` or a compose `config`.
- **Task 4 (the bring-up) and its gate.** `6f9ad57`. The gate run found, and the controller fixed,
  seven harness defects (`fd00e39`, `c21a18e`, `1848d26`, `7b8b76b`, `5c01fd8`, `73a6b08`,
  `f37ad50`); a review approved them with five minors (`3689fc7`, `5122a00`).
- **Task 5 (the measurement).** `edeeaf3`. Reviews added the lab guards: lab tests skip unless
  `PORT49_LAB_L44=1`, and a fresh run refuses to start while a DC is up (an agent's stray
  `go test` once tore down the gate's DC).
- **Task 6 (the runs, the note).** `c84116c`. Eight runs, each fixing what the last one showed:
  an NTDS restart was replaced by a reboot (run 2's `lsass.exe` crash followed the restart; none
  followed a reboot under channel binding 2); the PKINIT client was pinned to MIT 1.22.2
  (Server 2025's KDC answers FFDH PKINIT without MS-PKCA's `paChecksum2` with error 79, and MIT
  1.20 failed every cell with it); the KDC-stop cell registers a start task (an SSH logon fails
  while the KDC is down); EXTERNAL cells run over StartTLS (a DC rejects EXTERNAL on the LDAPS
  port, [MS-ADTS] 5.1.1.2). The harness fixes between runs: `7da9618`, `dde9b3a`, `ddc1fd3`,
  `09929c7`, `ce5f3b4`, `0e5f39c`, `4f81b01`, `7b95b9e`, `36d4bf4`, `e6d3d14`, `6d3fefb`,
  `9040a92`, `7964ac3`, `50ee9ad`, `c9318a0`. Final review (0 Critical, 2 Important, 11 Minor):
  I1 fixed, and minors M1–M7 and M9–M11 fixed (`eed4353`, `9972c3a`, `413a25b`, `11d0f94`); M8
  went to the PR description and M11's leftover long line was parked. I2 (the OR-1 hazard)
  became OR-1; merged as PR #31 (`1b56020`).
- **Task 7 (what the note fired), each spec first.**
  - **7a, the issuer's quoting** (`586266b`, `093a361`) and **7b, the serial's sign byte**
    (`97a054c`), on `fix/l44-mapping`. The re-run at ad1e4a9 added five quirk CAs (`91a74cc`)
    and showed the KDC matches a backslash or a slash as it is and refuses it quoted, so rule 4
    removed them from `adQuote`'s set (`e526922`, `1012d5f`, `7f98da9`, `b30673d`, confirmed at
    e612b71; `8dd4183`), PR #34 (`80bc19e`).
  - **7d, GSSAPI asks `mutual-required`** (`ac46305`, `7ea9b37`, `67555e4`, `5526785`,
    `e3db1d3`), PR #32 (`6e3e41c`). The first Task 6 runs got 49: a defect in port49's client
    (the AP-REQ's mutual-required option was not set), not the DC. L43's Samba cells were re-run
    and did not change.
  - **7c did not run.** Neither OR-1 branch (ii) nor (i) held; see OR-1 below. Instead, Ryan
    approved a per-DC refusal on EXTERNAL (`51f01ad`, spec `bf9bf58`), PR #36 (`8b3cfdf`). It
    also fixed a starvation in the probe order that predated it: refusers now take turns.
  - **The `start_tls` hint** on a 7 to `external` over `ldaps://`, and the 49 hint, are in PR #36.
- **A harness follow-up (PR #37, `4ea7a08`, `0cfa267`).** A kept DC read its clock 7h off after a
  container restart; the DC now runs in the UTC time zone. A fresh run (1894s) and a restart plus
  reuse (484s) passed.
- **Task 8 (the `docs/l44-close` branch, which the controller merges into `main`).** The §15
  row, decision 38 items 1, 6 and 8, design §7 and §10, and this README.

**Deviations from the plan, as built.**
- **`winQuote` in `tests/lab` was not changed; only `adQuote` was.** The plan's reading rule
  removed `\` and `/` from both. `winQuote` keeps Microsoft's documented set, because its
  `-quoted` rows are the evidence that refutes that set: it is the record of the hypothesis, not
  port49's form. `winQuote`'s comment says so (PR #34 review M3).
- **The MIT client is Fedora 43's 1.22.2, pinned by digest, not Debian bookworm's.** The plan's
  text still says bookworm.
- **EXTERNAL is measured over StartTLS**, with one LDAPS EXTERNAL row kept as an observation.
- **The Windows URIs name `dc1.corp.example.com`,** not `localhost`: an `ldap/localhost` SPN left
  the DC's account within minutes, twice, with no event naming who removed it.
- **Task 7 ran on `fix/` branches after 7h, and Task 8 on `docs/l44-close`** (controller R1–R4): the L44
  work edited neither the `Makefile` nor `tests/lab/README.md`, and there is no "Windows Server
  AD (L44)" subsection in `tests/lab/README.md`; Ryan did not ask for one.

**The plan's rulings R1–R8, as they stood** (all stood except R4's transport, see the deviations): R1 Server 2025 alone; R2 `dockurr/windows`
6.06 by digest, from a cached ISO checked by SHA-256; R3 setup only over OpenSSH as the domain
Administrator (`ktpass`'s argv inside the VM is the one command line with a password); R4 "the
certificate the DC maps" measured by PKINIT and by EXTERNAL, under enforcement absent, 1 and 2 (the
run found no difference between them); R5 certificates from AD CS and from the harness's CAs; R6 a
setup failure is never a mapping result (the control gates each block); R7 a closing run is a
fresh DC at the pinned commit; R8 the carried questions answered with data.

**Ryan's answers, 2026-10-07.**
- **OR-1: a per-DC refusal on EXTERNAL.** Measured: an unmapped certificate (e2, e3) and a mapped
  one with the KDC stopped (e5, valid) all got 49. 49 is already a refusal, so a DC with its KDC
  down read as one and held off every bind in the pool. Under `external` a refusal now holds off
  that DC alone and the query fails over; the pool holds off only when every server not open has
  refused and none is bound. Built in PR #36; decision 38 item 9 says it.
- **OR-2: yes.** L44 closes on Windows Server 2025 alone. A 2022 domain was not measured.
- **OR-3: document it.** GSSAPI is refused (49) under `LdapEnforceChannelBinding = 2` because
  port49 sends no channel binding token; `external` and `simple` are accepted there. "GSSAPI with
  channel binding" is carried to the pre-beta review as a hardening feature (it means changing
  go-ldap's GSSAPI client and the bind's design).
- **EXTERNAL over `ldaps://` on AD** is a 7: the operator note says use `ldap://` with
  `start_tls: true`.
- **PR #34 review M2:** the `issuer_serial` lookup for an issuer whose RDN holds `\` or `/`
  changed from the quoted value to the raw one; see the upgrade note under "The binds".

**Carried to the pre-beta review:** GSSAPI with channel binding (above); the CertNameToStr
characters L44 did not measure (empty, trailing white space, `= < > # ;`, newline) are quoted as
Microsoft documents them and unmeasured; an issuer with a multi-valued RDN is `identity_unmapped`
and unmeasured; `identity_unmapped` could print the value it searched.

### Plan 7h — As built

Executed from `2026-10-06-07h-oidc-and-trust-domains.md` on `feature/oidc-and-trust-domains`
(base `2614adc`, 62 commits at `a4b8e83` before this one), each task reviewed, most through
several fix rounds. The ledger is `.superpowers/sdd/2026-10-06-07h-oidc-and-trust-domains/progress.md`,
with each task's brief, report and review beside it. A pre-flight review (2 critical, 13
important, 23 minor) revised the plan before Task 1 (`2614adc`). What differs from the plan's
text, task by task:

- **Task 1 (spec and design; 76ab728, e6e8891, 4eac8dc, 11396dc, 19523c8, 9910174).** Four fix
  rounds. Ruling R-4: an OIDC token a person holds ends at `exp` or `max_token_age`, so cached keys
  cannot outlive it; the 24h `jwks_max_age` cut-off (503 `identity_provider_unavailable`) is the
  broker's own, and the failure matrix keeps the two outages apart.
- **Task 2 (decision, api, store; 6922518, c67d534, 2a30693).** Ruling: two machine verifiers on
  different issuers that list one `client_id` are refused at load, since `app:` + the client id
  names no issuer (decision 39 ruling 22 says so). An empty issuer has no OIDC key.
- **Task 3 (the JOSE layer; f171cad, 6d90c2f, 212075c).** In-house on the standard library (OR-1,
  pending). 1060 Wycheproof vectors, 0 failed, 0 skipped; fuzz clean. Review found base64 that
  accepted CR/LF (token malleability, which breaks `credential_sha256` correlation) and header
  and JWK members read case-insensitively with a duplicate keeping the last; both refused now.
- **Flake (219de50, a0b28fa, f67e7f6, c54618a, 7f79685).** `TestALateReplicasContextIsCarriedWhenItReloads`
  failed about 1 in 20 at the base: a test race (the swap opened the mint gate after the store
  mark landed). The reload answering 503 `store_unavailable` in that millisecond window is the
  anti-escalation gate working; the test waits for it, and spec §5.7's row names the gate.
- **Task 4 (one issuer's keys; f1597b2, 3ced419, e65ed7d, 1062302).** Four rounds. A hung `Save`
  frees the flight and keeps one pending file; one minute gate for `Key` and `Fetch`; an older key
  file is never saved after a newer one; a proxy URL is validated and never printed with its
  password.
- **Task 5 (verifiers per trust domain; 5223b7a, 0e25cde, d4821ab, 5f4ced7).** Claims are read
  through `exactObject`, so a repeated member is refused, never last-wins. Rulings (spec amended
  first, `0e25cde`): `typ` is an allowlist (humans absent or `jwt`; machines also `at+jwt`);
  `act` and `may_act` are refused on a machine token; a claim name outside printable ASCII is
  refused. Also ruled, without a spec amendment (it follows from ruling 2's "exactly one must
  accept"): an unavailable verifier beats an acceptance when the token's verifiers cannot all be
  asked.
- **Task 6 (logout tokens; 168ec02, 84415e0, a3ffd7d).** The controller reversed its own
  provisional fail-closed ruling on review: one acceptance wins, and 503 comes only when no
  verifier accepted and one is unavailable (refusing a validated logout is the anti-revocation
  side). `aud` refuses an empty entry; `jti` is never encoded.
- **Task 7 (config; e41caa8, b6542c2).** Issuer userinfo and opaque forms are refused, as are two
  verifiers whose issuers differ only by trailing slash or case; values in refusals are quoted; a
  verifier's `ca_file` joins the collision list.
- **Task 8 (the store; 76c25ee, c585812, 8104b9e).** `PutOnce`, `TakeOnce`, `PutOIDCOwner`,
  `PutLogout` and `GetLogout`; an owner with no principal or a record with no life is refused. The
  etcd harness gained a 1 MB WAL segment and a sweep of data dirs a dead run left (a full `/tmp`
  failed other suites). Owner and logout records are unsealed, like marks (pre-flight M-9, below).
- **Task 9 (a bearer per request; e2287d7, 66f12a6, 37a87b2).** The sub-logout bound
  (`+ clock_skew`), the owner renewal and the machine exemption are each pinned by a mutation;
  `unmint`'s records carry `auth.oidc`; no test message prints a body that could hold a token.
- **Task 10 (OIDC-only broker, `/v1/config`; d1a5aad, 4c211c4, b1b619f).** A bearer on a
  `NoX509` broker mints (in process and over a real listener); no bearer answers what the broker
  takes, `trust_domain_unresolved`, recorded as `auth.method: oidc`; a human verifier with no
  scopes lists `[openid]`.
- **Task 11 (the OIDC refresh; 6bedfab, a0ea153, 3f81e37, 7bd40b1, c5ca8d9, e9b23ec).** Five
  rounds, the last by a fresh Opus implementer. A refresh marks what it extended whether it
  finishes or fails, so a logout racing it cannot leave an extended context. A sid-less token
  indexes nothing. The operator's recovery lines (`logoutRecovery`) say a logout is not a ban:
  check the decision log, `revoke` then `--lift`, with the broker's own admin socket and, with no
  admin socket, the policy-file grants fallback.
- **Task 12 (back-channel logout; dd9ea52, 08d4208, 99ca10e, 36e122d).** The logout record's life
  is `logoutRecordTTL`, shared with the advised lift time (a test captures the TTL, so the two
  cannot drift); a `PutOnce` that errored gives its `jti` back before the 503, so Keycloak's
  retry cannot be answered 200 and lose the logout; a store failure that wrote nothing says an
  unconditional revoke with its lift time and the `sid` call first; `Logout` and `RevokeSid`
  with no identity fail closed. Origin is exactly `backchannel_logout <issuer>`.
- **Task 13 (`/v1/tokens/revoke` by `sid`; b5a2ac8, 7cf0c84).** The store-fault 503, an issuer
  with no `sid` (never a standing ban), a multi-verifier refusal and the `sid` length bound are
  each mutation-pinned; the answer names every owner principal.
- **Task 14 (port49d wiring; 1f274a6, 3795cbc, 68ed52a).** The opener is `openOIDC` (`openIdentity`
  was taken). Tests poll for the key file, since `Fetch` returning does not mean `Save` ran. The
  state directory comes from `broker.revocations_file`, and a group-writable one is refused (a 7e
  rule). `make test-race` caught a shared `strings.Builder` (`syncBuffer`); from Task 15 every
  implementer ran `make test-race` too.
- **Task 15 (Keycloak harness; 069eb98, 72bea35, 15f1699).** Keycloak 26.4, digest-pinned. A setup
  fault is INVALID, never a measurement; `RedactNote` is Junos-only, so an `oidcNoteLeak` guard
  keeps tokens out of notes; `end_session` URLs keep `id_token_hint` out of errors; the PKI keys
  are 0600.
- **Task 16 (lab; 2914930, 46b8973, 4aa4cb6, cd56f55, a4b8e83).** Split: the controller ran L45 and
  L46 (431s), a Sonnet implementer built the end to end, and each was reviewed before its run. The
  end to end passed on vEOS 4.31.2F (223s). An undelivered logout is INVALID, and an expired ID
  token is not measured. See Lab, below.
- **Task 17 (this section).** The roadmap's status line is not edited here: the L44 work owns a
  line on main, and the controller updates it after the merge.

**The rulings, as made** (decision 39; Rulings 1–24 of the plan). All twenty-four stood. Four
carry an in-flight edit, each in decision 39's text: ruling 2 (`typ` allowlist, ASCII claim
names; `0e25cde`), ruling 21 (`act` and `may_act` refused; `0e25cde`), ruling 22 (machine
`client_id` across issuers; `2a30693`) and ruling 20 (L46 closed, L45 open; `a4b8e83`). Ruling 12
stood as measured on Keycloak. **Ruling 13 is contradicted in one case** (an administrator's "sign
out user" with several sessions; see Lab) and the question is Ryan's. No task departed from a
ruling in a way decision 39's text does not already say, so the spec's "as built" text is not
amended here.

**Ryan's answers.** Pending. The build used each recommendation.

- **OR-1, the JOSE layer in-house on the standard library:** pending; execution proceeded on the
  recommendation (in-house, no new module, checked against Wycheproof, a matrix and fuzzing).
- **OR-2, the defaults** (`clock_skew` 60s, `max_token_age` 2h, `jwks_refresh_interval` 1h,
  `jwks_max_age` 24h, the refresh challenge's 5m): pending; execution proceeded on the
  recommendation (those values).
- **OR-3, hosted providers as their own row, L47:** pending; execution proceeded on the
  recommendation (L47 stays open until measured on an Entra ID and an Okta tenant; the notes say
  measured on Keycloak only).

**Rulings made during execution.** Before Task 1 (planfix, pre-flight M-9), owner and logout
records are unsealed, like marks: a store writer can already delete marks and tokens (sealing
`oo/` records with principal AAD is carried to the pre-beta review). Task 2, two machine verifiers on different issuers list no
shared `client_id`. Task 5, the `typ` allowlist, `act`/`may_act`, ASCII claim names, an
unavailable verifier. Task 6, one acceptance wins (a reversal). Task 7, issuer spelling variants
refused. Task 8, the etcd harness fix. Task 11, a logout is not a ban, and the recovery says so. Task
12, a `jti` is given back on a `PutOnce` error. From Task 15,
`make test-race` on touched packages. Task 16, L46 closes and L45 stays open.

**The operator notes, as built** (the plan's notes, corrected by what the lab measured and the
reviews found):

- **`broker.identity`** (decision 39). As the plan's notes list it:
  - **`humans`:** `x509` with `trust_anchor_file` (one anchor), or `oidc` with `issuer`,
    `client_id`, `principal_claim` (required: `preferred_username`, `email` with
    `email_verified`, or `upn`), `principal_domains` (required, exact), `scopes`, `algorithms`
    (default `[RS256]`) and `ca_file`.
  - **`machines`:** `oidc` with `issuer`, `audience`, `clients` (required: `[{client_id, sub}]`),
    `algorithms`, `ca_file`; the principal is `app:<azp>`, case kept.
  - **Without `broker.identity`,** `broker.client_ca_file` is the verifier as before; with it,
    `client_ca_file` is refused. `x509` under `machines` and `k8s` are refused until plans 8 and 10.
  - **A person's token is never a machine's:** one carrying `auth_time`, `sid`, `nonce`, `scp`,
    `amr`, `act` or `may_act`, an `idtyp` other than `app`, another `sub` than the client's, or an
    unlisted client is refused.
  - **Timing:** `clock_skew` 60s, `max_token_age` 2h, `jwks_refresh_interval` 1h, `jwks_max_age`
    24h (OR-2, pending).
- **The principal claim must be one only your provider's administrators can set.** On Keycloak,
  turn off "edit username", and "trust email" on a realm that brokers another provider.
  Measured (L46): `preferred_username` for a user created as `alice` is `alice`, with no `@`, so
  it is refused `identity_unmapped` unless the username is an address; `email` is the usual
  choice there. Entra ID's `email_verified` is unmeasured (L47).
- **Each provider names its own people** through `principal_domains`; a token naming a principal
  outside them is `identity_unmapped`, and that provider's logout reaches none of your staff.
- **OIDC people need a username source:** the directory's, or an identity subject's `username:`.
  port49 never takes a username or a group from a token.
- **Every OIDC request carries its token** (`Authorization: Bearer`). Its connection counts
  against `broker.max_pending_conns_per_source` (16) while open: raise it for an office behind
  one address. An OIDC-only broker (no `x509` verifier) asks for no client certificate and takes
  no `certificate_status`.
- **The session clock is the provider's `auth_time`;** an older one than
  `session.max_session_age_default` is `session_expired`.
- **Refresh:** `POST /v1/refresh/challenge`, a `prompt=login` login at the provider with that
  nonce, `POST /v1/refresh` with the new ID token. Measured (L46): Keycloak honours `prompt=login`
  and `max_age=0`, moves `auth_time` and echoes the `nonce`; a plain SSO login does not, and
  answers `refresh_not_fresh`.
- **Back-channel logout:** register `https://<broker>/v1/logout` as the client's back-channel
  logout URL, "session required" on. Measured on Keycloak 26.4.7 (L45): the token is
  form-encoded, `typ` `logout+jwt`, carries `iss`, `aud`, `iat`, `exp` (`iat` + 120s), `jti`,
  `sid`, `sub` and `events`, never `nonce`, and `events` also carries Keycloak's
  `revoke_offline_access`.
  - **One session or one person.** A logout at the end-session endpoint, and an administrator
    ending one session, each send one token with that session's `sid` and `sub`. **An
    administrator's "sign out user" over several sessions sends one token naming one session's
    `sid` and the user's `sub`, so only that session ends; the others' device contexts live until
    their session ceiling and their held ID tokens can mint until `exp`.** Until Ryan rules (below),
    end the rest with `port49 revoke --principal <principal>` on the serving process's admin socket,
    and `--lift` it only after the time of the revoke plus `max_token_age` + 2 × `clock_skew`
    (`logoutByHand`'s not-applied form): no logout record stands for the other sessions, so an
    earlier lift lets their held ID tokens mint again.
  - **Keycloak does not retry a logout:** a 503, a 400 and a refused connection each got one
    request, and the end-session endpoint still answered 302. A logout port49 answers 503 is lost
    unless the operator ends it by hand, so the broker says how.
  - **A logout leaves no mark,** so the person can log in again at once. To ban, use
    `port49 revoke`.
  - **`logoutByHand`'s two recovery forms** (the broker prints one):
    - **The logout wrote something:** check the decision log for the `revoke` record whose origin
      is `backchannel_logout <issuer>`, and `port49 revoke --list` for a mark. If it is absent,
      `port49 revoke --principal <principal>`, then `port49 revoke --principal <principal> --lift` after
      the time the line prints (the logout record's life: `max_token_age` + 2 × `clock_skew`), on the serving
      process's own `--socket`.
    - **The logout wrote nothing (store error):** the line says an unconditional revoke with its
      lift time, and the `sid` call first: `port49 revoke --sid SID --sid-issuer ISSUER` (the API form `{"sid", "issuer"}`, gated by a touch).
    - **With no `admin_socket`** (the memory backend) there is no socket to name: the line says
      to cut the principal's grants in `policy_file`, restore them after the ceiling, or configure
      `admin_socket`.
  - **`port49 revoke --sid SID --sid-issuer ISSUER` (API: `POST /v1/tokens/revoke {"sid", "issuer"}`, with a touch)** ends one OIDC session and needs
    `revoke_others`; an `issuer` with no `sid` is refused, never a standing ban.
  - **A `sid` logout ends a certificate-path context an OIDC refresh extended under it.** A
    `sub` logout finds the person through the owner record's life (a day, or
    `session.max_session_age_default` if longer); a renamed person is reached under
    both principals for a day.
  - On Junos, as with every revocation, the open session keeps what it had at login.
- **A provider outage.** Held tokens work against the keys last fetched, kept in the state
  directory across a restart, until `jwks_max_age` after the last fetch; past it every OIDC
  request is 503 `identity_provider_unavailable`. Certificate logins, live device sessions and
  break-glass are unaffected. Alert at half: `time() -
  port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age / 2 or
  absent(port49_oidc_keys_last_success_timestamp_seconds)`, with a `for:` of a few minutes.
  - **The 3am escape:** raise `broker.identity.jwks_max_age` (up to 720h) and restart
    port49-broker where you run one; a port49d restart also restarts device AAA.
  - **In the decision log** an outage's refusals read `trust_domain_unresolved`; tell them from
    bad tokens by the 503s' `identity_provider_unavailable`, the hourly "keys not refreshed" line
    and `port49_oidc_tokens_total{outcome="unavailable"}`. A JWKS with no usable key is a failed
    fetch: the last good keys stand.
- **The state directory.** The kept keys (`oidc-<hash>.json`, 0600, written by rename) live in the
  directory of `broker.revocations_file`, the one port49d and the broker already own. It must be
  0700: a group-writable one is refused at start. **On Kubernetes with an `fsGroup` volume,
  which is group-writable, use a 0700 subdirectory** (plan 12 owns the note).
- **An egress proxy.** `HTTPS_PROXY` and `NO_PROXY` are honoured; the start says which, with the
  password redacted.
- **Upgrade order.** Upgrade every broker replica before setting `broker.identity` or
  registering the logout URL: an older replica answers 404 to `/v1/logout` and that logout is
  lost.
- **Also new:** `port49 revoke --principal app:<client_id>`; `GET /v1/config`'s `oidc` and `methods`;
  `auth.oidc` on every record of an OIDC caller; `revoke` records `by: sid|sub` with
  `oidc_issuer` and `revocation.principals`; API errors `503 identity_provider_unavailable`,
  `401 refresh_not_fresh`, `400 bad_request` for a client certificate and a bearer on one request;
  metrics `port49_oidc_tokens_total{issuer,outcome}`,
  `port49_oidc_keys_last_success_timestamp_seconds{issuer}`,
  `port49_oidc_keys_fetch_failures_total{issuer}`, `port49_oidc_logouts_total{outcome}`. No reason
  code is new.

**Lab.**

- **L46, closed** on Keycloak 26.4.7, 2026-10-07 (`tests/lab/results/L46-keycloak.md`): the control
  held; `prompt=login` and `max_age=0` asked for the password, moved `auth_time` and echoed the
  `nonce`, keeping the `sid`; a refresh-token grant keeps the last `auth_time` with no `nonce`;
  a client-credentials token carries none of `auth_time`, `sid`, `nonce`, `scp`, `amr`, `idtyp`,
  `client_id`, and its `sub` is the service account's fixed id. Rulings 15 and 21 stay
  provisional on L47 alone.
- **L45, measured and open** (`tests/lab/results/L45-keycloak.md`): ruling 12's token shape holds,
  and Keycloak does not retry. In the administrator's "sign out user" case with two sessions,
  Keycloak sent one logout token naming one session's `sid` plus the user's `sub`, which ruling
  13's sid-first logout answers by ending that one session. Closing the row would make ruling 13
  firm while the lab contradicts it, so it stays open on a **decision pending with Ryan**. The
  two options, put to Ryan by the controller on 2026-10-07 (ledger):
  - **(A) Status quo, sid-first.** An administrator's sign-out-user over N sessions ends one; the
    others live until their session ceiling (a refresh needs `prompt=login` at the provider) and
    their held ID tokens can mint until `exp`.
  - **(B) A token carrying both `sid` and `sub` also ends every session of that `sub`.** It fails
    closed, but Keycloak's three cases send indistinguishable tokens, so every RP logout and every
    administrator ending one session would also end the person's other sessions (a re-login).
  - **The controller recommends (B)**, security first; the recommendation is the controller's, and
    Ryan decides. It is a change to ruling 13, a follow-up after the merge.
- **End to end** (`tests/lab/results/oidc-e2e-arista_eos.md`, vEOS 4.31.2F): a Keycloak login mints,
  SSH permits, an RP logout writes a revoke record by `sid` and the open session's next command is
  `credential_revoked`, a new login works, a plain SSO answer to the refresh challenge is
  `refresh_not_fresh`, a `prompt=login` one extends the session, and a client-credentials token
  mints `app:port49-svc`.
- **L47, open:** hosted providers (OR-3).

**The interfaces 7h added.** `internal/oidc` (verifiers, `KeySet`, compact JWS and JWK, logout
tokens, `oidctest`); `store` `PutOnce`, `TakeOnce`, `PutOIDCOwner`, `OIDCOwner`, `PutLogout`,
`GetLogout`, `OIDCKey`, `SidKey`, types `OIDCOwner`, `OwnerPrincipal`, `Logout`; `broker`
`Identity`, `NoX509`, `caller`, `bearerCaller`, `Logout`, `RevokeSid`, `oidcChallenge`,
`oidcRefresh`, `noteOwner`, `loggedOut`; `session.AddSid`; `config` `Identity` and
`BrokerStateDir`; `decision.Revocation.Principals`; the four metrics above.

**Carried forward.**

- **After the merge, on a fix/ branch:** the marks-lift durability fix
  (`fix/marks-lift-durability`; the admin-socket lift answers before the marks copy learns it, so
  a stop before the watch delivers loses the lift and restart re-asserts the mark, fail closed;
  introduced in 7e, `9f4e941`). The diagnosis and a test are in
  `.superpowers/sdd/marks-lift-durability-report.md` and `-fix.diff`; the racy `copyHolds=="10"`
  wait in `TestATakeoverPutsBackAMarkTheStoreLost` goes with it. `logoutByHand`'s "revoke, then
  lift" depends on the lift holding, so the operator docs owe this recovery.
- **For the final review:**
  - **The burst-logout question, answered and fixed.** The broker closed certificate-less
    connections after each logout without saying so, so a second logout on Keycloak's pooled
    connection within about 2s was lost (Keycloak does not retry). Every answer to a request with no
    client certificate now carries `Connection: close`, so the provider opens a new connection; the
    idle close stays as the backstop. A lab recheck (an administrator signs out two users back to
    back, and two requests arrive) is cheap and open.
- **For the pre-beta review:** sealing owner and logout records (`oo/`, with the principal as AAD;
  pre-flight M-9).
- **Parked:** Task 8's re-review N1 (the etcdtest sweep could remove a live data dir where
  containers share `/tmp` across pid namespaces; test-only); Task 11's re-review 4 optional clarity
  note.
- **Ryan's pending answers:** OR-1, OR-2, OR-3, and the L45 sign-out-user decision above.
- **Plan 8:** `x509` under `broker.identity.machines` (refused at load until then); a workload
  certificate's directory entry through `Resolver.Map`.
- **Plan 9:** the agent's OIDC public client with PKCE: `/v1/config`'s `oidc`, the refresh
  challenge as the `nonce` of a `prompt=login` request, the ID token as each request's bearer,
  re-login on `credential_revoked` from a logout, and the provider's refresh token kept per
  design §7.
- **Plan 10:** the `k8s` verifier under `machines`.
- **Plan 12:** the alerts (`time() - port49_oidc_keys_last_success_timestamp_seconds >
  jwks_max_age / 2 or absent(...)` with a `for:`; `port49_oidc_logouts_total{outcome=~"store_error|partial"}`
  increasing; `port49_oidc_tokens_total{outcome="unavailable"}` increasing); per-source admission
  sizing for an office behind one address; and the Kubernetes `fsGroup` note (a 0700
  subdirectory of the volume for the state directory).
- **Plan 13:** the operator docs for all of the above, including the three recovery forms and the
  L45 sign-out-user caveat until it is decided.
- **Unassigned:** L47, the hosted providers (OR-3), with Entra's `idtyp`, `scp`, v2 `aud` and
  missing `email_verified` (pre-flight M-8, C-1).

## Plan 8 — Workload certificates (§19 step 8)

Design §7 "Machine identity" option 2: enrollment, self-renewal, multi-identity subjects,
`username` declared on machine subjects, cross-domain username collision at mint. Unattended
config backup (Oxidized) as the day-one consumer.

### Plan 8 — As built

Executed from `2026-10-07-08-workload-certificates.md` on `feature/workload-certificates` (base
`f789c3f`, which holds the plan and its pre-flight fixes; 65 commits at `9db27c1` before this
record), each task reviewed, most through one to three fix rounds. The ledger is
`.superpowers/sdd/2026-10-07-08-workload-certificates/progress.md`, with each task's brief, report
and review beside it, the pre-flight in `preflight.md` (1 critical, 6 important, 19 minor, applied
before Task 1), and the lab's anomalies and the certificate-status work in `run3-investigation.md`
and `idp-review.md`. What differs from the plan's text, task by task:

- **Task 1 (spec and design; a55a03d, 70ce4b8).** Decision 40, L48–L50 opened, plan 8b named and
  decision 16 deferred to it, not withdrawn. One fix round: the `username_collision` row of §5.7
  had been split across two lines.
- **Task 2 (`internal/spiffe`; e091e75).** One parser for the policy, the verifier and revocation.
- **Task 3 (config; 98db865).** `x509` under `broker.identity.machines`.
- **Task 4 (the chain's anchor decides the domain; e1a9939, 2ae9e10, 2731781).** Ruling: the
  principal is read from the URI SAN's own DER bytes, not `leaf.URIs[0].String()`, which folds
  `SPIFFE://` and drops an empty `#`; ruling 4's "never folded" overrides the plan's code. The
  re-review found a constructed `[6]`, which Go's parser skips, counted as a URI SAN, so it would
  bypass URI name constraints: a constructed `[6]` is refused, and the raw URI count must equal
  `len(leaf.URIs)`.
- **Task 5 (a workload mints; 26b9939, f732acb).** Ruling: a late renewal is counted only on the
  served path, so a revoked certificate raises no false late-renewal alert.
- **Task 6 (the listener; 2cd7060, a569b99, 0e9a6c1).** `Broker.Wire` landed here, not in Task 8:
  port49d's listener had `Map` without `Caller`, which `ErrUnwired` refuses. Ruling: `BindMap`
  refuses a chain ending at both anchors on its own, without asking the directory, answered
  `trust_domain_unresolved` (§5.7), not `identity_unmapped`.
- **Task 7 (revoke and explain by SPIFFE ID; 9dd386d, baa68cd).** The `spiffe://` branch moved before
  the 1024-byte principal guard, so an ID up to `spiffe.MaxLen` (2048) that mints can be revoked and
  explained; every downstream limit was checked (the admin frame is about 2110 of 4096 bytes).
- **Task 8 (port49d; fffecb2, 4e998b6, 7cd3c81).** Ruling: the start lines name the YAML keys as
  written (`broker.identity.machines[].trust_anchor_file`, `broker.identity.humans[].trust_anchor_file`),
  an uncovered anchor's or intermediate's line follows `on_unavailable` instead of saying "will be
  refused" under `allow`, and a run-level test pins that certificate status covers the workload
  anchor (mutation-proven). The plan's operator block and Task 8 text still show the old spelling
  and the refuse-only wording; the notes below are what shipped.
- **Task 9 (`internal/workload`; 567edea, fed0d19, d42d447, 6f070de, 7f0a51f).** Ruling 10 amended
  first (`fed0d19`, `6f070de`): the client talks `https` only, trusts `--broker-ca` alone (never the
  system's roots), follows no redirect, and retries a 502 or 504 like a 503 under the same key. A
  redirect is its own final error (`RedirectError`), not an invented broker code. Backoff jitter
  is pinned by a test.
- **Task 10 (`port49 workload token` and `identity`; 4b6660b, 2893020, 9293d42, edb69aa).** Ruling 10
  amended first (`2893020`): a device whose TSV line would hold a control character is left out
  and said (exit 1, or 77/75 when none is left); an output that cannot be written is 75, and the
  last `--out` stands. `identity` exits 2 on a bad URL or CA, as `token` does, and 77 on a redirect.
- **Task 11 (end to end; 8bd0d3f, 527ef14).** Ruling: an end-to-end test pins that a certificate
  mark does not follow a renewal (ruling 8; Task 7 had pinned only the warning's text).
- **Task 12 (`examples/oxidized`; be18f28, 1b33f0f, c280429).** Rulings: a failed REST call no longer
  stops the later nodes (it is said, and the run exits 75); a skipped node exits 1, as the CLI
  does; unmeasured interval and level claims were made provisional on L49; the README discloses
  `fallback_exposure` and `unenforced_rules`; a lock (`router.db.lock`), and 75 takes precedence
  over 1. shellcheck clean.
- **Task 13 (the L48 and L49 harnesses; 2f4f4bb, 5b252cc, f382ff0, d15c4c4).** Oxidized is pinned by
  digest (0.37.0-101-g65125713; no tag names it). Review found step-ca's entrypoint printing its
  provisioner password to a 0644 log (no log existed yet, nothing leaked): the harness now makes
  its own password file, scrubs the log, and removes the secrets copy at cleanup. Only `router.db`'s
  token column is registered as a secret, so a note may name the account.
- **Task 14 (the lab), split.** 14a, the test code, was reviewed before any lab time (eb824d7,
  f1e5207, 65b04cc). 14b ran four run sets, each harness fix reviewed or verified before the next:
  - **Set 1 (65b04cc), invalid.** L48's local broker would not start (a31ebe3 loads its config
    through port49d's real path). L49 EOS recorded a harness fault as a measurement; the debug
    found Oxidized's default `auth_methods` lacks `keyboard-interactive`, which vEOS needs (L4), and
    the wrapper's `PUT /node/next` with an empty body, which oxidized-web 0.18.1 answers 500 (the
    harness's fake accepted it). Fixes 9f04a95, ec990df, e4715dd, da2fb95, 0a6d546.
  - **Set 2 (0a6d546), a shakedown, not committed.** It measured `auth_methods` set globally costing
    two authentications per stale run on NX-OS and IOS-XE, and two permits missing from the
    example's role. Fixes 8a3bc05, d67c529, 31c329c (Junos sends no `authorize_command`).
  - **Set 3 (31c329c).** EOS, IOS-XE and NX-OS kept. Five anomalies went to an investigator, nothing
    committed until each was called real or harness (`run3-investigation.md`): Junos phase A hit the
    broker's first-takeover purge (a plan 7e product bug the harness walked into; Carried forward);
    L48 cells 3 and 4 were harness faults (argument order; the default `candidate_cap` of 8);
    cell 5 was real (step-ca's CRL is distribution-point scoped, and port49 refused it); cell 6
    was both. Harness fixes bfa22b3, 25ce8f8; vJunos-router re-run at bfa22b3.
  - **The certificate-status work.** Decision 40 ruling 17 (bdfc9cf, then af12318 after review),
    d839fca, 737a229 (`examples/oxidized/step-ca-workload.tpl`; L48 cell 5 measures both leaf
    shapes), ab08dff, 060d016, 88159d5, then the OCSP classes 6b6a1d0, 1cd17cf, f7b96b8; three
    review rounds (`idp-review.md`).
  - **Set 4 (f7b96b8).** L48 and vSRX, PASS. Notes a0b909b and 9ac9c7c; example corrections c48b0be,
    f07ae93, 711b5bb (rule 4); register closed 9db27c1.
  - A runner's background limit killed the vJunos-router run in set 3 and left its compose stack up;
    its cleanup was denied by the permission classifier and Ryan ran it.
- **Task 15 (this section; b0d673c).** The roadmap's status line is not edited here; the controller
  updates it after the merge.

**Controller slip.** The raw capture of L49 EOS run 1 (set 1, at 65b04cc) was lost: a copy loop failed
on `ls`'s colour codes and the lab worktree was then removed with `--force`. Its redacted evidence
pcap and note are archived at `/mnt/images/port49-dbg-captures-2026-10-08/lab-p8/`. The run was
invalid (a harness fault), not a measurement that counted. Run set 2's raw captures and set 3's
killed and purge-hit Junos captures are archived under `/mnt/images/` (`port49-runset2-0a6d546-…`,
`port49-runset3-31c329c-…`); every kept note's capture is in `main` (labpcap audit PASS, 250 pairs).

**The rulings, as made** (decision 40, rulings 1–16 of the plan). All sixteen stood. Those an
in-flight edit or fix sharpened, each in decision 40's text or consistent with it:
- **Ruling 2:** a chain ending at both anchors is `trust_domain_unresolved` at the listener's bind
  too (0e9a6c1).
- **Ruling 3:** read from the SAN's own bytes; a constructed `[6]` refused (2ae9e10, 2731781).
- **Ruling 7:** stood. Its revisit condition did not fire: with ruling 17, L48 measured step-ca's
  CRL usable (a templated leaf revoked 1m after `step ca revoke`). What counts as uncovered was
  amended into its text by this task (b0d673c).
- **Ruling 9:** counted only when served (f732acb).
- **Ruling 10:** amended three times in flight (fed0d19, 6f070de, 2893020). Its exit-code text
  matches `cmd/port49/workload.go`: 75 covers both a deadline and an output that cannot be written.
- **Ruling 13:** both rows closed 2026-10-08, the example corrected to them (9db27c1).
- **Ruling 15:** up to `spiffe.MaxLen`, before the 1024-byte guard (baa68cd).
- **Ruling 17** was added during execution (bdfc9cf, af12318).

**Q1–Q3** (the controller's rulings on recommendation at pre-flight, in decision 40's closing
paragraph). **Q1:** a workload certificate's directory groups are deferred to plan 8b, constrained
to machine-scoped group subjects, not withdrawn (the fix for pre-flight C-1). **Q2:** one
`certificate_status` block, no per-verifier opt-out. **Q3:** mint by `scope` is plan 9's. Ryan has
made no override.

**Rulings made on recommendation during execution.** Each was ruled by the controller on
recommendation; Ryan may override.
- **Task 4, the raw SAN:** the SPIFFE ID is parsed from the SAN's DER, and any disagreement with Go's
  parse is refused.
- **`auth_methods` for EOS alone (measured):** global, it cost two failed authentications per stale
  run on devices that offer `password` (set 2), so it sits under `models: eos: vars`.
- **The wrapper's JSON body for `PUT /node/next`:** oxidized-web 0.18.1 answers 500 to an empty one
  (9f04a95).
- **I4, a revocation stands whatever the list's scope:** stricter than RFC 5280; it matches how
  marks already treat every new entry, and serials are unique per issuer (af12318, ab08dff).
- **R1 and R3, the OCSP classes:** a responder that applies and fails is an outage, retried; one
  that does not apply (no responder, a non-http AIA url, `unauthorized`, a signed `unknown`) is
  final (6b6a1d0, f7b96b8; spec b0d673c).
- **The purge:** a plan 7e broker bug, fixed in its own PR right after plan 8 merges (Carried
  forward); the L49 harness waits the window out (bfa22b3).
- **Also:** Tasks 5, 6, 8, 11, 12 and 13's rulings above; Task 9's redirect as its own final error;
  Task 10's control-character and unwritable-output exits; Task 14's split before lab time and
  "nothing committed until each anomaly is called real or harness"; commit trailers name the
  implementing model.

**Lab.**
- **L48, closed** on step-ca 0.30.2, 2026-10-08 (`tests/lab/results/L48-step_ca.md`, at f7b96b8):
  the requested ID is the leaf's one URI SAN (step's default template adds `serverAuth` beside
  `clientAuth`); renew keeps the ID and the key with a new serial; `step ca renew --daemon` renewed
  at 0.66 of a 15m lifetime; with the CA down the late line came at 0.79 and minting stopped at
  expiry, exit 77 (the CLI's own expiry check); step-ca's CRL is DER, signed by the intermediate,
  fetched over https through `SSL_CERT_FILE`, and scoped by a critical IDP naming its own URL, so a
  default leaf is undecided (503) and a leaf under `step-ca-workload.tpl` was `credential_revoked`
  1m after `step ca revoke`; no step-ca name policy pins one SPIFFE ID (the provisioner's `allow`
  is ignored, the authority's refuses a full URI at start), and a fixed-`uris` template pins it by
  rewriting the request.
- **L49, closed** on Oxidized 0.37.0-101-g65125713, 2026-10-08, on vEOS 4.31.2F, Catalyst 8000V
  17.13.01a, Nexus 9300v 10.4(2)F (at 31c329c), vJunos-router 23.4R2-S2.1 (at bfa22b3) and vSRX3
  21.4R3.15 (at f7b96b8) (`tests/lab/results/L49-oxidized-<platform>.md`): one authentication per
  run, a stale token refused once (`token_spent`), the credential read at `/reload`, no token in
  Oxidized's log; on Junos under set 1.0.0 a backup asks port49 about no command. Not measured: a
  level below `admin`.
- **Example corrections L48 and L49 caused:** `keyboard-interactive` for `eos` alone (e4715dd,
  d67c529); the queue request's JSON body (9f04a95); `show vtp status` (c48b0be) and
  `show inventory all` (f07ae93) in the role; `step-ca-workload.tpl` (737a229); the README's §3, §5,
  §5a and §9 rewritten to what was measured (711b5bb).
- **L50, closed in plan 8b** (2026-10-09, Windows Server 2025 and Samba AD 4.17; see "Plan 8b — As
  built", below).

**The interfaces plan 8 added.** `internal/spiffe` (`ID`, `Parse`, `ParseWorkload`,
`CheckTrustDomain`, `Scheme`, `MaxLen`, `ErrNotSPIFFE`); `broker.Workload` (with `Issued`),
`CertCaller`, `Broker.CertCallerOf`, `WorkloadPrincipal`, `ErrWorkloadUnmapped`, `ReadAnchor`;
`Listener.Caller`, `Broker.Wire`, `ErrUnwired`; `api.LateRenewal` (with `LateRenewalFraction`),
`api.UncoveredStatus`; `internal/workload` (`Client`, `New`, `Config`, `Mint`, `MintOptions`,
`Identity`, `LoadCertificate`, `CertError`, `APIError`, `RedirectError`, `TemporaryError`,
`ErrTemporary`, `DefaultDeadline`); `config.BrokerConfig.WorkloadCAFile`, `oidc.X509Machine`;
`testpki.WriteWorkloadLab`, `RenewWorkload`, `WriteWorkloadLabFrom`, `CA.IssueCA`;
`Policy.SPIFFEIdentities`; the metric `port49_workload_certificates_renewal_late_total`. No reason
code is new.

**Carried forward.**
- **A fix PR right after plan 8 merges: the takeover purge (plan 7e).** port49-broker answers
  `/readyz` and mints before its runner's first takeover, and that takeover purges every unspent
  token: a window of `hold_ttl/3` plus the takeover (5s at defaults, 21s measured) on a first start
  or a start after a policy edit. The device says `token_not_found`, and the only clue is a count in
  the broker's stderr. Recommended fix: `POST /v1/token` answers 503 until this replica sees a
  takeover complete (its own, or `meta/judged` naming the bundle it serves); `/readyz` unchanged. A
  §5.7 reason must be added to the spec first. The facts are in `run3-investigation.md`, "Purge
  facts". The L49 harness waits the window out (bfa22b3).
- **Plan 8b:** a workload certificate's directory groups, constrained to machine-scoped group
  subjects (L50), unless Ryan cancels it. *Built 2026-10-09 (Plan 8b — As built, below).*
- **Plan 9:** mint by `scope` (in "Plan 9" since pre-flight); the agent's per-user config file may
  later serve `port49 workload` too.
- **Plan 10:** the `k8s` verifier joins `machines`. `CertCallerOf` is untouched by it, and a subject
  listing `spiffe://` and `system:serviceaccount:` is the migration spec §2 describes.
- **Plan 12:** the alert `increase(port49_workload_certificates_renewal_late_total[1h]) > 0` (summed
  over replicas); the workload anchor's CRL in each deployment shape, a private CA's https CRL
  endpoint included (`SSL_CERT_FILE`, or a `file:` source).
- **A lab recheck, unassigned** (pre-flight M-15): a Keycloak back-channel logout against a broker
  with a workload verifier, which sends a `CertificateRequest` L45 was not measured with.
- **Plan 13:** the operator notes below; `examples/oxidized/README.md` as the Oxidized page; the
  enrollment page for step-ca, with `step-ca-workload.tpl` and the README's step-ca sections (§2,
  §3, §5); one CA more if a later row measures it.
- **For the final review:**
  - step-ca prints the harness's password once into docker's container log, which stays until
    `down -v` (lab harness; scrubbed from `step-ca.log`).
  - Task 12's deferred minors: no `sync` before the wrapper's `mv`; the `next_adds_job` comment; the
    missing-directory test exercises `exec 9>`, not the `mktemp` branch (N-2).
  - `TestWorkloadE2EFilesLoadForBothRoles` loads the compose stack's configs through the loaders,
    not the daemon's real load path (as `a31ebe3` did for L48's local broker).
  - The late-renewal warning prints "(in )" with under 30s left (`internal/workload/client.go`,
    the rounded duration trimmed to nothing).
  - The `broker.certificate_status` refusal says "required when broker: is present"; it is required
    only with an x509 verifier.
- **For the pre-beta review:** the port49d package takes about 9 minutes to test (538s at the base),
  near `go test`'s 10m default timeout; slowest are the late-replica reload and restored-token purge
  tests.
- **Parked minors** (ledger, "minor (deferred)"): `Workload.Issued` matches on the DN string; one
  attempt can overrun `--deadline` by up to 30s; an explicit `Retry-After` is not jittered; U+2028
  and U+2029 pass the TSV control-character guard (harmless to `awk`); the L48 harness's cosmetic
  nits (a negative lead worded "-1s before", step's ANSI codes quoted in cell 6).

### Operator notes (for the pull request body)

- **Workload certificates** (decision 40).
  - **Configuration.** `broker.identity.machines: [{type: x509, trust_anchor_file: <the CA that
    issues your workload certificates>, spiffe_trust_domains: [<yours>]}]`. At most one, beside at
    most one human `x509` verifier. On step-ca the anchor is its intermediate.
  - **The two anchors** must be different certificates in unrelated hierarchies. The start refuses
    one certificate in both files, or one anchor signing the other, naming both keys
    (`broker.identity.machines[].trust_anchor_file`, and `broker.identity.humans[].trust_anchor_file`
    or `broker.client_ca_file`). An anchor further down the other's hierarchy is refused at each
    request whose chain shows it.
  - **Certificate status.** `broker.certificate_status` is required with any x509 verifier and
    covers both anchors, with no per-verifier opt-out. An anchor or CRL signer no source covers is
    said at start, never a refused start; the line says what happens under your `on_unavailable`
    (refused 503 under `refuse`, admitted unchecked under `allow`). For a workload CA with no CRL,
    turn its CRL on (step-ca's `crl.enabled`), or sync it to a `file:` source, or stop workloads by
    principal; never `on_unavailable: allow` or `disabled: true`, which weaken it for people too. A
    private CA's https CRL endpoint needs its root in the broker's trust store (`SSL_CERT_FILE`,
    measured on L48), or a `file:` source.
  - **step-ca users need `examples/oxidized/step-ca-workload.tpl`.** step-ca 0.30.2's CRL names its
    own URL in a critical issuing distribution point, and port49 applies such a list only to a
    certificate whose CRL distribution points name that URL (decision 40 ruling 17). step-ca's
    default leaf names none, so with that CRL configured every default leaf is refused 503
    `certificate_status_unavailable` and `port49 workload` exits 77, the detail naming the missing
    distribution point. Issue under the template, its `crlDistributionPoints` set to the name
    `step crl inspect` shows. Measured (L48): a templated leaf was refused `credential_revoked` 1m
    after `step ca revoke`.
  - **OCSP.** A responder that applies and fails (no answer, a bad signature, a stale answer) is an
    outage: 503 "try again", and `port49 workload` retries within `--deadline`. A responder that
    does not serve the CA (`unauthorized`, a signed `unknown`), a non-http AIA url, or none at all
    leaves the issuer uncovered: final, exit 77.
  - **The TLS handshake changes for everyone** (pre-flight M-15). A workload verifier makes even an
    OIDC-only broker ask every client for a certificate (`VerifyClientCertIfGiven`), so every
    connection sees a `CertificateRequest`, Keycloak's back-channel logout included. L45 was
    measured without one; a recheck is carried.
  - **The workload CA is the trust root.** Whoever can get it to issue a certificate naming a SPIFFE
    ID is that workload. Restrict each provisioner to its host's own ID. On step-ca 0.30.2 no name
    policy can (L48): a provisioner's x509 `allow` is ignored, and the authority's refuses a full
    URI at start. A provisioner x509 template with the ID fixed in `uris` pins it, by rewriting the
    request, not refusing it: one provisioner per host, its credential that host's alone. The fixed
    `uris` and the CRL distribution point in one template are not measured together.
- **The principal** is the certificate's one URI SAN, a SPIFFE ID with a path
  (`spiffe://corp.example.com/host/oxidized-01`), verbatim, read from the SAN's own bytes.
  - Anything else is refused `identity_unmapped`, over HTTP with the reason.
  - Upper case is refused, never folded.
  - The policy refuses a `spiffe://` identity outside that form at load. The start says which
    identities no verifier can give.
- **No directory for a workload.** It mints with every DC down, never matches a `group:` subject,
  and declares its `username:`. Directory groups for workloads, through a machine-scoped group
  subject only, are plan 8b's.
- **A declared username stands.** Declaring a username a directory user holds locks that user out at
  the next refresh, and CI cannot see it in advance; `username_collision` names both claimants
  (decision 38 ruling 3).
- **Renewal is your CA's job.**
  - port49 needs nothing at a renewal. Measured on step-ca (L48): a renewal keeps the ID and the
    key; `step ca renew --daemon` renewed at about two thirds of the lifetime.
  - A certificate presented with under a quarter of its life left is said once a day and counted in
    `port49_workload_certificates_renewal_late_total`. Each broker replica counts it once, so alert
    on its increase, not on a count.
  - **To stop a workload**, revoke its principal (`port49 revoke --principal spiffe://…`). A mark by
    certificate does not follow a renewal, and `port49 revoke` says so. Revoke at the CA too.
- **`port49 workload token`** mints with no agent, reading the certificate and key each run.
  - It talks to the broker over `https` only, trusting `--broker-ca` alone, and follows no redirect.
  - It pages by `batch_max` under one `Idempotency-Key` per page, and retries 503, 502, 504, 409
    in-progress, 429 and dropped connections within `--deadline` (2m). A 503 for a certificate
    status nothing covers is final, not retried, and no longer says "try again".
  - Tokens go to stdout or `--out` (0600, renamed into place). Output is `--format tsv|json`.
    Under cron, always `--out`: cron mails a job's stdout.
  - Exit 0 all permitted and written; 1 some written, some not (a device denied, or left out
    because its line would hold a control character); 2 usage (flags, the broker URL, an
    unreadable file); 75 temporary: the broker did not answer in time (pages minted before it are
    written) or the output could not be written (the last `--out` stands); 77 nothing minted, and a
    run again will not change it (expired certificate, revoked principal, every device denied,
    uncovered status, or a TLS trust failure either way: the broker's certificate not under
    `--broker-ca`, or the broker refusing the workload's certificate). On 77, and on 75 with
    nothing minted, nothing is written.
  - **A stdout consumer must discard what it read on exit 75**: a failed write may have handed it a
    truncated line. `--out` has no such case.
- **`port49 workload identity`** shows what the broker makes of a workload's certificate. Run it
  after enrollment.
- **Oxidized:** `examples/oxidized/` (the wrapper for cron, Oxidized's config, a policy snippet, the
  step-ca template), measured by L49 on EOS, NX-OS, IOS-XE, vJunos-router and vSRX. The wrapper
  replaces `router.db` only when it has a node to write, so a bad night leaves Oxidized's last one in
  place.
  - The config sets `keyboard-interactive` for the `eos` model alone: vEOS offers no `password`
    method, and set globally it costs two failed authentications per stale run elsewhere.
  - The example's role gained `show vtp status` (IOS-XE) and `show inventory all` (NX-OS), which
    Oxidized sends.
  - On Junos under set 1.0.0 a backup asks port49 about no command: the device's login class for
    the backup account is what limits it.
  - The role is at `admin`; `port49 policy test` reports `fallback_exposure` on EOS and NX-OS (L22).
    A lower level is not measured.
- **`/v1/config`'s `methods`** names how a person authenticates: `x509` only with a human anchor.
- **A known issue, fixed in a follow-up PR:** on a first start of port49-broker, or after a policy
  edit, tokens minted in the first 5–21s may be purged by the broker's own takeover; the device then
  says `token_not_found`. Mint again.
- **Lab:** L48 (step-ca 0.30.2) and L49 (Oxidized on five images) closed; see the notes. L50 was
  open for plan 8b, which closed it (Plan 8b — As built, below).

## Plan 8b — Workload directory groups (design §7; spec §13 decisions 16 and 40 ruling 5)

Deferred from plan 8 by the controller's ruling on its pre-flight Q1 (2026-10-07), on
recommendation: deferred, not cut. Ryan may cancel it. Plan 8 builds no directory path for a
workload, and that stays the default when this is built: a workload with no mapping mints with
every DC down.

- **The constraint.** A machine principal matches only a machine-scoped group subject, never a
  human `group:` subject. Today's `group:` subject carries `attached_roles.humans` and human
  `api:` rights (`buildSubjects` sets `Domain = "humans"`), which design §7 forbids a workload.
  One subject of both domains is a load error. Decision 38 ruling 15's diff gate and the CI report
  cover the machine form as they cover `group:`.
- **The mapping.** Opt-in per verifier (a `directory:` key on the `x509` machine verifier), a new
  mapping kind keyed on the SPIFFE ID: exactly one entry whose attribute equals it. No existing
  kind serves: `issuer_serial` changes at every renewal, `sid` is AD CS's extension, and the weak
  kinds need `allow_weak` and an `issuers:` pin. It is a weak kind under decision 38 ruling 1,
  pinned to the workload anchor, the entry pinned by `objectGUID` or `entryUUID`.
- **The username.** From the entry's `username_attribute`, under decision 38 ruling 3's collision
  rules (amending decision 8), or declared on the machine group subject. Spec text first.
  **Superseded by decision 41 ruling 4:** a `machine_group:` subject declares no `username:` (a
  load error). The username is the declaring identity subject's, else the entry's.
- **Plumbing.** The `IsUser` gates (`memberFor`, `storedMemberOf`, the scheduled refresh,
  `refresh.go`) become per domain; `forget`, pre-warm and `normalPrincipal` for `forget` widen
  past `user:`; the membership record is keyed by the SPIFFE ID.
- **Lab.** Its own row, L50 (opened by plan 8): who can write the attribute on Windows AD (L44's
  box) and on Samba, since "only directory administrators can write it" is a directory-behaviour
  claim.
- **3am, with the mapping configured.** A DC outage past `broker.directory.grace` stops the
  workload's mints (`directory_unavailable`, `port49 workload` exit 75), and its live device
  sessions deny `context_stale` at `session.staleness_ceiling`. The start line and the operator
  notes say so.
- **Cost.** About 6 to 8 tasks and the lab row.

### Plan 8b — As built

Executed from `2026-10-09-08b-workload-directory.md` on `feature/workload-directory` (base
`df198b2`, which holds the plan and its pre-flight amendment 3b67275), each task reviewed, most
through one fix round, then a whole-branch review. The ledger is
`.superpowers/sdd/2026-10-09-08b-workload-directory/progress.md`, with each task's brief, report and
review beside it, and the final review in `final-review.md` (0 Critical, 2 Important, 6 Minor). The
pre-flight (0 Critical, 9 Important, 8 Minor) was applied before Task 1. The rulings are decision 41
of the spec (§13). What the build settled:

- **Rulings Q1–Q6 (the writer's questions, ruled on recommendation 2026-10-09).**
  - **Q1.** The username is the identity subject's declared one, else the entry's. A
    `machine_group:` subject declares none, so no group shares a `(nas, username)` context. The
    brief's "or declared on the machine group subject" is superseded (decision 41 ruling 4).
  - **Q2.** Every workload of a mapped verifier needs an entry: `identity_unmapped` otherwise, and
    a directory outage stops its mints. Opt-in per verifier; the start line says so.
  - **Q3.** `issuers:` is required, as decision 38 ruling 1 requires it for every weak kind.
  - **Q4.** `attribute` has no default; the docs name `uid` or `description` after L50.
  - **Q5.** L50 measured `uid`, `description`, `wWWHomePage` and `url` against four writers: the
    entry itself, Account Operators, a delegated OU administrator and an ordinary user.
  - **Q6.** The start line states the ACL requirement, not L50's status.
- **L50, closed 2026-10-09** on Windows Server 2025 and Samba AD 4.17, same matrix
  (`tests/lab/results/L50-windows_ad.md`, `L50-samba_ad.md`). Ruling 10's final form says what was
  measured and prescribes no deny ACL:
  - an ordinary user writes none of the four attributes;
  - the entry itself writes `wWWHomePage` and `url`, whatever the OU's ACL;
  - Account Operators write all four, whatever the OU's ACL;
  - a delegated OU administrator writes all four, and defeats an inherited deny by adding an allow
    ACE for itself; owning the entry alone gives no write;
  - so the attribute is `uid` or `description`, and whoever can change the entry's ACL decides a
    workload's groups.

  Not measured, and asserted nowhere: a narrower delegation, a persistent Samba `smb.conf` audit
  setting, whether an ACE change is itself logged.
- **Carried to plan 13's docs.** The final review's operator-facing notes, summarized here;
  decision 41 has the text:
  - opting in (the `broker.identity.machines[].directory` block; `kind`, `attribute`, `allow_weak`
    and `issuers` all required) and the cost of it: every workload the verifier accepts needs one
    entry, and an outage past grace stops its mints; without the block nothing changes;
  - choosing the attribute (`uid` or `description` on AD; never `wWWHomePage` or `url`; never the
    broker's `username_attribute` or `principal_attribute`);
  - who decides a workload's groups, directory-change auditing (Windows 5136 and 4662; Samba
    `dsdb_json_audit` at level 5) and the reason the docs prescribe no deny;
  - `machine_group:` subjects: workloads only, `attached_roles.machines`, never `username:`, never
    beside `group:`; moving a subject between the two keys is a gated change in `port49 policy diff`;
  - usernames, including that a mapped workload's entry always needs one canonical, unique
    `username_attribute` value;
  - the 3am behaviour: mints refused 503 `directory_unavailable` past grace (`port49 workload` exits
    75), sessions deny `context_stale` at the ceiling, `/readyz` stays 200 by design (decision 34),
    and the metric and decision records to watch;
  - pre-warm (keep it on; up to twice the searches), `port49 directory forget spiffe://…`, and each
    refusal with its HTTP status (401 `identity_unmapped`, `identity_ambiguous`,
    `username_collision`; 503 `directory_unavailable`);
  - the start lines, quoted with what each means.
- **Parked.**
  - **M-5, for plan 13's docs.** Writing a SPIFFE ID onto a person's entry takes effect at the
    next refresh (within `refresh_interval`); run `port49 revoke user:…` for immediate effect.
    Until then the entry can serve both domains; only a directory administrator can open the
    window (ruling 10), and ruling 4 accepts it.
  - **The Task 8 re-review's four Minors,** none a security issue, judged by the final review.
  - **Declined by the final review:** several SPIFFE IDs in one identity subject share one
    `(nas, username)` (plan 8's intent); refusing the attribute by OID form as well as name.
- **Fixed after the final review.** M-1 (the start line names any entry under the workload
  `user_filter`), M-2 (a lint finding for a spiffe-only subject with no `username:`), M-3 (config
  refuses `attribute` equal to `username_attribute` or `principal_attribute`), M-4 (decision 41
  ruling 4 says the entry always needs a username), M-6 (SPIFFE IDs in the resolver's log lines go
  through `printsafe.Line`). I-2 (the §15 conflict with main) was resolved by the merge 0dcfabc.

## Plan 9 — Agent in full (§19 step 9)

`port49 ssh` with host-key verification and `port49 devices trust`, the OIDC public client,
the in-session re-auth flow, integration examples (design §17 "Integration examples").

**Split 2026-10-09 into four plans, each one branch; a fifth, 9e, added 2026-10-10.** The boundary
is the client's credential. 9a works with today's credential, a PEM key and a certificate. 9b and 9c
change what the agent holds. 9d changes what the broker returns. 9e adds a second way to get 9b's
certificate. Each later plan is written after the one before it merges (CLAUDE.md).

- **9a — Sweeps by scope, the config file, and `port49 ssh`** (`2026-10-09-09a-sweeps-and-ssh.md`,
  written 2026-10-09; branch `feature/sweeps-and-ssh`).
  - **What it builds:** all of plan 8's owed item (mint by `scope`) and the config file plan 3
    owes; `port49 ssh` with `port49 devices trust`, and the certificate path's in-session warning;
    the Netmiko example.
  - **Its rulings and rows:** decision 42; it opens L53 (host keys per platform) and L54
    (`port49 ssh` per platform).
  - **Pre-flight questions,** each ruled as recommended on 2026-10-09 (decision 42 rulings 10, 13,
    2, 9 and 14):
    - **Q1:** wrap the operator's OpenSSH 8.5+, not an `x/crypto/ssh` client. 8.0–8.4 are refused,
      as measured in `tests/ssh-compat/2026-10-09-openssh-askpass.md`.
    - **Q2, for 9c:** PKCS#11 through purego and TPM through go-tpm, both without cgo; the Secure
      Enclave behind a macOS spike.
    - **Q3:** a sweep may name any declared scope, intersected with the caller's grants.
    - **Q4:** `devices trust` learns the address by one mint, or `--address`.
    - **Q5:** inventory host keys and the Python and Ansible clients go to 9d, after L53.
- **9b — Port49-issued user certificates over an OIDC sign-in** (plan 7h's hand-off;
  `2026-10-09-09b-oidc-public-client.md`, written 2026-10-09 and rewritten 2026-10-10 on Ryan's
  direction; branch `feature/oidc-public-client`). Design §7's "the broker MAY issue a short-lived
  client certificate", made v1: a company with neither a PKI nor an IdP-held session on disk can use
  port49, and after the sign-in every session runs on the certificate path.
  - **The sign-in:** `port49 login --oidc`, an authorization-code flow with PKCE (S256) over a
    loopback redirect (RFC 8252), `prompt=login`, `state`, `nonce` and `iss` checked, against
    `/v1/config`'s `oidc` providers. A host with no browser pastes back the address; no device
    grant.
  - **The certificate:** the login generates a key on the host (a 0600 file through
    `userconfig.WritePrivate`; 9c's hardware behind the same signer). `POST /v1/certificate` takes
    the ID token as its bearer, its `nonce` naming the key, its `auth_time` within 5 minutes, once,
    and the broker issues a certificate from its own issuing CA: `certificate_lifetime` (12h,
    1h–24h), the sign-in's `iss`, `sub` and `sid` in a URI SAN.
  - **After it:** the agent runs the existing mTLS path unchanged. Mints, refreshes and a new
    agent's extension of earlier sessions are key signatures (decision 43 ruling 11; D1 dissolves).
    A held certificate is reused while a quarter of its life is left; `--sign-in` forces a sign-in.
  - **One path for people:** a broker that issues takes a person's ID token at
    `/v1/certificate` alone. 7h's bearer verifier stays for machines; its human path retires at the
    pre-beta review (Q1).
  - **The client's config, with no step per user** (Ryan's no-toil rule, 2026-10-10; the toil
    audit's H4). `~/.port49/` holds `config.yaml` and the issued key and certificate, as `~/.ssh`
    does, and no host-key pins. A root-owned `/etc/port49/config.yaml`, shipped by the install, is
    read under it key by key, so a new user's first login is `port49 login` and the sign-in.
    `$PORT49_CONFIG` and `--config` name another file. 9a's `~/.config/port49/config.yaml` is
    refused in one line naming the move. No CA rotation asks anything of a user: the broker sends
    its CA bundle on `/v1/config` (`broker.tls_ca_bundle_file`), each agent keeps it per broker, and
    a login trusts it beside `broker_ca` (ruling 25).
  - **The 3am cases, each a test:**
    - the IdP down: everyone holding a certificate works all day, new agents included; only a
      sign-in fails, and says so;
    - the issuing CA's key missing or unreadable: the broker starts and serves everything else;
      a sign-in is 503 `issuance_unavailable`, and the start says to run `init-issuer`;
    - a back-channel logout: the certificate carries its sign-in's `sid`, so the logout refuses
      its next use and reaches its device sessions; the next login removes it.
  - **The CA:** `issuing-ca.pem` and `.key` in the state directory, made once by `init-issuer`,
    rotated with overlap by `rotate-issuer` (stage, promote, the previous trusted until removed); a
    KMS or HSM is a later swap behind `crypto.Signer`.
  - **Lab:** L55 (Keycloak as the client meets it) and L56 (issued certificates end to end on
    Keycloak and vEOS). L47, the hosted providers, stays unassigned.
  - **Dropped from the 2026-10-09 draft:** tokens in the agent, silent renewal, the browser refresh,
    `id_token_not_renewed`.
- **9b1 — Junos apply-groups and per-user `junoscript`** (Ryan's rulings, 2026-10-11;
  `2026-10-11-09b1-junos-groups-and-junoscript.md`, written 2026-10-11; branch
  `feature/junos-groups-and-junoscript`). Named as `06b1` was: a fix slotted between two plans of
  one step, numbered after the earlier.
  - **Builds:** platform set 1.2.0 (1.1.0 plus `juniper_junos`'s `rpc_entry_denies:
    ["junoscript **", "op **"]`, `op **` as the lab said), the new default. Where a deny is the only
    guard beneath a sent bit or the baseline, the projection keeps the capability shape and adds
    the entry deny, so the CLI deny is the boundary and NETCONF is closed for that subject alone.
    Two CI warnings, `projection_netconf_closed` and
    `projection_deny_beneath_view_configuration`, the latter Ryan's "class grants
    view-configuration, policy denies show configuration"; `policy diff` prints new ones. `devices
    check-config` reads `show configuration | display set | display inheritance`, passes groups
    that change no template, names a group that adds a permission, regex or authentication to one,
    refuses a capture missing an applied group's expansion, drops the NETCONF/XML API services
    rule under 1.2.0, and takes `--batch FILE...`. A readonly with a deny beneath `show **`
    (`show **` less `show configuration **`) projects under 1.2.0 (Ryan's fourth ruling, Task
    5b): `view`, 170 bytes of `deny-commands` with the baseline's `word **` denies in one
    alternative and `xml-mode` sent as nothing beside `junoscript`, allows of `show log`, `show
    firewall` and `show policer` beyond the bits; view-configuration stays out. Set 1.2.0's tree
    adds `save`.
  - **Spec sections:** §8 (the RPC paragraphs rewritten, management services by set, the
    readonly paragraph), §12 (check-config, the projection codes table), §13 decision 44 (ten
    rulings), §14 (two assertions), §15 L26c and the new L57 and L58.
  - **Inherits:** plan 5b's projection (option C, `JunosFacts.DenyBindsRPCs` false, the
    management-services allowlist, `TemplateDrift`); the 2026-09-30 `L26c-junoscript` run (the
    `junoscript` deny measured on both images with a control); the L26c, L12-netconf and
    operator SRX notes.
  - **Leaves:** set 1.1.0 untouched (a released set is never edited); J-Web and JET/gRPC still
    fail check-config under 1.2.0 until measured. A readonly with a show deny gets `show log`,
    `show firewall` and `show policer` only through allows beyond `view`; Task 9 measured them
    running, and `show configuration` refused under a deny elsewhere in `show` (Plan 9b1 — As
    built: the open question for Ryan). view-configuration's whole reach stays undecided.
  - **Lab entries:** opens and closes **L57** (what the inherited capture carries for groups) and
    **L58** (`save` a keyword, bare `xml-mode` refused under the factored `junoscript` deny; Task
    3, gates G3 and G4 stop the plan if not); closes **L26c** (Task 3's entry cells: port 22
    subsystem, exec channel, `op url`, REST, `scp`; Task 9's set 1.2.0 differential).
    vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15.
  - **Controller rulings at pre-flight (2026-10-11):** `web-management`, `extension-service` and
    `rest` keep failing check-config under 1.2.0 unless a lab cell measures the `junoscript` deny
    closing them (decision 44 ruling 6); the allowlist for statements under a template stands;
    verifying the capture is inherited stands; `op **` joins `rpc_entry_denies` only if cell (b)
    measures an `op url` script reaching an RPC past the `junoscript` deny.
  - **Ryan's ruling after pre-flight (2026-10-11):** pre-flight finding 5's remedy goes into 9b1,
    in set 1.2.0, view-configuration kept out of readonly. Building it found the ruling's three
    changes leave the readonly `refused_shape` (view-configuration's carve-outs need `show **`
    as an allow, which beats the deny), so 9b1 adds carved allows and keeps the narrow shape
    where its bits reach every allow (decision 44 ruling 10, R9).
- **9c — Hardware-backed client keys, `per_login_mfa`, and the broker certificate's CRL check**
  (plan 3's two hand-offs; `per_login_mfa` added by Ryan, 2026-10-10).
  - **Keys:** behind one `crypto.Signer`, so `agent.Config.Cert.PrivateKey` and the refresh
    signature (`api.SignRefresh`) take it unchanged:
    - PKCS#11 through purego, for YubiKey PIV and smartcards;
    - TPM 2.0 through go-tpm;
    - the macOS Secure Enclave through purego, experimental and opt-in by name (decision 42 ruling
      13 as Ryan ruled it on 2026-10-12: built without a Mac and marked needs testing).
  - **Policy:** touch and PIN policy are the operator's (design §7: `cached` or PIN-only is the
    default). The PEM file stays as the fallback.
  - **Issued keys too:** `port49 login --oidc` (9b) generates its key in the TPM, the Secure
    Enclave or the token behind the same signer, in place of 9b's 0600 file.
  - **`per_login_mfa`: a second factor at each login to the devices a policy level marks** (Ryan,
    2026-10-10). It is a proof at the login to a matching device, not the daily sign-in, which may
    already include MFA; it is never called `mfa: required`. It extends spec §5.1.4's "`amr` and
    `acr` are recorded … a role that requires MFA is a natural extension". The intended schema,
    illustrative until 9c's spec task fixes it:

    ```yaml
    per_login_mfa:
      accept: [hardware_key_touch]   # or [hardware_key_touch, idp_mfa]
      reuse_for: 15m                 # the default; 0m asks for a proof at every login
    ```

    - **`accept`** is an explicit list of self-describing methods, with no booleans and no `none`;
      leaving the key out is no requirement.
      - `hardware_key_touch`: a touch on an always-touch slot, signing a broker challenge. It is
        instant.
      - `idp_mfa`: a fresh sign-in at the identity provider whose `amr` shows a second factor (an
        Okta push, say). It is a browser round trip at each such login, and operators will see
        the difference.
    - **`reuse_for`** is how long one proof covers further logins to devices under a requirement
      that proof satisfies. It defaults to 15m when left out. The proof is bound to the principal
      and to the agent's session: another agent, or the same person on another machine, proves
      again.
    - **Four levels:** under `defaults` (global), under a role, under an inventory device class or
      tag (`tier: core`, say), and under one device. The strictest that applies wins: the
      intersection of the `accept` lists and the minimum `reuse_for`. A lower level never weakens a
      higher one. An empty intersection is a policy error at load, naming both levels.
    - **Machine principals are exempt** (a workload has no finger to touch a key, and its
      credential is already a key) unless a level sets `applies_to_machines: true`, which is
      spelled out and never implied. So a global or per-device requirement does not break
      automation.
    - **What people see.** A refusal or a prompt names the device, the level that set the
      requirement, and the accepted methods. `port49 explain` and the policy tooling print a
      device's effective requirement: the accepted methods, the effective `reuse_for`, and the
      level each came from, so the default is never invisible.
    - **9c's spec task also writes** how the proof rides the mint (a signature over a mint
      challenge by the touch slot's key) and what a held device session does, on a platform that
      never asks about a command, when the proof is not given.
  - **The 3am case,** a test: the key unplugged mid-session. The held connection still mints, since
    the key was used at the handshake. `port49 refresh` and a reconnect say "insert your key", and
    never end the session.
  - **The CRL check:** the broker certificate's, from the distribution points its chain names (`check`
    passes a link that names none; `require` refuses it; defence in depth: the CA is the operator's).
  - **CI and lab:** SoftHSM2 and swtpm in CI; a new row for a real YubiKey on the SER8 (touch, PIN,
    unplug), if one is to hand.
  - **Built:** see Plan 9c — As built, below, for what was built, what is left (L60, L62, L63, the
    Secure Enclave) and the operator notes.
- **9d — OpenSSH's own host-key handling, and the Python and Ansible clients** (design §17).
  - **Host keys are OpenSSH's job** (Ryan, 2026-10-10; replaces decision 42's pin-first rule). port49
    does not reimplement host-key trust. `port49 ssh` forces `StrictHostKeyChecking=accept-new`
    (never `no`) against the person's own `~/.ssh/known_hosts`: a first connection is accepted and
    saved, and a changed key stops with OpenSSH's own warning and is re-trusted the usual way
    (`ssh-keygen -R`). A thousand-switch Ansible run that has never touched a device trusts nothing
    by hand. 9a's separate pins file, `internal/hostkeys` and `port49 devices trust` leave the user
    flow: 9d removes them, or keeps `devices trust` only as an admin tool if a reason survives
    review. The reason host keys matter at all stays in the docs: the device password is a one-time
    token, and an impostor that takes it can replay it to the real device within its lifetime.
  - **No inventory host keys** (Ryan, 2026-10-10). Keeping every device's key in the source of
    truth, and updating it on every re-key, is not feasible at production scale. port49 stores no
    host keys anywhere. The first-contact window accept-new leaves is the one every SSH user
    accepts, and the docs say so plainly. A shop that wants verified first contact can already
    use OpenSSH's own tools (a managed `GlobalKnownHostsFile`, or host certificates via
    `@cert-authority`), which `port49 ssh` leaves untouched.
  - **Netmiko and Python:** Paramiko's equivalent of accept-new (save an unknown key, and Paramiko
    always refuses a changed one) replaces the example's strict `RejectPolicy`.
  - **Clients:** the Python library (~300 lines: identity, mint, sweep, retry) and the Ansible
    lookup plugin over it.
  - The 9d plan amends the spec (decision 42) to match. 9a's final review I-1 (the direct dial in
    `devices trust`) is moot with the command out of the user flow.
  - **9d must fix `port49 ssh` refusing on a group-writable `~/.config`** (carried from 9b's
    pre-flight 2, m5). After 9b the pins file stays in 9a's `~/.config/port49/known_hosts`, read
    through ruling 6's walk, and 9b's refusal no longer names a `chmod` for a directory. So on a
    host whose `~/.config` is group-writable (Ubuntu's default 0775), `port49 ssh` and `devices
    trust` are refused with no fix to run. The pins file goes away in 9d, which ends it; 9d's
    plan checks that nothing it keeps reads a file under `~/.config` through that walk.
  - **Written 2026-10-13:** `2026-10-13-09d-openssh-host-keys-and-python-clients.md`, thirteen
    tasks, branch `feature/openssh-host-keys-and-python-clients`, base `235beee`; decision 46
    (seventeen rulings). `port49 ssh` reads the operator's `StrictHostKeyChecking` and
    `HostKeyAlias` with `ssh -G` and passes accept-new (their `yes` stands) and the inventory name
    as the alias (theirs stands), nothing else about host keys. `devices trust` is removed, not
    kept as an admin tool: verified first contact is OpenSSH's (a managed `GlobalKnownHostsFile`,
    `@cert-authority`), and pre-seeding keys is the per-device toil ruled out. `userconfig.LegacyDir`
    is unexported, so nothing kept reads under `~/.config`. The Python library drives the CLI
    (`port49 token --json` and `workload token --format json` gain JSON failures); Netmiko keeps
    keys under the inventory name in the operator's known_hosts; the Ansible lookup is
    `port49.client.token`. Gate G1 (Task 2) measures whether OpenSSH 8.5p1's accept-new refuses a
    key of another type under a known alias, as 10.2p1 does. Lab: L53 and L54 stay closed (claims
    amended); L64, L65 and L66 are opened.
  - **Pre-flight 2026-10-13** (1 Critical, 8 Important, 18 Minor; all applied). The thousand-switch
    run above trusts nothing by hand on every path, but its safety holds only where keys are filed
    under the name: `port49 ssh` and the Python client. Ansible's `network_cli` keys host keys by
    `ansible_host`, so an address added to a device in the source of truth is a first contact
    there, and design §17's attack is open under `host_key_auto_add`. Decision 46 rulings 2 and
    15, design §17 and the collection README say so; the README sets `HostKeyAlias={{
    inventory_hostname }}` where the connection runs OpenSSH, and L66 (e) measures each path.
    Whether port49 closes the gap for `network_cli` is carried to Ryan.
  - **Built:** see Plan 9d — As built, below, for what was built, the rows closed, what is carried
    to later plans, and the operator notes.

- **9e — A directory-password sign-in** (Ryan, 2026-10-10; written 2026-10-14, executed 2026-10-14
  to 2026-10-15; see Plan 9e — As built, below). The route for a company
  with neither an IdP nor a PKI: `port49 login` signs the person in by an LDAP bind against
  `broker.directory`, plus a second factor, and the broker issues the same short-lived certificate
  9b issues, so everything after the sign-in is 9b's.
  - **Its spec task decides:** the second factor (TOTP enrolled where, or the directory's own); the
    password's path (to the broker over its TLS, to the directory as a bind over LDAPS or StartTLS,
    never stored or logged, never hashed into `credential_sha256`); lockout and rate limits against
    password spraying, per principal and per source; and what `auth.amr` records.
  - **It amends design §7's "port49 has no password path at all",** written for service accounts:
    a person's password reaches the broker once per sign-in and is never a device credential.
  - **The 3am case, a test:** the directory down, holders of a certificate keep working; only a
    sign-in fails, and says so.
  - **Lab:** a new row on OpenLDAP and Samba AD (the 7g harness), and Windows AD on the SER8.
  - **Order:** after 9d, before plan 10.
  - **Built:** see Plan 9e — As built, below, for what was built, the rulings, the row closed, what
    is carried to later plans, and the operator notes.

### Plan 9a — As built

Executed from `2026-10-09-09a-sweeps-and-ssh.md` on `feature/sweeps-and-ssh` (base `40cbb23`), each
task reviewed, most through one or two fix rounds. The ledger is
`.superpowers/sdd/2026-10-09-09a-sweeps-and-ssh/progress.md`. The pre-flight (0 Critical, 10
Important, 17 Minor) was applied before Task 1. The rulings are decision 42 of the spec (§13).

- **Built** (`git log d6bc054..HEAD`; `make test` passes on every package, about 3,240 tests):
  - **Spec and broker** (ae0446c, c6cdeb2, 26bbb18, 8226bfc, d685ece): mint by `scope`, paged by
    name, with no enumeration oracle.
    - `after` takes up to 255 bytes (`bundle.NameOK`); `scope` and `devices` keep 253.
    - A `devices` key beside `scope` is refused, even when empty.
    - An empty sweep page sits behind the mint gate and writes one `mint deny no_grants_matched`.
  - **`port49 workload token --scope`** (acff6f6, 8802f50): sweeps by the broker's pages, and the
    Oxidized wrapper takes `PORT49_SCOPE`. The minted count excludes denied devices, and a
    cut-short sweep never exits 0.
  - **userconfig** (9e38b8f, 4f994ca, 2e7408a, 61b7428, 1f2c4f9): the per-user config file gives
    `port49 login` its defaults. One top-down path resolver, `resolveOwned`, with `PrivateDir`, walks
    the written and the resolved path. The broker CA is read once and passed to the agent child on
    fd 3 (`--broker-ca-fd`).
  - **hostkeys and `port49 devices trust`** (7589b00, 8773ef8): names match case-insensitively,
    stored as given, and a fold collision needs `--replace`. A pins file with any line port49
    cannot parse is refused whole. The trust prompt goes to stderr.
  - **`port49 ssh`** (f65465e, fa4af0b, cb6965f, 1abc249):
    - the askpass is `/proc/<pid>/exe` on Linux;
    - it fails closed on every askpass error path;
    - it signals its parent through a pidfd-guarded call;
    - it folds the device name's case in the prompt match;
    - it restores the terminal;
    - a stale-socket sweep touches only sockets over 10 s old, so it leaves live sessions alone.
  - **Netmiko example** (085c63f, 198160b, 3685669): stderr is inherited, port 22 only, and a
    host-key mismatch names the device. Netmiko 4.8.0 and Paramiko 5.0.0 refuse a wrong or unknown
    key before authentication.
  - **Lab:** **L53 and L54 closed 2026-10-09 on five platforms** (EOS, NX-OS, IOS-XE,
    vJunos-router, vSRX; 317914c, then re-measured with positive controls and closed again in
    77f3d30; `tests/lab/results/L53-*.md`, `L54-*.md`). `make lab-ssh` re-measures only with
    `PORT49_LAB_REMEASURE=L53,L54` (b19dc76). The re-measure corrected the first close: the scan
    does write a log line on EOS, vJunos and vSRX, the negotiated algorithm is `rsa-sha2-256`, and
    only NX-OS prints a SHA256 fingerprint (404a7c4 fixed the `devices trust` help).
- **Carried:**
  - **Pre-beta review** (final review P1, P2b, P3, P8, P12, and a failure that predates the branch):
    - by-name `no_grants_matched` denies carry no bundle (pre-existing; fix the three denies
      together) (P1);
    - mint bodies accept trailing JSON, here and at the other endpoints' decoders; reject it
      everywhere at once, a second `Decode` returning `io.EOF` (P2b);
    - names of 254–255 bytes can be swept but not named in `devices` (plan 3 F11) (P3);
    - `--broker-ca-fd N` given by hand wraps any descriptor; an `fstat` for `S_IFIFO` is the fix
      (P8);
    - the no-pidfd fallback of the askpass's parent signal has no CI test; `PidfdOpen` needs to be
      injectable (P12);
  - **9b and 9c:** the OIDC and hardware-key credentials, as outlined above; 9a changes nothing the
    agent holds.
    - **9c** (P4): the agent child reads `--cert` and `--key` by path, with the keyfile checks only.
      9c replaces how the agent holds its key.
  - **9d:** inventory host keys and the Python and Ansible clients, in a format that follows what
    L53 measured.
    - Netmiko's host-key check is structural only (P14); 9d's Python client replaces the example and
      takes the mint-carried fingerprint.
    - `devices trust` through a jump host (I-1; above).
  - **Plan 12 and plan 13** (P15): install port49 0755, with no setgid and no file capabilities.
    Otherwise `/proc/<pid>/exe` is unexecutable for the askpass, and the device is sent `""`. Plan 12
    states it as a deployment requirement; plan 13's guide repeats it.
  - **Plan 13** also tabulates the exit codes: `port49 ssh`'s own refusals exit 1, as a remote
    command's exit 1 does (the `port49 ssh:` line tells them apart), and login exits 2 where ssh
    and trust exit 1 for the same refused `~/.config`.
- **Operator-facing notes** (the plan's "Operator notes," as the lab measured them; plan 13 owns
  the guide). **The `devices trust` and pins-file notes below are superseded by plan 9d (Plan 9d
  — As built, below): host keys are OpenSSH's, `devices trust` is gone, and the pins file is no
  longer read. Plan 13 withdraws them.**
  - `port49 login` needs no flags once `~/.config/port49/config.yaml` exists. Keep it, the CA file
    and every directory above them writable by you alone; on Ubuntu run `chmod go-w ~/.config`
    once. `--config FILE` reads another file, which must exist.
  - Pin a device once before `port49 ssh`: `port49 devices trust DEVICE`. Verify the key on the
    console. The lab found: every platform shows the scanned RSA key on a privileged console (EOS
    `show management ssh hostkey rsa public`; Junos `file show /etc/ssh/ssh_host_rsa_key.pub`;
    NX-OS `show ssh key`; IOS-XE `show ip ssh` or `show crypto key mypubkey rsa`). Only NX-OS
    prints a SHA256 fingerprint, so elsewhere compare the key or run `ssh-keygen -lf` on it. Pins
    are keyed by inventory name; `--fingerprint` is for automation; `--replace` after verifying a
    changed key.
  - `port49 ssh DEVICE [-- COMMAND]` needs OpenSSH 8.5 or later; on older ones use `port49 token`.
    It forces public-key authentication off (L51), asks a jump host's password on your terminal,
    and sends the token once to the device's own prompt. A refused token is not retried.
  - A scan by `devices trust` is no TACACS+ exchange and does not count against IOS-XE
    `login block-for` or NX-OS `aaa authentication rejected`. EOS, IOS-XE, vJunos and vSRX log it
    on the device; NX-OS does not.
  - The key survives a reload with the configuration saved, on all five platforms.
  - On EOS, NX-OS and Junos `port49 ssh` prints the session-ceiling warning (L34).
  - `port49 workload token --scope NAME` exits 77 for a scope that selects nothing you hold and a
    scope that does not exist alike. Every mint record a sweep page writes carries `sweep: {scope,
    after}`; the revocation re-check's records do not (decision 42 ruling 4).
  - `port49 devices trust` connects directly, not through your ssh_config's `ProxyJump` or `Port`
    (`port49 ssh` honours both). Behind a jump host, forward a port with `ssh -N -L
    2222:<addr>:22 <jump>`, then run `port49 devices trust --address 127.0.0.1 --port 2222
    --fingerprint SHA256:… DEVICE`. The pin is keyed by the inventory name and authorized by the
    fingerprint you verified, so the forward cannot substitute a key. A scan that cannot dial prints
    this with your device and flags.

### Plan 9b — As built

Executed from `2026-10-09-09b-oidc-public-client.md` on `feature/oidc-public-client` (base
`48a67a3`), each task reviewed, most through one or two fix rounds. The ledger is
`.superpowers/sdd/2026-10-09-09b-oidc-public-client/progress.md`. Two pre-flights were applied
before Task 1. The rulings are decision 43 of the spec (§13).

- **Built** (`git log 48a67a3..HEAD`; `make test` passes on every package, 4,473 passing tests and
  subtests by `go test ./... -v`, counted as 9a's entry was):
  - **Spec** (b8f1f42, 3c47758, then fcf625f, 70f5079, d88413d, 7ab7c26 from reviews): decision 43,
    port49-issued user certificates over an OIDC sign-in, with ruling 8's certifiability check and
    `issue` among the events that carry `trust_domain_unresolved` and `identity_unmapped`.
  - **The test authorization server** (b127c57): PKCE, for the public client's tests.
  - **`internal/oidcclient`** (331ee2e, 1da58ec, 8d7e615, 2b7d2e6): discovery, the code exchange, the
    loopback sign-in with PKCE S256, `state`, `nonce` and `iss`, and a pasted address. An empty nonce
    and a repeated `iss`, `state` or `code` are refused, and the code and verifier stay out of errors.
  - **`internal/issuer` and `POST /v1/certificate`** (52d8cf9, 3fe2af3, 97be208, fd4e3e0, 3b1f1ce,
    0c20bad, a4d8a5b): the issuing CA, the sign-in a certificate carries, and the exchange of a
    fresh, key-bound sign-in. `Issue` fails closed on its inputs. A sign-in is checked for
    certifiability before it is spent (401 `sign_in_not_certifiable`). Issued certificates are
    trusted for people alone, and a logout reaches them for as long as they live.
  - **port49d** (f9b6859, 860df6c): `broker.identity.issuance`, the issuing CA at start (a start is
    never refused over it), `init-issuer` and `rotate-issuer`, and the broker's CA bundle
    (`tls_ca_bundle_file`).
  - **The agent and `port49 login --oidc`** (7869356, 4953cf8, c9ca381, 0b65ec9): signs in, holds
    the certificate the broker issues, and starts the agent on it. Only `credential_revoked` stops a
    login from using its held certificate; the terminal is restored on a signal.
  - **userconfig** (db7ebe1, b6e5748, d769ec4): the client's config in `~/.port49`, under a
    root-owned `/etc/port49/config.yaml`; the broker's CA bundle kept per broker. A root-owned file
    this user cannot read names the mode it needs, and 9a's file is refused without being read.
  - **Lab** (4b214fe, 926303c, 56cf438, 8fe45c8, 69cb591, 729f470, e7f808a, 9e89d59): **L55 closed
    2026-10-11 on Keycloak 26.4.7** (`tests/lab/results/L55-keycloak.md`) and **L56 closed
    2026-10-11 on vEOS 4.31.2F** (`tests/lab/results/L56-arista_eos.md`). Both were closed in
    9e89d59. **L47 (hosted providers) stays open.** The lab corrected two things: Keycloak admits an
    ephemeral loopback port only for a redirect registered as `http://127.0.0.1/callback` or
    `http://127.0.0.1/*`, and L56's refresh with Keycloak stopped needs a live device session, which
    the harness now opens first.
- **Carried:**
  - **9c:** the issued key moves into the TPM, the Secure Enclave or a token, behind the same
    `crypto.Signer`, in place of 9b's 0600 file; and `per_login_mfa`.
  - **9d:** the pins file leaves `userconfig.LegacyDir` with `port49 devices trust`; `LegacyDir` then
    serves the refusal of plan 9a's config file alone.
  - **9d:** `port49 ssh` and `devices trust` are refused with no fix on a host whose `~/.config` is
    group-writable (pre-flight 2 m5); removing the pins file fixes it. The 9d entry above carries it
    already, and the PR body lists it under known limitations.
  - **Plan 12:** each deployment shape's client package ships `/etc/port49/config.yaml` and the
    broker CA beside it, root-owned (decision 43 ruling 24).
  - **Plan 12:** a check that every broker on one store holds the same issuing CA (each start prints
    its fingerprint today); the issuing CA's files in each deployment shape's state volume, and
    `init-issuer` in each shape's setup.
  - **Plan 12: the issuing CA's custody at broker scale** (pre-flight 2 m7). `init-issuer` and
    `rotate-issuer` mean copying CA files to each broker by hand, three restart rounds per
    rotation: fine for 2 to 5 brokers once in five years. A Kubernetes Secret mounted read-only
    makes `rotate-issuer`'s writes fail, so that shape needs its own rotation (a new Secret per
    round). Keeping the CA in the shared store, sealed by `internal/store/crypt`, removes the
    copying; plan 12 weighs it against the key leaving the broker's disk for the store.
  - **Pre-beta review:** retiring plan 7h's bearer path for people (Q1), and its harness
    (`make lab-oidc`) rebuilt on issuance.
  - **Plan 13:** this plan's operator notes as the lab corrected them (below).
  - **L47:** stays unassigned.
- **Operator-facing notes** (the plan's "Operator notes," as L55 and L56 measured them; plan 13
  owns the guide):
  - Turn issuance on with `broker.identity.issuance: {}` (default `certificate_lifetime: 12h`; 1h to
    24h). It needs a human `oidc` verifier. Make the issuing CA once per install with `port49d
    init-issuer` (or `port49-broker init-issuer`) as the broker's user; it writes `issuing-ca.pem`
    and `issuing-ca.key` (0600) to `broker.state_dir`. Copy both to every further broker on the
    same store and restart; compare the fingerprints each start prints. Configure `issuance` alike
    on every broker on one store: a broker without it keeps a logout's record for `max_token_age`
    alone.
  - With the key missing or unreadable the broker starts and serves everything else; `/v1/config`
    says `issuance.available: false`, so `port49 login` says the broker cannot issue before any
    sign-in (L56 cell 0a; a valid held certificate is still used), an exchange gets 503
    `issuance_unavailable`, and the start line says what to run. Alert on
    `port49_certificates_issued_total{outcome="unavailable"}` and on
    `port49_issuing_ca_not_after_timestamp_seconds` (0, or within 90 days).
  - Rotate the issuing CA with overlap, running `rotate-issuer` on one broker throughout: (1) stage
    `issuing-ca-next.pem`, copy it alone to every other broker, restart all; (2) run it again to
    promote, copy `issuing-ca.pem`, `issuing-ca.key` and `issuing-ca-previous.pem` to the others,
    remove their staged `issuing-ca-next.pem`, restart all; (3) after `certificate_lifetime`, remove
    `issuing-ca-previous.pem` and restart. The next promotion is refused until it is gone.
  - Register port49 at the provider as a public client: no secret, authorization-code flow, PKCE
    S256 required; its client id is the verifier's `client_id`. Measured on Keycloak 26.4.7 (L55):
    register `http://127.0.0.1/callback` (or `http://127.0.0.1/*`) to admit any port; a fixed
    `http://127.0.0.1:<port>/callback` admits that port alone, so set `oidc_redirect_port: <port>`;
    `http://127.0.0.1:*/callback` admits none. Put the claim the broker maps (`email`, say) in the
    verifier's `scopes`.
  - Ship `/etc/port49/config.yaml` with the client, root-owned and writable by root alone, with the
    broker CA beside it: `broker`, `broker_ca` (relative to the file's directory), `method: oidc`,
    and `oidc_issuer` or `oidc_ca` only when needed. A new user's first step is `port49 login` and
    the sign-in. `~/.port49/config.yaml` (or `$PORT49_CONFIG`) overrides it key by key; a flag
    overrides both.
  - `port49 login --oidc` asks the password and MFA every time (`prompt=login`; L55 control: the
    same browser shows no form without it). It needs `broker` and `broker_ca`. With several
    providers, name one with `--issuer`; a private CA for the provider's TLS needs `oidc_ca`.
  - The key and certificate live in `~/.port49/issued/<broker host>_<port>.key` and `.pem`, 0600.
    The key is the session until the certificate ends: never copy it off the host. port49 marks
    `~/.port49/issued/` excluded from Time Machine and from backup tools that honour CACHEDIR.TAG
    (borg, restic --exclude-caches, tar --exclude-caches); other backups exclude it by policy,
    once, fleet-wide.
  - Check whom you signed in as: the login prints `signed in at … as <you>`. The printed address is
    not a password, but whoever has it can finish your sign-in with their own account; on a shared
    host use `--no-browser`. On a host with no browser, open the address on your laptop and paste
    the `127.0.0.1` address the browser fails to load; with no terminal, use `ssh -t`, or
    `--redirect-port N` with `ssh -L N:127.0.0.1:N`.
  - After the sign-in there is no browser: `port49 refresh`, `port49 login` with the agent running,
    and a new agent after a reboot all use the key (L56 cells 3 and 4a). A new sign-in comes when the
    certificate has under a quarter of its life left, or with `port49 login --sign-in`.
  - With the provider down, everyone holding a certificate keeps working: mints, device-session
    refreshes (needing a live device session) and new agents (L56 cell 6). Only a sign-in fails, and
    it says so, naming the certificate's end.
  - A back-channel logout refuses the certificate at its next use in the broker's words and ends its
    device sessions (L56 cell 5). The next `port49 login` removes the certificate and the one after
    signs in, from the time the broker names. A broker that issues keeps the logout's record
    `max(max_token_age, 24h) + 2×clock_skew`.
  - Revoke a person's certificates with `port49 revoke --principal user:…`, or one with
    `--cert-issuer DN --cert-serial HEX` from its `issue` record. A person's ID token is refused at
    a broker that issues, except at `POST /v1/certificate`; a machine's token is unaffected.
  - Rotate the broker's TLS CA with no user action: set `broker.tls_ca_bundle_file` (1 to 4 CAs, at
    most 64 KiB) and every agent keeps it per broker in `~/.port49/broker_ca/`. Add the next CA and
    restart; ship current and next together in `/etc/port49/broker-ca.pem` through config
    management; wait while people log in; switch `tls_cert_file` and restart; drop the old CA from
    both. If the old CA is compromised, push the new `broker-ca.pem` at once: the bundle adds trust
    and never removes it. Removing the bundle once done is safe: each agent's next start cuts what
    it kept to the CA its connection verified to. An unmanaged host away for the whole overlap runs
    `port49 login --broker-ca FILE` once.

### Plan 9b1 — As built

Executed from `2026-10-11-09b1-junos-groups-and-junoscript.md` on
`feature/junos-groups-and-junoscript` (base `b80dc84`, the plan's last pre-flight commit on `main`),
each task reviewed, most through one to three fix rounds. The ledger is
`.superpowers/sdd/2026-10-11-09b1-junos-groups-and-junoscript/progress.md`. The rulings are decision
44 of the spec (§13). Lab images: vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15, measured
2026-10-11 and 2026-10-12.

- **Built** (`git log b80dc84..HEAD`; `make test && make vet` pass on every package at the Task 10
  commit):
  - **Task 1, spec** (f68b49f, 8f0a12f, aeb37bc): decision 44, §8, §12, §14, §15 L26c, and the new
    L57 and L58 rows.
  - **Task 2, lab harness** (4aea0e7, 4331d5f, 1010b64, then 8057428, e5b23df, 7852220, 3cb39d2,
    eca3cbc, 23626ec, 3ec6d64 from the Task 3 run): the entry cells (port-22 subsystem, exec channel,
    `op url`, REST, `scp`, `xnm-ssh`), L57's groups and L58's baseline words. A refusal needs the
    device's word in every entry cell; a silent exit is not a refusal.
  - **Task 3, the lab run before code** (53b477c, 8c0448e, 56dd91a, abbf4ae, e4cb5f7, 05f5d1d, then
    ab5fc59, 743dbce, 460cfc6, f5cd0e0 from review): the gates below.
  - **Task 4, platform set 1.2.0** (2387124): `juniper_junos` `rpc_entry_denies: ["junoscript **",
    "op **"]`, `save` in the keyword tree, the new default; 1.1.0 is untouched.
  - **Task 5, projection with entry denies** (bb4baba, d2c0976, df12708, 090b701, 4517b13): where a
    deny sits beneath a sent bit or the baseline, the projection keeps the capability shape and adds
    the list. An allow that opens an RPC entry makes the projection decline the entry deny (fail
    closed). `policy load` refuses a partial `rpc_entry_denies`: a block keeps the set's whole list
    or drops it.
  - **Task 5b, the readonly with a show deny** (989387b, 6e81e22, e2fbd92): `view`, one factored
    alternative, carved allows beyond the bits, the narrow shape kept where its bits reach every
    allow.
  - **Task 6, warnings** (78b4c18, 7748e15, 8b5d6e2, 2fb5551): `projection_netconf_closed` and
    `projection_deny_beneath_view_configuration`, one remedy for both shapes.
  - **Plan text** (7e6b21d, 7fdcd82, 8ad7715, 88a2e43, 36cab30): Task 7 was rewritten after Task 3
    measured groups, and Task 7b added.
  - **Task 7, check-config reads groups** (d98771a, d78ae1c, 33e58b0, 2122e6f): expanded lines under a
    template are judged as the template's own; a capture with `apply-groups` as a word or any `set
    groups` line is refused as not inherited. 2122e6f fixes the lab redactor, which had crossed a
    newline and dropped a real set line from the L57 fixtures.
  - **Task 7b, services by set** (9e5cfbe, 777be18): under 1.2.0 an allowlist, an unlisted service
    fails; routing-instances services are judged like top-level ones under both sets.
  - **Task 8, `devices check-config --batch`** (06edd14, 7dbecaa, c35650b, 068ec95): `--config` is
    run-wide (projected devices use it, others ignore it); a file naming no inventory device exits 1;
    a repeated path is checked once; batch lines name their file; the summary lists the failed
    files.
  - **Task 9, the lab run and close** (9b1f1b6, 1635060, 1426da7, 2590c57, 56c5a52, e9b5063,
    6274425, bce2509, 58afbf9, 823c6f4, ee05c6f): set 1.2.0's differential on both images, the
    reruns of L57 and L58, and the register edits.
  - **Task 10, this entry.**
- **What Task 3's gates decided** (`L26c-scripts-juniper_*.md`, `L58-juniper_*.md`,
  `L57-juniper_*.md`):
  - **G1:** an `op url` script printed version and configuration under the `junoscript` deny alone
    (`L26c-scripts-juniper_vsrx.md:140`), so `op **` joined the list. Under the list's reply, `op
    url` and `op ur` were refused in the four rows carrying the entry deny and in the narrow readonly
    (five refusing rows) of Task 9's differential, while the control ran the script
    (`L26c-projected-juniper_vsrx.md:75-76`, `:145-146`).
  - **G2:** REST was not measured: the lab's tunnel reached it in no cell, the control's included
    (`L26c-scripts-juniper_vsrx.md:73`, `:141`). `rest` stays a check-config finding under 1.2.0.
  - **G3:** `save` is a keyword and is refused under view (`L58-juniper_vsrx.md:47`, `:57-58`).
  - **G4:** bare `xml-mode` and `xml-mode netconf` are refused under the factored `junoscript` deny
    (`L58-juniper_vsrx.md:42-43`, `:48`).
  - **G5:** the shipped readonly's nested deny is enforced as the factored form
    (`L58-juniper_vsrx.md:49`).
  - **L57's gates** (`L57-juniper_vsrx.md:42-49`, `:104`): a group applied at the top is expanded
    under the class, in either order of the two pipes. The inherited capture prints no `set groups`
    and no top-level `apply-groups` line, so a capture holding one is not inherited. A nested group
    commits and is not expanded and not applied in a session: measured for one shape, the inner
    group under `<p49-*>` adding `permissions`, applied from a top-level group's definition;
    other nestings are unmeasured. A class-level `apply-groups` is stripped by inheritance and its
    group expanded. `apply-groups-except` beside it is stripped too (lab rule 4 amended the
    spec). A class's own `idle-timeout` stands over a group's.
  - **Group permission beside own** (carry M7): a group's `permissions` lands beside the class's own
    (`L57-juniper_vsrx.md:42-43`, the "group permission beside own" column: yes), so a
    `view-configuration` from a group is in the reply's bits' reach, not instead of them.
- **Rows:** **L57** and **L58** opened and closed; **L26c** closed, its `op` part included
  (`op url` and `op ur` refused in the four rows carrying the entry deny and in the narrow
  readonly, the control running the script; the isolated cells are the operator and admin rows);
  **L59** opened for what no cell measured.
- **What a readonly's allows beyond `view` did** (Task 9, `L26c-projected-juniper_*.md`, the
  sections "readonly denying show configuration" and "readonly denying show security"): this is
  what a readonly with a show deny can read.
  - `show log messages | count` ran on both images in every row, the readonly rows included
    (vJunos `:310`, `:383`, `:455`; vSRX `:298`, `:367`, `:439`).
  - `show firewall | no-more` and `show policer | no-more` ran on both images in the same rows
    (vJunos `:311-312`, `:384-385`, `:456-457`; vSRX `:299-300`, `:368-369`, `:440-441`).
  - `show security zones` and `show security policies` ran on vSRX under a deny of `show
    configuration` (`:296-297`) and were refused under a deny of `show security` (`:365-366`). On
    vJunos-router the device refused them in every row, even the undenied readonly's (`:308-309`,
    `:453-454`), so that is the image, not the allow.
  - **`show configuration`, allowed beyond the bits under a deny of `show security`, was refused by
    the device on both images** (vJunos `:363-367`; vSRX `:347-351`). `policy test` now predicts
    the same: it says the device refuses `show configuration` under that reply, and lists no
    `show log`, `show firewall` or `show policer` shortfall (what port49 sends is unchanged). The
    undenied readonly, which gets `view-configuration`, ran it. Fail closed, but it is the open
    question below.
- **Ruled 2026-10-15 (Ryan):** permitted means it runs. When a class allows `show configuration`
  under a deny beneath `show`, the reply sends `view-configuration` with its other reach denied, in
  a small plan under set 1.2.0, gated on a lab cell proving the bit reaches nothing the denies
  leave open. Built as set 1.3.0 by plan 9g (decision 48; the controller's R3 ruling): set 1.2.0
  is released and stays as it was. The question it settles:
- **Former open question (closed under set 1.3.0 by plan 9g; it stays as measured under 1.2.0):** a readonly with a deny beneath `show` other than `show configuration`
  (`show security **`, say) cannot read `show configuration`, because the allow beyond `view` does
  not take and the reply does not send `view-configuration`. The alternative the ruling set aside is
  to send `view-configuration` with its other reach denied. Until ruled, `policy test` says the
  device refuses `show configuration` for that readonly (measured), and lists it among the probe
  commands the device refuses.
- **Carried:**
  - **L59's REST cell and its harness item:** the lab's tunnel reached REST in no cell, the
    control's included. The parked fix is binding REST to the management address the tunnel
    reaches (not 127.0.0.1), so the control reaches it first. `rest` stays failing.
  - **L59's other cells:** the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`), `outbound-ssh`,
    file reads of `/config` (`scp`, `sftp`, `ftp`) past a configuration deny, and the NETCONF-off
    `xml-mode` cell. Unmeasured: nothing here asserts them closed.
  - **L59's pager save:** under the narrow readonly on vSRX 21.4R3.15 a probe typed into a
    `---(more)---` pager and its `s` saved the paged output to a file. Seen once and uncaptured;
    `s` or a `| save` pipe writing under a readonly is unmeasured. Docs must not say a readonly
    cannot write files until L59 closes.
  - **`display inheritance` and a parked group:** whether it prints a `deactivate` or `protect
    apply-groups` line is unmeasured (review M4). check-config refuses one; its message names a
    parked group application as a cause and the remedy. The cell is `set apply-groups
    p49g-unapplied` beside `deactivate apply-groups p49g-unapplied`, committed together, after L57's
    session cells (the group grants `all`).
  - **`entryServices`** (Task 7b): an operator's benign service missing from it gets a finding; each
    addition names its source, as the list's comment does.
  - **L59 harness, xnm cells** (Task 2 re-review M1): an mgd crash or restart before the C cell
    could misread a closed xnm cell. The xnm cells closed nothing in this plan (the XML API moved
    to L59 and still fails check-config), so the risk lands only when L59 runs them.
  - **REST reachability harness:** REST binds the management address, not 127.0.0.1 (see the REST
    item above); `rest` fails check-config meanwhile, which is fail-closed.
  - **The redundant `set +cli` alternative** (Task 5b M4, 24 B beside `set` in the readonly deny):
    removing it changes what 1.2.0 sends, and that exact reply is what Task 9 measured end to end
    (`L26c-projected-*`, L58 G5). It fits the budget (170 B). Fold it into the next lab rerun of
    the differential.
  - **Flake watch:** `TestAFailedRescanHookReloadsNothing` in `internal/store` failed once and did
    not recur (the package is outside this plan's diff); `cmd/port49` had one unexplained FAIL and
    then nine clean runs (`-count=3` here, `-count=6` earlier). Watch, don't block.
  - **Deny-row transcripts:** Task 9's deny rows have verdicts and pcaps (lab rule 3 holds) but no
    transcripts; add them at the next differential rerun.
  - **Lab lessons:** the Junos CLI is case-sensitive (an uppercase probe is refused, a reading and
    not a failure; `L12-projection`), and a paged probe is INVALID, never typed into.
- **Operator-facing notes** (the plan's "Operator notes," edited to what was built; plan 13 builds
  the docs from these):
  - **New platform set 1.2.0, and the default.** It is 1.1.0 plus one key on `juniper_junos`,
    `rpc_entry_denies: ["junoscript **", "op **"]` (an `op url` script reached RPCs past the
    `junoscript` deny alone: `L26c-scripts-juniper_vsrx.md:140`), and `save` in its keyword tree. A
    policy pinned to 1.1.0 renders exactly as before. `port49 platform upgrade --policy … --to
    1.2.0` shows the change; `policy diff` gates it until the `acknowledge:` entry for
    `platforms.juniper_junos.rpc_entry_denies` is added. A block keeps the whole list or drops it.
  - **Junos subjects granted everything but a few denies now project.** Under 1.1.0 a grant like
    operator `**` less `show configuration **` got the fail-closed reply. Under 1.2.0 it gets its
    bits, its denies, and `junoscript` and `op` denied. The CLI deny then holds, and `xml-mode`,
    `junoscript netconf` and NETCONF on port 830 are refused **for that user only**
    (`L26c-junoscript-juniper_vsrx.md:60` for `junoscript netconf`, `L58-juniper_vsrx.md:42` for
    bare `xml-mode`; vJunos twins). `policy diff` on the pin move lists each such subject's
    projection change.
  - **A readonly with a show deny now projects.** Under 1.1.0 `show **` less `show configuration
    **` (or less `show security **`, or any deny under `show`) got the fail-closed reply. Under
    1.2.0 it gets `view`, its denies and the baseline's in one regex with `junoscript` (170 bytes
    for the common case), and allows of `show log`, `show firewall` and `show policer`. The CLI
    deny holds; `xml-mode` and NETCONF are refused for that user. `view-configuration` is not sent.
    `show log messages | count`, `show firewall` and `show policer` ran under the reply on both lab
    images. Under a deny elsewhere in `show` (`show security **`), `show configuration` does
    **not** run through its allow: the device refused it on both images, and `policy test` says so
    (it prints that the device refuses it under that reply, and lists it among the probe commands
    the device refuses). A readonly granted `show **` with no deny renders exactly as under 1.1.0.
  - **Who has NETCONF.** A subject whose grant has no deny beneath its bits (an automation account
    granted everything its level reaches) keeps NETCONF. A subject with any such deny does not.
    `policy test` warns `projection_netconf_closed` for each. An Ansible or PyEZ account that needs
    NETCONF needs a grant with no deny beneath its bits.
  - **New warning `projection_deny_beneath_view_configuration`.** A policy whose reply sends
    `view-configuration` and denies `show configuration` beneath it (an operator or admin granted
    `**` less that deny) gets a warning, not a refusal. A readonly with that deny gets no warning:
    its reply does not send the bit. The CLI refuses the command and NETCONF is closed, but the bit
    is what grants the configuration, so the real fix is a level without the bit. `policy diff`
    prints new warnings as `warning:` lines and still exits 0 on them.
  - **`devices check-config` reads configuration groups.** Capture with `show configuration |
    display set | display inheritance`. Junos prints each group's statements expanded under the
    classes and users they reach, and no `set groups` or top-level `apply-groups` line
    (`L57-juniper_vsrx.md:42`), so a device that templates its logins through groups no longer
    fails for using them. Every expanded line under `p49-remote`, `remote` or another port49
    template is judged as the template's own: a permission, a command or configuration regex,
    authentication, or any statement not on the harmless list fails, whether a group or the
    template wrote it. `idle-timeout`, `login-tip`, `login-alarms` and `full-name` pass. A group's
    `permissions` lands beside the class's own, so a group that adds `view-configuration` widens
    the template. The capture cannot say which group brought a line, so the finding tells you to
    run `show configuration system login | display inheritance`, which names it (`## 'clear' was
    inherited from group 'p49g-excepted'`); fix the group, since loading the reference does not
    clear what a group adds. A capture holding a `set groups` line, or `apply-groups` anywhere
    (a class-level one included), was taken without `display inheritance` and is refused at that
    line with the command to use: change the CI capture command once, fleet-wide.
    `apply-groups-except` is neither a finding nor a sign: beside a class-level `apply-groups`,
    inheritance strips it too. A group applied from inside another group is not expanded and not
    applied in a session, measured for one shape (the inner group under `<p49-*>` adding
    `permissions`, applied from a top-level group's definition); other nestings are unmeasured.
  - **Capture over the SSH exec channel, not a terminal session.** Run `ssh <device> 'show
    configuration | display set | display inheritance | no-more'`, which prints no command echo and
    no prompt. check-config refuses any line that is not a statement, the echo and the prompt
    included, naming the line: a check that skipped them could skip a wrapped or mangled `system
    services` line too, and go green on a device running REST.
  - **`devices check-config --batch FILE...`** checks a directory of captures in one run. Each file
    is checked against the device its file name names: the name as it is where the inventory has it
    (Oxidized's extensionless files, FQDNs included), else less its last extension (`srx-01.conf` is
    `srx-01`). Every output line names its file. `--config` is run-wide: projected devices use it
    and the others ignore it, so a mixed Junos and Arista directory is one run. A file that names no
    inventory device exits 1, as a single file does. A path repeated on the command line is checked
    once; different files for one device are each checked. It prints `batch: N configurations
    checked, M failed`, lists the failed files, and exits 1 if any failed.
  - **Management services under 1.2.0.** NETCONF no longer fails check-config. Under `system
    services`, `netconf`, `ssh` (with any option, `sftp-server` included: provisional on L59) and
    `telnet` pass with any option, and so do `database-replication`, `dhcp`, `dhcp-local-server`,
    `dns`, `dynamic-dns`, `finger`, `ftp` (provisional on L59), `static-subscribers`,
    `subscriber-management` and `subscriber-management-helper`. Any other service there fails, and
    the finding quotes it: `service-deployment`, `outbound-https`, `tftp-server` or one port49 has
    never heard of. If one of yours serves no management session, report it and it is added with its
    source. A service under `routing-instances` is judged like a top-level one, under both sets
    (under 1.1.0 it was not read before). REST (`rest`), J-Web (`web-management`), JET/gRPC
    (`extension-service`), the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`) and `outbound-ssh`
    still fail wherever they are written. REST and the XML API are unmeasured (L59, open); they stay
    findings until a lab cell measures the `junoscript` deny closing each.
  - **No new reason code, metric or config key in `port49d.yaml`.** The decision log records the
    reply as before; the `junoscript` deny appears in it.

### Plan 9c — As built

Executed from `2026-10-12-09c-hardware-keys-and-per-login-mfa.md` on
`feature/hardware-keys-and-per-login-mfa` (base `e8d3e1a`, the plan's last pre-flight commit on
`main`), each code task reviewed, most through one to four fix rounds. The ledger is
`.superpowers/sdd/2026-10-12-09c-hardware-keys-and-per-login-mfa/progress.md`. The rulings are
decision 45 of the spec (§13), twenty-six of them. Lab hardware: a YubiKey 5C Nano FIPS (firmware
5.4.3, libykcs11 from Debian's `ykcs11`), SoftHSM2, swtpm, Keycloak 26.4.7. **The rest of L60 and L62
have not run, and the Secure Enclave has never run on a Mac (below): nothing here says otherwise.**

- **Gates read:**
  - **SE1** (an unsigned `port49`, built with `CGO_ENABLED=0`, creates a Secure Enclave key, finds it
    from a second process and from a rebuilt binary, and signs): **not read, because no Mac is
    here.** Ryan ruled on 2026-10-12 to build the backend anyway (Task 14), experimental and opt-in,
    marked needs testing on macOS for community Mac users, so SE1 is a check a Mac user runs
    (Task 2, `tests/spike/secureenclave`), not a gate on building. It passes when four cells pass:
    `create-permanent`, `find`, `sign` and `find-rebuilt` (the key found and signed with by a copy
    of the spike built again, as a port49 upgrade is). A fifth, `control` (a software key through
    the same calls), must pass or the run is invalid. L63 stays open.
  - **M1** (Keycloak puts `mfa` in `amr`): **failed as worded.** Keycloak emits `otp`, and only
    `mfa` if the OTP execution's reference is set to it. The default stays `[mfa]`; the operator
    notes carry the Keycloak setup.
- **Built** (`git log e8d3e1a..HEAD`; commits are grouped by task, the fixes after review among them):
  - **Task 1, spec** (b9b8f5b, 305065b, 54676c2): decision 45, §5.1.5, §5.7, §13, §15 L60–L63. Later
    amended by 6eeeb6c, fd8a2bc, 23a2d47 (rulings 25 and 26), 8420de6 and 34e5f10 (ruling 9),
    609ac8d (ruling 14), fa73ed7 (ruling 7), 212dd48 (the key-failure codes), 8836395 (ruling 13).
  - **Task 3, PKCS#11 through purego** (082ce56, 9a894ca, 1323bda, d3ade79, bf842c7, e1e8857): one
    `hwkey.Key`; the module is checked as code the agent runs; `C_Initialize` with
    `CKF_OS_LOCKING_OK`; `make check-static` builds `bin/static/<cmd>` and fails closed.
  - **Task 4, TPM 2.0 through go-tpm** (5a283f3, 656627e, 75b26d4): ECC P-256 under the ECC SRK, a TSS2
    key file, 0600; a key survives dictionary-attack lockout, a password or a loose file is refused,
    each error names its cause.
  - **Task 8, the broker certificate's CRL** (04b77af, 2f6044f, 40f4094, 34e5f10, 8420de6, afcdd95,
    4f32efc, 113b1aa, 4aef096): `broker_crl: check | require | off`, link by link, in login, the
    agent and `port49 workload`. Ryan ruled on 2026-10-12 that `require` refuses a link with no
    http(s) distribution point (the trust anchor aside).
  - **Task 9, `per_login_mfa` in the policy** (89a9d7f, 2a31e1f, 6eeeb6c, 18e71dd, fd8a2bc, 40bac09,
    23a2d47): four levels, the strictest wins; an empty intersection is an error or a quarantine
    by where it is found (ruling 11); `policy diff` fails on a weakening unless a session test asserts
    the new requirement (ruling 24, the controller's ruling at Task 1 review, a change from the plan's
    warning).
  - **Task 10, YubiKey attestation** (9b05f1e, ada5ff4, c65892d, 4fc99c4, ec1a46c, dc78cd3, aa50b68,
    80d62f2): `internal/pivattest` verifies slot f9 to the operator's roots and each slot's
    attestation to f9; a roots file with a byte order mark or comments loads.
  - **Task 11, the broker verifies a proof** (6be2c3a, efbfadb, 9f3f298, bb7a318, 39d78b7):
    `POST /v1/mfa`, one challenge per request, the proof keyed by its binding; replay is decided
    once (`ReplayOnly`), so a spent proof never turns a minted token into a required one.
  - **Task 12, refresh under a requirement** (3665b93, a77146b, 0450452, 4c41868, 1562789, 4aef096): a
    refresh extends a context only when a proof covers it; a reload revokes nothing. The context
    records the proving agent (`mfa_agent_sha256`), so a bearer's proof covers no other agent's
    refresh (ruling 15).
  - **Task 5, hardware keys in login and the agent** (e926ea5, then 896cafd, f3bc093, c490a0b, 850c9ab,
    e57bd87, 402d933, 6a6764b, 0e58eeb, 98eb724, 099bb0a, 0e9d873, 221267b, ee0936d): the PIN asked
    once with echo off, on descriptor 4; a blocked PIN told as blocked with the PUK as the way out;
    a key's own failure at the handshake is a typed error with its own socket code, found by a
    recorder around the key and never retried. **Touch timeout** (b25ded5, 609ac8d): ruling 14.
  - **Task 6, the key unplugged** (ebc3907, d0471ee): "insert your key", no session ended.
  - **Task 7, `port49 login --oidc` in hardware** (b830877, 05636d4, 31f96db, f394afd, fa73ed7, 8b99a3e,
    78dd101, 819705b): `issued_key_store`; the shared-home naming; a named store looks only for its
    own pair.
  - **Task 13, the proof from the CLI** (2a35677, a59af4d, 61e0bb9): `port49 token`, `ssh`, `refresh`
    and `workload token` give a proof when asked; the sign-in proof goes to the agent's broker;
    `idp_mfa` is the fallback when the touch cannot be made.
  - **Task 2 and Task 14, the Secure Enclave, experimental** (ee329dc, the spec and plan amended to
    Ryan's ruling; af0e4f4, 4a4bb89, then 9a17c8f, 791fa83, 224e9f6 after review). Nothing has run on
    a Mac. `internal/hwkey/secureenclave` is the backend through purego, in a darwin-only
    `secapi` package that the static build never links; it is opt-in by name (`key:
    "secure-enclave:label=NAME"` or `issued_key_store: secure_enclave`), `auto` never picks it, it
    prints a one-line experimental warning once per process, and any Security.framework error is a
    refusal naming the OSStatus, never a fallback. The issued key is labeled
    `port49.<host>_<port>.<machine>`, made once under a lock and kept across sign-ins. Two keys under
    one label refuse every sign-in, and `port49 login --delete-key` removes them: it asks on a
    terminal, and deletes without asking when there is no terminal. `make check-darwin` (and a
    `darwin` job in the `hwkeys` workflow) cross-compiles `cmd/port49` with `-tags hwkey_dlopen` and
    the spike for arm64 and amd64 with `CGO_ENABLED=0`, and vets darwin with and without the tag.
  - **Task 15, the lab, L61 half** (e5e3eff, 9e98d1d, 8836395). L62's half has not run.
  - **Task 17, this entry** (5b8c6a8, revised after Tasks 2 and 14).
- **Left, and why:**
  - **Task 2's check on a Mac (SE1, L63):** from a port49 checkout with Go installed, `go run
    ./tests/spike/secureenclave`, then `go run ./tests/spike/secureenclave locked` (it asks the user
    to lock the screen and waits 45s). Each prints `cell <name>: pass` or `cell <name>: fail OSStatus
    <n> <description>`; the first ends `SE1: pass` or `SE1: fail`. Neither prints key bytes or a
    signature, and each deletes the keys it made. The one who runs it reports both outputs with the
    macOS version and Mac model. `find-rebuilt` runs `go build` itself, so it needs `go` on `PATH`
    and the checkout. The locked cells are not part of SE1: they say whether the agent's refresh and
    a new process sign with the screen locked (a locked-screen refresh is unmeasured, provisional on
    L63). Also observed, outside SE1: whether a held key reference still signs after its keychain
    item is deleted. If the Enclave refuses an unsigned binary (`-34018`, `errSecMissingEntitlement`, is the
    answer L63 asks about), port49 names that OSStatus and fails closed. **L63 stays open, marked needs testing on
    macOS;** a help-wanted issue asks community Mac users to run it at go-public.
  - **Task 16, the rest of L60:** needs Ryan at the key. Measured so far on the YubiKey 5C Nano FIPS,
    firmware 5.4.3, libykcs11 2.7.2 (2026-10-13; the partial results note
    `tests/lab/results/L60-ser8.md`, its probe at `tests/lab/l60/probe_test.go`; everything else
    stays *provisional on L60*): libykcs11 lists the f9 attestation certificate and each slot's attestation with no login, the
    f9 certificate is issued directly by Yubico's PIV root (no intermediate on this firmware), every
    attestation verifies in `pivattest`, the slot issuer is byte for byte the f9 subject, one device
    serial runs through every slot attestation, touch policy reads 9a=1 9c=2 9e=1, and
    `C_Initialize` with `CKF_OS_LOCKING_OK` runs clean five times with the token present (threads
    6/6/6). An untouched 9c sign returns `CKR_USER_NOT_LOGGED_IN` after about 14.4s although the
    token stays logged in (a touched sign on the same session then succeeds with no PIN). Ryan
    approved the ruling that follows: a not-logged-in that took 5s or more is a touch timeout, not a
    lock. **L60 stays open.** Cells not run: b, d, e, e2, f, g; the physical pull (does the return
    code map to `ErrKeyAbsent`?); the object order after a certificate is imported beside the
    attestation; the cost of `GET /status` reading attestations on the real key; the optional
    three-wrong-PIN lockout.
  - **L62, the SER8's TPM:** deferred to a session with Ryan. It needs a lab user in `tss`, a reboot
    of the SER8 and a second host for the shared home, including the mixed-store (token and file)
    cell. **L62 stays open.** *(Update 2026-10-15: **L62 closed** in that session,
    `tests/lab/results/L62-ser8.md`; the second host was a container with its own swtpm, every
    firmware clause ran on the SER8's TPM, AMD Pluton fw 0x60004.)*
- **Rows:** **L61 closed** (`L61-keycloak.md`, Keycloak 26.4.7, 2026-10-12: `amr` is `[pwd otp]`, or
  `[pwd mfa]` with the OTP reference set to `mfa`; `acr` is `"1"` in every cell). **L60, L62, L63
  open.**
- **Every claim provisional on an open row:**
  - **On L60:** ruling 3's module checks and `C_Initialize` with a live token (cell (a) measured
    clean; the rest of the row is not); ruling 4's PIN asked once and a wrong PIN sent once with the
    tries left; ruling 8's unplug (`GET /status` says `locked` after re-insertion, a second process
    does not drop the agent's PIV login, the return code maps to `ErrKeyAbsent`); ruling 12's
    attestation chain per firmware (one firmware measured), the policy bytes a YubiKey Bio reports,
    and a touch proving end to end; ruling 14's touch timeout (14.4s measured, the 5s rule approved,
    "15s" is the words' round figure); `issued_key_store: pkcs11` issuing with nothing written to
    the token.
  - **On L62:** ruling 5 on a real TPM (the SRK, a restart, a reboot, another machine refusing the
    key file, a user outside `tss` told the group); ruling 7's shared-home naming, the token host and
    file host each keeping their own certificate.
  - **On L63:** ruling 6, the whole Secure Enclave: that an unsigned binary can create and find a
    key, that a rebuilt binary still finds it, the call shapes (checked against the headers from
    memory, not an SDK), the data protection keychain, the refresh with the screen locked, and what a
    held key reference does after its item is deleted.
- **Carried:**
  - **The 7h bearer path's session refresh passes no agent session.** A person refreshing through it
    proves at every refresh under a requirement (ruling 15). It retires at the pre-beta review.
  - **ssh's askpass re-mint does not prove.** A stale token with no reuse cover ends `ssh` with
    "second factor required"; `port49 token` (or `ssh` again) proves.
  - **The agent's `GET /status`, or a `port49 token` in another terminal, waits up to about 15s** while a touch is
    pending (the token lock). It does not fail: the socket's timeout is longer. Still parked.
  - **The final review's fix round** fixed: a token listing a slot's own certificate before its
    attestation (`mfatouch.Chain` takes the one the f9 certificate signed); an OIDC login looping on
    a Locked issued token key (it now unlocks through the agent, never opening the token); a reload
    adding or tightening `per_login_mfa` left unspent no-proof tokens redeemable (now superseded);
    the mint gate's 503 spending the proof; ruling 18's start-time line; redirects followed by every
    broker client but the proof posts; a `pin-source` PIN tried while the token reports tries low;
    the `TestATPMKeyFromAnotherTPMIsReplacedBySigningIn` flake (tests shared one `HOME`, so a reused
    port handed one test another's issued pair; each lab broker now has its own); and, of the parked
    minors, the `TestMain` TPM stub, exit 75's `--scope`, `QuoteToASCII`, the `--broker-crl` help
    width and the redirects. The plan's Task 8 test list omits six real tests:
    `TestAForgedListIsNotSaidToBeIssuerFiles`, `TestALeafWithNoFetchableDistributionPoint`,
    `TestAnHTTPLeafIsStillCheckedUnderRequire`, `TestAStaleListIsRememberedForAMinute`,
    `TestNoVerifiedChainIsRefusedUnderRequire` and `TestParseMode` (`internal/brokercrl`).
  - **Still parked** (the final review's reports list each with its reason):
    - Tasks 3 and 4: `closeOwned`'s owner guard has no red test of its own.
    - Tasks 7 and 13: `auto` loads the TPM pair twice; a staging file left by a killed login; the
      attestation lost after the prompt is untested; older agents fall back to the config's broker CA.
    - Task 12: the sealed `Credential` has no json tags (a sealed-format change, left for its own
      ruling).
    - Task 5: the concurrent-dials test could be a channel version.
    - Tasks 2 and 14: the "after asking on a terminal" wording; a lock failure mislabelled "Secure
      Enclave refused"; `--delete-key` refuses other flags with exit 2.
  - **Carried to the lab session with Ryan:** the rest of L60 (cells b, d, e, e2, f, g and the others
    above) and L62, which the ledger defers: it needs a new lab user in `tss` (sudo, a host change), a
    reboot of the SER8, and a second host for the shared home.
  - **Plan 12:** ship `attestation_roots_file` (the broker) and the `touch_key`, `key`,
    `issued_key_store` and `broker_crl` lines in each shape's `/etc/port49/config.yaml`; build the
    macOS client with `-tags hwkey_dlopen` (the only build with the Secure Enclave) and keep `make
    check-darwin` in CI; whether that build must be signed is L63's question; add the lab
    user to `tss` in the client packages that use the TPM; build **two `port49` artifacts** (decision
    45 ruling 22) and name them so an operator can tell which is which: the static one
    (`make build`, `CGO_ENABLED=0`, no PKCS#11, no Secure Enclave) in the image and the server
    packages, and the client release (`make build-client`, `-tags hwkey_dlopen`, dynamically linked)
    in the desktop and jump-host packages people run `port49 login` from; keep `make check-static`
    in the release pipeline. The `hwkeys` workflow is the first CI to run Go tests; plan 12 decides
    whether `make test` joins it. The polkit rule for pcscd (below) is a host install, not the
    package's.
  - **Plan 13:** the operator notes below.
  - **At go-public:** a help-wanted issue for the Secure Enclave, "needs testing" for community Mac
    users (Ryan, 2026-10-12).
- **Verification:** `make test && make vet` and `make test-hw`: see the pull request body.

### Operator notes (for the pull request body)

- **Which `port49` has hardware keys.** There are two builds. The client build (`make
  build-client`, written as `bin/port49-client`; plan 12's desktop and jump-host release) has
  PKCS#11 (YubiKeys, smartcards) and the TPM; it needs the system's dynamic loader, which every
  desktop Linux and macOS has. The static build (`make build`, written as `bin/port49` with
  `CGO_ENABLED=0`, and the container image) has the TPM and file keys only. Given a `pkcs11:` key it
  says "this port49 was built without PKCS#11 support (the static build, as in the container image);
  use the client release", and nothing else changes. Its `issued_key_store: auto` passes over a
  configured `issued_key` and says so, rather than refusing. Run `port49 login` from the client build.
  The macOS client build carries the Secure Enclave, experimental (below); the static build does not.
- **Your key can live in hardware.** In `/etc/port49/config.yaml` (once, for the fleet) or your own
  `~/.port49/config.yaml`, set `key:` to a reference instead of a path:
  - a YubiKey or smartcard: `key: "pkcs11:id=%01?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"`
    (slot 9a is `id=%01`). Leave `cert:` out and port49 reads the certificate from the token. The
    module, any symbolic link to it, and every directory above it must be owned by root or you and
    writable by no one else.
  - a TPM key file: `key: "tpm:file=/home/alice/.port49/my.tpmkey"`, or a persistent handle
    `tpm:handle=0x81000001`. You must be in the `tss` group.

  `port49 login` asks the token's PIN once, on the terminal; it is never on the command line, in the
  environment or in a log. A wrong PIN is sent once: port49 never retries it, and tells you when the
  token says few tries are left. For a host with no terminal, put the PIN in a file only you can
  read and add `pin-source=file:///path` to the URI; `pin-value` is refused. The PIN travels on a
  file descriptor and is zeroed after login, but copies inside `net/http` and `x/term` buffers cannot
  be zeroed.
- **A `pin-source` PIN is never tried while tries are low.** When the token reports a failed PIN try
  since the last success (`CKF_USER_PIN_COUNT_LOW`) or one try left (`CKF_USER_PIN_FINAL_TRY`), a
  PIN read from `pin-source` is not sent: the agent's start and `port49 workload` refuse, saying
  tries are low. A wrong file on a timer would otherwise block the token in three runs, every key on
  it with it. Fix the file, then a person runs `port49 login` at a terminal: with a terminal it
  asks the PIN there instead of reading the file (one try, zeroed, sent once), and a typed success
  resets the flag; without one it refuses as before. `ykman piv info` shows the tries left. A typed
  PIN is tried as before. A token whose tries state cannot be read is not tried either: the run is
  refused, no try is spent, and it says to run again.
  Whether libykcs11 sets these flags is unmeasured (provisional on L60); a module that does not
  leaves the guard silent and each run spends one try.
- **A wrong PIN typed in another process logs the running agent off the key** (L60 finding F1,
  `tests/lab/results/L60-ser8.md`, GitHub issue #6). Measured: one wrong PIN typed at a second
  `port49 login` left the running agent's next refresh saying "your key needs its PIN: run port49
  login", with its status `locked`. Unmeasured: other processes using the token, whether the agent
  still mints on its held connection after the wrong PIN, and what puts the PIN back (a login to
  the agent's socket failed while the PIN was blocked; a new login after the unblock worked). Until
  measured, give each token one user at a time, and do not let a script try a PIN on a token an
  agent holds.
- **A blocked PIN.** `CKR_PIN_LOCKED`, or the token's own flag, means the PIN is blocked; `port49
  login` says so and keeps no retry. Unblock it with the PUK: `ykman piv access unblock-pin`.
- **Touch and PIN policy are yours.** For the session key, PIN once and touch never or cached is the
  sane default: the key is used once per session, at the handshake and at each refresh, never per
  device.
- **A touch that does not come.** With about 15s and no touch, `port49` says "no touch within 15s;
  touch the key when it blinks and try again". The key stays unlocked, and nothing is retried:
  run the command again and touch when it blinks. (Measured on one firmware, 5.4.3: an untouched sign
  returned after 14.4s; provisional on L60.)
- **`port49 login --oidc` keeps its key in hardware by default.** `issued_key_store: auto` is a token
  when `touch_key` and `issued_key` are both set and PKCS#11 is available, then the TPM on Linux if a
  key can be created there (it says so), else the 0600 file as before. `tpm`, `pkcs11` (with
  `issued_key: "pkcs11:…;id=%04"`) or `file` name one store and never fall back; a named store that
  cannot be used stops before your browser opens and says why:
  - the TPM has an owner password: clear it, or use `auto` or `file`;
  - the TPM is in lockout: `tpm2_dictionarylockout -c`;
  - the device is missing or not yours: check `/dev/tpmrm0` and the `tss` group.

  For `pkcs11`, make the key once yourself (`ykman piv keys generate 9e …`): port49 signs with it and
  never writes to your token, so it never needs your management key. When tokens are present and none
  matches `issued_key`, the error lists them by label, serial and manufacturer.
- **Shared home directories.** Each machine keeps its own key and certificate, so jump hosts that share
  your home never overwrite each other. A TPM pair is `<host>_<port>.<machine>.tpmkey` and
  `.<machine>.pem`, where `<machine>` is eight hex digits of SHA-256 of `/etc/machine-id`; it is
  useless on any other machine. A token key's certificate is `<host>_<port>.<8hex>.pem`, where the hex
  is SHA-256 of the canonical `pkcs11:` reference without its query. A file key is
  `<host>_<port>.key` and `.pem`. (Measured: L62, closed 2026-10-15.)
- **Rolling out touch keys.** A host keeps the file or TPM pair it holds until that pair renews.
  `port49 login --sign-in` switches it to the token at once.
- **The key unplugged at 3am.** Your open device sessions and the agent's held connection keep working:
  `port49 token` still mints, and says "(tokens are still minted on the held connection while it
  stays up)" where one exists. `port49 refresh` and anything that needs a new connection say "insert
  your key; your session goes on until <time>"; nothing ends. Put the key back and run `port49
  login`: it says "your key is back and needs its PIN: run `port49 login`" (or "your key needs its
  PIN" if it never left), asks the PIN and carries on. Over the agent's socket these are
  `touch_timeout`, `key_locked`, `key_absent` and `broker_refused`, each answered 502, and
  `/unlock`'s `key_absent` answers 409. (The unplug is provisional on L60.)
- **The broker's certificate is checked against its CRL**, link by link, for every link that names a
  distribution point. `broker_crl: check` (default): a revoked broker certificate is refused before
  anything is sent to it; a CRL server that does not answer is said once and the login goes on (tried
  again after a minute, not at every connection); a link with no distribution point is not checked.
  `require` refuses that too, and refuses any certificate in the chain (the trust anchor aside) that
  names no `http` or `https` distribution point: add an HTTP CDP to the CA, or use `check`. `off`
  checks nothing. **`require` therefore refuses a stock step-ca broker certificate, which carries no
  HTTP CDP, and the intermediates of many private PKIs, until the CA adds one.** To see whether yours
  has one: `openssl x509 -noout -ext crlDistributionPoints -in broker.pem` (and the same for each
  intermediate); no output means none. Lists are kept in `~/.port49/crl/`.
  - **Rotating the broker's certificate.** Issue the new one and load it before publishing the
    revocation; revoke the leaf, not the CA.
  - **Rotating the broker's CA.** Issue the new CA, publish its CRL, rotate the brokers onto it, then
    revoke the old one. Revoking the CA with no replacement stops all authentication under `require`:
    held sessions continue, new logins do not.
- **`per_login_mfa`: a second factor at each login to the devices you mark.** Under `defaults:`, a
  role, or a scope (`match: {tier: core}` for a class, `match: {name: core-sw01}` for one device):

  ```yaml
  per_login_mfa:
    accept: [hardware_key_touch, idp_mfa]   # one or both
    reuse_for: 15m                          # 0m: a proof at every login; at most 8h
  ```

  The strictest level wins: the methods every level accepts, the shortest `reuse_for`. Two levels that
  share no method are a policy error naming both: `port49 policy test` fails, `policy diff` fails
  when your edit introduces it, and a reload of an edited policy that introduces it is refused (the
  old one keeps serving). If an inventory change makes them meet (a sync adds `tier: core`), that
  device alone is quarantined with the cause, and the rest of the inventory change applies; watch
  `port49_devices_quarantined`. While it stays quarantined, policy edits that do not add a new
  conflict still load: fixing a grant at 3am never waits on it. A scope that matches by an attribute
  needs `on_missing` and `security_log: true` (one matching `name` alone needs neither); `on_missing:
  exclude` there is a lint warning. Machines are exempt unless a level says `applies_to_machines:
  true`, and then prove by a touch from a key and touch slot on one token (`port49 workload token
  --key pkcs11:… --touch-key pkcs11:…`); a connection that changes during the touch exits 75: run it
  again. `port49 explain` prints the effective requirement and where each part came from; `policy
  diff` fails on a weakening (a method added to `accept`, a longer `reuse_for`, a level removed,
  `applies_to_machines` turned off, a requirement removed) unless a session test asserts the new
  `per_login_mfa:`, as it does for a privilege raise; a tightening only prints.
- **Upgrade first.** Upgrade every broker and daemon before adding `per_login_mfa` to a policy: a
  replica that does not know the key refuses the policy and keeps serving the old one, with no
  requirement; `port49_policy_file_refused` is 1 there and `port49_policy_bundle_matches_runner` 0
  until it is upgraded.
- **The two methods.**
  - `hardware_key_touch`: a touch on your token's always-touch slot. Set `touch_key:
    "pkcs11:id=%02?module-path=…"` (slot 9c, made with `ykman piv keys generate --touch-policy always
    9c`), and on the broker `broker.identity.per_login_mfa.hardware_key_touch.
    attestation_roots_file:` Yubico's PIV attestation roots, every one Yubico publishes (newer
    firmware may chain through an intermediate under a newer root: list the root and the
    intermediate; L60 records which, and measured none on firmware 5.4.3:
    `tests/lab/results/L60-ser8.md`, partial, the row open). The broker checks that the
    touch slot is on the same token as your session key; a TPM, a file key or an imported key cannot
    give it. **So a device that accepts only `hardware_key_touch` locks out anyone whose session key
    is not on their token**, including `--oidc` users whose key went to the TPM under `auto`: give
    them `issued_key` on the token, or accept `idp_mfa` too. port49 says this at the prompt ("your
    session key is in the TPM; a touch proves only from the token that holds it") instead of trying
    a touch that must fail. (Provisional on L60.)
  - `idp_mfa`: a fresh sign-in at your identity provider whose `amr` shows a second factor (`mfa` by
    default; `broker.identity.per_login_mfa.idp_mfa.amr` widens it). A browser round trip each time,
    and it needs a terminal. It is also the fallback when the touch key is out or the token shows no
    attestations, where the device accepts it.
  - **Keycloak (measured, L61, 26.4.7).** Its ID token has no `amr` until you add an AMR mapper to
    the client. Then set the OTP execution's reference to `otp` and list `otp` in `idp_mfa.amr`, or
    set that reference to `mfa` and keep the default. **Never list `pwd`:** every login carries it,
    so it proves nothing. **`acr` is no signal on Keycloak:** it is `"1"` in every case, and
    `acr_values` does not change it.

  Accept both where you can: with the IdP down, the touch still works, and with no token to hand, the
  sign-in does.
- **What you see.** `port49 token core-sw01` prints `core-sw01 asks for a second factor at each login:
  scope core accepts hardware_key_touch (reuse 15m, from scope core)` then `touch your key now`. One
  proof covers your further logins under that requirement for `reuse_for`, in this agent only: another
  agent, or another machine, proves again. **A known wait:** the agent's status, or a `port49 token`
  in another terminal, waits up to about 15s while a touch is pending. **A known gap:** `ssh`'s askpass re-mint
  does not prove; a stale token with no reuse cover ends `ssh` with "second factor required": run
  `port49 token` (or `ssh` again) to prove.
- **Live sessions are never cut by a policy edit.** Adding a requirement revokes nothing. Your next
  `port49 refresh` asks one proof before it extends those sessions; without it they keep their
  current end. On Junos (which never asks port49 about a command) the device's own session runs until
  it is closed, and `port49 refresh` says so. A login not yet made is gated at once: the reload
  deletes the unspent tokens minted under no requirement or a looser one, so a token minted at 09:58
  is not redeemed at 10:10 without a proof; `port49 token` again asks one.
- **A requirement no method here can meet is said at start.** When a device's `accept` holds no
  method this broker verifies (a touch-only scope with no `attestation_roots_file`, an
  `idp_mfa`-only one with no human OIDC verifier), the broker says one line at its start and at each
  policy reload naming those devices; it starts anyway, and every login there is `deny
  per_login_mfa_unavailable` until it is configured.
- **New in the decision log:** event `per_login_mfa` (`per_login_mfa_proved`, `per_login_mfa_refused`);
  `per_login_mfa_required` and `per_login_mfa_unavailable` on `mint` and `refresh`; a mint record says
  which method covered it and whether it was reused. Alert on `per_login_mfa_refused` (someone trying
  another token or another person's sign-in) and on `per_login_mfa_unavailable` (a broker that cannot
  verify a method a policy demands). Metric: `port49_per_login_mfa_total{method,outcome}`.
- **Hardware tests and hosts.** `make test-hw` needs `softhsm2`, `swtpm`, `swtpm-tools`, `ykcs11` and a
  running `pcscd`; the `hwkeys` workflow runs it on every pull request and fails if the static build
  stops being static (`make check-static`). Where a non-console user uses a token through `pcscd`,
  the host needs a polkit rule scoped to that user (the lab box's is
  `/etc/polkit-1/rules.d/99-port49-pcscd.rules`).
- **Secure Enclave (macOS, experimental; needs testing on macOS).** Built without a Mac to run it
  on, so it has never run on one (L63 open). It is cross-compiled and vetted for darwin in CI (`make
  check-darwin`), which proves it builds and nothing about how it behaves. Opt-in only: `key:
  "secure-enclave:label=NAME"` or `issued_key_store: secure_enclave` in the macOS client build; `auto`
  never picks it. Each process that opens or makes a key prints, once, "the Secure Enclave backend is
  experimental and untested (L63); report results at the port49 issue tracker". Any
  Security.framework error, `errSecMissingEntitlement` (-34018) among them, is a refusal naming the
  OSStatus, never a fallback to a file or another store. The issued key is labeled
  `port49.<host>_<port>.<machine>` and made once, under a lock in `~/.port49/issued/`, then kept
  across sign-ins; a sign-in never removes it. Two keys under that label refuse every sign-in, naming
  the count; `port49 login --delete-key` deletes them (and the certificate held for them), asking
  `[y/N]` on a terminal and deleting without asking when there is none; the next login makes one. It
  works only with `issued_key_store: secure_enclave`. Whether the agent's refresh signs with the
  screen locked is unmeasured. To help, from a port49 checkout on a Mac with Go installed:
  `go run ./tests/spike/secureenclave`, then `go run ./tests/spike/secureenclave locked` (it asks
  you to lock the screen). Each prints `cell <name>: pass` or `fail` with the OSStatus; the first
  ends `SE1: pass` or `SE1: fail`. Neither prints a key or a signature, and each deletes the keys it
  made. Report both outputs with the macOS version and the Mac model; a help-wanted issue asks for
  this at go-public.

### Plan 9d — As built

Executed from `2026-10-13-09d-openssh-host-keys-and-python-clients.md` on
`feature/openssh-host-keys-and-python-clients` (base `b898e1c4`, the plan's last pre-flight commit),
each code task reviewed, most through one to five fix rounds. The ledger is
`.superpowers/sdd/2026-10-13-09d-openssh-host-keys-and-python-clients/progress.md`. The rulings are
decision 46 of the spec (§13), seventeen of them. Pre-flight: 1 Critical, 8 Important, 18 Minor,
all applied before Task 1.

- **Built** (`git log b898e1c4..HEAD`; `make test` and `make vet` pass):
  - **Spec** (2c4d9215 and its fixes): decision 46 and L64–L66.
  - **Gate G1, the floor** (6af683f2, e63bab1e, 29d713e3; `tests/ssh-compat/2026-10-13-openssh-accept-new.md`):
    accept-new under a known `HostKeyAlias` refuses a key of another type, in the attack's shape (a
    server offering only Ed25519 against a filed ECDSA key), and the askpass answers only the ssh
    port49 started (G1c, the hop's password prompt, with a control). It holds on OpenSSH 8.5p1,
    8.9p1, 9.6p1 and 10.2p1, so **the OpenSSH floor stays 8.5**. 10.2p1 was not run for one
    quoted-path form (Task 9 refuses that value).
  - **`port49 ssh`** (3c097919, 18f2f305, 82c2c810, 62ce3a0e, 543e6c69): reads the operator's
    `StrictHostKeyChecking`, `HostKeyAlias` and known_hosts with `ssh -G` (evaluated with the real
    command and environment, so `Match` blocks see them), passes accept-new (their `yes` stands,
    `no` never passes) and the inventory name as the alias (theirs stands). It refuses an effective
    `UserKnownHostsFile` that does not resolve to a writable regular file (or a missing one in a
    writable directory), `/dev/null` included, naming the setting and the resolved path.
  - **`port49 devices trust`, `internal/hostkeys` and the pins file removed** (459efda6): the command
    says so and exits 2; `userconfig.LegacyDir` is unexported, so nothing kept reads under
    `~/.config` and 9b's group-writable refusal is gone.
  - **`token --json`, `workload token --format json`** (6d23df56, c2730421 and their fixes): a
    failure is one JSON object with the code or the §5.7 reason; a sweep lists what it did not mint
    in `refused`, prints `"results": []` never `null`, and names a run that stopped early in
    `stopped`. New client code `broker_unavailable` (an unreachable or 503 broker, which sent
    nothing), carried across the agent socket as a typed error.
  - **The Python library** (3203c098, a63a074f and their fixes; `clients/python`, 3.10+): `Agent`,
    `Workload`, typed errors, retry only of `revocation_running`, `connection_changed` and
    `broker_unavailable`. `Workload` never reruns a run (decision 46 ruling 11).
  - **Netmiko and Python host keys** (ab07f245 and its fixes): `port49.netmiko.connect` files keys
    under the inventory name in the operator's known_hosts, refuses `@revoked` keys, a
    `KnownHostsCommand`, a proxy and a port mismatch (below), and a key that is not the filed one.
  - **The Ansible lookup** `port49.client.token` (864a013e and its fixes; collection `port49.client`,
    ansible-core 2.16+): tested on 2.16, 2.17, 2.18 and 2.21 with the token absent from the
    output at every verbosity tested.
  - **Lab** (47a5ea28 to 6c967491): L64 and L65 closed on five platforms (80a4665d); L66 closed on
    five platforms (6c967491). Under rule 4 the lab corrected the collection README, spec ruling 15
    and design §17: the first guess, that Paramiko with `host_key_auto_add` rewrites known_hosts
    without its `@revoked` and `@cert-authority` lines, was wrong in the way described there.
- **Rows:** L53 and L54 stay closed (claims amended). L64, L65, L66 closed 2026-10-14
  (`tests/lab/results/L64-*.md`, `L65-*.md`, `L66-*.md`).
- **Residuals, measured (spec §15 L64–L66; the collection README says how to configure around
  each; this is the list):**
  - **Ansible `network_cli` keys host keys by address** (`ansible_host`), not by name. Under
    `host_key_auto_add`, both libssh and paramiko presented the token to another host at a moved
    address (L66 (e)). No `network_cli` `ssh_type` honoured a `HostKeyAlias`. **Ruled 2026-10-15; plan 9f
    (`2026-10-16-09f-network-cli-host-keys.md`) closes it in the lookup.** With the lookup, a moved address is refused
    before the mint when the address holds another host's key, and `paramiko` refuses it when the address has
    no entry (L66 (e3), (e3b), (e3d)). The gap that stays: `libssh` with `host_key_auto_add` accepts a
    changed key and presents the token (L66 (e3b)), and a device whose name holds no key (case 4) is a first
    contact; both are documented.
  - **libssh with `host_key_auto_add` accepts a changed key** and presents the token (L66 (c)).
  - **paramiko refuses a known_hosts that holds any `@revoked` or `@cert-authority` line**
    (`InvalidHostKey`), and on a first contact rewrites the file without its comments (L66 (c)). A
    shop on `@cert-authority` breaks Ansible's paramiko path.
  - **`persistent_log_messages` writes the token to its log** (L66 (d)), which breaks the rule that
    no token is ever logged.
  - **The `ansible.builtin.ssh` master is shared between two names at one address** (L66 (e2)): the
    second name reuses the first's ControlPath master (the measured reading is in the notes).
  - **A lookup in `ansible_password` mints more than once per task** (L66 (a)): 10 mints for the
    first 2 tasks, and at the default cap of 8 the play failed at its second task with
    `candidate_cap_reached`. The README mints once.
- **Carried:**
  - **Plan 12:** publish the Python library (PyPI `port49`) and the Ansible collection (Galaxy
    `port49.client`) at go-public, **after reserving both names**; each shape's client package
    installs them beside the client build; the Oxidized example's `secure: true` asks for every device's key in
    `~/.ssh/known_hosts` before its first backup (per-device toil): measure Oxidized's own host-key
    options against accept-new and change the example, or say why not.
  - **Pre-beta review:** the `port49 devices trust` removal line in `cmd/port49/main.go` goes; plan
    9a's pins-file hint in `port49 ssh` goes.
  - **L60's session:** whether parallel Ansible forks under a `hardware_key_touch` requirement ask
    one touch or several (the agent's token lock serializes them; unmeasured). The README's
    pre-play `port49 token <one such device>` stands until then.
  - **Ansible's address keying:** see Residuals. If a later plan takes it, a lookup check that
    refuses a new address for a device whose key is filed under its name is one option; it is
    Ryan's decision, not this plan's. The `@cert-authority`-only gap in Paramiko (below) is decided
    with it.
  - **Plan 13:** these operator notes; plan 9a's `devices trust` notes withdrawn.
- **Left for later:**
  - **Netmiko through ProxyJump** (`sock=` via `ssh -W`): the Python client fails closed on a
    `ProxyJump`, `ProxyCommand` or a `Port` that is not the one it dials, and points to `port49
    ssh`. Following a bastion safely is a follow-up issue Ryan decides at the 9d PR.
  - **A `@cert-authority`-only device in Paramiko:** Paramiko cannot check it, so the Python client
    refuses; use `port49 ssh` or file the key. Owner: the network_cli address-keying decision that
    awaits Ryan (Carried, above).
  - **Parked review minors**, none a false pass: Task 9's `ssh-dss` in the algorithm map (M-A),
    `host_key_uncheckable` for nothing filed (M-B) and a real publickey login in the end-to-end test;
    Task 12's M1 to M3 (an INVALID first contact marking dependants NOT RUN, CI paramiko against the
    lab's libssh, an unpinned `ansible.utils`). The final whole-branch review takes them.
- **Operator-facing notes** (the plan's "Operator notes," as built; plan 13 builds the guide):
  - **Host keys are OpenSSH's now.** `port49 ssh` uses your own known_hosts: the first connection to
    a device is accepted and saved ("Permanently added 'core-sw01'"), and a changed key stops at
    OpenSSH's warning before the token is sent. Nothing to run first; `port49 devices trust` is gone
    (it says so and exits 2). Keys are filed under the device's inventory name (`HostKeyAlias`), so
    an address changed in inventory for a device you have reached before is refused at the key
    exchange. An ssh_config with `UserKnownHostsFile /dev/null` (often beside `StrictHostKeyChecking
    no` in a `Host *` block) is refused, naming the line: it would make every connection a first
    contact. Your own `Host` blocks match the device name as written, case and all. A refusal that
    comes after the mint (`ssh -G` failing, that `/dev/null`) leaves the token unused; it expires.
  - **Why it matters.** The token is the device's password for its lifetime. A host that takes it
    can replay it to the real device until it expires. The window port49 leaves is the first
    contact, per device and per operator, the same one every SSH user accepts.
  - **Checking a first contact.** Compare the fingerprint ssh prints with the device's console:
    NX-OS `show ssh key` prints a SHA256 fingerprint; EOS `show management ssh hostkey <type>
    public`, Junos `file show /etc/ssh/ssh_host_<type>_key.pub`, IOS-XE `show ip ssh` print the key,
    so run `ssh-keygen -lf` on it (L53; the type is the one ssh filed, L64).
  - **A changed key.** `port49 ssh` says the key filed under the name is not the one the address
    presents. Either the device was re-keyed (verify the new key on its console, then `ssh-keygen -R
    core-sw01`), or the address is not the device: tell security. Ansible's `network_cli` files its
    own entry under the address, so a re-keyed device you also reach from Ansible needs both:
    `ssh-keygen -R core-sw01` and `ssh-keygen -R 10.0.0.11` (`-R '[10.0.0.11]:2222'` on another
    port). For a planned fleet re-key (an image upgrade), over a file of inventory names and one of
    their addresses: `while read -r d; do ssh-keygen -R "$d"; done < devices.txt` and the same over
    `addresses.txt`. That reopens the first-contact window for every device in it, until each is
    reached again; check a sample on the console.
  - **Verified first contact for a shop.** Ship a managed `GlobalKnownHostsFile` keyed by inventory
    name, or host certificates with `@cert-authority`; `port49 ssh` leaves both alone. Your own
    `StrictHostKeyChecking yes` and `HostKeyAlias` in ssh_config stand; `no` is never used.
  - **Plan 9a's pins file** (`~/.config/port49/known_hosts`) is no longer read. `port49 ssh` names
    it while it exists; its lines are already OpenSSH's format under the same names, so keep keys
    you verified with `cat ~/.config/port49/known_hosts >> ~/.ssh/known_hosts`, then remove it. A
    group-writable `~/.config` (Ubuntu's default) no longer stops `port49 ssh`. `--known-hosts` is
    refused: use `UserKnownHostsFile` in an ssh_config (`--ssh-config`).
  - **`--ssh` with a shell wrapper.** `port49 ssh --ssh PATH` takes a program that execs the real
    `ssh`. A wrapper that is not an exec (a shell script that runs `ssh` as a child) is not the
    process port49's askpass trusts, so the device's password prompt falls to the terminal and the
    token is never typed for you. That fails closed; make the wrapper `exec ssh "$@"`.
  - **`port49 token --json`** prints one JSON object on a failure too (a deny's §5.7 `reason`, or a
    code: `no_agent`, `per_login_mfa_required`, `touch_timeout`, `key_locked`, `key_absent`,
    `broker_refused`, `broker_unavailable`, ...); the exit status is unchanged. **`port49 workload
    token --format json`** lists what was not minted in `refused`, and prints on exit 75 and 77 too.
  - **Python.** `pip install './clients/python[netmiko]'` (Python 3.10+). `port49.Agent().token(
    "core-sw01")` for a person, `port49.Workload(broker=…, broker_ca=…, cert=…, key=…).tokens(
    scope="backup")` for a machine, `port49.netmiko.connect("core-sw01")` for Netmiko. It runs the
    `port49` CLI, so touches, PINs, hardware keys and the broker CRL check work as they do for
    `port49 token`; prompts appear on your terminal. Errors are typed (`Denied` with the reason,
    `MFARequired`, `KeyUnavailable`, `NoAgent`, ...; `broker_unavailable` is `Temporary` and
    retried). Netmiko's host keys follow `port49 ssh`'s rule in the same known_hosts. Paramiko
    cannot check `@cert-authority`, so a device covered only by one is refused there; use `port49
    ssh`, or file its key. A key an `@revoked` line or your `RevokedHostKeys` (a KRL) names is
    refused, filed or at first contact, before authentication; a `KnownHostsCommand` is refused
    (use `port49 ssh`); a device name holding `*`, `,`, a space and the like is refused before
    anything is minted.
  - **Python and bastions.** The Python client does not follow a `ProxyJump` or `ProxyCommand`, and
    refuses a `Port` that is not the one it dials, and a `BindAddress` or `BindInterface` (a VRF
    per site will hit this), which Paramiko cannot honour: Paramiko would dial the address itself, and a
    key checked or filed could be another host's. It refuses, naming the setting, and the fix is
    `port49 ssh`, which honours both. This fails closed.
  - **Ansible.** `ansible-galaxy collection install` the collection and `pip install
    ./clients/python` on the controller. Mint once per host per play (`pre_tasks` first,
    `gather_facts: false`, `set_fact`, `no_log: true`); a lookup in `ansible_password` mints more
    than once per task (10 mints for the first 2 tasks; at the default cap of 8 the play failed at
    its second task with `candidate_cap_reached`, L66 (a)). Never enable `persistent_log_messages`:
    it writes the token to its log (L66 (d)). For devices that ask for a touch, run `port49 token <one such device>` before
    the play, so one proof covers the forks. Host keys are Ansible's own, and `network_cli` keys
    them by `ansible_host`, the address, not the name: an address changed in Ansible's inventory is
    a first contact there, and with `host_key_auto_add` the host at it gets the token (both
    `ssh_type`s, L66 (e)). `ssh_type: libssh` with `host_key_auto_add` also accepts a changed key:
    never set `host_key_auto_add` with `ssh_type: libssh` (L66 (c)). `ssh_type: paramiko` refuses a
    known_hosts holding `@revoked` or `@cert-authority` lines and drops its comments on a first
    contact (L66 (c)). Where the connection runs OpenSSH, set `-o HostKeyAlias={{
    inventory_hostname }}`. The `ansible.builtin.ssh` master is shared between two names at one
    address: use one inventory name per address (L66 (e2)). The settings per
    `ssh_type` are as L66 measured; the collection README has them.
  - **A wrong PIN typed elsewhere** logs a running agent off a hardware key (L60 F1, issue #6):
    see Plan 9c's operator notes above.

### Plan 9e — As built

Executed from `2026-10-14-09e-directory-password-sign-in.md` on `feature/directory-password-sign-in`
(base `7c7bdf84`, the plan commit), each task reviewed, most through one to three fix rounds. The
ledger is `.superpowers/sdd/2026-10-14-09e-directory-password-sign-in/progress.md`. The rulings are
decision 47 of the spec (§13). Pre-flight: 5 Critical, 15 Important, 14 Minor, all applied before
Task 1.

- **Built** (`git log 7c7bdf84..HEAD`; `make test` and `make vet` pass):
  - **Spec** (Task 1; 1a2624e5, 274bd8c9): decision 47, five §5.7 reasons, the new events, design §7,
    §10 and §12, and L67.
  - **TOTP** (Task 2; b0e329bb, 9f044b67): codes over `pquerna/otp` v1.5.0, the window edges tested on
    both sides, the QR code on `boombuler/barcode` v1.1.0.
  - **Vocabulary** (Task 3; f2fe85ca): `sign_in_refused`, `sign_in_throttled`, `enrollment_closed`,
    `enrollment_store_lost`, `second_factor_enrolled`; the `enroll` event; `port49_sign_ins_total`
    and `port49_directory_enrollment_store_ok`.
  - **The stores** (Task 4; f5d6edd4, a775733b, 122aef36, 6c4cf422): attempt counts in `store:`; the
    enrollment store as its own handle, a sealed file on memory and keys in etcd. State, enrollment
    time, used step and the creation mark are sealed and compared clear against sealed; a mark under
    the previous key reports `Stale` and is re-sealed by revision.
  - **Config** (Task 5; 9f3e28ed, 076943a7): the `directory_password` verifier and
    `directory.enrollment_store`. A memory enrollment store beside an etcd `store:` is refused
    (per-replica files would break single use), as are an endpoint shared with `store.etcd` and an
    overlapping prefix (default `/port49-enrollments/`).
  - **The directory** (Task 6; d8cc713d, dfc27761): the entry a name names, and a person's bind on a
    fresh connection. LDAP 51 and 52 are `ErrUnavailable` (503, not counted); 53 is a refusal.
  - **The certificate** (Tasks 7 and 8; 77b4e35c, f9cb69cf, a9b5ec3e, 2c6f7ddb): a directory sign-in
    rides in the issued certificate's URI (`method=directory_password`, `amr=pwd&amr=otp`), and the
    broker reads it, refresh records included.
  - **`POST /v1/sign-in` and `/v1/sign-in/confirm`** (Task 9; 5b7c298f, b6c2ca6c, 02f7d6bf): the
    order of D4, counts given back on a broker fault, a 202 that keeps its reopened window, and a
    handle put back after a failed confirm.
  - **Operations** (Task 10; 5f90efc1, 31b2f03f, 0eee5e46, ad83bf72, a7a5aeb5, bcda09af, 77a2232b,
    dd1747fe, babc5fed): the scheduled re-seal pass, `port49 directory reset-second-factor [--all]`,
    `unlock`, `init-enrollments`, `export` and `import [--replace]` on the admin socket, port49d and
    the broker wired, `store-roles` printing the enrollment store's own etcd role, and a stale open
    never replacing a newer handle.
  - **The client** (Task 11; dfbffd94, 389ced23): `port49 login --directory`, with the enrollment's QR
    code and its own retry words.
  - **The 3am cases through the real CLI** (Task 12; 0a483914, 5e9499fb): the directory down, a lost
    store, a throttle, a skewed phone, each end to end.
  - **Lab harness and run** (Tasks 13 and 14; 27e93b26, 9fb957f5, 6515ce80, 6735a7d4, 69aaf6e0,
    13a32cbb, 0182eb53, b22bf5a2, f60d1d91, 36367e22, b6b75d14, df5c865c, 13cf173a, 1527141c). Two
    product fixes came out of the harness review: a `directory_password`-only broker now starts with
    no `client_ca_file` (9fb957f5), and the L67 and L56 harnesses pin `issued_key_store: file`, so a
    lab never probes the machine's TPM (6735a7d4).
- **Rulings as made** (decision 47; D1 to D13 are the plan's):
  - **D1 to D11, as recommended: Ryan, 2026-10-14.** D1 TOTP held by port49, D2 enrollment as
    trust on first use inside windows, D3 the password's path, D4 the code before the password, D5
    the limits, D6 `auth.amr` `["pwd","otp"]`, D8 no domain shared with an IdP, D9 `pquerna/otp`,
    D10 `totp` is not a `per_login_mfa` method in 9e (carried, below), D11 the vocabulary.
  - **D7** a sealed file on the memory store that fails closed when lost (Ryan's rewrite of the
    recommendation), **D12** `directory.enrollment_store`, **D13** `export` and `import`: Ryan,
    2026-10-14.
  - **Pre-flight, the controller's:** counts live in `store:` (regional) and enrollments in
    `enrollment_store` (C2); the enrollment window is decided before the password, so outside every
    window there is no bind (C5); the TOTP step is taken before the bind (I1); port49d and the
    broker never create the enrollment store, `init-enrollments` does (I15).
  - **During execution, the controller's:** a store sealed under an unreadable key is `Stale` and
    re-sealed by revision (Task 4); `--all` replaces unopenable records and never drops an opening
    factor, and mark, import and create reopen a lost file first (Task 10); the lost-store answer
    says "missing or unreadable ... creates or restores it (the broker's log says which)", because
    the broker cannot tell a fresh volume from a deleted one and "not initialised" would steer a
    real loss away from the restore (Task 12); a directory_password-only broker failing to start is
    a product bug (Task 13).
  - **Ruling 7, corrected by the lab (df5c865c, rule 4):** a state is named to the person only past
    a right code or when the directory's refusal proves the password (`PasswordRefusal.Proven()`:
    AD 530, 531, 532, 533, 701 and 773, `password_expired`, `change_after_reset`). The first draft
    named any account-state result, but L67 showed 775 and `accountLocked` also answer a wrong
    password, so an enrolling person was told whether a name was locked. Ruled by the controller
    as a security tightening, without Ryan; the cost, if wrong, is that a locked person sees
    "refused" while enrolling. Rulings 6 and D3 and D5 were corrected in the same commit.
- **Rows:** **L67 closed 2026-10-15** (`tests/lab/results/L67-openldap.md`, `L67-samba_ad.md`,
  `L67-windows_ad.md`: OpenLDAP, Samba AD, and Windows Server 2025 AD, build 26100.32230). What it
  changed:
  - Stock OpenLDAP (`olcPPolicyUseLockout` FALSE) answers a locked or disabled account as a plain
    wrong password.
  - Windows AD answers an empty-password bind success as anonymous, so port49 refuses an empty
    password before it dials.
  - The lockout margin is 1: nine directory failures through a fixed window against AD's threshold
    of ten.
  - Cell (f): every directory's entry creation time is what the broker reads (the control row);
    OpenLDAP's and Samba's were 1s and 7s before the fixture was logged loaded, and Windows AD's
    `whenCreated` could not be compared with an independently known seed time.
- **Carried:**
  - **Done 2026-10-16 (PR #14 and plan 9f).** **Ryan's rulings, 2026-10-15:** after 9e, a **small fix branch for issues #5 and #8**; **issue
    #6 is documented as intended behaviour in plan 13**; and a **small plan closes the `network_cli`
    address-keying gap** in the port49 Ansible lookup (9d's open gap). The lookup copies a name's
    key to an address that has none, and refuses an address with a different key, naming both and
    minting nothing.
  - **D10's `totp` as a `per_login_mfa` method:** a directory-password person meets a device's
    requirement only by `hardware_key_touch`; adding `totp` changes the policy schema and 9c's diff
    gate. A later plan.
  - **Plan 12:** ship `method: directory` in `/etc/port49/config.yaml`. Each shape keeps
    `enrollments.json` on state that survives (a persistent volume on k8s, `StateDirectory=` under
    systemd, a mounted volume in a container) and backs it up (`port49 directory export` from a cron
    job or CronJob, under `umask 077`). `port49 directory init-enrollments` is an install step (a
    one-off job on k8s), never a start path.
  - **Plan 11a:** the rest of the D12 split, with the enrollment keyspace as its own store role.
  - **Plan 13:** the guide, and these operator notes (issue #6 as intended behaviour with them).
  - **The pre-beta review:** looks at the enrollment windows (D2), and decides whether a `Proven`
    state (expired, must-change) telling a password-only person that the password was right is
    acceptable. It equals what a direct LDAP bind says and is throttled per principal.
  - **A flake to check at the final review:** `internal/port49d`
    `TestALostHoldEndsTheRunnersPassBeforeItWrites` failed once under full-suite load, 10 of 10
    alone, in code this plan did not touch. Known flake or real race; file an issue if pre-existing.
- **Left for later:**
  - **`port49 token` does not retry `store_unavailable`'s "retry in 5s"** (spec §5.7, on purpose,
    for the agent). After a broker restart on etcd the start gate keeps mints closed until the
    first takeover, 20s or more at the default hold, so an operator sees the refusal that long and
    has to retry by hand. Needs a spec ruling; proposed as an issue.
  - **A misleading log line:** `internal/directory/resolver.go` logs "minted from a membership
    verified 0s ago (grace)" when the start gate then refuses the mint. Pre-existing; an issue.
  - **`GET /v1/identity` shows no directory sign-in** (a certificate issued over one is not
    described there). Operators read the `issue` and `enroll` records.
  - **Parked review minors**, none a weakening: a doc reflow in Tasks 7 and 8, and Task 3's
    polish items. The final whole-branch review takes them.
- **Operator-facing notes** (the plan's "Operator notes," as built and corrected by the lab; plan 13
  builds the guide):
  - **New: sign in with the directory password and a second factor.** For a company with no PKI and
    no identity provider; either store shape works. A person runs `port49 login`, types their
    directory password and their authenticator's code, and holds a 12h certificate; after that
    everything is the certificate path (9b). The broker's config:

    ```yaml
    broker:
      directory: { … }                  # plan 7g's; certificate_mapping is optional without an x509 verifier
      identity:
        humans:
          - type: directory_password
            principal_domains: [corp.example.com]
            second_factor: totp
            filter: "(memberOf=CN=port49-people,OU=Groups,DC=corp,DC=example,DC=com)"   # keeps service accounts out
            enrollment:
              open_until: 2026-11-30T00:00:00Z   # the rollout
              new_entries_for: 336h               # a new hire's first 14 days; 0s off
              reopen_for: 24h                     # after reset-second-factor
            rate_limits: { failures_per_principal: 5, failures_per_source: 50, window: 15m }
        issuance: {}
    ```

    A broker whose only human verifier is `directory_password` starts without a `client_ca_file`.
    On each host, `/etc/port49/config.yaml` has `method: directory`. `GET /v1/identity` does not
    show a directory sign-in.
  - **Once per install, run `port49 directory init-enrollments`** on the broker's admin socket (as the
    broker's user or root). It creates the enrollment store; port49d never does, so a lost or
    unmounted volume is never mistaken for a new install. Until it runs, password sign-in is refused
    (`enrollment_store_lost`) and `port49_directory_enrollment_store_ok` reads 0. It refuses to run
    over a store that is already there.
  - **Back it up.** On the memory store the second factors are sealed in `enrollments.json` in the
    broker's state directory: run `port49 directory export > enrollments.sealed` from cron under
    `umask 077`, and restore with `port49 directory import` (`--replace` over a newer store). On
    etcd they live in etcd or, with `broker.directory.enrollment_store`, in an etcd of their own
    (one cluster across regions, so a code used in one region is used everywhere). With a replicated
    store, set `totp_label` explicitly: the default is built from the host name.
  - **First sign-in.** Inside a window, the right password shows a QR code: scan it with any
    authenticator app (or type the key), then type the first code. Every enrollment is an `enroll`
    record and `port49_sign_ins_total{outcome="enrolled"}`: **alert on enrollments outside your
    rollout.** Inside a window a stolen password enrolls the thief's phone first; the real person
    then finds a second factor they never set up, and that is the signal.
  - **Why the code comes first.** port49 checks the code, and uses it up, before it sends the password
    to the directory. A spray without the codes never reaches your DCs, so port49 cannot lock an AD
    account. The person sees one refusal for a wrong name, password or code; one who mistypes the
    password waits for the next code. Outside every enrollment window a person with no second factor
    is told enrollment is closed, and the password is not tried at all; that answer says the name
    exists and has not enrolled, which port49 accepts. port49 refuses an empty password before it
    dials, because Windows AD answers an empty-password bind as success (anonymous).
  - **Limits.** 5 failures per person and 50 per source address (an IPv6 /64) in 15 minutes, counted
    before they are judged, in `store:` (regional); a store error refuses. **Behind a load balancer
    or NAT that hides client addresses, every sign-in shares one source:** raise
    `failures_per_source` or set it to 0. **Keep `2 × failures_per_principal` under your
    directory's lockout threshold:** a fixed window lets up to `2 × 5 − 1 = 9` failures through
    around a window boundary, one under AD's default of 10 (L67 (d) measured it). The 429 for a
    person's limit says an operator can unlock the account; it never names the principal.
    **Attempt counts are per `store:` (regional):** with K regions, a spray against a person inside
    an enrollment window can reach K × (2 × `failures_per_principal` − 1) binds per window; size
    `failures_per_principal` against the directory's lockout threshold with that in mind.
  - **Locked and disabled accounts, by directory.** port49 names an account's state to a person only
    after a right code, or when the directory's refusal proves the password (expired, must change).
    **Stock OpenLDAP answers a locked or disabled account like a wrong password** (`olcPPolicyUseLockout`
    FALSE): it is refused and counted as a wrong password, with no state message. Set it TRUE for
    state messages and accurate records. **`port49 directory unlock` clears port49's count, not a
    lock held in the directory**; unlock the account in the directory too.
  - **At 3am.**
    - The directory down: sign-ins fail at once, 503, saying so; everyone holding a certificate keeps
      working, new agents included, within `directory.grace`.
    - Someone locked out by a spray of their name: `port49 directory unlock <principal>` on the
      broker's admin socket. Their held certificate works meanwhile.
    - A lost phone: `port49 directory reset-second-factor <principal>`; they enroll at their next
      sign-in within `reopen_for`.
    - A phone's clock off: the refusal says by how much.
    - "your second factor could not be read": the store's encryption key in use is not the one it was
      sealed under, and the previous is gone; reset the person's second factor. Keep
      `encryption.previous` until a scheduled re-seal pass has run after a rotation.
    - "the broker's store of second factors is missing or unreadable" (`enrollment_store_lost`,
      `port49_directory_enrollment_store_ok` 0; the answer says creating or restoring it fixes it
      and the broker's log says which): the file or etcd key is gone, will not unseal (the seal key
      changed), or this is a new install not yet initialised. Password sign-in alone is refused;
      held certificates, tokens and IdP sign-in serve. On a new install run `port49 directory
      init-enrollments`. Otherwise restore it (`port49 directory import < backup`, or the etcd
      snapshot). With no backup, `port49 directory reset-second-factor --all` lets everyone enroll
      again for `reopen_for` (24h): **alert on it**, as a stolen password enrolls first in that
      window. The unreadable file is kept beside the new one. **Run `--all` only on a replica that
      holds every current and previous key, never in the middle of a key rotation.**
    - After an etcd restore, a `reset-second-factor` run since the snapshot is undone (the lost
      phone's factor is back): run it again.
    - A person's entry re-created in the directory (after `port49 directory forget`): their sign-in
      is refused with the usual sentence, and the broker's log names `reset-second-factor` for them.
    - A broker restarted on etcd: for 20s or more the start gate keeps mints closed and `port49
      token` says `store_unavailable` ("retry in 5s") once; run it again.
  - **Alert on** `second_factor_reset` records with `"all"` or `"created"` (outside an install), on
    `port49_directory_enrollment_store_ok` 0 **and** `absent(port49_directory_enrollment_store_ok)`,
    on `enrollment_store_lost`, `sign_in_throttled`, `second_factor_enrolled` and
    `enrollments_import`.
  - **What is never logged:** the password, the code, the secret, the QR code's URI, the enrollment
    handle, and a name that matches no entry (people type passwords at name prompts).
  - **`per_login_mfa`.** A directory-password person meets a device's requirement only by
    `hardware_key_touch` (a YubiKey); `idp_mfa` needs a provider. A TOTP method there is carried to a
    later plan.
  - **New reason codes:** `sign_in_refused`, `sign_in_throttled`, `enrollment_closed`,
    `enrollment_store_lost`, `second_factor_enrolled`; new events `enroll`, `second_factor_reset`,
    `sign_in_unlock`, `enrollments_import`; metrics `port49_sign_ins_total{outcome}` and
    `port49_directory_enrollment_store_ok`; commands `port49 directory reset-second-factor [--all]`,
    `unlock`, `init-enrollments`, `export`, `import [--replace]`.
  - **Lab:** L67 (OpenLDAP, Samba AD, Windows Server 2025 AD) is closed; the readings above are its.

**Owed from plan 3 (owner's rulings 2026-09-24):**
- **A per-user config file** (e.g. `~/.config/port49/config.yaml`: `broker`, `broker_ca`,
  `cert`, `key`) so `port49 login` needs no flags. `broker_ca` stays **required** — the file
  supplies it, it never falls back to the system roots — and it pins the **CA**, not the
  broker's leaf, so a broker certificate renewal does not break every client. Flags override
  the file.
- **Hardware-backed client keys**: YubiKey through its **PIV** applet (PKCS#11), and platform
  keystores (TPM, macOS Secure Enclave), with touch/PIN policy. FIDO2 alone cannot sign a TLS
  handshake; it belongs to the OIDC path. Plan 3's PEM file stays as the fallback.
- **Optional CRL check of the broker's certificate** against the distribution points its chain names (`require` refuses a link that names none; the
  CA is the operator's own, so this is defence in depth; revocation of *client* certificates
  at the broker is plan 7's, spec §5.1.4).

**Owed from plan 8 (the controller's ruling on its pre-flight Q3, 2026-10-07):**
- **Mint by `scope`** (design §17: "Targets are named, not addressed: a device name or a
  `scope`, resolved through inventory"). Plan 7a built device names only (`api.MintRequest`'s
  `devices`), and no other plan owns scope targets. Spec text first: a sweep answers only devices
  the caller holds a grant on, so it is no enumeration oracle; per-item results; paging against
  `batch_max`. Then `port49 workload token --scope` (plan 8's client) and the Oxidized wrapper
  can ask for "every device I may back up" instead of a node list.

### Plan 9f — As built

`feature/network-cli-host-keys`, base `647f5e30`, 2026-10-16. Four tasks, each reviewed; a final
Opus review (0 Critical, 4 Important, 9 Minor) and one fix round.

- **Built:** `port49.hostkeys` gains `filed`, `address_entry`, `known_files`, `key_alias`,
  `revoked_keys_file`, `append` (the one O_APPEND, flock'd writer, which `remember` now calls with
  `refuse_other_types=True`) and `fingerprint`. The lookup `port49.client.token` checks every
  `network_cli` device before any mint (R2's four cases, R4 workload mode first), with the option
  `known_hosts_file` (default `~/.ssh/known_hosts`).
- **Rulings (controller):** case 3 (the name has no key, the address has) copies the address's key
  under the name, beyond Ryan's ruling, and warns and mints when no user file is writable; the
  gate reads the device's own `hostvars` (`ansible_connection`, else `ansible_network_os`), and the
  play's variables only for the current host; the name's keys are the port49 name's and the
  ssh_config `HostKeyAlias`'s, and a disagreement refuses; `KnownHostsCommand` refuses
  `host_key_uncheckable`; a name whose every filed key is revoked refuses `host_key_revoked`;
  `remember` keeps refusing a filed key of another type.
- **Lab (L66 (e3)–(e3d), arista_eos, 2026-10-16):** a moved address holding another key is refused
  before the mint on both ssh types, also with `connection:` as a play keyword (e3, e3c). A moved
  address with no entry: with `host_key_auto_add`, libssh still presents the token (e3b); without
  it, libssh and paramiko both refuse the stand-in after the lookup's copy (e3d). The README now
  says to run `network_cli` without `host_key_auto_add`; only a device's first contact needs its
  key filed another way. Results: `tests/lab/results/L66-arista_eos.md`.
- **Carried:** three `ssh -G` calls per device (final review m8; fold into one); the
  `ansible_network_os` fallback for a hidden connection is unit-tested only (the lab's play keyword
  reached the lookup); the e3 cells ran on one platform (client behaviour, as L66 says).

### Plan 9g — As built

`feature/junos-view-configuration`, base `681867cb`, 2026-10-16. Seven tasks, each reviewed; a
narrow fix (Opus review) and a second fix after Task 6's first lab run.

- **Built, with the task commits:**
  - Task 1, the L68 lab and gate G1 (`059d5548`, `a440bdd3`, `226b97ba`, `a19ad30a`, `5fba3a80`;
    L68 closed `0bacaa3f`; review fix `dd939078`).
  - Task 2, decision 48 (`3c0d0b27`).
  - Task 3, platform set 1.3.0 with `juniper_junos`'s `deny_reach_bits` (`613c69f1`).
  - Task 4, the reply sends `view-configuration` with its undecided reach denied (`e70bff04`,
    `6637d85c`).
  - Task 5, `policy test` names set 1.3.0's reach denies and predicts the configuration runs
    (`e5f5ddfd`, `aebbe484`).
  - Task 6, the projection differential and L68 through the broker (`539d5f82`, `efc6494c`),
    after the fix below (`909500e6`, `4aa55dea`).
  - Task 7, this entry.
- **Shipped as set 1.3.0, not 1.2.0.** Set 1.2.0 is released and frozen; 1.3.0 is 1.2.0 plus
  `juniper_junos`'s `deny_reach_bits: [view-configuration]`. A policy pinned to 1.2.0 renders as
  before. Where the added denies would pass 255 bytes, the reply falls back to the 1.2.0-style one
  and CI warns `projection_reach_deny_overflow` (as ruled).
- **Lab (L68, 2026-10-16, vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15):** G1 and G1-operator
  passed on both images, so the operator gets the bit too. `show configuration` ran and the
  rest of view-configuration's reach was refused in rows P, H and O where C took it; V
  (`view` alone) did not run it. Through the broker, set 1.3.0's rendered replies ran
  `show configuration` and refused `monitor`, for the readonly and the operator, on both images;
  the readonly's reply is the 173-byte `deny-commands`. One word runs nowhere: on vSRX
  `request unified-edge` and `req vir` are refused in C too.
- **Task 6's lab found a bug:** a plain readonly (granted `show **` alone) rendered the capability
  shape under 1.3.0, where spec and plan say the narrow shape as 1.2.0. Fixed (`909500e6`,
  `4aa55dea`) so set 1.3.0 renders exactly as 1.2.0 except where 1.2.0 refuses a permitted
  `show configuration`. Where 1.2.0 fails closed (`show **` less exactly `show configuration`),
  1.3.0 sends 1.2.0's reply plus `deny monitor **`; the controller ruled this within Ryan's ruling.
  The rerun was valid on both images; every vJunos disagreement with the model was the device
  being narrower (uppercase, image refusals), none wider.
- **Harness reader fixes (L68):** a BEL before the caret, a caret at the end of the echo, and an
  exec refusal tied to the probe's own word (a refusal of another word is not the probe's).
- **Recorded, not gated:** `show log` ran in P, H and O (a carve-out); `show firewall` and
  `show policer` were not refused; `file list /config` and `file show /config/juniper.conf.gz`
  were refused in P and O and taken in H; an scp read of `/config/juniper.conf.gz` was refused in
  P, V and C. `show configuration | save` wrote its file in P, H, O and C, and the pager's `s`
  was not graded (the pager did not appear where `set cli` is denied; elsewhere the harness's
  keystrokes were mangled); the `| save`, pager and `/config` readings stay L59's.
- **Carried:**
  - **L59 unchanged.**
  - **Hidden commands** are unmeasured.
  - **R2's fallback past 255 bytes:** the 1.2.0-style reply and `projection_reach_deny_overflow`,
    as ruled.
  - **Bit sets other than the two L68 measured** (readonly's and operator's) are covered by the
    model only.
  - **M5, for the final review:** reserve the role names `reach_deny` and `baseline` at policy
    load.

**Operator notes (plan 13).** These go in the pull request body; plan 13's docs pick them up.

- **What changes for a readonly and an operator under set 1.3.0.** Take a Junos grant that
  permits `show **` but denies something beneath it other than the configuration, such as
  `show security **`.
  - Under set 1.2.0 it could not read the configuration: the device refused `show configuration`,
    and `policy test` listed that refusal.
  - Under 1.3.0 the reply sends `view-configuration` too, and denies the rest of that bit's reach
    the grant does not grant (`monitor`, for a readonly). So `show configuration` runs.
  - Secrets stay hidden as they are for any session without the `secret` bit.
  - `monitor` stays refused. NETCONF stays closed for that subject, as it already was under 1.2.0
    (`projection_netconf_closed`).
  - Nothing changes for a grant that denies `show configuration **`, or for one with no deny
    beneath `show`.
  - A grant of `show **` less exactly `show configuration` (no `**`) does change: under 1.2.0 it
    failed closed; under 1.3.0 it gets `view view-configuration` with `deny show configuration`
    and `deny monitor **`. `policy diff` shows it as a RAISE.
- **Getting it: `port49 platform upgrade --to 1.3.0`.** A policy pinned to 1.2.0 renders exactly
  as before on the new binary; the change arrives only with the pin.
  - The upgrade report lists `platforms.juniper_junos.deny_reach_bits` as a gated change, with the
    `acknowledge:` entry to paste.
  - `port49 policy diff` on the move shows each reply that gains `view-configuration`.
  - To stay on 1.2.0's behaviour while taking the rest of 1.3.0, write
    `platforms: {juniper_junos: {deny_reach_bits: []}}`.
- **`projection_reach_deny_overflow`, at 3am.** It is a warning, not a failure. It means:
  - this subject's reply would have carried `view-configuration`, but the extra denies it needs
    would push `deny-commands` past RFC 8907's 255 bytes, which locks a Junos user out;
  - so port49 sent the 1.2.0-style reply instead: the session works, and `show configuration` is
    refused on the device.

  Nothing is broken and nobody is locked out. There are two remedies:
  - deny fewer commands beneath `show` in that subject's roles;
  - move the denies into the template's class on the device (`port49 platform export --classes`),
    where the 255-byte limit does not apply but they bind every subject at that template: every
    remote user on that device loses those commands, so move only denies all of them should have.

## Plan 10 — Kubernetes path (§19 step 10)

Projected ServiceAccount token validation against the cluster JWKS; identity
`system:serviceaccount:<ns>:<name>`; the `k8s` verifier type. Design §7.

Status: **executed 2026-10-16** (`2026-10-16-10-kubernetes-path.md`, branch
`feature/kubernetes-path`; twelve tasks; decision 49; Q1 and Q2 ruled; L69 closed, L70 open).
See "Plan 10 — As built", below.

### Plan 10 — As built

Executed from `2026-10-16-10-kubernetes-path.md` on `feature/kubernetes-path` (rebased onto main `02ca1ce8`; the plan
commits `c81d68f0`, `62f51e2b` and `aef54b9d` hold the plan, its pre-flight fixes and the Q1 ruling), each task reviewed, several through
a fix round. The ledger is `.superpowers/sdd/2026-10-16-10-kubernetes-path/progress.md`, with each
task's brief, report and review beside it. The Opus pre-flight (1 critical, 9 important, 15 minor)
was applied before Task 1.

- **Built, with the task commits:**
  - Task 1, spec: decision 49, L69 and L70 opened (`025c564e`).
  - Task 2, `internal/k8sid`, one parser for a service account principal (`d4e0af99`).
  - Task 3, `k8s` under `broker.identity.machines` (`9fa796a4`).
  - Task 4, a key set reads a cluster's JWKS directly and says where discovery differs
    (`e01c9998`).
  - Task 5, the k8s verifier: a pod-bound token, the exact audience, a listed namespace
    (`58efe511`, fix `73ef78c0`).
  - Task 6, the broker mints for a service account and records `auth.k8s` (`4a0bdbe9`, fix
    `153b37ee`).
  - Task 7, port49d builds each cluster's key set and says what it trusts (`a1e5cd23`, fix
    `79fdbfc8`).
  - Task 8, `port49 workload token --token-file` (`fbe9f79d`).
  - Task 9, `examples/kubernetes` (`87b42ee7`, fix `aa7a7832`).
  - Task 10, the L69 harness (`c164aa4e`, fix `e5ff120d`).
  - Task 11, the L69 run and its close (`ab54076a`).
  - Task 12, this entry (`7a42b0fb`).
  - The final-review fix wave: a bearer that is no JWS is recorded and said `k8s` on a broker whose
    verifiers are all clusters (`656e1700`, spec §5.7); test comments reworded (`f992a629`); the
    stalled-discovery and vanished-token-file tests (`30749596`); the k8s audience wording and the
    x509 and `directory_password` k8s-key refusals (`4f1db10a`); `NewClient`'s comment
    (`5198be7f`); `make test-race` takes `-timeout 30m` (`730641dc`); the example README claims only
    what an L69 cell measured (`9be5eaaa`); and the commit of this record's IDs.
- **Rulings as made.**
  - **Q1 (Ryan, ruled 2026-10-16):** several clusters may list one namespace. The same workload
    in every region's cluster is one identity and one policy subject. Each `k8s` verifier takes a
    required, unique `cluster:` name (`^[a-z][a-z0-9_]{0,63}$`) that port49 uses in records and
    log lines; nothing in the cluster changes. The start names the clusters that vouch for each
    namespace. The plan's text refused a name in two clusters; that was changed before Task 1.
    Cost if wrong: a cluster-qualified principal later, as an opt-in.
  - **Q2:** no TokenReview. `port49 revoke --principal` closes the window a deleted service
    account leaves (up to `exp` or `max_token_age`, 2h). L69 (e) measured it.
- **What differs from the plan's text.**
  - **Task 2.** Policy load now refuses a service-account principal Kubernetes can never issue
    (upper case, `_`, a dot in the namespace, a leading or trailing `-`, over length). Such a
    principal never matched a token, so nothing working breaks; the operator notes carry the
    upgrade note.
  - **Task 5.** A k8s assertion carries no `acr` or `amr`: the review found they could satisfy
    `per_login_mfa` (ruling 15). A token with `amr` is refused at the verifier; an `acr`-only
    token is still `per_login_mfa_required`. Its refusals and `String()` name the cluster.
  - **Task 6.** `K8s` is added to `token.MintRequest` and copied at the broker and minter; the
    identity answer shows a k8s caller as `k8s`, not `oidc`.
  - **Task 7.** The migrating case (one issuer moving between two `jwks`) shares a cluster name
    and is tested quiet about discovery naming the other issuer.
  - **Task 8.** The token file is read at every request and never printed; a missing or unusable
    file is exit 2.
  - **Task 10.** Names `port49-l69-a` and `-b`; the disk floor is 67584M; cell (c) has a positive
    control, (d) proves the key swapped, and a FAIL cell fails the run.
- **Interfaces added.** `internal/k8sid`; `oidc.KindK8s`; `VerifierConfig.Kind`, `.Cluster`,
  `.JWKS`, `.Namespaces`, `.Who`; `Config.K8s`; `KeySetConfig.JWKS`, `.Migrating`, `.Who`;
  `K8sBinding`; `Assertion.K8s`; `MethodOf`; `decision.K8s`; `workload.Config.TokenFile`;
  `TokenFileError`; `Policy.ServiceAccountIdentities`.
- **Lab.** L69 closed on kind v0.29.0 with `kindest/node:v1.33.1` (2026-10-16, all eight cells,
  `tests/lab/results/L69-kind.md`): the projected token's claims, the kubelet's rewrite at 0.87 of
  `expirationSeconds` (the docs' "about 80%" stands), anonymous discovery only after the
  ClusterRoleBinding, a rotated key fetched on first sight, a deleted pod's and service account's
  token still minting until revoked, a second cluster's token refused where unlisted and minted
  where both list the namespace, and the five refused shapes and the default token's audience.
  The anonymous `conditions` form of the structured authentication configuration is not
  measured. **L70** (EKS, GKE, AKS) stays open until an account exists.
- **Parked minors, carried** (the final fix wave fixed the rest):
  - Task 2: a mixed-case-prefix load test; a redundant length check; a wrapped error's wording.
  - Task 3: the `distinctClusters` compare of `jwks` is exact-string (it fails closed); the k8s
    `ca_file` load path is untested at config.
  - Task 4: overlapping discovery reads can land out of order; the "could not be read" note
    varies per attempt and prints the URL twice; no all-clear when discovery agrees again;
    no test sets `Who` on the key set's own lines.
  - Task 7: a migrating cluster prints two "is fetched" lines.
  - Task 8: a library test for a cert alone or a key alone; a `MaxTokenFile` boundary test.
  - Final review M2 and M3: `serviceAccount` checks the namespace before the `kubernetes.io`
    binding (messages only, fails closed); the unmapped answer names the configured cluster to a
    verified caller (a cluster name is not a secret).

**Carried forward.**

- **Plan 12:** a Kubernetes deployment test that runs the CronJob in a cluster against a broker
  outside it (and one inside it); the Helm chart's `issuer-discovery` binding per cluster; L39
  (b) and (c) stay plan 12's. The alert `time() - port49_oidc_keys_last_success_timestamp_seconds
  > jwks_max_age/2 or absent(...)` covers clusters with no change.
- **L70:** managed clusters, when an account on EKS, GKE or AKS exists.
- **Plan 13:** `examples/kubernetes/README.md` as the Kubernetes workload page, and the notes below.
- **Plan 11a:** a k8s verifier's kept keys are per broker state directory, like an OIDC issuer's.
  With one config across three regional brokers, each broker builds a key set for every cluster:
  one that cannot reach another region's API server says "keys not refreshed" hourly and fires
  the staleness alert for clusters it never serves (pre-flight M14). 11a decides whether a
  regional broker's config lists only its own region's clusters, or the alert is scoped per
  broker.
- **Left for later:** a cluster-qualified principal (`system:serviceaccount:<ns>:<name>`
  qualified by the verifier's `cluster`) as an opt-in, for an operator whose clusters'
  namespaces mean different tenants and who would rather name them apart than list different
  namespaces per verifier (decision 49, "Left for later"). Not planned to a plan yet.

**Operator notes (plan 13).** These go in the pull request body; plan 13's docs pick them up.

- **Upgrade note.** Policy load now refuses service-account principals Kubernetes can never issue:
  upper case, `_`, a dot in the namespace, a leading or trailing `-`, or over length. Such a
  principal never matched a token, so remove or correct it.
- **Kubernetes workloads mint with their pod's token** (spec §13 decision 49). No CA, no
  certificate, no secret at rest: the kubelet writes and rotates a projected service account
  token, and the broker validates it against the cluster's keys.
  - **Configuration:** `broker.identity.machines: [{type: k8s, cluster: us_east, issuer: <the
    cluster's --service-account-issuer>, jwks: <the API server's own address + /openid/v1/jwks,
    never the issuer's host>, ca_file: <the cluster CA>, audience: port49, namespaces:
    [netops]}]`, one per cluster. `cluster` is port49's name for it (`^[a-z][a-z0-9_]{0,63}$`,
    unique; nothing in the cluster changes), used in records and log lines. `issuer` is matched
    byte for byte with the token's `iss`; set it per cluster (kubeadm's default is the same on
    every cluster, and port49 refuses one issuer twice).
  - **The cluster** publishes its keys to the broker with one ClusterRoleBinding,
    `examples/kubernetes/issuer-discovery.yaml` (measured on kind, L69 (c); managed clusters are
    L70, unmeasured). Issuer discovery needs anonymous access to two paths; a CIS-hardened
    cluster with `--anonymous-auth=false` allows them through the 1.32+ structured
    authentication configuration (its anonymous `conditions` form is not measured).
  - **Several clusters may list one namespace.** The same workload deployed to every region's
    cluster is one identity and one policy subject: list `netops` in each region's verifier, no
    per-cluster namespace or overlay. The start says which clusters vouch for each namespace
    (`identity: k8s namespaces: netops: eu_west, us_east`); check it after adding a cluster.
    Where a namespace means different tenants in different clusters, list different namespaces
    per verifier.
  - **The principal** is `system:serviceaccount:<namespace>:<name>`, verbatim. The policy refuses
    one outside that form at load, and the start says which a configured cluster cannot give.
- **The workload:** `port49 workload token --broker … --broker-ca … --token-file
  /var/run/secrets/port49/token leaf1`. The token is read at every request, never printed. The
  pod mounts a projected `serviceAccountToken` volume with `audience: port49` and
  `expirationSeconds: 3600`, and `automountServiceAccountToken: false` (the default token's
  audience is the API server's, and it is refused). Exit codes are `port49 workload`'s: 0, 1, 2
  (a missing or unusable token file), 75 (retry later), 77 (final).
- **What is refused, and how it reads:** another audience, an unbound, Secret- or Node-bound
  token, a token older than `max_token_age` (2h), a namespace the cluster does not list, a
  cluster not configured. Each is 401 with the reason and a detail naming the check.
- **A cluster's API server unreachable:** keys held are used for `jwks_max_age` (24h) after the
  last good fetch, said hourly and on `port49_oidc_keys_fetch_failures_total{issuer}`; then 503
  `identity_provider_unavailable`, retried by `port49 workload`.
- **Key rotation at the cluster** needs nothing from port49: a new key is fetched on first sight
  (measured on kind, L69 (d)).
- **To stop a workload at once:** `port49 revoke --principal system:serviceaccount:<ns>:<name>`.
  Deleting its service account or pod is not immediate at port49: a token already issued stays
  valid until its `exp` or 2h after issue (measured on kind, L69 (e)). The mark also stands for a
  service account re-created under that name until `port49 revoke --lift`, and, since the
  principal names no cluster, for that service account in every cluster that lists its namespace.
- **Records:** a cluster caller's records carry `auth: {method: k8s, k8s: {cluster, issuer, sub,
  serviceaccount_uid, pod, pod_uid, node, jti}}`: which cluster and pod minted. Log lines and
  refusals name a cluster as `cluster us_east (<issuer>)`.
- **Metrics:** the `port49_oidc_*` series cover clusters, labelled by the configured issuer (not
  by `cluster`).
- **Per-login MFA** applying to machines cannot be proved by a k8s workload: such a device is
  reported `per_login_mfa_required`, not minted.
- **Lab:** L69 (kind v0.29.0, Kubernetes v1.33.1); L70 (managed clusters) open.

## Plan 11 — RFC 9887 TLS listener (§19 step 11)

Separate listener on 300, mutual TLS replacing the shared key, device records expressing
both. Design §11.

Status: **executed 2026-10-17** (`2026-10-16-11-tls-listener.md`, branch `feature/tls-listener`;
fourteen tasks; decision 50; L71 and L72 closed, L73 open). See "Plan 11 — As built", below.

### Plan 11 — As built

Executed from `2026-10-16-11-tls-listener.md` on `feature/tls-listener` (rebased onto main
`8fdebdff`; `1bc6bc75` and `9c5c328a` hold the plan and its pre-flight fixes), each task reviewed,
most through one to three fix rounds. The ledger is
`.superpowers/sdd/2026-10-16-11-tls-listener/progress.md`, with each task's brief, report and
review beside it. The Opus pre-flight (0 critical, 7 important, 14 minor) was applied before Task 1.

- **Built, with the task commits** (fixes follow the task's own commit):
  - Task 1, spec: decision 50, L71 to L73 opened (`64c7e062`, fix `1aff17ba`).
  - Task 2, wire header checks for TLS and the RFC 9887 ERROR reply (`592178b2`).
  - Task 3, admission of a `transport: tls` device with no shared key (`d022dbb0`, fix `80005018`).
  - Task 4, `internal/devicecert`, the verdict on a device's client certificate (`7489744e`, fixes
    `d26c4fcc`, `053e1860`, `62992bb9`; the Junos note on L73 `cfc88ad4`).
  - Task 5, `tls_listener:` and `listen: none` in port49d.yaml; certificate status by component and
    a cached check; two `tls` devices equal under ASCII fold refused admission at load (`79e9a5cb`,
    `ee4fd771`, `0d43aef0`, fixes `ae944f36`, `adb08981`).
  - Task 6, TLS record fields, diagnoses and metrics (`f710ae77`).
  - Task 7, the listener: decided at Accept, then TLS 1.3 with mutual certificates (`550d6901`,
    fixes `11973200`, `37ba645c`, `1212ddab`).
  - Task 8, a transport or address change withdraws open connections; the 49 mismatch record
    (`24c7dc84`, fix `5e053d6b`).
  - Task 9, single-use, age-bounded session tickets (`050ffa4d`, fixes `cca746f7`, `c55d31ef`,
    `7adbc1e0`).
  - Task 10, port49d loads, reloads and serves the listener (`83085748`, `63114549`, fixes
    `6cc95b47`, `88feaabd`, `b647c744`, `09595630`, `d6d4db8d`; a test flake, `a51323f9`).
  - Task 11, the L72 harness (`35092d55`, fix `a3ff4c10`).
  - Task 12, the L71 probe (`f3cbe387`, fixes `73100c39`, `09a68f75`).
  - Task 13, the lab runs and their closes (`e26c6c9e`, `a9bee774`, `7631fe16`, `10be6456`).
  - After Task 13: L29's refused phase uses `transport: udp`, since `tls` is now served
    (`d70176c0`).
  - Task 14, this entry.
- **Rulings as recorded** (decision 50 and the ledger), and what a review or a lab result changed:
  - **Q2 (ruled 2026-10-16, Ryan told):** one host may serve both listeners, with the start notice
    and its two caveats; a per-device transport blocks a downgrade by port. Cost: a departure from
    RFC 9887 §5.1.1's SHOULD NOT, named in decision 50.
  - **Pre-flight:** the certificate's status is checked after the handshake completes (so a refusal
    for status is a reset, not an alert); the certificate-status metrics gain a `component` label;
    `expiry_warning_fraction` is 0.33; an open connection is re-checked from the cached status
    only.
  - **Changed by review:**
    - Names (Task 4): ASCII-only fold; two `tls` devices equal under it are both refused
      admission, not the whole load, as their own refusal `tls_name_clash` (not `key_group_tie`,
      which names a key group a `tls` device lacks).
    - Unidentifiable devices (Tasks 5 and 7): a `dns_suffixes` clash, or a non-ASCII name with no
      `ip_address` match, is judged by the TLS listener alone (`devicecert.Rule.Unidentifiable`),
      not by admission, so every replica means one thing. It is decided at Accept from the source
      address, with no handshake and no strike (the first draft struck in `VerifyConnection`, which
      runs before `CertificateVerify`, so the peer had proved nothing), and named once at start or
      reload.
    - Tickets (Task 9): a resumption chain is bounded by its original full handshake plus the
      lifetime, with stamps taken as monotonic time since the guard began, so a wall-clock step
      replays nothing. Cost: a device re-handshakes at most hourly, when tickets are enabled
      (`session_ticket_lifetime` defaults to `0s`, off).
    - Reload (Task 10): a CA rotation needs no restart: the checker's issuer set follows the
      swapped anchors, and the unidentifiable set is computed before the swap, closing a
      fail-open window. Edits to `tls_listener:` keys do need a restart, said once at SIGHUP.
  - **Changed by lab (Task 13):** L72 cell h proves a CRL past a real `nextUpdate` served over
    HTTP, not a list never loaded; the openssl transcripts are filtered of every hex dump line,
    because the first run's leak check found session material in one. L71 sends no TACACS+, so its
    capture is the masked CLI probe transcript, not a pcap.
  - **No new register cells** for port49-internal behaviour unit tests pin against `crypto/tls`
    (Unidentifiable, the name clash, sequence 255, the ticket chain, CA rotation). Cost: no
    process-level measurement of the ticket chain across SIGHUP.
- **Q1 (the images that carry an RFC 9887 client): pending with Ryan.** Ryan read the Juniper
  Feature Explorer on 2026-10-16: TACACS+ over TLS arrives in Junos 26.2R1 on routing and
  switching platforms, not SRX. Fetching a vJunos-router 26.2R1 or later and a C8000V 17.18.1 or
  later is pending, so L73 stays open.
- **Lab.**
  - **L72 closed 2026-10-17** (`tests/lab/results/L72-reference.md`, run at `e26c6c9e`): all 15
    cells agree with decision 50.
  - **L71 closed 2026-10-17** (`tests/lab/results/L71-*.md`, five notes): none of vEOS-lab 4.31.2F,
    C8000V 17.13.01a, N9300v 10.4(2)F, vJunos-router 23.4R2-S2.1 or vSRX3 21.4R3.15 offers a
    client. vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 were not probed: they are not in the
    harness platform list.
  - **L73 open:** every claim about a device's RFC 9887 behaviour is unmeasured.
- **Parked minors, carried:** Task 2, gofmt churn and the ERROR reply's default type; Task 6, a
  double read of `DevicesByTransport`, a metric registered outside the main list, a hard-coded 14;
  Task 9, three minors on the ticket guard; Task 10, an accept under `c.mu` on an issuer change.
- **Before the final review.** The controller's full suite found L29's refused phase still
  setting `transport: tls`, which is now served; it sets `udp` (`d70176c0`).
- **Final review** (0 Critical, 1 Important, 5 Minor; one fix wave and a scoped re-review):
  - **Important, fixed:** port49d judged the certificate-name clash over admitted devices only,
    so Task 5's refused-device rule never took effect and `leaf1.example.net` beside a refused
    `leaf1` was served. It now judges every inventory device, on start and reload (`361df03c`,
    `75b9fc18`).
  - **Fixed:** a seq_no 255 packet with the unencrypted flag clear is closed without a reply
    (`9db8c9b8`); an OCSP answer in use is refreshed at its refresh point with no packet needed,
    as ruling 9 says (`5caded46`); the L72 evidence carries no credential or token hash value
    (`b26f020d`, `1cba72b9`); ruling 19 and the design cite Junos 26.2R1 as unmeasured until
    L73 closes (`e8cdda43`, `32d990c9`).
  - **Accepted:** a ticket is marked used before crypto/tls checks its binder, so an on-path
    observer at an admitted device's address can burn one. Ruling 11 names it, crypto/tls gives
    no later hook, and it costs the device one full handshake.

**Carried forward.**

- **Plan 12:** the reference device configurations, the listener's exposure, the alarms and the
  load test, as listed under "Plan 12", below.
- **Plan 13:** the RFC 9887 page and the operator notes, as listed under "Plan 13", below.
- **L73:** device images that carry a client (Q1).
- **Final-review note** (not operator-facing): a session ticket is marked used before the PSK
  binder check, so an on-path observer can burn a ticket. It costs the device one full handshake.

## Plan 11a — Directory and session stores (design §13; Ryan, 2026-10-14 and 2026-10-17)

Status: **executed 2026-10-19** (`2026-10-17-11a-directory-and-session-stores.md`, branch
`feature/directory-and-session-stores`; twenty-two tasks; decision 51; L74 and L75 closed 2026-10-19,
`tests/lab/results/L74-regions.md` and `L75-regions.md`). Written 2026-10-17: thirty rulings recorded
as decision 51 by its Task 1, R1–R10 and R13 (membership split by write rate) Ryan's; Q1, a
back-channel logout's reach across regions, ruled by the team lead as R26: logout records in the
directory store, followed into each broker's copy; the pre-flight's fixes on the team lead's rulings
as R27–R29 and amendments to R13, R19 and R25, and the one item not taken as R30. It opened L74
(three regions: the cache, the cut, a restart during it, the fail-closed edges) and L75 (the TOTP used
step, the unlock, membership's pin and back-channel logouts across brokers).

Roles and data placement are built in; topology is the operator's. port49 has two stores named by
function. The **directory** store (`stores.directory`) holds what is written rarely and must agree
everywhere: enrollments (9e's `directory.enrollment_store` folds into it), revocations, unlocks,
second-factor resets, the TOTP used-step record, back-channel logout records, and a directory
membership's pin (so one
`port49 directory forget` reaches every region; its per-mint freshness stays regional). The policy is a file every host loads; the
store keeps only a runner's judgement of it, beside its own sessions (R12). Each port49d and
port49-broker watches the directory and serves reads from a local cache. The **session** store
(`stores.session`) holds the hot path: tokens, login contexts, receipts, and attempt counts (a spray
across three regions gets 3×5 guesses, accepted unless the lab says otherwise). A single site omits
`stores.session` or points it at the same store. Ryan's shape at work (three regions, three
Kubernetes clusters) stretches the directory etcd one member per region and runs one session etcd
per cluster. A region cut off from the directory keeps verifying from its cache and refuses
directory writes (fail closed), password sign-in included, since its TOTP step is a directory write.
The old top-level `store:` key is removed outright. `port49 store status` shows each store as a
process sees it. Lab: three simulated regions with netem latency and a cut region, measuring the
cache, the fail-closed edges, and the cross-region replay of a TOTP code. Backups stay the operator's
tools (cron, Velero, etcd snapshots); the notes show one of each, alongside 9e's `port49 directory
export` and `import`. Lands before plan 12, whose failure matrix includes the cut region.

### Plan 11a — As built

Executed from `2026-10-17-11a-directory-and-session-stores.md` on `feature/directory-and-session-stores`
(base `29c11d98`; main merged in at `b3329154`), each task reviewed, most through one to three fix
rounds. The ledger is `.superpowers/sdd/2026-10-17-11a-directory-and-session-stores/progress.md`, with
each task's brief, report and review beside it. The Opus pre-flight (2 Critical, 9 Important, 20 Minor,
then two re-reviews) was applied before Task 1.

- **Built, with the task commits** (fixes follow the task's own commit):
  - Task 1, spec: decision 51, L74 and L75 opened (`02e256c2`).
  - Task 2, `stores:` replaces `store:` and `broker.directory.enrollment_store` (`eae7953c`, `72385ac5`).
  - Task 3, a mark's origin in the process's copy, the directory cache's freshness, and a feed that
    loads first (`76375c08`, `0987241c`).
  - Task 4, unlock records in the directory store, `ul/` (`c9204005`, `c41587c6`, `7b57406a`).
  - Task 5, an unlock starts every region's attempt count (`a363c07a`, `31150045`).
  - Task 6, `internal/store/placement`: the marks in the directory store and their copy (`be87de5e`,
    `c60d7749`, `f76945b8`).
  - Task 7, etcd roles per store and the member count (`f4d19cbe`, `e0dfe912`).
  - Task 8, `Broker.ReachMark`, Revoke's reach after its mark (`f1bb527d`, `e118928c`).
  - Task 8a, directory membership's pin in the directory store with no lease, freshness per region
    (`c3efddbe`, `90a07821`, `84d6b511`).
  - Task 8b, back-channel logout records in the directory store, followed into each broker's copy
    (`8ea39a66`, `582a165b`, `7d43014b`, `1a19a0dc`).
  - Task 8c, `Broker.ReachLogout` (`92438b17`, `aea61ecd`).
  - Task 9, port49-broker on two stores (`2173f277`, `c23d0a46`, `c0ca605b`, `0b194a8a`).
  - Task 9a, every region holds the directory's encryption keys; one cluster named twice refused
    (`8c934fc6`, `df873f96`, `51441e27`, `6785a6d9`).
  - Task 10, port49d on two stores (`b8d1a5a3`, `f9db08e4`, `642026c8`).
  - Task 10a, a restart during a cut serves from the region's sealed snapshot to the ceiling
    (`ec4a43f8`, `7aa045b4`).
  - Task 11, `port49d store-roles` prints a section per store (`db28096f`, `ee341fd4`).
  - Task 12, `port49 store status` (`d312b7f7`, `22cfdc4e`, `4ba43c9e`).
  - Task 13, the docs sweep: every config key named as `stores:` names it (`d05c567a`, `021bd304`).
  - Task 14, the three-region harness for L74 (`b9d6861a`, `7b4c0f9f`, `e722fc4f`, `1f8d3c91`,
    `0d49da99`, `7d3f800b`).
  - Task 14a, the L75 harness (`053bb702`, `1307dbe5`, `49a15de6`).
  - Task 15, the lab runs: nine runs; L74 and L75 closed at run 9, commit `470a6d08`
    (`cfce0f84`; the region evidence redacts `token_sha256` and `credential_sha256`, `a5f84e2e`).
  - Task 16, this record.
- **Found by the lab, fixed in port49** (not in the plan's tasks):
  - **One dark etcd member read as the directory not answering.** `RejectOldCluster` made
    `clientv3.New` fail whenever any one member was down, so a restart with one member dark was a
    cold-start outage, and a dark member with quorum intact stalled a call for the keepalive window
    (10s plus 2s: gRPC raises a keepalive below 10s to 10s). Fixed: `RejectOldCluster` off,
    `etcd.Open` never waits, reads are re-sent at a quarter and a half of the deadline, and the
    revocation and the lift are re-sent on another member by an explicit context opt-in
    (`767f0de1`, `e5e2093e`, `dbdbf117`, `c60af035`; `DialKeepAliveTime` 10s). The first diagnosis,
    a blocking dial (`b13f56fa`), was wrong and is reverted by `767f0de1`.
  - **`probeTLS` depended on endpoint order.** It now proceeds when any endpoint completes a verified
    handshake and is a store fault only when none does (`cb392148`, `8d3f03af`); a certificate fault
    confined to one member shows in `port49 store status` as `n/m members` (decisions 35 and 51).
  - **A stray lift could erase a later revocation.** A hedged or late delete landed after a
    re-revoke. A lift now deletes only the mark it read (`If ModRevision`), and a lift that finds the
    mark revoked again says nothing was lifted (`fe991838`, `dea01ee8`, `068ea1e2`).
  - **A logout or mark followed during a runner's takeover was dropped.** The follower queues from
    the start of the takeover (`97b075b7`).
  - **A watched pin served during a cut says it was served from the cached pin** (`a09127f4`).
- **Rulings, as recorded, and what a review or a lab result changed:**
  - R1–R10 and R13 are Ryan's and stand. R13 (pin, tombstone and refusals in the directory,
    freshness in the session store) held; Task 8a's review found that a cut and a miss on the pin
    read as "not pinned" (the moved-entry attack). It now reads as unavailable, and pin writes are
    compare-and-set.
  - **Q1 as ruled (R26).** A back-channel logout's reach across regions: the logout record lives in
    the directory store. Ruled by the team lead under standing autonomy; Ryan may overrule, and no
    overrule is recorded. Cost accepted: pending logouts are lost if the session store is lost before
    the heal. Keycloak does not retry a 503 (L45), so a cut region answers 200 and holds the logout
    pending.
  - R19 (the sealed snapshot, a 4h ceiling) stands. Task 10a's review kept a younger snapshot serving
    after the one that passed the ceiling is gone: skipping it costs availability and buys no
    security.
  - A failed start check after a snapshot start, or in port49-broker, ends the process (exit 1); a
    held non-snapshot port49d run says it once and does not follow.
  - L74 cell (d) waits 15s, not the harness's first 5s, for region 2's denial and records the
    latency: the marks watch can sit on the dark member's connection for the keepalive window.
  - L74 cell (i) proves the put-back by broker 3's `port49_store_feed_rescans_total{feed="marks"}`
    rising after the heal, not by a log line.
  - `tests/lab/results/*.md` keep `store.etcd.*`: they are historic measurement records.
- **Lab.**
  - **L74 closed 2026-10-19** (`tests/lab/results/L74-regions.md`, run 9 at `470a6d08`, etcd 3.6.15): all
    nine cells agree with decision 51. A cut region keeps logging in from its cache and refuses
    revocations (exit 1 in about half a second); a revocation made elsewhere reaches it about 11s
    after the heal; `port49 store status` exits 3.
  - **L75 closed 2026-10-19** (`tests/lab/results/L75-regions.md`, same run): a TOTP code is refused
    across brokers (20 of 20 races), an unlock reaches every broker, attempt counts are per broker
    (15 failures in all), membership's pin and a back-channel logout cross brokers, and a cut broker
    answers a logout 200, applies it at once and holds it pending.
- **Carried forward.**
  - **Plan 12:** the list under "Plan 12", below, with the etcd version floor.
  - **Plan 13:** the "Stores" page under "Plan 13", below, and the pending-logout dedupe note.
  - **Pre-beta review:** a full logout queue drops a logout's reach (the tokens live to their TTL).
  - **Qualification suite:** a lab cell for a write that lands after the heal (a lift or a revoke
    sent on a stalled connection, delivered once the link returns), and its reverse, a stray revoke
    re-creating a lifted mark (fails closed).
  - **Parked:** the hedge fires at a quarter of `call_timeout`, 125ms at the 500ms default, close to
    one cross-region read (40ms round trip at L74's netem); a stretched deployment's slow-tail reads
    hedge routinely and double the read load. Consider a floor, or hedging after a half.
  - **Parked minors:** a broker `dirErr` end-to-end test; a 1s held window before `watchCeiling`'s
    first tick; the config does not refuse an etcd endpoint host that is not an IP literal or a valid
    DNS name, or a non-numeric port (`store-roles` does today; when the config does,
    `TestStoreRolesRefusesAnUnsafeEndpoint`'s `;` input fails at config first).

## Plan 11b — Qualification suite (design §14; Ryan, 2026-10-17 and 2026-10-19)

Status: **written 2026-10-19** (`2026-10-19-11b-qualification-suite.md`, branch
`feature/qualification-suite`; twenty-three tasks; decision 52; opens L78 and L79; revision 1 applies the
pre-flight review; **executed 2026-10-21**, Plan 11b — As built, below). Numbered 11b, not 12: it
needs 11a's stores in the conformance runs, and plan 12 consumes its fleet mode for the load test, so it
lands between them (the 05b and 06b1 precedent; nothing is renumbered).

**Builds.** A mock device per vetted platform and firmware. Each is a YAML profile (snake_case) in three
parts. Credit: cisshgo (MIT) for "behaviour is data" and fleet mode.
1. **Stimulus**, generated from closed lab evidence:
   - the ClientHello;
   - the flight delay (NX-OS 10.6(2)F: 5.00 s);
   - the connection pattern;
   - each step's packet fields and attribute list;
   - the accounting records.
2. **Reaction table.** GETPASS → `send_credential`; FAIL → stop; ERROR → the measured fallback (IOS XE 17.18.02
   over TLS: break-glass fails); an alert → give up.
3. **Acceptance rules.** Byte limits, privilege range, role names, refused attributes. A measured rule
   cites a note whose Image version line names that firmware; otherwise it is `unmeasured` and never gates.

One engine, `internal/devicemock`, plays any profile against a real in-process port49d. It runs under the
same policy (`tests/qual/qual-policy.yaml`), daemon fragment (`tests/qual/qual-daemon.yaml`) and broker
mint path as the lab conformance run, so a golden from the lab is the mock's expectation. Credentials are
minted fresh per test:
- **TLS:** a byte-exact hello probe, then a `crypto/tls` session. Delays run at 0.1 scale against
  `handshake_timeout: 1s`, and one test runs the real 5.00 s against the 10 s default.
- **Gates:** port49's replies are pinned in goldens; a measured acceptance-rule violation fails.
- **Escape hatch:** Go only for what a profile cannot say, listed in its `engine_gaps`.

The tooling around it:
- **`genprofile`** builds part 1 from whitelisted evidence and pre-fills parts 2 and 3. It never reads
  a capture or a body.
- **`TestQualify`** is the lab conformance run that produces that evidence.
- **`make qual-vet`** chains the lab run, the generator, the mocks and the list for review.
- **`make lab-regress`** reruns closed entries on beehive under the lab lock (held once, passed to each
  child as a descriptor) and the STOP sentinel; `notediff` reports changed observations. Its full-run
  time is measured in Task 4.
- **Fleet mode** (`make qual-fleet`): N mocks from N loopback addresses against one port49d.
- **`docs/qualified-platforms.md`**, generated from the profiles and notes, with a drift test.
- **Tiers:** mocks on every PR on any runner (`qual.yml`, `runs-on` one line); SR Linux, the one
  redistributable image, in `lab-free.yml` on dispatch and release tags; vendor images on beehive only, before pre-beta and release
  tags and on any image change, not nightly.

**Spec sections.**
- §5.7: a `packet_fields` object on validated request records, the header fields as enum names (decision
  52 ruling 3).
- §13: decision 52; decision 48 ruling 4 made provisional on L78.
- §15: L78 and L79 opened.
- Design §14.

**Earlier plans hand it.**
- L73's `l73Dialects`, `l73Conns` and `*.tls.json` summaries.
- The lab harness (`platforms`, `labOccupyForRun`, the `lab.fault_file` switch).
- The decision log's validated records.
- `internal/port49d`'s in-process run, broker and `mint` test helpers, and `testpki`.
- 11a's stores. Plan 11's `handshake_timeout` (10 s default since PR #28).

**Leaves for later.**
- An SSH front on the mock (cisshgo-style): its CLI would be invented behaviour, and the ssh path is
  measured on real devices (L54, L64).
- SONiC (L77) gets its profile when its lab row lands.
- Plan 12 drives fleet mode at the §5 target rate.
- Plan 13 publishes the qualified-platforms page and the contributor guide.
- **Known, not fixed here:** `GOOS=darwin go vet -tags lab ./tests/lab/` fails on main at
  `tests/lab/l56_test.go:131` (`syscall.TIOCSPTLCK` is Linux-only). `make check-darwin` does not vet the
  `lab` tag, so CI never sees it. The fix (moving L56's pty helper into an `_linux_test.go` file) belongs
  to the next touch of L56, or the pre-beta review.

**Lab entries.**
- Opens and measures **L78**: a Junos *permit* reply over 255 bytes in total, Ryan's lock-out prior,
  unmeasured until now. It stays open for hardware Junos whatever vJunos shows.
- Opens and closes **L79**: a directory write delivered after the heal (11a's M4).
- Re-measures rows L1, L4, L6, L10, L13, L15, L19, L21, L28 and L73, open or closed, per firmware, closing
  none (decision 52 ruling 10).
- Adds a full **L73** note on **XRd 26.1.1** through a new XR dialect, help first.

**Carry-ins.**
- XRd 26.1.1's full L73 row (Task 16).
- 11a's **M4**: a lift or revoke delivered after the heal, and its reverse stray revoke, as row L79,
  cells (j) and (k) on L74's harness (Task 17).
- L76's **R3-M1**: `l76WriteText`'s mixed-pair wording, no rerun (Task 18).

### Plan 11b — As built

Executed from `2026-10-19-11b-qualification-suite.md` on `feature/qualification-suite` (base `cbc795de`;
rebased onto main at `800e8d2f`, PR #29, mid-run), each task reviewed, most through one to four fix rounds.
The ledger is `.superpowers/sdd/2026-10-19-11b-qualification-suite/progress.md`, with each task's brief,
report and review beside it. The Opus pre-flight (5 Critical, 14 Important, 14 Minor, then four scoped
re-reviews) was applied before Task 1. The plan grew one task, **14b** (below), which the controller added
when Task 14's review found a security-relevant device fact.

- **Built, with the task commits** (fixes follow the task's own commit):
  - Task 1, spec: decision 52, `packet_fields`, L78 and L79 opened (`545a0813`).
  - Task 2, `make lab-regress`: one held lab lock, the STOP sentinel, SIGTERM at the budget
    (`110ca2b2`, `6941bf44`, `7d9b0cd9`).
  - Task 3, `notediff`: a rerun's changed observations, timings kept (`d086f6ef`, `2c680dbf`).
  - Task 4, the first full `lab-regress` run and its fixes (`aeab4cad`, then `c0f53abf`, `afb5b36a`;
    notes `f4a9bed4`..`ce71c448`).
  - Task 5, `packet_fields` on validated request records (`1473b479`).
  - Task 6, `internal/devicemock`: the profile, loaded strictly (`90c45402`, `de420bcd`, `d293c1c6`).
  - Task 7, acceptance rules and the reaction table (`95c1ac19`, `05c99f48`).
  - Task 8, the hello probe and the flight delay (`4a01d4f6`, `7f6f7e9f`).
  - Task 9, the engine, `Judge` and the golden format (`3907232c`, `3ae17d68`, `850103b3`).
  - Task 10, `TestQual` and the shared policy and daemon fragment (`373c30ef`, `0c1b975c`, `c8e2582b`,
    `0e5d8b77`, `8d896ebb`).
  - Task 11, the mock tier in CI on every PR (`a860d936`).
  - Task 12, `TestQualify`, the lab conformance run with whitelisted evidence (`a7c94524`, `1cab078b`,
    `e486c565`, `c85e39eb`).
  - Task 13, `genprofile` (`5e7b4e44`, `b0a097d4`, `30dfc2fe`).
  - Task 14, ten platforms vetted, mock and golden each (`06279069`, `cf3404b8`, `ceb68909`, `be8862a1`,
    `3bf7cc40`, `68a04fe0`, `fd181ad5`, `1170bd92`, `857b62f1`, `2e43cea9`, with the harness fixes
    between them).
  - Task 14b, the TLS grading rework (below).
  - Task 15, L78 measured on vJunos 23.4 and 26.2 (`96a06528`, `33bdc8dc`, `4e549560`).
  - Task 16, XRd 26.1.1: an XR dialect, the full L73 row, the eleventh platform (`f1044cde`, `eade4fce`,
    `dd3b60fc`, `0d985aaf`, `00692cfe`, `452a3741`).
  - Task 17, L79 closed (`aa3685b3`, `870cd264`, `3d5f615a`, `33edde39`, `51161553`).
  - Task 18, L76's R3-M1 wording (`e7ff23d7`).
  - Task 19, fleet mode, `make qual-fleet` (`5b06903b`, `b15f4793`, `e47313d4`).
  - Task 20, the free-image tier for SR Linux (`2d23b712`, `5c912421`, `5f507862`).
  - Task 21, `docs/qualified-platforms.md` and its drift test (`b15cbef7`, `aec3ea98`).
  - Task 22, `make qual-vet` and the two procedures (`1d7b93b2`, `a82d766c`).
  - Task 23, this record.
- **Task 14b, the TLS grading rework** (`e60e7126`..`ec966feb`, then `7e4db36a`..`069d98f9`, a lab re-vet of
  the five TLS images, and `7cb1941f`..`0f6febe6`). Task 14's review found that NX-OS 10.6 over default
  per-request TLS never reached port49 with a command authorization, so a golden claiming "command
  authorization yes" was false.
  - TestQualify grades two TLS cells apart: per-request (the device default) and `tls_single_connection`.
    Each starts its verdict with the mode it ran in. A TLS cell that is not sent a command
    authorization is a recorded device fact, not an engine gap.
  - The hello probe records and sends the device's `key_share` groups, nothing it did not send
    (cEOS 4588, IOS XE 25, NX-OS, vJunos and XRd 29).
  - A command counts as run only when its output is no refusal (`qualRan`); the survey added the refusal
    text of every platform, NX-OS's role refusal among them.
  - `genprofile` carries hand-written entries forward, refuses a conflict, and refuses a generator-owned
    entry that a new run no longer yields. `-keep` and `-take` are per key. All eleven profiles regenerate
    with no flags.
  - The page has a column for command authorization over TLS.
- **Found by the lab or a review, fixed in 11b:**
  - L35 and L37 judged a dark port49d by plan 7e's circuit-open line. Decision 37's health checks make it
    dark at about 5 s, so the verdict was stale since 7f, not a regression (`c0f53abf`, `97c27bfb`).
  - The Ansible lookup failed for a name outside the inventory (L66, five entries). Fixed on main by
    PR #29 before the rerun.
  - The L78 grader counted any answer as a command run; Junos has no refusal marker, and a fail-closed
    reply answered `error: unknown command: show` (`4e549560`).
  - A wrong credential counted as refused on a reset with no record; it now needs a denied redeem
    (`c756f2ad`). The evidence audit no longer counts a recomputed TCP checksum as a rewritten byte
    (`8fe0bc32`).
- **Rulings, as recorded, and what a review or a lab result changed:**
  - **Q1** (the SR Linux job runs on dispatch and release tags) and **Q2** (an L78 result with no lockout
    on vJunos leaves the Junos rule `unmeasured`, decision 48's budget stands, ruling 4 provisional on
    L78) stand as ruled before Task 1.
  - L62, the Windows-VM and many-hour rows, and the hand-measured L11, L21 and L51 are excluded from the
    default `lab-regress` run, each with its reason in `tests/lab/regress.yaml`.
  - A rerun's rewritten notes are not committed wholesale: the Run line, dates and ids churn, and the L73
    rewrite drops hand-written operator facts. Only the changes a classified investigation called real
    were refreshed (L10 Junos, L49, L64 and L65, L22's wording).
  - `qual-policy.yaml` is one file for lab and mock (decision 52 ruling 5), scoped per platform for the
    denied command; platforms with no `platform_set` 1.3.0 adapter (SR Linux, XRd) carry an operator
    `platforms:` privilege block, measured, shown in the profile and printed on the page.
  - Junos's and SR Linux's command cells grade `not_applicable`: neither sends per-command authorization
    (L18, L76 cell b), and the page reads "— (L18)" or "— (L76 cell b)", never "no", only when that marker
    is recorded.
  - Golden paths are confined to `tests/qual/golden/` in `devicemock.Validate`, so every consumer gets it.
  - A refusal (alert, reset, close) resolves as one class per step: the alert and the reset race on the
    port49 side, so keying on the exact event made goldens flap.
  - The free-image job installs a pinned, checksummed containerlab `.deb`, not `curl | bash`.
  - Fleet mode: a reload that changes the answer clears only the changed keys (§5.1.3), which is why the
    fleet asserts no `projection_fail_closed` in any phase.
- **Lab.**
  - **`make lab-regress` in full: 733.6 minutes** (the sum of the 59 `measured_minutes` in
    `tests/lab/regress.yaml`, Task 4's first run plus the L35, L37, L66, L79 and L80 entries; the first
    full run took 723.5 minutes of passing entries and about 18 h 45 min of wall time with NX-OS boot
    retries). Slowest: L34 (103), L36 (67), L22 (44). Routine use needs `-only=` subsets.
  - **`TestQual`'s wall time: 11.1 s** (Task 14's final run, all ten platforms then vetted); `make qual`
    23.9 s, `make qual-fleet` 68.6 s. `make test` took about 948 s, of which `internal/port49d` was 910 to
    914 s of its 1200 s timeout, so `TestQual` stays inside `make test` with about 4.8 minutes of headroom.
    A package past about 1100 s needs the timeout raised or the package split.
  - **L78 measured, still open.** vJunos-router 23.4R2-S2.1 and 26.2R1.7: no lockout at any step up to a
    375-byte permit reply (break-glass logged in before and after every step;
    `tests/lab/results/L78-vJunos-router-*-juniper_vjunos-router.md`). Totals 400 and 600 cannot be
    rendered with every attribute at most 255: a deny list past 255 makes the projection fail closed
    (decision 26, `projection_fail_closed`), and on both versions that reply refused `show version`.
    Per Q2 the Junos profiles keep `junos_reply_total` `unmeasured`; the row stays open for hardware
    Junos and decision 48's 255-byte budget stands.
  - **XRd 26.1.1 and L73** (`tests/lab/results/L73-cisco_xrd.md`, row stays closed). The full row through
    a new XR dialect: XR's TLS server defaults to port 49, not 300, without `port`; it opens its single
    connection at commit; it needs `domain name` before enrolment; a group member and its host are
    removed in separate commits. Generic XR (no `platform_set` adapter) answers every command "not
    authorized" without asking port49, so it fails safe and is unusable: the profile carries an operator
    privilege block (readonly priv-lvl 1, operator and admin 15). After an ERROR reply break-glass fails
    on XRd over both transports, as on IOS XE 17.18.02.
  - **L79 closed** (`tests/lab/results/L79-regions.md`, `3d5f615a`, rerun at `33edde39`). (j) A lift under a
    cut exits 1 and says "could not be lifted, and stands": true, the mark is unchanged after the heal.
    (k) A revoke under a cut reports "could not be recorded", yet the hedged create-if-absent was
    delivered about 250 ms after the heal and re-created the mark after an operator's lift elsewhere. It
    fails closed (a denial, never a grant), but the message is false and the re-revoke is not logged.
    Decision 51's "provisional on L79" is resolved.
  - **L80 opened and closed 2026-10-21** (`tests/lab/results/L80-cisco_nxos.md`, `33fd31e9`). On NX-OS
    10.6(2)F over per-request TLS, `show users`, which port49's qual policy denies, ran, and port49 was
    never asked about it (0 `authorize_command` records for it). With single-connection on, port49 was
    asked and denied it. The cause, the device's local fallback, was presumed then; the post-11b fix
    (decision 50 ruling 20, port49 offering single-connect) closed the gap: with the offer the device asks about
    every command and `show users` is denied (fixed arm and re-vet, `tests/lab/results/L80-cisco_nxos.md`),
    and the page row reads "qualified". `tests/lab/regress.yaml` has an entry, `L80-nxos106`, and a run that observes nothing
    is INVALID and writes no L80 note, so the committed one stands (final review I2). Other NX-OS images do
    not overwrite the note.
  - L35, L37 and L66 passed on the rerun (L35 at `fee22706`, judging a dark port49d by decision 37).
    L29-reload's vJunos refused phase is a device flake, retry it.
- **Resolved: NX-OS 10.6 over per-request TLS.** Superseded by decision 50 ruling 20: port49 now offers single-connect, and with the offer the device asks port49 about every command and the deny holds (L80 fixed arm, `tests/lab/evidence/L80-cisco_nxos/fixed/`), so a warning or refusal is no longer pending.
- **Carried forward.**
  - **A post-11b fix PR** (port49 code, not 11b scope; Opus implementer, with P-1 first):
    - **P-1:** the settle pass keeps the old policy among priors and `supersedeTokens` clears each key
      whole, so tokens minted under the policy in force are deleted for about 30 s after an
      answer-changing edit (`token_not_found`); judge each unspent token by its own blob. Spec §5.1.3
      does not license that loss. **Fixed** on `fix/post-11b`: a changed key's tokens are judged one by
      one, blob and second-factor proof included (`MFAFresh`), and the reload line says the tokens kept.
    - **SNI:** an IPv6 literal fails `server_names`' `dnsShape` check, so IPv6 Junos cannot be listed;
      and `sni_mismatch` counts a strike, so a wrong `server_names` puts every Junos into malformed
      back-off. Trace the 3am case and decide whether a config error should strike devices.
      **Fixed** on `fix/post-11b`: `sni_mismatch` is declined under a standing window, with no strike
      (decision 50 ruling 10). `server_names` takes IP addresses, stored canonical and matched by
      address, and refuses at load a numeric entry that is not an address. What Junos sends over IPv6
      is L81 (b), open.
    - **Fail-closed reload (L78):** a reload that turns a subject's grant fail-closed must say so in the
      reload line, not only "0 device(s) quarantined". Spec §12 warning row first. **Fixed** on `fix/post-11b`:
      a count line and each finding at start, after every swap and every expiry pass, and the gauge
      `port49_policy_fail_closed_compositions`.
    - **Revoke text (L79 k):** "could not be recorded" should say it may still land when the link heals;
      the late write is logged and attributed. Consider a guard so a stale copy cannot re-create after a
      lift (a tombstone or revision floor).
    - **NX-OS 10.6 per-request TLS:** the §12 warning, if Ryan takes it.
    - **Concurrent mints from one principal** under fleet load.
    - **An XR `platform_set` adapter:** generic XR is unusable without an operator block.
  - **Plan 12:** the hand-offs under "Plan 12", below.
  - **Plan 13:** the hand-offs under "Plan 13", below.
  - **Final review (whole-branch, done 2026-10-21; its fix wave landed on this branch):**
    - `TestTLSDecidesAtAcceptBeforeAnyTLSByte` and `TestTLSNilMaterialDeclinesWithoutAStrike` ran
      `-count=100` under load with 0 failures. The flake is not reproduced, likely only under full-suite
      load, so it stays a carry. L74 cell (i), "marks feed rescan, 1 vs 1", flaked once (lab).
    - Fixed: the harness "ran <cmd>" grep found L78's grader reading only an `error:` prefix (I4; it now
      grades through `qualRan` and knows fail-closed steps, and the committed vJunos rows grade the same).
      Task 16's re-grade of the ten earlier platforms rests on committed evidence (a permitted
      `authorize_command` and output bytes), not first lines; the TLS re-vet regraded five.
    - Fixed: a not-measured L80 run no longer writes an L80 note (I2), and `lab-regress` fails an entry
      whose note the run did not rewrite (I3).
    - Fixed: SR Linux `operator` renders `priv-lvl=1`, read-only until a middle level is measured (I1).
      The QUAL SR Linux note is rewritten by an SR Linux re-vet, not by hand.
    - **Pre-beta review:** `0eee340`, `20fb9fa`, `2a74f88` and `79812ef`, cited in the L35 and L37 §15
      rows, are not ancestors of main (an earlier history rewrite; M5).
    - The key share is exact for cEOS and read from the ClientHello's group ids for the rest.
    - A source the generator drops survives as an extra citation.
    - The per-request TLS login cell grades login, so its `run.json` can read "pass" with no command
      authorization; the verdict and the page say so.
    - Confirm L35's iosxe `token_not_found` records (a spent token after the store came back) with a
      kept decision log on the next run.
    - Parked minors: Task 3's `-run-<12hex>` and `KEY=value` masks; Task 13's sub-5 ms delay rounding to
      0; Task 8's DelayFlight on a second ClientHello after an HRR.
    - **L80 restart cell (final review M1), measured 2026-10-23:** port49d restarted during an NX-OS
      command loop under device debug. On etcd, three runs: a clean reconnect, 0 lost, 0 unasked, 0
      denied, `ssl_read_failed=0`, `mark_server_dead=0`; on the memory store the device reconnects
      the same way, but every later command is denied `context_missing` until the operator logs in
      again (spec §15 L80; `tests/lab/evidence/L80-cisco_nxos/fixed/restart-summary.txt`,
      `restart_etcd-summary.txt`). The plan 12 NX-OS TLS reference config need not name two servers
      for a restart; its operator notes should say a restart on the memory store ends every live
      NX-OS session's commands until a new login.

## Plan 12 — Deployment (§19 step 12)

Deployment artifacts, the **reference device AAA configuration per platform** (the thing that
disables fall-through on FAIL, design §12), load validation at the §5 target rate, the
failure-matrix tests of design §12 and §14, observability alarms with a metric behind each
(design §15).

**Split into three plans (team lead, 2026-10-24), each merged before the next is written.** The
inventory every part draws from is `.superpowers/sdd/plan12-inputs.md` (105 items, themes A–G).
- **12a — Server hardening** (`2026-10-24-12a-server-hardening.md`).
  - **Builds:** every server-code item. Theme B, and theme A's code half:
    - `secret_ref` resolvers (`env:`, `file:`; no secret-store client, Ryan 2026-10-25) replacing every `*_env` secret key outright;
    - the key sets moved into the policy file's `keys:` (port49-broker.yaml's `key_refs` removed);
    - `token_secret_ref` and `webhook_secret_ref`;
    - one YAML document per file;
    - the source-of-truth client's `HTTPS_PROXY`;
    - `limits.max_connections`, shedding at Accept (`port49_connections_shed_total`);
    - `key_secret_refs`, bounding which secrets a policy may name;
    - the etcd version floor at start;
    - the broker start's paged loads retrying `ErrCompacted`;
    - the issuing-CA record (`meta/issuer`, fingerprints only; the key stays on each broker's disk, Ryan);
    - the write fence's ancestor walk.
  - **Spec:** decision 53 (its Task 1); §10 and §12; decisions 31, 43 (ruling 14) and 51; design §11 and §13.
  - **Hands on:** the configuration surface 12b's artifacts write.
  - **Lab:** none.
  - Status: **written 2026-10-24**, revised 2026-10-25 (`vault:` dropped; pre-flight C1, I1–I12 and M1–M19 applied); re-review READY, its 13 minors applied 2026-10-26; sixteen tasks; **executed** (Plan 12a — As built, below).
- **12b — Deployment artifacts, release and publishing.**
  - **Builds:**
    - the systemd and Kubernetes shapes beside 7f's container, each with its smoke test;
    - the four requirements every shape states;
    - etcd artifacts, single-site and multi-region examples, backups;
    - the issuing CA's files in each shape's state volume;
    - the release pipeline and client packages;
    - PyPI and Galaxy;
    - `make test`/`make vet` and `TestAnotherUIDIsRefused` in CI (Ryan lifted the workflow hold on 2026-10-24);
    - `file:` secrets per shape (Plan 12a — As built, Hand-offs, below);
    - each artifact's README (plan 13 writes the docs-site pages);
    - anycast through MetalLB, offered only after a lab row measures `externalTrafficPolicy: Local`.
  - Inventory themes A and E. Written after 12a merges.
  - **Plan:** `2026-10-27-12b-deployment-release.md`.
  - **Spec:** decision 54 (its Task 1); §10, and §12's "A key secret rewritten in place"; design §13.
  - **Lab:** opens L82 (Secret volumes and External Secrets on kind), L83 (Vault Agent and the CSI driver), L84
    (`LoadCredential=` and Compose `secrets:`) and L85 (MetalLB anycast), and runs each. L39 (b) and (c) stay 12c's.
  - Status: **written 2026-10-27**, revised the same day after its pre-flight (C1, I1–I14 and M1–M15 applied; the `.rpm` Python library (pip-only) ruled by the lead, Ryan may override; the release environments' tag restrictions are open for Ryan); amended 2026-10-27 for Ryan's ruling that every admin operation goes over the broker API with a security key press, the admin sockets removed and no socket flag on any command (Tasks 3a–3h, lab row L86); twenty-five tasks; **executed** (Plan 12b — As built, below).
- **12c — Reference configurations, alarms and lab rows.**
  - **Builds:**
    - the per-platform reference AAA configurations (L73's TLS ones included);
    - L39 (b), (c), the SR Linux ERROR row, and the Junos/NX-OS ERROR disagreement;
    - the failure matrix;
    - the alert rules (the global cap's shedding included);
    - the Junos `idle-timeout` per role (pending a ruling);
    - load validation at the §5 rate and the items sized from it.
  - Inventory themes C, D and F. Written after 12b merges.
  - **Hands on:** the artifacts 12b ships (Plan 12b — As built, Hand-offs, below): the `port49_key_secret_files_changed` alarm, L39 (b), the Oxidized `secure: true` follow-up, a measured Velero example, and whatever L83, L84 or L85 left FAIL. TODO(L83) TODO(L85)

Carried here from plan 1's review:

- **A global connection cap.** Today the only one is `EMFILE`, which is the worst possible
  cap: it fails `Accept` for admitted devices too, and it fails the spool's own `OpenFile`, so
  accounting starts answering ERROR. Plan 1 pulled forward the two cheap parts — the
  `accept_error` counter and log, and a 5s header deadline for a source that is not admitted.
  The cap itself, its sizing, and its alarm are this plan's.
- **Accounting throughput is bounded by one disk's fsync latency.** `Offer` holds one mutex
  across a `stat`, an open, a write, an fsync and a close, per record, for the whole fleet.
  The fix is a group commit — batch concurrent offers into one fsync — and it needs this
  plan's load numbers to size. Do not change it before there are numbers.
- **`key_validations_total{key_ref}` is a device-identity label in one deployment shape.** Key
  groups make `key_ref` a fleet-wide label with a handful of values, which is what the
  cardinality rule assumes. A deployment that pins a key per device (the tier-1 pin) turns it
  into one series per device — both a cardinality problem and, against design §15's "device
  identity never appears in metric labels", a correctness one. Say which it is and bound it
  when the alarms are written.

**Carried from plan 9a** (final review P15): state in the deployment docs that port49 is installed
0755, with no setgid bit and no file capabilities. `port49 ssh`'s askpass is `/proc/<pid>/exe`, which
a setgid or capability install makes unexecutable, and ssh then sends the device `""`.

**Carried from plan 6a** (Plan 6a — As built, "Carried"): `secret_ref:` resolvers, with the key
sets moving into the policy repository; `key_ref` on `port49_key_version_devices` and
`port49_key_retirement_seconds` as well as above; the write fence's ancestor directories and
ACLs, for `inventory_file` as for the policy file; `TestAnotherUIDIsRefused` run in CI as root;
the inventory-only refresh's cost at fleet size.

**Carried from plan 6b** (final review Minor 7): port49d's config loader
(internal/config/config.go) ignores a second YAML document; refuse it as port49-inventory does.
`config.InventoryServiceOf`, which `SIGHUP` reads, ignores one too.

**Carried from L76** (closed 2026-10-18; `tests/lab/results/L76-nokia_srlinux.md`): the SR Linux reference
configuration sets:
- `system aaa authentication exit-on-reject true` (cell l: break-glass is refused while port49 is up
  and denies it, and logs in with port49 stopped or a wrong shared secret);
- `priv-lvl-authorization true` on the port49 server group (cell i);
- `services [ cli ]` on every local role that a TACACS+ priv-lvl maps to (schema findings).

Before plan 12 ships `exit-on-reject true`, measure one case L76 could not reach: port49 up but
answering ERROR (its store unreachable, `store_unavailable`). L76's store is in memory, so cell (l)
covered a deny, a wrong key and port49 stopped, but not this one. If SR Linux treats an ERROR as a
reject, break-glass is locked out exactly when the store is down. That is the 3am case, so the
reference config waits on the measurement.

**Carried from plan 11a** (decision 51):
- Every shape ships a single-site example (`stores.directory` alone) and a multi-region one
  (`stores.directory` stretched one member per region, `stores.session` per region), each with
  `port49d store-roles` run once per cluster. On Kubernetes the stretched directory etcd is three
  StatefulSets (one per cluster) joined across clusters, or VMs; the session etcd is a
  StatefulSet per cluster. Neither is required; systemd and containers are peers.
- The failure matrix includes the cut region (L74): devices keep logging in; directory writes and
  password sign-in refused; `port49 store status` exits 3.
- Alarms: `port49_store_directory_reachable == 0` for 1m (a region cut from the directory: its
  revocations do not arrive); `time() - port49_store_directory_confirmed_timestamp_seconds > 60`
  (the cache is stale, whatever the reason); `port49_store_logouts_pending > 0` for 5m (a cut region
  holds logouts the other regions have not seen); `port49_store_feed_up{feed="marks"} == 0` as
  before.
- The same `encryption:` key material in every region, from one secret, and the three-step
  rotation (R27) as a runbook.
- Backups: each cluster its own. The directory etcd's snapshot (with `port49 directory export` from
  cron beside it, under `umask 077`) and each region's session etcd's snapshot; Velero for a
  Kubernetes-hosted etcd's volumes. One example of each in the operator notes.
- `stores.directory.etcd.call_timeout` sized to the directory's cross-region round trip, and the
  load test's numbers for the directory's reads at a sign-in.
- **The etcd version floor is enforced nowhere.** The client sets `RejectOldCluster` off (it failed
  `New` whenever any one member was down, which made one dark member a cold-start outage), and it
  enforced only 3.5.0 in any case. The documented floor (3.4.24, 3.5.8 or 3.6) is a deployment
  requirement: state it, and check it in the deployment tests, or at start without waiting on any
  member. L74 and L75 ran on etcd 3.6.15.
- **A dark member costs up to 12s.** gRPC raises a keepalive below 10s to 10s, plus a 2s timeout, so
  a dropped link to one member stalls the marks watch (events resume on another member) and an
  unhedged call for that long. Say it where the failure matrix and the alarms are written; reads and
  the opted-in mark writes are hedged, other writes are not.
- **The broker start's paged loads retry only `ErrUnavailable`.** Logouts and marks read 500 at a
  time at one revision (`brokerd.go`, the two loads beside the ledger's), so a compaction between
  pages returns `ErrCompacted` and the start exits instead of reading again. Pass
  `store.ErrCompacted` to both retries, as the ledger load does (11a final review, N1). The same
  pass can say a failed logout reach's long remedy once per run of failures rather than every
  retry, and drop the entry when the logout lapses.

**Carried from plan 11** (decision 50):
- The reference device AAA configuration for `transport: tls`, per platform, written from L73
  (closed 2026-10-18; every reading below is from `tests/lab/results/L73-<platform>.md`): port,
  SNI, the client certificate's enrolment (subjectAltName as `device_identity` expects, clientAuth),
  single-connection, the fallback timings, and no non-TLS fallback server for the same host
  (RFC 9887 §5.1.1). **Junos** (vJunos-router 26.2R1.7): mutual TLS is optional there and port49
  requires the client certificate, so the configuration must set `tls mutual-authentication
  certificate-id <id>`; a client that sends no certificate is refused `no_client_certificate`
  (measured, L72 cell c). The L73 inputs, per platform:
  - **Port (a).** Junos (`L73-juniper_vjunos-router.md`) and NX-OS (`L73-cisco_nxos.md`) dial 49
    when no port is set, so the reference configuration sets the port on the device; IOS XE dials
    6049 (`L73-cisco_iosxe.md`); EOS defaults to 300 (`L73-arista_ceos.md`). NX-OS sent a TLS
    ClientHello (215 bytes, four connections) to :49, where the RFC 8907 listener was running. The
    note shows no port49 record for them; if the RFC 8907 listener strikes them, ruling 17 shares
    the strike with 300. Set the port before the first login.
  - **SNI (c).** Junos sends the literal address as server name, so `server_names` must list it or
    stay unset (`L73-juniper_vjunos-router.md`); IOS XE, NX-OS and EOS send none.
  - **Enrolment (e).** Every platform's leaf is clientAuth only. Junos, IOS XE and NX-OS send leaf
    and intermediate; EOS sends its leaf alone, so set `intermediates_file`
    (`L73-arista_ceos.md`). NX-OS needs an RSA key: the ECC key Cisco document 224882 makes was
    refused at `crypto ca enroll` ("no rsa key-pair is associated with the trustpoint
    configuration"), so a reference configuration written from the document fails on 10.6(2)F
    (`L73-cisco_nxos.md`). On Junos the lab filled the TLS trust folder and placed the client certificate through a
    lab-only root shell (`L73-juniper_vjunos-router.md`). The refusals that led there (the image
    naming a root-owned folder, a super-user's `file make-directory` refused) were seen in earlier
    runs and are not in the note, so "Junos needs root" is not yet a measured claim. If it holds,
    it is operator toil at fleet scale, to raise with the vendor.
  - **Single-connection (h).** Without it one login opened 1 (Junos), 6 (IOS XE), 5 (NX-OS) and 6
    (EOS) connections. With it the logins opened 2 then 1 new connections on Junos
    (`L73-juniper_vjunos-router.md`), 1 then 0 on IOS XE and 1 then 0 on EOS, and 0 then 0 on NX-OS,
    which reused the readiness probe's connection (`L73-cisco_iosxe.md`, `L73-arista_ceos.md`,
    `L73-cisco_nxos.md`).
  - **Server identity (d).** IOS XE 17.18.02 accepted a server certificate naming another address,
    or none (cell d): it does not check the server's identity. Issue port49's server certificate
    from a CA the device trusts for nothing else (`L73-cisco_iosxe.md`). Unproven on Junos and
    NX-OS: both failed the login on a dNSName-only and on a wrong-iPAddress certificate with the
    cause unproven (`L73-juniper_vjunos-router.md`, `L73-cisco_nxos.md`); EOS refused both with
    `bad_certificate` (`L73-arista_ceos.md`). All four refused an expired certificate and one from
    an unknown CA.
  - **Fallback timings (i), warning first.** **When port49's store is down (ERROR replies), IOS
    XE 17.18.02 over TLS, as on 49 (L4), does not fall to its local method, so break-glass fails** (ok false in
    4.1 s after two `store_unavailable` records, `L73-cisco_iosxe.md`). Measured on the others
    with the same fault: break-glass landed on Junos in 2.2 s (`L73-juniper_vjunos-router.md`),
    EOS in 2.0 s (`L73-arista_ceos.md`) and NX-OS in 5.2 s (`L73-cisco_nxos.md`). After an alert,
    a reset at Accept and a decline window it landed on all four: Junos about 45 ms, EOS 2.0 s,
    IOS XE 5.1 s (alert), 21 ms (reset), 47 ms (window), NX-OS 5.2 s (reset 198 ms). NX-OS waits 5.00 s per handshake, so `handshake_timeout` must
    exceed 5s and a login takes about 25 s (`L73-cisco_nxos.md`). IOS XE: two `tacacs server`
    objects cannot share an address, so a TLS server replaces the plain one, and after declines the
    server stays Dead for 57 to 67 s (`L73-cisco_iosxe.md`).
  - **Never list a non-TLS server after a TLS one** on Junos or EOS: in the mixed list (j2) Junos
    opened one connection and EOS three to the plain server, each reset at once, so what they
    would have sent is unmeasured. IOS XE and NX-OS opened none. No platform sent a TACACS+ header.
  - **XRd 26.1.1.** Its sshd rate-limits at 60 sessions a minute by default
    (`L71-cisco_xrd.md`), which a login test must stay under.
- Every deployment shape exposes `tls_listener.listen` (default 300) beside 49, with the source
  address preserved as for 49. Binding 300 needs what binding 49 does.
- Alarms: `rate(port49_tls_handshakes_total{outcome!~"ok|resumed"}[5m])` by outcome;
  `port49_tls_device_certificate_lifetime_left_ratio < 0.33` and
  `port49_tls_server_certificate_lifetime_left_ratio < 0.33`, the default
  `expiry_warning_fraction`: a certificate past two thirds of its own lifetime, where ACME and
  cert-manager renew, so its renewal is late, whatever the lifetime (a fixed number of days
  would fire forever on short-lived certificates); `port49_tls_server_certificate_lifetime_left_ratio < 0`
  pages (expired);
  `increase(port49_cert_status_unavailable_total{component="tls_listener"}[10m]) > 0` while TLS
  devices are admitted; `time() - port49_crl_next_update_timestamp_seconds{component="tls_listener"} > -3600`;
  `increase(port49_inventory_changes_total{kind="transport_changed"}[1h]) > 0`, since a sync
  flipping a device from `tls` to `tcp` is a downgrade port49 records but does not block.
  **The `component` label:** `port49_cert_status_checks_total`, `port49_crl_loads_total`,
  `port49_crl_next_update_timestamp_seconds` and `port49_cert_status_unavailable_total` carry
  `component` (`broker`, `tls_listener`). A rule that divides or compares two such series
  one-to-one now fails to match across components; aggregate with `sum by (...)` or match with
  `ignoring(component)`.
- The load test includes full TLS 1.3 handshakes per connection (tickets off, the default) at the
  §5 target rate. Whether tickets should default on is that number's to decide.

**Carried from plan 11b** (Plan 11b — As built, above):
- The load test drives `make qual-fleet` at the §5 rate. Fleet mode plays N mock devices from N loopback
  addresses against one port49d, and one run holds a reload and a store fault mid-run (68.6 s at its
  default size). Concurrent mints from one principal under fleet load are unmeasured.
- A deployment shape's smoke test may use a mock device (`internal/devicemock`, a profile under
  `tests/qual/profiles/`) in place of vEOS: a login through the shape, then the state surviving a restart.
- Decision 48's 255-byte budget is provisional on L78. vJunos-router 23.4 and 26.2 showed no lockout up to
  375 bytes; hardware Junos is unmeasured, so ship the budget as it stands.
- Alarm on `port49_policy_fail_closed_compositions` > 0: a reload that turns a grant fail-closed
  prints the composition count line and each finding (the post-11b fix PR).
- The XR reference configuration needs an operator `platforms: cisco_iosxr:` block until a `platform_set`
  adapter lands (readonly priv-lvl 1, operator and admin 15; `tests/lab/results/QUAL-XRd-*.md`). SR Linux
  needs its block too.
- **NX-OS 10.6(2)F over TLS:** before the fix (L80), over per-request TLS a command port49 denies ran and
  port49 was never asked; port49 now offers single-connect and the device honors it
  (`tests/lab/results/L80-cisco_nxos.md`). A §12 warning or
  refusing those logins is no longer pending (resolved above).
- The pre-beta review runs `make lab-regress` in full (733.6 minutes).

**Deployment shapes (Ryan, 2026-10-03): not prescriptive.** Kubernetes is supported natively, never
required. Supporting every shape well matters for adoption. So "supported" means each shape has:

- its artifact;
- an end-to-end smoke test in CI. A device logs in through it, and its state survives a restart:
  - a systemd unit under a systemd container;
  - `docker compose up`;
  - a kind cluster.
- its own install page in plan 13's operator guide.

A shape without its test is not shipped. This plan ships all three shapes and treats them as peers.
The container shape arrives early, in 7f's Task 1: the image, `deploy/compose` and its CI smoke
test (`make compose-smoke`) exist and passed in 7f. This plan adds the other two and finishes the
container's install page:

1. **Binaries under systemd.** Units for port49d and, on etcd, port49-broker.
2. **A container image**, with a compose example: port49d, port49-broker and a three-member etcd.
3. **Kubernetes manifests or a Helm chart.**

Every shape states the same four requirements:

- **The device's source address reaches port49d unrewritten** (design §13). On Kubernetes that means
  `externalTrafficPolicy: Local` or host networking is expected to be needed (L39 (b), (c), open). Under Docker, for a device off the Docker host, a published port left it
  unchanged with the userland proxy on and off (L39 (a), 2026-10-05; modelled: a device on the clab bridge with an iptables RETURN rule keeping
  that bridge's own masquerade off its traffic, `tests/lab/results/L39-docker-proxy-*-arista_eos.md`). A device on another Docker network on the same
  host is masqueraded to the compose gateway by Docker's rule for its own network (the notes' first run). Kubernetes is unmeasured until plan 12.
- **On etcd, two processes.** port49d and port49-broker run apart (plan 7e). The memory store stays one
  process.
- **`broker.state_dir` survives a restart** (plan 7e Rulings 12 and 18). It holds `marks.json` and
  `witness.json`. A broker without it cannot tell that etcd was restored, so a `--bump-revision`
  restore with that broker started first goes uncaught.
  - systemd: a directory.
  - Docker: a named volume.
  - Kubernetes: a StatefulSet with a volume per replica, never a Deployment's empty directory.
    The Kubernetes deployment test must prove that a pod restart under the recommended
    `securityContext` (plan 7e Task 18's notes: no `fsGroup`, or `fsGroupChangePolicy:
    OnRootMismatch`, and a 0700 subdirectory an initContainer makes) keeps `broker.state_dir`
    accepted: under the default `Always` the kubelet makes it group-writable at each mount, and
    port49-broker refuses it.
- **etcd is port49's own cluster, never the Kubernetes control plane's.** It needs port49's roles,
  compaction, quota and backups (design §13), and a managed control plane does not expose its etcd.
  It runs as VMs under systemd, as containers with volumes, or as a StatefulSet.

`port49 revoke` speaks to a local Unix socket, so each shape says where to run it: the host,
`docker exec` or `kubectl exec`. Whether revocation should also be reachable over the authenticated
API is a question for this plan; it is not decided here.

### Plan 12a — As built

Executed from `2026-10-24-12a-server-hardening.md` on `feature/12a-server-hardening`, each task reviewed
(Opus 5.5 reviewers, Sonnet 5.5 implementer), most through one to three fix rounds. The ledger is
`.superpowers/sdd/2026-10-24-12a-server-hardening/`, with each task's brief, report and review beside it.
It opens no lab row.

- **Built, with the task commits** (fixes follow the task's own commit):
  - Task 1, spec: decision 53 (rulings 1–12), §10, §12, decisions 31, 43 and 51, design §11 and §13
    (`a8292c0c`, `68b127da`; later amendments `2e1df7df`, `37b49c2e`).
  - Task 2, one YAML document per file (`263ab3eb`, `0a7580ea`, `d8c7017e`).
  - Task 3, `internal/secretref`: `env:` and `file:`, read through the write fence (`aabf04fe`, `e5a8650f`,
    `7323dcd9`).
  - Task 4, port49d.yaml and port49-broker.yaml name every secret by `secret_ref` (`79b3a734`, `e6af8a43`,
    `7e14d2d9`).
  - Task 5, `internal/keyset` and the policy file's `keys:` block (`d455dcf8`, `3a927e7d`, `4ea60277`,
    `19e3bd2c`).
  - Task 6, port49d and port49-broker take their device keys from the policy, read at every reload
    (`91e18f58`, `d00ad1ae`, `00affe2c`, `2b3563c9`).
  - Task 7, a reload that retires a version ends its open connections with no strike (`14c38bea`,
    `9f646275`, `cedf4e26`, `0401f359`, `bdb1cd4b`).
  - Task 8, the CLIs read the key sets from the policy (`5888a143`, `f8f8e82c`, `29f0b4db`).
  - Task 9, `token_secret_ref` and `webhook_secret_ref` (`9b642e86`, `1527ce25`, `7a23e943`).
  - Task 10, the source-of-truth client's `HTTPS_PROXY` (`18a9addf`, `0530187a`).
  - Task 11, the global connection cap (`19edef0e`, `d851cfca`).
  - Task 12, the etcd floor (`fc70ff0e`, `abb5b076`).
  - Task 13, the broker start survives a compaction (`b9379a90`, `77fe9e3b`, `07da219b`).
  - Task 14, one issuing CA per store (`aa12c822`, `eb714c21`, `37b49c2e`, `7408b94d`).
  - Task 15, the fence's ancestor walk (`bafefe7f`, `641f0ccb`).
  - Task 16, this record (`35d2254a`, `6bfb7c77`, `408d96fc`).
  - Flake and race fixes found along the way: `033a532a`, `b6b04d1f`, `acbba4e3` and `da3cf8ae` (a shutdown no
    longer drops close_notify behind an in-flight reply write), `d049c197`, `72174c1b`, `a4498a61`, `babc4f6a`,
    `d61d0638`.
- **What changed in review.**
  - A late-directory broker issued certificates from a CA nobody had checked, because the record lives in
    the directory: issuance is now held (`503 issuance_unavailable`, unrecorded, the sign-in unspent) until the
    check passes, and `issueTo` itself refuses while held. A broker reads its CA files once and checks and
    issues from that one read. A rollback to the CA a rotation retired is refused as behind. `forget-issuer`
    now names the CA it forgets and deletes over the revision it read.
  - The fence's ancestor walk found test fixtures that nested a directory under `t.TempDir()`; under umask 002
    that parent is group-writable and is now refused. They were fixed in the tests, not excused in the code.
- **Carried forward.**
  - The Task 6 review's M5 items.
  - **12b: in-place rotation.** At each reload, re-read the held `file:` references (an `env:` value cannot change in
    process) and, when a held version's bytes differ, say a warning that the process keeps the bytes it read, that a
    restart takes the new ones and diverges from replicas that did not restart, and to add a version; repeat it at
    most every 10 minutes, as the key retry does. Warn, never refuse: a refused reload at 3am would block an unrelated
    urgent edit behind a key-file mistake. The warning goes into spec §12 first.
  - **12b: CI.** Raise `make test`'s `-timeout` to 30m (`internal/port49d` takes about 943 s against 20 m), and
    split port49d's etcd-backed end-to-end tests into a build-tagged or separate CI job. Do not parallelise: the
    tests swap package variables (`pagedLoadFault`, `endpointVersions`, `startRetryWait`, `stderr`, `stdout`).
  - **12b CI hardening: flake hit 8** (`brokerd_test.go:2206`, `:2293`, also `:2114` and `split_e2e_test.go:55`):
    add a test hook the witness follower calls with the revision it saw, and wait on it in place of each
    `time.Sleep(2 * witnessEvery)`.

#### Operator notes

These are the notes the pull request body carries. Each is true of the code as built.

- **Secrets.**
  - Every `*_env` secret key is replaced by a `secret_ref` key, with no alias; a config written for an
    earlier build is refused, naming each removed key and what replaces it.
  - `secret_ref` is `env:NAME` or `file:/absolute/path`. There is no `vault:` scheme (decision 53 ruling 5):
    a secret store reaches port49 as a file its own agent renders.
  - A `file:` secret drops one trailing newline; an `env:` secret is not trimmed.
  - An `env:` error names the key that holds the reference and never the variable. That is deliberate.
  - An unset directory bind password is found when the directory opens, not when the config loads.
- **Device keys.**
  - `keys:` moves from port49d.yaml into the policy file; port49-broker.yaml's `key_refs` goes. port49d and
    port49-broker refuse a policy with no `keys:`. Move `keys:` into the policy and remove it from port49d.yaml
    in the same rollout: the new build refuses either alone.
  - A policy names only the secrets `key_secret_refs` allows: `env_prefix` (default `PORT49_KEY_`, and it must end in `_`) and
    `file_dir` (default `/run/port49/keys`, holding device keys only). port49d.yaml's own secrets may not sit
    inside it. The compose stack's variable is `PORT49_KEY_TACACS`.
  - **Rotation is add, move, retire, and it is a reload, never a restart.** Add the new version (a new file or
    variable and a policy edit), move the devices to it, and retire the old version only once
    `port49_key_validations_total` for it has stopped counting. A reload that retires a version resets its open
    connections with no strike.
  - **Never rewrite a version in place.** An edit of a held secret (same version, new bytes) is not re-read until
    restart. Always add a new version.
  - A start with an unreadable config secret exits. So does a port49d start whose policy names a device-key file
    that cannot be read: `dk.build` runs once at start and its error ends the run (`internal/port49d/main.go`),
    pinned by `TestAStartWhoseDeviceKeyFileIsUnreadableExits`; the reload's retry is pinned in `keyretry_test.go`. A port49-broker loads no device keys. A
    reload whose secret file is not rendered yet keeps the old keys and retries every 30 s and on SIGHUP.
- **Startup under systemd.** A refused start exits and systemd restarts it. Set `RestartSec=` and
  `StartLimitIntervalSec=`/`StartLimitBurst=` so a start the server refuses (a CA mismatch, an etcd below the
  floor, a policy with no `keys:`) does not flap. This belongs in 12b's units; it is not written here.
- **etcd floor.** The floor is 3.4.24, 3.5.8 or 3.6.0, and a pre-release of a floor release is below it.
  Only the configured endpoints are asked, each within `call_timeout`: list every member's URL, never a VIP or a
  Kubernetes Service. A member that is down at start is said and stays unchecked until the next start. At a
  broker's late directory open a member below the floor is said and the open retried every 5 s.
- **Compaction.** A broker's start retries a compaction between pages. A compaction that keeps recurring says,
  once, to raise etcd's `--auto-compaction-retention`.
- **Global cap.** `limits.max_connections` sheds: it accepts, then resets the connection with no strike. It says
  so in one log line a minute, and the counter is `port49_connections_shed_total{reason="global_cap"}`;
  `port49_connections_max` is the cap. Unset, the cap is sized from the open-file limit (less 1024, or half the
  limit where that is less); an unreadable limit is taken as 4096, and the start line says so. The 12b hand-off covers `LimitNOFILE=`.
- **Egress proxy.** The inventory service's sources honour `HTTPS_PROXY` and `NO_PROXY`. Proxy credentials are
  never printed. A 407 means the proxy refused `HTTPS_PROXY`'s credentials; the token was not sent.
- **Issuing CA.**
  - Every port49-broker on one etcd store must hold the same CA. Run `init-issuer` on one broker and copy its
    `issuing-ca.pem` and `issuing-ca.key` to each other; each start prints the fingerprint. The store records the
    fingerprint only; the key never leaves a broker's disk.
  - A broker whose CA differs refuses to start, naming both fingerprints. One restarted before the rotation's
    files were copied is refused as behind a promotion and told what to copy.
  - A split broker whose directory has not answered answers `503 issuance_unavailable` until its CA is checked
    there; it says so once at start.
  - `port49-broker forget-issuer --current sha256:<hex>` removes the record, only when it names that CA. Stop
    every broker on the store first, then start one on the CA you mean to keep.
- **One YAML document.** A second document is refused in every file.
- **The fence.** Every directory above a policy, inventory or key file must be neither group- nor
  world-writable and owned by root or port49d's user, unless it is sticky (as `/tmp` is) and owned by root or
  port49d's user. A directory on a read-only mount is excused for its mode alone: its ownership is still
  checked. That excuse trusts whoever writes the mount's source, so the host side must itself be protected:
  `-v /srv/shared:/cfg:ro` with a 0777 host `/srv/shared` lets any host user swap the tree below it. Bind a
  directory only root or port49d's user can write. A `/home/<someone>` path, or a umask of 002 that left a
  group-writable parent, is refused naming the directory and the file being read. For a shared ancestor
  such as `/srv` or `/home/team`, do not `chmod go-w` it: move the file under a root- or port49d-owned 0755
  directory. POSIX ACLs show in the mode's group bits; NFSv4
  ACLs are not read, so keep the policy off NFS.
- **Upgrade.**
  - Brokers that each ran their own `init-issuer` refuse after the first records its CA. Before upgrading, compare
    the fingerprint in each broker's start line and copy one CA's files to the others.
  - The first replica of a rollout refuses to start against an etcd member below the floor: upgrade etcd first.
  - The start guard's first start is judged against the bundle last judged, which predates the policy's `keys:`.
    A new policy whose `keys:` omits a key_ref a key group names takes those devices out of service, and past
    `max_removed_percent` the start is refused. Run `port49 policy diff` between the old and new policy in CI.
  - A pre-12a replica decodes the policy strictly, so it refuses a policy with `keys:` at reload
    (`port49_policy_file_refused` at 1, its policy in force kept) and cannot restart on it. Roll the binary in the
    same change.

#### Hand-offs

- **12b.**
  - Each deployment shape writes `secret_ref`, and each shape's device keys live under `key_secret_refs.file_dir`
    or in `PORT49_KEY_*` variables.
  - `file:` secrets per shape (`fence.ReadSecret`: links followed inside the directory, owner root or port49d's
    user, no world bit, group-read allowed):
    - Kubernetes Secret volume: mount the whole volume at `file_dir`. Kubernetes' documentation says a `subPath` mount does
      not receive updates, which would keep a new key version from the next retry (unmeasured: assert it in the
      kubernetes smoke, which also asserts a whole-volume mount does receive it). `defaultMode: 0440` (or `0400`)
      and `fsGroup` set to port49d's group.
    - Secrets Store CSI driver: the same whole-volume mount. The driver's default file mode is documented as 0644
      (unmeasured); a mode with a world bit is refused, so set the provider's file permission and `fsGroup`, and
      measure what each provider writes before the shape documents it (a 12b or 12c lab row).
    - Vault Agent: the template's `perms = "0440"` (or `"0400"`), and the agent running as root or as port49d's user.
      The injector's default uid is documented as 100, which `fence.ReadSecret` would refuse (owner root or
      port49d's user): measure in the shape's smoke before the shape documents it. Render into `file_dir`.
    - Docker and systemd credentials: Docker's `secrets:` long syntax with `mode: 0440` and the gid (the default is
      documented as 0444: measure it in the shape's smoke); systemd's `LoadCredential=` files under
      `$CREDENTIALS_DIRECTORY`, which `key_secret_refs.file_dir` names (owner, mode and ACL unmeasured: measure first).
    - Each shape's smoke test adds a key version by writing a new file and asserts it is in force without a restart (the 30 s retry).
  - A secret store shown as `file:` references rendered by its agent in at least one shape.
  - `limits.max_connections` and `LimitNOFILE=`; systemd `RestartSec=` and `StartLimit*`.
  - The issuing CA's files on each broker's state volume, `init-issuer` once and copies to every other broker; `forget-issuer`
    in the runbook. A broker refused "behind a promotion" on Kubernetes crash-loops, so `kubectl cp` into it cannot work: the runbook
    copies the files with a debug pod that mounts the broker's state PVC.
  - The etcd floor asserted in each shape's smoke test, with every member URL listed.
  - The policy file's `keys:` in every shape's example; no NFS for the policy.
  - Every directory above the policy, inventory and key files non-group-writable (an initContainer or the image sets it; compose's umask).
- **12c.** An alarm on `port49_connections_shed_total{reason="global_cap"}` increasing; a warning on `port49_connections` near
  `port49_connections_max`, sustained.
- **Plan 13.** The `secret_ref` reference page with `key_secret_refs`; key rotation as policy edits, and the 30 s retry while a file is
  rendered; the issuer record's three refusals at 3am; the shedding lines.

### Plan 12b — As built

Executed 2026-10-27 to 2026-10-30 on `feature/12b-deployment-release` (draft PR #36). Twenty-five tasks: one spec, two code, the admin-over-API
amendment (3a–3h), two CI, seven artifact-and-smoke, four lab, one docs. Every task was reviewed (Opus for security, CI and release tasks, Sonnet
for mechanical ones) and every finding closed before the next task began. **Not yet recorded here, pending the CI runs: the lab states of L82, L83,
L85 and L86.** Those are the `TODO(L8x)` markers below; no result is asserted until its results note and spec §15 row exist.

#### Commits per task

- **Task 1, spec** (decision 54; the rewrite warning; rows L82–L85): `8fb1e43c`, minors `21d4566d`.
- **Task 2, the in-place rewrite warning:** `ab34d61d`; review fix `a6106161` (the said-state is keyed on reference and version, so a
  rewritten-then-removed file is still reported).
- **Task 3, flake hit 8:** `d850e7fe` (waits on the witness follower's hook, not a sleep); minors `c644dc8d`.
- **Task 3a, spec for admin calls over the API:** `fa557c3a`, `90de133d`, `d50022bb`.
- **Task 3b, the admin proof:** `89bc8b7d`; review `b1dfbce2`, `19bf4b98` (every gated form needs a touch; a record's `why` is a fixed word).
- **Task 3c, the admin endpoints and rights:** `fb43dffe`, `11b39814`; fixes `2f79b326`, `fce1b3dd`, `e399400a`, `5c1d511d`, `d1eacb7d`.
- **Task 3d, the agent and the CLI:** `a94cb5d5`, `a6a1432d`, `c58c17f5`, `3a0251dd` (`port49 revoke --sid`), `db810105`, `050391fd`, `caf26b00`.
- **Task 3e, the sockets removed:** `bb167345`, `a2ee8a14`; fixes `534c8530`, `a2b2547e`, `c5c57174`, `67952016`.
- **Task 3f, `keys-diagnose` from a capture:** `0bdf1236`; fixes `568fbc2a`, `3a3964c8`, `0ba75b17`, `ecd0fdf5`, `0b305179`.
- **Task 3h, no socket flag:** `d97c52c6`, `af334af3`; test flakes found on the way `fa995a02`, `cf8289c5`.
- **Task 3g, the L86 harness and runbook** (written for Ryan's run; no hardware touched by an agent): `8da1cb18`, `2e455159`, `93311ef0`,
  `dc561615`, `76afa2b7`, `4059e2c7`, `cddd60ba`.
- **Task 4, CI:** `f65f6b25`, `1cef7d3c`.
- **Task 5, the image:** `d8500531`, `9536ab7f`, `7dde9a5a`.
- **Task 6, compose:** `4a142e9e`, `b03815bb`, `95e78e59`, `ed7bbfaf`, `3b37c6e6`, `80b8cf31`, `b0d189b6`, `ab5b58c6`.
- **Task 7, systemd:** `747ea754`; fixes `37cacc46`, `3635aafc`, `2327579b`, `e2cd286f`, `e2eea048`, `e6ab6d1b`, `8c429236`, `67744964`, `f57e9496`.
- **Task 8, packages:** `4dae81ed`, `50f7da3e`, `c55a133e`, `c80f0910`, `d7817e36`, `98dcfb83`.
- **Task 9, the systemd smoke:** `21910f24`, `2b043296`, `602ead90`, `418cb82b`, `c5454929`, `7c7fb811`, `55b822fd`.
- **Task 10, the chart:** `27594859`, `743b03cd`, `e94d36bb`, `e855d2cd`, `c3c04251`, `92c24d8e`, `a9d1acde`, `2a6eb7c8`, `b8efc92d`,
  `aad1208b`, `a037d8ed`, `1b0a31c5`; the data-dir init split `7a297200`.
- **Task 11, the kind smoke:** `31f28c39`, `2dfbc8dd`, `f0615a3b`, `04b963db`.
- **Task 12, the release workflow:** `70ccc381`, `c680f3c0`, `e2f3c92f`, `6c3f128e`, `add6a936`; requirements `ffe0150f`.
- **Task 13, L82 harness:** `bd8a7cc6`, `bd861121`, `e1de5e08`, `706e9f16`, `0d23c118`.
- **Task 14, L83 harness:** `7ca3f75f`, `cc9a30cd`.
- **Task 15, L84:** `d6544a36`, `f53663e5`.
- **Task 16, L85 harness:** `92a08df5`, `915c7e8b`, `354eafab`.
- **CI-found fixes after the PR opened:** the systemd smoke ran an L84 lab test unanchored (`23e8c1f2`) and its `put` made no parent directory
  (`add3edb7`); the kind smoke read the kind network before the cluster existed (`b6237982`); the fence's wording for a group-writable `/etc`
  (`b8476520`); the feed's echo evicted a cache entry already at that revision (`ad518234`); the cluster key set tests raced a save
  (`2a3df2c3`); the one-off `store-roles` pod saw the same certificate for both components (`ff90afef`, `ac85a274`); `ExecReload` used
  `/bin/kill`, absent from `debian:trixie-slim` (`c8847d06`, `22995eb8`); the chart's root init added `DAC_READ_SEARCH`, which Pod Security
  `baseline` refuses, so no pod was created (`714e8c64` documented `privileged`; the lead refused that weakening; `7a297200` split the init).

#### What changed in review

- **The admin sockets were removed** (Ryan, 2026-10-27): every admin-level operation goes over the broker API with a security key press bound to
  the request; no command has a socket flag; break-glass is `port49-broker revoke --offline` as the file's owner with the brokers stopped.
  A root-run offline revoke wrote root-owned files a non-root daemon could not open, so the offline forms refuse any uid but the owner and the
  message names `sudo -u`.
- **The chart's PVC root.** Dropping the group-write bit (`5e88550c`) makes the kubelet's `OnRootMismatch` walk every later mount, which makes
  `state/` group-writable and the fence refuse it. The root is `root:65532 3770` (setgid so the kubelet skips, sticky so the fence excuses it),
  the data directory is repaired at every start, and a test carries the kubelet's rule from `volume_linux.go`. **PSA:** the repair first needed
  `DAC_READ_SEARCH`, outside `baseline`'s list; it is now two init containers (root: `CHOWN`, `FOWNER`, `FSETID`, inodes only; 65532: no
  capability, the recursive `chmod`, a loud stop naming the `chown -R 65532:65532` command on a foreign-owned file).
- **CI-found, none visible to local tests:** package modes took the builder's umask (explicit directory entries, `file_info` modes); the rpm
  owned no directories; the feed echo evicted a cache entry and a hung store answered `store_unavailable`; `/bin/kill`; the store-roles
  certificates; `put` without a parent directory; the unanchored smoke.
- **Keys:** the sealing key stays raw 32 bytes (a base64 cut to 24 characters was refused as a weakening); the key recipes never overwrite
  (rotation with the same recipe would have destroyed the old key) and never use a fixed `/tmp` name.
- **Release:** every publisher waits on a job proving the tag is on `main`; goreleaser, image and chart run in a `release` environment with a
  reviewer; only three jobs hold `id-token`.
- **Smokes** run with named capabilities, never `--privileged`, and refuse on a host with a TPM or a Yubico key unless the hosted-runner job sets
  `PORT49_SMOKE_ON_KEY_HOST=1`; a static test forbids the override anywhere else.
- **Test flakes classified:** a product bug (the feed echo), a test bug (`floorIn`'s substring match), a helper that did not wait for a save.

#### Carried forward

- **TODO(L82):** Secret volumes and External Secrets on kind. Harness written; state to be filled from the `lab-l82` artifact.
- **TODO(L83):** Vault Agent and the Secrets Store CSI driver. Harness written; state to be filled from the `lab-l83` artifact. The injector
  variant needs `automountServiceAccountToken: true`; the chart's default stays `false` and the caveat belongs in the L83 note only.
- **TODO(L85):** MetalLB anycast. Harness written. The chart's `externalTrafficPolicy: Local` anycast option is added only if all four cells
  PASS; otherwise commit `docs: record lab register entry L85 (MetalLB anycast not offered)`.
- **TODO(L86):** an admin call's touch on a real YubiKey. Harness and runbook written; Ryan's run is on the SER8 (planned 2026-10-31).
- **L84** is partial: Compose `secrets:` measured (long and short syntax PASS; a new secret needs `up -d`); `LoadCredential=` runs in CI.
- The detached JWKS fetch may save after `Run` returns (`identity.go:155`). Benign: the file is public, written atomically and owner-only. For the
  pre-beta review.
- Parked for plan 13: every binary prints its version; a `healthcheck` subcommand (the image has no shell).
- Regression lab run: cells re-driven through the API (l67, l69, l74, l75, revoke, api_revoke, split) still need one run before merge.
- `requirements-release.txt` and the `.rpm` Python library (pip-only, the lead's ruling) stay as ruled. Ryan's one-time release setup is open (below).

#### Operator notes (for the pull request body)

- **Three shapes, peers.** systemd (`make packages`, `make systemd-smoke`), container/compose (`make image`, `make compose-smoke`), Kubernetes
  (`deploy/helm/port49`, `make helm-test`, `make kind-smoke`). The smokes refuse on a host with a TPM or a Yubico key; they run in CI.
- **Where secrets live.** systemd: files under `/etc/port49/`, owner root or the service user, no
  world bit. Compose: files placed once by `setup.sh` and mounted; adding a new `secrets:` entry needs `up -d`. Kubernetes: a Secret mounted whole
  (never `subPath`), `defaultMode 0440`, `fsGroup 65532`; the External Secrets example writes one file per key version.
- **Key files are read under the secret-file rule.** A key directory that is group- or world-writable is refused (`chmod 0755` or
  `0750` it; a Secret volume's read-only mount is excused), and a group-readable key must belong to a group the service is in: port49's
  own, or fsGroup. Debian's `ssl-cert` group is refused. The issuing CA key, a TPM blob and the CLI's own key keep the owner-only rule.
  Expected remedy if L83's CSI cells show `root:root` files: the provider's `filePermission 0400`.
- **The rewrite warning.** A held key file rewritten in place is reported at once (`port49_key_secret_files_changed`, a log line per change)
  and the reload is never refused. Add a version by writing a new file; never edit one in place.
- **`ProtectSystem=true`**, not `strict` or `full`: the fence checks `/etc`'s mode, and a mount namespace that hides it would pass a host the
  fence would refuse.
- **Two users:** `port49d` and `port49-broker`, made by `sysusers.d`; directories by `tmpfiles.d`. The units set `StartLimitIntervalSec=0`
  (a boot with etcd down must not end in a dead unit) and `LimitNOFILE=65536`; `ExecReload` is `sh -c 'kill -HUP "$MAINPID"'`.
- **Admin calls go over the broker API with a key press.** Rights: `revoke_others`, and the admin-level rights each route names. One agent
  per user. Break-glass per shape: `sudo -u port49-broker port49-broker revoke --offline` (systemd; as root it refuses and names that line), `docker compose run --rm --no-deps port49-broker revoke --offline` (compose), `scripts/revoke-offline.sh` (Kubernetes: scales the brokers to 0, runs it on the PVC). **3am order:** another admin first, then offline.
- **Packages:** `port49-server` and `port49` conflict; binaries are 0755 root-owned with no setuid, setgid or file capability; directories 0755;
  the client's `/etc/port49/config.yaml` is a `noreplace` conffile; the `.rpm` leaves the Python library to `pip install port49`.
- **`copy-issuer.sh <ns> <release> --from <n> --to <m>`** copies the issuing CA between brokers; it refuses to overwrite a different CA and
  names both fingerprints. Never run `init-issuer` twice.
- **Release artifacts** (tag `vX.Y.Z` on `main` only): packages and a multi-arch image (GHCR), the chart, PyPI `port49`, Galaxy `port49`,
  with provenance. **One version:** the tag equals `pyproject.toml`, `galaxy.yml` and `Chart.yaml`'s `version` and `appVersion`
  (`versioncheck` on every PR and at the tag).
- **CI jobs:** `test` (vet, rest, port49d in three shards, race, root, versions, release requirements, packages), `systemd`, `compose`, `kind`,
  `hwkeys`, `python`, `qual`, `leaks`, `lab-free`, and the label-gated `lab-kind` (`l82`, `l83`, `l85`).
- **The chart runs in a `baseline` namespace.** The kind smoke labels its namespace `enforce=baseline`.
- **Unmeasured:** the kind smoke's two-generation fsGroup cell against a real kubelet until its CI run; TODO(L82), TODO(L83), TODO(L85),
  TODO(L86).

#### Hand-offs

- **12c:**
  - an alarm on `port49_key_secret_files_changed > 0` for 10m;
  - an alarm on `port49_issuing_ca_not_after_timestamp_seconds == 0` while `broker.identity.issuance` is configured: a broker that started
    without a usable issuing CA (the start never fails over it, so the gauge is the only signal besides the log line `issuing-ca.* is not usable`);
  - L39 (b), with Task 11's login cell as its first evidence;
  - the reference configurations; load;
  - **the Oxidized `secure: true` follow-up** (plan 9d carry): measure Oxidized's host-key options against accept-new, and change
    `examples/oxidized` or say why not;
  - **a Velero example** for the chart's PVCs, with a measurement behind it (pre-flight M10);
  - whatever L83, L84 or L85 left FAIL that a later platform change might reopen. TODO(L83) TODO(L85)
- **Plan 13:** install pages from each README, the "When it will not start" tables, and the `encryption:` rotation runbook; `--version` and
  `healthcheck`.
  - **Versioning (Ryan 2026-10-30): SemVer.** `v0.1.0` is the beta, and 0.x may break config with loud notes. `1.0.0` is the compatibility promise. Bumps come from Conventional Commits, and there is one version across every artifact. Tags are manual and carry no pre-release suffix unless it is mapped to PEP 440. The release docs state this.
- **Ryan:**
  - ruled: admin over the API with a key press (2026-10-27); smokes CI-only (2026-10-30); maintainer `port49 maintainers
    <port49@blanketfish.com>`; the `.rpm` library is pip-only (the lead's ruling, Ryan may override);
  - still open: the one-time release setup (PyPI trusted publisher, the `galaxy` and `release` environments, tag restrictions, the `v*` tag
    ruleset, public GHCR at go-public); no automated admin call (offboarding goes through the identity provider's back-channel logout);
    the L86 run.

## Plan 13 — User and admin documentation

**Builds:** a published documentation site — MkDocs Material on GitHub Pages, deployed by a
GitHub Action — written when the repository goes public. Six sections:

- **Concepts:** the token, the receipt and the login context; revocation; trust domains.
- **Operator guide:** install, the broker and the agent, `port49 login`, and troubleshooting
  organized by what the operator sees.
- **Admin guide:** policy, roles and grants, key rotation, revocation, and one device-configuration
  page per platform built from `tests/lab/results/`, including the traps the lab measured.
- **Reference:** config keys, reason codes, metrics and the decision-log schema, generated from the
  code so it cannot drift.
- **Agent quick start** (Ryan, 2026-10-16), for people who let an AI agent reach devices through
  port49. The agent gets its own machine identity (a workload certificate or, plan 10, a
  Kubernetes service account), never a person's login or a password, and a policy subject of its
  own with the narrowest roles that do its job. Its tooling mints and presents the token
  (`port49 ssh`'s askpass, the Python client, the Ansible lookup) so the token never enters the
  agent's context or its transcript. A refusal reaches it as `port49 token --json`'s reason code,
  which it can act on. Every command it runs is recorded under its principal. A device under
  per-login MFA is refused to it (`per_login_mfa_required`): those stay human. Worked example: one
  read-only agent, from identity to a recorded `show` command.
- **Agent setup runbook** (Ryan, 2026-10-16): one page an AI agent follows to set up a port49
  environment, linking the operator guide rather than restating it so it cannot drift. It lists
  the decisions the agent asks its human first (deployment shape, identity provider, trust
  domain, devices); the path per shape with a check after every step (`port49 policy test`, a
  smoke login); and where it stops for a human: secrets, hardware keys, and any device's AAA
  configuration. The site publishes an `llms.txt` naming the pages in reading order.

**Inherits:** from every earlier plan, the "Operator-facing notes" section of its PR body (top of
this file). From plan 9a's final review: the install must be 0755 with no setgid or file
capabilities (plan 12 states it; this guide repeats it), and a table of `port49 ssh`, `trust` and
`login` exit codes. From plan 11a: a
"Stores" page:
- the two roles, and what each holds;
- the single-site and multi-region recipes;
- a cut region at 3am (the plan's 3am table);
- `port49 store status`;
- `port49 directory forget` in a split (one forget reaches every region; refused during a cut);
- a back-channel logout's reach in every region (R26), and the pending logouts of a cut region;
- a restart during a cut: the snapshot and its ceiling (R19);
- one set of encryption keys everywhere, and the three-step rotation (R27);
- no migration from one store to two: a split starts on fresh stores (R25);
- a user who logs in again during a cut may be logged out again when the logout arrives (a
  late-followed logout ends logins made after it: a cut-off by time would fail open under
  cross-region clock skew);
- the "served from the cached pin" line is said once per principal per 10 minutes; past 1024
  principals the map behind it stops deduplicating, so the line can repeat.
From plan 11: an RFC
9887 page (the two listeners, `listen: none`, `tls_listener`'s keys, device identity by
inventory name or address, revocation, the 3am table, migrating a device from `tcp` to `tls`
with the window where a device lists both servers kept short (RFC 9887 §6.1), and the server
certificate's names (a device configured with a DNS-ID or IP-ID is not shown to check it: IOS XE
17.18.02 accepted a certificate naming another address, or none, so the server certificate must
come from a CA the device trusts for nothing else, `tests/lab/results/L73-cisco_iosxe.md`; Junos and
NX-OS unproven; any wildcard confined to a subdomain only TACACS+ servers use, RFC 9887 §5.1.6),
and the `tls_outcome` vocabulary in the
reference. The page also carries, each as what an operator sees and the fix:
- **`tls_name_clash`.** Two `tls` devices whose names are equal under ASCII case fold are both
  refused admission, and the start names them. Rename one.
- **Unidentifiable devices.** A `dns_suffixes` clash, or a non-ASCII name with no `ip_address`
  match, cannot be told from a certificate. Such a device is declined at Accept as
  `identity_mismatch`, with no handshake and no strike, and named once at start or reload. Rename
  it, or give it an `ip_address`.
- **Junos** (measured on vJunos-router 26.2R1.7, `tests/lab/results/L73-juniper_vjunos-router.md`).
  port49 requires the client
  certificate and Junos makes mutual TLS optional, so set `tls mutual-authentication
  certificate-id <id>` (Junos 26.2R1 and later, routing and switching platforms, not SRX).
  Without a client certificate a login is refused `no_client_certificate` (that refusal is
  measured, L72 cell c).
- **IOS XE and a down store.** When port49's store is down and port49 answers ERROR
  (`store_unavailable`), IOS XE 17.18.02 over TLS, as on 49 (L4), does not fall to its local method, so
  break-glass fails (`tests/lab/results/L73-cisco_iosxe.md`, cell i, ok false in 4.1 s). Junos,
  EOS and NX-OS fell to local in the same test (`L73-juniper_vjunos-router.md`,
  `L73-arista_ceos.md`, `L73-cisco_nxos.md`). The 3am table says it as a warning beside the
  IOS XE row.
- **The `component` label** on the four certificate-status metrics, and `sum by` or
  `ignoring(component)` where a rule matched them one-to-one.
- **Config changes.** An edit to a `tls_listener:` key needs a restart (said once at SIGHUP).
  The certificate, key, CA and CRL files reload live every `reload_interval` and at SIGHUP, and a
  CA rotation needs no restart.

From plan 11b (Plan 11b — As built, above):
- **The qualified-platforms page,** published from `docs/qualified-platforms.md` (generated by
  `make qualified-platforms`; a drift test fails when it is stale). Keep its "What an operator must do"
  list beside the table, and its status column's `partial` and "re-vet pending" meanings.
- **The contributor guide,** from `tests/qual/README.md`: vetting a firmware, adding a platform, `make
  qual`, `make qual-vet`, `make qual-fleet`, and what a golden and an `engine_gaps` entry are. Vendor
  images are never hosted.
- **`packet_fields`** in the decision-log reference: the header fields of a validated request record as
  enum names, absent on an unvalidated record.
- **Per-platform device pages,** the traps the lab measured:
  - **Junos** sends the server's IP as the SNI, so `server_names` must list every address or stay unset.
    The device sees alert 80 (`internal_error`) while port49d logs `tls_refused` / `sni_mismatch`, so
    "the device logs `internal_error` at the handshake" maps to "check `server_names`".
  - **IOS XR (XRd 26.1.1)** dials TLS port 49, not 300, unless the server sets `port`; it needs `domain
    name` before enrolment, and group member and host leave in separate commits. Without a `platforms:`
    privilege block (or an adapter) every command is refused locally.
  - **SR Linux** setup leads with `priv-lvl-authorization true`: the default false sends port49 no
    authorization, and the YANG says that is full admin. Each local role also needs `services [ cli ]`.
  - **NX-OS 10.6(2)F over TLS:** port49 offers single-connect and the device honors it, so port49's command
    rules hold over per-request TLS (L80 fixed arm; before the fix they did not).
  - **IOS XE and XR** do not fall to the local method on an ERROR reply, so break-glass fails with the
    store down (3am-table warning).
- The `lab-regress` operator environment (the README section "Regressions (plan 11b)") and the NX-OS boot
  hang's `-only=` workaround belong in the contributor guide.

**Leaves for later:** nothing. **Lab:** none.

---

Plans 8–11 are small and may be merged into a neighbour when written. Renumber nothing;
leave a gap and say why in this file.
