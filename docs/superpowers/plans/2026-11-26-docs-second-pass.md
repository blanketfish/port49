# Docs second pass: restructure and shorten

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to carry out this plan task by task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the site clear, logical and brief for a human reader: one home per topic, page types that do
not mix, numbered install steps that each end in a check, overview pages in the approved Install-overview
layout, and detail moved behind a link, not deleted.

**Binding inputs:** `.superpowers/sdd/docs-second-pass/rules.md` (Ryan's rules 1–10) and
`.superpowers/sdd/docs-second-pass/fix-list.md` (items 1–13). Where this plan and those files disagree, they
win; report the disagreement.

**Branch:** `docs/second-pass` (from `main`). One PR at the end (fix-list rule: batch the docs fixes).

**Precondition (Task 0):** `feature/key-generate` must be merged and this branch rebased on it before
Task 7, Task 8 or Task 15 starts. That branch already rewrites the key sections of
`deploy/systemd/README.md`, `deploy/compose/README.md`, `docs/site/admin/key-rotation.md` and
`tests/shapes/recipes_test.go` (it adds `port49d key sealing` and `port49d key device <name>`); touching
those files before it merges is a rebase conflict, which is a dependency (memory: parallel plans need no
overlap).

---

## 0. Conventions every task follows

### Page types

| Type | What it holds | What it never holds |
|---|---|---|
| **overview** | The Install-overview layout (fix-list 11): a short table linking the choices, a table of the parts involved, a few one-line prerequisites with links, then the first commands. About 300 words. | rationale, edge cases, a second explanation of anything |
| **how-to** | Numbered steps. Each step that changes something ends with a command that shows it worked and what success looks like (written as plain prose, see "Plain prose" below). Choices branch with `=== "OIDC"` tabs (pymdownx.tabbed is on). | design rationale, lab narrative, a second copy of a concept. One line + link instead. |
| **concept** | What a thing is and why, for someone deciding or debugging. | install steps, command reference tables |
| **reference** | Lookup: tables of keys, codes, exit codes, requirements with their numbers and evidence. May be long. | steps |
| **troubleshooting** | Symptom (**You see**) → cause → fix, one entry per symptom. | install steps, rationale |

### How detail leaves a page

In this order of preference:
1. One line and a link to the topic's one home.
2. A guidance fact the reader must act on (etcd WAL fsync p99 < 10 ms, NTP) in `!!! info` with the number
   and a link to `reference/requirements.md`.
3. A safety warning stays visible as `!!! warning`, shortened, with a link to the detail. Never collapsed.
4. Edge-case detail a runbook reader may need mid-incident (key-rotation re-seal waits, restore bands) in a
   collapsed `??? info "<title>"` block on the same page. Word budgets count only words outside `???`
   blocks; use this only for runbook pages (key rotation, backup and restore, stores), never to hide a
   warning.

### Word budgets

A budget counts the rendered words a reader sees: front matter, fenced code blocks and collapsed `???`
blocks excluded; words pulled in by `--8<--` included. Measure a page from the repository root:

```sh
f=docs/site/<page>.md; awk 'NR==1&&/^---$/{fm=1;next} fm&&/^---$/{fm=0;next} fm{next} /^```/{c=!c;next} /^\?\?\? /{d=1;next} d&&/^[^ ]/{d=0} !c&&!d' "$f" | wc -w
```

For a page that includes a README section, add the section's words. A budget is a ceiling, not a target:
shorter is better if nothing true is lost. Over budget by more than 15% needs a sentence in the task report
saying what could not move and why.

### Links and lab IDs

- Site pages link each other relatively; READMEs link the site with absolute
  `https://blanketfish.github.io/port49/latest/...` URLs (as they do now).
- After moving any text that names a lab ID, run `go run ./internal/docgen/cmd/linklabids` (it links bare
  IDs on hand-written pages) and convert README-style absolute lab links to the page-relative form
  (`../reference/lab-register.md#l84`).
- A claim cited to an **open** register row stays inside `!!! warning "Unmeasured"`. Moving a sentence never
  moves it out of its warning. Check the row's status in spec §15 before rewording any device claim.
- Every page keeps `title` and a one-sentence `description` of at most 160 characters ending in a full stop.

### Nothing has been released (owner ruling 2026-11-26)

- No migration notes anywhere: no "if you are coming from an earlier version", no "previously", no "was
  renamed", no "no longer". Describe what is, with today's names only (for example the compose broker key is
  `broker-encryption[-<id>].key`; never mention its old name). An existing sentence of that kind is deleted, not
  moved, unless it states a current fact, which is kept in present tense.
- Upgrade pages describe upgrading between future releases: short and generic (read the release notes and
  [Versions](../versions.md); the deployment's upgrade commands; re-apply `store-roles` when the notes say the
  roles changed; replace one server group at a time). No release-specific steps.
- Pages may move and be rewritten freely: nobody depends on today's URLs, so there are no redirects.

### Plain prose (rule 11: the humanizer pass)

Every page or README section a task writes or rewrites gets a humanizer pass before its checks run. Read
`/home/rwendt/.claude/plugins/cache/humanizer/humanizer/4.0.0/SKILL.md` in full first. Each implementer
brief repeats this paragraph and the security rules below.

- Apply the skill in **file mode**: read the whole file from disk, change prose only. Code blocks, inline
  code, commands, paths, YAML, front-matter keys, link targets, anchors, `--8<--` lines and `<!-- -->`
  markers stay byte-for-byte. A `description:` value is prose: it gets the pass, and stays one sentence of at
  most 160 characters.
- Register: technical, neutral and plain (the skill's "Voice" for reference text). No writer sample, so §8
  applies in full: **no em dash (—) or en dash (–) in prose**, and no ` -- ` used as a dash.
- The tells that matter most here: §1 not-X-but-Y (keep a contrast only when the negative half corrects a
  belief an operator really holds, such as "`running` is not ready"); §2 one-line closers; §6 forced triads;
  §19 bold labels on every list item (bold stays only where a scanning reader needs it, such as a step's
  action); §20 sentence-case headings that name what the section holds, no arrows as decoration; §25 no
  writing about the page itself ("This page explains…", "The table below…"); §18 is/are/has.
- In pages, a step's check is written as plain prose, not a bold label: "To check, run:" then the command, then
  what success prints. The plan's `**Check:**` is shorthand for that.
- Exceptions the tests force: the 3am index keeps `**You see:**` at the start of a line (its log-line test reads
  that form); a mustSay string keeps its exact text (if it holds a dash, put it in a code span, where it is a
  quoted literal, e.g. `` `closed — measured <date>` `` on the contributing page).
- Then do the skill's step 3 against the old text: every fact, number, name, key, reason code, lab ID and
  warning still present and unchanged in meaning. A hedge that bounds a safety claim or an unmeasured claim
  is a scope statement (§9 says keep it), never a tell. The task report names the files reviewed and
  any section not covered.

### Security rules for every implementer and reviewer brief

- Every recursive grep excludes `realm.json`, `*.env`, `*-key.pem` and `*.keytab`. grep here is ugrep: write
  `grep -e PATTERN`, never `--` before a pattern (it drops `--include`/`--exclude`).
- Never print a secret, a key file's contents, a token or a captured TACACS+ body. Never decode a pcap.
- Do not write a device-behavior claim the lab register does not support; a results note beats a doc.

### The checks every task runs

```sh
make docs                                   # regenerate generated pages and llms.txt from their sources
go run ./internal/docgen/cmd/linklabids     # link bare lab IDs on hand-written pages
go test ./tests/ci/ -count=1                # mustSay, nav, front matter, lab-entry, lab-ID, lint, shape tests
make docs-build                             # mkdocs --strict: the link and anchor check
PORT49_DOCS_SITE=site go test ./tests/ci/ -count=1 -run 'Built'   # the built-site lab checks
```

Tasks that touch a `deploy/**/README.md` also run:

```sh
go test ./tests/shapes/... ./tests/compose/ ./tests/helm/ -count=1   # tests that read README text
make vet
```

The last task runs `make test && make vet` in full and reports the real output.

**Expected reds while the pass is in flight, and only these:** `TestNoPageSaysShape` and
`TestNoDashInProse` (Task 2) list the hits not yet removed; `TestNoPageIsAStub` lists the stub pages Task 1 created and no later task has filled
yet. Each task's report says which hits and stubs it cleared. Any other red is the task's to fix before it
reports done.

### Guarantees the checks protect (never weaken one to pass)

| Check | Guarantee | When a task moves text |
|---|---|---|
| `TestEveryPageSaysWhatItMust` (`mustSay`, `docs_content_*_test.go`) | A fact a page owes its reader cannot be edited out unseen. | Move the string's row to the page the fact moves to, in the same commit. Never delete a row unless the fact itself is deleted as a duplicate, and then the row moves to the fact's one home. Change a string only when its own wording or link path must change (e.g. `../reference/reason-codes.md` from a page that moved into `reference/`), and say so in the commit. |
| `TestOpenLabEntriesAreWrittenAsUnmeasured`, `TestTheBuiltSiteCitesOpenEntriesAsUnmeasured` | An open lab row is never asserted as fact. | Keep the `Unmeasured` warning around the moved claim. |
| `TestEveryDeviceClaimCitesItsEvidence` | Device-page claims cite their results note. | Device pages are touched for wording only (Task 16). |
| `TestNoSitePageHoldsABareLabID`, `TestTheBuiltSiteHoldsNoBareLabID` | A reader who meets L84 can click it. | Run `linklabids`. |
| `TestTheNavAndThePagesAgree` | Every page is reachable; nothing in the nav is missing. | Task 1 owns the nav; later tasks only delete lines from the temporary group. |
| `TestEveryQuotedLogLineIsInTheCode`, `TestEveryAlertIsInTheIndex` | The 3am index quotes real log lines and links every alert. | Keep the `## A log line says` and alert link forms on `operate/troubleshooting/index.md` (path unchanged). |
| `TestTheRunbookLinksAndDoesNotRestate`, token-mint tests | The agent runbook links the guide; no agent page runs `port49 token` to stdout. | Update links only; keep blocks ≤ 5 lines. |
| `TestEveryReadmeStatesTheKeyOrder` (`tests/shapes/units_test.go`) | Whoever adds or removes a device key on any deployment is told the order and the crash-loop it prevents. | Retargeted in Task 15 to the page that becomes the home; the four phrases and each deployment's symptom must stay. |
| `tests/shapes/recipes_test.go` | A key-making command shown to an operator really makes a safe key. | After key-generate it tests `port49d key`; keep the shown commands in the file the test reads, or retarget it in the same commit. |
| `tests/helm/static_test.go` (`--set keys.existingSecret=`), `suite_test.go` (`## The issuing CA` names `values-issuance.yaml` before `copy-issuer.sh`), `pod_security_test.go` (`CHOWN`, `FOWNER`, `FSETID`, `baseline`, `restricted`) | The Helm README's install commands match the chart and its examples; nobody is told to loosen Pod Security. | Keep these in `deploy/helm/port49/README.md`; adapt the heading match if the heading gains a step number. |
| `tests/compose/static_test.go` (rotation recipe refuses empty `KEY_ID`) | The compose rotation command refuses to run without an id. | D2 is done on key-generate (`port49d key sealing --id … --dir … --broker-dir …` in the setup image; static test updated there). Keep the command in the file the test reads, or retarget the test in the same commit. |
| `tests/shapes/l89/*` | The Velero README's commands are the measured ones. | `deploy/helm/port49/examples/velero/README.md` is not edited in this pass except for "shape". |
| `docs_lab_test.go` README wording rules | READMEs say an open row is open in their own words. | Same rule for README text moved into a page: it becomes `!!! warning "Unmeasured"`. |
| `docslint` (`LintText`) | No secrets, home paths, lab hosts or removed names in docs. | Unchanged. |
| `TestNoPageSaysShape`, `TestNoDashInProse` (Task 2) | Rules 6 and 11: the word "shape" and em/en dashes cannot come back into hand-written prose unseen. | Never add a prose allow-list; a literal that must keep a dash goes in a code span. |

---

## 1. The new nav tree

Paths in **bold** are new files; *(moved from X)* names the source. Budgets are rendered words.

```
Home                                   index.md                                   overview        250
Concepts
  Concepts                             concepts/index.md                          overview+concept 700
  Tokens, receipts and contexts        concepts/tokens-receipts-contexts.md       concept         900
  Identities                           concepts/identities.md                     concept         600
  Revocation                           concepts/revocation.md                     concept         600
  Trust domains                        concepts/trust-domains.md                  concept         450
Install
  Install                              **operate/deploy/index.md**  (from operate/install/index.md)   overview 300
  systemd
    Install                            **operate/systemd/install.md**   (README section `install`)   how-to 1000
    Upgrade                            **operate/systemd/upgrade.md**   (README section `upgrade`)   how-to  250
    Troubleshoot                       **operate/systemd/troubleshoot.md** (README section `troubleshoot`) troubleshooting 600
  Containers
    Try it                             **operate/containers/trial.md**  (README section `trial`)     how-to  300
    Install                            **operate/containers/install.md**                              how-to  800
    Upgrade                            **operate/containers/upgrade.md**                              how-to  250
    Troubleshoot                       **operate/containers/troubleshoot.md**                         troubleshooting 500
  Helm
    Install                            **operate/helm/install.md**                                    how-to 1000
    Upgrade                            **operate/helm/upgrade.md**                                    how-to  250
    Troubleshoot                       **operate/helm/troubleshoot.md**                               troubleshooting 800
    Back up with Velero                **operate/helm/velero.md** (snippet velero README, moved off the backup page)  how-to 2427 (snippet, unchanged)
Operate
  Stores                               operate/stores.md                          concept+how-to 1200
  TLS (RFC 9887)                       operate/tls.md                             how-to+concept 1100
  Secrets                              operate/secrets.md                         concept+how-to  900
  Backup and restore                   operate/backup-and-restore.md              how-to         1600
  Monitoring                           operate/monitoring.md                      how-to          600
  Versions and upgrades                operate/versions.md                        reference       400
  Troubleshooting                      operate/troubleshooting/index.md           troubleshooting 3000
Sign in
  Sign in                              **use/index.md**                           overview        300
  Install the client                   **use/install-client.md** (from operate/install/clients.md)   how-to 450
  Log in                               **use/login.md**  (from operate/login.md + broker-and-agent.md agent half)  how-to 800
  Connect to a device                  **use/connect.md** (from operate/login.md token/ssh)          how-to  800
  Hardware keys                        **use/hardware-keys.md** (from operate/hardware-keys.md)      how-to 1100
Administer
  Administer                           **admin/index.md**                         overview        300
  Sign-in backends
    OIDC                               **admin/sign-in/oidc.md**   (from admin/identity-providers.md)   how-to  800
    Client certificates (x509)         **admin/sign-in/x509.md**   (from admin/revocation.md CRL part, systemd README)  how-to 800
    Directory password                 **admin/sign-in/directory-password.md** (from identity-providers.md)  how-to 600
    The directory (LDAP)               **admin/directory.md**      (from identity-providers.md, compose README)  how-to 800
  Workloads
    Workloads                          admin/workloads.md                         overview+how-to 700
    Oxidized and step-ca               **admin/workloads-oxidized.md** (snippet examples/oxidized/README.md:8:)  how-to (snippet, unchanged)
    Kubernetes service accounts        **admin/workloads-kubernetes.md** (snippet examples/kubernetes/README.md:16:)  how-to (snippet, unchanged)
  Inventory                            admin/inventory.md                         how-to+concept 1400
  Policy
    Policy                             admin/policy.md                            overview+how-to 700
    Rules and scopes                   **admin/policy-rules.md**   (from admin/policy.md)          concept  1000
    Roles and grants                   admin/roles-and-grants.md                  concept+how-to 1000
    Tests                              **admin/policy-tests.md**   (from admin/policy.md)          how-to    900
    Reviewing a change                 **admin/policy-review.md**  (from admin/policy.md)          how-to   1000
    Platform sets                      **admin/platform-sets.md**  (from admin/policy.md)          how-to    350
  Admin access                         **admin/admin-access.md** (from the three READMEs' Admin operations)  how-to 500
  Revoking access                      admin/revocation.md                        how-to         1000
  Key rotation                         admin/key-rotation.md                      how-to         1800
  Devices
    Devices                            admin/devices/index.md                     overview+concept 600
    (7 device pages)                   admin/devices/*.md                         reference      6535 (unchanged)
Automation
  Python library                       **automation/python.md**  (snippet clients/python/README.md:3)     reference (snippet)
  Ansible collection                   **automation/ansible.md** (snippet clients/ansible/.../README.md:3)  reference (snippet)
  AI agents quick start                agents/quick-start.md                      how-to         1500
  AI agents setup runbook              agents/setup-runbook.md                    how-to          900
Reference
  Requirements                         **reference/requirements.md**              reference       900
  Client commands                      **reference/client-commands.md**           reference      1300
  Health checks                        **reference/health-checks.md**             reference       600
  Failure matrix                       operate/troubleshooting/failure-matrix.md (path kept; nav moves here)  reference 2438 (snippet, unchanged)
  (existing generated pages)           reference/config/*, reason-codes, decision-log, metrics, alerts, lab-register  unchanged layout
Contributing
  contributing/index.md, qualification.md, releasing.md                           unchanged
  Deployment design                    **contributing/deployment-design.md**      concept         700
```

Files removed at the end of their task: `operate/install/index.md`, `operate/install/systemd.md`,
`operate/install/container.md`, `operate/install/helm.md`, `operate/install/clients.md`,
`operate/broker-and-agent.md`, `operate/login.md`, `operate/hardware-keys.md`,
`operate/troubleshooting/will-not-start.md`, `admin/identity-providers.md`.

Paths kept on purpose: `operate/troubleshooting/index.md` (the alerts generator links
`../operate/troubleshooting/index.md#an-alert-fired`), every `reference/` page, every device page, every
`agents/` page (the token-mint tests glob `agents/*.md`, which is also why the Python and Ansible pages go
under `automation/`), `admin/policy.md`, `admin/roles-and-grants.md`, `admin/key-rotation.md`.

### Section totals (rendered words, human path)

| Section | Before | Ceiling |
|---|---:|---:|
| Home | 236 | 250 |
| Concepts | 4,927 | 3,250 |
| Install (overview, three deployments, Velero page) | ~16,800 (install index, three READMEs, will-not-start) | 8,477 (incl. Velero 2,427) |
| Operate (stores, TLS, secrets, backup, monitoring, versions, 3am index) | ~19,700 (incl. velero snippet, failure matrix) | 8,800 |
| Sign in (login, broker-and-agent, hardware keys, clients page) | 5,935 | 3,450 |
| Client READMEs (were on the clients page; now reference under Automation) | 4,552 | 0 on the human path |
| AI agents | 4,202 | 2,400 |
| Administer (device pages 6,535 unchanged; evidence and example READMEs not counted either side) | 28,565 | 20,785 |
| **Human path total** | **~85,000** | **~47,400** |
| Moved to reference (new hand-written pages; failure matrix and client READMEs re-filed) | | ~3,500 new + 6,990 re-filed |

Every number is a ceiling. A task that cannot meet its ceiling without dropping a true safety warning or a
mustSay fact says so in its report, names what would have to go, and stops at the warning; it never raises
the ceiling on its own.

Ceilings at risk, and what to do there first:
- `admin/key-rotation.md` 1800: 30 mustSay strings and the re-seal waits. Put the waits in `??? info` blocks
  (not counted); keep the order warning visible.
- `operate/backup-and-restore.md` 1600: 31 mustSay strings and the restore runbook. The Velero snippet moves
  to `operate/helm/velero.md` (it cannot be cut: `tests/shapes/l89` runs its commands as the measured
  procedure, so it is edited only for shape and dashes). Its mustSay row (`--8<-- "deploy/helm/port49/examples/velero/README.md`)
  moves to the new page; the backup page links it from the Helm tab.
- `operate/systemd/install.md` and `operate/helm/install.md` 1000: ten steps each with a check. Command blocks
  are not counted; keep prose to one sentence per step plus the check. Helm's `externalTrafficPolicy` table
  [L39] and MetalLB [L85] facts stay, as a table and two sentences.
- `agents/quick-start.md` 1500: 19 mustSay strings, several inside the worked example's fenced blocks (not
  counted). Cut the prose around them, never the blocks.

## 2. The one-home map

Each row: the topic, its one home, and the pages that keep **one line and a link** (nothing more).

| Topic | One home | Link-only elsewhere |
|---|---|---|
| What port49 is, the five parts of a login | `concepts/index.md` | Home, `operate/deploy/index.md` (parts table: one line per part), `use/index.md` |
| Glossary (item 8) | `concepts/index.md#terms` | none; other pages link a term on first use only where it helps |
| The session: held connection, lazy redial, same session ID, end fixed at login, reconnect = key use, fresh `auth_time` on reconnect (items 5, F1-1, F7-1) | `concepts/tokens-receipts-contexts.md#the-session` | `concepts/index.md` step 1, `concepts/identities.md`, `use/login.md` ("How long a session lasts": the messages a person sees only), `use/hardware-keys.md` (the PIN/touch at reconnect, where the person meets it) |
| Token expiry and clock skew mechanics (PR #83's text) | `reference/requirements.md#clocks` | `concepts/tokens-receipts-contexts.md` (two lines: expiry is read on port49d's clock; keep NTP), `operate/deploy/index.md` prerequisite, the three install pages (`!!! info`), troubleshooting "A token was minted ahead" entry (symptom → fix only) |
| Deployment requirements: source address unrewritten, etcd own cluster + version floor, `broker.state_dir` kept, NTP, etcd/spool disk | `reference/requirements.md` | `operate/deploy/index.md` (four one-line prerequisites), each install how-to (the step that meets it, `!!! info` for the disk figure) |
| etcd disk guidance (WAL fsync p99 < 10 ms, GCE pd-ssd and QLC lab result, spool fsync) | `reference/requirements.md#etcd-disk` | install steps (`!!! info` one line), `operate/monitoring.md` (the two alerts only) |
| `port49` binary mode 0755, no setgid, no file caps, and the askpass reason | `use/install-client.md` (rule as a step; reason in `!!! info`) | troubleshooting index ("port49 ssh sends an empty password": symptom → fix), packaging note in `contributing/deployment-design.md` none |
| `CAP_NET_BIND_SERVICE` ambient capability | `contributing/deployment-design.md` | systemd install: none needed (the package does it) |
| The memory-store trial and `port49d init-revocations` / `broker.revocations_file` | `operate/stores.md#the-memory-store` | `operate/deploy/index.md` none; backup page keeps its restore rows that name `revocations_file` (mustSay) |
| First-install commands (`store-roles`, `init-issuer`, `init-enrollments`) and "never in `ExecStartPre=`" | each deployment's install how-to (the step) | `operate/deploy/index.md` (three one-line commands with links, per the approved layout) |
| Etcd roles after an upgrade ("apply again by hand") | each deployment's upgrade how-to | `operate/versions.md` (one line), `operate/stores.md` none |
| Version policy, compatibility, reading a binary's version | `operate/versions.md` | each upgrade how-to links it first |
| Two server groups / side-by-side upgrade | each deployment's upgrade how-to | none |
| Sealing key creation (`port49d key sealing`, `--import` across hosts) TODO(key-generate) | each deployment's install how-to (the secrets step) | `operate/secrets.md` (what the key is), `admin/key-rotation.md` (rotation steps link the install step for the command) |
| Adding a device key version and its order (file first, policy line second) | `admin/key-rotation.md#device-keys` (deployment tabs) | `operate/secrets.md#when-a-key-file-is-not-there-yet` keeps the *behavior* (retry while running, refusal at start) — it is a different fact; the three README sections are cut to a link |
| Rotating the `encryption:` key | `admin/key-rotation.md#the-encryption-key` (deployment tabs) | READMEs: link; `operate/stores.md#one-set-of-encryption-keys-everywhere` keeps the cross-region rule only |
| Issuing CA first install (`init-issuer`, copying to a second broker) | each install how-to (step "Issuing CA, if the broker issues certificates") | `admin/key-rotation.md#the-issuing-ca` keeps refusals, `forget-issuer`, `rotate-issuer`; the "behind a promotion" Helm recovery moves to `operate/helm/troubleshoot.md` and key-rotation links it |
| Admin access: attestation roots, `api:` rights, ≥ 2 admins by `identity:`, groups resolve through the directory, no per-key enrollment (item 12) | `admin/admin-access.md` (deployment tabs for where the roots file goes and how it is reloaded) | `admin/revocation.md#what-you-need` (one line), the three READMEs (link) |
| Break-glass offline revoke | `admin/revocation.md#break-glass` (deployment tabs: systemd, compose, `revoke-offline.sh`) | troubleshooting index "Break-glass does not work" stays (that is the device-side local account — a different topic; keep its name distinct: "Device break-glass") |
| Admin-call 3am table | deployment-specific rows (attestation not chaining → that deployment's reload; no roots → that deployment's file; store down → that deployment's offline revoke) on each `operate/<deployment>/troubleshoot.md`; generic rows (no touch in time, IdP down, cert expired + IdP down, key not on a security key) in the 3am index under "An admin command is refused" | `admin/admin-access.md` links both |
| Process will not start (refusal table) | each `operate/<deployment>/troubleshoot.md` (README `will_not_start` section, renamed `troubleshoot`) | 3am index intro (one line per deployment) |
| Which healthcheck to use where, the Swarm restart-loop warning | `reference/health-checks.md` | containers install (`!!! warning` one line: shipped `--ready` is wrong for Swarm, link), helm install none (chart does it), each troubleshoot page (the `curl /readyz` check, one line) |
| Certificate status (OCSP/CRL) for client certificates, `issuer_file`, `on_unavailable`, "never `disabled: true` outside a trial", private-CA CRL over https needs `SSL_CERT_FILE` | `admin/sign-in/x509.md` | install x509 tab (one `!!! warning`: switch to `crls:` before first sign-in if your CA has no OCSP responder; link), `admin/workloads.md` (link) |
| Certificate status for the TLS listener | `operate/tls.md#revocation` | none |
| Directory (LDAP) config: servers, site/`PORT49_SITE`, bind (`gssapi` keytab, `external`, `simple`), Samba AD [L43] and Windows AD [L44] notes, `certificate_mapping`, `nested_groups`, `grace`, `prewarm` | `admin/directory.md` (keys themselves: `reference/config/port49d.md`) | install how-tos: the directory-password tab says "turn on `broker.directory` ([The directory](...))"; compose README key list deleted (duplicate of the generated reference) |
| Directory-password sign-in and enrollment, `init-enrollments` window | `admin/sign-in/directory-password.md` | install step (the command + check only) |
| OIDC: provider registration, back-channel logout URL, `HTTPS_PROXY` for the broker, JWKS kept in `state_dir` | `admin/sign-in/oidc.md` | install OIDC tab (the block to uncomment + check), compose README OIDC section cut to link |
| Kerberos | There is no Kerberos sign-in backend. A Kerberos keytab is only a directory **bind** method (`bind: gssapi`). Home: `admin/directory.md#bind` | install pages never list Kerberos as a sign-in choice |
| `LoadCredential=` for the encryption key [L84] | `operate/secrets.md#systemd-loadcredential` (an option: a plain step and one line on why) | systemd install: one line link |
| `ProtectSystem=true` not `strict`, two users on purpose, smoke tests (`make systemd-smoke`, `make compose-smoke`, kind smoke) | `contributing/deployment-design.md` | none |
| Secrets as files; the secret-file fence rules | `operate/secrets.md` | install how-tos: the secrets table (where each file goes on that deployment) is install content and stays there; the fence's rules are linked, not restated |
| TLS listener on port 300 per deployment | `operate/tls.md#turn-the-listener-on` (deployment tabs) | install pages: one optional line + link |
| Backups per deployment (snapshot units, enrollments export, Helm CronJobs, Velero warnings) | `operate/backup-and-restore.md#what-to-back-up` (deployment tabs) | READMEs: link; Velero procedure on `operate/helm/velero.md` |
| Device source address and NAT: per deployment detail (docker-proxy [L39], `externalTrafficPolicy` table [L39], MetalLB [L85]) | Requirement: `reference/requirements.md#device-source-address`; the Kubernetes measurement table and MetalLB: `operate/helm/install.md` (step "Expose port 49"); Docker: `operate/containers/install.md` | overview prerequisite one line |
| `port49 token`/`ssh` exit codes, `--json` keys and error codes, `port49 revoke` and `hwkey` exit codes | `reference/client-commands.md` | `use/connect.md`, `use/hardware-keys.md`, `admin/revocation.md` link it |
| Broker vs agent (who runs where, what each holds) | `concepts/index.md` parts table + `use/login.md` "The agent" | troubleshooting index ("Which side owns what" table moves there) |
| What an operator sees when the broker is down | 3am index "I cannot log in to any device" | `use/login.md` one line |
| Python library, Ansible collection | their READMEs, included whole on `automation/*.md` | `use/install-client.md` (one line each) |
| Banner / which docs version you read (item 1) | `operate/versions.md#which-version-of-these-docs-you-are-reading` | none |
| SoT/inventory write access is privilege-granting (item 6 S0) | `admin/inventory.md#who-may-write-the-inventory` | `concepts/trust-domains.md#what-is-trusted-and-what-is-not` one line |
| How port49d names a device (source address via the inventory, never anything the device sends) (item 7) | `concepts/tokens-receipts-contexts.md#the-token` "One device" bullet | `operate/tls.md#how-a-device-is-identified` keeps the TLS-specific second rule, linking the first |
| Single-connection mode | `admin/devices/index.md#single-connection` (trimmed) | device pages link it |

### Topics on the wrong type of page, and where each moves

| Now on | Topic | Wrong because | Moves to |
|---|---|---|---|
| `operate/install/index.md` | NTP skew mechanics (req. 5) | rationale in an overview | `reference/requirements.md#clocks` |
| `operate/install/index.md` | 0755 / askpass reason | rationale in an overview; a client fact on a server page | `use/install-client.md` |
| `operate/install/index.md` | memory-store trial | detail in an overview | `operate/stores.md#the-memory-store` |
| `deploy/systemd/README.md` | "The four things every shape needs" | duplicate of the overview | `reference/requirements.md` (deleted from README) |
| `deploy/systemd/README.md` | Admin operations + 3am table | user/admin guide in an install guide | `admin/admin-access.md`, `admin/revocation.md#break-glass`, troubleshoot pages |
| `deploy/systemd/README.md` | Adding a key version, Rotating the `encryption:` key | admin procedure in an install guide | `admin/key-rotation.md` |
| `deploy/systemd/README.md` | Certificate status | admin config in an install guide | `admin/sign-in/x509.md` |
| `deploy/systemd/README.md` | Directory, and the site | admin config | `admin/directory.md` (the `PORT49_SITE` drop-in stays in systemd install as a sub-step of the directory tab) |
| `deploy/systemd/README.md` | Two groups of servers | upgrade, not install | `operate/systemd/upgrade.md` |
| `deploy/systemd/README.md` | Why `ProtectSystem=true` | design rationale | `contributing/deployment-design.md` |
| `deploy/systemd/README.md` | `LoadCredential=` | option, not a step | `operate/secrets.md` |
| `deploy/systemd/README.md` | "After a port49 upgrade that changes the roles" | upgrade | `operate/systemd/upgrade.md` |
| `deploy/systemd/README.md` | The smoke test | contributor | `contributing/deployment-design.md` |
| `deploy/compose/README.md` | intro paragraph listing what `make compose-smoke` checks | contributor | `contributing/deployment-design.md` |
| `deploy/compose/README.md` | Directory key list | duplicate of generated reference | `admin/directory.md` (only facts not in the reference: Samba AD, `env:` vs file for the bind password) |
| `deploy/compose/README.md` | Admin operations, 3am table, Rotating, OIDC | admin | as for systemd |
| `deploy/compose/README.md` | "Keep image changes and policy edits apart" | upgrade | `operate/containers/upgrade.md` |
| `deploy/helm/port49/README.md` | CSI / Vault injector measurements [L83] | concept/reference | `operate/secrets.md#secret-agents` (already there: README keeps one line) |
| `deploy/helm/port49/README.md` | fsGroup / PVC root 3770 mechanics | design rationale | `contributing/deployment-design.md` (install keeps one `!!! note`: a cluster forbidding root init containers needs a volume root provisioned 3770 root:65532) |
| `deploy/helm/port49/README.md` | Rotating, Admin calls, Backups/Velero narrative | admin / operate | key-rotation, admin-access, revocation, backup-and-restore |
| `deploy/helm/port49/README.md` | preStop / rolling restart [L85], two releases | upgrade | `operate/helm/upgrade.md` |
| `deploy/helm/port49/README.md` | Status paragraph (renderer, CI run numbers), smoke tests | contributor | `contributing/deployment-design.md` |
| `operate/login.md` | `--json` keys, error codes, exit codes | reference on a how-to | `reference/client-commands.md` |
| `operate/broker-and-agent.md` | broker internals | concept | `concepts/index.md` |
| `operate/troubleshooting/will-not-start.md` | Which healthcheck to use where | reference/config guidance, not a symptom | `reference/health-checks.md` |
| `admin/policy.md` | Writing tests, Checking a change, Platform sets | three how-tos inside an overview | `admin/policy-tests.md`, `admin/policy-review.md`, `admin/platform-sets.md` |
| `admin/policy.md` | permit/deny specificity, scopes, `on_missing`, include-scope refusal, `security_log` | concept detail inside an overview | `admin/policy-rules.md` |
| `admin/revocation.md` | Checking your CA's revocation lists | sign-in backend config | `admin/sign-in/x509.md` |
| `admin/workloads.md` | "The guides in full" (two whole READMEs) | two how-tos inside an overview | `admin/workloads-oxidized.md`, `admin/workloads-kubernetes.md` |
| `operate/install/clients.md` | the Python and Ansible READMEs, whole | automation reference on a person's install page | `automation/python.md`, `automation/ansible.md` |

---

## 3. The move map

Legend: **keep** (stays, may be shortened), **move → X**, **link** (cut to one line + link to its home),
**ref → X** (moves to a reference page), **dup** (deleted as a duplicate; its home is named), **split**.
"Nothing true and useful is lost": a **dup** row names the home that already holds the same fact; if the
implementer finds a fact in the "duplicate" that the home lacks, it moves to the home first.

### Home and Concepts

| Current | Destination |
|---|---|
| `index.md` | keep; "deployment shapes, which are peers" → "three ways to deploy"; Where-to-start links to new paths (`operate/deploy/index.md`, `use/index.md`, `admin/index.md`); add `automation/` link |
| `concepts/index.md` opening | replace with fix-list item 2 text verbatim |
| (new) Terms table | from `/mnt/images/port49-fallacies-audit-2026-11-11/glossary-draft.md`, after the opening paragraph; check each row (below) |
| One login, end to end: parts list | keep as a 5-row table (person, `port49`/agent, broker, port49d, device) |
| step 1 "This held connection is the session…" | rewrite per item 5: the agent holds the connection while the network is up; one line + link to `tokens-receipts-contexts.md#the-session` |
| "Two things follow from this shape." | item 3: "Two things follow from how a login works." |
| In this section | keep |
| `tokens-receipts-contexts.md` table | keep |
| Two credentials, two lifetimes | becomes **The session** (item 5, F1-1, F7-1 one-home) |
| The token: One device | keep + item 7 sentence |
| The token: Expiry is the record's | two lines + link → `reference/requirements.md#clocks` (the full paragraph moves there, unchanged in meaning) |
| The receipt | keep; L15 note and Unmeasured warning stay; shorten prose |
| The login context: joins / replaces bullets | item 9 verbatim |
| The login context: sealed, Session control warning | keep (warning stays visible) |
| `identities.md` | keep; "*is* that held connection" (line 31) and line 54 rewritten per item 5, link to the session; trim "Machines" (305) to 150 by linking `admin/workloads.md` |
| `revocation.md` | keep; "What an operator runs" → 2 lines + link `admin/revocation.md` (dup of the runbook); "What revocation cannot do" keep (safety) |
| `trust-domains.md` | keep; "shape" fix; trim "What follows" to 200; add one-line S0 link |

### Install (deploy READMEs and pages)

| Current | Destination |
|---|---|
| `operate/install/index.md` intro + deploy table | move → `operate/deploy/index.md` (approved layout) |
| `…/index.md` "What every shape needs" 1–4 | one line each on the overview; detail ref → `reference/requirements.md` |
| `…/index.md` req. 5 NTP | one line on the overview; detail ref → `reference/requirements.md#clocks` |
| `…/index.md` Install the binaries with mode 0755 | move → `use/install-client.md`; `CAP_NET_BIND_SERVICE` line → `contributing/deployment-design.md` |
| `…/index.md` First-install steps | three one-line commands on the overview linking each install's step; the explanations move into each install step |
| `…/index.md` memory-store trial | move → `operate/stores.md#the-memory-store` |
| `operate/install/systemd.md` | deleted; `operate/systemd/{install,upgrade,troubleshoot}.md` include README sections |
| systemd README: intro + units table | keep in section `install` (units table is what you install) |
| systemd README: the four things | dup (overview + requirements) |
| systemd README: Install, "Without the package" | keep as steps 1 and a separate `## Manual install` at the end of section `install` (package is the recommended path) |
| systemd README: Where the secrets live (table) | keep (install step) |
| systemd README: sealing key + one key across hosts | keep as an install step with `port49d key sealing` / `--import` — TODO(key-generate): written by key-generate; this pass only renumbers it and adds the check (`ls -l /etc/port49/secrets` shows the two 0400 files, owners `port49d` and `port49-broker`) |
| systemd README: Adding a key version | move → `admin/key-rotation.md#device-keys` systemd tab (TODO(key-generate): `port49d key device <name>`) |
| systemd README: Issuing CA | keep as an install step; `forget-issuer`/`rotate-issuer` lines dup (key-rotation) |
| systemd README: Admin operations | move → `admin/admin-access.md` systemd tab; Break-glass → `admin/revocation.md#break-glass` systemd tab |
| systemd README: The 3am table | split: deployment rows → `operate/systemd/troubleshoot.md`; generic rows → 3am index |
| systemd README: The directory, and the site | directory config → `admin/directory.md`; `PORT49_SITE` drop-in and keytab placement stay as sub-steps of the directory-password tab; `init-enrollments` stays as a step; `init-revocations` line dup (stores) |
| systemd README: Certificate status | move → `admin/sign-in/x509.md`; one `!!! warning` line in the x509 tab |
| systemd README: etcd | keep as steps (install etcd, start members, check health); disk paragraph → `!!! info` one line + ref → requirements |
| systemd README: store-roles | keep as a step + check; "after an upgrade…" → `operate/systemd/upgrade.md` |
| systemd README: every config names every member | keep (one line in the config step) |
| systemd README: Backups | move → `operate/backup-and-restore.md#what-to-back-up` systemd tab; install keeps one step "enable the backup timers" with check (`systemctl list-timers port49-*`) |
| systemd README: Two groups of servers | move → `operate/systemd/upgrade.md` |
| systemd README: TACACS+ over TLS on 300 | move → `operate/tls.md#turn-the-listener-on` systemd tab |
| systemd README: Why ProtectSystem | move → `contributing/deployment-design.md` |
| systemd README: LoadCredential | move → `operate/secrets.md#systemd-loadcredential` |
| systemd README: Rotating the `encryption:` key | move → `admin/key-rotation.md` systemd tab |
| systemd README: When it will not start | keep as section `troubleshoot` (rename marker) |
| systemd README: The smoke test | move → `contributing/deployment-design.md` |
| compose README intro | contributor part → `contributing/deployment-design.md`; one-sentence intro stays |
| compose README Trial | section `trial` → `operate/containers/trial.md` |
| compose README The files | keep in `install` (volume table); "Keep image changes and policy edits apart" → section `upgrade`; Compose `secrets:` [L84] → `operate/secrets.md` (dup check) |
| compose README Adding a key version | move → key-rotation compose tab |
| compose README A deployment | keep as install steps; "One store or two" → link `operate/stores.md`; store-roles re-apply → `upgrade` |
| compose README Directory | link → `admin/directory.md` (unique facts move there first) |
| compose README Admin operations, 3am table | as for systemd |
| compose README `broker.state_dir` | keep in `install` (step + the chown fix as check) |
| compose README OIDC | keep the "replace `client_ca_file` with the commented block" sub-step in the OIDC tab; the rest → `admin/sign-in/oidc.md` |
| compose README The issuing CA, and a second broker | keep as install step |
| compose README Rotating | move → key-rotation compose tab (the `port49d key sealing --id` command key-generate wrote) |
| compose README When it will not start | keep as section `troubleshoot` |
| compose README etcd's disk | dup (requirements); `!!! info` one line |
| compose README Backups | link (already) |
| helm README intro + Status | intro one sentence keeps; Status → `contributing/deployment-design.md` |
| helm README Install | keep as section `install` steps (Secrets from `--from-file`, the `helm install` block unchanged, schema refusals as the check) |
| helm README etcd's disk | dup; `!!! info` |
| helm README Two server groups | move → section `upgrade` |
| helm README The four requirements | dup of the install step's flags (the four become the step's check list) |
| helm README Secrets and rotation | Secret mounts/`subPath`/`fsGroup` → `operate/secrets.md#kubernetes` (dup check; mustSay there already); CSI/Vault [L83] → `operate/secrets.md#secret-agents`; PVC 3770 mechanics → `contributing/deployment-design.md`; ExternalSecret example + ClusterSecretStore warning → install step "device keys" (keep the warning); key order → key-rotation Helm tab |
| helm README Rotating the `encryption:` key | move → key-rotation Helm tab |
| helm README The issuing CA | keep as install step (keep `## The issuing CA` text in the heading: suite_test) |
| helm README Admin calls | attestation ConfigMap → `admin/admin-access.md` Helm tab; `revoke-offline.sh` → revocation break-glass Helm tab; etcd roles Job and `init-enrollments` Job → install steps |
| helm README At 3am | section `troubleshoot` (with will-not-start's Kubernetes part, deduplicated: one table) |
| helm README Storage and scaling, Alerts and scraping | keep in `install` (optional steps: HPA, PrometheusRule) — scraping detail dup-checked against `operate/monitoring.md` |
| helm README Network + Anycast | `externalTrafficPolicy` table [L39] and MetalLB [L85] keep in `install` (step "Expose port 49"); preStop/terminationGrace [L85] → `upgrade`; Pod Security names keep in install (pod_security_test) |
| helm README Backups, Velero | move → `operate/backup-and-restore.md` Helm tab (the Velero section's warnings: "a Velero restore that includes `port49-etcd` is a store restore", "restore with the pods running", "the backup holds the issuing CA's private key" stay as `!!! warning`); the Velero procedure (README include) → `operate/helm/velero.md` |
| helm README Multi-region | link `operate/stores.md#several-regions` |
| helm README smoke tests | `contributing/deployment-design.md` |
| `operate/install/container.md`, `helm.md` | deleted (replaced by section includes) |
| `operate/troubleshooting/will-not-start.md` | split: intro `/readyz` check → each troubleshoot page (one line); systemd/compose includes → their troubleshoot pages; Kubernetes table → `operate/helm/troubleshoot.md` (merged with README At 3am, one table); "behind a promotion" → `operate/helm/troubleshoot.md`; Which healthcheck → `reference/health-checks.md`. Page deleted. |

### Operate (shared)

| Current | Destination |
|---|---|
| `operate/stores.md` | keep; add `## The memory store` (from install index); F5-1: multi-region example lists every member and says the list is static; F3-2 start-up scan cost one line; "A cut region at 3am" table keep; "What the lab measured" keep |
| `operate/tls.md` | keep; add `## Turn the listener on` (deployment tabs); shorten 3am table prose |
| `operate/secrets.md` | keep; add `### systemd: LoadCredential=` (from README); dedupe Kubernetes section against the Helm README text |
| `operate/backup-and-restore.md` | keep; "What each shape must keep" → `## What to back up` with deployment tabs absorbing the README backup sections; edge sections into `??? info` where allowed; every warning and mustSay string stays |
| `operate/monitoring.md` | keep; "The disk etcd and the spool need" → two lines (the alerts) + link to requirements |
| `operate/versions.md` | keep; banner sentence replaced (item 1); "Upgrading" → links to the three upgrade pages + the one-line etcd-roles rule |
| `operate/troubleshooting/index.md` | keep path; trim entries to You see / It means / Do this / Don't; add "Which side owns what" table (from broker-and-agent), "An admin command is refused" (generic rows), "port49 ssh sends an empty password" (0755); fix links to moved pages |
| `operate/troubleshooting/failure-matrix.md` | keep (snippet) |

### Sign in

| Current | Destination |
|---|---|
| `operate/install/clients.md` | move → `use/install-client.md`; Python/Ansible snippet includes → `automation/*.md` |
| `operate/login.md` `port49 login` | move → `use/login.md` with tabs: certificate / OIDC / directory password; each ends with a check (`port49 identity` or the `logged in … session ends at` line) |
| `operate/login.md` `port49 token`, `port49 ssh`, Host keys, Telling refusals apart | move → `use/connect.md` |
| `operate/login.md` `--json`, Exit codes | ref → `reference/client-commands.md` |
| `operate/broker-and-agent.md` table, The broker | `concepts/index.md` parts table (dup check); broker-down list → 3am index |
| `operate/broker-and-agent.md` The agent, How long it lives, One agent one identity | move → `use/login.md` ("The agent", "How long a session lasts": the person's view; links the session concept) |
| `operate/broker-and-agent.md` Which side owns what | move → 3am index |
| `operate/hardware-keys.md` | move → `use/hardware-keys.md`; exit codes table ref → `reference/client-commands.md`; "What has not been measured" stays as `!!! warning "Unmeasured"` (mustSay L60, L63); add F7-1 (a reconnect costs a PIN/touch) |

### Administer

| Current | Destination |
|---|---|
| (new) `admin/index.md` | overview: who-what-where path (sign-in backend → directory → inventory → policy → devices), a table of the pages, first commands (`port49 policy test`, `port49 explain`) |
| `admin/identity-providers.md` OIDC issuance, ID token not bearer, What a provider may name, Back-channel logout, When a logout did not land | move → `admin/sign-in/oidc.md` |
| `…` The directory, Certificate mapping | move → `admin/directory.md` |
| `…` Directory-password sign-in, Enrolling | move → `admin/sign-in/directory-password.md` |
| `admin/revocation.md` What you need | link → `admin/admin-access.md` |
| `admin/revocation.md` Revoking, `--cert`, stolen laptop, Lifting, Where marks are kept | keep; add `## Break-glass` with deployment tabs (from READMEs) |
| `admin/revocation.md` Exit codes | ref → `reference/client-commands.md#port49-revoke` (keep the two "look like refusals and are not" lines as a `!!! warning` on the page) |
| `admin/revocation.md` Checking your CA's revocation lists, `issuer_file`, `on_unavailable` | move → `admin/sign-in/x509.md` |
| `admin/policy.md` Pieces, Writing a rule (first rule only) | keep as overview + how-to (800) |
| `admin/policy.md` permit/deny, Output modifiers, Scopes, `on_missing`, include-scope refusal, `security_log` | move → `admin/policy-rules.md` |
| `admin/policy.md` Writing tests (all) | move → `admin/policy-tests.md` (worked example kept, shortened) |
| `admin/policy.md` Checking a change (test, diff, acknowledge, ceiling line, new grant, CI, replay, explain) | move → `admin/policy-review.md` |
| `admin/policy.md` Platform sets, `port49 platform upgrade` | move → `admin/platform-sets.md` |
| `admin/roles-and-grants.md` | keep; per_login_mfa subsections condensed |
| `admin/key-rotation.md` | keep; device-key and encryption-key steps gain deployment tabs absorbing the README sections; re-seal waits into `??? info`; all mustSay strings stay |
| `admin/inventory.md` | keep; add `## Who may write the inventory` (S0); NetBox source trimmed |
| `admin/workloads.md` | keep overview + step-ca section; "The guides in full" → two new snippet pages |
| `admin/devices/index.md` | keep; "How to read a device page" 269 → 120; single-connection 404 → 250 |
| device pages | wording only ("shape"); no structural change |

### Automation, Reference, Contributing

| Current | Destination |
|---|---|
| `agents/quick-start.md` | keep; trim "How a refusal reaches the agent" by linking `reference/client-commands.md`; every mustSay string stays |
| `agents/setup-runbook.md` | keep; relink steps 1, 2, 3 to the new install, client and workload pages; "shape" ×3 |
| (new) `reference/requirements.md` | from install index reqs 1–5, the three READMEs' disk paragraphs, etcd version floor, monitoring's disk section |
| (new) `reference/client-commands.md` | from login `--json` + exit codes, hardware-keys exit codes, revocation exit codes |
| (new) `reference/health-checks.md` | from will-not-start "Which healthcheck to use where" |
| (new) `contributing/deployment-design.md` | ProtectSystem, two users, CAP_NET_BIND_SERVICE, PVC 3770/fsGroup, smoke tests, chart Status, how READMEs and pages share sections |

---

## 4. Tasks

Run them in order. Tasks within the same wave touch disjoint files and may run in parallel worktrees; a
later wave depends on an earlier one. Each task ends with a commit (Conventional Commits, `docs:` or
`test:`), message ending in the `Co-Authored-By` line from CLAUDE.md and nothing else.

| Wave | Tasks |
|---|---|
| 0 | Task 0 (key-generate merged, rebase) |
| 1 | Task 1 (skeleton + nav) |
| 2 | Task 2 (shape and dash tests), Task 3 (banner), Task 4 (new reference + contributing pages) |
| 3 | Task 5 (concepts), Task 6 (install overview), Task 11 (sign in + automation), Task 13 (admin sign-in, directory, admin access), Task 14 (policy), Task 16 (devices) |
| 4 | Task 7 (systemd), Task 8 (containers), Task 9 (Helm) — each touches only its own README and pages |
| 5 | Task 10a (stores, secrets, tls), Task 10b (backup, monitoring, versions), Task 15 (key rotation, inventory, workloads, revocation) |
| 6 | Task 12 (3am index), Task 17 (agents, home, README.md) |
| 7 | Task 18 (final) |

Wave 5 follows wave 4 because Tasks 10/15 receive the sections the deploy tasks cut. To keep "nothing
lost", **a deploy task never deletes a README section whose destination page is not yet written**: it
replaces the section with a `<!-- moved: <dest> -->` marker and a one-line link, after copying the full
text into the destination file under a `<!-- from: deploy/... -->` comment block at the end of that page.
The wave-5 task owning that page then folds it in and removes the comment. Task 18 fails if any `moved:` or
`from:` marker remains.

### Task 0: Precondition

- [ ] Confirm `feature/key-generate` is merged into `main` (`gh pr list --state merged --head feature/key-generate`).
- [ ] Rebase `docs/second-pass` on `main`; `go test ./tests/ci/ ./tests/shapes/... -count=1` green before any edit.
- [ ] Record the `port49d key sealing` / `key device` usage lines from `internal/port49d/keycmd.go` in the task
      report; Tasks 7, 8, 9 and 15 quote them from the code, never from memory.

If key-generate is not merged, Waves 1–3 may proceed (they do not touch its files: verify with
`git diff --stat main...feature/key-generate`), and every step marked TODO(key-generate) waits.

### Task 1: Skeleton and nav

**Files:** `mkdocs.yml` (nav only), every **new** page in §1 as a stub. No redirects (owner ruling: nothing
depends on today's URLs).

- [ ] Write the final nav of §1 into `mkdocs.yml`. Add a last top-level group `Moving (temporary)` listing
      each file to be removed (`operate/install/*.md`, `operate/broker-and-agent.md`, `operate/login.md`,
      `operate/hardware-keys.md`, `operate/troubleshooting/will-not-start.md`, `admin/identity-providers.md`).
- [ ] Create each new page with front matter `title`, `description` (one sentence of at most 160 characters),
      `status: stub`, and an H1. No body.
- [ ] Checks: `go test ./tests/ci/` (expect only `TestNoPageIsAStub` red, listing the new stubs),
      `make docs-build`.
- [ ] Commit `docs: lay out the second-pass nav with stub pages`.

### Task 2: The "no shape" and "no dash" tests (fix-list 4, rules 6 and 11)

**Files:** `tests/ci/docs_shape_test.go` (new), `tests/ci/testdata/shape/` and `testdata/dash/` fixtures
(new), `internal/docgen/evidence.go` and its test, `tests/qual/cmd/qualified/qualified.go` and its test,
`docs/qualified-platforms.md` (regenerated),
`internal/docgen/descriptions/decision_log.yaml` ("token-shaped username" → "a username that looks like a
token"), `deploy/alerts/README.md:107` ("Same shape" → "Same form"), spec §15 L39 row ("in each
deployment shape" → "in each way to deploy"), then `make docs`.

- [ ] Write `TestNoPageSaysShape`: scans every `.md` and `.txt` under `docs/site` (snippets included) and every
      file a page includes with `--8<--` (resolve the path before any `:`), front matter included (the
      descriptions feed llms.txt); drops fenced blocks and inline code spans; fails on
      `(?i)\bshap(e|es|ed|ing)\b` with file and line. Code spans are exempt so `refused_shape` and
      `tests/shapes` pass.
- [ ] Fixture tests: a prose "shape" fails; "token-shaped" fails; `` `refused_shape` `` and `` `tests/shapes` `` pass;
      "reshaped" passes (not the word).
- [ ] Run it: red, listing every hit. Paste the list into the task report; each later task clears its own.
- [ ] Fix the three generator sources above; `make docs`; their generated hits are gone.
- [ ] Guarantee: the word cannot come back unseen. Do not add an allow-list for prose.
- [ ] Commit `test: fail the docs on the word shape` and `docs: say form, not shape, in generated sources`.

**The dash check (rule 11).** Same file or `tests/ci/docs_dash_test.go`, sharing the scanner.

- [ ] Write `TestNoDashInProse`: fails on `—` (U+2014), `–` (U+2013) or a spaced ` -- ` in prose, with file and
      line, after dropping fenced blocks, inline code spans, URLs and link targets. Scope: every hand-written
      page under `docs/site` (a page whose text holds `docgen.Header` is generated and skipped), and the
      *included range* of every hand-written file a page pulls in with `--8<--`: `file:N` is line N to the end,
      `file:N:M` lines N to M, `file:name` the `[start:name]`…`[end:name]` section, a bare path the whole
      file. Skipped as generated: anything carrying `docgen.Header`, and `docs/qualified-platforms.md`
      (`make qualified-platforms` writes it; match its "This page is generated by" first paragraph, not the
      path, so a hand edit is still caught). Front matter is scanned (descriptions are prose).
- [ ] Fixtures: an em dash in a sentence fails; an en dash in a range "3–5" fails (write "3 to 5"); ` -- ` as a
      dash fails; `--json`, `` `a — b` ``, a dash inside a fenced block and inside a URL pass; a page with the
      generated header passes.
- [ ] Run it: today it should list `index.md` and `contributing/index.md` (one each) and nothing in the
      included README ranges. Paste the list; Task 17 clears both (`closed — measured` goes in a code span, so
      its mustSay row still matches).
- [ ] Generated pages, decided per generator:
      - `internal/docgen/evidence.go` `const none = "—"` (an empty table cell on the device evidence
        tables) and the same marker in `tests/qual/cmd/qualified/qualified.go`: **cheap, do it here.** Change
        the marker to `none`, update `evidence_test.go`/`qualified_test.go` fixtures, run `make docs` and
        `make qualified-platforms`, and check `TestEveryDeviceClaimCitesItsEvidence` still passes.
      - `reference/lab-register.md` (9 dashes) and `reference/reason-codes.md` (14): the prose is the spec's own
        text (§15 rows, §5.7 table), not a generator template. **Not cheap, and not done:** rewriting spec
        rows is a design-record edit outside this pass. Both pages stay exempt as generated. Say so in the
        PR. A later spec pass can do it.
      - Other generated pages hold no dash today (checked 2026-11-26); `labregister.go`'s `TrimRight(… "—" …)`
        is parsing, not output.
- [ ] Commit `test: fail the docs on em and en dashes in prose` and `docs: write none, not a dash, in generated
      evidence tables`.

### Task 3: Remove the banner (fix-list 1)

**Files:** `docs/overrides/main.html`, `mkdocs.yml` (`extra` only), `.github/workflows/docs.yml`,
`tests/ci/cmd/docspublish/main.go`, `main_test.go`, `tests/ci/docs_theme_test.go`,
`tests/ci/docs_workflow_test.go`, `docs/site/operate/versions.md` (the banner sentence only).

- [ ] Tests first: change the workflow test to require that no step sets `PORT49_DOCS_BANNER` and that
      docspublish prints no `banner=`; change the theme test to check the `outdated` block override instead of
      `announce` (still no hard-coded color). Red.
- [ ] Remove `{% block announce %}`; add `{% block outdated %}` with "You are reading the docs of an older
      release. <a href="{{ '../' ~ base_url }}"><strong>Go to the latest.</strong></a>" (Material's documented
      form); `extra.version.default: latest`; drop `extra.banner`; drop the banner output from docspublish and
      the env from docs.yml.
- [ ] versions.md: replace the banner sentence with "A page from an older release says so at the top and links
      the latest." Keep every mustSay string.
- [ ] Humanizer pass (§0) on `operate/versions.md` and the notice's own text.
- [ ] Checks: all; `go test ./tests/ci/cmd/docspublish/`.
- [ ] Commit `docs: show Material's outdated-version notice instead of the banner`.

### Task 4: New reference and contributing pages (copy first)

**Files:** `docs/site/reference/requirements.md`, `reference/client-commands.md`,
`reference/health-checks.md`, `contributing/deployment-design.md`, `tests/ci/docs_content_25_test.go` (new
mustSay rows for these pages). Sources are **read, not edited** (later tasks cut them).

- [ ] `requirements.md` (900): sections `## Device source address`, `## etcd` (own cluster, 3 members, version
      floor 3.4.24 / 3.5.8 / 3.6 and the start line that names it), `## etcd disk` (WAL fsync p99 < 10 ms, the
      500 ms call timeout, `etcd_disk_slow`, GCE pd-ssd vs QLC with the `load-*` notes linked, spool
      fsync and `port49_accounting_spool_disk_slow`), `## broker.state_dir`, `## Clocks` (install-index req. 5
      and the tokens page's "Expiry is the record's" paragraph merged, meaning unchanged: copy both, then
      remove repetition only). mustSay: `10 ms`, `load-beehive-gates.md`, `port49_token_clock_skew`,
      `node_timex_sync_status == 0`, `lease_grace`, `externalTrafficPolicy: Local`.
- [ ] `client-commands.md` (1300): `## port49 token --json` (keys table, failure forms, error table),
      `## Exit codes` (login's table), `## port49 hwkey` exit codes, `## port49 revoke` exit codes. mustSay:
      `--json`, `per_login_mfa_required`, `broker_unavailable`, `reason-codes.md`, the three exit-code rows
      from `docs_content_14_test.go`.
- [ ] `health-checks.md` (600): the will-not-start section verbatim in meaning, the Swarm warning kept as
      `!!! warning`. mustSay: `--ready`, `/healthz`, `docker stack deploy`, `service_healthy`, `start_timeout`,
      `` `retries` from 3 to 6 ``.
- [ ] `deployment-design.md` (700): ProtectSystem, two users, `CAP_NET_BIND_SERVICE`, PVC 3770/fsGroup
      mechanics and the kind cell, smoke tests (systemd, compose, kind), chart status line, and how
      README sections feed the site (`--8<-- "deploy/systemd/README.md:install"`).
- [ ] Lab IDs: page-relative links; `linklabids`. L84 statement on LoadCredential is *not* copied here (its
      home is secrets).
- [ ] Humanizer pass (§0, rule 11) on the four new pages; copied text gets the pass too, with the fact check
      against its source page.
- [ ] Remove `status: stub`. Checks: all.
- [ ] Commit `docs: add requirements, client commands, health checks and deployment design pages`.

### Task 5: Concepts (fix-list 2, 3, 5, 6 F1-1/F7-1, 7, 8, 9)

**Files:** `docs/site/concepts/*.md`, `tests/ci/docs_content_12_test.go`.

- [ ] Tests first: mustSay on `concepts/index.md`: the item-2 first sentence, `## Terms`, "Two things follow
      from how a login works."; on `tokens-receipts-contexts.md`: `## The session`, "**Logging in again joins
      it.**", "**It belongs to one principal.**", `session.replaced_ctx_id`, "never from anything the device
      sends". Red.
- [ ] Item 2 verbatim; item 3 verbatim.
- [ ] Item 8: insert the Terms table. Check each row against code/spec before writing it, and fix in the
      table (not here): memory store is a single-process trial (not "a single host"); the `session` default
      (`max_session_age` default: read `internal/config` / spec, do not trust "12 hours"); trust domain wording
      against `trust-domains.md`; `token` 30–900 s against `token_ttl` bounds; device row matches item 7.
- [ ] Item 5 + F1-1 + F7-1: write `## The session` from `internal/agent/agent.go` (read it): held open while
      the network is up (the broker does not idle-close authenticated connections); a drop is redialed lazily
      on the next request, same certificate and key, same session (random session ID header; decision 45
      ruling 15); end time fixed at login by `max_session_age`; a hardware key costs a PIN or touch on a
      reconnect (no TLS resumption); ends on expiry, revocation, trust change, agent exit; after a reconnect the
      broker stamps a fresh `auth_time`, so a device-side ceiling can run past the end the agent states (verify
      in the broker code first; if the code keeps the login `auth_time`, say that instead and drop the
      sentence). Rewrite concepts/index step 1, identities.md lines 31 and 54 to one line + link.
- [ ] Item 7: add to "One device": "port49d names the device from the connection's source address, through the
      inventory, never from anything the device sends."
- [ ] Item 9: replace per the fix-list text verbatim, keeping the `port`/`rem_addr` part of "Keyed on the username".
- [ ] "Expiry is the record's" → two sentences + link to `../reference/requirements.md#clocks` (Task 4 holds the text).
- [ ] Humanizer pass (§0) on all five concept pages. The approved texts of items 2, 3 and 9 are already plain
      and stay verbatim.
- [ ] Budgets per §1. Clear "shape" and dash hits in these files. Checks: all.
- [ ] Commits: one per fix-list item group (`docs: concepts opening, glossary and login steps` / `docs: the
      session is a redialed connection, not the held one` / `docs: login context joins and replaces`).

### Task 6: Install overview (fix-list 11)

**Files:** `docs/site/operate/deploy/index.md`, delete `docs/site/operate/install/index.md` (and its line in
the temporary nav group), `tests/ci/docs_content_13_test.go`.

- [ ] Tests first: move the install-index mustSay rows: `externalTrafficPolicy: Local` and
      `` `port49-broker init-issuer` `` → `operate/deploy/index.md`; `0755`, `setgid` and the long 0755 sentence →
      `use/install-client.md` (Task 11 writes it; until then the row is red — note in report); `init-revocations` and
      `` `broker.revocations_file` is used only by a single-process trial `` → `operate/stores.md` (Task 10a).
      Add `port49-broker` (from broker-and-agent) here.
- [ ] Write the page in the approved layout, ~300 words:
      1. Deploy table: systemd / Containers / Helm, one line "you get", link to each Install.
      2. Parts table: client (`port49` + agent, on the person's machine), broker (`port49-broker`, HTTPS 8443),
         `port49d` (TACACS+ 49, optional TLS 300), etcd (three members, port49's own), device (unmodified).
      3. Four one-line prerequisites, each linking `../../reference/requirements.md#...`: source address
         unrewritten (Kubernetes: `externalTrafficPolicy: Local`); etcd 3 members at or above the floor on a
         fast disk; `broker.state_dir` kept; NTP on every broker and port49d host.
      4. Three first-install commands, one line each, linking the step on each install page:
         `port49d store-roles`, `port49-broker init-issuer` (only with issuance), `port49-broker init-enrollments`
         (only with directory password sign-in).
      Then one line: "The people who sign in install the [client](../../use/install-client.md)."
- [ ] Humanizer pass (§0). No "shape", no "peers" phrasing (rule from item 11). Checks: all.
- [ ] Commit `docs: install overview in the approved layout`.

### Task 7: systemd (fix-list 12, 13) — TODO(key-generate) for the secrets step

**Files:** `deploy/systemd/README.md`, `docs/site/operate/systemd/{install,upgrade,troubleshoot}.md`, delete
`docs/site/operate/install/systemd.md`, `tests/shapes/recipes_test.go` (only if a moved block breaks its
marker lookup), plus appended `<!-- from: -->` blocks on the destination pages listed in §3 when those pages
are not yet written (see the wave rule).

- [ ] Restructure the README into three marked sections, `<!-- --8<-- [start:install] -->` … `[end:install]`,
      `upgrade`, `troubleshoot` (rename `will_not_start` and update every includer). Text outside the sections:
      a two-line intro and a "More" list of site links. The README stays readable on GitHub and in
      `/usr/share/doc/port49-server/README.systemd.md` (packaging_test checks that path, not content).
- [ ] Section `install`, numbered, each step with **Check:**
      1. Install the package (`apt install ./port49-server_<version>_amd64.deb` or the rpm). **Check:**
         `systemctl list-unit-files 'port49*'` shows both units `disabled`; `id port49d port49-broker`.
      2. Install etcd on three hosts (the shipped examples, etcd ≥ 3.6.15 at `/usr/local/bin/etcd`).
         `!!! info` one line: WAL fsync p99 < 10 ms, link requirements. **Check:** `etcdctl endpoint health
         --cluster` (with the client cert flags) lists three healthy members.
      3. Apply port49's roles: `port49d store-roles … > roles.sh`, run as etcd's root. **Check:** `etcdctl role
         list` shows the two roles (read the role names from `internal/store/etcd/roles.go`).
      4. Put the secrets in place: the files table; TODO(key-generate): `sudo port49d key sealing`, `--import` on
         every other host, `sudo port49d key device <name>`. **Check:** `sudo ls -l /etc/port49/secrets
         /etc/port49/keys` shows the owners and modes of the table.
      5. Configure: copy `config/`, name every etcd member's URL, and choose the sign-in backend with tabs
         `=== "OIDC"`, `=== "Client certificate (x509)"`, `=== "Directory password"`: each tab is 2–5 lines
         (the block to set, the one warning that applies — x509: `certificate_status` before the first sign-in
         if the CA has no OCSP responder, never `disabled: true` outside a trial; directory: keytab placement
         0600 `port49-broker` and `PORT49_SITE` drop-in) and a link to the backend's admin page. No Kerberos tab.
      6. Issuing CA (only with issuance): `sudo -u port49-broker port49-broker init-issuer`, copy to other
         brokers. **Check:** the `issuing as … (sha256:…)` line is the same on every broker (journal).
      7. Enrollments (only with directory password): `sudo -u port49-broker port49-broker init-enrollments`.
         **Check:** its output line (quote it from the code).
      8. Start: `systemctl enable --now port49d port49-broker`. **Check:** `port49d healthcheck --ready` exits 0
         (or `curl -fsS 127.0.0.1:9049/readyz` prints `serving`); the port49d start line names every etcd
         member at or above the floor.
      9. Enable the backup timers. **Check:** `systemctl list-timers 'port49-*'`. Link backup-and-restore.
      10. First device and first login: link `../../admin/inventory.md` and `../../use/login.md`. **Check:**
          `port49 ssh <device> -- show version` and a `redeem` record with `verdict: permit` in the decision log.
      `## Manual install` (the "Without the package" paragraph, as steps).
      Optional, one line each + link: TLS on port 300 (`operate/tls.md`), `LoadCredential=` (`operate/secrets.md`).
- [ ] Section `upgrade`: read the [version policy](../versions.md) first; upgrade the package (check what the
      package scripts do on upgrade: read `packaging/server/` nfpm scripts; say whether units restart);
      re-apply `store-roles` when the release notes say the roles changed (what port49d does when a grant is
      missing: it refuses at start naming `port49d store-roles` for the checks it makes — quote the lines in
      `internal/port49d/store.go` and `internal/store/etcd/roles.go`; do not claim it detects every grant; the
      wider check is D3's follow-up issue); two groups of servers side by side, one host at a time. **Check:** `port49d --version` and readyz.
- [ ] Section `troubleshoot`: the `will_not_start` table + the systemd-specific admin-call rows.
- [ ] Pages: each `operate/systemd/*.md` is front matter, an H1, and the section include. Fix "shape" (4).
- [ ] Humanizer pass (§0) on the three README sections and the text outside them (README prose is site prose
      once included; the dash test reads the included ranges).
- [ ] Every other README section moves per §3 with the wave rule. Key order phrases stay until Task 15
      retargets `TestEveryReadmeStatesTheKeyOrder` — so **leave "Adding a key version" in the README until
      Task 15** (it moves there in one commit with the test change).
- [ ] Ceilings: install 1000, upgrade 250, troubleshoot 600. **At risk:** install (ten steps, each with a
      check). Command blocks are not counted; one sentence per step plus its check; etcd disk guidance in a
      `!!! info`. If 1000 still means dropping a step's check or a warning, report it and stop there.
      Checks: all, plus `go test ./tests/shapes/...`.
- [ ] Commits: `docs: systemd install as numbered steps with checks`, `docs: systemd upgrade and troubleshoot pages`.

### Task 8: Containers

**Files:** `deploy/compose/README.md`, `docs/site/operate/containers/{trial,install,upgrade,troubleshoot}.md`,
delete `operate/install/container.md`.

- [ ] Sections `trial`, `install`, `upgrade`, `troubleshoot` as in Task 7. Trial ends with **Check:**
      `docker compose ps` shows `healthy` for port49d and the broker, and the `port49 login` line.
- [ ] Install steps: bring your own PKI under `PORT49_COMPOSE_LOCAL` (TODO(key-generate): the sealing key with
      `port49d key sealing --dir` in the setup image, as key-generate wrote it); inventory by the address
      port49d sees (docker-proxy [L39] facts kept, open parts under `!!! warning "Unmeasured"`); policy edits on
      the host then `up -d`; `broker.state_dir` one named volume per broker; issuing CA; sign-in tabs; start;
      check readyz on 9049/9050. `!!! warning`: the shipped healthcheck uses `--ready`, wrong for Swarm, link
      `reference/health-checks.md`. `!!! warning`: Docker API access is root-equivalent.
- [ ] Upgrade: image rebuild + `up -d` as one change, policy edits separately; store-roles re-apply.
- [ ] Leave "Adding a key version" and "Rotating" in the README until Task 15 (tests read them).
- [ ] Humanizer pass (§0) on the compose README's four sections and the four pages.
- [ ] Clear "shape". Budgets per §1. Checks: all, plus `go test ./tests/compose/ ./tests/shapes/...`.
- [ ] Commits: `docs: containers trial, install, upgrade and troubleshoot pages`.

### Task 9: Helm

**Files:** `deploy/helm/port49/README.md`, `docs/site/operate/helm/{install,upgrade,troubleshoot}.md`, delete
`operate/install/helm.md` and `operate/troubleshooting/will-not-start.md` (after confirming Tasks 4, 7, 8
took their parts), `tests/helm/suite_test.go` (heading match only, if the heading gains a step number),
`tests/ci/docs_content_18_test.go` (will-not-start rows: `debug pod` → `operate/helm/troubleshoot.md`; the
rest already on `reference/health-checks.md` from Task 4).

- [ ] Install steps: create the Secrets `--from-file` (never `--from-literal`); the `helm install` block unchanged
      (static_test); schema refusals as the check; device keys via ExternalSecret (keep the ClusterSecretStore
      warning); Pod Security `baseline` with `CHOWN`, `FOWNER`, `FSETID` named (pod_security_test); expose
      port 49: `externalTrafficPolicy: Local` table [L39], MetalLB [L85]; etcd roles Job; issuing CA
      (`examples/values-issuance.yaml` named before `copy-issuer.sh`); `init-enrollments` Job; sign-in tabs;
      **Check:** `kubectl -n port49 get pods` Ready, `kubectl port-forward` + `/readyz` 200.
- [ ] Upgrade: `helm upgrade`, preStop 15 s and `terminationGracePeriodSeconds` ≥ sleep + 30 [L85], the
      Kubernetes 1.30 requirement for the sleep action, two releases in two namespaces, store-roles Job re-run.
- [ ] Troubleshoot: one table merging README "At 3am" and will-not-start's Kubernetes table (dedupe rows;
      keep the more specific wording), the "behind a promotion" recovery (steps kept, both "Do not" lines kept),
      Helm admin-call rows.
- [ ] Velero: `operate/helm/velero.md` is front matter, an H1, one sentence, and the
      `--8<-- "deploy/helm/port49/examples/velero/README.md"` include moved from the backup page, with its
      mustSay row moved to this page in the same commit. The README is not cut: `tests/shapes/l89` runs its
      commands as the measured procedure; shape and dash fixes only.
- [ ] Ceilings: install 1000, upgrade 250, troubleshoot 800. **At risk:** install (the [L39] traffic-policy table,
      [L85] MetalLB, Pod Security names, issuing CA, two Jobs). Tables and command blocks carry it; one sentence
      per step plus the check. Report rather than drop a warning (ClusterSecretStore, `--from-file`).
- [ ] Humanizer pass (§0) on the Helm README sections and the four pages. Keep the strings the Helm tests read
      (`--set keys.existingSecret=`, `The issuing CA`, `CHOWN`, `FOWNER`, `FSETID`, `baseline`, `restricted`).
- [ ] Clear "shape". Checks: all, plus `go test ./tests/helm/ ./tests/shapes/...`.
- [ ] Commits: `docs: Helm install, upgrade and troubleshoot pages`, `docs: fold will-not-start into the deployment pages`.

### Task 10a: Stores, secrets, TLS

**Files:** `docs/site/operate/stores.md`, `operate/secrets.md`, `operate/tls.md`, `tests/ci/docs_content_15_test.go`,
`docs_content_16_test.go`.

- [ ] Stores: add `## The memory store` (install-index text; mustSay moved in Task 6 goes green); F5-1: the
      multi-region example's session store lists every member and a sentence says the endpoint list is static,
      no member discovery (check `internal/store/etcd` for any `MemberList`/auto-sync use first); F3-2: one line
      on start-up scan cost ≈ contexts / 500 × RTT (read the fallacies report entry and the scan code; state the
      page size from code). Ceiling 1200.
- [ ] Secrets: add `### systemd: LoadCredential=` from the README (L84 measured cell; broker not claimed) as
      an option with plain steps and one line on why; fold `from:` blocks; dedupe Kubernetes vs Helm text.
- [ ] TLS: `## Turn the listener on` with tabs (systemd files in `/etc/port49/tls/`, compose, `tlsListener.enabled`
      + `existingSecret`). Ceiling 1100; secrets 900. Device-side TLS behavior stays as lab-cited cells; the
      reasoning on why TLS over RFC 8907 moves to one line + concepts link.
- [ ] Humanizer pass (§0) on stores, secrets and TLS.
- [ ] Clear "shape". Checks: all.
- [ ] Commit per page.

### Task 10b: Backup and restore, monitoring, versions

**Files:** `operate/backup-and-restore.md`, `operate/monitoring.md`, `operate/versions.md`,
`tests/ci/docs_content_17_test.go`, `docs_content_18_test.go` (monitoring rows `10 ms`,
`load-beehive-gates.md` → requirements, already on Task 4's page).

- [ ] Backup: `## What to back up` with deployment tabs absorbing the README backup sections (systemd timers
      and the `StandardOutput=file:` reason; Helm CronJobs and their stale-check; the Velero warnings in one
      `!!! warning` plus a link to `operate/helm/velero.md`, which holds the procedure). Every mustSay string
      stays; restore runbook order unchanged; edge sections may go into `??? info` but no warning does.
- [ ] Ceilings: backup 1600, monitoring 600, versions 400. **At risk:** backup (31 mustSay strings, the restore
      runbook's warnings). The Velero include no longer counts here. If 1600 cannot hold every warning, report the
      measured count and the warnings that hold it up; do not cut one.
- [ ] Monitoring: disk section → two lines (the alerts) + link. Keep `task_id`, `global_cap`, `etcd_disk_slow`,
      `port49_accounting_spool_disk_slow`, `job="port49-broker"`.
- [ ] Versions: "Upgrading" links the three upgrade pages; keep the etcd-roles rule as one line. Generic, for
      future releases (§0 "Nothing has been released").
- [ ] Humanizer pass (§0) on the three pages. On the restore runbook, keep step order and every warning
      exactly as strong as before.
- [ ] Checks: all. Commit per page.

### Task 11: Sign in and Automation

**Files:** `docs/site/use/*.md`, `automation/python.md`, `automation/ansible.md`, delete
`operate/install/clients.md`, `operate/login.md`, `operate/broker-and-agent.md`, `operate/hardware-keys.md`,
`tests/ci/docs_content_13_test.go` (clients rows), `docs_content_14_test.go`, `descriptions/client.yaml`
(F4-2), `make docs`.

- [ ] Tests first: move mustSay rows: clients → `use/install-client.md` (+ the 0755 rows from Task 6);
      broker-and-agent `agent.log`, `XDG_RUNTIME_DIR`, `max_session_age` → `use/login.md`; login `port49 ssh:`,
      `accept-new`, `known_hosts` → `use/connect.md`; hardware-keys → `use/hardware-keys.md` with
      `install/clients.md` changed to `install-client.md` (same guarantee: the page sends PKCS#11 users to the
      client build).
- [ ] `use/index.md` (overview, 300): table of the three sign-in methods (certificate, OIDC, directory password)
      with "your admin tells you which"; parts the person touches (client, agent, device); prerequisites (client
      installed, broker URL and CA from the admin); first commands `port49 login`, `port49 ssh <device>`.
- [ ] `use/install-client.md`: download + checksum steps with **Check:** `port49 --version`; the 0755 rule as a
      step with `!!! info` for the askpass reason; PKCS#11 section; one line each to the Python and Ansible pages.
- [ ] `use/login.md`: tabs per method, each ending in a check; the agent (socket, log, `XDG_RUNTIME_DIR`); "How
      long a session lasts" (messages only, link the session concept); one agent one identity.
- [ ] `use/connect.md`: `port49 token`, `port49 ssh`, host keys, telling refusals apart; exit codes and `--json`
      → links to `reference/client-commands.md`.
- [ ] `use/hardware-keys.md`: as now, shortened; F7-1 line (a reconnect asks for the PIN or a touch); exit codes
      → link; Unmeasured warning with L60/L63 kept.
- [ ] F4-2: verify in `internal/client` (or wherever the broker HTTP client is built) that `HTTPS_PROXY` is
      ignored for the broker; then one sentence in `descriptions/client.yaml` on the `broker` key; `make docs`.
- [ ] Automation pages: front matter + H1 + one-sentence lead + the existing snippet line.
- [ ] Humanizer pass (§0) on the five `use/` pages and the two automation pages' own prose. The included
      client READMEs (also the PyPI and Galaxy pages) get only the shape and dash fixes; a full pass on them is
      out of scope.
- [ ] Clear "shape". Checks: all. Commits per page group.

### Task 12: The 3am index

**Files:** `docs/site/operate/troubleshooting/index.md`, `tests/ci/docs_content_18_test.go` (index rows only).

- [ ] Keep the three-part structure, the `## A log line says` form (one whole code span per **You see:**), and
      every alert link `../../reference/alerts.md#<name>)`.
- [ ] Trim each entry to You see / It means / Do this / Don't; mechanics → links.
- [ ] Add: "Which side owns what" table (from broker-and-agent); "An admin command is refused" (generic rows of
      the admin 3am tables; deployment rows link each troubleshoot page); "`port49 ssh` sends an empty
      password" (0755 rule, link the client page); rename the device-local entry to "Device break-glass does
      not work" so it is not confused with the offline revoke.
- [ ] Intro: one line per deployment's troubleshoot page, and the `/readyz` check.
- [ ] Humanizer pass (§0). `**You see:**`, `**It means:**`, `**Do this:**`, `**Don't:**` stay: they are the
      scanning labels the 3am reader needs, and the log-line test reads `**You see:**`.
- [ ] Ceiling 3000. Checks: all (`TestEveryQuotedLogLineIsInTheCode`, `TestEveryAlertIsInTheIndex`).
- [ ] Commit `docs: trim the 3am index to symptom and fix`.

### Task 13: Sign-in backends, directory, admin access

**Files:** `docs/site/admin/index.md`, `admin/sign-in/{oidc,x509,directory-password}.md`, `admin/directory.md`,
`admin/admin-access.md`, delete `admin/identity-providers.md`, `admin/revocation.md` (only the "What you need"
and "Checking your CA's revocation lists" sections leave), `tests/ci/docs_content_19_test.go`,
`docs_content_20_test.go`.

- [ ] Tests first: identity-providers rows → the page each string's section moves to (grep each string's line
      first); revocation rows `issuer_file`, `disabled: true`, `certificate_status_unavailable`, "admitted with
      its revocation status unchecked" → `admin/sign-in/x509.md` (confirm each is in the CRL sections).
- [ ] Each backend page: what it is (2 lines + link to `concepts/identities.md`), numbered setup steps with checks
      (`port49 login --oidc` from a test account; `port49 login --cert`; `port49 login --directory` after
      enrollment), then the rules a 3am reader needs. OIDC page takes `HTTPS_PROXY`, back-channel URL,
      `sub` per provider, JWKS kept in `state_dir`. x509 page takes `certificate_status`, `crls:`, `issuer_file`,
      `on_unavailable`, `SSL_CERT_FILE` for private-CA https CRLs.
- [ ] `admin/directory.md`: servers and sites, bind methods (`gssapi` keytab — a bind method, not a sign-in
      backend; `external`; `simple` with `password_secret_ref: file:`), Samba AD [L43] and Windows AD [L44]
      (check each row's status; open → Unmeasured), certificate mapping, nested groups, grace. Keys link the
      generated reference.
- [ ] `admin/admin-access.md` (item 12 admin operations): attestation roots (deployment tabs: file path and reload:
      `systemctl reload port49-broker`; compose `up -d` + `kill -s HUP`; Helm `broker.attestationRootsConfigMap`);
      the `api:` right; "Can several admins share one directory group? Yes: a `group:` subject can hold the
      right. Also name at least two by `identity:`, because a group resolves through the directory, which may
      be down when you need it."; "Each admin's key: nothing to enroll. The broker checks the key's attestation
      against the roots; each admin runs `port49 login` with `key: pkcs11:…`." **Check:** `port49 revoke --list`
      asks for a touch and answers.
- [ ] `admin/index.md`: the overview layout.
- [ ] Humanizer pass (§0) on every page this task writes and on the trimmed `admin/revocation.md`.
- [ ] Clear "shape". Checks: all. Commits per page.

### Task 14: Policy

**Files:** `admin/policy.md`, `admin/policy-rules.md`, `admin/policy-tests.md`, `admin/policy-review.md`,
`admin/platform-sets.md`, `admin/roles-and-grants.md`, `tests/ci/docs_content_19_test.go` (policy rows only —
coordinate: Task 13 edits the revocation rows of the same file; run 13 and 14 in sequence or put each page's
rows in its own new file `docs_content_26_test.go`).

- [ ] Tests first: for each policy.md mustSay string, grep its section and move the row with it.
- [ ] `policy.md` (800): the pieces (subject, role, scope, grant), one complete minimal policy, first commands
      (`port49 policy test`, `port49 explain`), a table linking the four children.
- [ ] Move sections per §3; keep the worked example on `policy-tests.md`, shortened. Fix the home page's
      `admin/policy.md#writing-tests` link target in Task 17.
- [ ] Humanizer pass (§0) on the six policy pages. Rule syntax, test YAML and `policy diff` output stay
      byte-for-byte.
- [ ] Clear "shape" (policy 4, roles 1). Ceilings per §1 (roles and grants 1000: the grant table is reference
      and counts; move per-command detail to the generated config reference by link). Checks: all. Commit per page.

### Task 15: Key rotation, inventory, workloads, revocation break-glass

**Files:** `admin/key-rotation.md`, `admin/inventory.md`, `admin/workloads.md`, `admin/workloads-oxidized.md`,
`admin/workloads-kubernetes.md`, `admin/revocation.md` (break-glass section), the three READMEs (remove "Adding
a key version", "Rotating", break-glass), `tests/shapes/units_test.go`, `tests/shapes/recipes_test.go` (if its
blocks move), `tests/compose/static_test.go` (D2), `tests/ci/docs_content_16_test.go`, `docs_content_20_test.go`.

- [ ] Tests first: retarget `TestEveryReadmeStatesTheKeyOrder` to `docs/site/admin/key-rotation.md`: the four
      phrases plus each deployment's symptom (`Restart=`, `docker compose`, `CrashLoopBackOff`). Retarget
      recipes_test's block lookup if the `port49d key device` block moves. Red.
- [ ] Key rotation: device keys with tabs (systemd: TODO(key-generate) `sudo port49d key device <name>` then policy
      line then `systemctl reload port49d`; compose: the key-generate `docker run … port49d key device` block;
      Helm: a new Secret key or remote key). The order `!!! warning` (file first, policy line second; removing
      in reverse; the crash-loop and how each deployment shows it). Encryption key: three steps with tabs;
      re-seal waits into `??? info` blocks; all 30 mustSay strings stay.
- [ ] Compose tab of the encryption rotation: the `port49d key sealing --id <id> --dir … --broker-dir …` command
      in the setup image exactly as key-generate wrote it (D2, done there). If the command leaves the compose
      README, retarget `tests/compose/static_test.go` to the page in the same commit. Names are today's only:
      `broker-encryption[-<id>].key`, never the old name.
- [ ] Revocation: `## Break-glass` with tabs (systemd, compose, `scripts/revoke-offline.sh`), "stops issuance
      fleet-wide while the brokers are down" kept as `!!! warning`, the root-refusal line kept.
- [ ] Inventory: `## Who may write the inventory` (S0): SoT write access is privilege-granting (spec §10); on RFC
      8907 a shared CIDR/attribute key plus inventory write gives any in-range device's grants; use `tls` or a
      per-device name pin for crown jewels (check the spec text and the pin's config name before writing).
- [ ] Workloads: overview + step-ca; the two snippet pages.
- [ ] READMEs: remove the moved sections, leave one line + absolute link each.
- [ ] Humanizer pass (§0) on key rotation, inventory, workloads (own prose; the example READMEs get shape and
      dash fixes only), the revocation break-glass section, and the README lines left behind.
- [ ] Ceilings: key rotation 1800, inventory 1400, revocation 1000, workloads 700. **At risk:** key rotation (30
      mustSay strings, the re-seal waits, the order warning). Waits go in `??? info`; the order warning and the
      crash-loop warning stay visible. If 1800 needs a warning cut, report and stop. Revocation is next: the
      break-glass `!!! warning` and the root-refusal line stay.
- [ ] Clear "shape". Checks: all, plus `go test ./tests/shapes/... ./tests/compose/ ./tests/helm/`.
- [ ] Commits: `test: the key-order rule is checked on the key rotation page`, then one per page.

### Task 16: Devices

**Files:** `admin/devices/index.md`, device pages (wording only), `tests/ci/docs_content_21_test.go` (no change expected).

- [ ] Index: "How to read a device page" → 120; single-connection → 250; keep the qualified-platforms and
      device-aaa includes.
- [ ] Humanizer pass (§0) on the devices index only.
- [ ] Device pages: "shape" and dashes only; do not move a claim between sections ("What the lab measured", "Traps",
      "Unmeasured" are what `claimsOf` reads).
- [ ] Checks: all (`TestEveryDeviceClaimCitesItsEvidence`).
- [ ] Commit `docs: shorten the devices index`.

### Task 17: Agents, Home, README

**Files:** `agents/*.md`, `index.md`, `contributing/{index,qualification,releasing}.md`, `README.md` (links
and the humanizer pass), `tests/ci/docs_content_22_test.go` (no change
expected), `docs_content_24_test.go` (no change expected).

- [ ] Ceilings: quick start 1500, setup runbook 900. **At risk:** quick start (19 mustSay strings; fenced blocks
      do not count, prose around them does).
- [ ] Relink to new paths; trim quick-start "How a refusal reaches the agent" by linking client-commands;
      runbook blocks stay ≤ 5 lines; clear "shape" ×3 in the runbook.
- [ ] Home: new Where-to-start links; "three ways to deploy"; keep every mustSay string.
- [ ] README.md: links that pointed at moved pages; keep the bullet counts (`TestTheReadmeIsNotAFeatureList`).
- [ ] Contributing pages: no restructure; humanizer pass on `contributing/index.md` (its one dash: put
      `closed — measured <date>` in a code span so the mustSay row still matches), `qualification.md`,
      `releasing.md`.
- [ ] Humanizer pass (§0) on Home, both agent pages and the README's site-facing paragraphs. The agent pages'
      mustSay strings and fenced blocks stay exact; the Home page's dash goes.
- [ ] Checks: all. Commit `docs: point home, README and agent pages at the new tree`.

### Task 18: Final

**Files:** `mkdocs.yml` (delete the empty `Moving (temporary)` group), any remaining fixes.

- [ ] `grep -rn -e '<!-- moved:' -e '<!-- from:' docs deploy --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab'` is empty.
- [ ] `TestNoPageSaysShape`, `TestNoDashInProse` and `TestNoPageIsAStub` green.
- [ ] Humanizer audit: every hand-written page and included README range was in some task's pass (list the
      task per page in the report; a page no task covered gets its pass now). Grep the hand-written pages for
      the strongest surviving tells (`not just`, `not only`, `rather than`, `This page`, `The table below`,
      `serves as`, `Let's`, lines that are only a bold label plus colon) and fix or justify each hit. Every `go test ./tests/ci/` test green.
- [ ] `make docs && make docs-build`, `PORT49_DOCS_SITE=site go test ./tests/ci/ -count=1`, `make test && make vet`:
      paste the real tails into the report.
- [ ] Word count table: every page's measured words vs budget (the awk above), and the section totals.
- [ ] One-home audit: for each row of §2, grep the topic's key phrase across `docs/site` and the READMEs; every
      hit outside the home is one line with a link.
- [ ] Review: Opus, adversarial, against this plan, rules.md (1 to 11, the humanizer SKILL.md path named) and
      the fix-list, with the security rules of §0 in the brief; then PR. The PR says that
      `reference/lab-register.md` and `reference/reason-codes.md` keep the spec's dashes (Task 2).

---

## 5. Fix-list coverage

| Item | Task |
|---|---|
| 1 Banner → outdated-version notice | 3 |
| 2 Concepts opening | 5 |
| 3 "Two things follow from how a login works." | 5 |
| 4 No "shape" + test | 2 (test, generated sources); every content task clears its files; 18 (green) |
| 5 Held connection is not the session | 5 (`concepts/*`), 11 (`use/login.md` person's view) |
| 6 F1-1 fresh `auth_time` after reconnect | 5 |
| 6 F7-1 reconnect is a key use | 5 (concept), 11 (`use/hardware-keys.md`) |
| 6 F5-1 multi-region etcd endpoints, static list | 10a |
| 6 F4-2 client ignores `HTTPS_PROXY` for the broker | 11 (`descriptions/client.yaml`) |
| 6 F3-2 start-up scan cost | 10a |
| 6 F8-2 NTP / clock paths | done in PR #83 (`fix/token-expiry-clock`, merged); this pass only moves its text to `reference/requirements.md#clocks` in Task 4 without changing meaning |
| 6 S0 inventory write is privilege-granting | 15 |
| 7 Device named from source address via inventory (proposed) | 5 — included: it is true (tls.md: "A device is the inventory record its source address belongs to") and short |
| 8 Glossary table | 5 |
| 9 Joins / replaces bullets | 5 |
| 10 Overall volume | the whole plan; budgets in §1, measured in 18 |
| 11 Install overview layout | 6 (and the same layout for `use/index.md` 11, `admin/index.md` 13) |
| 12 duplicate requirements | 7 (removed from README; home `reference/requirements.md`, Task 4) |
| 12 Manual install as its own section | 7 |
| 12 No key scripts; binary makes keys | Task 0 dependency; 7, 8, 15 use `port49d key` — TODO(key-generate) |
| 12 Admin operations unclear; groups; each admin's key | 13 (`admin/admin-access.md`) |
| 12 Numbered steps | 7, 8, 9 |
| 12 3am table → troubleshooting per install type | 7, 8, 9 (deployment rows), 12 (generic rows) |
| 12 Branch on identity backend | 7, 8, 9 (tabs), 13 (backend pages); Kerberos is a directory bind only |
| 12 etcd disk → info admonition | 4 (home), 7, 8, 9 |
| 12 Verification per step | 7, 8, 9, 11, 13 |
| 12 "apply the roles again by hand" | 7, 8, 9 (upgrade pages), 10b (versions); D3 for the code question |
| 12 Two groups / ProtectSystem / LoadCredential | 7 → upgrade page / 4 (`contributing/deployment-design.md`) / 10a (`operate/secrets.md`) |
| 13 Parent/children nav, per-deployment upgrade | 1 (nav), 7, 8, 9 |
| Rule 11 humanizer | a pass step in every content task (3 to 17), §0 for how; `TestNoDashInProse` in 2; audit in 18 |

---

## 6. Risks and how to keep them

1. **A safety warning shortened into a wrong or missing one.** The ones at stake: the key order and crash-loop;
   never `disabled: true` outside a trial; OCSP-less CA refuses every certificate until `crls:` is set;
   `--ready` restart loops under Swarm; offline revoke stops issuance fleet-wide; a Velero restore including etcd
   is a store restore; the backup bucket holds the issuing CA key and every Secret; ClusterSecretStore without
   conditions exposes device keys; Docker API is root-equivalent; `forget-issuer` kills every issued certificate;
   "Session control stops at the device"; the receipt window bounds a leaked spent token. **Keep:** each becomes
   a visible `!!! warning` at its home, and Task 18's reviewer gets this list and checks each one by grep. Add
   each warning's key phrase to `mustSay` at its home as it moves, so it cannot be dropped later.
2. **A lab claim moves out of its Unmeasured warning, or a measured claim loses its note link when README
   absolute links become page links.** The open-entry and built-site tests catch most; `linklabids` fixes bare
   IDs. Rewrite README lab links by hand to the relative form, keeping the results-note path in the sentence
   (`citesNote` reads the sentence).
3. **"Copy first, cut later" loses text if a later task never folds the `from:` block.** Task 18's marker grep
   fails the pass.
4. **Shortening the session text (item 5) re-asserts a wrong claim** (the held connection *is* the session).
   Write from `internal/agent/agent.go` and the broker code, not from the old pages; F1-1 is checked in code
   before it is written either way.
5. **The clock text from PR #83 is reworded into something less exact.** Task 4 copies it; Task 5 only cuts the
   tokens page to two sentences + link. A reviewer diffs the meaning against PR #83.
6. **mustSay rows deleted instead of moved.** The guarantee table in §0 is the rule; the reviewer diffs the
   union of all mustSay strings before and after (`go test -run TestEveryPageSaysWhatItMust -v` lists them) —
   every string present before is present after, on some page, unless its wording had to change, which the
   commit message names.
7. **Tests that read README text break when sections move** (recipes, key order, helm existingSecret, issuing CA
   heading, Pod Security names, compose rotation recipe, L89 velero). §0 lists each; the task that moves the text
   changes the test in the same commit and says which guarantee it keeps.
8. **Moved pages.** Owner ruling: nobody depends on today's URLs, so no redirects. The risk is internal only:
   `make docs-build` (strict, anchors on) catches every broken link and anchor between pages.
9. **Snippet includes inside tabs.** Tabbed content is indented; a `--8<--` line inside a tab may not indent the
   included text. This plan writes tab content directly on the page and includes README sections only as whole
   pages, so it does not depend on it. If an implementer wants a snippet in a tab, prove it with
   `make docs-build` first.
10. **Kerberos.** There is no Kerberos sign-in backend; a keytab is a directory bind method. An implementer
    must not add a Kerberos tab to the install pages (rule 8 says check before writing).
11. **The package README offline.** `README.systemd.md` loses rotation, admin and backup detail to the site; it
    keeps install, upgrade and troubleshoot, which is what a host without network needs. Its "More" list gives
    the site URLs.
12. **Config has no offline check.** port49d has no `check-config` subcommand, so the "configure" step's check is
    the start line and readyz in the next step. Do not invent a command (D4: not in this PR).
13. **Device pages.** Their structure feeds `claimsOf`; Task 16 changes wording only.
14. **The humanizer pass changes a fact or softens a warning.** Its edits under §6 (triads), §9 (qualifiers) and
    §19 (bold labels) drop facts most often, by the skill's own account. Keep: every pass ends with the skill's
    step 3 check against the old text; a hedge that bounds a safety or unmeasured claim is kept as a scope
    statement; a "not X" that corrects a real operator belief ("`running` is not ready", "a token is not a
    password") is kept. The mustSay rows catch a dropped literal, not a changed meaning, so the Task 18 reviewer
    diffs each warning of risk 1 for meaning.
15. **The dash test fights a literal.** A mustSay string or a quoted log line with a dash goes in a code span,
    where the test exempts it; never widen the test.

---

## 7. Rulings (2026-11-26)

- **D1, redirects: no.** The owner overrode the first yes: nothing is released and nobody uses the site, so pages
  move freely. No `mkdocs-redirects`, no redirect map.
- **D2, compose encryption rotation: done on `feature/key-generate`.** The compose rotation is now
  `port49d key sealing --id … --dir … --broker-dir …` in the setup image, the compose broker key is
  `broker-encryption[-<id>].key`, and the static test was updated there. Tasks 7, 8 and 15 rebase onto it after
  it merges (Task 0).
- **D3, etcd roles after an upgrade: yes, as a separate follow-up issue, spec first.** Today port49d refuses at
  start naming `port49d store-roles` when etcd's roles are not in force and when the broker's role lacks the
  lift-record grant it probes (`internal/port49d/store.go`, `internal/store/etcd/roles.go`); it does not probe
  every grant. The upgrade pages describe that behavior and say to re-apply the roles when the release notes say
  they changed.
- **D4, `port49d check-config`: not in this PR.** The lead puts it to the owner as a proposal. The configure step
  verifies with the start line and readyz.
- **Budgets:** every budget is a ceiling, cut by about a third on the long how-tos (§1). A task that cannot meet
  one without dropping a true safety warning says so in its report instead of inflating it.
- **Nothing released:** no migration notes or old names; upgrade pages short and generic (§0).
