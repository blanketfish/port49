# Reference Configurations, Alarms, Load and Lab Rows Implementation Plan (plan 12c)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish design §19 step 12. This plan ships:
- the tested reference device AAA configuration per platform, for RFC 8907 and for RFC 9887 where the platform has it (design §12: "the thing that disables fall-through on FAIL, and the lab asserts it");
- the alert rules, one per MUST-alarm statement in both documents, each with a registered metric behind it (design §15);
- load validation at the design §5 rate, and the defaults sized from it;
- the failure matrix of design §12 and §14 as a test;
- the lab rows 12b handed on (L39 (b) and (c), L84's systemd cells), and four new ones: L87 (SR Linux on an ERROR), L88 (the reference configurations), L89 (Velero) and L90 (Oxidized host keys);
- three code items carried here: the Junos `idle-timeout` per class, `policy diff` reporting a changed session ceiling, and the `key_ref` label bounded.

**Architecture:**
- Device configurations live in `deploy/device-aaa/`, one file per platform and transport, written with closed-set `<PLACEHOLDER>` markers. `tests/deviceaaa` renders them. Its unit tests run under `make test`, and the L88 harness loads the same files onto each lab image.
- Alert rules live in `deploy/alerts/port49.rules.yaml`, a plain Prometheus rule file every shape can use. The chart carries a byte-identical copy behind `prometheusRule.enabled` (off by default). A Go test pins every rule to a registered metric. `promtool test rules` pins that each one fires.
- Load runs from `tests/lab/load_test.go`, on the lab host under the lab lock. It plays `internal/devicemock` fleets at a fixed open-loop rate against port49d and port49-broker on a three-member etcd (`PORT49_LAB_ETCD_BIN`). The numbers go in a results note. Each default sized from load is ruled in advance by a stated gate (ruling 7).
- The failure matrix runs on the compose stack (`tests/compose/failmatrix_test.go`, `make failure-matrix`), in CI. A row the stack cannot reach cites the closed lab row that measured it.
- The kind lab rows (L39, L89) are cells of the existing label-gated `lab-kind` workflow. L84's systemd cells run in a new label-gated `lab-hosted` workflow, because smokes run in CI only (Ryan, 2026-10-30). The device rows (L87, L88, L90) run on the lab host.

**Tech Stack:**
- Go 1.26: the standard library, `gopkg.in/yaml.v3` and `github.com/prometheus/client_golang`, all in go.mod. No new module.
- Prometheus `promtool` v3.5.0, pinned by sha256 in the Makefile as `bin/promtool-$(PROMTOOL_VERSION)`.
- etcd v3.6.15 (`PORT49_LAB_ETCD_BIN=/mnt/images/etcd-v3.6.15`).
- kind v0.29.0, Helm 3.22.0 and kubectl 1.33.1, as 12b pinned them. Velero and MinIO are pinned the same way in Task 15.
- containerlab images per `tests/lab/README.md`. Default selectors: vEOS, C8000V 17.13.01a, N9Kv 10.4(2)F, vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15. Opt-in selectors: `vjunos26`, `iosxe1718`, `nxos106`, `ceos436`, `xrd261` and `srlinux`.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.6, "Session lifetime" and decision 21 (the class `idle-timeout`);
  - §5.7 (`store_unavailable`, `admin_touch_refused`);
  - §10, "Version sets, and no cutover";
  - §12's warnings (no new one);
  - §13 decisions 21, 33, 37, 50, 51, 53 and 54, and decision 55, which Task 1 writes from the rulings below;
  - §15 rows L4, L13, L24, L28, L29, L35, L39, L41, L73, L74, L76, L84 and L87–L90.
- `docs/design/2026-08-21-port49-design.md`:
  - §5 (targets);
  - §12 (the failure model, "Device-side AAA configuration is part of the failure model", "A key mismatch is indistinguishable from an outage");
  - §13 (the source address; two independently upgraded server groups; the anycast note);
  - §14 (required assertions: the failure matrix, sustained load, observability, device fallback when servers are declared dead);
  - §15 (every stated alarm needs a metric; cardinality).
- The roadmap, `docs/superpowers/plans/README.md`:
  - "Plan 12 — Deployment": the 12c entry, and the carries from plans 1, 6a, 9a, 11, 11a, 11b and L76;
  - "Plan 12a — As built", Hand-offs (12c);
  - "Plan 12b — As built", Carried forward and Hand-offs (12c);
  - "Pre-beta review".
- The inventory, `.superpowers/sdd/plan12-inputs.md`: themes C, D and F, and the 2026-10-26 additions at its end.

## Decisions for Ryan

Each has a recommendation. The plan is written to the recommendation; where Ryan rules otherwise, the named task changes as its last line says.

1. **The Junos `idle-timeout` per class** (roadmap 12c entry, "pending a ruling"; plan 7b pre-flight M11).
   - Today every reference class carries `session.max_session_age_default` (`internal/platform/classes.go`, `ReferenceClasses`). Decision 21 says the class timer is rendered "from `max_session_age`", which spec §5.6 makes per role.
   - A class is shared: every session the policy lands at that level's template on a Junos device uses it. So "per role" has to become "per class".
   - **Recommended:** each class gets the least ceiling among the sessions the policy lands in it on that platform's devices. Each session's ceiling is the least across its own roles, with `session.max_session_age_default` for a role that names none (`SessionAge.Of`).
     - A class whose every session is `never` gets no `idle-timeout` line.
     - A class no session lands in keeps the default.
     - `devices check-config` holds the device to the same values.
   - **Why:** on a session-only device this timer is the only thing that ends a session (decision 21). A shared class set from the default lets a 1h role idle for 12h, and taking the least across the class is decision 33's "the option that denies more".
   - **Alternative:** keep the default for every class, and have `explain` say so. Task 2 then shrinks to the `never` case alone.
2. **The restore guard's ERROR on IOS XE** (a 7f follow-up, still unassigned; it is a §12 failure-matrix row).
   - After an etcd restore, port49d refuses token logins until a runner's purge. Its refusal is an `ERROR`, which IOS XE treats as final. Junos under the reference `tacplus`-only order does the same (ruling 2). SR Linux may too (L87). On those devices break-glass is refused until the brokers start and purge.
   - **Recommended:** keep the ERROR. Alarm on `port49_redemption_restore_guarded` (Task 5), and put the warning in the 3am table of `deploy/failure-matrix.md` (Task 9).
   - **Why:** closing the listener for the guard would hand every open session's commands to local authorization for the whole purge, which is a wider exposure than a break-glass delay that ends when the brokers start.
   - **Alternative:** close the listener while guarded, as go-dark does. That is a code change for a later plan, not this one.

## Rulings this plan is written under

Ryan's standing rulings: deployment is not prescriptive (systemd, container and Kubernetes are peers); no deprecation shims before beta; no operator toil at fleet scale; security first; follow the spec; smokes run in CI only (2026-10-30); every admin call goes over the broker API with a key press (decision 54 ruling 15).

This plan's rulings, made from the spec. Task 1 writes them into the spec as decision 55.

1. **The Junos and NX-OS "ERROR disagreement" is two method lists and two questions, not a contradiction.**
   - On **Junos**, `tests/lab/results/L73-juniper_vjunos-router.md` cell (i) ran `authentication-order [ tacplus password ]`, which falls through on ERROR, and on FAIL too (L4). `L4-error-juniper_*.md` ran `tacplus` alone, where ERROR is final.
   - On **NX-OS**, `L73-cisco_nxos.md` cell (i) recorded the break-glass *login* (`aaa authentication login default group port49 local`) landing in 5.2 s. `L4-error-cisco_nxos.md` and design §12 record that the commands that follow are refused by port49's authorization `FAIL store_unavailable`.
   - Both readings stand. Task 1 adds one sentence to design §12 saying so, citing all four notes. L88's cell (c) measures login and a command under the reference method list on every platform.
2. **Junos's reference order is `authentication-order tacplus`.**
   - With `password` listed, a port49 FAIL falls through to the local password (L4), which voids spec §5.6's security argument.
   - With `tacplus` alone, an ERROR is final until go-dark closes the listener (≤ 5.5 s at the defaults, L41). After that the server is unreachable, and break-glass logs in under either order (L4, L17).
   - The reference ships `tacplus` alone, and its README carries the 5.5 s window.
3. **SR Linux ships `exit-on-reject true`.** Without it, a port49 deny falls through to `local` (L76 cell d, measured 1.2 s), which voids §5.6's argument. L87 measures what an ERROR does under it. Its result decides the 3am line (the break-glass account waits for go-dark, or it does not), not whether the setting ships. The reference keeps `priv-lvl-authorization true` and `services [ cli ]` on every mapped role (L76).
4. **The `key_ref` label never names one device** (plan 1 carry; design §15: "device identity does not belong in metric labels").
   - A `key_ref` that admits exactly one device in the snapshot in force (a tier-1 pin, or a key group of one) is a device identity, so it is reported under `key_ref="single_device"` with `version="any"`:
     - `port49_key_validations_total` counts that device's trials there;
     - `port49_key_version_devices{key_ref="single_device",version="any"}` is the number of such devices on a version that has a `retire_after`;
     - `port49_key_retirement_seconds{key_ref="single_device",version="any"}` is the least time to retirement among those versions still presented by a device.
   - Which device is on which version is `port49 keys status`'s answer, from the log, as design §15 says per-device questions are.
   - A `key_ref` held by two or more devices keeps its own label.
5. **The chart offers no host networking.** Pod Security `baseline`, which the chart's namespace runs at (decision 54), refuses `hostNetwork`. L39 (c) is still measured, on a lab-only `privileged` namespace. Its result goes in the note and the chart README, and the chart keeps `externalTrafficPolicy: Local`.
6. **One alert file for every shape.** `deploy/alerts/port49.rules.yaml` is canonical. The chart's `files/port49.rules.yaml` is a byte-identical copy, rendered as a `PrometheusRule` only when `prometheusRule.enabled` (default false, since it needs the operator's CRD).
   - Alert names and label keys are snake_case.
   - `severity` is `page` or `ticket`.
   - No rule groups or filters by a device-identifying label.
   - The `etcd` group names etcd's own metrics, and only those are exempt from the registered-metric check.
7. **Defaults sized from load are ruled in advance.** Task 7 measures, and the gates below decide. A number that misses a design §5 target stops the plan, and the lead adds a task, as 12b did. A target is never relaxed to fit.
   - **TLS session tickets** stay off (`session_ticket_lifetime: 0s`) if the full-handshake run meets the per-command p99 < 5 ms target at 170 logins/s. If it does not, the lead rules before any default changes.
   - **Accounting group commit** (plan 1 carry) is built by Task 8 if Task 7's spool capacity is less than twice the sustained accounting rate at target. Otherwise Task 8 records the numbers and the `Offer` path stays as it is.
   - **`limits.max_connections`'s sizing** (12a) stands if the target run's peak `port49_connections` is under a quarter of the cap sized from `LimitNOFILE=65536` (12b's units). Otherwise the units' `LimitNOFILE=` rises.
   - **The chart's `autoscaling.averageConnections`** becomes half the peak `port49_connections` per replica measured at target, rounded to the nearest 50.
   - **`stores.session.etcd.call_timeout` (500 ms), `bulk_timeout` (30 s) and `packet_deadline` (2 s)** stand if the store call p99 at target is under a fifth of `call_timeout`. **`stores.directory.etcd.call_timeout`'s guidance** is at least four times the measured cross-region round trip, written in `deploy/examples/stores/multi-region/README.md`.
8. **A key version retired under an open connection, per platform** (2026-10-26 addition).
   - L29 measured the device's side of the reset a reload sends on vEOS, the N9Kv, the C8000V and vJunos-router. 12a made a retiring reload send that same reset with no strike, so for those four L29 is the answer, and the reference README cites it.
   - L88 cell (g) measures it on the platforms L29 did not cover: XRd, SR Linux, and the RFC 9887 listener on each TLS image.
9. **Oxidized host keys** (plan 9d carry).
   - `examples/oxidized/config` sets `secure: true` and tells the operator to populate `known_hosts` once per device, which is toil at fleet scale.
   - L90 measures two things: whether Oxidized can do accept-new itself (cell d), and whether it reads an entry OpenSSH's accept-new wrote under the address it dials (cell c).
   - If (d) passes, the example uses that setting.
   - Else, if (c) passes, `port49-oxidized-run` pre-populates each node absent from `known_hosts` with `ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes <address> exit`. The host key is saved at key exchange, before authentication, so no credential is sent.
   - Else the README says why neither works, and the per-device step stays as a measured limitation of Oxidized.
   - `secure: false` is never offered.
10. **Velero** is named in the chart README only if L89 passes. The example uses file-system backup (the node agent), because kind has no snapshot-capable CSI driver. CSI snapshots stay unmeasured and unnamed.
11. **The failure matrix runs on the compose stack with mock devices.** A §12 row the stack cannot reach is not re-measured. The matrix cites its closed lab rows instead:
    - directory unavailable: L42, L43, L67;
    - identity provider: L45, L46;
    - a cut region: L74;
    - device fall-through: L4, L28, L29, L35, L41.
12. **L84 closes in CI.** The systemd cells (`make lab-l84-systemd`) run on a GitHub-hosted runner in a new label-gated `lab-hosted` workflow. Then `make lab-l84 A_CELLS=` merges them with the Compose half on the same runner.
13. **The enrollments export CronJob** (12b hand-off) runs in a kind test with an OpenLDAP container and a username-free policy (`tests/kind/enrollments_test.go`, `make kind-enrollments`). It is a test of port49's own artifact, not a lab row.

## Global Constraints

- **Toolchain.** Go 1.26+, module `github.com/rhwendt/port49`. Code is `gofmt` and `go vet` clean, with no cgo and no new module. Linux-only test code goes in `_linux.go` files or behind a build tag.
- **snake_case** for every data key, metric, label, alert name and alert label: `key_ref="single_device"`, `version="any"`, `severity`, `prometheusRule` (a Helm value: chart interface, camelCase as 12b ruled).
- **Reason codes** come only from spec §5.7, and **warnings** only from spec §12. This plan adds neither. A CLI line that is not a warning (the export's header comment) is not a §12 warning.
- **Metrics:** no device identity in any label (ruling 4). No rule groups `by` a device, name, address or principal.
- **Security in every log, note, test message and artifact:**
  - no secret, token, password, challenge, nonce or signature;
  - credentials appear only as `credential_sha256`;
  - no TACACS+ body is decoded, by a harness or by an agent;
  - a failure dump goes through `tests/qual/secret-filter.sh`;
  - a test that asserts a secret is absent checks before printing.
- **Files never read** by an agent or a harness log: `realm.json`, `*.env`, `*-key.pem`, `*.keytab`, `router.db`, `/tmp/port49-lab-tokens.jsonl` and `tests/lab/logs/**`. Every recursive grep excludes them.
- **Hardware.** Agents never touch a real YubiKey or TPM, and never run `ykman`, `tpm2_*` or `pkcs11-tool`. Every harness that writes a client config pins `issued_key_store: file`.
- **Lab tasks** (11, 12, 13, 14, 15, 16, and Task 7's run):
  - Single occupant: take `/tmp/port49-lab.lock` (`labOccupyForRun`). A kind or CI cell runs on a hosted runner instead.
  - Run a background stall watchdog for the whole run, re-armed on wake. An idle "waiting" notice proves nothing.
  - Run `make lab-unit` before and after.
  - Never `-tags lab` with an unanchored `-run`: every target is `-run '^TestX$'`.
  - On etcd use `PORT49_LAB_ETCD_BIN=/mnt/images/etcd-v3.6.15`.
  - Close a row by CLAUDE.md's rule: a results note under `tests/lab/results/`, the §15 Status edited, and a `docs: close lab register entries ...` commit.
  - A cell that cannot be measured is NOT RUN and fails the run. A FAIL is a measured answer.
  - Before calling a device behavior a platform limitation, collect the device's own debug (`traceoptions`, `debug aaa`).
- **Measure first.** No README, reference file or doc asserts a device or third-party behavior beyond its closed lab row. Where a row is open, the text says "unmeasured (L<N>)".
- **Pins.** Every downloaded tool is pinned by version and sha256 in the Makefile, every Action by commit SHA, every image by tag.
- **Commits.**
  - Conventional Commits, one per step that says "Commit".
  - Each message ends with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, naming the implementing model.
  - No `Claude-Session:` line and no claude.ai link.
- **Verification.** Before each commit run `make test && make vet`, `make leaks`, and each task's own target, and report the real output.

## Review Focus

1. **A reference configuration that falls through on a port49 deny.** This is the hole design §12 exists to close: Junos with `password` listed, SR Linux without `exit-on-reject`, an IOS XE list that ends `none`. *Pinned:*
   - Task 10's `TestNoReferenceFallsThroughOnAReject` refuses each such shape statically;
   - L88 cell (a) logs in a user who has a local account with the same password, and asserts the refusal on every platform.
2. **An alert on a metric nobody registers, or one that never fires.** A renamed metric silently disarms a page. *Pinned:*
   - Task 5's `TestEveryAlertNamesARegisteredMetric`;
   - `promtool test rules`, with one firing case and one quiet case per alert.
3. **A per-device pin turns the key metrics into ten thousand series.** *Pinned:* Task 4's `TestASingleDeviceKeyRefIsNotALabel`, and `TestTwoDevicesKeepTheirKeyRef` beside it.
4. **A load number that only passes because the run was short or closed-loop.** A closed loop slows its own arrivals when port49 slows, and hides the queue. *Pinned:*
   - Task 6's `TestRateModeIsOpenLoop` asserts plays start on schedule while earlier plays are still stalled;
   - Task 7's run is 10 minutes at 170 logins/s, and `TestLoad` refuses a run shorter than that.
5. **A Junos class that idles longer than a role allows**, or a `never` that renders as `idle-timeout 0`. *Pinned:* Task 2's `TestAClassTakesTheLeastCeilingLandingInIt` and `TestANeverClassWritesNoIdleTimeout`, and the check-config twin `TestCheckConfigHoldsTheSameClassAges`.

---

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md` | decision 55; rows L87–L90; L39's cells; design §12's reconciliation sentence | 1 |
| `internal/platform/classes.go`, `internal/policy/classages.go`, `cmd/port49/platform.go`, `cmd/port49/devices.go` | the class `idle-timeout` per class | 2 |
| `internal/policy/diff.go`, `cmd/port49/policy.go` | `policy diff` reports a changed session ceiling | 3 |
| `internal/daemon/metrics/metrics.go`, `internal/daemon/server/conn.go`, `internal/port49d/main.go`, `internal/port49d/reload.go` | the `key_ref` label bounded | 4 |
| `deploy/alerts/`, `deploy/helm/port49/files/port49.rules.yaml`, `deploy/helm/port49/templates/prometheusrule.yaml`, `tests/alerts/`, `Makefile`, `.github/workflows/test.yml` | alert rules and their checks | 5 |
| `internal/devicemock/fleet.go`, `tests/lab/load.go`, `tests/lab/load_test.go`, `tests/lab/load_unit_test.go`, `internal/policy/fleet_bench_test.go` | the load harness | 6 |
| `tests/lab/results/load-<host>.md`, the defaults ruling 7 names | the load run and its sizing | 7 |
| `internal/daemon/acct/spool.go` | group commit, gated on Task 7 | 8 |
| `tests/compose/failmatrix_test.go`, `deploy/failure-matrix.md`, `Makefile`, `.github/workflows/compose.yml` | the failure matrix | 9 |
| `deploy/device-aaa/`, `tests/deviceaaa/` | the reference configurations | 10 |
| `tests/lab/l87_test.go`, `tests/lab/results/L87-nokia_srlinux.md` | lab row L87 | 11 |
| `tests/lab/l88.go`, `tests/lab/l88_test.go`, `tests/lab/l88_unit_test.go`, `tests/lab/results/L88-*.md` | lab row L88 | 12 |
| `tests/lab/l39_test.go`, `tests/shapes/l39/`, `.github/workflows/lab-kind.yml`, `tests/lab/results/L39-kind.md` | lab row L39 (b), (c) | 13 |
| `.github/workflows/lab-hosted.yml`, `tests/lab/results/L84-systemd-docker.md` | lab row L84's systemd cells | 14 |
| `tests/lab/l89_test.go`, `tests/shapes/l89/`, `deploy/helm/port49/examples/velero/`, `tests/lab/results/L89-kind.md` | lab row L89 | 15 |
| `tests/lab/l49_test.go`, `examples/oxidized/`, `tests/lab/results/L90-oxidized-arista_eos.md` | lab row L90 | 16 |
| `tests/kind/enrollments_test.go`, `Makefile`, `.github/workflows/kind.yml` | the enrollments CronJob run | 17 |
| `docs/superpowers/plans/README.md` | As built, operator notes, hand-offs | 18 |

Order: 1, then 2–6 in any order, then 7, 8, 9, 10. Next 11 must land before 12, because L87 decides SR Linux's 3am line. Then 13–17 in any order, and 18 last.

---

### Task 1: Spec: decision 55, rows L87–L90, L39's cells and the ERROR reconciliation

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §13, after decision 54 and before `## 14. Required test assertions`;
  - §15: row L39's claim, and new rows after L86.
- Modify: `docs/design/2026-08-21-port49-design.md` §12, the paragraph "Device-side AAA configuration is part of the failure model".

- [ ] **Step 1: Write decision 55, "Reference device configuration, alarms, load and the failure matrix (plan 12c)".**

  - Rulings 1–13 as this plan states them, one paragraph each. Rulings 14 and 15 are Decisions for Ryan 1 (the class `idle-timeout`) and 2 (the restore guard's ERROR), as Ryan rules them. Until he does, each is written with the recommendation and marked provisional.
  - Its "Open" line names rows L87–L90 and L39, provisional until they close.
  - Decision 21 gains one sentence: "As built (plan 12c): the export renders each class's `idle-timeout` from the least ceiling among the sessions the policy lands in it (decision 55 ruling 14)."

- [ ] **Step 2: In design §12, after "…against that, not against "ERROR falls through".", add the reconciliation sentence.**

  > Two readings that look like a disagreement are not one: over TLS (`tests/lab/results/L73-juniper_vjunos-router.md`, cell i) Junos ran `authentication-order [ tacplus password ]`, which falls through on an ERROR and on a FAIL (L4), while `L4-error-juniper_*.md` ran `tacplus` alone, where an ERROR is final; and NX-OS's break-glass *login* landed under ERROR in 5.2 s (`L73-cisco_nxos.md`, cell i) while its commands are then refused by port49's authorization `FAIL store_unavailable` (`L4-error-cisco_nxos.md`). The reference configuration (decision 55) uses `tacplus` alone on Junos, and L88 measures login and a command under it on every platform.

- [ ] **Step 3: Give L39's (b) and (c) their cells, in the claim column, after "(c) Kubernetes with host networking.".**

  > Cells, on kind, the device a container on the kind network outside every node, port49d one replica: (b1) a NodePort Service with `externalTrafficPolicy: Cluster`, dialled at the node running the pod; (b2) the same, at a node not running it; (b3) `Local`, at the node running it; (b4) `Local`, at a node not running it (what the device sees: an observation); (c) port49d with `hostNetwork: true` on a lab-only `privileged` namespace, dialled at its node. PASS for (b1)–(b3) and (c) iff the device-binding check passes (`token_redeemed`); a FAIL is the measured answer. A LoadBalancer under `Local` is L85 (a) (closed, PASS).

- [ ] **Step 4: Add rows L87–L90 to §15, each with Status `open`.**

  | ID | Claim to measure | What rests on it | Platforms |
  |---|---|---|---|
  | **L87** | SR Linux with `exit-on-reject true` when port49 is up and answers ERROR (`store_unavailable`, the lab fault switch), and once port49d has closed its listener on etcd (go-dark). (a) The break-glass account (local only) logs in, or not, and how fast, with authentication answered ERROR; and a port49 user's token login. (b) The same with port49d dark: break-glass logs in, and its time. (c) An ERROR to the session authorization of a login port49 authenticated: whether the login completes, and the roles it gets. | Decision 55 ruling 3: the reference configuration's 3am line for SR Linux (break-glass waits for go-dark, or it does not) | SR Linux 26.7.2 (`ghcr.io/nokia/srlinux:26.7.2-519`) |
  | **L88** | Each platform under port49's reference AAA configuration (`deploy/device-aaa/`), loaded as shipped. (a) A user port49 denies who has a local account with the same password: PASS iff refused, with no fall-through. (b) port49d stopped: PASS iff break-glass logs in within the platform's L13 timeout + 5 s (recorded). (c) port49 answering ERROR: break-glass login and one command, recorded. (d) port49d dark (listener closed by its health checks, on etcd): PASS iff break-glass logs in and runs a command. (e) A token login, one permitted and one denied command: PASS iff the permit runs, the deny is refused, and accounting START and STOP arrive. (f) The first server refusing (reset at Accept), the second answering: PASS iff a token login succeeds through the second (time recorded). (g) A reload retiring the open connection's key version, single-connection on: what the in-flight and the next command do (observation; L29's question for the platforms L29 did not measure). (h) For each TLS image, (a)–(g) over RFC 9887 under the TLS reference. (i) Junos only: the largest `idle-timeout` the commit accepts, by bisection. | Design §12 "port49 MUST ship tested reference AAA configuration per platform"; design §14's device fallback assertion; decision 55 rulings 1, 2, 3, 8 and 14 | vEOS 4.31.2F, cEOS 4.36.3M (TLS), C8000V 17.13.01a and 17.18.02 (TLS), N9Kv 10.4(2)F and 10.6(2)F (TLS), vJunos-router 23.4R2-S2.1 and 26.2R1.7 (TLS), vSRX 21.4R3.15, XRd 26.1.1 (both), SR Linux 26.7.2 |
  | **L89** | Velero file-system backup (node agent) of a chart release's PVCs, on kind with MinIO. (a) Back up both StatefulSets, delete the namespace, and restore: the owner, group and mode of `state/`, `issuing-ca.key` and the spool directory. PASS iff both StatefulSets become ready with no fence refusal and the broker prints the CA fingerprint it printed before. (b) After the restore, a mint and a login. PASS iff both succeed. | Whether the chart README may name Velero (decision 55 ruling 10; 12b pre-flight M10) | kind; Velero, node agent and MinIO versions recorded |
  | **L90** | Oxidized's SSH host-key handling against accept-new, on one EOS device. (a) `secure: true` with no `known_hosts` entry: what Oxidized does. (b) `secure: true` with a changed key: PASS iff refused. (c) `secure: true` after `ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes <address> exit` wrote the entry: PASS iff the backup runs. (d) Any Oxidized input or `vars` setting that maps to net-ssh's `verify_host_key: :accept_new`: PASS iff an unknown key is saved and a changed key refused. | `examples/oxidized` (decision 55 ruling 9; plan 9d carry) | Oxidized (version recorded), vEOS 4.31.2F |

- [ ] **Step 5: Check and commit.**

  - Run `make test && make vet` and `make lab-unit`. Expected: PASS. `notediff` reads §15.
  - Commit:

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: decision 55, lab rows L87-L90, L39's cells and the ERROR readings reconciled"
  ```

---

### Task 2: The Junos `idle-timeout` per class (Decision for Ryan 1)

**Files:**
- Modify: `internal/platform/classes.go` (`ReferenceClasses`, `templates`, `template.lines`, `TemplateDrift`)
- Create: `internal/policy/classages.go`
- Modify: `cmd/port49/platform.go` (`exportClasses`), `cmd/port49/devices.go` (`templateCheck`)
- Test: `internal/platform/classes_test.go`, `internal/policy/classages_test.go`, `cmd/port49/platform_test.go`, `cmd/port49/devices_test.go`

**Interfaces:**
- Consumes:
  - `(*policy.Policy).resolve(sub *Subject, d admission.Device, now time.Time) (Resolution, error)`;
  - `Resolution.SessionAge.Of(def time.Duration) time.Duration` (zero is `never`);
  - `Resolution.Projection.Template` (empty: the `remote` template);
  - `(*Policy).Devices() []admission.Device`;
  - `p.subs`;
  - `platform.RemoteClass`.
- Produces:
  - `type ClassAges struct { Default time.Duration; ByClass map[string]time.Duration }` in `internal/platform`. A zero in `ByClass` means no `idle-timeout` line, and a class absent from `ByClass` takes `Default`.
  - `func ReferenceClasses(d Dialect, ages ClassAges) ([]string, error)`.
  - `func TemplateDrift(config []byte, d Dialect, ages ClassAges) (missing []string, extra []ConfigFinding, err error)`.
  - `func (p *Policy) ClassAges(platformName string, def time.Duration, now time.Time) (platform.ClassAges, error)`.

- [ ] **Step 1: Write the failing tests.**

  - `internal/policy/classages_test.go`. The policy has two Junos devices, role `ops` (`max_session_age: 1h`, level `operator`), role `view` (unset, level `readonly`) and role `forever` (`never`, level `admin`), each granted to its own subject.
    - `TestAClassTakesTheLeastCeilingLandingInIt`: `ClassAges("juniper_junos", 12*time.Hour, now)` gives `ByClass["p49-operator"] == time.Hour` and `ByClass["p49-readonly"] == 12*time.Hour`.
    - `TestANeverClassWritesNoIdleTimeout`: `ByClass["p49-admin"] == 0`, and `ReferenceClasses` writes no `idle-timeout` line for `p49-admin`.
    - `TestASharedClassTakesTheLeast`: a second subject lands in `p49-operator` under a role with `max_session_age: 30m`, and the class becomes `30m`.
    - `TestAClassNoSessionLandsInKeepsTheDefault`: `p49-remote` is absent from `ByClass`, and its line reads `idle-timeout 720`.
  - `internal/platform/classes_test.go`: the existing tests move to `ClassAges{Default: d}`, unchanged in what they assert.
  - `cmd/port49/devices_test.go`, `TestCheckConfigHoldsTheSameClassAges`: a capture carrying the export's lines passes `check-config`. The same capture with `p49-operator idle-timeout 720` reports `set system login class p49-operator idle-timeout 60` missing.
  - `cmd/port49/platform_test.go`, `TestExportSaysEachClassAge`: the header line names each class and its age, for example `p49-operator 1h0m0s (least ceiling landing in it)`, and `never` for a never class.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/ -run 'ClassAge|NeverClass|SharedClass|NoSessionLands|CheckConfigHolds|ExportSays' -count=1`. Expected: FAIL to compile (`ClassAges` undefined).

- [ ] **Step 3: Implement.**

  - `ClassAges`: for each subject in `p.subs` and each device of `platformName` in `p.Devices()`, `resolve` it, skipping `ErrNoGrants`. Any other error is returned, naming the subject and the device.
  - The class is `res.Projection.Template`, or `platform.RemoteClass` when that is empty.
  - The age is `res.SessionAge.Of(def)`. Per class keep the least positive age. A class becomes 0 only when every session in it is 0.
  - `template.lines` writes `idle-timeout` only when the age is non-zero, in whole minutes rounded down and at least one, as today.
  - `exportClasses` and `templateCheck` both call `p.ClassAges(platformName, age, time.Now())` with `config.MaxSessionAge(raw)` as `def`. Without `--policy` (the built-in set) they pass `ClassAges{Default: age}`.
  - The header sentence names each class's age in place of the single default.

- [ ] **Step 4: Run the tests and see them pass.**

  - Run the Step 2 command. Expected: PASS.
  - Run `make test && make vet`. Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/platform/classes.go internal/platform/classes_test.go internal/policy/classages.go internal/policy/classages_test.go cmd/port49/platform.go cmd/port49/devices.go cmd/port49/platform_test.go cmd/port49/devices_test.go
  git commit -m "feat: the Junos reference classes take the least session ceiling landing in each"
  ```

  If Ryan rules the alternative, this task keeps `ClassAges{Default: age}` everywhere, keeps only `TestANeverClassWritesNoIdleTimeout` (a policy whose every role is `never` writes no line), and `explain` says the class timer is the default.

---

### Task 3: `policy diff` reports a changed session ceiling

**Files:**
- Modify: `internal/policy/diff.go` (`Diff`, `side`, `(*Policy).side`, `comparison.group`), `cmd/port49/policy.go` (the diff printer)
- Test: `internal/policy/diff_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Produces:
  - `type SessionCeilingChange struct { Subject string; Devices []string; At time.Time; Old, New string; Lengthened bool }`, where `Old` and `New` are `SessionAge.String()` (Step 3);
  - field `Diff.SessionCeilings []SessionCeilingChange`.

- [ ] **Step 1: Write the failing tests.**

  - `TestADiffReportsAShortenedCeiling`: role `ops` goes from `max_session_age: 8h` to `1h`. One change `{Old:"8h0m0s", New:"1h0m0s", Lengthened:false}` for the subject, on its devices.
  - `TestADiffReportsALengthenedCeiling`: from `1h` to `never`. `Lengthened` is true.
  - `TestAnUnchangedCeilingIsNotReported`: a deny added and nothing else. `SessionCeilings` is empty.
  - `TestACeilingChangeIsNotAGate`: `Unacknowledged()` is unchanged by a ceiling change. Spec §12's gate is privilege, access and regex, and a ceiling is none of them.
  - `cmd/port49/policy_test.go`, `TestDiffPrintsTheCeilingLine`: the output carries `session ceiling: <subject> on <n> devices: 8h0m0s -> 1h0m0s`. A lengthening adds `(lengthened: live sessions keep the shorter ceiling until they refresh, decision 33)`.

- [ ] **Step 2: Run them and see them fail.**

  `go test ./internal/policy/ ./cmd/port49/ -run 'Ceiling' -count=1`. Expected: FAIL to compile.

- [ ] **Step 3: Implement.**

  - `side` gains `age SessionAge`, set in `(*Policy).side` from the resolution. The diff loads no port49d.yaml, so it compares the roles' own values and never a default.
  - Add `func (a SessionAge) String() string` in `internal/policy/resolve.go`. It returns `never`, a duration's `String()`, `default` (every role names none), or `<duration> or the default, whichever is less`. `Old` and `New` are that string.
  - `Lengthened` is true when `New` is `never` and `Old` is not, or when both have a `Least` and the new one is larger.
  - The group key includes `age.String()`. `group` appends a `SessionCeilingChange` when `was.age != is.age`, deduplicated through `c.once("ceiling", …)`.

- [ ] **Step 4: Run the tests and see them pass.** Then run `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/policy/diff.go internal/policy/diff_test.go cmd/port49/policy.go cmd/port49/policy_test.go
  git commit -m "feat: policy diff reports a changed session ceiling"
  ```

---

### Task 4: The `key_ref` label never names one device (ruling 4)

**Files:**
- Modify: `internal/daemon/metrics/metrics.go` (`keyCollector`, `KeySample`, new label helpers), `internal/daemon/server/conn.go` (the four `KeyValidations.WithLabelValues` calls, lines ~508–555), `internal/port49d/main.go` (`WatchKeys`, ~line 1292), `internal/port49d/reload.go` (`swap`)
- Test: `internal/daemon/metrics/metrics_test.go`, `internal/port49d/keymetrics_test.go`

**Interfaces:**
- Consumes:
  - `(*policy.Policy).Devices()`;
  - `(*policy.Policy).Admitted(name string) (admission.Resolved, bool)`;
  - `admission.Resolved.KeyRef`.
- Produces:
  - `const SingleDeviceKeyRef = "single_device"` and `const AnyVersion = "any"`;
  - `func (m *Metrics) SetSingleDeviceKeyRefs(refs map[string]bool)`, stored atomically;
  - `func (m *Metrics) KeyLabels(ref string, version int) (keyRef, ver string)`;
  - `func singleDeviceKeyRefs(p *policy.Policy) map[string]bool` in `internal/port49d`.

- [ ] **Step 1: Write the failing tests.**

  - `TestASingleDeviceKeyRefIsNotALabel` (metrics). `SetSingleDeviceKeyRefs({"r1-pin": true})`. Then `KeyLabels("r1-pin", 3)` is `("single_device", "any")`, and the key collector's output has no series labelled `r1-pin`.
  - `TestTwoDevicesKeepTheirKeyRef`: `KeyLabels("core", 2)` is `("core", "2")`.
  - `TestTheSingleDeviceRetirementIsTheLeastPresented`. Samples: pin A v1 with retire in 10 days and 1 device; pin B v1 with retire in 1 day and 0 devices; pin C v2 with no retire and 1 device. The result is `port49_key_version_devices{key_ref="single_device",version="any"} == 1` and `port49_key_retirement_seconds{…} ≈ 10 days`. B is not presented, so it does not count.
  - `internal/port49d/keymetrics_test.go`, `TestAPinnedDeviceIsReportedAsSingleDevice`: a policy pinning one device to its own key and two devices to `core`. After start, a login from the pinned device raises `port49_key_validations_total{key_ref="single_device",version="any",outcome="validated"}`, and no exposition line contains the pin's name. Check that before printing.

- [ ] **Step 2: Run them and see them fail.**

  `go test ./internal/daemon/metrics/ ./internal/port49d/ -run 'SingleDevice|TwoDevicesKeep|LeastPresented|PinnedDevice' -count=1`. Expected: FAIL to compile.

- [ ] **Step 3: Implement.**

  - `KeyLabels` maps through the stored set.
  - `keyCollector.Collect` aggregates the single-device samples into one `devices` series (the sum of devices on versions with a non-zero `RetireAt`). Its `retires` series is the least `RetireAt` among those with `Devices > 0`, and is omitted when there are none.
  - `conn.go` calls `s.d.Metrics.KeyLabels(s.dev.KeyRef, version)` in place of the raw pair.
  - `main.go` sets the set at start from the policy in force. `reloader.swap` sets it after each swap.
  - Without a policy (an inventory key group only), use the admission index's devices the same way.

- [ ] **Step 4: Run the tests and see them pass.** Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go internal/daemon/server/conn.go internal/port49d/main.go internal/port49d/reload.go internal/port49d/keymetrics_test.go
  git commit -m "fix: a key_ref held by one device is reported as single_device, never as a label naming it"
  ```

---

### Task 5: Alert rules, one per stated alarm

**Files:**
- Create:
  - `deploy/alerts/port49.rules.yaml`;
  - `deploy/alerts/port49.rules.test.yaml` (promtool unit tests);
  - `deploy/alerts/README.md`;
  - `deploy/helm/port49/files/port49.rules.yaml`;
  - `deploy/helm/port49/templates/prometheusrule.yaml`;
  - `tests/alerts/alerts_test.go`, `tests/alerts/registered.go`.
- Modify:
  - `deploy/helm/port49/values.yaml` and `values.schema.json` (`prometheusRule: {enabled: false, labels: {}}`);
  - `tests/helm/static_test.go`;
  - `Makefile` (`PROMTOOL_VERSION ?= 3.5.0`, its sha256 from the release's `sha256sums.txt`, `bin/promtool-$(PROMTOOL_VERSION)`, `alerts-check`);
  - `.github/workflows/test.yml` (a job running `make alerts-check`).

**Interfaces:**
- Consumes:
  - `metrics.New(prometheus.Registerer) *Metrics` (`internal/daemon/metrics`);
  - `inventory.NewMetrics(prometheus.Registerer) *Metrics` (`internal/inventory/metrics.go`).
- Produces:
  - `func RegisteredNames() ([]string, error)` in `tests/alerts`. It runs both constructors against a recording `prometheus.Registerer` that collects every `Desc`'s fully-qualified name from `Describe`, so a vector with no child still counts.

- [ ] **Step 1: Walk both documents for every MUST-alarm statement.**

  - Grep `docs/design/2026-08-21-port49-design.md`, `docs/design/2026-08-23-policy-engine-spec.md` and `docs/superpowers/plans/README.md` for `alarm`, `alert on`, `page` and `MUST alarm`. Every recursive grep excludes the never-read files.
  - Write `deploy/alerts/README.md`'s table: statement (document, section and a short quote) | alert name | severity | `for:` | why this threshold.
  - The table must hold at least these:
    - the global cap: `increase(port49_connections_shed_total{reason="global_cap"}[5m]) > 0` (page), and `port49_connections / port49_connections_max > 0.8` for 10m (ticket) (12a hand-off);
    - `port49_key_secret_files_changed > 0` for 10m (ticket; 12b);
    - `port49_issuing_ca_not_after_timestamp_seconds{port49_issuance="enabled"} == 0` for 5m (page), and `… - time() < 90 * 86400` (ticket) (12b; the metric's help text). A broker without issuance also reads 0, so the rule selects on a target label. The README tells the operator to set `port49_issuance: enabled` on the scrape targets of brokers that set `broker.identity.issuance`, and the chart's `PrometheusRule` notes it beside the rule;
    - `increase(port49_admin_touch_total{outcome="refused"}[10m]) > 0` (page; 12b);
    - `port49_policy_fail_closed_compositions > 0` (ticket; 11b);
    - the stores (11a): `port49_store_directory_reachable == 0` for 1m; `time() - port49_store_directory_confirmed_timestamp_seconds > 60`; `port49_store_logouts_pending > 0` for 5m; `port49_store_feed_up{feed="marks"} == 0`;
    - design §15's store list, item by item: circuit open; reindexed; reindex failures; `calls_total{outcome="refused"}`; keyspace held summed 0 for 2×`hold_ttl`; client certificate within 30 days; `crypt_store_key_unknown`; `crypt_open_failures_total{record="token"}`; `feed_up` 0 past `hold_ttl`; feed rescans; ledger; bundle match; mint gate; restore guard; `store_health_failures >= close_after` (page); the health-check fail ticket; context cache stale;
    - TLS (plan 11): handshakes by outcome; device and server lifetime ratio `< 0.33`; server `< 0` (page); `cert_status_unavailable_total{component="tls_listener"}`; CRL next update; `inventory_changes_total{kind="transport_changed"}`;
    - OIDC: keys age `> jwks_max_age/2 or absent()`; logouts `store_error|partial`; tokens `unavailable`;
    - workload certificates renewal late; the directory's refresh age, ambiguous lookups, `server_up == 0` and `group_names_ambiguous > 0`; `port49_policy_file_refused == 1`; `port49_policy_refresh_pending == 1` for 2m; the accounting spool's drops; `port49_decision_log_write_failures_total` increase; `port49_directory_enrollment_store_ok == 0 or absent()`; inventory sync failing, bundle refused, mirror behind and persist failed; a key version with devices within 7 days of `retire_after` (ticket) and within 1 day (page);
    - the `etcd` group: `etcd_server_has_leader == 0` (page); `etcd_mvcc_db_total_size_in_bytes / etcd_server_quota_backend_bytes > 0.8` (ticket); `increase(etcd_server_leader_changes_seen_total[1h]) > 3` (ticket).
  - Below the table the README states:
    - the `component` label rule (`sum by` or `ignoring(component)`);
    - that a dark etcd member costs up to 12 s (gRPC raises a keepalive below 10 s to 10 s, plus a 2 s timeout). Reads and the opted-in mark writes are hedged, other writes are not, so no alert can fire faster than that;
    - that `close_after` × `interval` is shorter than any scrape, so nothing warns before the listener closes.

- [ ] **Step 2: Write the failing tests in `tests/alerts/alerts_test.go`.**

  - `TestEveryAlertNamesARegisteredMetric`: every `port49_[a-z0-9_]+` token in every `expr` is in `RegisteredNames()`, after stripping `_bucket`, `_sum` and `_count`. Only the `etcd` group's `etcd_` names are exempt.
  - `TestEveryAlertIsSnakeCaseAndHasASeverity`: `alert` names match `^port49_[a-z0-9_]+$` or `^etcd_[a-z0-9_]+$`. `labels.severity` is `page` or `ticket`. `annotations.summary` is non-empty and holds no `{{ $labels.` reference to a device label.
  - `TestNoAlertAggregatesByADeviceLabel`: no `by (…)`, `without (…)` or matcher names `device`, `nas`, `name`, `address`, `source`, `principal`, `subject` or `username`.
  - `TestEveryReadmeRowHasARuleAndEveryRuleARow`: the two name sets are equal.
  - `TestTheChartCarriesTheSameRules`: `deploy/helm/port49/files/port49.rules.yaml` is byte-equal to `deploy/alerts/port49.rules.yaml`.
  - `tests/helm/static_test.go`, `TestPrometheusRuleIsOffByDefault`: no `PrometheusRule` renders by default. With `prometheusRule.enabled: true` one renders, holding the file's groups.

- [ ] **Step 3: Run them and see them fail.**

  `go test ./tests/alerts/ -count=1`. Expected: FAIL (no rules file).

- [ ] **Step 4: Write the rules, the promtool tests, the chart copy and template, and the make target.**

  - Every alert has a promtool test case where it fires and one where it stays quiet, on synthetic series.
  - `make alerts-check` runs `bin/promtool-$(PROMTOOL_VERSION) check rules deploy/alerts/port49.rules.yaml`, then `test rules deploy/alerts/port49.rules.test.yaml`.

- [ ] **Step 5: Run the checks and see them pass.**

  - Run `go test ./tests/alerts/ -count=1`, `make alerts-check`, `make helm-test`, and `make test && make vet`. Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  git add deploy/alerts deploy/helm/port49/files deploy/helm/port49/templates/prometheusrule.yaml deploy/helm/port49/values.yaml deploy/helm/port49/values.schema.json tests/alerts tests/helm/static_test.go Makefile .github/workflows/test.yml
  git commit -m "feat: alert rules for every stated alarm, each on a registered metric, checked by promtool"
  ```

---

### Task 6: The load harness

**Files:**
- Modify: `internal/devicemock/fleet.go` (`Fleet`, `FleetResult`, `Run`)
- Create: `tests/lab/load.go` (`//go:build lab`), `tests/lab/load_test.go` (`//go:build lab`), `tests/lab/load_unit_test.go` (`//go:build lab`), `internal/policy/fleet_bench_test.go`
- Modify: `Makefile` (`lab-load`)
- Test: `internal/devicemock/fleet_test.go`

**Interfaces:**
- Consumes:
  - `devicemock.Load(path, root string) (*Profile, error)`;
  - `devicemock.LoopbackSource(i int) string`;
  - `devicemock.Target`, `devicemock.Login`;
  - `newRealEtcd` (`tests/lab/store_test.go`);
  - `labOccupyForRun(path, who string) error` (`tests/lab/occupancy.go`).
- Produces:
  - `Fleet` gains `Rate float64` (plays per second, open loop: play k starts at `k/Rate` whatever earlier plays are doing; 0 keeps today's semaphore mode) and `Duration time.Duration` (with `Rate`, plays cycle devices `k % N` until it passes);
  - `FleetResult` gains `StepP50, StepP99 map[string]time.Duration`, keyed by stimulus step name (`login`, `authorize_session`, `command_permitted`, `command_denied`, `account_start`, `account_stop`), and `Late int` (plays that started more than 100 ms behind schedule);
  - in `tests/lab`:
    - `type loadCell struct{ ID string; Transport string; Rate float64; Duration time.Duration; Pass bool; Observed map[string]string }`;
    - `func loadStack(t *testing.T, members int, devices int) *loadRun` (three etcd members from `PORT49_LAB_ETCD_BIN`, `port49d store-roles`, then port49-broker and port49d from `bin/`);
    - `func (r *loadRun) mint(i int) (devicemock.Login, time.Duration, error)`, goroutine-safe with no `t` helpers, whose token stays only in the `Login`;
    - `func loadNote(cells []loadCell, host hostFacts) (string, error)`.

- [ ] **Step 1: Write the failing tests.**

  - `internal/devicemock/fleet_test.go`:
    - `TestRateModeIsOpenLoop`: against a fake server that stalls every play for 2 s, `Fleet{Rate: 100, Duration: time.Second}` starts 100 ± 2 plays within 1.1 s, and `Late == 0`.
    - `TestStepLatenciesAreReported`: a fake server answering each step in 1 ms gives `StepP99["command_permitted"] > 0`.
  - `tests/lab/load_unit_test.go`:
    - `TestLoadRefusesAShortRun`: `validateLoadCell(loadCell{Rate:170, Duration: 5*time.Minute})` is an error.
    - `TestLoadNoteHoldsNoToken`: `loadNote` of cells whose `Observed` was built from a run whose logins carried `not-a-real-token` contains neither the token nor `credential`. Check before printing.
    - `TestTheLoadPolicyHas500PrincipalsAnd10000Devices`: the generated inventory has 10 000 devices on `127.0.1.1`…, and the policy has 50 machine principals, each with a batch grant, plus 450 human subjects.
  - `internal/policy/fleet_bench_test.go`: `BenchmarkResolveFleet` (500 subjects × 10 000 devices), `BenchmarkCompareFleet` (one role edit), `BenchmarkInventoryOnlyRefresh` (the 6a carry) and `BenchmarkContainsAtFleet` (the plan 4 carry, `engine.Contains`/`MayMeet`). Each reports ns/op and allocs.

- [ ] **Step 2: Run them and see them fail.**

  - Run `go test ./internal/devicemock/ -run 'RateMode|StepLatencies' -count=1`.
  - Run `make lab-unit`, which now includes `TestLoad*` from `load_unit_test.go`.
  - Expected: FAIL to compile.

- [ ] **Step 3: Implement `Fleet` rate mode and step timings, and the harness.**

  - `TestLoad` refuses unless `PORT49_LAB_LOAD=1`. It takes the lab lock and runs the cells in order:
    - **(a)** TCP, 170 logins/s for 10 min. Each login mints (batch API, principal `i % 50`), logs in, and plays the `token_login` steps of `tests/qual/profiles/arista_eos/cEOS-lab-4.36.3M.yaml`. PASS iff `Errors == 0`, `Late == 0` and `StepP99["command_permitted"] < 5ms`.
    - **(b)** The same over TLS, with tickets off. PASS on the same terms.
    - **(c)** Accounting capacity: `account_start`/`account_stop` alone, the rate stepped ×1.5 every 60 s from 170/s until spool `Offer` p99 passes 50 ms or errors appear. The capacity is the last step under both.
    - **(d)** A reload mid-run and a store fault mid-run (11b's shape) at 170/s. PASS iff no play hangs past 10 s.
    - **(e)** 20 concurrent batch mints from one principal during (a)'s rate (the 11b carry). PASS iff no error, with p99 recorded.
    - **(f)** The directory store behind `tc netem delay 40ms`, as `lab-regions` applies it (`sudo -n`): sign-in p99 recorded, and the call timeout compared with the round trip.
  - Each cell records:
    - rate, duration, plays and late plays;
    - step p50 and p99, mint p50 and p99;
    - peak `port49_connections`, `port49_accounting_spool_depth`, and the store call p99 from `port49_store_call_seconds`;
    - CPU and RSS of each process;
    - the host's CPU model, cores, RAM, disk and kernel.
  - `make lab-load` runs `go test -tags lab ./tests/lab/ -run '^TestLoad$' -count=1 -v -timeout 150m` with `PORT49_LAB_LOAD=1` and `PORT49_LAB_ETCD_BIN` passed through.

- [ ] **Step 4: Run the unit tests and see them pass.**

  - Run the Step 2 commands, `go test ./internal/policy/ -run '^$' -bench 'Fleet|InventoryOnly|ContainsAt' -benchtime 3x`, and `make test && make vet`. Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/devicemock/fleet.go internal/devicemock/fleet_test.go internal/policy/fleet_bench_test.go tests/lab/load.go tests/lab/load_test.go tests/lab/load_unit_test.go Makefile
  git commit -m "test: an open-loop load harness at the design 5 rate, on etcd, with step latencies"
  ```

---

### Task 7: The load run and the defaults sized from it (ruling 7)

**Files:**
- Create: `tests/lab/results/load-<host>.md`
- Modify, as the gates decide:
  - `deploy/systemd/port49d.service` (`LimitNOFILE=`);
  - `deploy/helm/port49/values.yaml` (`autoscaling.averageConnections`);
  - `deploy/examples/stores/multi-region/README.md` (the directory `call_timeout` guidance);
  - the matching tests in `tests/shapes/units_test.go` and `tests/helm/static_test.go`.

- [ ] **Step 1: Run the load.**

  Run `make lab-load` under the lab lock, with the watchdog, on the lab host. Run `make lab-unit` first. Expected: every cell gives a PASS or a FAIL.

- [ ] **Step 2: Write `tests/lab/results/load-<host>.md`.**

  It holds the host facts, every cell's numbers, the benchmark numbers from Task 6, and the commit the binaries were built from. No token, no credential.

- [ ] **Step 3: Apply ruling 7's gates, each a stated line in the note.**

  - Tickets: off stays, or STOP for the lead.
  - Group commit: Task 8 builds it, or records "not needed at <capacity>/s against <rate>/s".
  - `LimitNOFILE=`.
  - `averageConnections`: change the value test-first in `tests/helm/static_test.go` (`TestHPAAverageConnections`).
  - The timeouts.
  - Any benchmark that puts a reload's settle past `max(30s, 2 × policy.watch_interval + 5s)` at fleet size: STOP for the lead.

- [ ] **Step 4: Verify and commit.**

  - Run `make test && make vet && make helm-test`.
  - Commit:

  ```bash
  git add tests/lab/results/load-*.md deploy tests/helm tests/shapes
  git commit -m "test: load validated at 170 logins/s on 10 000 devices; defaults sized from it"
  ```

---

### Task 8: Accounting group commit (gated on Task 7)

**Files:**
- Modify: `internal/daemon/acct/spool.go` (`Offer`)
- Test: `internal/daemon/acct/spool_test.go`

Run this task only if Task 7's gate says to. Otherwise skip to Task 9; the gate line in the note is the record.

**Interfaces:**
- Produces: `Offer(r decision.Record) error`, unchanged in signature and contract. It returns nil only after this record's bytes are written and fsynced.

- [ ] **Step 1: Write the failing tests.**

  - `TestConcurrentOffersShareAnFsync`: 64 goroutines call `Offer` at once against a spool whose sync hook counts calls and sleeps 5 ms. Every `Offer` returns nil, the file holds 64 lines, and the sync count is below 64.
  - `TestAFailedGroupSyncFailsEveryOfferInIt`: the hook fails once. Every offer in that batch returns `ErrSpoolFull`, `needNewline` is set, and the next offer starts on its own line (`TestTornTailDoesNotSwallowTheNextRecord` still passes).
  - `TestNoOfferReturnsBeforeItsBytesAreSynced`: a hook records the file length at each sync. Each `Offer`'s line ends at or before a synced length recorded before it returned.

- [ ] **Step 2: Run them and see them fail.**

  `go test ./internal/daemon/acct/ -run 'GroupSync|ShareAnFsync|BeforeItsBytes' -count=1`.

- [ ] **Step 3: Implement.**

  - A leader-follower batch: the first offer to arrive while no sync is in flight becomes leader, appends every queued line in one write, syncs once, and wakes the batch with the one result.
  - The directory sync on a new file stays per creation.
  - `spool.go` keeps a test hook `syncFile func(*os.File) error`, defaulting to `(*os.File).Sync`.

- [ ] **Step 4: Run the tests and the load cell again.**

  - Run the Step 2 command, `make test && make vet`, and `make lab-load` cell (c) alone (`PORT49_LAB_LOAD_CELLS=c`).
  - Add the new capacity to the note.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/daemon/acct/spool.go internal/daemon/acct/spool_test.go tests/lab/results/load-*.md
  git commit -m "perf: accounting offers share one fsync per batch, each still durable before it returns"
  ```

---

### Task 9: The failure matrix (ruling 11; Decision for Ryan 2)

**Files:**
- Create: `tests/compose/failmatrix_test.go` (`//go:build compose`), `deploy/failure-matrix.md`
- Modify: `Makefile` (`failure-matrix`), `.github/workflows/compose.yml` (a `failmatrix` job)

**Interfaces:**
- Consumes:
  - `shapetest.Device{…}.TryLogin(user, password string) (uint8, error)`;
  - `shapetest.Device.Permits(user string, words ...string) bool`;
  - `shapetest.Mint(t, brokerDir, brokerAddr, device string) string`;
  - `shapetest.Gauge(t, metricsAddr, name string) float64`;
  - `shapetest.WaitFor`;
  - the compose smoke's stack bring-up in `tests/compose/smoke_test.go`, factored into `func composeUp(t *testing.T) *composeStack` if it is not one already.

- [ ] **Step 1: Write `TestFailureMatrix`, one subtest per design §12 row the stack reaches.**

  Each subtest restores the stack before the next.
  - `store_hangs`: `docker compose pause etcd-2 etcd-3`.
    - A token login is refused.
    - The listener refuses connections within `close_after × interval + call_timeout + 2s`.
    - `port49_store_health_failures >= close_after`.
    - After unpause, it listens again within `open_after` passes plus 2 s, and a login passes.
  - `store_stopped`: `docker compose stop etcd-1 etcd-2 etcd-3`, then the same assertions.
  - `one_member_dark`: pause `etcd-2` alone. 30 logins in a row all pass, and the slowest is recorded and asserted under 12 s + `call_timeout` (the 12 s statement).
  - `broker_stopped`:
    - an open session's next command is permitted;
    - a token minted before the stop logs in (split deployment, L37);
    - a mint fails with a connection error;
    - after the start, a mint passes.
  - `port49d_stopped`: the device's connection is refused at once (the device falls to local; L4, L35 measured that side).
  - `retired_key`: a policy edit retires the device's key version while the device still uses it. The next login is reset with no reply, and the log has an `unvalidated` record with no strike for an open connection (12a) and a strike for a new one (L28).
  - `policy_refused`: `chmod g+w` the policy's directory. `port49_policy_file_refused == 1`, and logins still pass on the policy in force. Restore the mode.
  - `restore_guarded`: restore etcd from a snapshot taken earlier in the test, as `TestStoreSnapshotRestore` does. `port49_redemption_restore_guarded == 1`, a token login is refused, and it clears once the broker's purge runs.
  - Every subtest's failure dump goes through `shapetest.Filtered`.

- [ ] **Step 2: Write `deploy/failure-matrix.md`.**

  - One row per design §12 row: the device-side outcome, what an operator sees (the line, the metric, the alert from Task 5), the fix, and the evidence (this test's subtest or the lab row, per ruling 11).
  - A 3am table leads it, with the IOS XE and Junos (`tacplus` alone) ERROR warnings, SR Linux's per L87 (filled in Task 11), and the restore guard's (Decision 2).

- [ ] **Step 3: Run it.**

  - Run `make failure-matrix` (`go test -tags compose ./tests/compose/ -run '^TestFailureMatrix$' -count=1 -v -timeout 40m`), CI only: it refuses on a key host (`shapetest.RefuseOnKeyHost`).
  - Push the branch and read the `failmatrix` job with `gh run watch`. Expected: PASS.

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/compose/failmatrix_test.go deploy/failure-matrix.md Makefile .github/workflows/compose.yml
  git commit -m "test: the design 12 failure matrix on the compose stack, and its operator table"
  ```

---

### Task 10: The reference AAA configurations

**Files:**
- Create: `deploy/device-aaa/README.md`, and these files:
  - `arista_eos.cfg`, `arista_eos-tls.cfg`;
  - `cisco_iosxe.cfg`, `cisco_iosxe-tls.cfg`;
  - `cisco_nxos.cfg`, `cisco_nxos-tls.cfg`;
  - `juniper_junos.set`, `juniper_junos-tls.set`;
  - `cisco_iosxr.cfg`, `cisco_iosxr-tls.cfg`;
  - `nokia_srlinux.cli`;
  - `policy-platforms.yaml` (the `platforms: cisco_iosxr:` and `nokia_srlinux:` blocks, 11b carry).
- Create: `tests/deviceaaa/deviceaaa.go`, `tests/deviceaaa/deviceaaa_test.go`

**Interfaces:**
- Produces:
  - `type Values struct { Servers []string; Port int; Source string; BreakGlass string; TLSPort int; ServerName string; CertID string }`;
  - `func Placeholders() []string`, the closed set `<PORT49_1>`, `<PORT49_2>`, `<KEY>`, `<SOURCE_INTERFACE>`, `<BREAKGLASS_USER>`, `<TLS_PORT>`, `<SERVER_NAME>`, `<CERT_ID>`;
  - `func Render(platform, transport string, v Values, key string) ([]string, error)`. It reads `deploy/device-aaa/<platform>[-tls].<ext>` from the repo root, substitutes, and refuses a leftover `<…>`. `key` is substituted last and never returned in an error.

- [ ] **Step 1: Write the failing tests.**

  - `TestEveryReferenceRenders`: every file renders with lab values and leaves no placeholder.
  - `TestOnlyClosedPlaceholders`: every `<[A-Z0-9_]+>` in every file is in `Placeholders()`.
  - `TestNoReferenceCarriesAKey`: no file holds a literal key, password or `$aes1$`, `$9$` or `7 ` secret form. The key appears only as `<KEY>`.
  - `TestNoReferenceFallsThroughOnAReject`. Each of these is a failure:
    - Junos with `password` in `authentication-order` (ruling 2);
    - SR Linux without `exit-on-reject true` (ruling 3);
    - any Cisco or Arista method list ending in `none`;
    - NX-OS with `deadtime` set (L4: `deadtime 1` locks token logins out for a minute);
    - IOS XE with `if-authenticated` on command authorization (L4-error: it permits every command on ERROR).
  - `TestEveryReferenceNamesTwoServers`: two server addresses (design §13). For IOS XE TLS they are two distinct addresses, never one shared (L73: two `tacacs server` objects cannot share one).
  - `TestEveryReferencePinsItsSource`: a source interface line (spec §10: "MUST be pinned in the reference AAA configuration").
  - `TestTLSReferencesFollowL73`. Each is a test case:
    - Junos sets `tls mutual-authentication certificate-id <CERT_ID>` and its port;
    - NX-OS sets its port and uses an RSA key in its enrolment comment;
    - EOS sets its port and needs no `intermediates_file` remark, because the README carries it;
    - no TLS file lists a non-TLS server for the same host;
    - every TLS file sets single-connection.
  - `TestTheSRLinuxReferenceFollowsL76`: `priv-lvl-authorization true` on the port49 group, and `services [ cli ]` on each mapped role.

- [ ] **Step 2: Run them and see them fail.** `go test ./tests/deviceaaa/ -count=1`.

- [ ] **Step 3: Write each file from the lab startup configs and the L73, L76 and L4 notes.**

  - Start from `tests/lab/configs/*` and the L73 and L76 notes, and change only what the rulings change.
  - Junos's login classes are not copied here. The README points at `port49 platform export --classes` (Task 2).
  - `deploy/device-aaa/README.md` holds one section per platform, each a table:

    | What | Measured | Note |
    |---|---|---|

    It covers: a deny; port49 stopped; ERROR (with go-dark's bound); dark; the second server; the key-retire reset (L29, or L88 g); TLS's port, SNI, enrolment and single-connection. Each cell cites its note, or reads "unmeasured (L88)" until Task 12 fills it.

- [ ] **Step 4: Run the tests and see them pass.** Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add deploy/device-aaa tests/deviceaaa
  git commit -m "feat: reference device AAA configuration per platform, with no fall-through on a reject"
  ```

---

### Task 11: Lab L87: SR Linux on an ERROR

**Files:**
- Create: `tests/lab/l87_test.go` (`//go:build lab`), `tests/lab/l87_unit_test.go`, `tests/lab/results/L87-nokia_srlinux.md`
- Modify: `Makefile` (`lab-l87`), spec §15 L87, `deploy/device-aaa/README.md`, `deploy/failure-matrix.md`

- [ ] **Step 1: Write `TestL87` and its unit test.**

  - It boots `srlinux` with `tests/lab/configs/srlinux-startup.cli`, then applies `exit-on-reject true` as L76 cell (l) did.
  - **(a)** It sets the lab fault switch to `store_unavailable`. It records break-glass's outcome and time, and a token login's outcome.
  - **(b)** It runs port49d on etcd as `l80EtcdDaemonYAML` builds it, pauses the etcd, waits for the listener to close (the `port49_store_health_failures >= close_after` gauge), and then does break-glass.
  - **(c)** It answers ERROR to the session authorization only, after a PASS authentication.
  - `TestL87NoteHoldsNoSecret` (unit): the note renderer drops every credential-bearing field.
  - `make lab-l87` runs `go test -tags lab ./tests/lab/ -run '^TestL87$' -count=1 -v -timeout 60m` with `PORT49_LAB_PLATFORMS=srlinux`.

- [ ] **Step 2: Run the lab.** Under the lab lock and the watchdog. Run `make lab-unit` before and after.

- [ ] **Step 3: Write the note, close the row, and fill SR Linux's 3am line.**

  - In `deploy/device-aaa/README.md` and `deploy/failure-matrix.md`, the line reads either "break-glass waits for go-dark (≤ 5.5 s)" or "break-glass logs in at once", as (a) measured. `exit-on-reject true` stays either way (ruling 3).
  - If SR Linux's own debug is needed to say why, collect it first (`debug` of `aaa_mgr`).

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/lab/l87_test.go tests/lab/l87_unit_test.go tests/lab/results/L87-nokia_srlinux.md docs/design/2026-08-23-policy-engine-spec.md deploy/device-aaa/README.md deploy/failure-matrix.md Makefile
  git commit -m "docs: close lab register entries L87 (SR Linux with exit-on-reject on an ERROR)"
  ```

---

### Task 12: Lab L88: the reference configurations on every platform

**Files:**
- Create: `tests/lab/l88.go`, `tests/lab/l88_test.go`, `tests/lab/l88_unit_test.go` (all `//go:build lab`), `tests/lab/results/L88-<platform>.md` per image
- Modify:
  - `Makefile` (`lab-l88`);
  - spec §15 L88, and decision 21's "largest value … unmeasured" sentence (from cell i);
  - `deploy/device-aaa/README.md`;
  - `internal/platform/classes.go` (`template.lines`: cap at cell (i)'s maximum, test-first in `classes_test.go`, `TestAClassAgePastTheDeviceMaximumIsCapped`; the export header names a capped class);
  - design §12's "Device-side AAA configuration" paragraph (cite L88).

**Interfaces:**
- Consumes:
  - `deviceaaa.Render(platform, transport string, v deviceaaa.Values, key string) ([]string, error)`;
  - the harness's `(l *lab) login`, `loginWithin`, `startDaemonWith`, `mark`, `recordsSince`;
  - L73's TLS enrolment helpers (`l73EnrolCommands`, `l73JunosLines`, `l73PKILines`);
  - `l80EtcdDaemonYAML` for cell (d).
- Produces:
  - `func l88Apply(l *lab, transport string) error`, which pushes the rendered lines over the break-glass session, as L73 pushes its own, and reads them back;
  - `func l88Cells(platform string, tls bool) []string`.

- [ ] **Step 1: Write the unit tests first.**

  - `TestL88AppliesTheShippedFileUnchanged`: the lines `l88Apply` sends are `Render`'s output, with lab values and nothing added.
  - `TestL88CellsPerPlatform`: (i) appears for Junos only. (h) appears for `vjunos26`, `iosxe1718`, `nxos106`, `ceos436` and `xrd261`. (g) is skipped where L29 measured the platform, unless TLS.
  - `TestL88NoteHoldsNoSecret`.

- [ ] **Step 2: Write `TestL88`.**

  - It loops over the selected platforms with `eachSelected`, applies the reference, runs each cell against its §15 condition, and writes `L88-<platform>.md`.
  - Cell (a) creates a local account with a known lab password equal to a port49-denied user's, and removes it at the end.
  - `make lab-l88` runs `go test -tags lab ./tests/lab/ -run '^TestL88$' -count=1 -v -timeout 300m`, one `PORT49_LAB_PLATFORMS` selector per run.

- [ ] **Step 3: Run it, one selector at a time.**

  - Default images first, then each opt-in TLS image, then `srlinux`.
  - Use the lab lock and the watchdog, and run `make lab-unit` around each run.
  - Before calling a FAIL a device limitation, collect `debug aaa`, `debug tacacs` or `traceoptions`.

- [ ] **Step 4: Fill the README, cap the class age, and close or update the row.**

  - Every "unmeasured (L88)" cell in `deploy/device-aaa/README.md` gets its reading.
  - A FAIL on (a), (b), (d), (e) or (f) means the reference file is wrong. Fix it test-first in `tests/deviceaaa`, re-run that platform, and say so in the commit.
  - The row closes when every listed image has every cell. Otherwise its Status says which images are measured.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/lab/l88.go tests/lab/l88_test.go tests/lab/l88_unit_test.go tests/lab/results/L88-*.md docs/design deploy/device-aaa internal/platform/classes.go internal/platform/classes_test.go Makefile
  git commit -m "docs: close lab register entries L88 (the reference AAA configuration on every platform)"
  ```

---

### Task 13: Lab L39 (b) and (c): the source address on Kubernetes

**Files:**
- Create: `tests/lab/l39_test.go` (`//go:build lab`), `tests/shapes/l39/l39.go`, `tests/shapes/l39/l39_test.go`, `tests/lab/results/L39-kind.md`
- Modify:
  - `Makefile` (`lab-l39`);
  - `.github/workflows/lab-kind.yml` (matrix cell `l39`);
  - spec §15 L39, and decision 54's "Open" line;
  - design §13's source-address requirement;
  - `docs/superpowers/plans/README.md` (the "four requirements" bullet);
  - `deploy/helm/port49/values.yaml`'s `service` comment, `deploy/helm/port49/README.md`.

**Interfaces:**
- Consumes:
  - `kindtest.UpWith(t, name, config string) *Cluster`;
  - `(*Cluster).Apply`, `Kubectl`, `WaitReady`, `Dump`;
  - `l82.Cell`, `l82.Save`;
  - `shapetest.Device`, `shapetest.Mint`.
- Produces:
  - `func Results(env Env, cells []l82.Cell) (string, error)` in `tests/shapes/l39`, as `l85.Results` is.

- [ ] **Step 1: Write `tests/shapes/l39/l39_test.go` (unit): `TestResultsNeedEveryCell` and `TestResultsHoldNoToken`.**

- [ ] **Step 2: Write `TestL39`, modelled on `TestL85`.**

  - The cluster has one control plane and two workers. The chart is installed with one port49d replica pinned to worker 1.
  - The device is a container on the kind network.
  - **(b1)–(b4):** the chart's TACACS+ Service switched to `type: NodePort`, under each policy, dialled at each worker's address.
  - **(c):** a lab-only `privileged` namespace with a port49d pod at `hostNetwork: true`, dialled at its node. Its manifest lives in the harness, never in the chart (ruling 5).
  - Each cell's verdict is the decision log's `token_redeemed`, or the refusal (`device_unknown` or a binding failure), and the source port49d recorded.

- [ ] **Step 3: Run it in CI.**

  Label the pull request `lab-kind` and read the `l39` cell's artifact. Expected: every cell gives a PASS or a FAIL.

- [ ] **Step 4: Write the note, close the row, and update the text.**

  - The design §13 requirement and the roadmap bullet state what was measured, in place of "expected to be needed".
  - The chart comment drops "unmeasured" when (b3) passes. If (b3) FAILs, the chart's default is wrong: STOP for the lead.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/lab/l39_test.go tests/shapes/l39 tests/lab/results/L39-kind.md Makefile .github/workflows/lab-kind.yml docs deploy/helm/port49/values.yaml deploy/helm/port49/README.md
  git commit -m "docs: close lab register entries L39 (the source address behind a Service and on the host network)"
  ```

---

### Task 14: Lab L84: the systemd cells, in CI (ruling 12)

**Files:**
- Create: `.github/workflows/lab-hosted.yml`
- Modify: `tests/lab/results/L84-systemd-docker.md`, spec §15 L84 and decision 54 ruling 2 and its "Open" line, `deploy/systemd/README.md`

- [ ] **Step 1: Write `lab-hosted.yml`.**

  - Copy `lab-kind.yml`'s guards: the `lab-hosted` label; `PORT49_SMOKE_ON_KEY_HOST: "1"`; `permissions: {contents: read}`; pinned actions; output through `tests/qual/secret-filter.sh`; the `bin/lab-out` artifact.
  - Its one job runs `make lab-l84-systemd CELLS_OUT=bin/lab-out/l84/cells.json`, then `make lab-l84 A_CELLS=bin/lab-out/l84/cells.json`.
  - `tests/ci/workflows_test.go` gains `TestLabHostedIsLabelGatedAndHoldsNoIDToken`. Write it first and see it fail.

- [ ] **Step 2: Run it.** Label the pull request `lab-hosted` and read the artifact. Expected: cells (a) and systemd's (c) each give a PASS or a FAIL.

- [ ] **Step 3: Write the note and close the row.**

  The systemd README names `LoadCredential=` for device keys only if (a) and (c) pass. If (c) fails, it names it for the encryption key only, saying why (decision 54 ruling 2).

- [ ] **Step 4: Commit.**

  ```bash
  git add .github/workflows/lab-hosted.yml tests/ci/workflows_test.go tests/lab/results/L84-systemd-docker.md docs/design/2026-08-23-policy-engine-spec.md deploy/systemd/README.md
  git commit -m "docs: close lab register entries L84 (systemd LoadCredential against the fence)"
  ```

---

### Task 15: Lab L89: Velero on kind (ruling 10)

**Files:**
- Create: `tests/lab/l89_test.go` (`//go:build lab`), `tests/shapes/l89/l89.go`, `tests/shapes/l89/l89_test.go`, `deploy/helm/port49/examples/velero/` (a `Schedule` and the README's restore steps), `tests/lab/results/L89-kind.md`
- Modify: `Makefile` (`VELERO_VERSION`, `MINIO_IMAGE`, their sha256 pins, `lab-l89`), `.github/workflows/lab-kind.yml` (cell `l89`), spec §15 L89, `deploy/helm/port49/README.md`

- [ ] **Step 1: Write the unit tests:** `TestL89ResultsNeedEveryCell`, `TestL89ResultsHoldNoKeyMaterial`, and `TestTheVeleroExampleBacksUpBothStatefulSets` (render the example and assert both PVC label selectors, with `defaultVolumesToFsBackup: true`).

- [ ] **Step 2: Write `TestL89`.**

  - It runs `kindtest.Up`, MinIO in-cluster with generated credentials passed by file, and Velero with the node agent.
  - It installs the chart as the kind smoke does, with issuance on, runs `copy-issuer.sh`, logs in once, backs up, deletes the namespace, restores, and runs cells (a) and (b).
  - The MinIO credentials are generated per run, never printed, and the `velero` namespace is never dumped.

- [ ] **Step 3: Run it in CI** (the `lab-kind` label, cell `l89`).

- [ ] **Step 4: Write the note and close the row.** The README names Velero only if both cells pass, with the example. Otherwise it says what was refused, quoting the fence line.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/lab/l89_test.go tests/shapes/l89 tests/lab/results/L89-kind.md deploy/helm/port49/examples/velero deploy/helm/port49/README.md docs/design/2026-08-23-policy-engine-spec.md Makefile .github/workflows/lab-kind.yml
  git commit -m "docs: close lab register entries L89 (Velero file-system backup of the chart's volumes)"
  ```

---

### Task 16: Lab L90: Oxidized host keys (ruling 9)

**Files:**
- Modify: `tests/lab/l49_test.go` (a `TestL90` beside the L49 harness), `tests/lab/l48_l49_unit_test.go`, `examples/oxidized/config`, `examples/oxidized/port49-oxidized-run`, `examples/oxidized/run_test.go`, `examples/oxidized/README.md`, spec §15 L90
- Create: `tests/lab/results/L90-oxidized-arista_eos.md`

- [ ] **Step 1: Write `TestL90`** on the L49 Oxidized container and vEOS, with cells (a)–(d) as §15 states. `known_hosts` lives in the run's temp home. Cell (c)'s `ssh` runs with `BatchMode=yes` and sends no credential.

- [ ] **Step 2: Run it** under the lab lock and the watchdog, with `make lab-unit` around it. The make target is `lab-l90`, `-run '^TestL90$'`.

- [ ] **Step 3: Change the example per ruling 9, test-first in `examples/oxidized/run_test.go`.**

  - If (d) passes: `TestTheConfigUsesAcceptNew`.
  - Else, if (c) passes: `TestTheWrapperPrepopulatesUnknownNodes`. The wrapper runs the `ssh … accept-new … BatchMode=yes … exit` line only for a node absent from `known_hosts`, never for one present, and never with `StrictHostKeyChecking=no`.
  - `secure: true` stays. The README's "populate it once per device" line goes, or, if neither cell passes, it states the measured limitation.

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/lab/l49_test.go tests/lab/l48_l49_unit_test.go tests/lab/results/L90-oxidized-arista_eos.md examples/oxidized docs/design/2026-08-23-policy-engine-spec.md Makefile
  git commit -m "docs: close lab register entries L90 (Oxidized host keys under accept-new)"
  ```

---

### Task 17: The enrollments export CronJob, run (ruling 13)

**Files:**
- Create: `tests/kind/enrollments_test.go` (`//go:build kind`)
- Modify: `Makefile` (`kind-enrollments`), `.github/workflows/kind.yml` (a second job), `deploy/helm/port49/README.md` ("unrun" removed)

- [ ] **Step 1: Write `TestEnrollmentsExportRuns`.**

  - It runs `kindtest.Up`, plus the L67 OpenLDAP image (`tests/lab/directory/openldap`) as a pod.
  - The broker is configured with a `directory_password` verifier and a username-free policy, and `backup.enrollments.enabled: true` with a test PVC.
  - It runs `port49-broker init-enrollments` as the install step, then `kubectl create job --from=cronjob/<release>-enrollments-export`.
  - It asserts:
    - the job succeeds;
    - the PVC holds one dated file, mode 0600 and owned by 65532;
    - the job's log holds no enrollment byte or secret, checked by `shapetest.Filtered` before printing.

- [ ] **Step 2: Run it in CI.** `make kind-enrollments` runs in the new `kind.yml` job. Expected: PASS.

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/kind/enrollments_test.go Makefile .github/workflows/kind.yml deploy/helm/port49/README.md
  git commit -m "test: the enrollments export CronJob runs against a directory on kind"
  ```

---

### Task 18: The roadmap's record and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line, the 12c entry, a new "Plan 12c — As built" before "Pre-beta review")

- [ ] **Step 1: Write "Plan 12c — As built".**

  It holds:
  - each task's commits;
  - what changed in review;
  - "Carried forward": anything not done; each lab row's state; the standing FAILs a later version bump could reopen (L83 (b) the CSI driver, L83 (c) the injector as a reload), re-run at each pin bump through `lab-kind`; and the restore guard as Ryan ruled it.
  - "Operator notes", each a line true of the code as built:
    - the reference configurations and their 3am lines;
    - the per-class `idle-timeout`;
    - the ceiling line in `policy diff`;
    - `single_device`;
    - the alert file and the chart's `prometheusRule`;
    - the load numbers and the host they came from;
    - the failure matrix's table;
    - whether Velero and `LoadCredential=` are named;
    - the Oxidized change.
  - "Hand-offs":
    - **Pre-beta review:** the load note, the failure matrix and every open row.
    - **Plan 13:** one device page per platform from `deploy/device-aaa/README.md`; the alerts page from `deploy/alerts/README.md`; the 3am table.

- [ ] **Step 2: Verify.** Run `make test && make vet` (PASS) and `make leaks` (no finding).

- [ ] **Step 3: Commit.**

  ```bash
  git add docs/superpowers/plans/README.md
  git commit -m "docs: plan 12c as built, its operator notes and hand-offs"
  ```
