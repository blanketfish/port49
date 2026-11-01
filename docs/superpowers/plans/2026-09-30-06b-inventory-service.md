# Plan 6b: The Inventory Service, Its Signed Bundle, and port49d's Pull Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A separate `port49-inventory` service syncs the inventory from its sources (the file
connector in this plan), bounds each sync, and publishes one signed, sequenced bundle document over
a mutual-TLS API, to its own disk and to a shared mirror directory. port49d pulls that document
every 30 s with an ETag, verifies it, and applies its inventory against its own policy file
through exactly the bound, admission and security-change records a file reload goes through. It
persists the last good document, starts from it or from the mirror when the service is down, and
serves nothing until it holds one. A policy-hash mismatch between the service and port49d is said
and alarmed, never applied. The lab measures L29 (what a device does when port49d resets an open
connection) through the service's syncs and across a real midnight UTC, runs spec §14's quarantine
through a sync, and records L30 (pagination, and Nautobot 3.x) as fixtures for plan 6c's connectors.

**Architecture:** The bundle document (`internal/bundle/document.go`) is the inventory in the
canonical form `bundle.ID` already hashes, plus its sequence, the policy hash and platform set the
service built it against, and the device names each source gave, sealed with an ed25519 signature.
One sealed byte string is what the API serves, what the service keeps in `state_dir` and writes to
`mirror_dir`, and what port49d persists: every copy is verified the same way. The service
(`internal/inventory`, `cmd/port49-inventory`) is one process: sources, a single-flight syncer, a
state directory, and an HTTP API behind `RequireAndVerifyClientCert` with two rights, read and
sync. In port49d a fetcher goroutine does the network I/O and hands each verified document to the
existing reloader, which alone swaps: `bundle.Parse` against the policy in force, `bundle.Check`,
`policy.Live.Swap`, `after` (the `inventory_change` records and the refresh). With
`inventory.service` set, `inventory_file` is absent, and port49d's start acquires a document
before it builds the broker.

**Tech Stack:** Go 1.22+ (the module's own `go` line), the standard library (`crypto/ed25519`,
`crypto/tls`, `net/http` with 1.22 method patterns), `gopkg.in/yaml.v3` and
`prometheus/client_golang` (both already dependencies). containerlab on the lab host (beehive) for
Tasks 19 and 20; Docker Compose on the same host for Task 2. **No new module dependencies.**

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §10 in full ("The inventory service",
"One versioned bundle", "Connectors and sync cadence", "How a daemon refreshes its snapshot",
"Source-of-truth write access is privilege-granting"), §5.7 (reason codes and events: none added),
§12 (`port49 inventory sync`, `inventory diff`), §13 decision 28, §14 "Inventory and capability",
§15 L27 (closed), L29 and L30 (open, owned here). Design `docs/design/2026-08-21-port49-design.md`
§6 (the inventory service), §10 "Device inventory", §12 (the failure matrix's inventory row), §17
"Internal interfaces", §19 step 6. Roadmap `docs/superpowers/plans/README.md`, "Plan 6", the 6a/6b
split, "Plan 6a — As built" (its "Carried" list), and plans 4's and 4b's "Hands to plan 6". Plan
6a's text, owner decision 3 in particular, which is binding here.

**Prerequisite:** plan 6a merged (PR #15, `3b830f4`). Branch `feature/inventory-service` off
`main` at the commit that adds this file.

## Owner decisions needed

Each is written into this plan at its default, the option that denies more. A different ruling
changes only the tasks named.

1. **Every copy of the bundle is signed by the service and verified by port49d.** The service
   holds an ed25519 key (`signing_key_file`); port49d holds the public half
   (`inventory.service.verify_key_files`, a list, so the signing key rotates without a flag day).
   The API is already mutual TLS, but the persisted copy and above all the mirror are files: whoever
   can write the object store behind `mirror_dir` could otherwise hand every fresh pod an inventory
   with a rogue address on a real device, which the mint hands to an SSH client (spec §10, a
   credential-capture path). With the signature, the mirror's writers can replay an older genuine
   bundle, never forge one. **Default:** signed; a document that does not verify is refused
   wherever it came from, said once, and alarmed. *Alternative:* trust mutual TLS for the API and
   the file system's permissions for the two copies, which saves provisioning one key pair.
   Tasks 3, 4, 8, 13–15.
2. **The mirror is a directory, not an object-store API.** The service writes
   `mirror_dir/bundle.json`; port49d reads its own `mirror_dir/bundle.json` at a cold start. The
   deployment mounts the object store there (a CSI driver, a ReadWriteMany volume, NFS). **Default:**
   the directory, which needs no new module and puts no object-store credential in port49d; decision
   1 is what makes a shared mount safe to read. *Alternative:* an S3 client in both binaries (a new
   dependency, and a bucket credential beside every port49d). Tasks 8, 14.
3. **Nothing the service sends assigns a key; a pin moves into the policy, matched by device
   name, at tier 1.** A document carries no `key_groups` and no `key_ref` pin: the service refuses a
   source that has either (the sync is refused, naming the device), and port49d refuses a document
   that has either. Key assignment is reviewed policy (spec §10, "Admission and keys"), and a synced
   source's writer choosing a device's key from everything in `keys:` is an escalation with no diff.
   **The tier-order fact** (spec §10, "Key group matching is deterministic";
   `internal/admission/admission.go` `Assign`): a record pin is tier 1, an attribute group tier 2,
   a CIDR group tier 3. So a `/32` key group is **not** a pin: every attribute group outranks it, a
   device with several addresses needs one per address or is refused when they disagree, and it
   follows the address, not the device. The pin tier exists "so an overlap can be resolved
   explicitly rather than by contorting the CIDR layout", and a `/32` cannot resolve the attribute
   overlap it exists for. So this plan keeps tier 1 and moves it into the reviewed policy: a key group
   may match a device **name**, `{match: {name: leaf-01}, key_ref: prod_key}`, resolved at tier 1
   (Task 3a). Spec §10 already allows it ("a group matching a single device name is legal", under
   "Per-device keys are not supported"). Two name groups for one device are a policy load error, as
   any tier tie is; with `inventory_file`, a record pin and a name group that disagree refuse that
   device alone. The service mode has no inventory `key_groups` fallback (spec §10's "read where the
   policy has none" applies to `inventory_file` only).
   **What this decision does not close.** Attribute key groups (tier 2) already let whoever writes the
   source of truth move a device among the keys the policy maps to attributes: change a device's
   `env: lab` to `env: prod` in NetBox and its key follows, with no policy diff. This decision narrows
   that escalation — a source writer can no longer pick *any* key in `keys:` for a device — but does
   not close it. The mitigation for what remains is the `inventory_change` record plan 6a already
   writes when a device's `key_ref` changes (`key_ref_changed`, counted in
   `port49_inventory_changes_total{kind="key_ref_changed"}`), which every swap from the service writes
   exactly as a file reload does (Task 15). port49d's own `inventory_file` mode keeps
   record pins, as plan 6a built. **Default:** refused on both sides, and the policy name group as the
   pin. *Alternative:* carry pins from the file source. Tasks 1, 3a, 4, 7. *(Revised after the
   pre-flight review, B1: the first draft offered a `/32` group as a pin's equivalent, which it is
   not.)*

## Revised after the pre-flight review (2026-09-30)

The pre-flight review (`.superpowers/sdd/2026-09-30-06b-inventory-service/preflight.md`) found one
blocker, nine major and sixteen minor problems. The controller ruled B1, M2–M9 and the merge gate;
every finding is fixed below, with the review's fix unless the line says otherwise.

- **B1 (a `/32` is not a pin).** New Task 3a: a policy key group matching a device `name`, at tier 1.
  Owner decision 3 now states the tier order, and every `/32` wording is gone (Tasks 1, 7, operator
  notes). *Added beyond the review:* with `inventory_file`, a record pin and a name group that
  disagree refuse that device alone, as a tie that only some devices meet does (6a owner decision 1).
- **M1 (a test that could not pass).** Task 9's bound test makes devices unadmittable from the
  source; a second test shows a service `policy_file` edit alone publishes, unbounded. The code is
  right and is not changed to fit the old test.
- **M2 (two rules for one device).** `bundle.DeviceProblem` (Task 4) is the one predicate: the
  syncer leaves out what it names, `Open` refuses it, and a zoned address is one. Task 9 tests that
  whatever the syncer publishes `Open` accepts.
- **M3 (verify keys unfenced).** Verify key files are read through `fence.Read`
  (`config.VerifyKeys`, Task 13); keyfile only parses them (`ParseEd25519Public`, Task 3), since Task
  3 comes before the fence moves (Task 6). A group-writable key refuses the start and the `SIGHUP`
  re-read, which keeps the keys in force.
- **M4 (a hung mirror blocks a restart).** `coldStart` reads the mirror in a goroutine under a 10 s
  deadline and passes it over, said, when it does not answer (Task 14).
- **M5 (a copy looked fresh).** A start from a copy dates the snapshot from the document's
  `published_at`; the first confirmation resets it (Tasks 1, 14, 15).
- **M6 (rotation reset the sequence).** port49-inventory.yaml's `verify_key_files` are the keys the
  service accepts for its own state and mirror, with its signing key's public half always among them
  (Tasks 5, 9, 11); a rotation keeps the sequence and the bound.
- **M7 (the mirror went stale).** The mirror is rewritten at `Restore` and at every sync whenever it
  differs from the bundle published, with `port49_inventory_mirror_behind`; port49d retries a failed
  persist at every confirmation (Tasks 9, 15).
- **M8 (two PKIs).** `writeServiceRunConfig` takes the PKI directory; the end-to-end tests share the
  service's (Tasks 14, 18).
- **M9 (Task 19 as written).** The lab source is padded with ten dummy devices, so each phase is
  under the default 10% bound on both sides (chosen over raising the bounds, which would leave them
  untested); the line regex takes padded names; the lab policy's `key_groups` is block style; a
  lab-unit test runs every phase's edit on the real `inventory-lab.yaml`.
- **Minors.** 1: Task 1 edits the "key references" paragraph, the tier table, "Device records" and
  L30's Decides column. 2: *reversed by the owner's rule (no spec function changes without a tested
  technical reason):* each source keeps its own `interval`, as spec §10's example has it, defaulting
  to a top-level `interval`; a sync of any source rebuilds the merged bundle from every source's
  latest fetch (Tasks 5, 9, 11). 3: the API logs a fixed route name and says a
  refusal once per reason and caller. 4: the rotation hint is given only for an unknown signing key;
  a signature that does not verify is called out for investigation (`bundle.ErrUnknownKey`). 5: every
  ask port49d makes of the service has a 30 s deadline (`requestTimeout`, cold start and the fetcher
  alike), and every dial a 10 s one; `port49 inventory sync` waits up to 6 min for its answer, since
  the sync it asks for is bounded by the service's `sync_timeout` (default 5m). 6: *departing from the review's
  "re-read at SIGHUP":* the client reads `ca_file` at every handshake, as it reads its certificate, so
  a CA rotation needs neither a restart nor a signal. 7: the mirror copy is 0640. 8: the fence says
  "the user this process runs as". 9: `Open` checks `bundle`, `policy_sha256` and `platform_set` for
  shape. 10: `sync_timeout` (default 5m) bounds every sync, and `Source` says so. 11: *departing
  from the review's conditional:* cold start picks the copy with the later `published_at` always, and
  says so, since publication time survives a sequence reset. 12: tests for a client certificate from
  another CA, and for service mode never expiring. 13, 14: see the merge gate below. 15: Task 2's
  result rule matches its unit test. 16: *taking the review's second option:* `port49 inventory
  export --service … [--from N]` goes to plan 6c's brief, where the first source with no file arrives.

**The merge gate.** Task 19 gates the merge: it is the first run of the service path on devices,
and spec §14's quarantine through a sync. Task 20 does not. It measures behaviour plan 6a shipped
(`retire_after` on an open connection) and depends on none of Tasks 3–19, so it is **executed
straight after Task 2**: its test and the shell helpers it shares with Task 19 are committed on
`feature/inventory-service` first, and its four nights start while the code tasks run. The lab is
single-occupant: no Task 20 night shares a night with any part of Task 2, and none overlaps Task
19's runs. Nights that land after the
merge come through a `lab/l29-midnight` branch and pull request, since evidence is not docs, and L29
stays open until every platform has both its notes (lab register rule 3).

## Why this plan is 6b, and what 6c is

The roadmap's brief for 6b is two branches' work: the service with its bundle, API, persistence,
mirror, triggers and port49d's pull, **and** the NetBox and Nautobot connectors with version
detection, GraphQL first, the REST fallback, the slug alias table, filters, maps and authenticated
webhooks. **The seam is the source.** 6b builds everything a bundle travels through, with the file
connector spec §10 requires regardless, so the distribution path is built and lab-tested end to end
with no third-party system in it. **Plan 6c** adds the NetBox and Nautobot connectors and the
webhook trigger: they are the contributable surface spec §10 isolates in this service, they carry
the only source-of-truth credentials in the system, and two of their four facts are unmeasured
(L30: a non-null pagination `next`, and Nautobot 3.x). So 6b's Task 2 measures L30 first and records
fixtures, exactly as 6a's Task 2 recorded L27 for this plan, and 6c is written after 6b merges,
against real code and those fixtures (CLAUDE.md: a plan is written against real code, not a guess).

Split this way each branch carries its own lab work: 6b measures L29 and spec §14's quarantine
through a sync with the file connector, which needs no source of truth; 6c's lab run is a NetBox and
a Nautobot sync end to end.

## Decided in this plan

1. **port49d keeps its own policy (plan 6a owner decision 3, binding).** The document names the
   policy the service built against (`policy_sha256`) and never carries a policy. port49d builds the
   bundle from its own `broker.policy_file` and the document's inventory, exactly as 6a builds it from
   two files. When the two hashes differ, port49d still applies the inventory, against its own
   policy, says so once per pair, and sets `port49_inventory_policy_mismatch` to 1: nothing the service
   sends changes the policy, and a policy rollout that reaches port49d first never stalls inventory.
   The service still reads a copy of the policy repository (`policy_file`), for the hash, for
   admission and quarantine in its own sync report, and for `bundle/diff`.
2. **One sealed document, three places.** The API body, `state_dir/published.json`, the history
   under `state_dir/history/`, `mirror_dir/bundle.json` and port49d's `state_dir/bundle.json` are
   the same bytes: `{"document": <base64>, "key_id": "ed25519:<16 hex>", "signature": <base64>}`.
   The signature is over the document's exact bytes, so nothing is canonicalized twice. `bundle.Open`
   verifies before it parses anything but the envelope, decodes strictly (unknown fields refused),
   and never quotes the document's text in an error.
3. **The sequence is an integer beside the name, not in place of it.** `sequence` is the service's
   publication count, persisted in `state_dir` and continued from the mirror when `state_dir` is
   lost. The service reads its own state and mirror against every key in its `verify_key_files`
   (its signing key's public half always among them), so rotating its signing key keeps the sequence,
   the history and the per-source bound (M6). `bundle` on every record stays the content hash (6a Decided 2), which every port49d
   computes itself from its own policy and the document's inventory. The sequence appears in lines,
   the ETag and `port49_inventory_bundle_sequence`. A sequence that goes backwards from the service
   is applied and said (`the service's sequence went back from 1842 to 3: its state_dir was reset`):
   the API is authenticated, and a service that can sign can already send anything.
4. **A pulled document is a reload like any other.** The fetcher goroutine verifies and hands over;
   the reloader, one goroutine as in plan 4b, parses the inventory against the policy in force
   (`bundle.Parse`), refuses it by `bundle.Check` with the same `inventory.max_removed_percent`, swaps
   it in one pointer, writes the `inventory_change` records, and runs the refresh. The daemon trusts
   nothing the service already checked (spec §10, "Validate locally before swapping").
5. **Cold start takes the newer of two copies, and waits only with neither.** At start port49d
   verifies its persisted copy and the mirror's and starts from the one published later
   (`published_at`, which survives a sequence reset), saying which and why. The mirror is read under
   a 10 s deadline: a hung mount is passed over, said, and never holds up a start from the persisted
   copy (M4). It asks the service at start only when it has neither, and until one arrives it
   keeps its TACACS+ listener closed and `/readyz` at 503: a device then finds the connection
   refused and falls to its next server or its local method at once, which is the measured
   break-glass shape (spec §15 L4; `tests/lab/results/L4-error-*.md`). The service is never on the
   start path while a copy exists: a restart in place needs nothing (spec §10, a MUST).
6. **The snapshot never expires.** A service that stops answering is said once per distinct error
   and `port49_inventory_snapshot_age_seconds` climbs; port49d serves the bundle in force for as long
   as it takes (spec §10). The age is the time since the service last confirmed the document in
   force, or one was loaded from it. A start from the persisted copy or the mirror counts the age
   from that document's `published_at`, never from the start: a restart confirms nothing, and a copy
   can be old (M5). This may overstate the age, the safe direction; the first confirmation resets it.
7. **`inventory_file` or `inventory.service`, never both,** and the service needs a `broker:` block,
   since without one port49d has no policy to build a bundle against. Two inventory sources would be
   the disagreement the bundle exists to prevent.
8. **The API is mutual TLS on every path, with two rights.** A caller is the verified leaf's one URI
   SAN, verbatim (a workload, design §7), or, with no URI SAN, `user:` and its one email SAN,
   lower-cased (a person, as the broker maps one); anything else is refused. `readers` may read the
   bundle, its version, its diff, one device and health; `syncers` may do that and trigger a sync
   (design §17: "reading a snapshot is not the same right as triggering a sync"). `/v1/healthz` is
   behind mutual TLS too; probes use `/healthz` and `/readyz` on the plain `metrics_listen`, which
   carries no fleet data.
9. **The service bounds each source against what that source gave last time.** A source whose
   devices, removed or newly refused admission under the service's policy, exceed its
   `safety.max_removed_percent` (default the top-level `safety.max_removed_percent`, default 10)
   refuses the sync; the last published bundle keeps being served. An empty result, or one the
   service's policy admits none of, is refused whatever the bound. port49d bounds again, by its own
   `inventory.max_removed_percent`: two bounds, two owners.
10. **A device the service cannot name safely is left out, by one rule both sides use.** A name
    that is not 1–255 bytes of printable ASCII without spaces (the broker's own rule for a device
    name), a platform or transport that is not such a name, an attribute key or value with a control
    character, or an address with a zone (`fe80::1%eth0`) cannot reach a record or a line.
    `bundle.DeviceProblem` names the fault (M2): the service leaves such a device out of the sync,
    says so and counts it, and port49d refuses a document that carries one, since the service never
    sends one. Anything the service publishes, `Open` accepts.
11. **A reload of either source tries the two together when both have moved** (plan 6a final review
    m7). At `SIGHUP`, and whenever a load of one is refused while the other has a settled version not
    in force, port49d builds the bundle from both and checks it against the bundle in force as one
    step. It passes, and one swap applies both; it fails, and neither is applied and one line names
    both. A whole-fleet re-address, where each file alone admits none, then loads, and no
    intermediate bundle revokes a context the final one keeps.
12. **`SIGHUP` re-reads two things from port49d.yaml,** `inventory.max_removed_percent` (6a) and
    `inventory.service.verify_key_files`, so a bound raised or a signing key rotated needs no
    restart. The service's CA file is read at every handshake, so a CA rotation needs neither. A
    restart ends every live login context (the store is in memory until plan 7). The verify keys are
    the trust root of decision 30, so they are read behind the write fence, as the policy file is
    (M3).
13. **No new reason code, decision event or diagnosis.** The swap port49d makes from a document
    writes the `inventory_change` records plan 6a defined. The service is not a decision point: its
    lines and metrics are its record.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **Normal day:** port49d says nothing. Every 30 s it asks `GET /v1/bundle/version` and finds the
  sequence it holds. `port49_inventory_snapshot_age_seconds` stays under 30.
- **A leaf is added to the source and synced:** the service says `port49-inventory: sync
  (schedule): published bundle 1843 (sha256:4c…): bundle sha256:9f… → sha256:4c…: +1 device(s), -0, 0
  changed; 0 quarantined`.
  Within 30 s each port49d says `port49d: inventory reloaded (inventory service, bundle 1843): bundle
  sha256:9f… → sha256:4c…: +1 device(s), -0, 0 changed; …` and writes the `device_added` record plan
  6a defined.
- **3am, the inventory service is down:** each port49d says once `port49d: inventory: the inventory
  service at https://inv:8443 did not answer (dial tcp …: connection refused); the bundle in force
  keeps serving, and port49_inventory_snapshot_age_seconds climbs` and keeps authenticating. `port49_inventory_snapshot_age_seconds` climbs, and
  `port49_inventory_fetches_total{outcome="failed"}` counts. When it answers again: `port49d:
  inventory: the inventory service at https://inv:8443 answers again`.
- **3am, the service is down and a port49d restarts in place:** it starts at once from
  `/var/lib/port49/inventory/bundle.json`: `port49d: inventory: starting from bundle 1842
  (sha256:9f…), the persisted copy, published 2026-10-01T02:00:00Z; the service at https://inv:8443
  is asked every 30s`. `port49_inventory_snapshot_age_seconds` counts from 02:00Z, not from the
  restart, so the staleness alarm stays up. If the mirror's mount has hung, the line before says
  `the mirror's copy is passed over: mirror_dir /mnt/port49-bundle did not answer in 10s`, and the
  start goes on.
- **3am, the service is down and a new pod lands on a fresh node:** it starts from the mirror, the
  line saying `the mirror's copy`. With no mirror configured it says `port49d: inventory: no bundle
  yet (persisted copy: none in /var/lib/port49/inventory; mirror: none configured; service at
  https://inv:8443: dial tcp …: connection refused); TACACS+ is not served until one arrives, and
  /readyz answers 503 (spec §10, cold start)`, retries every 30 s, and says a new reason when the
  reason changes. The other replicas keep serving; this one is not in the load balancer.
- **3am, a mistyped filter in the source drops half the fleet:** the service says once
  `port49-inventory: sync (schedule) refused; still publishing bundle 1842: source lab_file removes
  41 of 80 devices and refuses 0 more (51%), more than its safety.max_removed_percent (10%); fix the
  source, or, if the change is meant, raise safety.max_removed_percent in port49-inventory.yaml and
  restart port49-inventory`. `port49_inventory_sync_refused` is 1. port49d sees nothing new.
- **The same change, meant:** the operator raises the service's bound and restarts it; it publishes.
  Each port49d refuses the document by its own bound, once, with `port49_inventory_bundle_refused` at
  1: `…; fix the source of truth, or, if the change is meant, raise inventory.max_removed_percent in
  port49d.yaml and send SIGHUP, which re-reads it with the reload`. `SIGHUP` after raising it applies
  the document held.
- **The service's signing key is rotated:** until port49d.yaml lists the new public key, port49d
  says once `port49d: inventory reload (inventory service) refused; still serving bundle sha256:…
  (1900): the document does not open (bundle: the document is signed by ed25519:77aa…, which no
  verify key holds); if the service's signing key was rotated, add its public key to
  inventory.service.verify_key_files and send SIGHUP`, with `port49_inventory_bundle_refused` at 1.
  The documented order: add the new public key to every port49d's `verify_key_files` and `SIGHUP`;
  add the old public key to the service's own `verify_key_files`; switch its `signing_key_file` and
  restart it: it re-seals the bundle in force under the new key as bundle N+1, the fleet unchanged,
  its bound intact, and says so (final review I1); wait until every port49d's
  `port49_inventory_bundle_sequence` shows N+1; only then drop the old key from both. A
  document whose signature does not verify under a key port49d holds says instead `…; it was not
  signed by any key port49d holds for the service: investigate` — tampering, not a rotation.
- **A policy change reaches the service before port49d:** `port49d: inventory: the service built
  bundle 1843 against policy sha256:aa…, and the policy in force is sha256:bb…; its inventory is
  applied against the policy in force, and nothing the service sends changes the policy (spec §10)`,
  once; `port49_inventory_policy_mismatch` is 1 until port49d's own policy reload makes them agree,
  which is said too.
- **Someone adds `key_ref: lab_key` to a device in the service's source file:** the sync is refused,
  naming the device and the fix: a key group in the policy file matching the device by name,
  `{match: {name: leaf-01}, key_ref: lab_key}`, which is a pin (tier 1) under review.
- **The mirror's volume is re-provisioned empty, or a write to it failed:** the service writes it
  again at its next sync, and `port49_inventory_mirror_behind` is 1 until it has.
- **Someone with write access to the mirror bucket swaps its `bundle.json`:** a new pod refuses it
  (`does not verify`) and falls to the service. An older genuine copy verifies and is used until the
  first pull, 30 s later; the start line names its sequence and publication time.
- **An operator re-addresses the whole fleet with its key group:** they edit the policy's CIDR group
  and the inventory, then send `SIGHUP`; port49d says `port49d: policy and inventory reloaded together
  (SIGHUP): …` and no one is logged out.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–6a, and still binding:

- **Every claim about device or external-system behaviour cites a `tests/lab/results/` note or a
  register row.** A claim cited to an open row is unmeasured; do not "fix" a doc to assert it
  (CLAUDE.md, lab register rules 1–4). NetBox and Nautobot count (L27, L30).
- **A released platform set is never edited.** This plan edits none.
- **A blob fails closed; a quarantined device is closed without a reply; nothing logs a token.**
- **Every context write outside login goes through a narrow setter.** This plan adds none.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **A decode error prints a line and a category, never document text** (`internal/yamlfault`,
  plan 6a Task 15). This plan's YAML (port49-inventory.yaml, the new port49d.yaml keys) decodes
  through it, and its JSON decoders print fixed text and positions only.

New in this plan:

- **No secret reaches a log, an error or an output.** The signing key and every TLS key are read
  through `internal/keyfile` (no symlink, owner-only mode, regular file, bounded) and never printed; a
  key is named by its `key_id`, which is a hash of the public half. A test in each task that reads a
  secret-bearing file asserts that a decode error does not echo the file.
- **No new reason code, event or diagnosis** (Decided 13).
- **The code blocks are written against `3b830f4`.** They are not generated from a green commit.
  Where the compiler or a test says a block is wrong about the tree — a helper's name, an import —
  fix the block minimally, keep the behaviour the step's test asserts, and say so in the task's
  report and its commit. Never weaken a test to make a block pass.
- **Every commit is preceded by `make test && make vet`**, and by `make build`. Report their real
  output.
- **The lab tasks follow "Running the lab" below.** No new dependencies. Branch
  `feature/inventory-service`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Running the lab (Tasks 2, 19 and 20)

The lab host is beehive. Its containerlab holds one run at a time; Task 2 uses Docker Compose, not
containerlab, and may run while a code task is in progress, but never at the same time as Task 19 or
20 (all use the host's Docker). The owner has given standing consent for lab runs.

**Tasks 19 and 20 are containerlab runs** (Task 20 run first, straight after Task 2) and follow plan 5b's "Running the lab" exactly: one
platform per `go test` run, the harness's boot budgets (vEOS 6 min, vJunos-router 8 min, N9Kv 15
min, IOS-XE per `platforms` in `tests/lab/harness_test.go`) plus up to 8 min for TACACS+ readiness, a
deadline on every read where expiry is "not observed" and fails the run, and **a stall watchdog run
by the controller for the whole run** (`STALL=25` minutes, 40 on the N9Kv; Task 20's waits for
midnight are announced in its log every minute, so the watchdog sees a live log), which on a stall
or a `go test -timeout` panic destroys the topology, kills `bin/port49d`, `bin/port49-inventory` and
any `tcpdump` on `tests/lab/captures`. The watchdog script is plan 5b's, with `LOG`, `PID` and
`TOPO` set for the run, and `pkill -f bin/port49-inventory` added to its cleanup.

**Task 2 runs Docker Compose stacks** of NetBox and Nautobot, as plan 6a's Task 2 did, through
`tests/lab/sot/run.sh`, which already gives `/api/status/` and the recorder 10 minutes each and
tears the stack down on every exit. The controller still watches the log: a recorder that has not
written a line in 10 minutes is a stall, and a stalled run is never read as a result.

**Evidence.** Tasks 19 and 20 run `make evidence` after each run and commit the redacted captures
under `tests/lab/evidence/`, never `tests/lab/captures/`. If a run happened in a worktree, copy its raw
captures into the main checkout's `tests/lab/captures/` before removing the worktree, or the labpcap
audit fails. Task 2's evidence is its fixture files, which the recorder writes with no credential in
them. After every run confirm that no `port49d` still holds `172.100.100.1:49`, that no
`port49-inventory` is running, that the topology is destroyed, and that `docker compose ls` lists no
port49 stack.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §10, §12, §13 d29 d30, §14, §15 L29 L30 (Task 1); closed rows (Task 21)
docs/design/2026-08-21-port49-design.md       MOD  §6, §10, §12's inventory row, §17's internal interfaces (Task 1)
tests/lab/cmd/sot-record/main.go, seed.go     MOD  -devices, -page-limit, -proxy, GraphQL list candidates (Task 2)
tests/lab/sot/compose/*.yml, run.sh           MOD  an l30 proxy profile; nautobot-3.yml NEW (Task 2)
tests/lab/sot/l30/<stack>/                    NEW  recorded pages and lists; nautobot-3's full set (Task 2)
tests/lab/l30_unit_test.go                    NEW  the fixtures say what the notes say (Task 2)
internal/keyfile/ed25519.go                   NEW  LoadEd25519, ParseEd25519Public, EncodeEd25519, Ed25519KeyID (Task 3)
internal/admission/admission.go               MOD  KeyGroup.Name, the name tier in Assign (Task 3a)
internal/policy/admit.go, file.go             MOD  key_groups match.name (Task 3a)
cmd/port49/inventory.go                       MOD  inventory keygen (Task 3); Change.Line (Task 9); sync, diff --service (Task 12)
internal/bundle/bundle.go                     MOD  canonGroup.Name (Task 3a); Canonical exported (Task 4)
internal/bundle/document.go                   NEW  Document, NewDocument, Seal, Open, KeyIDOf, ETag, NameOK, TextOK,
                                                   DeviceProblem, ErrUnknownKey (Task 4)
internal/bundle/diff.go                       MOD  JSON tags and Change.Line (Task 9); CheckFrom, the key-group hint (Task 15)
internal/inventory/config.go                  NEW  port49-inventory.yaml (Task 5)
internal/fence/                               NEW  the write fence, moved from cmd/port49d unchanged (Task 6)
internal/inventory/source.go                  NEW  Source, FileSource, NewSources (Task 7)
internal/inventory/state.go                   NEW  State, Published, OpenFile, WriteAtomic (Task 8)
internal/inventory/sync.go, safety.go         NEW  Syncer, Result, the per-source bound (Task 9)
internal/inventory/metrics.go                 NEW  the service's metrics (Task 9)
internal/inventory/api.go, caller.go          NEW  the API, CallerOf, Server (Task 10)
internal/testpki/testpki.go                   MOD  Leaf.URIs; WriteInventoryLab (Task 10)
cmd/port49-inventory/main.go                  NEW  the service binary (Task 11)
Makefile                                      MOD  bin/port49-inventory (Task 11)
internal/inventory/client.go                  NEW  Client: Version, Bundle, Sync, Diff (Task 12)
internal/config/config.go                     MOD  inventory.service, VerifyKeys, InventoryServiceOf (Task 13)
internal/daemon/metrics/metrics.go            MOD  sequence, persist failed (Task 14); fetches, bundle refused (Task 15);
                                                   policy mismatch (Task 16)
cmd/port49d/policyfile.go                     MOD  wrappers over fence.Read (Task 6)
cmd/port49d/coldstart.go                      NEW  coldStart, readPersisted, readMirror, persistBundle (Task 14)
cmd/port49d/main.go                           MOD  metrics listener first, /readyz, the service path (Task 14); the fetcher (Task 15)
cmd/port49d/fetch.go                          NEW  fetcher, received (Task 15)
cmd/port49d/reload.go                         MOD  service mode (Task 14); receive, loadDocument (Task 15); policy match (Task 16);
                                                   loadBoth (Task 17)
cmd/port49d/service_e2e_test.go               NEW  the service and port49d together (Task 18)
tests/lab/l29_shell_test.go                   NEW  labShell, singleConnection, timedLogins, firstLine (Task 20)
tests/lab/l29_midnight_test.go                NEW  the midnight case (Task 20)
tests/lab/inventory_test.go                   NEW  the harness runs port49-inventory (Task 19)
tests/lab/l29_test.go                         NEW  L29's reload case and §14's quarantine through a sync (Task 19)
tests/lab/l29_unit_test.go                    NEW  every reload phase's edit, on the real lab inventory (Task 19)
tests/lab/results/L29-*.md, L30-*.md, quarantine-sync-*.md  NEW  written by the lab runs
docs/superpowers/plans/README.md              MOD  plan 6b as built, plan 6c's brief (Task 21)
```

Twenty-two tasks:
- **Task 1** is docs.
- **Task 2** is a lab measurement (L30), independent of the code; run it early, since plan 6c is
  written from its fixtures.
- **Task 20** is a lab measurement (L29's midnight case), four scheduled runs. It depends on none of
  Tasks 3–19: **execute it straight after Task 2**, commit its test on the branch, and run its nights
  while the code tasks go on ("The merge gate", above).
- **Tasks 3, 3a and 4–18** are code (Task 6 a refactor, Task 18 tests only). Every one leaves `make
  test` green.
- **Task 19** is a lab measurement (L29's reload case, and spec §14's quarantine through a sync)
  that needs Tasks 3a–17 and Task 20's shell helpers. It gates the merge.
- **Task 21** is lab closure and docs.

---

### Task 1: The spec and the design say what plan 6b builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Every later task cites the text this one writes. Each edit is given as the text to find
and the text to put in its place; where a paragraph is new, the text it goes after.

- [ ] **Step 1: §10, "The inventory service".** After the paragraph ending "rebuild the problem the
  component exists to prevent.", add:

  ```markdown
  **The API is mutual TLS on every path** (plan 6b). The service verifies each client certificate
  against one trust anchor and names the caller by the leaf's one URI SAN, verbatim, a workload's
  identity (design document §7), or, where there is none, `user:` and its one email SAN,
  lower-cased; a certificate with several of either is refused, since ambiguity fails closed. Two
  lists in the service's configuration decide what a caller may do: `readers` may read the bundle,
  its version, a diff, one device and health; `syncers` may do all of that and `POST /v1/sync`
  (design document §17: reading a snapshot is not the right to trigger a sync). Probes read
  `/healthz` and `/readyz` on the service's plain metrics listener, which carries no fleet data.

  **Four triggers are built in two plans.** The schedule (each source's `interval`, default the
  top-level `interval`, default 10 minutes; a sync of one source rebuilds the merged bundle from every
  source's latest fetch), startup,
  and `port49 inventory sync` are plan 6b's, with the file connector; the NetBox and Nautobot
  connectors and their authenticated webhooks are plan 6c's, written against the fixtures L27 and
  L30 recorded.
  ```

- [ ] **Step 2: §10, "One versioned bundle".** Replace the paragraph "This also closes a gap the
  documents otherwise leave open: **how policy reaches the broker** was previously unspecified."
  with:

  ```markdown
  This also closes a gap the documents otherwise leave open: **how policy reaches the broker** was
  previously unspecified. It reaches it from the broker's own `broker.policy_file`, reviewed and
  deployed beside port49d (§13, decision 29). The service holds the source-of-truth credentials and
  runs third-party connectors, and a compromise of it can already move devices between scopes and
  add addresses; taking policy from it too would let it grant anyone anything. The bundle document
  names the policy the service built it against (`policy_sha256`) and never carries one. port49d
  builds the bundle it runs on from its own policy and the document's inventory, as it builds it from
  two files. When the two hashes differ it still applies the inventory, against its own policy, says
  so once per pair of hashes, and sets `port49_inventory_policy_mismatch` to 1 until they agree:
  nothing the service sends changes the policy, and a policy rollout that reaches port49d before
  the service never stalls inventory.

  **The bundle document is signed** (§13, decision 30). It is the inventory in the canonical form
  the bundle's name hashes, with its `sequence` (the service's publication count, an integer), the
  `policy_sha256` and `platform_set` the service built it against, the device names each source
  gave (`sources`), and `published_at`, sealed as `{"document": …, "key_id": "ed25519:…",
  "signature": …}` with the service's ed25519 key over the document's exact bytes. The same sealed
  bytes are what the API serves, what the service keeps in its state directory and writes to the
  shared mirror, and what port49d persists, and port49d verifies them against the public keys in
  `inventory.service.verify_key_files` wherever they came from. A document carries **no key
  assignment**: no `key_groups`, and no device's `key_ref` pin. The service refuses a source that
  has either, and port49d refuses a document that does (§10, "Admission and keys": key assignment is
  reviewed policy). A pin is a policy key group matching the device by name (below). A document that
  does not verify, does not parse, carries a key assignment, or names a device with a control
  character or an unusable name is refused, said once, and alarmed
  (`port49_inventory_bundle_refused`), and the bundle in force keeps serving.
  ```

  Replace the paragraph beginning "**The service emits key *references*, never key material.**" with:

  ```markdown
  **The service emits no key assignment, and never key material.** A document carries a device's
  facts and no `key_ref`: port49d resolves each device's `key_ref` from its own policy's key groups
  and each `key_ref` from its own secret mount. A compromised inventory service leaks the fleet list,
  not the ability to speak to it, and cannot choose a device's key.
  ```

  In the "Consumers take what they need" table, replace the `broker` row with:

  ```markdown
  | broker | inventory (from the bundle), policy (its own `broker.policy_file`), platform set (the policy's pin) | resolves and compiles decisions |
  ```

- [ ] **Step 2b: §10, the pin tier (owner decision 3, Task 3a).** In "Key group matching is
  deterministic", replace the tier block with:

  ```
  1  a device record pinning key_ref (inventory_file), or a policy key group matching the
     device's name
  2  an attribute match
  3  the longest matching CIDR prefix
  ```

  and after "The device-pinned tier exists so an overlap can be resolved explicitly rather than by
  contorting the CIDR layout." add:

  ```markdown
  A pin in the policy is a key group matching one device name, `{match: {name: leaf-01}, key_ref:
  prod_key}`: it matches on the name alone, never with a CIDR or attributes, and outranks every
  attribute and CIDR group whatever the device's addresses. Two name groups for one device tie for
  every device they could match and are a policy load error. With `inventory_file`, a record pin and a
  name group that name different keys refuse that device alone. A key group on a `/32` is not a pin:
  it is tier 3, every attribute group outranks it, and it follows the address rather than the device.
  With the inventory service, a record carries no pin (§13, decision 30) and the policy name group is
  the only tier 1; the inventory `key_groups` fallback above is `inventory_file`'s alone.
  ```

  In "Device records", replace "`key_ref` pins a key (tier 1);" with "`key_ref` pins a key (tier 1,
  with `inventory_file` only; with the inventory service a pin is the policy's name group);".

- [ ] **Step 3: §10, "Connectors and sync cadence".** Replace the four trigger bullets' first line,
  "Four triggers, not one:", with "Four triggers, not one (the webhook is plan 6c's, with the
  connectors):". Replace the paragraph beginning "**Bounded change per sync.**" with:

  ```markdown
  **Bounded change per sync.** A sync in which a source takes more than its
  `safety.max_removed_percent` of the devices it gave the last published bundle out of service —
  removed, or kept and newly refused admission under the service's policy — MUST refuse, retain the
  last good snapshot, and alarm (`port49_inventory_sync_refused`). A source's bound defaults to the
  top-level `safety.max_removed_percent`, default 10. An empty result, and one the service's policy
  admits none of, are refused whatever the bound. A partially-available source of truth or a
  mistyped filter would otherwise silently deauthorize the fleet. Each port49d bounds the document
  again by its own `inventory.max_removed_percent`: a deliberate large removal raises both.
  ```

  Replace the YAML block after "Ship an alias table, …" with:

  ```yaml
  # port49-inventory.yaml (plan 6b: the file source; netbox and nautobot are plan 6c's)
  listen: ":8443"
  metrics_listen: ":9050"
  tls_cert_file: /etc/port49-inventory/server.pem
  tls_key_file: /etc/port49-inventory/server-key.pem
  client_ca_file: /etc/port49-inventory/clients-ca.pem
  readers: ["spiffe://example.com/port49d"]
  syncers: ["user:alice@example.com", "spiffe://example.com/policy-ci"]
  signing_key_file: /etc/port49-inventory/signing.key
  policy_file: /etc/port49-inventory/policy.yaml
  state_dir: /var/lib/port49-inventory
  mirror_dir: /mnt/port49-bundle
  interval: 10m                     # a source's default
  safety: {max_removed_percent: 10}
  sync:
    - name: lab_file
      type: file
      path: /etc/port49-inventory/inventory.yaml
      interval: 10m
      safety: {max_removed_percent: 10}
    # plan 6c:
    # - name: netbox_prod
    #   type: netbox
    #   url: https://netbox.example.com
    #   token_secret_ref: vault:port49/prod/netbox   # resolved like a key secret_ref, never inline
    #   interval: 10m
    #   filter: {status: active, has_primary_ip: true}
    #   map: {site: site.slug, role: role.slug, platform: platform.slug, os_version: custom_fields.os_version}
  ```

  After it add:

  ```markdown
  A device whose name is not 1–255 bytes of printable ASCII without a space, or whose platform or
  attributes carry a control character, is left out of the sync, said and counted: it could not
  reach a record or a line safely, and the broker refuses to mint for such a name anyway.
  ```

- [ ] **Step 4: §10, "How a daemon refreshes its snapshot".** Replace the pseudo-code block with:

  ```
  every 30s (inventory.service.poll_interval):
    GET /v1/bundle/version
    if etag == held.etag:  done                     ← the common case
    GET /v1/bundle  (If-None-Match: <etag>)
    verify signature → parse → build index → validate → bound → atomic pointer swap → persist
  ```

  Replace "1. **The last good bundle is persisted to local disk** (a MUST, not a SHOULD), so a
  restart in place needs nothing." and item 2 with:

  ```markdown
  1. **The last good bundle is persisted to local disk** (a MUST, not a SHOULD), so a restart in
     place needs nothing: port49d writes each document it applies to
     `inventory.service.state_dir/bundle.json`, atomically, mode 0600, and reads it at start behind
     the policy file's write fence.
  2. **A shared object-store location** holds the most recent bundle, written by the inventory
     service and readable by daemons. A pod scheduled onto a fresh node reads that and serves. The
     location is a directory the deployment mounts (`mirror_dir` on both sides): port49 speaks no
     object-store API. The copy is signed, so whoever can write the store can replay an older
     genuine bundle and never forge one; the start line names the sequence and publication time it
     started from, and the first pull replaces it.

  At start port49d verifies both copies and starts from the one published later (`published_at`,
  which survives a sequence reset). It asks
  the service at start only when it has neither, and until a bundle arrives it keeps its TACACS+
  listener closed, so a device finds the connection refused and falls to its next server or its
  local method at once (§15, L4), and `/readyz` on the metrics listener answers 503. It says why
  once per distinct reason and asks again every `poll_interval`.
  ```

  Replace the paragraph beginning "**Until plan 6b, the snapshot is `inventory_file`.**" up to its
  first sentence's end with "**With `inventory_file`, the snapshot is the file.**" (the rest of the
  paragraph stands), and after that paragraph add:

  ```markdown
  **With `inventory.service`, the snapshot is the service's document**, and `inventory_file` is
  absent: port49d.yaml naming both is refused, as is `inventory.service` without a `broker:` block.
  A document is a reload like a file's: parsed against the policy in force, bounded by
  `inventory.max_removed_percent` (`fix the source of truth, or, …`), swapped in one pointer, its
  security changes written as `inventory_change` records, and followed by the refresh. A refused one
  is said once per document, `port49_inventory_bundle_refused` is 1, and `SIGHUP` tries the
  document held again after the bound is raised. `SIGHUP` also re-reads
  `inventory.service.verify_key_files`, read behind the write fence as the policy file is, since
  whoever can write a verify key accepts any inventory it signs; so a signing-key rotation needs no
  restart. `port49_inventory_snapshot_age_seconds` is the time since the service last confirmed the
  document in force, or one was loaded; a start from the persisted copy or the mirror counts it from
  that document's `published_at`, so a restart never makes an old snapshot look fresh. The mirror is
  read under a 10 s deadline at start: a hung mount is passed over, said, and never holds up a start
  from the persisted copy.

  **A reload of either source tries both together when both have moved.** At `SIGHUP`, and whenever
  a load of one is refused while the other holds a settled version not in force, port49d builds the
  bundle from both and bounds it against the bundle in force as one step, by `bundle.Check` and the
  policy's bound together. It passes and one swap applies both; it fails and neither is applied, one
  line naming both. A whole-fleet re-address with its key group — where each file alone admits none —
  then loads, and no bundle between the two revokes a context the final one keeps.
  ```

- [ ] **Step 5: §12, Tooling.** After the paragraph for `port49 inventory diff`, add:

  ```markdown
  **`port49 inventory sync --service <url> --ca <file> --cert <file> --key <file>`** asks the
  inventory service to sync now (`POST /v1/sync`, the `syncers` right) and prints its outcome:
  `published`, with the sequence, the swap's summary and every security change marked `!`;
  `unchanged`; `refused`, with why; or `failed`. It exits 0 on `published` and `unchanged`, and 1
  otherwise. **`port49 inventory diff --service <url> … --from <sequence>`** prints what changed
  between that published bundle and the latest, as `inventory diff` prints two files, the
  inventory's change judged under the policy the service holds now; the service keeps the last 64.
  **`port49 inventory keygen --dir <dir>`** writes the service's signing key (`signing.key`, 0600)
  and its public half (`signing.pub`), refuses to overwrite either, and prints the `key_id`.
  ```

  Replace "**Rollback** is `git revert` of the policy change and `port49 inventory sync`;" with
  "**Rollback** is `git revert` of the policy change, deployed to port49d's `broker.policy_file`
  and the service's `policy_file`, and `port49 inventory sync`;".

- [ ] **Step 6: §13.** After decision 28, add:

  ```markdown
  **29. port49d takes only the inventory from the service; the policy stays its own.** *Plan 6a
  owner decision 3, built in plan 6b, 2026-09-30.* The service's bundle names the policy it was
  built against and carries none. port49d builds its bundle from its own `broker.policy_file` and
  the service's inventory, and a hash mismatch is said and alarmed (`port49_inventory_policy_mismatch`),
  never applied: the service holds third-party credentials and connectors, and a compromise of it
  must not reach the grants.

  **30. The bundle document is signed, and assigns no key.** *Plan 6b, 2026-09-30, owner decisions
  1 and 3 at their defaults.* The service signs each document with ed25519 and port49d verifies every
  copy — the API's, its own persisted one, the mirror's — against the keys in
  `inventory.service.verify_key_files`, so a shared mirror mount's writers cannot forge an
  inventory. A document carries neither key groups nor pins: key assignment is reviewed policy, and a
  synced source's writer choosing a device's key is an escalation with no diff; a pin is a policy key
  group matching the device's name, at tier 1 (§10). The service reads its own state and mirror against its own
  `verify_key_files`, so rotating its signing key keeps its sequence and its bound.
  ```

  In decision 28, replace "Plan 6b adds the service as a second source of the same bundle; whether
  port49d then takes the policy from it is an owner decision recorded in plan 6a." with "Plan 6b
  adds the service as the other source of the same bundle's inventory; the policy stays port49d's
  own (decision 29)."

- [ ] **Step 7: §14, "Inventory and capability".** Replace the "**Cold start**" bullet with:

  ```markdown
  - **Cold start**: a daemon with no snapshot keeps its TACACS+ listener closed and `/readyz` at
    503, and retries, while existing replicas keep serving; a daemon restarted with the inventory
    service down starts from its persisted bundle, one scheduled onto a fresh node starts from the
    shared mirror's copy, and with both it starts from the one published later (`published_at`,
    which survives a sequence reset).
  - **The document is verified everywhere**: a document the service did not sign — from the API,
    the persisted copy or the mirror — is refused and the bundle in force keeps serving; one carrying
    a key group, a `key_ref` pin, or a name with a control character is refused; a signing key
    added to `verify_key_files` takes effect at `SIGHUP`.
  - **Policy mismatch**: a document built against another policy is applied against the policy in
    force, said, and alarmed, and changes no grant.
  - **The service bounds each source**: a source that removes or newly refuses more than its bound
    of the devices it gave last time refuses the sync, and the last published bundle keeps being
    served; each daemon bounds the document again.
  - **Both sources at once**: a whole-fleet re-address, where each source alone admits no device,
    loads at `SIGHUP` as one swap, and no live context on a device the final bundle admits is revoked.
  - **API rights**: a reader cannot trigger a sync, a certificate the anchor does not verify gets no
    answer, and one with two URI SANs is refused.
  - **A pin in the policy**: a key group matching a device's name assigns its key at tier 1, over an
    attribute group and over every address's CIDR group; two name groups for one device refuse the
    policy.
  - **One rule for a usable device**: whatever the service publishes, port49d opens.
  ```

- [ ] **Step 8: §15.** In L29's Status, replace "Owner: plan 6b, the next plan with a device lab
  run (spec §14's quarantine through a sync), whose syncs make the reload case routine" with "Owner:
  plan 6b: its Task 19 measures the reload case through the service's syncs, and its Task 20 the
  `retire_after` case, one scheduled run across 00:00:00Z per platform". In L30's Status, replace
  "Owner: plan 6b" with "Owner: plan 6b, whose Task 2 records it; plan 6c's connectors are written
  against its fixtures", and in its Decides column replace "Plan 6b's connectors" with "Plan 6c's
  connectors". In L29's Status, add: "The midnight case measures behaviour plan 6a shipped, so plan 6b
  merges on the reload case; nights after the merge land through a lab pull request."

- [ ] **Step 9: Design document.** In §6, after the paragraph beginning "**Inventory service.**",
  add: "It is `port49-inventory` (plan 6b): a mutual-TLS API with read and sync rights, a signed
  bundle document kept in its state directory and written to a shared mirror, and, from plan 6c,
  the NetBox and Nautobot connectors." In §10 "Device inventory", replace "Until plan 6b builds the
  service, port49d builds the bundle from its own two files and bounds an inventory reload the same
  way (policy engine spec §10, decision 28)." with "The service bounds each source against what it
  gave last time, and each port49d bounds the document again, as it bounds its own inventory file
  (policy engine spec §10, decision 28)." In §12's failure matrix, replace the "Inventory service
  unavailable" row's parenthesis "(until plan 6b, the snapshot is `inventory_file`, and a refused
  edit leaves the bundle in force serving)" with "(the snapshot in force, or on a restart the
  persisted copy or the mirror's, never expiring; a daemon with neither stays unready with its
  listener closed, policy engine spec §10)". In §17 "Internal interfaces", replace the row
  `| daemon → inventory service | workload certificate | read a snapshot |` with
  `| daemon → inventory service | workload certificate, listed in `readers` | read a snapshot |` and
  the row for `POST /v1/sync` with `| operator or CI → `POST /v1/sync` | operator or CI certificate, listed in `syncers` | trigger a sync |`.

- [ ] **Step 10: Check the edits against the tree.** Run:

  ```bash
  grep -n "Until plan 6b" docs/design/*.md
  grep -n "decision 29\|decision 30" docs/design/2026-08-23-policy-engine-spec.md | head
  ```

  Expected: the first prints nothing; the second prints the new decisions and the references to
  them.

- [ ] **Step 11: Commit**

```bash
git add docs/design
git commit -m "docs(spec): the inventory service, its signed bundle and port49d's pull (plan 6b)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: (lab, on beehive) How NetBox and Nautobot page, and what Nautobot 3.x returns: L30

**Files:**
- Modify: `tests/lab/cmd/sot-record/main.go`, `tests/lab/cmd/sot-record/seed.go`
- Modify: `tests/lab/sot/run.sh`, `tests/lab/sot/README.md`, `tests/lab/sot/compose/{netbox-3.7,netbox-4,nautobot-1.6,nautobot-2}.yml`
- Create: `tests/lab/sot/compose/nautobot-3.yml`
- Create: `tests/lab/l30_unit_test.go`
- Create (by the runs): `tests/lab/sot/l30/<stack>/*.json`, `tests/lab/results/L30-netbox.md`, `tests/lab/results/L30-nautobot.md`

**Interfaces:**
- Consumes: the recorder as plan 6a Task 2 built it (`recorder.call`, `callAs`, `write`, `remember`,
  `seedFor`, `graphQLCandidates`, `webhookSteps`); `run.sh`.
- Produces: fixtures plan 6c's connector tests replay. Per stack, under `tests/lab/sot/l30/<stack>/`:
  `seed-bulk.json` (the bulk create's status and count), `rest-pages.json` (every page of a REST list
  followed by `next` to the end: status, `count`, `next`, `previous`, the names), `rest-page-proxied.json`
  (the first page read through a reverse proxy), `graphql-list.json` (each list query candidate:
  status, errors, how many names). For `nautobot-3`, also every L27 file (`status.json`,
  `api-root.json`, `seed.json`, `rest-device.json`, `rest-device-depth1.json`, `rest-page.json`,
  `graphql.json`, `webhooks.json`).

L30's questions (spec §15): for each of NetBox 3.7 and 4.x and Nautobot 1.6 and 2.x, a REST list
holding more devices than its `limit` — whether `next` is an absolute URL, which host and scheme it
carries behind a proxy, whether following it to the end returns every device once — and how GraphQL
pages the same list, if at all; and for Nautobot 3.x, every L27 question. The recorder already
answers every L27 question for any version it is pointed at; this task adds the list and seeds
enough devices to page.

- [ ] **Step 1: Write the failing unit test.** Create `tests/lab/l30_unit_test.go`:

```go
//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestL30FixturesAreWhatTheNotesSay reads every L30 fixture directory: each
// file parses and carries no credential, the product's note names the
// directory as a capture pointer, and rest-pages.json followed `next` to a
// null and saw every device it counted exactly once — the claim L30 exists
// to make — or the note says it did not.
func TestL30FixturesAreWhatTheNotesSay(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("sot", "l30", "*"))
	if len(dirs) == 0 {
		t.Skip("no L30 fixtures recorded yet")
	}
	for _, dir := range dirs {
		product := strings.SplitN(filepath.Base(dir), "-", 2)[0]
		note, err := os.ReadFile(filepath.Join("results", "L30-"+product+".md"))
		if err != nil {
			t.Fatalf("%s has fixtures and no note: %v", dir, err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l30/"+filepath.Base(dir)+"/") {
			t.Errorf("L30-%s.md does not name %s as a capture pointer", product, dir)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, path := range files {
			raw, err := os.ReadFile(path)
			if err != nil || !json.Valid(raw) {
				t.Fatalf("%s: unreadable or not JSON: %v", path, err)
			}
			if strings.Contains(string(raw), `"Authorization"`) || l27Credential.Match(raw) {
				t.Fatalf("%s carries a credential", path)
			}
		}
		raw, err := os.ReadFile(filepath.Join(dir, "rest-pages.json"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var pages struct {
			Count    int      `json:"count"`
			Names    []string `json:"names"`
			EndedAt  string   `json:"ended_at"`
			Repeated []string `json:"repeated"`
		}
		if err := json.Unmarshal(raw, &pages); err != nil {
			t.Fatal(err)
		}
		complete := pages.EndedAt == "null_next" && len(pages.Names) == pages.Count && len(pages.Repeated) == 0
		if !complete && !strings.Contains(string(note), filepath.Base(dir)+": the list did not page to the end once") {
			t.Errorf("%s: %d of %d names, ended at %q, repeated %v, and the note does not say so",
				dir, len(pages.Names), pages.Count, pages.EndedAt, pages.Repeated)
		}
	}
}
```

- [ ] **Step 2: Run it.** `go test -tags lab ./tests/lab/ -run '^TestL30FixturesAreWhatTheNotesSay$' -count=1`
  Expected: SKIP ("no L30 fixtures recorded yet").

- [ ] **Step 3: Seed many devices, and read the list to its end.** In
  `tests/lab/cmd/sot-record/main.go`, add three flags to `main`:

```go
	devices := flag.Int("devices", 1, "L30: create this many devices in all (leaf-01 and leaf-002..), to make a list page")
	pageLimit := flag.Int("page-limit", 50, "L30: the REST limit and the GraphQL page size")
	proxy := flag.String("proxy", "", "L30: a reverse proxy's base URL in front of -url, to read one page through")
```

  and, after `r.write("graphql.json", gql)`, before the webhook steps:

```go
	if *devices > 1 {
		r.write("seed-bulk.json", r.seedMany(*product, *devices))
		r.write("rest-pages.json", r.pages(*pageLimit))
		if *proxy != "" {
			r.write("rest-page-proxied.json", r.viaProxy(*proxy, *pageLimit))
		}
		r.write("graphql-list.json", r.graphQLList(*product, gqlPath, *pageLimit))
	}
```

  Add to `tests/lab/cmd/sot-record/seed.go`:

```go
// seedMany creates devices leaf-002 .. leaf-<n> beside leaf-01, in one bulk
// POST per hundred (both products take a JSON list on the device endpoint),
// each naming the objects leaf-01's seed created. Only each call's status and
// how many it created are recorded: the bodies are leaf-01's shape n times.
func (r *recorder) seedMany(product string, n int) []map[string]any {
	var out []map[string]any
	for start := 2; start <= n; start += 100 {
		var batch []any
		for i := start; i < start+100 && i <= n; i++ {
			d := map[string]any{"name": fmt.Sprintf("leaf-%03d", i), "device_type": "@device_type.id",
				"platform": "@platform.id", "status": "active"}
			if product == "nautobot" {
				d["status"] = "Active"
				d["role"], d["location"] = "@role.id", "@location.id"
				if r.legacy {
					d["status"], d["device_role"], d["site"] = "active", "@role_v1.id", "@site_v1.id"
					delete(d, "role")
					delete(d, "location")
				}
			} else {
				d["role"], d["site"] = "@role.id", "@site.id"
			}
			batch = append(batch, d)
		}
		x := r.call(fmt.Sprintf("bulk_%d", start), "POST", "/api/dcim/devices/", batch)
		var created []any
		_ = json.Unmarshal(x.Body, &created)
		out = append(out, map[string]any{"step": x.Step, "status": x.Status, "sent": len(batch), "created": len(created)})
		fmt.Printf("sot-record: bulk %d: %d, %d created\n", start, x.Status, len(created))
	}
	return out
}

// pages reads the device list limit at a time and follows each `next` as the
// product wrote it, to a null or 100 pages, recording per page the status,
// count, next and previous, and in all every name seen and every name seen
// twice. next is followed verbatim — host, scheme and all — since whether it
// can be is the question.
func (r *recorder) pages(limit int) map[string]any {
	next := fmt.Sprintf("%s/api/dcim/devices/?limit=%d", r.base, limit)
	var pages []map[string]any
	seen := map[string]bool{}
	var names, repeated []string
	count, ended := 0, "page_cap"
	for i := 0; i < 100 && next != ""; i++ {
		x := r.callURL(fmt.Sprintf("page_%d", i), next)
		var body struct {
			Count    int     `json:"count"`
			Next     *string `json:"next"`
			Previous *string `json:"previous"`
			Results  []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		_ = json.Unmarshal(x.Body, &body)
		pages = append(pages, map[string]any{"step": x.Step, "url": next, "status": x.Status, "count": body.Count,
			"next": body.Next, "previous": body.Previous, "results": len(body.Results)})
		if x.Status != 200 {
			ended = fmt.Sprintf("status_%d", x.Status)
			break
		}
		count = body.Count
		for _, d := range body.Results {
			if seen[d.Name] {
				repeated = append(repeated, d.Name)
			}
			seen[d.Name] = true
			names = append(names, d.Name)
		}
		next = ""
		if body.Next != nil {
			next = *body.Next
		} else {
			ended = "null_next"
		}
	}
	return map[string]any{"limit": limit, "pages": pages, "count": count, "names": names, "repeated": repeated,
		"ended_at": ended}
}

// viaProxy reads the first page through the reverse proxy, which forwards
// the client's Host and sets X-Forwarded-Proto: https and X-Forwarded-Host,
// and records the next the product wrote there.
func (r *recorder) viaProxy(proxy string, limit int) exchange {
	return r.callURL("page_proxied", fmt.Sprintf("%s/api/dcim/devices/?limit=%d", proxy, limit))
}

// graphQLList asks for every device's name through each list shape a version
// might take — unpaged, and paged by the version's own arguments — and
// records how many names each returned, so a silent page cap shows.
func (r *recorder) graphQLList(product, path string, limit int) []map[string]any {
	var out []map[string]any
	for i, q := range graphQLListCandidates(product, limit) {
		x := r.call(fmt.Sprintf("graphql_list_%d", i), "POST", path, map[string]any{"query": q})
		var body struct {
			Data   map[string][]map[string]any `json:"data"`
			Errors []any                       `json:"errors"`
		}
		_ = json.Unmarshal(x.Body, &body)
		n := 0
		for _, list := range body.Data {
			n += len(list)
		}
		out = append(out, map[string]any{"step": x.Step, "query": q, "status": x.Status, "names": n,
			"errors": body.Errors})
	}
	return out
}

func graphQLListCandidates(product string, limit int) []string {
	if product == "nautobot" {
		return []string{
			`{ devices { name status { name } } }`,
			fmt.Sprintf(`{ devices(limit: %d, offset: 0) { name } }`, limit),
			fmt.Sprintf(`{ devices(limit: %d, offset: %d) { name } }`, limit, limit),
		}
	}
	return []string{
		`{ device_list { name status } }`,
		fmt.Sprintf(`{ device_list(pagination: {offset: 0, limit: %d}) { name } }`, limit),
		fmt.Sprintf(`{ device_list(pagination: {offset: %d, limit: %d}) { name } }`, limit, limit),
		fmt.Sprintf(`{ device_list(limit: %d, offset: 0) { name } }`, limit),
	}
}
```

  `callURL` is `call` for an absolute URL, which `next` is on every version if L30 finds it so; add
  it beside `callAs` in `main.go`:

```go
// callURL is call for a full URL, as a list's `next` gives one: the base is
// not prepended, and the credential goes only to the recorder's own base or
// proxy host, never to a host a response named.
func (r *recorder) callURL(step, full string) exchange {
	u, err := url.Parse(full)
	if err != nil {
		return exchange{Step: step, Method: "GET", Path: full, Status: 0, Headers: map[string]string{},
			Body: json.RawMessage(`"not a URL"`)}
	}
	if !r.ownHost(u.Host) {
		// Recorded, never followed: the token would go to wherever next says.
		return exchange{Step: step, Method: "GET", Path: full, Status: 0, Headers: map[string]string{},
			Body: json.RawMessage(`"next names a host the recorder did not dial; not followed"`)}
	}
	saved := r.base
	r.base = u.Scheme + "://" + u.Host
	defer func() { r.base = saved }()
	return r.call(step, "GET", u.RequestURI(), nil)
}
```

  with `ownHost(h string) bool` true for the host of `-url` and of `-proxy` (store both on the
  recorder when `main` parses them), and `net/url` added to the imports. A `next` naming another
  host is itself the finding: the page records `ended_at` as `status_0` and the body says why.

- [ ] **Step 4: The proxy, and Nautobot 3.x.** Add to each of the four compose files a service in
  a profile, so the L27 runs are unchanged:

```yaml
  proxy:
    profiles: ["l30"]
    image: docker.io/library/nginx:1.27-alpine@sha256:<digest resolved at run time, written here>
    ports: ["127.0.0.1:${L30_PROXY_PORT:?}:8080"]
    volumes: ["./l30-proxy.conf:/etc/nginx/conf.d/default.conf:ro"]
    depends_on: [netbox]   # nautobot in the Nautobot files
```

  and create `tests/lab/sot/compose/l30-proxy.conf`:

```nginx
# L30: a reverse proxy in front of the product, as a production install has one.
# It forwards the Host the client used and says the client spoke https.
server {
    listen 8080;
    location / {
        proxy_pass http://netbox:8080;   # run.sh substitutes nautobot:8080 for Nautobot
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

  Create `tests/lab/sot/compose/nautobot-3.yml` from `nautobot-2.yml`, the image
  `docker.io/networktocode/nautobot:3.2.6@sha256:<digest>` (resolve the newest `3.*` tag and its
  digest with `docker buildx imagetools inspect docker.io/networktocode/nautobot:3.2` on the run
  day; write the tag you ran into the file and the note). In `run.sh`: add `nautobot-3) product=nautobot
  port=18030 project=port49-l27-nautobot3 ;;` to the stack `case`, `nautobot-3) flags+=(-depth1-read)
  ;;` to the flags `case`, and a second-argument mode `l30`:

```bash
[ -z "$legacy" ] || [ "$legacy" = legacy ] || [ "$legacy" = l30 ] ||
	{ echo "run.sh: second argument is 'legacy', 'l30' or nothing" >&2; exit 64; }
# ...
if [ "$legacy" = l30 ]; then
	suffix=""
	out=$root/tests/lab/sot/l30/$stack
	log=$root/tests/lab/logs/l30-$stack.log
	export L30_PROXY_PORT=$((port + 1000))
	upstream=netbox; [ "$product" = nautobot ] && upstream=nautobot
	sed "s/netbox:8080/$upstream:8080/" "$root/tests/lab/sot/compose/l30-proxy.conf" >"$tmp/l30-proxy.conf"
	flags+=(-devices 120 -page-limit 50 -proxy "http://127.0.0.1:$L30_PROXY_PORT")
	profile=(--profile l30)
fi
```

  with `dc()` passing `"${profile[@]}"` before the subcommand, the proxy's volume reading
  `$tmp/l30-proxy.conf` (pass it as `L30_PROXY_CONF` and use `${L30_PROXY_CONF:?}` in the compose
  file), and `legacy=""` for the `-prefer-legacy` test (`[ "$legacy" = legacy ] && flags+=(-prefer-legacy)`).
  For Nautobot 1.6, run `l30` with `-prefer-legacy` added, since 1.6 took only the legacy spelling (L27):
  `run.sh nautobot-1.6 l30` adds it when `stack` is `nautobot-1.6`. Update `README.md`'s table and its
  Running block with the `l30` runs.

- [ ] **Step 5: Build the recorder.** `go build -o /dev/null ./tests/lab/cmd/sot-record && make vet`
  Expected: exit 0.

- [ ] **Step 6: Run the five stacks, one at a time.**

```bash
tests/lab/sot/run.sh netbox-3.7 l30
tests/lab/sot/run.sh netbox-4 l30
tests/lab/sot/run.sh nautobot-1.6 l30
tests/lab/sot/run.sh nautobot-2 l30
tests/lab/sot/run.sh nautobot-3 l30      # also records every L27 file: the L27 question set for 3.x
```

  Each writes `tests/lab/sot/l30/<stack>/`. For each, check its log for `bulk … created`: a bulk
  POST refused (400) is recorded, and the note says it, but then no list pages; fix the seed shape
  (the refusal body names the field, as L27's did) and run again. A run that pages fewer than 120
  devices is not a result unless the note says why the list stopped (`<stack>: the list did not page
  to the end once`, which the unit test reads): a `next` naming a host the recorder did not dial is a
  finding, not a failure.

- [ ] **Step 7: Write the notes.** Create `tests/lab/results/L30-netbox.md` and
  `tests/lab/results/L30-nautobot.md` in the L27 notes' format: date, product and versions (from each
  `status.json`, and for NetBox and Nautobot 1.6/2.x from the L27 note, since the same images ran),
  images by digest (the proxy's too), compose files, run commands, capture pointers
  (`tests/lab/sot/l30/<stack>/`), credentials (as L27's), the claim, and an observation table with
  one column per version and these rows, each cell quoting the fixture it was read from:
  - `next` on the first page read directly: absolute or relative; its scheme, host and port.
  - `next` on the first page read through the proxy (`rest-page-proxied.json`): its scheme and
    host, and whether it names the proxy's host or the product's own.
  - following `next` to the end: pages, `ended_at`, names seen, `count`, repeats.
  - each GraphQL list candidate: status, errors, names returned; whether an unpaged list returned
    all 120, and which paged shape (if any) the version took.
  - GraphQL `status` in the unpaged candidate: the value's spelling (for plan 6c's filter).
  - For Nautobot 3.x: every row of `L27-nautobot.md`'s table, read from `tests/lab/sot/l30/nautobot-3/`.
  A stack whose list did not page to the end once says `<stack>: the list did not page to the end
  once` and why, which the unit test reads. Also a "Not observed" section, as L27's.

- [ ] **Step 8: Run the unit test.** `make lab-unit`
  Expected: `TestL30FixturesAreWhatTheNotesSay` and `TestL27FixturesAreWhatTheNotesSay` PASS.

- [ ] **Step 9: The count-only secret audit.** Run each stack once more with `L27_ENV_DIR` set (or
  keep the env files from Step 6 by setting it then) and run README's audit loop over
  `tests/lab/sot tests/lab/results/L30-*.md`. Expected: `0`.

- [ ] **Step 10: Commit**, after `make build && make test && make vet` (expected: exit 0; the commit
  carries Go code, the recorder and a unit test):

```bash
git add tests/lab/cmd/sot-record tests/lab/sot tests/lab/l30_unit_test.go tests/lab/results/L30-*.md
git commit -m "test(lab): L30, how NetBox and Nautobot page and what Nautobot 3.x returns

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  The row stays open until Task 21 closes it (lab register rule 3); the commit says what was
  measured and what was not.

---

### Task 3: The signing key, and `port49 inventory keygen`

**Files:**
- Create: `internal/keyfile/ed25519.go`
- Test: `internal/keyfile/ed25519_test.go`
- Modify: `cmd/port49/inventory.go`, `cmd/port49/main.go` (usage)
- Test: `cmd/port49/inventory_test.go`

**Interfaces:**
- Consumes: `keyfile.readPrivate` (unexported, same package): no symlink, a regular file, owned by
  port49's user or root, no group or other bit, at most 1 MiB, non-blocking.
- Produces:
  - `func keyfile.LoadEd25519(path string) (ed25519.PrivateKey, error)` — the service's signing key.
  - `func keyfile.ParseEd25519Public(raw []byte, path string) (ed25519.PublicKey, error)` — a verify
    key from bytes already read; `path` names it in errors. It does not read the file: a verify key
    is the trust root of decision 30, so its reader is the write fence (`config.VerifyKeys`, Task 13;
    pre-flight M3), which moves into `internal/fence` only in Task 6.
  - `func keyfile.EncodeEd25519(priv ed25519.PrivateKey) (privPEM, pubPEM []byte, err error)`.
  - `func keyfile.Ed25519KeyID(pub ed25519.PublicKey) string` — `ed25519:` and the first 16 hex of
    the public key's sha256: the name every line gives a key.
  - `port49 inventory keygen --dir DIR`.

- [ ] **Step 1: Write the failing tests.** Create `internal/keyfile/ed25519_test.go`:

```go
package keyfile

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeKey(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnEd25519KeyRoundTrips(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, pubPEM, err := EncodeEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadEd25519(writeKey(t, privPEM, 0o600))
	if err != nil || !got.Equal(priv) {
		t.Fatalf("private: %v", err)
	}
	pubPath := filepath.Join(t.TempDir(), "signing.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := ParseEd25519Public(pubPEM, pubPath)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("public: %v", err)
	}
	if id := Ed25519KeyID(pub); !regexp.MustCompile(`^ed25519:[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("key id %q", id)
	}
}

// The signing key is read as every private key is: owner-only.
func TestAGroupReadableSigningKeyIsRefused(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, _, _ := EncodeEd25519(priv)
	if _, err := LoadEd25519(writeKey(t, privPEM, 0o640)); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
}

// A key of another kind, and a file that is not a key, are refused, and the
// refusal never quotes the file: it may be a secret pasted in the wrong place.
func TestAnythingButAnEd25519KeyIsRefusedWithoutEchoingIt(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	for name, body := range map[string][]byte{
		"ecdsa":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"garbage": []byte("SECRET-hunter2-not-a-key\n"),
		"broken":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("SECRET-bytes")}),
	} {
		_, err := LoadEd25519(writeKey(t, body, 0o600))
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseEd25519Public([]byte("SECRET-not-a-public-key"), "x.pub"); err == nil ||
		strings.Contains(err.Error(), "SECRET") {
		t.Errorf("public: %v", err)
	}
}
```

  Add to `cmd/port49/inventory_test.go`:

```go
func TestInventoryKeygenWritesAPairOnceAndNamesIt(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "keygen", "--dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	fi, err := os.Stat(filepath.Join(dir, "signing.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("signing.key: %v %v", fi, err)
	}
	priv, err := keyfile.LoadEd25519(filepath.Join(dir, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(filepath.Join(dir, "signing.pub"))
	pub, err := keyfile.ParseEd25519Public(pubPEM, "signing.pub")
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("signing.pub: %v", err)
	}
	if !strings.Contains(out.String(), keyfile.Ed25519KeyID(pub)) {
		t.Fatalf("the key id is not printed: %s", out.String())
	}
	// Never over an existing key: that would strand every port49d verifying
	// against the old public half.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"inventory", "keygen", "--dir", dir}, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "already exists") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	// One file present: refused before either is written, so no lone new
	// private key is left beside an old public one (conflict scan F14).
	lone := t.TempDir()
	os.WriteFile(filepath.Join(lone, "signing.pub"), []byte("old"), 0o644)
	errOut.Reset()
	if code := run([]string{"inventory", "keygen", "--dir", lone}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(lone, "signing.key")); err == nil {
		t.Fatal("a lone signing.key was left")
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/keyfile/ ./cmd/port49/ -run 'Ed25519|SigningKey|Keygen' -count=1`
  Expected: FAIL (undefined: `EncodeEd25519`, `LoadEd25519`, …).

- [ ] **Step 3: Implement.** Create `internal/keyfile/ed25519.go`:

```go
package keyfile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// LoadEd25519 reads the inventory service's signing key (spec §13, decision
// 30): one PKCS#8 "PRIVATE KEY" block holding an ed25519 key, read with
// readPrivate's checks. No error quotes the file.
func LoadEd25519(path string) (ed25519.PrivateKey, error) {
	raw, err := readPrivate(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keyfile: %s holds no PKCS#8 PRIVATE KEY block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: its PRIVATE KEY block does not parse", path)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keyfile: %s holds a key that is not ed25519", path)
	}
	return priv, nil
}

// ParseEd25519Public reads one PKIX "PUBLIC KEY" block holding an ed25519
// key from raw, which the caller read: port49d's and port49-inventory's
// verify_key_files. A public key is no secret, but it is the trust root of
// the bundle's signature (spec §13, decision 30), so whoever could write it
// decides which inventories are accepted; its reader is the write fence
// (config.VerifyKeys), never a plain read. path names it in errors, which
// never quote raw.
func ParseEd25519Public(raw []byte, path string) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("keyfile: %s holds no PUBLIC KEY block", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: its PUBLIC KEY block does not parse", path)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keyfile: %s holds a key that is not ed25519", path)
	}
	return pub, nil
}

// EncodeEd25519 is priv as `port49 inventory keygen` writes it: the private
// key as PKCS#8, the public half as PKIX.
func EncodeEd25519(priv ed25519.PrivateKey) (privPEM, pubPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// Ed25519KeyID names a key in every line and in the sealed document: the
// first eight bytes of its public half's sha256, in hex. It says which key,
// and nothing that helps forge one.
func Ed25519KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}
```

  In `cmd/port49/inventory.go`, dispatch `keygen` from `inventoryCmd` (`if len(args) > 0 && args[0] ==
  "keygen" { return inventoryKeygen(args[1:], stdout, stderr) }`) and add:

```go
// inventoryKeygen is `port49 inventory keygen`: the inventory service's
// signing key pair (spec §13, decision 30). signing.key goes to the service
// alone, signing.pub to every port49d's inventory.service.verify_key_files.
// Neither file is ever overwritten: a new key beside a daemon still holding
// the old public half would strand it on the bundle in force.
func inventoryKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("port49 inventory keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "the directory to write signing.key and signing.pub into")
	if err := flags.Parse(args); err != nil || *dir == "" || flags.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory keygen:", err)
		return 1
	}
	privPEM, pubPEM, err := keyfile.EncodeEd25519(priv)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory keygen:", err)
		return 1
	}
	// Refuse before writing either, so a refusal never leaves one new file
	// beside an old one (conflict scan F14).
	for _, name := range []string{"signing.key", "signing.pub"} {
		if _, err := os.Lstat(filepath.Join(*dir, name)); err == nil {
			fmt.Fprintf(stderr, "port49 inventory keygen: %s already exists; a new key is written beside no old one\n",
				filepath.Join(*dir, name))
			return 1
		}
	}
	var written []string
	undo := func() {
		for _, w := range written {
			os.Remove(w)
		}
	}
	for _, f := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{{"signing.key", privPEM, 0o600}, {"signing.pub", pubPEM, 0o644}} {
		path := filepath.Join(*dir, f.name)
		// O_EXCL still: a file that appeared since the check is not overwritten.
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err != nil {
			undo()
			fmt.Fprintln(stderr, "port49 inventory keygen:", err)
			return 1
		}
		written = append(written, path)
		_, werr := out.Write(f.body)
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			undo() // the first file is removed if the second fails
			fmt.Fprintln(stderr, "port49 inventory keygen:", werr)
			return 1
		}
	}
	fmt.Fprintf(stdout, "port49 inventory keygen: wrote %s (0600: port49-inventory's signing_key_file) and %s "+
		"(every port49d's inventory.service.verify_key_files); key_id %s\n", filepath.Join(*dir, "signing.key"),
		filepath.Join(*dir, "signing.pub"), keyfile.Ed25519KeyID(priv.Public().(ed25519.PublicKey)))
	return 0
}
```

  (`crypto/ed25519` and `crypto/rand` join the file's imports.) Add to `usage` in `main.go`: `  port49 inventory keygen --dir DIR`.

- [ ] **Step 4: Run them.** `go test ./internal/keyfile/ ./cmd/port49/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/keyfile cmd/port49
git commit -m "feat(keyfile): the inventory service's ed25519 signing key, and port49 inventory keygen

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3a: A key group can pin a device by name, at tier 1

**Files:**
- Modify: `internal/admission/admission.go` (`KeyGroup.Name`, `KeyGroup.String`, `Assign`)
- Modify: `internal/policy/file.go` (`fileKeyGroup.Match.Name`), `internal/policy/admit.go`
  (`buildKeyGroups`)
- Modify: `internal/bundle/bundle.go` (`canonGroup.Name`)
- Test: `internal/admission/admission_test.go`, `internal/policy/admit_test.go` (new tests, and
  `TestKeyGroupLoadErrors`' "no match" and "both terms" cases updated to the new wording: each is still
  refused with its reason)

**Interfaces:**
- Consumes: `admission.Assign`, `TierPin`, `KeyGroup`; `policy.buildKeyGroups`, `fileKeyGroup`;
  the admit tests' `good`, `keyGrouped`, `env()` and `(*Policy).KeyAssignment`.
- Produces:
  - `admission.KeyGroup.Name string` — a group matching one device by inventory name; a group
    matches on exactly one of `Name`, `CIDR` and `Attributes`.
  - `Assign` resolves a name group at tier 1 (`TierPin`), before attributes and CIDRs; two name
    groups for one device are a tie; a record pin and a name group naming different keys are a tie.
  - Policy YAML: `key_groups: [{match: {name: leaf-01}, key_ref: prod_key}]`.
  - `KeyGroup.String()` renders a name group as `name leaf-01 → prod_key`, which `keys show` prints.

Owner decision 3 (revised after the pre-flight review, B1): the service carries no pin, so the pin
tier moves into the reviewed policy, as a key group matching a device name. Spec §10 allows it ("a
group matching a single device name is legal", under "Per-device keys are not supported"); Task 1
Step 2b writes the tier table. A `/32` group is not a substitute: it is tier 3, below every attribute
group, per address, and it follows the address (`Assign`, tiers 2 and 3).

- [ ] **Step 1: Write the failing tests.** Add to `internal/admission/admission_test.go`:

```go
// A name group is tier 1: it outranks an attribute group, and a device with
// addresses in two CIDR groups for different keys takes it whole.
func TestANameGroupPinsTheDeviceAtTierOne(t *testing.T) {
	d := Device{Name: "leaf-01", Attributes: map[string]string{"env": "lab"},
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.1")}}
	groups := []KeyGroup{
		{Attributes: map[string]string{"env": "lab"}, KeyRef: "lab_key"},
		{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"},
		{CIDR: netip.MustParsePrefix("192.168.0.0/16"), KeyRef: "other_key"},
		{Name: "leaf-01", KeyRef: "pin_key"},
	}
	as, err := Assign(d, groups)
	if err != nil || as.KeyRef != "pin_key" || as.Tier != TierPin || as.Group != "name leaf-01 → pin_key" {
		t.Fatalf("%+v %v", as, err)
	}
	// Without the name group the same device is refused: its addresses
	// disagree at tier 3 — the multi-address case the pin tier exists for.
	d.Attributes = nil
	if _, err := Assign(d, groups[1:3]); err == nil {
		t.Fatal("the addresses' disagreement was not refused")
	}
}

func TestTwoNameGroupsForOneDeviceTie(t *testing.T) {
	d := Device{Name: "leaf-01"}
	if _, err := Assign(d, []KeyGroup{{Name: "leaf-01", KeyRef: "a"}, {Name: "leaf-01", KeyRef: "b"}}); err == nil ||
		!strings.Contains(err.Error(), "in the pin tier") {
		t.Fatalf("got %v", err)
	}
}

// With inventory_file, a record pin and a name group that name different
// keys refuse the device; the same key is no conflict.
func TestARecordPinAndANameGroupMustAgree(t *testing.T) {
	groups := []KeyGroup{{Name: "leaf-01", KeyRef: "b"}}
	if _, err := Assign(Device{Name: "leaf-01", KeyRef: "a"}, groups); err == nil {
		t.Fatal("a disagreement was not refused")
	}
	if as, err := Assign(Device{Name: "leaf-01", KeyRef: "b"}, groups); err != nil || as.KeyRef != "b" {
		t.Fatalf("%+v %v", as, err)
	}
}
```

  Add to `internal/policy/admit_test.go`:

```go
// Owner decision 3: the pin, in the reviewed policy, by name.
func TestAKeyGroupPinsADeviceByName(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"campus_key", "prod_key", "pin_key"}
	p, err := Parse([]byte(keyGrouped+"  - {match: {name: campus-sw-7}, key_ref: pin_key}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	if as, _ := p.KeyAssignment("campus-sw-7"); as.KeyRef != "pin_key" || as.Tier != admission.TierPin {
		t.Fatalf("%+v", as)
	}
}

func TestANameGroupIsOneTermAndOneGroupPerName(t *testing.T) {
	for name, c := range map[string]struct{ group, want string }{
		"with a cidr":  {"  - {match: {name: leaf-01, cidr: 10.0.0.0/8}, key_ref: prod_key}\n", "exactly one of name, cidr or attributes"},
		"twice":        {"  - {match: {name: leaf-01}, key_ref: prod_key}\n  - {match: {name: leaf-01}, key_ref: campus_key}\n", "tie for device leaf-01"},
		"not a name":   {"  - {match: {name: \"leaf 01\"}, key_ref: prod_key}\n", "match.name is not a device name"},
	} {
		if _, err := Parse([]byte(keyGrouped+c.group), env()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/admission/ ./internal/policy/ -run 'NameGroup|RecordPin|PinsADevice|OneTerm' -count=1`
  Expected: FAIL (unknown field `Name`).

- [ ] **Step 3: Implement.** In `internal/admission/admission.go`, add the field and its comment to
  `KeyGroup`:

```go
	// Name matches one device by its inventory name: the pin, in the
	// reviewed policy, at tier 1 (spec §10; plan 6b owner decision 3). A
	// group matches on exactly one of Name, CIDR and Attributes.
	Name string
```

  In `KeyGroup.String`, first: `if g.Name != "" { return fmt.Sprintf("name %s → %s", g.Name, g.KeyRef) }`.
  Replace `Assign`'s opening, down to the attribute tier, with:

```go
func Assign(d Device, groups []KeyGroup) (Assignment, error) {
	// Tier 1: a pin, on the record (inventory_file) or as a policy group
	// matching the name. Two that name different keys are a tie, refused:
	// guessing between two reviewed pins would admit under the wrong key.
	var named []KeyGroup
	for _, g := range groups {
		if g.Name != "" && g.Name == d.Name {
			named = append(named, g)
		}
	}
	if len(named) > 1 {
		return Assignment{}, fmt.Errorf("admission: device %q matches key groups %s and %s in the pin tier", d.Name,
			named[0], named[1])
	}
	if d.KeyRef != "" {
		if len(named) == 1 && named[0].KeyRef != d.KeyRef {
			// The record's key_ref is not printed: a pin is where a secret
			// gets pasted.
			return Assignment{}, fmt.Errorf("admission: device %q is pinned on its record and by key group %s, "+
				"to different keys, in the pin tier", d.Name, named[0])
		}
		return Assignment{KeyRef: d.KeyRef, Tier: TierPin, Group: "key_ref pinned on the device record"}, nil
	}
	if len(named) == 1 {
		return Assignment{KeyRef: named[0].KeyRef, Tier: TierPin, Group: named[0].String()}, nil
	}
```

  and update `Assign`'s doc comment: "a pin — on the record, or a group matching the device's name —
  then an attribute group, then the longest matching CIDR". The attribute and CIDR loops need no
  change: a name group has neither term. `ParseFile`'s legacy inventory `key_groups` does not take
  `name` (its `match` struct has no such field, and the strict decode refuses it): the pin by name is
  the policy's.

  In `internal/policy/file.go`, add `Name string `yaml:"name"`` to `fileKeyGroup.Match`. In
  `internal/policy/admit.go` `buildKeyGroups`: set `kg.Name = g.Match.Name`; refuse a name that is
  not 1 to 255 bytes of printable ASCII without a space (`"%s: match.name is not a device name"`,
  not quoting it); replace the two-way `switch` with a count of the terms given
  (`name`, `cidr`, `attributes`): none is `"%s: matches on neither name, cidr nor attributes, so it
  would admit the whole fleet under %s; give it one"` (today's message, generalized), and two or more is
  `"%s: match on exactly one of name, cidr or attributes: each tier is its own group (spec §10)"`; and
  add a `names map[string]string`, where a
  second group for one name is `"%s: %s and %s tie for device %s (spec §10); keep one"`. A name group
  naming a device the inventory lacks is kept, as a scope's pinned name is (plan 6a Task 17): a device
  racked later takes it.

  In `internal/bundle/bundle.go`, add `Name string `json:"name,omitempty"`` to `canonGroup` and set it
  from `g.Name` in `canonical`: an inventory file carries no name group, so no bundle name changes.

  In `internal/policy/admit_test.go`'s `TestKeyGroupLoadErrors`, change two expected substrings,
  and nothing else in the test: "no match" expects `"matches on neither name, cidr nor attributes"`
  (was `"matches on neither cidr nor attributes"`), and "both terms" expects `"exactly one of name,
  cidr or attributes"` (was `"not both"`). Both cases are still refused, each with its reason; the
  wording names the new term.

- [ ] **Step 4: Run them.** `go test ./internal/admission/ ./internal/policy/ ./internal/bundle/ ./cmd/port49/ -count=1`
  Expected: PASS. Every other existing key-group and bundle-name test is unchanged.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/admission internal/policy internal/bundle
git commit -m "feat(admission): a policy key group pins a device by name, at tier 1

Plan 6b owner decision 3, revised after the pre-flight review (B1): the
inventory service carries no pin, so the pin tier moves into the reviewed
policy. A /32 group is tier 3 and is not a pin. TestKeyGroupLoadErrors'
"no match" and "both terms" cases now expect the wording that names the
name term; both are still refused.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: The bundle document: sealed, opened, and never assigning a key

**Files:**
- Modify: `internal/bundle/bundle.go` (`canonical` → `Canonical`)
- Create: `internal/bundle/document.go`
- Test: `internal/bundle/document_test.go`

**Interfaces:**
- Consumes: `bundle.ID`, `canonical` (renamed `Canonical`), `canonDevice`, `canonGroup`;
  `admission.Validate`; `engine.HashOf`; `keyfile.Ed25519KeyID` (Task 3).
- Produces:
  - `const bundle.DocumentFormat = "port49-bundle/1"`, `const bundle.MaxDocument = 64 << 20`.
  - `type bundle.Document struct { Format string; Sequence int64; PublishedAt time.Time; Bundle,
    PolicySHA256, PlatformSet string; Sources map[string][]string; Inventory json.RawMessage }`
    (JSON: `format`, `sequence`, `published_at`, `bundle`, `policy_sha256`, `platform_set`,
    `sources`, `inventory`).
  - `func bundle.NewDocument(seq int64, at time.Time, policyRaw []byte, platformSet string, inv
    admission.Inventory, sources map[string][]string) Document`.
  - `func bundle.Seal(d Document, key ed25519.PrivateKey) ([]byte, error)`.
  - `func bundle.Open(raw []byte, keys []ed25519.PublicKey) (Document, admission.Inventory, error)`.
  - `func bundle.ETag(raw []byte) string` — `"` + `engine.HashOf(raw)` + `"`.
  - `func bundle.DeviceProblem(d admission.Device) string` — the one rule for a usable device (Decided
    10, pre-flight M2): name, platform, transport, attribute keys and values, and no zoned address.
    The syncer leaves out what it names (Task 9); `Open` refuses it.
  - `var bundle.ErrUnknownKey` — wrapped by `Open` when no verify key names the signer.
  - `func bundle.NameOK(s string) bool`, `func bundle.TextOK(s string) bool` — Decided 10's rules,
    which the service's syncer applies too.
  - `func bundle.Canonical(inv admission.Inventory) []byte`.

- [ ] **Step 1: Write the failing tests.** Create `internal/bundle/document_test.go`:

```go
package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
)

const docPolicy = "scopes: [{name: all_devices, match: {}}]\n"

func docInventory() admission.Inventory {
	return admission.Inventory{Devices: []admission.Device{
		{Name: "leaf-02", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.3")},
			Attributes: map[string]string{"site": "dc1"}, Transport: admission.TransportTCP},
		{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("10.0.0.1")}, Transport: admission.TransportTCP},
	}}
}

func sealed(t *testing.T, inv admission.Inventory, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := Seal(NewDocument(7, time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC), []byte(docPolicy), "1.1.0", inv,
		map[string][]string{"lab_file": {"leaf-01", "leaf-02"}}), key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sealBody signs bytes the test wrote itself, to hand Open a document the
// service would never write.
func sealBody(t *testing.T, body []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope{Document: body, KeyID: keyIDOf(key), Signature: ed25519.Sign(key, body)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func keyIDOf(key ed25519.PrivateKey) string { return KeyIDOf(key.Public().(ed25519.PublicKey)) }

func TestASealedDocumentOpensWithItsKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	doc, inv, err := Open(sealed(t, docInventory(), key), []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Sequence != 7 || doc.PlatformSet != "1.1.0" || doc.PolicySHA256 != engine.HashOf([]byte(docPolicy)) {
		t.Fatalf("doc %+v", doc)
	}
	// The name port49d computes from the same policy and the opened
	// inventory is the one the service wrote (spec §10).
	if doc.Bundle != ID([]byte(docPolicy), inv) || doc.Bundle != ID([]byte(docPolicy), docInventory()) {
		t.Fatalf("bundle %s", doc.Bundle)
	}
	if string(Canonical(inv)) != string(Canonical(docInventory())) {
		t.Fatal("the inventory did not round-trip")
	}
}

// A signing-key rotation: port49d holds both public keys for a while.
func TestADocumentOpensWithAnyVerifyKeyThatSignedIt(t *testing.T) {
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealed(t, docInventory(), newKey)
	if _, _, err := Open(raw, []ed25519.PublicKey{oldPub}); err == nil ||
		!strings.Contains(err.Error(), "signed by "+KeyIDOf(newPub)+", which no verify key holds") {
		t.Fatalf("old key only: %v", err)
	}
	if _, _, err := Open(raw, []ed25519.PublicKey{oldPub, newPub}); err != nil {
		t.Fatal(err)
	}
}

func TestAnyChangeToTheSignedBytesIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var e envelope
	if err := json.Unmarshal(sealed(t, docInventory(), key), &e); err != nil {
		t.Fatal(err)
	}
	e.Document = []byte(strings.Replace(string(e.Document), "10.0.0.3", "10.66.0.1", 1))
	raw, _ := json.Marshal(e)
	if _, _, err := Open(raw, []ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("got %v", err)
	}
}

// Plan 6b owner decision 3: nothing the service sends assigns a key.
func TestADocumentThatAssignsAKeyIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	pinned := docInventory()
	pinned.Devices[0].KeyRef = "lab_key"
	if _, _, err := Open(sealed(t, pinned, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "pins key_ref") {
		t.Fatalf("pin: %v", err)
	}
	grouped := docInventory()
	grouped.KeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "lab_key"}}
	if _, _, err := Open(sealed(t, grouped, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "carries key_groups") {
		t.Fatalf("groups: %v", err)
	}
}

// Decided 10: a name that could not reach a line safely is refused, and not
// printed.
func TestADocumentWithAnUnusableNameIsRefusedWithoutEchoingIt(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, mutate := range map[string]func(*admission.Inventory){
		"name":      func(i *admission.Inventory) { i.Devices[0].Name = "leaf\nINJECTED" },
		"space":     func(i *admission.Inventory) { i.Devices[0].Name = "leaf INJECTED" },
		"attribute": func(i *admission.Inventory) { i.Devices[0].Attributes["site"] = "dc1\x1b[2JINJECTED" },
		"transport": func(i *admission.Inventory) { i.Devices[0].Transport = "tls INJECTED" },
		"zone":      func(i *admission.Inventory) { i.Devices[0].Addresses[0] = netip.MustParseAddr("fe80::1%INJECTED") },
	} {
		inv := docInventory()
		mutate(&inv)
		_, _, err := Open(sealed(t, inv, key), []ed25519.PublicKey{pub})
		if err == nil || strings.Contains(err.Error(), "INJECTED") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A field a line prints is checked for shape (pre-flight minor 9), and an
// unknown signer is told apart from a bad signature (minor 4).
func TestAPrintedFieldOfTheWrongShapeIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil)
	d.PolicySHA256 = "sha256:\nINJECTED"
	body, _ := json.Marshal(d)
	if _, _, err := Open(sealBody(t, body, key), []ed25519.PublicKey{pub}); err == nil ||
		strings.Contains(err.Error(), "INJECTED") {
		t.Fatalf("got %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Open(sealed(t, docInventory(), key), []ed25519.PublicKey{other}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an unknown signer: %v", err)
	}
}

func TestAnUnknownFieldOrFormatIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := json.Marshal(NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil))
	for name, body := range map[string]string{
		"unknown field": strings.Replace(string(good), `"format"`, `"grants":["everyone"],"format"`, 1),
		"other format":  strings.Replace(string(good), DocumentFormat, "port49-bundle/2", 1),
		"trailing":      string(good) + `{}`,
	} {
		if _, _, err := Open(sealBody(t, []byte(body), key), []ed25519.PublicKey{pub}); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// An envelope is read before anything verifies it, so nothing in it is
// printed but a key id of the right shape.
func TestAGarbledEnvelopeIsRefusedWithoutEchoingIt(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, raw := range []string{`SECRET not json`, `{"document":"eA==","key_id":"SECRET\n","signature":"eA=="}`,
		`{"document":"eA==","key_id":"ed25519:0011223344556677","signature":"eA==","SECRET":1}`} {
		if _, _, err := Open([]byte(raw), []ed25519.PublicKey{pub}); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func TestAnOversizedDocumentIsRefusedUnread(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Open(make([]byte, MaxDocument+1), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/bundle/ -count=1`
  Expected: FAIL (undefined: `Seal`, `Open`, `NewDocument`, `envelope`, …).

- [ ] **Step 3: Implement.** In `internal/bundle/bundle.go` rename `canonical` to `Canonical` (its two
  uses: `ID` and the new code), with its comment's first word changed to match. Create
  `internal/bundle/document.go`:

```go
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/keyfile"
)

// DocumentFormat names the document's shape; Open refuses any other.
const DocumentFormat = "port49-bundle/1"

// MaxDocument bounds a sealed document as inventory_file is bounded: a
// 10,000-device inventory is a few megabytes.
const MaxDocument = 64 << 20

// Document is what the inventory service publishes (spec §10, "One versioned
// bundle"; §13 decisions 29 and 30): the inventory in the canonical form the
// bundle's name hashes, the policy and platform set the service built it
// against — named, never carried — the device names each source gave, which
// the service's next sync bounds against, and its place in the service's
// sequence.
type Document struct {
	Format       string              `json:"format"`
	Sequence     int64               `json:"sequence"`
	PublishedAt  time.Time           `json:"published_at"`
	Bundle       string              `json:"bundle"`
	PolicySHA256 string              `json:"policy_sha256"`
	PlatformSet  string              `json:"platform_set"`
	Sources      map[string][]string `json:"sources"`
	Inventory    json.RawMessage     `json:"inventory"`
}

// NewDocument is the document for inv, published as seq at at.
func NewDocument(seq int64, at time.Time, policyRaw []byte, platformSet string, inv admission.Inventory,
	sources map[string][]string) Document {
	return Document{Format: DocumentFormat, Sequence: seq, PublishedAt: at.UTC(), Bundle: ID(policyRaw, inv),
		PolicySHA256: engine.HashOf(policyRaw), PlatformSet: platformSet, Sources: sources, Inventory: Canonical(inv)}
}

// envelope is a document as it travels and rests: its exact bytes, which key
// signed them, and the signature. Signing the bytes, not a re-encoding, means
// nothing is canonicalized twice.
type envelope struct {
	Document  []byte `json:"document"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// KeyIDOf is keyfile.Ed25519KeyID, the name a document gives its key.
func KeyIDOf(pub ed25519.PublicKey) string { return keyfile.Ed25519KeyID(pub) }

// Seal is d, signed by key.
func Seal(d Document, key ed25519.PrivateKey) ([]byte, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Document: body, KeyID: KeyIDOf(key.Public().(ed25519.PublicKey)),
		Signature: ed25519.Sign(key, body)})
}

// ETag is the HTTP entity tag of sealed bytes.
func ETag(raw []byte) string { return `"` + engine.HashOf(raw) + `"` }

var (
	keyIDShape = regexp.MustCompile(`^ed25519:[0-9a-f]{16}$`)
	hashShape  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrUnknownKey is a document signed by a key no verify key names: a
// rotation port49d has not heard of yet, most likely. A signature that does
// not verify under a key it holds is not this: that is tampering or a
// foreign signer (pre-flight minor 4).
var ErrUnknownKey = errors.New("bundle")

// Open verifies raw against keys and reads it (spec §13, decision 30): the
// envelope, then the signature, and only then the document, strictly —
// an unknown field, another format or trailing bytes refuse it. A document
// that assigns a key (plan 6b owner decision 3), names a device with an
// unusable name or text (Decided 10), or does not validate as an inventory
// is refused. No error quotes the document: an envelope is read before
// anything vouches for it, and the rest is printed by position.
func Open(raw []byte, keys []ed25519.PublicKey) (Document, admission.Inventory, error) {
	if len(raw) > MaxDocument {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document is larger than %d bytes", MaxDocument)
	}
	var e envelope
	if strict(raw, &e) != nil {
		return Document{}, admission.Inventory{}, errors.New("bundle: the sealed document does not parse")
	}
	if !keyIDShape.MatchString(e.KeyID) {
		return Document{}, admission.Inventory{}, errors.New("bundle: the sealed document names no key id of the form ed25519:<16 hex>")
	}
	var pub ed25519.PublicKey
	for _, k := range keys {
		if KeyIDOf(k) == e.KeyID {
			pub = k
		}
	}
	if pub == nil {
		return Document{}, admission.Inventory{}, fmt.Errorf("%w: the document is signed by %s, which no verify key "+
			"holds", ErrUnknownKey, e.KeyID)
	}
	if !ed25519.Verify(pub, e.Document, e.Signature) {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document's signature by %s does not verify", e.KeyID)
	}
	var d Document
	if strict(e.Document, &d) != nil {
		return Document{}, admission.Inventory{}, errors.New("bundle: the signed document does not parse as a port49 bundle")
	}
	if d.Format != DocumentFormat {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document is not in format %s", DocumentFormat)
	}
	// Every field a line prints is checked for shape first (pre-flight
	// minor 9): the start line, the swap line and the mismatch line name them.
	if !hashShape.MatchString(d.Bundle) || !hashShape.MatchString(d.PolicySHA256) || !NameOK(d.PlatformSet) ||
		d.Sequence < 1 {
		return Document{}, admission.Inventory{}, errors.New("bundle: the document's bundle, policy_sha256, " +
			"platform_set or sequence is not of the form port49 writes")
	}
	for name := range d.Sources {
		if !NameOK(name) {
			return Document{}, admission.Inventory{}, errors.New("bundle: the document names a source that is not a name")
		}
	}
	inv, err := inventoryOf(d.Inventory)
	if err != nil {
		return Document{}, admission.Inventory{}, err
	}
	return d, inv, nil
}

// strict decodes one JSON value into v, refusing unknown fields and anything
// after it.
func strict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// inventoryOf reads the document's inventory back from its canonical form.
func inventoryOf(raw []byte) (admission.Inventory, error) {
	var c struct {
		Format    string        `json:"format"`
		Devices   []canonDevice `json:"devices"`
		KeyGroups []canonGroup  `json:"key_groups"`
	}
	if strict(raw, &c) != nil || c.Format != "port49-inventory/1" {
		return admission.Inventory{}, errors.New("bundle: the document's inventory does not parse")
	}
	if len(c.KeyGroups) > 0 {
		return admission.Inventory{}, errors.New("bundle: the document carries key_groups; key assignment is " +
			"reviewed policy, and nothing the inventory service sends assigns a key (spec §13, decision 30)")
	}
	var inv admission.Inventory
	for i, d := range c.Devices {
		label := fmt.Sprintf("#%d", i)
		if NameOK(d.Name) {
			label = d.Name
		}
		if d.KeyRef != "" {
			return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s pins key_ref; key assignment "+
				"is reviewed policy, and nothing the inventory service sends assigns a key (spec §13, decision 30)", label)
		}
		dev := admission.Device{Name: d.Name, Platform: d.Platform, Transport: d.Transport}
		if dev.Transport == "" {
			dev.Transport = admission.TransportTCP
		}
		if len(d.Attributes) > 0 {
			dev.Attributes = d.Attributes
		}
		for j, s := range d.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s: addresses[%d] is not an "+
					"IP address", label, j)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		// The service's own rule (DeviceProblem): it leaves such a device out,
		// so one here was not published by it.
		if why := DeviceProblem(dev); why != "" {
			return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s %s", label, why)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	if err := admission.Validate(inv.Devices); err != nil {
		return admission.Inventory{}, fmt.Errorf("bundle: the document's inventory: %w", err)
	}
	// The service writes the canonical form; one that is not is not the
	// service's, whatever signed it.
	if !bytes.Equal(Canonical(inv), raw) {
		return admission.Inventory{}, errors.New("bundle: the document's inventory is not in canonical form")
	}
	return inv, nil
}

// DeviceProblem says why d cannot reach a record or a line safely, or "" when
// it can (Decided 10; pre-flight M2). It is the one rule: the service leaves
// out a device it names, and Open refuses a document carrying one, so
// whatever the service publishes, port49d opens. It never quotes the value.
func DeviceProblem(d admission.Device) string {
	switch {
	case !NameOK(d.Name):
		return "has a name that is not 1 to 255 bytes of printable ASCII without a space"
	case !NameOK(d.Platform):
		return "has a platform that is not 1 to 255 bytes of printable ASCII without a space"
	case d.Transport != "" && !NameOK(d.Transport):
		return "has a transport that is not 1 to 255 bytes of printable ASCII without a space"
	}
	for k, v := range d.Attributes {
		if !NameOK(k) || !TextOK(v) {
			return "has an attribute with a control character or an unusable key"
		}
	}
	for i, a := range d.Addresses {
		// A zone is free text, and netip keeps it through the canonical form.
		if a.Zone() != "" {
			return fmt.Sprintf("has a zoned address at addresses[%d]", i)
		}
	}
	return ""
}

// NameOK is a device name, platform or attribute key that can reach a record
// and a line as it is: 1 to 255 bytes of printable ASCII, no space — the
// broker's rule for a device name (pre-flight F11).
func NameOK(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// TextOK is an attribute value that can: valid UTF-8 of at most 255 bytes, every
// rune printable (a space included, no control character).
func TextOK(s string) bool {
	return len(s) <= 255 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}
```

  `admission.Validate`'s error names devices and addresses already in the inventory, which are
  checked above before it runs, so it quotes nothing unchecked.

- [ ] **Step 4: Run them.** `go test ./internal/bundle/ -count=1`
  Expected: PASS, the existing `ID` tests included (the rename changes no output).

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/bundle
git commit -m "feat(bundle): the signed bundle document, which assigns no key

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: port49-inventory.yaml

**Files:**
- Create: `internal/inventory/config.go`
- Test: `internal/inventory/config_test.go`

**Interfaces:**
- Consumes: `config.ReadRegular`, `config.MaxConfigSize`; `yamlfault.Of`; `admission.KeyRefShape` (a
  source's name has a `key_ref`'s shape: a name every line prints).
- Produces:
  - `type inventory.SourceConfig struct { Name, Type, Path string; Interval time.Duration;
    MaxRemovedPercent int }` — each source's own `interval` (spec §10), default the top-level one.
  - `type inventory.Config struct { Listen, MetricsListen, TLSCertFile, TLSKeyFile, ClientCAFile,
    SigningKeyFile, PolicyFile, StateDir, MirrorDir string; Readers, Syncers, VerifyKeyFiles []string;
    Interval, SyncTimeout time.Duration; MaxRemovedPercent int; Sync []SourceConfig }`.
    `verify_key_files` (optional) are the public keys the service accepts for its **own** state and
    mirror besides its signing key's: during a signing-key rotation, the old one (pre-flight M6).
    `sync_timeout` (default 5m, 10s to 1h) bounds every sync (minor 10).
  - `func inventory.Load(path string) (Config, error)`; `func (c Config) Bounds() map[string]int`.

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/config_test.go`:

```go
package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
listen: 127.0.0.1:8443
tls_cert_file: /etc/i/server.pem
tls_key_file: /etc/i/server-key.pem
client_ca_file: /etc/i/ca.pem
readers: ["spiffe://example.com/port49d"]
syncers: ["user:alice@example.com"]
signing_key_file: /etc/i/signing.key
policy_file: /etc/i/policy.yaml
state_dir: /var/lib/port49-inventory
sync:
  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}
`

func loadString(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49-inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestTheMinimalConfigLoadsWithItsDefaults(t *testing.T) {
	c, err := loadString(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	if c.MetricsListen != ":9050" || c.Interval != 10*time.Minute || c.MaxRemovedPercent != 10 ||
		c.Bounds()["lab_file"] != 10 || c.MirrorDir != "" || c.SyncTimeout != 5*time.Minute ||
		len(c.VerifyKeyFiles) != 0 {
		t.Fatalf("%+v", c)
	}
}

// Spec §10: each source syncs on its own interval, defaulting to the
// top-level one.
func TestAPerSourceIntervalOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5m}", 1))
	if err != nil || c.Sync[0].Interval != 5*time.Minute {
		t.Fatalf("%+v %v", c.Sync, err)
	}
	c, err = loadString(t, minimalConfig)
	if err != nil || c.Sync[0].Interval != 10*time.Minute {
		t.Fatalf("the default: %+v %v", c.Sync, err)
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5s}", 1)); err == nil ||
		!strings.Contains(err.Error(), "sync[0].interval must be between 1m and 24h") {
		t.Fatalf("got %v", err)
	}
}

func TestASourceBoundOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, safety: {max_removed_percent: 30}}", 1)+"safety: {max_removed_percent: 5}\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxRemovedPercent != 5 || c.Bounds()["lab_file"] != 30 {
		t.Fatalf("%+v", c)
	}
}

// A secret pasted under a mistyped key is not echoed: the line and a
// category (yamlfault).
func TestAnUnknownKeyIsNamedByLineWithoutItsText(t *testing.T) {
	_, err := loadString(t, minimalConfig+"signing_key: \"-----BEGIN PRIVATE KEY-----SECRET\"\n")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("got %v", err)
	}
}

func TestWhatTheServiceCannotRunWithoutIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ from, to, want string }{
		"no state_dir":      {"state_dir: /var/lib/port49-inventory\n", "", "state_dir is required"},
		"no signing key":    {"signing_key_file: /etc/i/signing.key\n", "", "signing_key_file is required"},
		"nobody may read":   {"readers: [\"spiffe://example.com/port49d\"]\nsyncers: [\"user:alice@example.com\"]\n", "", "readers or syncers"},
		"no source":         {"sync:\n  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}\n", "", "at least one sync source"},
		"netbox":            {"type: file", "type: netbox", "type netbox is not built yet"},
		"bad source name":   {"name: lab_file", "name: Lab-File", "sync[0].name"},
		"file with no path": {", path: /etc/i/inventory.yaml", "", "sync[0] (lab_file): path is required"},
		"bound over 100":    {"state_dir:", "safety: {max_removed_percent: 101}\nstate_dir:", "between 0 and 100"},
		"a bad identity":    {`"user:alice@example.com"`, `"alice"`, "syncers[0]"},
		"interval too fast": {"state_dir:", "interval: 10s\nstate_dir:", "interval must be between 1m and 24h"},
		"sync_timeout":      {"state_dir:", "sync_timeout: 2h\nstate_dir:", "sync_timeout must be between 10s and 1h"},
	} {
		_, err := loadString(t, strings.Replace(minimalConfig, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: FAIL (no package, or undefined: `Load`).

- [ ] **Step 3: Implement.** Create `internal/inventory/config.go`:

```go
// Package inventory is port49-inventory (spec §10, "The inventory service"):
// its configuration, its sources, the syncer that bounds and publishes the
// signed bundle document, its state directory and mirror, and its mutual-TLS
// API; and the client port49d and the port49 tool read that API with.
package inventory

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/yamlfault"
)

// SourceConfig is one entry of sync: (spec §10, "Connectors and sync
// cadence"). The file source is this plan's; netbox and nautobot are plan
// 6c's.
type SourceConfig struct {
	Name, Type, Path string
	// Interval is how often this source is synced (spec §10), default the
	// top-level interval.
	Interval          time.Duration
	MaxRemovedPercent int
}

// Config is port49-inventory.yaml. Every path is read at start; nothing in
// it is a secret — the TLS and signing keys are files read through keyfile.
type Config struct {
	// Listen is the API, mutual TLS on every path; MetricsListen serves
	// /metrics, /healthz and /readyz in plain HTTP, and no fleet data.
	Listen, MetricsListen                   string
	TLSCertFile, TLSKeyFile, ClientCAFile   string
	// Readers may read; Syncers may read and POST /v1/sync (design §17).
	Readers, Syncers                        []string
	SigningKeyFile, PolicyFile              string
	// VerifyKeyFiles are further public keys the service accepts for its own
	// state_dir and mirror: the old signing key's, through a rotation, so the
	// sequence and the bound survive it (pre-flight M6). Its own signing key's
	// public half is always accepted.
	VerifyKeyFiles                          []string
	StateDir, MirrorDir                     string
	// SyncTimeout bounds one sync: a source that hangs cannot hold the
	// syncer, the schedule or a shutdown (pre-flight minor 10).
	Interval, SyncTimeout                   time.Duration
	// MaxRemovedPercent is the bound a source without its own takes, and a
	// source no longer configured is held to.
	MaxRemovedPercent                       int
	Sync                                    []SourceConfig
}

type safetyYAML struct {
	MaxRemovedPercent *int `yaml:"max_removed_percent"`
}

type fileConfig struct {
	Listen         string        `yaml:"listen"`
	MetricsListen  string        `yaml:"metrics_listen"`
	TLSCertFile    string        `yaml:"tls_cert_file"`
	TLSKeyFile     string        `yaml:"tls_key_file"`
	ClientCAFile   string        `yaml:"client_ca_file"`
	Readers        []string      `yaml:"readers"`
	Syncers        []string      `yaml:"syncers"`
	SigningKeyFile string        `yaml:"signing_key_file"`
	VerifyKeyFiles []string      `yaml:"verify_key_files"`
	SyncTimeout    time.Duration `yaml:"sync_timeout"`
	PolicyFile     string        `yaml:"policy_file"`
	StateDir       string        `yaml:"state_dir"`
	MirrorDir      string        `yaml:"mirror_dir"`
	Interval       time.Duration `yaml:"interval"`
	Safety         safetyYAML    `yaml:"safety"`
	Sync           []struct {
		Name     string        `yaml:"name"`
		Type     string        `yaml:"type"`
		Path     string        `yaml:"path"`
		Interval time.Duration `yaml:"interval"`
		Safety   safetyYAML    `yaml:"safety"`
	} `yaml:"sync"`
}

// identityShape is a caller as CallerOf names one: `user:` and an email, or a
// URI with a scheme; printable, no space.
var identityShape = regexp.MustCompile(`^(user:[^@\s]+@[^@\s]+|[a-z][a-z0-9+.-]*://\S+)$`)

// Load reads port49-inventory.yaml as port49d reads its own: a regular file,
// bounded, strictly decoded, a decode error printed as its line and a
// category only.
func Load(path string) (Config, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return Config{}, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return Config{}, fmt.Errorf("port49-inventory: %s: %w; check the key spelling against the "+
			"port49-inventory.yaml schema", path, yamlfault.Of(err))
	}
	c := Config{Listen: f.Listen, MetricsListen: f.MetricsListen, TLSCertFile: f.TLSCertFile, TLSKeyFile: f.TLSKeyFile,
		ClientCAFile: f.ClientCAFile, Readers: f.Readers, Syncers: f.Syncers, SigningKeyFile: f.SigningKeyFile,
		VerifyKeyFiles: f.VerifyKeyFiles, PolicyFile: f.PolicyFile, StateDir: f.StateDir, MirrorDir: f.MirrorDir,
		Interval: f.Interval, SyncTimeout: f.SyncTimeout}
	if c.SyncTimeout == 0 {
		c.SyncTimeout = 5 * time.Minute
	}
	if c.SyncTimeout < 10*time.Second || c.SyncTimeout > time.Hour {
		return Config{}, fmt.Errorf("port49-inventory: sync_timeout must be between 10s and 1h; got %s", c.SyncTimeout)
	}
	if c.MetricsListen == "" {
		c.MetricsListen = ":9050"
	}
	if c.Interval == 0 {
		c.Interval = 10 * time.Minute
	}
	for _, req := range []struct{ key, v string }{{"listen", c.Listen}, {"tls_cert_file", c.TLSCertFile},
		{"tls_key_file", c.TLSKeyFile}, {"client_ca_file", c.ClientCAFile}, {"signing_key_file", c.SigningKeyFile},
		{"policy_file", c.PolicyFile}, {"state_dir", c.StateDir}} {
		if req.v == "" {
			return Config{}, fmt.Errorf("port49-inventory: %s is required", req.key)
		}
	}
	if c.Interval < time.Minute || c.Interval > 24*time.Hour {
		return Config{}, fmt.Errorf("port49-inventory: interval must be between 1m and 24h; got %s", c.Interval)
	}
	if len(c.Readers)+len(c.Syncers) == 0 {
		return Config{}, fmt.Errorf("port49-inventory: readers or syncers must name someone; nobody could read the bundle")
	}
	for _, l := range []struct {
		key string
		ids []string
	}{{"readers", c.Readers}, {"syncers", c.Syncers}} {
		for i, id := range l.ids {
			if !identityShape.MatchString(id) {
				// The index, not the value: a list of names is where a
				// token gets pasted.
				return Config{}, fmt.Errorf("port49-inventory: %s[%d] is not an identity: `user:` and an email, "+
					"or a certificate's URI SAN such as spiffe://...", l.key, i)
			}
		}
	}
	if c.MaxRemovedPercent, err = bound("safety.max_removed_percent", f.Safety, 10); err != nil {
		return Config{}, err
	}
	if len(f.Sync) == 0 {
		return Config{}, fmt.Errorf("port49-inventory: sync must name at least one sync source")
	}
	seen := map[string]bool{}
	for i, s := range f.Sync {
		if !admission.KeyRefShape.MatchString(s.Name) || seen[s.Name] {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d].name must be unique, lowercase letters, digits "+
				"and _, starting with a letter", i)
		}
		seen[s.Name] = true
		switch s.Type {
		case "file":
			if s.Path == "" {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): path is required for a file source", i, s.Name)
			}
		case "netbox", "nautobot":
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type %s is not built yet (plan 6c); "+
				"this build has the file source", i, s.Name, s.Type)
		default:
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type must be file", i, s.Name)
		}
		p, err := bound(fmt.Sprintf("sync[%d].safety.max_removed_percent", i), s.Safety, c.MaxRemovedPercent)
		if err != nil {
			return Config{}, err
		}
		iv := s.Interval
		if iv == 0 {
			iv = c.Interval
		}
		if iv < time.Minute || iv > 24*time.Hour {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d].interval must be between 1m and 24h; got %s", i, iv)
		}
		c.Sync = append(c.Sync, SourceConfig{Name: s.Name, Type: s.Type, Path: s.Path, Interval: iv,
			MaxRemovedPercent: p})
	}
	return c, nil
}

func bound(key string, s safetyYAML, def int) (int, error) {
	if s.MaxRemovedPercent == nil {
		return def, nil
	}
	if p := *s.MaxRemovedPercent; p < 0 || p > 100 {
		return 0, fmt.Errorf("port49-inventory: %s must be between 0 and 100; got %d", key, p)
	}
	return *s.MaxRemovedPercent, nil
}

// Bounds is each configured source's bound, by name.
func (c Config) Bounds() map[string]int {
	out := map[string]int{}
	for _, s := range c.Sync {
		out[s.Name] = s.MaxRemovedPercent
	}
	return out
}
```

- [ ] **Step 4: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory
git commit -m "feat(inventory): port49-inventory.yaml

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The write fence becomes a package both binaries read through

**Files:**
- Create: `internal/fence/fence_linux.go`, `internal/fence/fence_other.go` (moved from
  `cmd/port49d/policyfile.go`, `cmd/port49d/policyfile_other.go`)
- Test: `internal/fence/fence_linux_test.go` (moved from the parts of `cmd/port49d/policyfile_test.go`
  that test the fence itself)
- Modify: `cmd/port49d/policyfile.go`, `cmd/port49d/policyfile_other.go`, `cmd/port49d/policyfile_test.go`

**Interfaces:**
- Consumes: `readGuarded`, `resolvePolicyPath`, `openDir`, `writableByUsAlone`,
  `dirWritableByUsAlone`, `ownedByUsOrRoot`, `notWritableByOthers`, `article`, and the swap
  variables `geteuid`, `fileOwner`, `readOnlyFS`, as they are in `cmd/port49d/policyfile.go`.
- Produces:
  - `func fence.Read(path string, max int64, what string) ([]byte, error)` — `readGuarded`, exported,
    unchanged. On other systems it refuses, as `readPolicyFile` does there.
  - The swap variables stay package variables of `fence` (`fence.Geteuid`, `fence.FileOwner`,
    `fence.ReadOnlyFS`, exported for the tests of both packages).
  - `cmd/port49d`'s `readPolicyFile` and `readInventoryFile` become one-line wrappers over
    `fence.Read`, with `maxPolicySize` and `maxInventorySize` staying in `cmd/port49d`.
  - `func fence.ReadVerifyKeys(key string, files []string) ([]ed25519.PublicKey, error)` — each file
    read through `Read` and parsed with `keyfile.ParseEd25519Public` (Task 3); an error names `key[i]`
    and the path. port49d's `config.VerifyKeys` (Task 13) and port49-inventory's own verify keys (Task
    11) read through it (pre-flight M3).

Why: the service's file source (Task 7), port49d's persisted bundle (Task 14) and every verify key
(Tasks 11, 13) are read behind the same fence as the policy file. A verify key is the trust root of
the bundle's signature: whoever can write it gets any inventory they sign accepted. The service's source file decides scope membership and the addresses a
mint hands out as surely as `inventory_file` does, and it reaches every port49d within one pull.

- [ ] **Step 1: Move the code.** `git mv cmd/port49d/policyfile.go internal/fence/fence_linux.go` and
  `git mv cmd/port49d/policyfile_other.go internal/fence/fence_other.go`. In both: `package fence`;
  rename `readGuarded` to `Read`, `geteuid` to `Geteuid`, `fileOwner` to `FileOwner`, `readOnlyFS` to
  `ReadOnlyFS`; delete `readPolicyFile`, `readInventoryFile`, `maxPolicySize` and `maxInventorySize`
  from the moved file (they go back to `cmd/port49d` in Step 3); give the package a doc comment:

```go
// Package fence reads a file that decides access within seconds of an edit —
// the policy file, the inventory file, the inventory service's file source,
// port49d's persisted bundle — only when nobody but the user port49 runs as,
// or root, could have written it (spec §5.1.3, §10). Read is port49d's policy
// file fence of plan 4b, moved here unchanged so both binaries read through it.
package fence
```

  `fence_other.go` keeps one function, `Read`, refusing with `"port49 reads " + what + " on Linux
  only: the check of who could have written it is Linux's"`. The owner refusal's text becomes "it
  must belong to the user this process runs as (uid %d) or to root", since port49-inventory reads
  through it too (pre-flight minor 8); a test asserting the old words is updated with it.

  Add `internal/fence/verify.go` (no build tag; it calls `Read`):

```go
package fence

import (
	"crypto/ed25519"
	"fmt"

	"github.com/blanketfish/port49/internal/keyfile"
)

// maxVerifyKey bounds a verify key's read: a PEM ed25519 public key is 113
// bytes.
const maxVerifyKey = 64 << 10

// ReadVerifyKeys reads each verify key behind the fence and parses it. A
// verify key is public, but whoever can write it decides which inventories
// are accepted (spec §13, decision 30), so it is held to the policy file's
// rule. key is the configuration key that lists them, for the error.
func ReadVerifyKeys(key string, files []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(files))
	for i, f := range files {
		raw, err := Read(f, maxVerifyKey, "verify key")
		if err != nil {
			return nil, fmt.Errorf("%s[%d] %s: %w", key, i, f, err)
		}
		k, err := keyfile.ParseEd25519Public(raw, f)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", key, i, err)
		}
		out = append(out, k)
	}
	return out, nil
}
```

  and to `fence_linux_test.go`:

```go
// Pre-flight M3: a verify key others could write is refused, as a policy
// file is.
func TestAVerifyKeyOthersCouldWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, pubPEM, _ := keyfile.EncodeEd25519(priv)
	p := filepath.Join(dir, "signing.pub")
	os.WriteFile(p, pubPEM, 0o664)
	os.Chmod(p, 0o664)
	if _, err := ReadVerifyKeys("verify_key_files", []string{p}); err == nil ||
		!strings.Contains(err.Error(), "verify_key_files[0]") || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
	os.Chmod(p, 0o644)
	if keys, err := ReadVerifyKeys("verify_key_files", []string{p}); err != nil || len(keys) != 1 {
		t.Fatalf("%v %v", keys, err)
	}
}
```

- [ ] **Step 2: Move the fence's own tests.** Create `internal/fence/fence_linux_test.go` from every
  test in `cmd/port49d/policyfile_test.go` that calls `readGuarded`, `readPolicyFile` or
  `readInventoryFile` directly and asserts only on the bytes or error it returns (the mode, owner,
  link, pipe, size and read-only-mount cases), with `package fence`, the calls rewritten to `Read(path,
  max, what)` and the swaps to the exported names. Tests that load a policy or start a reloader stay
  in `cmd/port49d/policyfile_test.go`, their swaps rewritten to `fence.Geteuid` and so on. No test is
  deleted and none changes what it asserts; list the moved test names in the commit body.

- [ ] **Step 3: port49d's wrappers.** Create `cmd/port49d/policyfile.go` again (no build tag):

```go
package main

import "github.com/blanketfish/port49/internal/fence"

// maxPolicySize bounds the policy file's read: a policy file is kilobytes,
// and a link aimed at a multi-gigabyte file must not be read at every poll.
const maxPolicySize = 1 << 20

// maxInventorySize bounds the inventory file's read: a 10,000-device
// inventory is a few megabytes.
const maxInventorySize = 64 << 20

// readPolicyFile reads broker.policy_file behind the write fence (spec
// §5.1.3; fence.Read).
func readPolicyFile(path string) ([]byte, error) { return fence.Read(path, maxPolicySize, "policy file") }

// readInventoryFile reads inventory_file behind the same fence: with a broker
// it is reloaded live and decides scope membership, the addresses a mint
// hands out and key pins (spec §10; plan 6a C2).
func readInventoryFile(path string) ([]byte, error) {
	return fence.Read(path, maxInventorySize, "inventory file")
}
```

  Delete `cmd/port49d/policyfile_other.go` (fence_other.go refuses for it).

- [ ] **Step 4: Run everything.** `make build && make test && make vet`
  Expected: PASS, with the same test count as before the move (`go test ./... -count=1 -v 2>&1 | grep -c '^=== RUN'`
  before and after; report both numbers).

- [ ] **Step 5: Commit**

```bash
git add internal/fence cmd/port49d
git commit -m "refactor: the write fence moves to internal/fence, unchanged

port49-inventory's file source and port49d's persisted bundle read through it
too (plan 6b). Tests moved with the code: <names>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: The file source, which assigns no key

**Files:**
- Create: `internal/inventory/source.go`
- Test: `internal/inventory/source_test.go`

**Interfaces:**
- Consumes: `fence.Read` (Task 6); `admission.ParseFile`; `bundle.NameOK` (Task 4); `SourceConfig`
  (Task 5).
- Produces:
  - `type inventory.Source interface { Name() string; Fetch(ctx context.Context) (admission.Inventory, error) }`
    — plan 6c's connectors implement it.
  - `type inventory.FileSource struct { SourceName, Path string }`.
  - `func inventory.NewSources(cfgs []SourceConfig) ([]Source, error)`.
  - `func inventory.deviceLabel(i int, name string) string` — a device as a line names it: its name
    when `bundle.NameOK`, else `#i`.

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/source_test.go`:

```go
package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fencedFile writes body where the fence passes it: a directory only its
// owner can write, a file only its owner can.
func fencedFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAFileSourceReadsTheInventoryFile(t *testing.T) {
	src := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], attributes: {site: dc1}}\n")}
	inv, err := src.Fetch(context.Background())
	if err != nil || len(inv.Devices) != 1 || inv.Devices[0].Attributes["site"] != "dc1" {
		t.Fatalf("%+v %v", inv, err)
	}
}

// Plan 6b owner decision 3: the service assigns no key.
func TestAFileSourceThatAssignsAKeyIsRefused(t *testing.T) {
	pin := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")}
	if _, err := pin.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "device leaf-01 pins key_ref") ||
		!strings.Contains(err.Error(), "{match: {name: leaf-01}, key_ref: ...}") {
		t.Fatalf("pin: %v", err)
	}
	groups := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices: []\nkey_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n")}
	if _, err := groups.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "carries key_groups") {
		t.Fatalf("groups: %v", err)
	}
}

// The source file decides access within one pull: it is read behind the
// write fence (Task 6).
func TestAFileSourceOthersCouldWriteIsRefused(t *testing.T) {
	p := fencedFile(t, "devices: []\n")
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileSource{SourceName: "lab_file", Path: p}).Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
}

func TestNewSourcesBuildsEachConfiguredSource(t *testing.T) {
	srcs, err := NewSources([]SourceConfig{{Name: "a", Type: "file", Path: "/x"}, {Name: "b", Type: "file", Path: "/y"}})
	if err != nil || len(srcs) != 2 || srcs[1].Name() != "b" {
		t.Fatalf("%v %v", srcs, err)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ -run Source -count=1`
  Expected: FAIL (undefined: `FileSource`, `NewSources`).

- [ ] **Step 3: Implement.** Create `internal/inventory/source.go`:

```go
package inventory

import (
	"context"
	"fmt"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/fence"
)

// Source is one source of truth the service syncs from (spec §10,
// "Connectors and sync cadence"). Fetch returns every device the source
// holds, as facts: name, platform, addresses, attributes, transport. It
// never returns a key assignment (spec §13, decision 30). A source that
// cannot answer returns an error, and the sync keeps the bundle published.
// Fetch MUST return when ctx ends: the syncer gives each sync sync_timeout
// (default 5m), and a source that outlives it holds the schedule and a
// shutdown. Plan 6c's NetBox and Nautobot connectors implement it.
type Source interface {
	Name() string
	Fetch(ctx context.Context) (admission.Inventory, error)
}

// maxSourceFile bounds a file source's read as inventory_file's is bounded.
const maxSourceFile = 64 << 20

// FileSource is the file connector spec §10 requires regardless: an
// inventory file in port49d's schema, read behind the write fence, since
// whoever can write it decides scope membership and the addresses a mint
// hands out within one pull.
type FileSource struct{ SourceName, Path string }

func (f FileSource) Name() string { return f.SourceName }

// Fetch reads the file. A key group or a device's key_ref pin refuses it
// whole, naming the device: key assignment is reviewed policy (plan 6b owner
// decision 3), and a file that carries one was written for port49d's own
// inventory_file, whose reader assigns what it says.
func (f FileSource) Fetch(context.Context) (admission.Inventory, error) {
	raw, err := fence.Read(f.Path, maxSourceFile, "file source")
	if err != nil {
		return admission.Inventory{}, err
	}
	inv, err := admission.ParseFile(raw, f.Path)
	if err != nil {
		return admission.Inventory{}, err
	}
	if len(inv.KeyGroups) > 0 {
		return admission.Inventory{}, fmt.Errorf("%s carries key_groups; the inventory service never assigns keys: "+
			"move the block to the policy file (spec §13, decision 30)", f.Path)
	}
	for i, d := range inv.Devices {
		if d.KeyRef != "" {
			// The fix names the device: a pin is a policy key group matching
			// the name, tier 1 (Task 3a).
			label := deviceLabel(i, d.Name)
			return admission.Inventory{}, fmt.Errorf("%s: device %s pins key_ref; the inventory service never "+
				"assigns keys: pin it in the policy file with {match: {name: %s}, key_ref: ...}, which is tier 1, "+
				"and remove the pin here (spec §13, decision 30)", f.Path, label, label)
		}
	}
	return inv, nil
}

// NewSources builds each configured source. Load has refused every type
// this build does not have.
func NewSources(cfgs []SourceConfig) ([]Source, error) {
	var out []Source
	for _, c := range cfgs {
		switch c.Type {
		case "file":
			out = append(out, FileSource{SourceName: c.Name, Path: c.Path})
		default:
			return nil, fmt.Errorf("port49-inventory: source %s: type %s is not built", c.Name, c.Type)
		}
	}
	return out, nil
}

// deviceLabel is a device as a line names it: its name where the name can
// reach a line as it is (bundle.NameOK), and otherwise its position.
func deviceLabel(i int, name string) string {
	if bundle.NameOK(name) {
		return name
	}
	return fmt.Sprintf("#%d", i)
}
```

- [ ] **Step 4: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory
git commit -m "feat(inventory): the file source, read behind the fence, assigning no key

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: The service's state directory, history and mirror

**Files:**
- Create: `internal/inventory/state.go`
- Test: `internal/inventory/state_test.go`

**Interfaces:**
- Consumes: `bundle.Open`, `bundle.MaxDocument`, `bundle.Document` (Task 4); `config.ReadRegular`.
- Produces:
  - `type inventory.Published struct { Raw []byte; Doc bundle.Document; Inv admission.Inventory }`.
  - `type inventory.State struct { Dir, MirrorDir string; Keep int }`.
  - `func (s State) Save(p Published) error` — `published.json`, then `history/<seq>.json`, pruned
    to the newest `Keep`.
  - `func (s State) Latest(keys []ed25519.PublicKey) (*Published, error)` — nil, nil when none.
  - `func (s State) At(seq int64, keys []ed25519.PublicKey) (*Published, error)`.
  - `func (s State) WriteMirror(raw []byte) error` (mode 0640: the fleet list is not the world's,
    pre-flight minor 7); `func (s State) Mirror(keys []ed25519.PublicKey) (*Published, error)`;
    `func (s State) MirrorRaw() ([]byte, error)` — the mirror's bytes as they are, for the service to
    see it is behind (M7).
  - Every read takes the keys the service accepts for its own state (M6): its signing key's public
    half and its `verify_key_files`.
  - `func inventory.WriteAtomic(dir, name string, body []byte, mode os.FileMode) error` — temp file,
    fsync, rename, fsync of the directory; port49d persists its copy with it (Task 14).
  - `func inventory.OpenFile(path string, keys []ed25519.PublicKey) (*Published, error)` — read a
    sealed copy from disk as a regular file, bounded, and open it.

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/state_test.go`:

```go
package inventory

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
)

func published(t *testing.T, key ed25519.PrivateKey, seq int64, devices ...string) Published {
	t.Helper()
	var inv admission.Inventory
	for i, d := range devices {
		inv.Devices = append(inv.Devices, admission.Device{Name: d, Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})}, Transport: admission.TransportTCP})
	}
	doc := bundle.NewDocument(seq, time.Now(), []byte("scopes: []\n"), "1.1.0", inv, map[string][]string{"a": devices})
	raw, err := bundle.Seal(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	return Published{Raw: raw, Doc: doc, Inv: inv}
}

func TestSavedStateIsTheLatestAndKeepsHistory(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: filepath.Join(t.TempDir(), "state"), Keep: 2}
	if p, err := s.Latest([]ed25519.PublicKey{pub}); p != nil || err != nil {
		t.Fatalf("empty state: %v %v", p, err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	keys := []ed25519.PublicKey{pub}
	p, err := s.Latest(keys)
	if err != nil || p.Doc.Sequence != 3 {
		t.Fatalf("latest: %v %v", p, err)
	}
	if _, err := s.At(1, keys); err == nil || !strings.Contains(err.Error(), "bundle 1 is no longer kept") {
		t.Fatalf("pruned: %v", err)
	}
	if p, err := s.At(2, keys); err != nil || p.Doc.Sequence != 2 {
		t.Fatalf("kept: %v %v", p, err)
	}
	fi, _ := os.Stat(filepath.Join(s.Dir, "published.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// No temporary file is left behind.
	if left, _ := filepath.Glob(filepath.Join(s.Dir, ".tmp-*")); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

// State another key signed, or a corrupt file, is an error that names the
// file and quotes nothing from it.
func TestStateThatDoesNotVerifyIsAnError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: t.TempDir(), Keep: 2}
	if err := s.Save(published(t, other, 1, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Latest([]ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "published.json") {
		t.Fatalf("got %v", err)
	}
	os.WriteFile(filepath.Join(s.Dir, "published.json"), []byte("SECRET"), 0o600)
	if _, err := s.Latest([]ed25519.PublicKey{pub}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("got %v", err)
	}
}

func TestTheMirrorRoundTrips(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: t.TempDir(), MirrorDir: t.TempDir(), Keep: 2}
	p := published(t, key, 9, "leaf-01")
	if err := s.WriteMirror(p.Raw); err != nil {
		t.Fatal(err)
	}
	m, err := s.Mirror([]ed25519.PublicKey{pub})
	if err != nil || m.Doc.Sequence != 9 {
		t.Fatalf("%v %v", m, err)
	}
	if fi, _ := os.Stat(filepath.Join(s.MirrorDir, "bundle.json")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("the mirror copy is mode %v", fi.Mode())
	}
	if m, err := (State{Dir: t.TempDir()}).Mirror([]ed25519.PublicKey{pub}); m != nil || err != nil {
		t.Fatalf("no mirror configured: %v %v", m, err)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ -run 'State|Mirror' -count=1`
  Expected: FAIL (undefined: `State`, `Published`).

- [ ] **Step 3: Implement.** Create `internal/inventory/state.go`:

```go
package inventory

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
)

// Published is one bundle the service published: the sealed bytes, and what
// they hold.
type Published struct {
	Raw []byte
	Doc bundle.Document
	Inv admission.Inventory
}

// State is what the service keeps (spec §10): the bundle it publishes, so a
// restart serves it and continues its sequence; the last Keep of them by
// sequence, for bundle/diff; and, when MirrorDir is set, the copy daemons read
// at a cold start.
type State struct {
	Dir, MirrorDir string
	Keep           int
}

const (
	publishedName = "published.json"
	historyDir    = "history"
	mirrorName    = "bundle.json"
)

// Save keeps p as the bundle published, then in the history, pruned to the
// newest Keep. published.json is written first: a crash between the two
// loses a diff, never the bundle being served.
func (s State) Save(p Published) error {
	if err := os.MkdirAll(filepath.Join(s.Dir, historyDir), 0o700); err != nil {
		return err
	}
	if err := WriteAtomic(s.Dir, publishedName, p.Raw, 0o600); err != nil {
		return err
	}
	if err := WriteAtomic(filepath.Join(s.Dir, historyDir), strconv.FormatInt(p.Doc.Sequence, 10)+".json", p.Raw,
		0o600); err != nil {
		return err
	}
	seqs, err := s.history()
	if err != nil {
		return err
	}
	for len(seqs) > max(s.Keep, 1) {
		if err := os.Remove(filepath.Join(s.Dir, historyDir, strconv.FormatInt(seqs[0], 10)+".json")); err != nil {
			return err
		}
		seqs = seqs[1:]
	}
	return nil
}

// history is every sequence kept, oldest first.
func (s State) history() ([]int64, error) {
	names, err := os.ReadDir(filepath.Join(s.Dir, historyDir))
	if err != nil {
		return nil, err
	}
	var seqs []int64
	for _, n := range names {
		if seq, err := strconv.ParseInt(strings.TrimSuffix(n.Name(), ".json"), 10, 64); err == nil {
			seqs = append(seqs, seq)
		}
	}
	slices.Sort(seqs)
	return seqs, nil
}

// Latest is the bundle published, or nil when the service has published none.
// keys are every key the service accepts for its own state (pre-flight M6).
func (s State) Latest(keys []ed25519.PublicKey) (*Published, error) {
	return openIfPresent(filepath.Join(s.Dir, publishedName), keys)
}

// At is bundle seq from the history.
func (s State) At(seq int64, keys []ed25519.PublicKey) (*Published, error) {
	p, err := openIfPresent(filepath.Join(s.Dir, historyDir, strconv.FormatInt(seq, 10)+".json"), keys)
	if err == nil && p == nil {
		return nil, fmt.Errorf("bundle %d is no longer kept; the service keeps the last %d", seq, s.Keep)
	}
	return p, err
}

// WriteMirror writes the copy daemons read at a cold start (spec §10). 0640:
// the fleet list and its addresses are for the daemons' group, not the
// world (pre-flight minor 7); the deployment gives port49d that group.
func (s State) WriteMirror(raw []byte) error { return WriteAtomic(s.MirrorDir, mirrorName, raw, 0o640) }

// MirrorRaw is the mirror's bytes as they are, or nil when it holds none.
func (s State) MirrorRaw() ([]byte, error) {
	raw, err := config.ReadRegular(filepath.Join(s.MirrorDir, mirrorName), bundle.MaxDocument)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// Mirror is the mirror's copy, or nil with no mirror or no copy in it.
func (s State) Mirror(keys []ed25519.PublicKey) (*Published, error) {
	if s.MirrorDir == "" {
		return nil, nil
	}
	return openIfPresent(filepath.Join(s.MirrorDir, mirrorName), keys)
}

func openIfPresent(path string, keys []ed25519.PublicKey) (*Published, error) {
	p, err := OpenFile(path, keys)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return p, err
}

// OpenFile reads a sealed copy as a regular file of at most
// bundle.MaxDocument bytes and opens it against keys. Its error names the
// file and, from bundle.Open, quotes nothing in it.
func OpenFile(path string, keys []ed25519.PublicKey) (*Published, error) {
	raw, err := config.ReadRegular(path, bundle.MaxDocument)
	if err != nil {
		return nil, err
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Published{Raw: raw, Doc: doc, Inv: inv}, nil
}

// WriteAtomic writes body to dir/name so that a reader sees the old file or
// the new one, whole: a temporary file in dir, synced, renamed over name,
// and the directory synced so the rename survives a crash.
func WriteAtomic(dir, name string, body []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after the rename there is nothing here to remove
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
```

  `config.ReadRegular`'s missing-file error wraps `fs.ErrNotExist` (it returns `os.OpenFile`'s error
  as is), which `openIfPresent` relies on; if it does not, wrap it there.

- [ ] **Step 4: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory
git commit -m "feat(inventory): the state directory, its history, and the mirror

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: The syncer: every source, bounded per source, published once, said once

**Files:**
- Create: `internal/inventory/sync.go`, `internal/inventory/safety.go`, `internal/inventory/metrics.go`
- Test: `internal/inventory/sync_test.go`
- Modify: `internal/bundle/diff.go` (JSON tags on `Change`; `Change.Line`), `cmd/port49/inventory.go`
  (`changeLine` becomes `c.Line`)

**Interfaces:**
- Consumes: `Source` (Task 7), `State`, `Published`, `WriteAtomic` (Task 8), `bundle.Parse`,
  `bundle.Diff`, `bundle.NewlyRefused`, `bundle.NewDocument`, `bundle.Seal`, `bundle.NameOK`,
  `bundle.TextOK` (Task 4), `admission.Validate`, `policy.Policy.Quarantines`, `.Redactions`,
  `.AdmissionRefusals`, `.PlatformSet`, `platform.RedactQuoted`, `config.ReadRegular`.
- Produces:
  - `type inventory.Syncer struct { Sources []Source; Bounds map[string]int; Default int; PolicyFile
    string; Key ed25519.PrivateKey; VerifyKeys []ed25519.PublicKey; Timeout time.Duration; State State;
    Metrics *Metrics; Now func() time.Time; Log io.Writer }` — `VerifyKeys` are the further keys its
    own state and mirror are read against (M6); `Timeout` is `sync_timeout` (minor 10).
  - `func (s *Syncer) Restore() error`; `func (s *Syncer) Current() *Published`;
    `func (s *Syncer) Sync(ctx context.Context, trigger string, only ...string) Result` — fetches the
    sources named in `only` (every source when none, and any not fetched yet) and rebuilds the merged
    bundle with every other source's latest fetch: each source syncs on its own `interval` (spec §10);
    `func (s *Syncer) Diff(from int64) (bundle.Report, error)`;
    `func (s *Syncer) Describe(addr netip.Addr) (DeviceView, bool)`.
  - `type inventory.Result struct { Outcome string; Sequence int64; Bundle, Summary string; Changes
    []bundle.Change; Quarantined []QuarantinedDevice; LeftOut []string; Reason string }` (JSON
    `outcome`, `sequence`, `bundle`, `summary`, `changes`, `quarantined`, `left_out`, `reason`);
    outcomes `published`, `unchanged`, `refused`, `failed`.
  - `type inventory.QuarantinedDevice struct { Device, Platform, Cause string }`;
    `type inventory.DeviceView struct { Name, Platform, Transport, Admission string; Addresses []string;
    Attributes map[string]string }`.
  - `type inventory.Metrics` and `func inventory.NewMetrics(reg prometheus.Registerer) *Metrics`:
    `port49_inventory_syncs_total{trigger,outcome}`, `port49_inventory_sync_refused`,
    `port49_inventory_sync_failing`, `port49_inventory_source_errors_total{source}`,
    `port49_inventory_devices_left_out`, `port49_inventory_published_sequence`,
    `port49_inventory_published_timestamp_seconds`, `port49_inventory_devices`,
    `port49_inventory_last_good_sync_timestamp_seconds`, `port49_inventory_mirror_write_failures_total`,
    `port49_inventory_mirror_behind` (M7), `port49_inventory_api_refused_total{reason}`.
  - `bundle.Change` gains JSON tags (`kind`, `device`, `platform`, `scope`, `address`, `from`, `to`,
    `security`) and `func (c Change) Line(addresses string) string` (the body of today's
    `changeLine`, moved unchanged).

- [ ] **Step 1: Move `changeLine`.** In `internal/bundle/diff.go`, add the JSON tags to `Change`
  (snake_case, `omitempty` on every string) and move `cmd/port49/inventory.go`'s `changeLine` there
  as `func (c Change) Line(addresses string) string`, unchanged but for one thing: a `device_added`
  line omits ` at <addresses>` when `addresses` is empty, as the service's lines and `port49 inventory
  sync` call it (the change carries no addresses). Replace its calls in `cmd/port49` with
  `c.Line(...)`. Run `go test ./cmd/port49/ ./internal/bundle/ -count=1`: PASS.

- [ ] **Step 2: Write the failing tests.** Create `internal/inventory/sync_test.go`:

```go
package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
)

const syncPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

// memSource is a source a test sets by hand.
type memSource struct {
	name string
	inv  admission.Inventory
	err  error
}

func (m *memSource) Name() string { return m.name }
func (m *memSource) Fetch(context.Context) (admission.Inventory, error) {
	return m.inv, m.err
}

// devices is n arista_eos devices leaf-01..leaf-n at 10.0.0.1.. .
func devices(n int) admission.Inventory {
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: fmt.Sprintf("leaf-%02d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	return inv
}

type syncRig struct {
	s   *Syncer
	src *memSource
	out *bytes.Buffer
	pub ed25519.PublicKey
	dir string
}

func newSyncRig(t *testing.T, policyBody string, inv admission.Inventory) *syncRig {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rig := &syncRig{src: &memSource{name: "a", inv: inv}, out: &bytes.Buffer{}, pub: pub, dir: dir}
	rig.s = rig.syncer(key)
	if err := os.MkdirAll(rig.s.State.MirrorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return rig
}

func (rig *syncRig) syncer(key ed25519.PrivateKey) *Syncer {
	return &Syncer{Sources: []Source{rig.src}, Bounds: map[string]int{"a": 10}, Default: 10,
		PolicyFile: filepath.Join(rig.dir, "policy.yaml"), Key: key,
		State:   State{Dir: filepath.Join(rig.dir, "state"), MirrorDir: filepath.Join(rig.dir, "mirror"), Keep: 64},
		Metrics: NewMetrics(prometheus.NewRegistry()), Now: time.Now, Log: rig.out}
}

func (rig *syncRig) pubs() []ed25519.PublicKey { return []ed25519.PublicKey{rig.pub} }

func (rig *syncRig) sync(t *testing.T) Result {
	t.Helper()
	return rig.s.Sync(context.Background(), "schedule")
}

func TestTheFirstSyncPublishesBundleOneEverywhere(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	res := rig.sync(t)
	if res.Outcome != "published" || res.Sequence != 1 {
		t.Fatalf("%+v %s", res, rig.out)
	}
	for _, get := range []func([]ed25519.PublicKey) (*Published, error){rig.s.State.Latest, rig.s.State.Mirror} {
		p, err := get(rig.pubs())
		if err != nil || p.Doc.Sequence != 1 || len(p.Inv.Devices) != 3 {
			t.Fatalf("%v %v", p, err)
		}
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: sync (schedule): published bundle 1 (sha256:") {
		t.Fatalf("the line: %s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.Published) != 1 || testutil.ToFloat64(rig.s.Metrics.Devices) != 3 {
		t.Fatal("metrics")
	}
}

func TestAnUnchangedSyncPublishesNothingAndSaysNothing(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.out.Reset()
	if res := rig.sync(t); res.Outcome != "unchanged" || res.Sequence != 1 || rig.out.Len() != 0 {
		t.Fatalf("%+v %q", res, rig.out)
	}
}

func TestAChangeIsTheNextSequenceAndItsSecurityChangesAreSaid(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	inv := devices(3)
	inv.Devices[0].Addresses = append(inv.Devices[0].Addresses, netip.MustParseAddr("10.66.0.1"))
	rig.src.inv = inv
	res := rig.sync(t)
	if res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: bundle 2: ! address added leaf-01: 10.66.0.1") {
		t.Fatalf("the security line: %s", rig.out)
	}
}

// Spec §10, "Bounded change per sync": a source that removes more than its
// bound refuses the sync, the bundle published stays, said once.
func TestASourceOverItsBoundIsRefusedOnce(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	rig.src.inv = devices(5)
	for i := 0; i < 2; i++ {
		if res := rig.sync(t); res.Outcome != "refused" || res.Sequence != 1 {
			t.Fatalf("%+v", res)
		}
	}
	out := rig.out.String()
	if strings.Count(out, "sync (schedule) refused; still publishing bundle 1") != 1 ||
		!strings.Contains(out, "source a removes 5 of 10 devices and refuses 0 more (50%), more than its "+
			"safety.max_removed_percent (10%)") ||
		!strings.Contains(out, "raise safety.max_removed_percent in port49-inventory.yaml and restart port49-inventory") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncRefused) != 1 {
		t.Fatal("port49_inventory_sync_refused is not 1")
	}
	rig.s.Bounds["a"] = 60
	if res := rig.sync(t); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("raised: %+v", res)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncRefused) != 0 {
		t.Fatal("port49_inventory_sync_refused stayed 1")
	}
}

// Newly refused admission counts as a removal: a source that moves devices
// out of every key group's reach takes them out of service as surely as it
// removes them (pre-flight M1: the source makes them unadmittable).
func TestNewlyRefusedDevicesCountTowardTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	inv := devices(10)
	for i := 0; i < 3; i++ {
		inv.Devices[i].Addresses = []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}
	}
	rig.src.inv = inv
	res := rig.sync(t)
	if res.Outcome != "refused" || !strings.Contains(res.Reason, "removes 0 of 10 devices and refuses 3 more") {
		t.Fatalf("%+v", res)
	}
}

// The bound measures what the sources changed. An edit to the service's own
// policy_file changes no daemon's admission (each applies the inventory
// against its own policy, decision 29), so it publishes, unbounded. Do not
// "fix" sync() to bound it: prevPol is parsed under the policy now on purpose.
func TestAServicePolicyEditAlonePublishesUnbounded(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	os.WriteFile(rig.s.PolicyFile, []byte(strings.Replace(syncPolicy, "10.0.0.0/8", "10.0.0.0/29", 1)), 0o600)
	if res := rig.sync(t); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v %s", res, rig.out)
	}
}

// Pre-flight M2: whatever the syncer publishes, Open accepts; what Open would
// refuse, the syncer leaves out.
func TestWhatTheSyncerPublishesPort49dOpens(t *testing.T) {
	inv := devices(4)
	inv.Devices[1].Transport = "tls "
	inv.Devices[2].Addresses = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}
	rig := newSyncRig(t, syncPolicy, inv)
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.LeftOut) != 2 {
		t.Fatalf("%+v", res)
	}
	if _, _, err := bundle.Open(rig.s.Current().Raw, rig.pubs()); err != nil {
		t.Fatalf("port49d would refuse what the service published: %v", err)
	}
}

// Pre-flight M6: a signing-key rotation keeps the sequence and the bound —
// the old key is in the new service's verify keys.
func TestASigningKeyRotationKeepsTheSequenceAndTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := rig.syncer(newKey)
	rotated.VerifyKeys = []ed25519.PublicKey{rig.pub}
	if err := rotated.Restore(); err != nil || rotated.Current() == nil || rotated.Current().Doc.Sequence != 1 {
		t.Fatalf("%v %v", rotated.Current(), err)
	}
	rig.src.inv = devices(5)
	if res := rotated.Sync(context.Background(), "startup"); res.Outcome != "refused" {
		t.Fatalf("the bound did not survive the rotation: %+v", res)
	}
	rig.src.inv = devices(11)
	if res := rotated.Sync(context.Background(), "startup"); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
}

// Pre-flight M7: a mirror wiped, or once not written, is written again at the
// next sync, whatever the sync found.
func TestAMirrorThatFellBehindIsWrittenAgain(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	os.Remove(filepath.Join(rig.s.State.MirrorDir, "bundle.json"))
	if res := rig.sync(t); res.Outcome != "unchanged" {
		t.Fatalf("%+v", res)
	}
	raw, err := rig.s.State.MirrorRaw()
	if err != nil || !bytes.Equal(raw, rig.s.Current().Raw) {
		t.Fatalf("the mirror was not written again: %v", err)
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Fatal("port49_inventory_mirror_behind is not 0")
	}
}

func TestAnEmptyOrUnadmittedSyncIsRefusedWhateverTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, admission.Inventory{})
	rig.s.Bounds["a"] = 100
	if res := rig.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason, "name no device") {
		t.Fatalf("empty: %+v", res)
	}
	none := newSyncRig(t, strings.Replace(syncPolicy, "10.0.0.0/8", "192.0.2.0/24", 1), devices(2))
	if res := none.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason, "admits none of the 2") {
		t.Fatalf("none admitted: %+v", res)
	}
}

func TestAFailingSourceKeepsTheBundleAndIsSaidOnce(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.src.err = errors.New("dial tcp: connection refused")
	for i := 0; i < 3; i++ {
		if res := rig.sync(t); res.Outcome != "failed" || res.Sequence != 1 {
			t.Fatalf("%+v", res)
		}
	}
	if n := strings.Count(rig.out.String(), "sync (schedule) failed; still publishing bundle 1: source a: dial tcp"); n != 1 {
		t.Fatalf("said %d times: %s", n, rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 1 {
		t.Fatal("port49_inventory_sync_failing is not 1")
	}
	rig.src.err = nil
	rig.sync(t)
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 0 {
		t.Fatal("port49_inventory_sync_failing stayed 1")
	}
}

// Spec §10: each source syncs on its own interval. A sync of one source
// fetches it alone and rebuilds the bundle with the other's latest fetch.
func TestASyncOfOneSourceKeepsTheOthersLatestFetch(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(2))
	b := &memSource{name: "b", inv: admission.Inventory{Devices: []admission.Device{{Name: "leaf-b",
		Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.1")},
		Transport: admission.TransportTCP}}}}
	rig.s.Sources = append(rig.s.Sources, b)
	rig.sync(t)
	rig.src.inv = devices(3) // source a changes, but only b is due
	b.inv.Devices = append(b.inv.Devices, admission.Device{Name: "leaf-b2", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.2")}, Transport: admission.TransportTCP})
	res := rig.s.Sync(context.Background(), "schedule", "b")
	if res.Outcome != "published" || len(rig.s.Current().Inv.Devices) != 4 {
		t.Fatalf("%+v: %d devices, want a's two and b's two", res, len(rig.s.Current().Inv.Devices))
	}
	if res := rig.s.Sync(context.Background(), "schedule", "a"); len(rig.s.Current().Inv.Devices) != 5 {
		t.Fatalf("%+v", res)
	}
}

func TestADeviceInTwoSourcesIsRefused(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(2))
	rig.s.Sources = append(rig.s.Sources, &memSource{name: "b", inv: devices(1)})
	if res := rig.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason,
		"device leaf-01 is in both source a and source b") {
		t.Fatalf("%+v", res)
	}
}

// Decided 10: a device that cannot reach a line safely is left out, said by
// position, and counted; the rest publishes.
func TestAnUnusableDeviceIsLeftOutAndSaidByPosition(t *testing.T) {
	inv := devices(3)
	inv.Devices[1].Name = "leaf\nINJECTED"
	rig := newSyncRig(t, syncPolicy, inv)
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.LeftOut) != 1 || strings.Contains(rig.out.String(), "INJECTED") ||
		!strings.Contains(rig.out.String(), "left out: source a: device #1") {
		t.Fatalf("%+v %s", res, rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.LeftOut) != 1 {
		t.Fatal("port49_inventory_devices_left_out is not 1")
	}
}

// A restart serves what it published and continues the sequence; a lost
// state_dir continues from the mirror.
func TestARestartContinuesTheSequence(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	again := rig.syncer(rig.s.Key)
	if err := again.Restore(); err != nil || again.Current().Doc.Sequence != 2 {
		t.Fatalf("%v %v", again.Current(), err)
	}
	os.RemoveAll(rig.s.State.Dir)
	lost := rig.syncer(rig.s.Key)
	if err := lost.Restore(); err != nil || lost.Current().Doc.Sequence != 2 {
		t.Fatalf("from the mirror: %v %v", lost.Current(), err)
	}
	rig.src.inv = devices(5)
	if res := lost.Sync(context.Background(), "startup"); res.Sequence != 3 {
		t.Fatalf("%+v", res)
	}
}

const unmappedPolicy = `
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: unmapped, permit: ["show **"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

// Spec §10: a sync the service's policy quarantines a device in publishes,
// and says which, with the cause.
func TestAQuarantinedDeviceIsPublishedAndSaid(t *testing.T) {
	rig := newSyncRig(t, unmappedPolicy, devices(1))
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.Quarantined) != 1 || res.Quarantined[0].Device != "leaf-01" ||
		!strings.Contains(rig.out.String(), "device leaf-01 (arista_eos) is quarantined against the service's policy") {
		t.Fatalf("%+v %s", res, rig.out)
	}
}
```

- [ ] **Step 3: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: FAIL (undefined: `Syncer`, `NewMetrics`, …).

- [ ] **Step 4: Implement the metrics.** Create `internal/inventory/metrics.go`:

```go
package inventory

import "github.com/prometheus/client_golang/prometheus"

// Metrics is what the service exports on metrics_listen. No label names a
// device; source names are configuration, not device identity.
type Metrics struct {
	// Syncs counts syncs by trigger (startup, schedule, api, signal) and
	// outcome (published, unchanged, refused, failed).
	Syncs *prometheus.CounterVec
	// SyncRefused is 1 while the last sync was refused — over a bound,
	// empty, admitting none, a device in two sources — and the bundle
	// published is older than the sources: the alarm for a mistyped filter.
	SyncRefused prometheus.Gauge
	// SyncFailing is 1 while the last sync failed: a source, the policy
	// file or the state directory did not answer.
	SyncFailing  prometheus.Gauge
	SourceErrors *prometheus.CounterVec
	// LeftOut is how many devices the last sync left out for a name or text
	// that could not reach a line safely (Decided 10).
	LeftOut        prometheus.Gauge
	Published      prometheus.Gauge
	PublishedAt    prometheus.Gauge
	Devices        prometheus.Gauge
	// LastGood is when a sync last ended published or unchanged: alert on
	// time() minus it, beside SyncRefused and SyncFailing.
	LastGood       prometheus.Gauge
	MirrorFailures prometheus.Counter
	// MirrorBehind is 1 while the mirror's copy differs from the bundle
	// published: a fresh pod with the service down would start from it.
	MirrorBehind prometheus.Gauge
	APIRefused   *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Syncs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_syncs_total",
			Help: "Syncs, by trigger and outcome."}, []string{"trigger", "outcome"}),
		SyncRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_sync_refused",
			Help: "1 while the last sync was refused and an older bundle is published."}),
		SyncFailing: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_sync_failing",
			Help: "1 while the last sync failed: a source, the policy file or the state directory did not answer."}),
		SourceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_source_errors_total",
			Help: "Fetches a source did not answer, by source."}, []string{"source"}),
		LeftOut: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_devices_left_out",
			Help: "Devices the last sync left out: a name or text that cannot reach a line safely."}),
		Published: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_published_sequence",
			Help: "The sequence of the bundle published."}),
		PublishedAt: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_published_timestamp_seconds",
			Help: "When the bundle published was published."}),
		Devices: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_devices",
			Help: "Devices in the bundle published."}),
		LastGood: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_last_good_sync_timestamp_seconds",
			Help: "When a sync last ended published or unchanged."}),
		MirrorFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_inventory_mirror_write_failures_total",
			Help: "Writes of the mirror's copy that failed."}),
		MirrorBehind: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_mirror_behind",
			Help: "1 while the mirror's copy differs from the bundle published."}),
		APIRefused: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_api_refused_total",
			Help: "API requests refused, by reason (untrusted, forbidden)."}, []string{"reason"}),
	}
	reg.MustRegister(m.Syncs, m.SyncRefused, m.SyncFailing, m.SourceErrors, m.LeftOut, m.Published, m.PublishedAt,
		m.Devices, m.LastGood, m.MirrorFailures, m.MirrorBehind, m.APIRefused)
	return m
}
```

- [ ] **Step 5: Implement the bound.** Create `internal/inventory/safety.go`:

```go
package inventory

import (
	"errors"
	"fmt"
	"slices"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/policy"
)

// checkSafety refuses next (spec §10, "Bounded change per sync"): empty, or
// admitting none under the service's policy, whatever any bound says; or with
// a source that takes more than its bound of the devices it gave prev out of
// service — removed from the bundle, or kept and newly refused admission.
// A source prev had and the configuration no longer names is held to def,
// since its devices are leaving. prev nil, the first sync the service
// remembers, is bounded by nothing else: each port49d bounds it again.
func checkSafety(prev *Published, prevPol, next *policy.Policy, now map[string]bool, bounds map[string]int, def int,
	policyFile string) error {
	n := len(next.Devices())
	if n == 0 {
		return errors.New("the sources name no device; an empty inventory admits nothing, so it is never published " +
			"(spec §10)")
	}
	if refused := next.AdmissionRefusals(); len(refused) == n {
		return fmt.Errorf("the service's policy admits none of the %d device(s) (%s: %s); check key_groups in "+
			"policy_file %s", n, refused[0].Device.Name, refused[0].Refused, policyFile)
	}
	if prev == nil {
		return nil
	}
	newly := map[string]bool{}
	for _, r := range bundle.NewlyRefused(prevPol, next) {
		newly[r.Device.Name] = true
	}
	names := make([]string, 0, len(prev.Doc.Sources))
	for name := range prev.Doc.Sources {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		was := prev.Doc.Sources[name]
		b, ok := bounds[name]
		if !ok {
			b = def
		}
		if len(was) == 0 || b >= 100 {
			continue
		}
		removed, refused := 0, 0
		for _, d := range was {
			switch {
			case !now[d]:
				removed++
			case newly[d]:
				refused++
			}
		}
		if gone := removed + refused; gone*100 > len(was)*b {
			return fmt.Errorf("source %s removes %d of %d devices and refuses %d more (%d%%), more than its "+
				"safety.max_removed_percent (%d%%); fix the source, or, if the change is meant, raise "+
				"safety.max_removed_percent in port49-inventory.yaml and restart port49-inventory",
				name, removed, len(was), refused, gone*100/len(was), b)
		}
	}
	return nil
}
```

- [ ] **Step 6: Implement the syncer.** Create `internal/inventory/sync.go`:

```go
package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/policy"
)

// Outcomes of a sync.
const (
	OutcomePublished = "published"
	OutcomeUnchanged = "unchanged"
	OutcomeRefused   = "refused"
	OutcomeFailed    = "failed"
)

// Result is what one sync did: the API's answer to POST /v1/sync, and what
// the service says.
type Result struct {
	Outcome     string              `json:"outcome"`
	Sequence    int64               `json:"sequence"`
	Bundle      string              `json:"bundle,omitempty"`
	Summary     string              `json:"summary,omitempty"`
	Changes     []bundle.Change     `json:"changes,omitempty"`
	Quarantined []QuarantinedDevice `json:"quarantined,omitempty"`
	LeftOut     []string            `json:"left_out,omitempty"`
	Reason      string              `json:"reason,omitempty"`
}

// QuarantinedDevice is a device the service's policy quarantines in the
// bundle it published (spec §10): each port49d quarantines it again against
// its own policy (spec §13, decision 29).
type QuarantinedDevice struct {
	Device   string `json:"device"`
	Platform string `json:"platform"`
	Cause    string `json:"cause"`
}

// Syncer runs one sync at a time: every source, merged and validated, parsed
// against the service's policy, bounded against the bundle published, and,
// when it changed, published — sealed, kept in State, mirrored. A trigger
// that arrives during a sync waits for it and then runs its own.
type Syncer struct {
	Sources    []Source
	Bounds     map[string]int
	Default    int
	PolicyFile string
	Key        ed25519.PrivateKey
	// VerifyKeys are the further keys the service's own state and mirror
	// are read against: through a signing-key rotation, the old key's
	// (pre-flight M6). Its own key's public half is always among them.
	VerifyKeys []ed25519.PublicKey
	// Timeout bounds one sync (sync_timeout; pre-flight minor 10); zero is 5m.
	Timeout time.Duration
	State   State
	Metrics *Metrics
	Now     func() time.Time
	Log     io.Writer

	mu      sync.Mutex
	current atomic.Pointer[Published]
	// said is the last refusal or failure said, and mirrorSaid the last mirror
	// fault, so each is said once.
	said, mirrorSaid string
	// fetched is each source's latest fetch, which a sync of another source
	// merges with (spec §10: each source on its own interval).
	fetched map[string]admission.Inventory
}

// maxPolicy bounds the service's read of its policy copy, as port49d bounds
// its own.
const maxPolicy = 1 << 20

// Current is the bundle published, or nil before the first.
func (s *Syncer) Current() *Published { return s.current.Load() }

// keys are every key the service reads its own state and mirror against.
func (s *Syncer) keys() []ed25519.PublicKey {
	return append([]ed25519.PublicKey{s.Key.Public().(ed25519.PublicKey)}, s.VerifyKeys...)
}

// Restore serves what the service last published, the newer of state_dir's
// copy and the mirror's, so a restart serves at once and continues the
// sequence (Decided 3). A copy that does not open is said and passed over:
// the service's job is to publish, and every port49d bounds what it publishes
// next.
func (s *Syncer) Restore() error {
	keys := s.keys()
	var best *Published
	for _, c := range []struct {
		what string
		get  func([]ed25519.PublicKey) (*Published, error)
	}{{"state_dir " + s.State.Dir, s.State.Latest}, {"mirror_dir " + s.State.MirrorDir, s.State.Mirror}} {
		p, err := c.get(keys)
		if err != nil {
			fmt.Fprintf(s.Log, "port49-inventory: %s: %s; passed over\n", c.what, oneLine(err))
			continue
		}
		if p != nil && (best == nil || p.Doc.Sequence > best.Doc.Sequence) {
			best = p
		}
	}
	if best == nil {
		fmt.Fprintln(s.Log, "port49-inventory: no bundle published yet; the first sync publishes bundle 1, bounded "+
			"by each port49d")
		return nil
	}
	s.publish(best)
	fmt.Fprintf(s.Log, "port49-inventory: serving bundle %d (%s), published %s\n", best.Doc.Sequence,
		best.Doc.Bundle, best.Doc.PublishedAt.Format(time.RFC3339))
	s.mirror(best.Raw) // a mirror behind the state is brought level at once (M7)
	return nil
}

func (s *Syncer) publish(p *Published) {
	s.current.Store(p)
	s.Metrics.Published.Set(float64(p.Doc.Sequence))
	s.Metrics.PublishedAt.Set(float64(p.Doc.PublishedAt.Unix()))
	s.Metrics.Devices.Set(float64(len(p.Inv.Devices)))
}

// Sync runs one sync for trigger, under Timeout, says what it did, and
// returns it. It fetches the sources named in only — every source when only
// is empty, and any source not fetched since start — and rebuilds the merged
// bundle from every source's latest fetch, so each source syncs on its own
// interval (spec §10). Whatever it found, the mirror is brought level with
// the bundle published (M7).
func (s *Syncer) Sync(ctx context.Context, trigger string, only ...string) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := s.sync(ctx, only)
	if cur := s.current.Load(); cur != nil {
		s.mirror(cur.Raw)
	}
	s.Metrics.Syncs.WithLabelValues(trigger, res.Outcome).Inc()
	s.Metrics.SyncRefused.Set(b2f(res.Outcome == OutcomeRefused))
	s.Metrics.SyncFailing.Set(b2f(res.Outcome == OutcomeFailed))
	if res.Outcome == OutcomePublished || res.Outcome == OutcomeUnchanged {
		s.Metrics.LastGood.Set(float64(s.Now().Unix()))
	}
	s.say(trigger, res)
	return res
}

func (s *Syncer) sync(ctx context.Context, only []string) Result {
	prev := s.current.Load()
	held := func(r Result) Result {
		if prev != nil {
			r.Sequence, r.Bundle = prev.Doc.Sequence, prev.Doc.Bundle
		}
		return r
	}
	policyRaw, err := config.ReadRegular(s.PolicyFile, maxPolicy)
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "policy_file " + s.PolicyFile + ": " + oneLine(err)})
	}
	var inv admission.Inventory
	sources := map[string][]string{}
	owner := map[string]string{}
	var leftOut []string
	if s.fetched == nil {
		s.fetched = map[string]admission.Inventory{}
	}
	for _, src := range s.Sources {
		got, cached := s.fetched[src.Name()]
		if !cached || len(only) == 0 || slices.Contains(only, src.Name()) {
			var err error
			if got, err = src.Fetch(ctx); err != nil {
				s.Metrics.SourceErrors.WithLabelValues(src.Name()).Inc()
				return held(Result{Outcome: OutcomeFailed, Reason: "source " + src.Name() + ": " + oneLine(err)})
			}
			// Kept only once fetched whole: a failed fetch leaves the last one.
			s.fetched[src.Name()] = got
		}
		for i, d := range got.Devices {
			// The one rule port49d's Open applies (pre-flight M2).
			if why := bundle.DeviceProblem(d); why != "" {
				leftOut = append(leftOut, fmt.Sprintf("source %s: device %s %s", src.Name(), deviceLabel(i, d.Name), why))
				continue
			}
			if o, dup := owner[d.Name]; dup {
				return held(Result{Outcome: OutcomeRefused, Reason: fmt.Sprintf("device %s is in both source %s and source %s; "+
					"a device name is one device", d.Name, o, src.Name())})
			}
			owner[d.Name] = src.Name()
			inv.Devices = append(inv.Devices, d)
			sources[src.Name()] = append(sources[src.Name()], d.Name)
		}
	}
	s.Metrics.LeftOut.Set(float64(len(leftOut)))
	for _, names := range sources {
		slices.Sort(names)
	}
	if err := admission.Validate(inv.Devices); err != nil {
		return held(Result{Outcome: OutcomeRefused, Reason: oneLine(err)})
	}
	// The service knows no port49d's key names (Env.KeyRefs nil): key_refs are
	// each daemon's to check (spec §10).
	next, err := bundle.Parse(policyRaw, inv, policy.Env{})
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "policy_file " + s.PolicyFile + ": " + oneLine(err)})
	}
	var prevPol *policy.Policy
	if prev != nil {
		// The bundle published, judged under the policy the service holds
		// now: what the sources changed, not what the policy did.
		if prevPol, err = bundle.Parse(policyRaw, prev.Inv, policy.Env{}); err != nil {
			return held(Result{Outcome: OutcomeFailed, Reason: "the bundle published does not load under policy_file " +
				s.PolicyFile + ": " + oneLine(err)})
		}
	}
	present := map[string]bool{}
	for name := range owner {
		present[name] = true
	}
	if err := checkSafety(prev, prevPol, next, present, s.Bounds, s.Default, s.PolicyFile); err != nil {
		return held(Result{Outcome: OutcomeRefused, Reason: err.Error()})
	}
	now := s.Now()
	quarantined := quarantinedIn(next, now)
	if prev != nil && prev.Doc.Bundle == next.Bundle && maps.EqualFunc(prev.Doc.Sources, sources, slices.Equal[[]string]) {
		return held(Result{Outcome: OutcomeUnchanged, Quarantined: quarantined, LeftOut: leftOut})
	}
	seq := int64(1)
	if prev != nil {
		seq = prev.Doc.Sequence + 1
	}
	doc := bundle.NewDocument(seq, now, policyRaw, next.PlatformSet(), inv, sources)
	raw, err := bundle.Seal(doc, s.Key)
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "sealing bundle " + fmt.Sprint(seq) + ": " + oneLine(err)})
	}
	p := &Published{Raw: raw, Doc: doc, Inv: inv}
	// Kept before served: a bundle the service could not keep is not
	// published, so a restart never serves an older one after a newer.
	if err := s.State.Save(*p); err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "state_dir " + s.State.Dir + ": " + oneLine(err)})
	}
	s.publish(p)
	rep := bundle.Report{To: next.Bundle, Added: len(inv.Devices)}
	if prevPol != nil {
		rep = bundle.Diff(prevPol, next, now)
	}
	return Result{Outcome: OutcomePublished, Sequence: seq, Bundle: next.Bundle, Summary: rep.Summary(), Changes: rep.Changes,
		Quarantined: quarantined, LeftOut: leftOut}
}

// mirror brings the mirror's copy level with raw, the bundle published,
// whenever it differs — at Restore and after every sync, whatever the sync
// found — so a failed write is retried and a wiped volume refilled (spec
// §10: the store "holds the most recent bundle"; pre-flight M7). Reading it
// costs one bounded read. A failure is said once per distinct fault and
// counted; port49_inventory_mirror_behind is 1 until the copy is level.
func (s *Syncer) mirror(raw []byte) {
	if s.State.MirrorDir == "" {
		return
	}
	if have, err := s.State.MirrorRaw(); err == nil && bytes.Equal(have, raw) {
		s.Metrics.MirrorBehind.Set(0)
		s.mirrorSaid = ""
		return
	}
	s.Metrics.MirrorBehind.Set(1)
	if err := s.State.WriteMirror(raw); err != nil {
		s.Metrics.MirrorFailures.Inc()
		if msg := oneLine(err); msg != s.mirrorSaid {
			s.mirrorSaid = msg
			fmt.Fprintf(s.Log, "port49-inventory: mirror_dir %s: %s; the bundle is published from the API and "+
				"state_dir, and a port49d starting with neither the service nor its own copy waits for one\n",
				s.State.MirrorDir, msg)
		}
		return
	}
	s.Metrics.MirrorBehind.Set(0)
	s.mirrorSaid = ""
}

// quarantinedIn is every device next quarantines now, its cause redacted by
// the policy's patterns (spec §5.8): a cause quotes rule text.
func quarantinedIn(next *policy.Policy, now time.Time) []QuarantinedDevice {
	var out []QuarantinedDevice
	for _, q := range next.Quarantines(now) {
		for _, e := range q.Entries {
			if e.Current(now) {
				out = append(out, QuarantinedDevice{Device: q.Device, Platform: q.Platform,
					Cause: platform.RedactQuoted(next.Redactions(), e.Cause)})
				break
			}
		}
	}
	return out
}

// say writes what a sync did: a publication in full, a refusal or failure
// once per distinct reason, and an unchanged sync only when it ends one.
func (s *Syncer) say(trigger string, res Result) {
	switch res.Outcome {
	case OutcomePublished:
		s.said = ""
		fmt.Fprintf(s.Log, "port49-inventory: sync (%s): published bundle %d (%s): %s; %d quarantined\n", trigger,
			res.Sequence, res.Bundle, res.Summary, len(res.Quarantined))
		for _, c := range res.Changes {
			if c.Security {
				fmt.Fprintf(s.Log, "port49-inventory: bundle %d: %s\n", res.Sequence, c.Line(""))
			}
		}
		for _, q := range res.Quarantined {
			fmt.Fprintf(s.Log, "port49-inventory: bundle %d: device %s (%s) is quarantined against the service's "+
				"policy: %s\n", res.Sequence, q.Device, q.Platform, q.Cause)
		}
		for _, l := range res.LeftOut {
			fmt.Fprintf(s.Log, "port49-inventory: bundle %d: left out: %s\n", res.Sequence, l)
		}
	case OutcomeUnchanged:
		if s.said != "" {
			s.said = ""
			fmt.Fprintf(s.Log, "port49-inventory: sync (%s): the sources and the policy are as bundle %d has them "+
				"again\n", trigger, res.Sequence)
		}
	default:
		if key := res.Outcome + "\x00" + res.Reason; key != s.said {
			s.said = key
			still := "no bundle is published yet"
			if res.Sequence > 0 {
				still = fmt.Sprintf("still publishing bundle %d", res.Sequence)
			}
			fmt.Fprintf(s.Log, "port49-inventory: sync (%s) %s; %s: %s\n", trigger, res.Outcome, still, res.Reason)
		}
	}
}

// Diff is what changed from bundle from to the bundle published, both judged
// under the policy the service holds now (spec §12, `inventory diff
// --service`).
func (s *Syncer) Diff(from int64) (bundle.Report, error) {
	cur := s.current.Load()
	if cur == nil {
		return bundle.Report{}, errors.New("no bundle is published yet")
	}
	old, err := s.State.At(from, s.keys())
	if err != nil {
		return bundle.Report{}, err
	}
	raw, err := config.ReadRegular(s.PolicyFile, maxPolicy)
	if err != nil {
		return bundle.Report{}, err
	}
	o, err := bundle.Parse(raw, old.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, err
	}
	n, err := bundle.Parse(raw, cur.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, err
	}
	return bundle.Diff(o, n, s.Now()), nil
}

// DeviceView is one device as GET /v1/devices/{address} shows it: a
// diagnostic, never on a hot path (spec §10).
type DeviceView struct {
	Name       string            `json:"name"`
	Platform   string            `json:"platform"`
	Addresses  []string          `json:"addresses"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Transport  string            `json:"transport"`
	Admission  string            `json:"admission"`
}

// Describe is the device the bundle published gives addr to, with its
// admission under the service's policy.
func (s *Syncer) Describe(addr netip.Addr) (DeviceView, bool) {
	cur := s.current.Load()
	if cur == nil {
		return DeviceView{}, false
	}
	for _, d := range cur.Inv.Devices {
		if !slices.Contains(d.Addresses, addr) {
			continue
		}
		v := DeviceView{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, Transport: d.Transport,
			Admission: "unknown: policy_file does not load"}
		for _, a := range d.Addresses {
			v.Addresses = append(v.Addresses, a.String())
		}
		if raw, err := config.ReadRegular(s.PolicyFile, maxPolicy); err == nil {
			if pol, err := bundle.Parse(raw, cur.Inv, policy.Env{}); err == nil {
				v.Admission = "admitted"
				if r, _ := pol.Admitted(d.Name); r.Refused != "" {
					v.Admission = "refused: " + r.Refused
				}
				if cause, q := pol.Quarantined(d.Name, s.Now()); q {
					v.Admission = "quarantined: " + platform.RedactQuoted(pol.Redactions(), cause)
				}
			}
		}
		return v, true
	}
	return DeviceView{}, false
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// oneLine is err's text on one line.
func oneLine(err error) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(err.Error(), "\n", "; ")), " ")
}
```

  `pol.Quarantined` is `(*policy.Policy).Quarantined` (`internal/policy/resolve.go`), which
  `policy.Live.Quarantined` delegates to.

- [ ] **Step 7: Run them.** `go test ./internal/inventory/ ./internal/bundle/ ./cmd/port49/ -count=1`
  Expected: PASS.

- [ ] **Step 8: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory internal/bundle cmd/port49
git commit -m "feat(inventory): the syncer, bounded per source, publishing once and saying once

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: The API: mutual TLS on every path, a read right and a sync right

**Files:**
- Create: `internal/inventory/caller.go`, `internal/inventory/api.go`
- Test: `internal/inventory/api_test.go`
- Modify: `internal/testpki/testpki.go` (`Leaf.URIs`; `WriteInventoryLab`)

**Interfaces:**
- Consumes: `Syncer` (Task 9); `bundle.ETag` (Task 4); `testpki.NewCA`, `Issue`, `PEMs`, `writeFresh`.
- Produces:
  - `func inventory.CallerOf(cs *tls.ConnectionState, now time.Time) (string, error)`.
  - `type inventory.API struct { Syncer *Syncer; Readers, Syncers []string; Now func() time.Time; Log
    io.Writer; Metrics *Metrics }`; `func (a *API) Handler() http.Handler`.
  - `func inventory.Server(addr string, cert tls.Certificate, anchor *x509.CertPool, h http.Handler,
    errLog *log.Logger) *http.Server` — `RequireAndVerifyClientCert`, TLS 1.2 or later, HTTP/1.1 only,
    timeouts.
  - `type inventory.VersionInfo struct { Sequence int64; ETag, Bundle, PolicySHA256 string;
    PublishedAt time.Time }` (JSON `sequence`, `etag`, `bundle`, `policy_sha256`, `published_at`).
  - `type inventory.DiffResult struct { From, To int64; Summary string; Changes []bundle.Change }`
    (JSON `from`, `to`, `summary`, `changes`).
  - `testpki.Leaf.URIs []*url.URL`; `func testpki.WriteInventoryLab(dir string, now time.Time) error`
    writing `inventory-ca.pem`, `inventory.pem`/`inventory-key.pem` (server, 127.0.0.1),
    `port49d.pem`/`port49d-key.pem` (client, URI SAN `spiffe://port49.test/port49d`) and
    `operator.pem`/`operator-key.pem` (client, email `alice@slice.port49.test`), as constants
    `InvCA`, `InvServerCert`, `InvServerKey`, `InvDaemonCert`, `InvDaemonKey`, `InvOperatorCert`,
    `InvOperatorKey`, and `InvDaemonID = "spiffe://port49.test/port49d"`.

- [ ] **Step 1: testpki learns URI SANs.** Add `URIs []*url.URL` to `testpki.Leaf` and `URIs: l.URIs`
  to the template in `Issue`. Add `WriteInventoryLab` beside `WriteLab`, written the same way (one CA,
  fresh 0600 files, valid a day), with the files and identities above. Run `go test ./internal/testpki/
  -count=1`: PASS.

- [ ] **Step 2: Write the failing tests.** Create `internal/inventory/api_test.go`:

```go
package inventory

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/testpki"
)

type apiRig struct {
	*syncRig
	srv                     *httptest.Server
	ca                      *testpki.CA
	reader, syncer, nobody  *http.Client
}

func (rig *apiRig) client(t *testing.T, l testpki.Leaf) *http.Client {
	t.Helper()
	l.Client, l.NotBefore, l.NotAfter = true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	cert, err := rig.ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool(), Certificates: []tls.Certificate{cert}}}}
}

func uri(s string) *url.URL { u, _ := url.Parse(s); return u }

func newAPIRig(t *testing.T) *apiRig {
	t.Helper()
	rig := &apiRig{syncRig: newSyncRig(t, syncPolicy, devices(3))}
	ca, err := testpki.NewCA("inv test CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rig.ca = ca
	srvCert, _ := ca.Issue(testpki.Leaf{CommonName: "inv", IPs: testpki.Loopback(), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)})
	api := &API{Syncer: rig.s, Readers: []string{"spiffe://port49.test/port49d"},
		Syncers: []string{"user:alice@example.com"}, Now: time.Now, Log: rig.out, Metrics: rig.s.Metrics}
	s := Server("127.0.0.1:0", srvCert, ca.Pool(), api.Handler(), log.New(io.Discard, "", 0))
	rig.srv = httptest.NewUnstartedServer(s.Handler)
	rig.srv.TLS = s.TLSConfig
	rig.srv.StartTLS()
	t.Cleanup(rig.srv.Close)
	rig.reader = rig.client(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")}})
	rig.syncer = rig.client(t, testpki.Leaf{CommonName: "alice", Emails: []string{"Alice@Example.com"}})
	rig.nobody = rig.client(t, testpki.Leaf{CommonName: "x", URIs: []*url.URL{uri("spiffe://port49.test/other")}})
	return rig
}

func (rig *apiRig) do(t *testing.T, c *http.Client, method, path string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, rig.srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestBeforeTheFirstSyncTheBundleIsNotThere(t *testing.T) {
	rig := newAPIRig(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/version", nil)
	if resp.StatusCode != 503 || !strings.Contains(string(body), `"no_bundle"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestAReaderReadsTheBundleWithAnETag(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/version", nil)
	var v VersionInfo
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || v.Sequence != 1 || v.ETag == "" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	resp, body = rig.do(t, rig.reader, "GET", "/v1/bundle", nil)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != v.ETag || bundle.ETag(body) != v.ETag {
		t.Fatalf("%d %q %q", resp.StatusCode, resp.Header.Get("ETag"), v.ETag)
	}
	if _, _, err := bundle.Open(body, rig.pubs()); err != nil {
		t.Fatal(err)
	}
	resp, _ = rig.do(t, rig.reader, "GET", "/v1/bundle", map[string]string{"If-None-Match": v.ETag})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}
}

// Design §17: reading a snapshot is not the right to trigger a sync.
func TestAReaderCannotSyncAndASyncerCan(t *testing.T) {
	rig := newAPIRig(t)
	if resp, _ := rig.do(t, rig.reader, "POST", "/v1/sync", nil); resp.StatusCode != 403 {
		t.Fatalf("reader: %d", resp.StatusCode)
	}
	resp, body := rig.do(t, rig.syncer, "POST", "/v1/sync", nil)
	var res Result
	if resp.StatusCode != 200 || json.Unmarshal(body, &res) != nil || res.Outcome != "published" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: sync requested by user:alice@example.com") {
		t.Fatalf("the request is not said: %s", rig.out)
	}
}

func TestACallerInNeitherListIsRefusedAndSaidOnce(t *testing.T) {
	rig := newAPIRig(t)
	for i := 0; i < 3; i++ {
		if resp, _ := rig.do(t, rig.nobody, "GET", "/v1/bundle/version", nil); resp.StatusCode != 403 {
			t.Fatalf("%d", resp.StatusCode)
		}
	}
	// Said once per reason and caller, whatever paths it cycles through
	// (pre-flight minor 3), and naming a fixed route, never the path it sent:
	// a decoded path is text the caller chose.
	rig.do(t, rig.nobody, "GET", "/v1/devices/10.0.0.1%0aport49-inventory:%20forged", nil)
	out := rig.out.String()
	if n := strings.Count(out, "port49-inventory: api: refused spiffe://port49.test/other"); n != 1 ||
		strings.Contains(out, "forged") || !strings.Contains(out, "(read)") {
		t.Fatalf("said %d times: %s", n, out)
	}
}

// A certificate from another CA gets no answer: the anchor is one CA.
func TestACertificateFromAnotherCAGetsNoAnswer(t *testing.T) {
	rig := newAPIRig(t)
	other, err := testpki.NewCA("another CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := other.Issue(testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")},
		Client: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool(), Certificates: []tls.Certificate{cert}}}}
	if _, err := c.Get(rig.srv.URL + "/v1/bundle/version"); err == nil {
		t.Fatal("answered a certificate from another CA")
	}
}

// Ambiguity fails closed: two URI SANs name no one.
func TestTwoURISANsAreRefused(t *testing.T) {
	rig := newAPIRig(t)
	two := rig.client(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d"),
		uri("spiffe://port49.test/other")}})
	if resp, _ := rig.do(t, two, "GET", "/v1/bundle/version", nil); resp.StatusCode != 403 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// Mutual TLS on every path: no certificate, no answer — health included.
func TestNoClientCertificateGetsNoAnswer(t *testing.T) {
	rig := newAPIRig(t)
	bare := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool()}}}
	if _, err := bare.Get(rig.srv.URL + "/v1/healthz"); err == nil {
		t.Fatal("answered without a client certificate")
	}
}

func TestADiffNamesWhatChangedSinceASequence(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=1", nil)
	var d DiffResult
	if resp.StatusCode != 200 || json.Unmarshal(body, &d) != nil || d.From != 1 || d.To != 2 ||
		!strings.Contains(d.Summary, "+1 device(s)") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=x", nil); resp.StatusCode != 400 {
		t.Fatalf("from=x: %d", resp.StatusCode)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=99", nil); resp.StatusCode != 404 {
		t.Fatalf("from=99: %d", resp.StatusCode)
	}
}

func TestADeviceIsDescribedByAnyOfItsAddresses(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/devices/10.0.0.2", nil)
	var v DeviceView
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || v.Name != "leaf-02" || v.Admission != "admitted" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/devices/192.0.2.1", nil); resp.StatusCode != 404 {
		t.Fatalf("unknown: %d", resp.StatusCode)
	}
}
```

  with `rig.pubs()` from `sync_test.go` (Task 9), and `testpki.Loopback()` a helper returning
  `[]net.IP{net.ParseIP("127.0.0.1")}` (add it in Step 1).

- [ ] **Step 3: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: FAIL (undefined: `API`, `Server`, `CallerOf`, …).

- [ ] **Step 4: Implement the caller.** Create `internal/inventory/caller.go`:

```go
package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
)

var errUntrusted = errors.New("no client certificate the trust anchor verified")

// CallerOf names a request's caller by its verified client certificate
// (design §17, "Internal interfaces"; spec §10): the leaf's one URI SAN,
// verbatim — a workload (design §7, the workload x509 row of spec §2) — or,
// with no URI SAN, `user:` and its one email SAN, lower-cased, as the broker
// names a person. Several of either, neither, a certificate outside its
// validity now, or a leaf not issued for client authentication is refused:
// ambiguity fails closed. Only VerifiedChains is read. The name is checked to
// be printable before any line carries it.
func CallerOf(cs *tls.ConnectionState, now time.Time) (string, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errUntrusted
	}
	chain := cs.VerifiedChains[0]
	for _, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return "", errors.New("a certificate in the chain is outside its validity")
		}
	}
	leaf := chain[0]
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return "", errors.New("the certificate is not issued for client authentication")
	}
	switch {
	case len(leaf.URIs) > 1:
		return "", fmt.Errorf("the certificate names %d URI SANs; a caller is one", len(leaf.URIs))
	case len(leaf.URIs) == 1:
		id := leaf.URIs[0].String()
		if !bundle.NameOK(id) {
			return "", errors.New("the certificate's URI SAN is not printable ASCII")
		}
		return id, nil
	case len(leaf.EmailAddresses) == 1:
		e := strings.ToLower(leaf.EmailAddresses[0])
		if !bundle.NameOK(e) || strings.Count(e, "@") != 1 {
			return "", errors.New("the certificate's email SAN is not one printable address")
		}
		return "user:" + e, nil
	case len(leaf.EmailAddresses) > 1:
		return "", fmt.Errorf("the certificate names %d email SANs and no URI SAN; a caller is one", len(leaf.EmailAddresses))
	}
	return "", errors.New("the certificate names no URI SAN and no email SAN")
}
```

- [ ] **Step 5: Implement the API.** Create `internal/inventory/api.go`:

```go
package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
)

// VersionInfo is GET /v1/bundle/version: what a daemon compares with what it
// holds, every poll_interval, before it asks for anything larger.
type VersionInfo struct {
	Sequence     int64     `json:"sequence"`
	ETag         string    `json:"etag"`
	Bundle       string    `json:"bundle"`
	PolicySHA256 string    `json:"policy_sha256"`
	PublishedAt  time.Time `json:"published_at"`
}

// DiffResult is GET /v1/bundle/diff?from=<sequence>.
type DiffResult struct {
	From    int64           `json:"from"`
	To      int64           `json:"to"`
	Summary string          `json:"summary"`
	Changes []bundle.Change `json:"changes"`
}

// API is the service's HTTP API (spec §10), behind Server's mutual TLS. Every
// path names its caller (CallerOf); Readers may read, Syncers may read and
// sync.
type API struct {
	Syncer           *Syncer
	Readers, Syncers []string
	Now              func() time.Time
	Log              io.Writer
	Metrics          *Metrics

	mu   sync.Mutex
	told map[string]bool
}

// maxTold bounds the refusals remembered as said: past it, a refusal is
// counted and not said, so a caller cycling certificates cannot grow memory.
const maxTold = 256

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle", a.gate(false, a.bundle))
	mux.HandleFunc("GET /v1/bundle/version", a.gate(false, a.version))
	mux.HandleFunc("GET /v1/bundle/diff", a.gate(false, a.diff))
	mux.HandleFunc("GET /v1/healthz", a.gate(false, a.healthz))
	mux.HandleFunc("GET /v1/devices/{address}", a.gate(false, a.device))
	mux.HandleFunc("POST /v1/sync", a.gate(true, a.sync))
	// A path that matches no route is refused like any other: named first.
	mux.HandleFunc("/", a.gate(false, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}))
	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, caller string)

// gate names the caller and refuses one without the right: a sync needs
// syncers, anything else readers or syncers.
func (a *API) gate(sync bool, h handler) http.HandlerFunc {
	right := "read"
	if sync {
		right = "sync"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := CallerOf(r.TLS, a.Now())
		if err != nil {
			a.refuse(w, "untrusted", "an unnamed caller ("+err.Error()+")", right)
			return
		}
		if !slices.Contains(a.Syncers, caller) && (sync || !slices.Contains(a.Readers, caller)) {
			a.refuse(w, "forbidden", caller, right)
			return
		}
		h(w, r, caller)
	}
}

// refuse answers 403 and says it once per reason and caller. The line names
// the right asked for, never the path: a decoded path is the caller's text,
// and one caller cycling paths must not use up maxTold for everyone
// (pre-flight minor 3). caller is CallerOf's name, printable by construction.
func (a *API) refuse(w http.ResponseWriter, reason, caller, right string) {
	a.Metrics.APIRefused.WithLabelValues(reason).Inc()
	a.mu.Lock()
	if a.told == nil {
		a.told = map[string]bool{}
	}
	key := reason + " " + caller
	say := !a.told[key] && len(a.told) < maxTold
	if say {
		a.told[key] = true
	}
	a.mu.Unlock()
	if say {
		fmt.Fprintf(a.Log, "port49-inventory: api: refused %s (%s) %s; readers and syncers in port49-inventory.yaml "+
			"decide who may call\n", caller, right, reason)
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}

func (a *API) bundle(w http.ResponseWriter, r *http.Request, _ string) {
	p := a.Syncer.Current()
	if p == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
		return
	}
	etag := bundle.ETag(p.Raw)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.Raw)
}

func (a *API) version(w http.ResponseWriter, _ *http.Request, _ string) {
	p := a.Syncer.Current()
	if p == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
		return
	}
	writeJSON(w, http.StatusOK, VersionInfo{Sequence: p.Doc.Sequence, ETag: bundle.ETag(p.Raw), Bundle: p.Doc.Bundle,
		PolicySHA256: p.Doc.PolicySHA256, PublishedAt: p.Doc.PublishedAt})
}

func (a *API) diff(w http.ResponseWriter, r *http.Request, _ string) {
	from, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from_not_a_sequence"})
		return
	}
	rep, err := a.Syncer.Diff(from)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_kept", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, DiffResult{From: from, To: a.Syncer.Current().Doc.Sequence, Summary: rep.Summary(),
		Changes: rep.Changes})
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request, _ string) {
	if p := a.Syncer.Current(); p != nil {
		writeJSON(w, http.StatusOK, map[string]int64{"sequence": p.Doc.Sequence})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
}

func (a *API) device(w http.ResponseWriter, r *http.Request, _ string) {
	addr, err := netip.ParseAddr(r.PathValue("address"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not_an_address"})
		return
	}
	v, ok := a.Syncer.Describe(addr)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) sync(w http.ResponseWriter, r *http.Request, caller string) {
	fmt.Fprintf(a.Log, "port49-inventory: sync requested by %s\n", caller)
	writeJSON(w, http.StatusOK, a.Syncer.Sync(r.Context(), "api"))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Server serves h over mutual TLS on addr (spec §10): a client certificate
// is required on every path and verified against anchor, the one trust
// anchor. HTTP/1.1 only (a non-nil TLSNextProto). WriteTimeout covers a POST
// /v1/sync waiting for a slow source.
func Server(addr string, cert tls.Certificate, anchor *x509.CertPool, h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ErrorLog: errLog,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 6 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientCAs: anchor,
			ClientAuth: tls.RequireAndVerifyClientCert},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}
```

  `POST /v1/sync` reads no body: Go closes an
  unread body, and `MaxHeaderBytes` and `ReadTimeout` bound the rest.

- [ ] **Step 6: Run them.** `go test ./internal/inventory/ ./internal/testpki/ -count=1`
  Expected: PASS.

- [ ] **Step 7: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory internal/testpki
git commit -m "feat(inventory): the API, mutual TLS on every path, with read and sync rights

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: `port49-inventory`, the binary

**Files:**
- Create: `cmd/port49-inventory/main.go`
- Test: `cmd/port49-inventory/main_test.go`
- Modify: `Makefile` (`build`)

**Interfaces:**
- Consumes: `inventory.Load` (Task 5), `keyfile.LoadEd25519` (Task 3), `fence.ReadVerifyKeys` (Task 6),
  `broker.LoadTLS` (one anchor,
  the server key through keyfile), `inventory.NewSources` (Task 7), `State` (Task 8), `Syncer`,
  `NewMetrics` (Task 9), `API`, `Server` (Task 10), `broker.Limit`.
- Produces:
  - `func run(ctx context.Context, cfgPath string, hup <-chan os.Signal) error`.
  - `var onListening func(api, metrics string)` — a test hook, nil in production.
  - `bin/port49-inventory` from `make build`.

What an operator sees at start: `port49-inventory: API on 127.0.0.1:8443 (mutual TLS; 1 reader(s),
2 syncer(s)), metrics on [::]:9050; signing key ed25519:3f9a…; 1 source(s): lab_file (file)`, then
`serving bundle 1842 …` or `no bundle published yet …`, then the startup sync's line. Each source is
then synced on its own `interval`; startup, `SIGHUP` and `POST /v1/sync` sync every source. `/readyz` is 200
once a bundle is published or restored; until then the API's reads answer 503 `no_bundle`.

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49-inventory/main_test.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/keyfile"
	"github.com/blanketfish/port49/internal/testpki"
)

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuffer) String() string               { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fixture struct {
	dir, cfg, source string
	pki              string
}

const servicePolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

func newFixture(t *testing.T, keyMode os.FileMode) fixture {
	t.Helper()
	f := fixture{dir: t.TempDir()}
	if err := os.Chmod(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.pki = filepath.Join(f.dir, "pki")
	if err := testpki.WriteInventoryLab(f.pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, _, _ := keyfile.EncodeEd25519(priv)
	key := filepath.Join(f.dir, "signing.key")
	os.WriteFile(key, privPEM, keyMode)
	os.Chmod(key, keyMode)
	os.WriteFile(filepath.Join(f.dir, "policy.yaml"), []byte(servicePolicy), 0o600)
	f.source = filepath.Join(f.dir, "inventory.yaml")
	f.writeSource(t, 1)
	f.cfg = filepath.Join(f.dir, "port49-inventory.yaml")
	os.WriteFile(f.cfg, []byte(fmt.Sprintf(`
listen: 127.0.0.1:0
metrics_listen: 127.0.0.1:0
tls_cert_file: %[1]s/%[2]s
tls_key_file: %[1]s/%[3]s
client_ca_file: %[1]s/%[4]s
readers: [%[5]q]
syncers: ["user:alice@slice.port49.test"]
signing_key_file: %[6]s
policy_file: %[7]s
state_dir: %[8]s
sync: [{name: lab_file, type: file, path: %[9]s}]
`, f.pki, testpki.InvServerCert, testpki.InvServerKey, testpki.InvCA, testpki.InvDaemonID, key,
		filepath.Join(f.dir, "policy.yaml"), filepath.Join(f.dir, "state"), f.source)), 0o600)
	return f
}

func (f fixture) writeSource(t *testing.T, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("devices:\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: leaf-%02d, platform: arista_eos, addresses: [10.0.0.%d]}\n", i, i)
	}
	if err := os.WriteFile(f.source, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) client(t *testing.T, cert, key string) *http.Client {
	t.Helper()
	c, err := tls.LoadX509KeyPair(filepath.Join(f.pki, cert), filepath.Join(f.pki, key))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(f.pki, testpki.InvCA))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{c}}}}
}

// start runs the service and returns its API and metrics addresses.
func start(t *testing.T, f fixture, out *syncBuffer, hup chan os.Signal) (string, string, chan error) {
	t.Helper()
	e := stderr
	t.Cleanup(func() { stderr = e; onListening = nil })
	stderr = out
	addrs := make(chan [2]string, 1)
	onListening = func(api, metrics string) { addrs <- [2]string{api, metrics} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, hup) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case a := <-addrs:
		return a[0], a[1], done
	case err := <-done:
		t.Fatalf("run: %v; stderr %s", err, out)
	case <-time.After(10 * time.Second):
		t.Fatalf("not listening: %s", out)
	}
	return "", "", nil
}

func waitFor(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q; have %q", want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTheServiceStartsSyncsAndResyncsOnSIGHUP(t *testing.T) {
	f := newFixture(t, 0o600)
	var out syncBuffer
	hup := make(chan os.Signal, 1)
	api, metrics, _ := start(t, f, &out, hup)
	waitFor(t, &out, "port49-inventory: sync (startup): published bundle 1 ")
	if code, _ := get(t, http.DefaultClient, "http://"+metrics+"/readyz"); code != 200 {
		t.Fatalf("readyz %d", code)
	}
	reader := f.client(t, testpki.InvDaemonCert, testpki.InvDaemonKey)
	if code, body := get(t, reader, "https://"+api+"/v1/bundle/version"); code != 200 ||
		!strings.Contains(body, `"sequence":1`) {
		t.Fatalf("%d %s", code, body)
	}
	f.writeSource(t, 2)
	hup <- syscall.SIGHUP
	waitFor(t, &out, "port49-inventory: sync (signal): published bundle 2 ")
}

// No source, no bundle: the service is up and says why, and is not ready.
func TestAServiceWithNoBundleIsNotReady(t *testing.T) {
	f := newFixture(t, 0o600)
	os.Remove(f.source)
	var out syncBuffer
	_, metrics, _ := start(t, f, &out, make(chan os.Signal))
	waitFor(t, &out, "port49-inventory: sync (startup) failed; no bundle is published yet: source lab_file:")
	if code, _ := get(t, http.DefaultClient, "http://"+metrics+"/readyz"); code != 503 {
		t.Fatalf("readyz %d", code)
	}
}

func TestASigningKeyOthersCanReadRefusesTheStart(t *testing.T) {
	f := newFixture(t, 0o640)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	err := run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "signing_key_file") || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./cmd/port49-inventory/ -count=1`
  Expected: FAIL (no `run`).

- [ ] **Step 3: Implement.** Create `cmd/port49-inventory/main.go`:

```go
// Command port49-inventory is the inventory service (spec §10): the one
// component that talks to a source of truth. It syncs its sources on a
// schedule, at start, at SIGHUP and when a syncer asks, bounds each sync,
// and publishes one signed bundle document over a mutual-TLS API, to its
// state directory and to a shared mirror. Nothing depends on it being up:
// every port49d serves the bundle it holds, and starts from its own copy or
// the mirror's.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/keyfile"
)

func main() {
	cfgPath := flag.String("config", "/etc/port49-inventory/port49-inventory.yaml", "path to port49-inventory.yaml")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	if err := run(ctx, *cfgPath, hup); err != nil {
		fmt.Fprintln(os.Stderr, "port49-inventory:", err)
		os.Exit(1)
	}
}

// stderr is where the service's lines go; tests swap it.
var stderr io.Writer = os.Stderr

// onListening is told the bound addresses; a test's hook, nil otherwise.
var onListening func(api, metrics string)

// maxConns caps the API's connections: its callers are a fleet of port49d
// polling every 30 s and a few operators.
const maxConns = 512

// run is the service from config to exit. Everything that can fail on a
// typo fails before a listener opens.
func run(ctx context.Context, cfgPath string, hup <-chan os.Signal) error {
	cfg, err := inventory.Load(cfgPath)
	if err != nil {
		return err
	}
	key, err := keyfile.LoadEd25519(cfg.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("signing_key_file %s: %w", cfg.SigningKeyFile, err)
	}
	cert, anchor, err := broker.LoadTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile)
	if err != nil {
		return fmt.Errorf("TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w", cfg.TLSCertFile,
			cfg.TLSKeyFile, cfg.ClientCAFile, err)
	}
	sources, err := inventory.NewSources(cfg.Sync)
	if err != nil {
		return err
	}
	// The keys its own state and mirror may be signed by besides its own:
	// the old key's, through a rotation (pre-flight M6). Behind the fence
	// (M3): whoever writes one decides what the service restores.
	verify, err := fence.ReadVerifyKeys("verify_key_files", cfg.VerifyKeyFiles)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("state_dir %s: %w", cfg.StateDir, err)
	}
	reg := prometheus.NewRegistry()
	m := inventory.NewMetrics(reg)
	s := &inventory.Syncer{Sources: sources, Bounds: cfg.Bounds(), Default: cfg.MaxRemovedPercent,
		PolicyFile: cfg.PolicyFile, Key: key, VerifyKeys: verify, Timeout: cfg.SyncTimeout,
		State: inventory.State{Dir: cfg.StateDir, MirrorDir: cfg.MirrorDir, Keep: 64},
		Metrics: m, Now: time.Now, Log: stderr}
	if err := s.Restore(); err != nil {
		return err
	}
	api := &inventory.API{Syncer: s, Readers: cfg.Readers, Syncers: cfg.Syncers, Now: time.Now, Log: stderr, Metrics: m}
	srv := inventory.Server(cfg.Listen, cert, anchor, api.Handler(), stdlog.New(stderr, "port49-inventory: api: ", 0))

	mln, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics_listen %s: %w", cfg.MetricsListen, err)
	}
	defer mln.Close()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Ready is "has a bundle to serve": a probe needs nothing else, and this
	// listener carries no fleet data.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Current() == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	go http.Serve(mln, mux)
	apiErr := make(chan error, 1)
	go func() { apiErr <- srv.ServeTLS(broker.Limit(ln, maxConns), "", "") }()

	names := make([]string, len(cfg.Sync))
	for i, c := range cfg.Sync {
		names[i] = c.Name + " (" + c.Type + ")"
	}
	fmt.Fprintf(stderr, "port49-inventory: API on %s (mutual TLS; %d reader(s), %d syncer(s)), metrics on %s; "+
		"signing key %s; %d source(s): %s\n", ln.Addr(), len(cfg.Readers), len(cfg.Syncers), mln.Addr(),
		keyfile.Ed25519KeyID(key.Public().(ed25519.PublicKey)), len(sources), strings.Join(names, ", "))
	if onListening != nil {
		onListening(ln.Addr().String(), mln.Addr().String())
	}

	s.Sync(ctx, "startup")
	// Each source on its own interval (spec §10): a ticker per source names
	// the source due, and that sync rebuilds the bundle with every other
	// source's latest fetch.
	due := make(chan string)
	for _, c := range cfg.Sync {
		go func(name string, every time.Duration) {
			tick := time.NewTicker(every)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					select {
					case due <- name:
					case <-ctx.Done():
						return
					}
				}
			}
		}(c.Name, c.Interval)
	}
	for {
		select {
		case <-ctx.Done():
			shut, done := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shut)
			done()
			fmt.Fprintln(stderr, "port49-inventory: signal received, exiting")
			return nil
		case err := <-apiErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("listen %s: %w", cfg.Listen, err)
		case name := <-due:
			s.Sync(ctx, "schedule", name)
		case <-hup:
			s.Sync(ctx, "signal")
		}
	}
}
```

  Add `go build -o bin/port49-inventory ./cmd/port49-inventory` to the `build` target in `Makefile`.

- [ ] **Step 4: Run them.** `make build && go test ./cmd/port49-inventory/ -count=1`
  Expected: PASS, and `bin/port49-inventory` exists.

- [ ] **Step 5: Commit** (after `make test && make vet`)

```bash
git add cmd/port49-inventory Makefile
git commit -m "feat: port49-inventory, the inventory service binary

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: The client, `port49 inventory sync`, and `inventory diff --service`

**Files:**
- Create: `internal/inventory/client.go`
- Test: `internal/inventory/client_test.go`
- Modify: `cmd/port49/inventory.go`, `cmd/port49/main.go` (usage)
- Test: `cmd/port49/inventory_service_test.go`

**Interfaces:**
- Consumes: `VersionInfo`, `DiffResult`, `Result` (Tasks 9, 10); `keyfile.LoadX509KeyPair`;
  `bundle.MaxDocument`, `bundle.Change.Line`.
- Produces:
  - `type inventory.Client struct` and `func inventory.NewClient(rawURL, caFile, certFile, keyFile
    string) (*Client, error)` — `https` only, no user information in the URL, the CA file's
    certificates as the only roots, and both the CA file and the client certificate re-read at each
    handshake (a renewed workload certificate or a rotated CA is used without a restart; pre-flight
    minor 6); dials time out at 10 s (minor 5). The client sets no deadline of its own on an ask:
    port49d's asks carry `requestTimeout` (30 s, Task 14) in their context, and `port49 inventory
    sync` waits up to 6 min (`ResponseHeaderTimeout`) for a sync the service bounds by `sync_timeout`.
  - `func (c *Client) Version(ctx context.Context) (VersionInfo, error)`;
    `func (c *Client) Bundle(ctx context.Context, etag string) (raw []byte, newETag string, notModified bool, err error)`;
    `func (c *Client) Sync(ctx context.Context) (Result, error)`;
    `func (c *Client) Diff(ctx context.Context, from int64) (DiffResult, error)`;
    `var inventory.ErrNoBundle`.
  - `port49 inventory sync --service URL --ca FILE --cert FILE --key FILE` (exit 0 on published and
    unchanged, 1 otherwise); `port49 inventory diff --service URL --ca --cert --key --from N`.

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/client_test.go`, reusing
  `newAPIRig` (Task 10), with the rig's client certificates written to files:

```go
package inventory

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// clientFiles writes a certificate for l and the CA to files, as a deployment
// holds them.
func (rig *apiRig) clientFiles(t *testing.T, l testpki.Leaf) (ca, cert, key string) {
	t.Helper()
	dir := t.TempDir()
	l.Client, l.NotBefore, l.NotAfter = true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	c, err := rig.ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := testpki.PEMs(c)
	ca, cert, key = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(ca, rig.ca.PEM(), 0o644)
	os.WriteFile(cert, certPEM, 0o644)
	os.WriteFile(key, keyPEM, 0o600)
	return ca, cert, key
}

func TestTheClientReadsAndSyncs(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	c, err := NewClient(rig.srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Version(ctx); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("before: %v", err)
	}
	res, err := c.Sync(ctx)
	if err != nil || res.Outcome != "published" {
		t.Fatalf("%+v %v", res, err)
	}
	v, err := c.Version(ctx)
	if err != nil || v.Sequence != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	raw, etag, nm, err := c.Bundle(ctx, "")
	if err != nil || nm || etag != v.ETag || len(raw) == 0 {
		t.Fatalf("%v %v %v", etag, nm, err)
	}
	if _, _, nm, err := c.Bundle(ctx, etag); err != nil || !nm {
		t.Fatalf("If-None-Match: %v %v", nm, err)
	}
}

// Pre-flight minor 6: the CA file is read at each handshake. Another CA in the
// file fails the next connection; the right one back, the next succeeds —
// with the same client, no restart.
func TestTheClientReadsTheCAFileAtEachHandshake(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")}})
	c, err := NewClient(rig.srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(ca)
	other, _ := testpki.NewCA("another", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	os.WriteFile(ca, other.PEM(), 0o644)
	if _, err := c.Version(context.Background()); err == nil || errors.Is(err, ErrNoBundle) {
		t.Fatalf("a service the CA file does not vouch for was answered: %v", err)
	}
	os.WriteFile(ca, good, 0o644)
	c.http.CloseIdleConnections()
	if _, err := c.Version(context.Background()); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("the CA put back: %v", err)
	}
}

// The service authenticates by certificate: a URL carrying a password is
// refused before anything is dialled, and not echoed.
func TestAURLWithCredentialsOrPlainHTTPIsRefused(t *testing.T) {
	for _, u := range []string{"https://ops:SECRET@inv.example:8443", "http://inv.example:8443"} {
		_, err := NewClient(u, "ca", "c", "k")
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: %v", u, err)
		}
	}
}
```

  Create `cmd/port49/inventory_service_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/testpki"
)

const servicePolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

const leaf01 = "  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}\n"

// testService is port49-inventory in-process, its syncer the operator's
// certificate may drive: the lab inventory PKI's operator is a syncer.
type testService struct {
	url, ca, cert, key, dir string
	syncer                  *inventory.Syncer
}

func startService(t *testing.T) *testService {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(servicePolicy), 0o600)
	s := &testService{dir: dir, ca: filepath.Join(pki, testpki.InvCA), cert: filepath.Join(pki, testpki.InvOperatorCert),
		key: filepath.Join(pki, testpki.InvOperatorKey)}
	s.writeSource(t, leaf01)
	m := inventory.NewMetrics(prometheus.NewRegistry())
	s.syncer = &inventory.Syncer{Sources: []inventory.Source{inventory.FileSource{SourceName: "lab_file",
		Path: filepath.Join(dir, "inventory.yaml")}}, Bounds: map[string]int{}, Default: 10,
		PolicyFile: filepath.Join(dir, "policy.yaml"), Key: key, Metrics: m, Now: time.Now, Log: io.Discard,
		State: inventory.State{Dir: filepath.Join(dir, "state"), Keep: 64}}
	cert, anchor, err := broker.LoadTLS(filepath.Join(pki, testpki.InvServerCert), filepath.Join(pki, testpki.InvServerKey),
		filepath.Join(pki, testpki.InvCA))
	if err != nil {
		t.Fatal(err)
	}
	api := &inventory.API{Syncer: s.syncer, Syncers: []string{"user:alice@slice.port49.test"}, Now: time.Now,
		Log: io.Discard, Metrics: m}
	h := inventory.Server("127.0.0.1:0", cert, anchor, api.Handler(), log.New(io.Discard, "", 0))
	srv := httptest.NewUnstartedServer(h.Handler)
	srv.TLS = h.TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// writeSource writes "devices:" and body (device lines, or nothing).
func (s *testService) writeSource(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "inventory.yaml"), []byte("devices:\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *testService) sync(t *testing.T) {
	t.Helper()
	if res := s.syncer.Sync(context.Background(), "api"); res.Outcome != "published" {
		t.Fatalf("%+v", res)
	}
}

func TestInventorySyncPrintsWhatTheServiceDid(t *testing.T) {
	svc := startService(t) // the in-process service, one device in its source
	var out, errOut bytes.Buffer
	args := []string{"inventory", "sync", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key}
	if code := run(args, &out, &errOut); code != 0 || !strings.Contains(out.String(), "published bundle 1 (") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := run(args, &out, &errOut); code != 0 || !strings.Contains(out.String(), "unchanged: bundle 1 is current") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	svc.writeSource(t, "") // no device: refused
	out.Reset()
	if code := run(args, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused; still publishing bundle 1: the sources name no device") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

func TestInventoryDiffAgainstTheService(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key, "--from", "1"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "bundle 1 → 2") ||
		!strings.Contains(out.String(), "! device added leaf-02") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
}
```


- [ ] **Step 2: Run them.** `go test ./internal/inventory/ ./cmd/port49/ -run 'Client|URLWith|InventorySync|InventoryDiffAgainst' -count=1`
  Expected: FAIL (undefined: `NewClient`, …).

- [ ] **Step 3: Implement the client.** Create `internal/inventory/client.go`:

```go
package inventory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/keyfile"
)

// ErrNoBundle is the service answering that it has published none yet.
var ErrNoBundle = errors.New("the inventory service has published no bundle yet")

// Client reads the service's API over mutual TLS: port49d's fetcher, and the
// port49 tool. The service's certificate is verified against the CA file
// alone; the client certificate is read from its files at each handshake, so
// a renewed workload certificate is used without a restart.
type Client struct {
	base *url.URL
	http *http.Client
}

// maxReply bounds a reply that is not a bundle.
const maxReply = 1 << 20

func NewClient(rawURL, caFile, certFile, keyFile string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("inventory.service.url must be https://host[:port]")
	}
	if u.User != nil {
		// Not printed: whatever is there is a credential.
		return nil, errors.New("inventory.service.url carries user information; the service authenticates by " +
			"certificate, so remove it")
	}
	if _, err := readCA(caFile); err != nil {
		return nil, err
	}
	if _, err := keyfile.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("tls_cert_file %s, tls_key_file %s: %w", certFile, keyFile, err)
	}
	host := u.Hostname()
	tr := &http.Transport{
		// A black-holed service costs 10s a dial, not the kernel's minutes
		// (pre-flight minor 5).
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			// Verification is not skipped: it is VerifyConnection's, in full,
			// against the CA file read at this handshake, so a CA rotation
			// needs no restart and no signal (pre-flight minor 6).
			InsecureSkipVerify: true,
			VerifyConnection:   func(cs tls.ConnectionState) error { return verifyService(cs, caFile, host) },
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				c, err := keyfile.LoadX509KeyPair(certFile, keyFile)
				return &c, err
			}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 6 * time.Minute, MaxIdleConnsPerHost: 2}
	return &Client{base: u, http: &http.Client{Transport: tr}}, nil
}

// readCA is the CA file's certificates, read as a regular file, bounded.
func readCA(caFile string) (*x509.CertPool, error) {
	raw, err := config.ReadRegular(caFile, maxReply)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("ca_file %s holds no certificate", caFile)
	}
	return pool, nil
}

// verifyService is what crypto/tls would check, done here so the roots are
// the CA file as it is now: the chain to a root in it, for server auth, and
// the name or address the URL gives.
func verifyService(cs tls.ConnectionState, caFile, host string) error {
	pool, err := readCA(caFile)
	if err != nil {
		return err
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("the inventory service presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Roots: pool, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

// do asks path, with query as the URL's query: JoinPath would escape a `?`
// written into the path (conflict scan F13).
func (c *Client) do(ctx context.Context, method, path, query string, hdr map[string]string) (*http.Response, error) {
	u := c.base.JoinPath(path)
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.http.Do(req)
}

// answer decodes a JSON reply into v, or says what the service refused with:
// its fixed error code, never its body.
func answer(resp *http.Response, v any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return json.Unmarshal(body, v)
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Error == "no_bundle" {
		return ErrNoBundle
	}
	if !bundle.NameOK(e.Error) {
		e.Error = "an unreadable error"
	}
	return fmt.Errorf("the inventory service answered %d (%s)", resp.StatusCode, e.Error)
}

func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var v VersionInfo
	resp, err := c.do(ctx, "GET", "/v1/bundle/version", "", nil)
	if err != nil {
		return v, err
	}
	return v, answer(resp, &v)
}

// Bundle is the sealed document, unless etag is the service's, which is
// notModified.
func (c *Client) Bundle(ctx context.Context, etag string) ([]byte, string, bool, error) {
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-None-Match"] = etag
	}
	resp, err := c.do(ctx, "GET", "/v1/bundle", "", hdr)
	if err != nil {
		return nil, "", false, err
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, answer(resp, nil)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxDocument+1))
	if err != nil {
		return nil, "", false, err
	}
	if len(raw) > bundle.MaxDocument {
		return nil, "", false, fmt.Errorf("the inventory service sent more than %d bytes", bundle.MaxDocument)
	}
	return raw, resp.Header.Get("ETag"), false, nil
}

func (c *Client) Sync(ctx context.Context) (Result, error) {
	var r Result
	resp, err := c.do(ctx, "POST", "/v1/sync", "", nil)
	if err != nil {
		return r, err
	}
	return r, answer(resp, &r)
}

func (c *Client) Diff(ctx context.Context, from int64) (DiffResult, error) {
	var d DiffResult
	resp, err := c.do(ctx, "GET", "/v1/bundle/diff", "from="+strconv.FormatInt(from, 10), nil)
	if err != nil {
		return d, err
	}
	return d, answer(resp, &d)
}
```

- [ ] **Step 4: Implement the commands.** In `cmd/port49/inventory.go`, dispatch `sync` from
  `inventoryCmd`, and in `inventoryDiff` a `--service` branch taken when `--service` is given (then
  `--policy` and the two files are not). Both parse `--service`, `--ca`, `--cert`, `--key` (and
  `--from` for the diff), build `inventory.NewClient`, and print:

```go
// printResult is a sync's outcome as `port49 inventory sync` prints it, and
// its exit code: 0 for published and unchanged, 1 otherwise.
func printResult(w io.Writer, res inventory.Result) int {
	switch res.Outcome {
	case "published":
		fmt.Fprintf(w, "published bundle %d (%s): %s; %d quarantined\n", res.Sequence, res.Bundle, res.Summary,
			len(res.Quarantined))
		for _, c := range res.Changes {
			fmt.Fprintln(w, c.Line(""))
		}
		for _, q := range res.Quarantined {
			fmt.Fprintf(w, "  device %s (%s) is quarantined against the service's policy: %s\n", q.Device, q.Platform, q.Cause)
		}
		for _, l := range res.LeftOut {
			fmt.Fprintf(w, "  left out: %s\n", l)
		}
		return 0
	case "unchanged":
		fmt.Fprintf(w, "unchanged: bundle %d is current\n", res.Sequence)
		return 0
	}
	still := "no bundle is published yet"
	if res.Sequence > 0 {
		still = fmt.Sprintf("still publishing bundle %d", res.Sequence)
	}
	fmt.Fprintf(w, "%s; %s: %s\n", res.Outcome, still, res.Reason)
	return 1
}
```

  The diff prints `bundle <from> → <to>: <summary>` and each change's `c.Line("")`. A client error
  prints `port49 inventory sync: <error>` and exits 1. Add both to `usage`:
  `  port49 inventory sync --service URL --ca FILE --cert FILE --key FILE` and
  `  port49 inventory diff --service URL --ca FILE --cert FILE --key FILE --from SEQUENCE`.

- [ ] **Step 5: Run them.** `go test ./internal/inventory/ ./cmd/port49/ -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory cmd/port49
git commit -m "feat: the inventory client, port49 inventory sync and inventory diff --service

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: port49d.yaml's `inventory.service`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/service_test.go`

**Interfaces:**
- Consumes: `fence.ReadVerifyKeys` (Task 6); `inventoryYAML`, `Load`, `yamlfault`; the tests'
  `sample`, `inv`, `write`, `setKeyEnv` (`config_test.go`) and `brokerBlock` (`broker_test.go`).
- Produces:
  - `type config.InventoryServiceConfig struct { URL, CAFile, TLSCertFile, TLSKeyFile string;
    VerifyKeyFiles []string; PollInterval time.Duration; StateDir, MirrorDir string }` (YAML `url`,
    `ca_file`, `tls_cert_file`, `tls_key_file`, `verify_key_files`, `poll_interval`, `state_dir`,
    `mirror_dir`), under `inventory.service`.
  - `config.Config.InventoryService *InventoryServiceConfig` — nil without the block.
  - `func config.VerifyKeys(files []string) ([]ed25519.PublicKey, error)`.
  - `func config.InventoryServiceOf(raw []byte) (*InventoryServiceConfig, error)` — the block from a
    port49d.yaml's bytes, decoded and checked as `Load` does; nil, nil without one (SIGHUP's re-read).

- [ ] **Step 1: Write the failing tests.** Create `internal/config/service_test.go`:

```go
package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/keyfile"
)

// loadService is the standing sample (config_test.go) with block appended:
// with or without its inventory_file line, and with or without broker_test.go's
// broker block.
func loadService(t *testing.T, withFile, withBroker bool, block string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	body := fmt.Sprintf(sample, write(t, "inv.yaml", inv))
	if !withFile {
		body = regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(body, "")
	}
	if withBroker {
		body += brokerBlock
	}
	return Load(write(t, "port49d.yaml", body+block))
}

// serviceBlock is inventory.service with a verify key that exists.
func serviceBlock(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, pubPEM, _ := keyfile.EncodeEd25519(priv)
	pub := filepath.Join(t.TempDir(), "signing.pub")
	os.WriteFile(pub, pubPEM, 0o644)
	return fmt.Sprintf(`inventory:
  service:
    url: https://inv.example:8443
    ca_file: /etc/port49/inventory-ca.pem
    tls_cert_file: /etc/port49/port49d.pem
    tls_key_file: /etc/port49/port49d-key.pem
    verify_key_files: [%s]
    state_dir: /var/lib/port49/inventory
`, pub)
}

func TestTheInventoryServiceBlockLoadsInPlaceOfTheFile(t *testing.T) {
	c, err := loadService(t, false, true, serviceBlock(t))
	if err != nil {
		t.Fatal(err)
	}
	s := c.InventoryService
	if s == nil || s.PollInterval != 30*time.Second || s.StateDir != "/var/lib/port49/inventory" || c.InventoryFile != "" {
		t.Fatalf("%+v", s)
	}
	if keys, err := VerifyKeys(s.VerifyKeyFiles); err != nil || len(keys) != 1 {
		t.Fatalf("%v %v", keys, err)
	}
}

func TestTheInventoryServiceBlockIsRefusedWhereItCannotWork(t *testing.T) {
	block := serviceBlock(t)
	for name, c := range map[string]struct {
		cfg  func() (Config, error)
		want string
	}{
		"both sources": {func() (Config, error) { return loadService(t, true, true, block) },
			"name inventory_file or inventory.service, not both"},
		"neither": {func() (Config, error) { return loadService(t, false, true, "") },
			"inventory_file or inventory.service is required"},
		"no broker": {func() (Config, error) { return loadService(t, false, false, block) },
			"inventory.service needs a broker: block"},
		"plain http": {func() (Config, error) {
			return loadService(t, false, true, strings.Replace(block, "https://", "http://", 1))
		}, "inventory.service.url must be https"},
		"no verify key": {func() (Config, error) {
			return loadService(t, false, true, strings.Replace(block, "verify_key_files: [", "verify_key_files: [/nonexistent/x.pub, ", 1))
		}, "inventory.service.verify_key_files[0]"},
		"poll too fast": {func() (Config, error) {
			return loadService(t, false, true, block+"    poll_interval: 1s\n")
		}, "poll_interval must be between 5s and 10m"},
	} {
		if _, err := c.cfg(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// Pre-flight M3: a verify key others could write refuses the start.
func TestAVerifyKeyOthersCouldWriteRefusesTheStart(t *testing.T) {
	block := serviceBlock(t)
	pub := regexp.MustCompile(`verify_key_files: \[(.*)\]`).FindStringSubmatch(block)[1]
	if err := os.Chmod(pub, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := loadService(t, false, true, block); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
}

// SIGHUP re-reads verify_key_files (Decided 12).
func TestInventoryServiceOfReadsTheBlockAlone(t *testing.T) {
	s, err := InventoryServiceOf([]byte(serviceBlock(t)))
	if err != nil || s == nil || len(s.VerifyKeyFiles) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	if s, err := InventoryServiceOf([]byte("inventory: {max_removed_percent: 10}\n")); s != nil || err != nil {
		t.Fatalf("no block: %v %v", s, err)
	}
}
```


- [ ] **Step 2: Run them.** `go test ./internal/config/ -run 'InventoryService' -count=1`
  Expected: FAIL (undefined: `InventoryService`, …).

- [ ] **Step 3: Implement.** In `internal/config/config.go`:

```go
// InventoryServiceConfig is where port49d takes its inventory from when the
// inventory service publishes it (spec §10), in place of inventory_file.
// port49d asks url every poll_interval for the bundle's version, over mutual
// TLS with its own certificate, and fetches a new document when it changes.
// Every document, from the service, from state_dir or from mirror_dir, is
// verified against verify_key_files (spec §13, decision 30) and applied
// against port49d's own broker.policy_file (decision 29).
type InventoryServiceConfig struct {
	URL         string `yaml:"url"`
	CAFile      string `yaml:"ca_file"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// VerifyKeyFiles are the service's signing public keys: two while its key
	// rotates. SIGHUP re-reads the list.
	VerifyKeyFiles []string `yaml:"verify_key_files"`
	// PollInterval is how often port49d asks: default 30s, 5s to 10m.
	PollInterval time.Duration `yaml:"poll_interval"`
	// StateDir holds the last document port49d applied, bundle.json, which a
	// restart starts from with no service (spec §10, a MUST).
	StateDir string `yaml:"state_dir"`
	// MirrorDir is the shared copy the service writes, read at a cold start
	// when StateDir has none. Optional.
	MirrorDir string `yaml:"mirror_dir"`
}
```

  Add `Service *InventoryServiceConfig `yaml:"service"`` to `inventoryYAML` and
  `InventoryService *InventoryServiceConfig` to `Config` (comment: "nil without an inventory.service
  block; with one, InventoryFile is empty"). In `Load`, replace `if c.InventoryFile == "" { return
  Config{}, fmt.Errorf("config: inventory_file is required") }` with:

```go
	switch svc := f.InventoryOpts.Service; {
	case svc != nil && c.InventoryFile != "":
		return Config{}, fmt.Errorf("config: name inventory_file or inventory.service, not both: two inventory " +
			"sources would be the disagreement the bundle exists to prevent (spec §10)")
	case svc == nil && c.InventoryFile == "":
		return Config{}, fmt.Errorf("config: inventory_file or inventory.service is required")
	case svc != nil:
		if f.Broker == nil {
			return Config{}, fmt.Errorf("config: inventory.service needs a broker: block: port49d applies the " +
				"service's inventory against its own broker.policy_file (spec §13, decision 29)")
		}
		if c.InventoryService, err = checkService(*svc); err != nil {
			return Config{}, err
		}
	}
```

  and add:

```go
func checkService(s InventoryServiceConfig) (*InventoryServiceConfig, error) {
	if u, err := url.Parse(s.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("config: inventory.service.url must be https://host[:port], with no user information")
	}
	for _, req := range []struct{ key, v string }{{"ca_file", s.CAFile}, {"tls_cert_file", s.TLSCertFile},
		{"tls_key_file", s.TLSKeyFile}, {"state_dir", s.StateDir}} {
		if req.v == "" {
			return nil, fmt.Errorf("config: inventory.service.%s is required", req.key)
		}
	}
	if len(s.VerifyKeyFiles) == 0 {
		return nil, fmt.Errorf("config: inventory.service.verify_key_files must name the service's signing public " +
			"key (port49 inventory keygen writes it)")
	}
	if _, err := VerifyKeys(s.VerifyKeyFiles); err != nil {
		return nil, err
	}
	s.PollInterval = orD(s.PollInterval, 30*time.Second)
	if s.PollInterval < 5*time.Second || s.PollInterval > 10*time.Minute {
		return nil, fmt.Errorf("config: inventory.service.poll_interval must be between 5s and 10m; got %s",
			s.PollInterval)
	}
	return &s, nil
}

// VerifyKeys reads each verify key file behind the write fence (pre-flight
// M3): a verify key is the trust root of the bundle's signature, so whoever
// could write it would have any inventory they sign accepted — from the
// mirror, the persisted copy and the API alike. One that does not read is
// named by its position and path.
func VerifyKeys(files []string) ([]ed25519.PublicKey, error) {
	keys, err := fence.ReadVerifyKeys("inventory.service.verify_key_files", files)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return keys, nil
}

// InventoryServiceOf is inventory.service from a port49d.yaml's bytes,
// decoded as strictly as Load and checked as Load checks it, or nil when the
// file has none: what SIGHUP re-reads verify_key_files from. It resolves no
// secret.
func InventoryServiceOf(raw []byte) (*InventoryServiceConfig, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	if f.InventoryOpts.Service == nil {
		return nil, nil
	}
	return checkService(*f.InventoryOpts.Service)
}
```

  Imports gain `crypto/ed25519`, `net/url` and `internal/fence` (which imports nothing of
  `internal/config`, so there is no cycle). The `c.Broker != nil` early
  return already leaves the inventory unread, so nothing below it changes.

- [ ] **Step 4: Run them.** `go test ./internal/config/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/config
git commit -m "feat(config): inventory.service, in place of inventory_file

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: Cold start: the newer copy, or no TACACS+ and `/readyz` 503 until the service answers

**Files:**
- Create: `cmd/port49d/coldstart.go`
- Test: `cmd/port49d/coldstart_test.go`
- Modify: `cmd/port49d/main.go` (the metrics listener first, `/readyz`, the service path);
  `cmd/port49d/reload.go` (no inventory-file poll in service mode; `inForce`, `seq`, `latestRaw`,
  `startDocument`)
- Modify (mechanically, for the `loadPolicy` and `buildBroker` signatures): `cmd/port49d/broker_test.go`
  (`loadPolicy` and every `buildBroker` call), `cmd/port49d/reload_test.go` (`newReloadRig`'s
  `buildBroker`), `cmd/port49d/reload_inventory_test.go` (`restart`'s `loadPolicy`/`buildBroker`); name
  them in the report and the commit
- Modify: `internal/daemon/metrics/metrics.go` (`InventoryBundleSequence`, `InventoryPersistFailed`,
  `InventoryBundleRefused`)

**Interfaces:**
- Consumes: `config.InventoryServiceConfig`, `config.VerifyKeys` (Task 13); `inventory.Client`,
  `VersionInfo`, `Published`, `OpenFile`, `WriteAtomic` (Tasks 8, 12); `fence.Read` (Task 6);
  `bundle.Open`, `bundle.MaxDocument` (Task 4).
- Produces:
  - `type fetchClient interface { Version(ctx) (inventory.VersionInfo, error); Bundle(ctx, etag string)
    ([]byte, string, bool, error) }` — `*inventory.Client` is one; tests fake it.
  - `func readPersisted(dir string, keys []ed25519.PublicKey) (*inventory.Published, error)` — nil,
    nil when absent; read behind the fence.
  - `func readMirrorFile(dir string, keys []ed25519.PublicKey) (*inventory.Published, error)`, read
    through the variable `readMirror` under `mirrorDeadline` (10 s) by `mirrorWithin` (pre-flight M4).
  - `const requestTimeout = 30 * time.Second` — every ask of the service (minor 5; Task 15's fetcher
    uses it too).
  - `func persistBundle(dir string, raw []byte) error` — `dir/bundle.json`, 0600, atomic.
  - `func coldStart(ctx context.Context, svc *config.InventoryServiceConfig, keys []ed25519.PublicKey,
    c fetchClient, m *metrics.Metrics) (*inventory.Published, string, error)` — the document and where
    it came from
    (`the persisted copy`, `the mirror's copy`, `the service`); of two copies, the one published later
    (minor 11).
  - `func (r *reloader) startDocument(p *inventory.Published, from string)` — records the etag,
    sequence and sealed bytes in force, and dates the snapshot: from `p.Doc.PublishedAt` for a copy,
    from now for the service (M5). This task declares the reloader fields it writes: `inForce string`,
    `seq int64`, `latestRaw []byte`; Task 15 declares the rest.
  - `metrics.InventoryBundleRefused` (`port49_inventory_bundle_refused`): 1 while a document port49d
    was given does not open or was refused; a copy that fails `bundle.Open` at cold start sets it
    (spec §10 as Task 1 writes it: "refused, said once, and alarmed").
  - `metrics.InventoryBundleSequence` (`port49_inventory_bundle_sequence`),
    `metrics.InventoryPersistFailed` (`port49_inventory_persist_failed`).
  - `/readyz` on the metrics listener: 200 while the TACACS+ listener serves, 503 before and during
    shutdown.

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49d/coldstart_test.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

// fakeService answers from a script; a nil entry fails as a dial does.
type fakeService struct {
	bundles [][]byte
	calls   int
	t       *testing.T
	forbid  bool
}

func (f *fakeService) Version(context.Context) (inventory.VersionInfo, error) {
	return inventory.VersionInfo{}, errors.New("unused")
}

func (f *fakeService) Bundle(_ context.Context, _ string) ([]byte, string, bool, error) {
	if f.forbid {
		f.t.Fatal("the service was asked with a copy at hand")
	}
	i := min(f.calls, len(f.bundles)-1)
	f.calls++
	if f.bundles[i] == nil {
		return nil, "", false, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	}
	return f.bundles[i], bundle.ETag(f.bundles[i]), false, nil
}

func sealedDoc(t *testing.T, key ed25519.PrivateKey, seq int64, n int) []byte {
	t.Helper()
	return sealedDocAt(t, key, seq, n, time.Now())
}

// sealedDocAt is sealedDoc published at at.
func sealedDocAt(t *testing.T, key ed25519.PrivateKey, seq int64, n int, at time.Time) []byte {
	t.Helper()
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: "leaf" + string(rune('0'+i)), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	raw, err := bundle.Seal(bundle.NewDocument(seq, at, []byte(minimalPolicy), "1.1.0", inv, nil), key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func coldRig(t *testing.T) (*config.InventoryServiceConfig, ed25519.PrivateKey, []ed25519.PublicKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &config.InventoryServiceConfig{URL: "https://inv.test:8443", StateDir: filepath.Join(safeDir(t), "state"),
		MirrorDir: safeDir(t), PollInterval: 10 * time.Millisecond}
	return svc, key, []ed25519.PublicKey{pub}
}

func TestColdStartTakesTheNewerCopyAndNeverAsksTheService(t *testing.T) {
	svc, key, keys := coldRig(t)
	if err := persistBundle(svc.StateDir, sealedDocAt(t, key, 3, 1, time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, key, 5, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
	if err != nil || p.Doc.Sequence != 5 || from != "the mirror's copy" {
		t.Fatalf("%v %q %v", p, from, err)
	}
}

// Pre-flight minor 11: newer is later publication, not a higher sequence,
// which a service reset starts again at 1.
func TestColdStartPrefersTheLaterPublicationOverTheHigherSequence(t *testing.T) {
	svc, key, keys := coldRig(t)
	persistBundle(svc.StateDir, sealedDocAt(t, key, 40, 1, time.Now().Add(-48*time.Hour)))
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, key, 2, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
	if err != nil || p.Doc.Sequence != 2 || from != "the mirror's copy" ||
		!strings.Contains(out.String(), "published later than the persisted copy") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
}

// Pre-flight M4: a mirror mount that hangs is passed over at its deadline,
// said, and the start goes on from the persisted copy.
func TestAHungMirrorNeverHoldsUpAStartFromThePersistedCopy(t *testing.T) {
	svc, key, keys := coldRig(t)
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
	hang := make(chan struct{})
	defer close(hang)
	defer func(r func(string, []ed25519.PublicKey) (*inventory.Published, error), d time.Duration) {
		readMirror, mirrorDeadline = r, d
	}(readMirror, mirrorDeadline)
	readMirror = func(string, []ed25519.PublicKey) (*inventory.Published, error) { <-hang; return nil, nil }
	mirrorDeadline = 50 * time.Millisecond
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	start := time.Now()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
	if err != nil || from != "the persisted copy" || p.Doc.Sequence != 3 || time.Since(start) > 5*time.Second ||
		!strings.Contains(out.String(), "the mirror's copy is passed over: mirror_dir "+svc.MirrorDir+" did not answer in") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
}

// Pre-flight M5: a start from a copy dates the snapshot from its
// publication, so a restart never makes an old snapshot look fresh.
func TestAStartFromACopyCountsTheAgeFromItsPublication(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealedDocAt(t, key, 7, 1, rig.now.Add(-48*time.Hour))
	doc, inv, err := bundle.Open(raw, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	rig.r.startDocument(&inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the persisted copy")
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age < 47*3600 || age > 49*3600 {
		t.Fatalf("age %v, want about two days", age)
	}
	rig.r.startDocument(&inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the service")
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age > 1 {
		t.Fatalf("a start from the service is a confirmation: age %v", age)
	}
}

func testMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

// A copy the service did not sign is passed over, said, and alarmed (spec
// §10: "refused, said once, and alarmed").
func TestACopyThatDoesNotVerifyIsPassedOver(t *testing.T) {
	svc, key, keys := coldRig(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, other, 9, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m)
	if err != nil || p.Doc.Sequence != 3 || from != "the persisted copy" ||
		!strings.Contains(out.String(), "which no verify key holds") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatal("port49_inventory_bundle_refused is not 1 for a copy that does not open")
	}
}

// The persisted copy is port49d's own and read behind the write fence.
func TestAPersistedCopyOthersCouldWriteIsPassedOver(t *testing.T) {
	svc, key, keys := coldRig(t)
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
	os.Chmod(filepath.Join(svc.StateDir, "bundle.json"), 0o664)
	if p, err := readPersisted(svc.StateDir, keys); p != nil || err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v %v", p, err)
	}
}

// With neither copy, port49d waits for the service, says why once per
// reason, and persists what it gets.
func TestWithNoCopyItWaitsForTheServiceSayingWhyOnce(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	doc := sealedDoc(t, key, 1, 2)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{nil, nil, nil, doc}}, testMetrics())
	if err != nil || p.Doc.Sequence != 1 || from != "the service" {
		t.Fatalf("%v %q %v", p, from, err)
	}
	if n := strings.Count(out.String(), "port49d: inventory: no bundle yet (persisted copy: none in "); n != 1 ||
		!strings.Contains(out.String(), "mirror: none configured; service at https://inv.test:8443: dial tcp") ||
		!strings.Contains(out.String(), "TACACS+ is not served until one arrives, and /readyz answers 503") {
		t.Fatalf("said %d times: %s", n, out.String())
	}
	fi, err := os.Stat(filepath.Join(svc.StateDir, "bundle.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("not persisted: %v %v", fi, err)
	}
}

func TestColdStartEndsWithItsContext(t *testing.T) {
	svc, _, keys := coldRig(t)
	svc.MirrorDir = ""
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	if _, _, err := coldStart(ctx, svc, keys, &fakeService{bundles: [][]byte{nil}}, testMetrics()); !errors.Is(err,
		context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
```

  Add to `cmd/port49d/run_test.go` two tests through `run`, with two helpers:

```go
// keyPath writes key's public half where verify_key_files can name it.
func keyPath(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	_, pubPEM, err := keyfile.EncodeEd25519(key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "signing.pub")
	if err := os.WriteFile(p, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeServiceRunConfig is writeRunConfig with inventory.service in place of
// inventory_file: svc's url, state_dir and mirror_dir, pki's inventory PKI
// for its TLS files — the service's own, so the two verify each other, or a
// fresh one when pki is "" (pre-flight M8) — and pubFile as its one verify
// key (a fresh key's when "").
func writeServiceRunConfig(t *testing.T, b *config.BrokerConfig, svc *config.InventoryServiceConfig,
	pki, pubFile string) string {
	t.Helper()
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if pki == "" {
		pki = filepath.Join(safeDir(t), "inv-pki")
		if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if pubFile == "" {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		pubFile = keyPath(t, key)
	}
	mirror := ""
	if svc.MirrorDir != "" {
		mirror = "    mirror_dir: " + svc.MirrorDir + "\n"
	}
	body := regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(string(raw), "") +
		fmt.Sprintf("inventory:\n  service:\n    url: %s\n    ca_file: %s\n    tls_cert_file: %s\n"+
			"    tls_key_file: %s\n    verify_key_files: [%s]\n    poll_interval: 5s\n    state_dir: %s\n%s",
			svc.URL, filepath.Join(pki, testpki.InvCA), filepath.Join(pki, testpki.InvDaemonCert),
			filepath.Join(pki, testpki.InvDaemonKey), pubFile, svc.StateDir, mirror)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}
```

  and the tests:

```go
// Spec §10, cold start: no copy, no service — port49d serves no TACACS+ and
// is not ready, and says why.
func TestRunWithNoBundleServesNoTACACSAndIsNotReady(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 127.0.0.0/8}, key_ref: k}]\n").Broker
	svc, _, _ := coldRig(t)
	svc.URL, svc.MirrorDir = "https://127.0.0.1:1", ""
	cfgPath := writeServiceRunConfig(t, b, svc, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: inventory: no bundle yet")
	metrics := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if metrics == nil {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	if resp, err := http.Get("http://" + metrics[1] + "/readyz"); err != nil || resp.StatusCode != 503 {
		t.Fatalf("readyz: %v %v", resp, err)
	}
	if strings.Contains(out.String(), "port49d: listening on") {
		t.Fatal("TACACS+ is listening with no bundle")
	}
}

// A restart in place with the service down starts from the persisted copy.
func TestRunStartsFromThePersistedCopyWithTheServiceDown(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n").Broker
	svc, key, _ := coldRig(t)
	svc.URL, svc.MirrorDir = "https://127.0.0.1:1", ""
	persistBundle(svc.StateDir, sealedDoc(t, key, 7, 2))
	cfgPath := writeServiceRunConfig(t, b, svc, "", keyPath(t, key))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 7 (") ||
		!strings.Contains(out.String(), "the persisted copy") {
		t.Fatalf("the start line: %s", out.String())
	}
	metrics := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if resp, err := http.Get("http://" + metrics[1] + "/readyz"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("readyz: %v %v", resp, err)
	}
}
```

  `writeRunConfig`'s keys block defines `k`, as the policies above name.

- [ ] **Step 2: Run them.** `go test ./cmd/port49d/ -run 'ColdStart|Copy|NoCopy|NoBundle|PersistedCopy' -count=1`
  Expected: FAIL (undefined: `coldStart`, `persistBundle`, …).

- [ ] **Step 3: Implement the copies and the wait.** Create `cmd/port49d/coldstart.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/inventory"
)

// fetchClient is what port49d asks the inventory service: the version, and
// the document. *inventory.Client is one.
type fetchClient interface {
	Version(ctx context.Context) (inventory.VersionInfo, error)
	Bundle(ctx context.Context, etag string) ([]byte, string, bool, error)
}

// persistedName is the copy port49d keeps in inventory.service.state_dir.
const persistedName = "bundle.json"

// readPersisted is port49d's own copy (spec §10: "the last good bundle is
// persisted to local disk"), read behind the write fence, since whoever can
// write it decides a restart's inventory, and verified. nil, nil when there
// is none.
func readPersisted(dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	path := filepath.Join(dir, persistedName)
	raw, err := fence.Read(path, bundle.MaxDocument, "persisted bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &inventory.Published{Raw: raw, Doc: doc, Inv: inv}, nil
}

// readMirrorFile is the shared mirror's copy (spec §10). The mount is the
// deployment's and anyone with the store's credentials may write it, so the
// signature, not the file's owner, is what is checked. nil, nil with no
// mirror or no copy in it.
func readMirrorFile(dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	if dir == "" {
		return nil, nil
	}
	p, err := inventory.OpenFile(filepath.Join(dir, persistedName), keys)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return p, err
}

// readMirror is the mirror read, swapped in tests; mirrorDeadline bounds it.
var (
	readMirror     = readMirrorFile
	mirrorDeadline = 10 * time.Second
)

// requestTimeout bounds one ask of the service: one that accepts and never
// answers must not stretch the retries (pre-flight minor 5).
const requestTimeout = 30 * time.Second

// mirrorWithin reads the mirror under mirrorDeadline (pre-flight M4). A
// read from a FUSE, NFS or object-store CSI mount that has hung blocks in
// the kernel, and O_NONBLOCK does not help on a regular file, so the read
// runs in a goroutine that is abandoned at the deadline: a hung mount costs
// the start ten seconds and one goroutine, never the start itself (spec §10:
// a restart in place needs nothing).
func mirrorWithin(dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	type result struct {
		p   *inventory.Published
		err error
	}
	done := make(chan result, 1)
	read := readMirror // read before the goroutine: a test swaps the variable back while it blocks
	go func() {
		p, err := read(dir, keys)
		done <- result{p, err}
	}()
	select {
	case r := <-done:
		return r.p, r.err
	case <-time.After(mirrorDeadline):
		return nil, fmt.Errorf("mirror_dir %s did not answer in %s", dir, mirrorDeadline)
	}
}

// persistBundle keeps raw as port49d's copy: atomic, 0600, in a directory
// only port49d's user can write.
func persistBundle(dir string, raw []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return inventory.WriteAtomic(dir, persistedName, raw, 0o600)
}

// coldStart is port49d's first inventory with inventory.service (spec §10,
// "Cold start"; Decided 5): the newer of its persisted copy and the mirror's,
// and with neither, the service, asked every poll_interval until it answers.
// Only that last case waits, and while it does port49d serves no TACACS+ and
// /readyz answers 503, since the caller has not opened the listener. Each
// reason it is still waiting is said once. A copy that does not open is said
// and passed over.
func coldStart(ctx context.Context, svc *config.InventoryServiceConfig, keys []ed25519.PublicKey,
	c fetchClient, m *metrics.Metrics) (*inventory.Published, string, error) {
	persistedWhy, mirrorWhy := "none in "+svc.StateDir, "none configured"
	var best *inventory.Published
	from := ""
	if p, err := readPersisted(svc.StateDir, keys); err != nil {
		persistedWhy = oneLine(err)
		m.InventoryBundleRefused.Set(1) // refused, said once, and alarmed (spec §10)
		fmt.Fprintf(stderr, "port49d: inventory: the persisted copy is passed over: %s\n", persistedWhy)
	} else if p != nil {
		best, from = p, "the persisted copy"
	}
	if svc.MirrorDir != "" {
		mirrorWhy = "none in " + svc.MirrorDir
		if mc, err := mirrorWithin(svc.MirrorDir, keys); err != nil {
			mirrorWhy = oneLine(err)
			m.InventoryBundleRefused.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: the mirror's copy is passed over: %s\n", mirrorWhy)
		} else if mc != nil && (best == nil || mc.Doc.PublishedAt.After(best.Doc.PublishedAt)) {
			// Newer is later publication: a sequence starts again at 1
			// after a service reset, a publication time does not
			// (pre-flight minor 11).
			if best != nil {
				fmt.Fprintf(stderr, "port49d: inventory: the mirror's bundle %d, published %s, is published later "+
					"than the persisted copy's bundle %d, published %s\n", mc.Doc.Sequence,
					mc.Doc.PublishedAt.Format(time.RFC3339), best.Doc.Sequence, best.Doc.PublishedAt.Format(time.RFC3339))
			}
			best, from = mc, "the mirror's copy"
		}
	}
	said := ""
	for best == nil {
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		raw, _, _, err := c.Bundle(rctx, "")
		cancel()
		if err == nil {
			doc, inv, oerr := bundle.Open(raw, keys)
			if oerr == nil {
				best, from = &inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the service"
				break
			}
			m.InventoryBundleRefused.Set(1)
			err = oerr
		}
		if why := fmt.Sprintf("port49d: inventory: no bundle yet (persisted copy: %s; mirror: %s; service at %s: %s); "+
			"TACACS+ is not served until one arrives, and /readyz answers 503 (spec §10, cold start)", persistedWhy,
			mirrorWhy, svc.URL, oneLine(err)); why != said {
			fmt.Fprintln(stderr, why)
			said = why
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(svc.PollInterval):
		}
	}
	if from != "the persisted copy" {
		if err := persistBundle(svc.StateDir, best.Raw); err != nil {
			fmt.Fprintf(stderr, "port49d: inventory: state_dir %s: %s; a restart with the service down will "+
				"need the mirror\n", svc.StateDir, oneLine(err))
		}
	}
	fmt.Fprintf(stderr, "port49d: inventory: starting from bundle %d (%s), %s, published %s; the service at %s is "+
		"asked every %s\n", best.Doc.Sequence, best.Doc.Bundle, from, best.Doc.PublishedAt.Format(time.RFC3339),
		svc.URL, svc.PollInterval)
	return best, from, nil
}
```

- [ ] **Step 4: Wire it into `run`.** In `cmd/port49d/main.go`:
  1. Move `reg := prometheus.NewRegistry()`, `m := metrics.New(reg)` and the metrics listener's bind
     and serve up to just after `announce(stderr, &cfg)`, with `defer mln.Close()`, and add a `ready
     atomic.Bool` whose `/readyz` handler answers 200 when set and 503 otherwise. The listener's
     address goes into a line of its own at once — `port49d: metrics on %s` — since a cold start may
     wait a long time before the `listening` line. Keep every later `mln.Close()`: a second close is
     harmless.
  2. Replace the `if cfg.Broker != nil { inv, v, err := fencedInventory(cfg) … }` block, which runs
     before `announce` today, with this one placed right after the metrics listener binds (so a cold
     start's `/readyz` answers 503 while it waits):

```go
	var inventoryAtStart string
	var startDoc *inventory.Published
	// Service mode's verify keys and client, which the fetcher (Task 15)
	// goes on with after the start.
	var verifyKeysAtStart []ed25519.PublicKey
	var client *inventory.Client
	var startFrom string
	switch {
	case cfg.InventoryService != nil:
		// Spec §10, cold start: a copy, or the service; until one, no
		// listener and /readyz 503 (Decided 5).
		if verifyKeysAtStart, err = config.VerifyKeys(cfg.InventoryService.VerifyKeyFiles); err != nil {
			return err
		}
		if client, err = inventory.NewClient(cfg.InventoryService.URL, cfg.InventoryService.CAFile,
			cfg.InventoryService.TLSCertFile, cfg.InventoryService.TLSKeyFile); err != nil {
			return fmt.Errorf("inventory.service: %w", err)
		}
		if startDoc, startFrom, err = coldStart(ctx, cfg.InventoryService, verifyKeysAtStart, client, m); err != nil {
			if ctx.Err() != nil {
				return nil // stopped while waiting for a bundle: nothing was served
			}
			return err
		}
		cfg.Inventory = startDoc.Inv
		m.InventoryBundleSequence.Set(float64(startDoc.Doc.Sequence))
	case cfg.Broker != nil:
		inv, v, err := fencedInventory(cfg)
		if err != nil {
			return err
		}
		cfg.Inventory, inventoryAtStart = inv, v
	}
```

     (`ctx` is created before this block: move `ctx, cancel := context.WithCancel(parent)` up with it.)
  3. After the `port49d: listening on …` line, `ready.Store(true)`; at the `case <-ctx.Done()` of the
     final select, and before every return after it, `ready.Store(false)`.
  4. `loadPolicy`'s admits-none refusal names the inventory's source: `inventory_file X` in file mode,
     `the inventory service's bundle N` in service mode; pass the label in from `run` as a new
     parameter, `loadPolicy(cfg config.Config, inventoryFrom string)`, and update its callers and
     `buildBroker`'s signature to carry it.
  5. Hand the reloader the start document, once: `r.startDocument(startDoc, startFrom)` after
     `newReloader` (Task 15 adds the fetcher after this call and does not call it again). Add to the
     `reloader` struct the fields it writes:

```go
	// Service mode (inventory.service): inForce is the etag of the document
	// in force, seq its sequence, and latestRaw its sealed bytes, which a
	// persist that failed is retried with (pre-flight M7).
	inForce   string
	seq       int64
	latestRaw []byte
```

     and `startDocument` in `reload.go`:

```go
// startDocument records the document the start loaded — its etag and
// sequence, so the fetcher's first unchanged answer confirms it — and dates
// the snapshot. A copy, persisted or mirrored, confirms nothing: the age
// counts from its publication, which may overstate it, the safe direction,
// until the first confirmation (spec §10; pre-flight M5). From the service,
// the start is itself a confirmation.
func (r *reloader) startDocument(p *inventory.Published, from string) {
	if p == nil {
		return
	}
	r.inForce, r.seq, r.latestRaw = bundle.ETag(p.Raw), p.Doc.Sequence, p.Raw
	seen := r.now()
	if from != "the service" {
		seen = p.Doc.PublishedAt
	}
	r.invSeen.Store(seen.UnixNano())
}
```

  In `cmd/port49d/reload.go`: `newReloader` reads `inventoryVersion(cfg.InventoryFile)` only when
  `cfg.InventoryFile != ""`; `poll` calls `pollInventory` only when `r.cfg.InventoryService == nil`;
  `reload` reads the inventory file only then. Add to `internal/daemon/metrics/metrics.go`, with
  `Help` text and registration as the neighbouring gauges:

```go
	// port49_inventory_bundle_sequence: the inventory service's sequence of
	// the document in force; 0 with inventory_file.
	InventoryBundleSequence prometheus.Gauge
	// port49_inventory_persist_failed: 1 while the document in force could
	// not be written to inventory.service.state_dir, so a restart with the
	// service down would start from an older copy, or none.
	InventoryPersistFailed prometheus.Gauge
	// port49_inventory_bundle_refused: 1 while a document port49d was given
	// — a copy at cold start, or one the service sent — did not open or was
	// refused; the bundle in force keeps serving. The first document from the
	// service applied or confirmed in force clears it.
	InventoryBundleRefused prometheus.Gauge
```

- [ ] **Step 5: Run them.** `go test ./cmd/port49d/ ./internal/daemon/metrics/ -count=1`
  Expected: PASS, the existing run and reload tests included.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add cmd/port49d internal/daemon/metrics
git commit -m "feat(port49d): cold start from the newer copy, or no TACACS+ until the service answers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 15: The pull: a fetcher that verifies, a reloader that bounds and swaps

**Files:**
- Create: `cmd/port49d/fetch.go`
- Test: `cmd/port49d/fetch_test.go`, `cmd/port49d/reload_service_test.go`
- Modify: `cmd/port49d/reload.go`, `cmd/port49d/main.go`
- Modify: `internal/bundle/diff.go` (`CheckFrom`; the key-group hint only where the inventory in force
  carries key groups), `internal/bundle/diff_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`InventoryFetches`)

**Interfaces:**
- Consumes: `fetchClient`, `persistBundle`, `requestTimeout`, the reloader's `inForce`, `seq` and
  `latestRaw`, `startDocument`, `metrics.InventoryBundleRefused` (Task 14); `bundle.Open`, `bundle.ETag`; `bundle.Parse`,
  `bundle.Diff`; `config.InventoryServiceOf`, `config.VerifyKeys` (Task 13); the reloader's `swap`,
  `after`, `rereadBound`, `invSeen`.
- Produces:
  - `type received struct { pub *inventory.Published; raw []byte; etag string; err error; unchanged bool }`.
  - `type fetcher struct { client fetchClient; keys func() []ed25519.PublicKey; url string; interval
    time.Duration; metrics *metrics.Metrics }` and `func (f *fetcher) run(ctx context.Context, out
    chan<- received, poke <-chan struct{})`.
  - On `reloader` (beside Task 14's `inForce`, `seq`, `latestRaw`): `docs <-chan received`, `poke
    chan<- struct{}`, `docRefused`, `persistSaid string`, `latest *received`, `verifyKeys
    atomic.Pointer[[]ed25519.PublicKey]`;
    `func (r *reloader) receive(ctx context.Context, d received)`;
    `func (r *reloader) loadDocument(ctx context.Context, trigger string, d received)`;
    `func (r *reloader) rereadVerifyKeys()`; `func (r *reloader) reopenLatest()`.
  - `func bundle.CheckFrom(old, new *policy.Policy, maxRemovedPercent int, fix string) error`;
    `Check` is `CheckFrom(…, "fix the file")`.
  - `metrics.InventoryFetches` (`port49_inventory_fetches_total{outcome}`: `unchanged`, `received`,
    `failed`, `invalid`).

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49d/reload_service_test.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/keyfile"
)

var _ = engine.HashOf // Task 16's tests use it

const groupedPolicy = minimalPolicy + "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n"

type serviceRig struct {
	*reloadRig
	key ed25519.PrivateKey
	pub ed25519.PublicKey
}

// newServiceRig is a reload rig whose inventory comes from the service: no
// inventory_file, a state_dir, and one verify key.
func newServiceRig(t *testing.T, policyBody string) *serviceRig {
	t.Helper()
	rig := &serviceRig{reloadRig: newReloadRig(t, policyBody)}
	rig.pub, rig.key, _ = ed25519.GenerateKey(rand.Reader)
	rig.cfg.InventoryFile = ""
	rig.cfg.InventoryService = &config.InventoryServiceConfig{URL: "https://inv.test:8443",
		StateDir: filepath.Join(safeDir(t), "state"), PollInterval: 30 * time.Second}
	rig.r.cfg = rig.cfg
	keys := []ed25519.PublicKey{rig.pub}
	rig.r.verifyKeys.Store(&keys)
	return rig
}

// doc is what the fetcher hands over for devices leaf1..leafN at 10.0.0.i,
// sealed and opened as it opens one, built against policyBody.
func (rig *serviceRig) doc(t *testing.T, seq int64, policyBody string, n int, extra ...admission.Device) received {
	t.Helper()
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: fmt.Sprintf("leaf%d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	inv.Devices = append(inv.Devices, extra...)
	raw, err := bundle.Seal(bundle.NewDocument(seq, rig.now, []byte(policyBody), "1.1.0", inv, nil), rig.key)
	if err != nil {
		t.Fatal(err)
	}
	doc, opened, err := bundle.Open(raw, []ed25519.PublicKey{rig.pub})
	if err != nil {
		t.Fatal(err)
	}
	return received{pub: &inventory.Published{Raw: raw, Doc: doc, Inv: opened}, raw: raw, etag: bundle.ETag(raw)}
}

func (rig *serviceRig) receive(d received) {
	rig.with(func() { rig.r.receive(context.Background(), d) })
}

func TestADocumentIsLoadedAsAReloadIsAndPersisted(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("not loaded: %s", rig.out.String())
	}
	if !strings.Contains(rig.out.String(), "port49d: inventory reloaded (inventory service, bundle 1): bundle ") {
		t.Fatalf("the swap line: %s", rig.out.String())
	}
	if !strings.Contains(buf.String(), `"kind":"device_added"`) {
		t.Fatalf("no inventory_change record: %s", buf.String())
	}
	p, err := readPersisted(rig.cfg.InventoryService.StateDir, []ed25519.PublicKey{rig.pub})
	if err != nil || p == nil || p.Doc.Sequence != 1 {
		t.Fatalf("persisted: %v %v", p, err)
	}
	if testutil.ToFloat64(rig.m.InventoryBundleSequence) != 1 ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")) != 1 {
		t.Fatal("metrics")
	}
}

// Spec §10: the daemon MUST NOT trust the payload — its own bound applies,
// said once per document, and SIGHUP after raising it applies the document
// held.
func TestADocumentOverTheBoundIsRefusedOnceAndSIGHUPAppliesIt(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 10))
	over := rig.doc(t, 2, groupedPolicy, 5)
	rig.receive(over)
	rig.receive(over)
	out := rig.out.String()
	if strings.Count(out, "port49d: inventory reload (inventory service, bundle 2) refused; still serving bundle") != 1 ||
		!strings.Contains(out, "removes 5 of 10 devices") || !strings.Contains(out, "fix the source of truth") ||
		strings.Contains(out, "key_groups was deleted") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatal("port49_inventory_bundle_refused is not 1")
	}
	rig.sighupWithBound(t, 100)
	if len(rig.b.Policy.Load().Devices()) != 5 || testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 {
		t.Fatalf("SIGHUP did not apply the document held: %s", rig.out.String())
	}
}

// Decided 12: a document signed by a key port49d does not hold yet is
// refused once, and applies at the SIGHUP that adds the key.
func TestADocumentThatDoesNotVerifyAppliesOnceItsKeyIsAdded(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := &serviceRig{reloadRig: rig.reloadRig, key: newKey, pub: newPub}
	d := rotated.doc(t, 2, groupedPolicy, 3)
	_, _, err := bundle.Open(d.raw, []ed25519.PublicKey{rig.pub})
	rig.receive(received{raw: d.raw, etag: d.etag, err: err})
	if !strings.Contains(rig.out.String(), "which no verify key holds") ||
		!strings.Contains(rig.out.String(), "add its public key to inventory.service.verify_key_files and send SIGHUP") {
		t.Fatalf("the refusal: %s", rig.out.String())
	}
	_, pubPEM, _ := keyfile.EncodeEd25519(newKey)
	newFile := filepath.Join(t.TempDir(), "new.pub")
	oldFile := filepath.Join(t.TempDir(), "old.pub")
	os.WriteFile(newFile, pubPEM, 0o644)
	_, oldPEM, _ := keyfile.EncodeEd25519(rig.key)
	os.WriteFile(oldFile, oldPEM, 0o644)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s, %s]}
`, oldFile, newFile)), 0o600)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if len(rig.b.Policy.Load().Devices()) != 3 {
		t.Fatalf("not applied after the key was added: %s", rig.out.String())
	}
}

// Pre-flight minor 4: a signature that does not verify under a key port49d
// holds is not a rotation, and the line says to investigate.
func TestATamperedDocumentIsCalledOutNotExplainedAsARotation(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy, 2)
	tampered := []byte(strings.Replace(string(d.raw), `"signature":"`, `"signature":"AAAA`, 1))
	_, _, err := bundle.Open(tampered, []ed25519.PublicKey{rig.pub})
	rig.receive(received{raw: tampered, etag: bundle.ETag(tampered), err: err})
	out := rig.out.String()
	if !strings.Contains(out, "investigate") || strings.Contains(out, "signing key was rotated") {
		t.Fatalf("%s", out)
	}
}

// Pre-flight M3: a SIGHUP that finds a verify key others could write keeps
// the keys in force.
func TestASIGHUPReReadOfAnUnfencedVerifyKeyKeepsTheKeysInForce(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	_, pubPEM, _ := keyfile.EncodeEd25519(rig.key)
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.pub")
	os.WriteFile(loose, pubPEM, 0o664)
	os.Chmod(loose, 0o664)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s]}
`, loose)), 0o600)
	before := *rig.r.verifyKeys.Load()
	rig.with(func() { rig.r.rereadVerifyKeys() })
	if !strings.Contains(rig.out.String(), "not re-read") || !strings.Contains(rig.out.String(), "writable by others") ||
		len(*rig.r.verifyKeys.Load()) != len(before) {
		t.Fatalf("%s", rig.out.String())
	}
}

// The service confirming the document in force keeps the snapshot young.
func TestAnUnchangedAnswerKeepsTheSnapshotYoung(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy, 2)
	rig.receive(d)
	rig.now = rig.now.Add(10 * time.Minute)
	rig.receive(received{etag: d.etag, unchanged: true})
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age > 1 {
		t.Fatalf("age %v", age)
	}
}

// Decided 3: a sequence that goes backwards is applied and said.
func TestASequenceThatGoesBackIsSaid(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 40, groupedPolicy, 2))
	rig.receive(rig.doc(t, 1, groupedPolicy, 2, admission.Device{Name: "leaf9", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}, Transport: admission.TransportTCP}))
	if !strings.Contains(rig.out.String(), "the service's sequence went back from 40 to 1") {
		t.Fatalf("%s", rig.out.String())
	}
}
```

  Add to `internal/bundle/diff_test.go`:

```go
func TestCheckFromNamesTheFixAndHintsOnlyWhereKeyGroupsWere(t *testing.T) {
	// A policy and inventories as the file's other Check tests build them;
	// old carries no inventory key groups.
	old, new := checkPair(t, 10, 5) // ten devices, then five
	err := CheckFrom(old, new, 10, "fix the source of truth")
	if err == nil || !strings.Contains(err.Error(), "fix the source of truth") ||
		strings.Contains(err.Error(), "key_groups was deleted") {
		t.Fatalf("got %v", err)
	}
}
```

  with `checkPair(t, before, after int) (*policy.Policy, *policy.Policy)` written from the file's
  existing Check fixtures if it has none by that name.

- [ ] **Step 2: Run them.** `go test ./cmd/port49d/ ./internal/bundle/ -run 'Document|SIGHUPApplies|Verify|Unchanged|SequenceThat|CheckFrom' -count=1`
  Expected: FAIL (undefined: `received`, `receive`, `CheckFrom`, …).

- [ ] **Step 3: `CheckFrom`.** In `internal/bundle/diff.go`, rename `Check` to `CheckFrom` with a
  `fix string` parameter, used in place of `"fix the file"` in the bound's refusal, and add
  `func Check(old, new *policy.Policy, maxRemovedPercent int) error { return CheckFrom(old, new,
  maxRemovedPercent, "fix the file") }`. The two hints `(if key_groups was deleted from the inventory
  file, add it to the policy file first)` — the bound's and `admitsNone`'s — are given only when
  `len(old.Inventory().KeyGroups) > 0`: pass that as a `hint bool` to `admitsNone`, and `true` from
  `CheckAdmission`'s call only where the same holds. The 6a tests that expect the hint start from an
  inventory carrying key groups, so they still pass; run `go test ./internal/bundle/ ./cmd/port49d/`
  to confirm.

- [ ] **Step 4: The fetcher.** Create `cmd/port49d/fetch.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

// received is what the fetcher hands the reloader: a document opened, or one
// that did not open (err, with the bytes, so SIGHUP can try them against new
// keys), or the service confirming the etag the fetcher handed over last.
type received struct {
	pub       *inventory.Published
	raw       []byte
	etag      string
	err       error
	unchanged bool
}

// fetcher asks the inventory service every interval (spec §10, "How a daemon
// refreshes its snapshot"): the version first, and the document only when
// its etag is not the last one handed over. It does the network I/O so a
// slow service never holds up a policy reload or a refresh, verifies what
// arrives, and swaps nothing: the reloader is the one goroutine that does.
type fetcher struct {
	client   fetchClient
	keys     func() []ed25519.PublicKey
	url      string
	interval time.Duration
	metrics  *metrics.Metrics
	// etag is the last one handed over; failing the last failure said.
	etag, failing string
}

func (f *fetcher) run(ctx context.Context, out chan<- received, poke <-chan struct{}) {
	tick := time.NewTicker(f.interval)
	defer tick.Stop()
	for {
		if d, ok := f.once(ctx); ok {
			select {
			case out <- d:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-poke:
			// SIGHUP: fetch the document again, whatever etag is held, so
			// one refused under the old keys is opened under the new.
			f.etag = ""
		}
	}
}

// once asks once. ok is false when there is nothing to hand over: the
// service did not answer, which once says.
func (f *fetcher) once(ctx context.Context) (received, bool) {
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	v, err := f.client.Version(cctx)
	if err == nil && f.etag != "" && v.ETag == f.etag {
		f.answered()
		f.metrics.InventoryFetches.WithLabelValues("unchanged").Inc()
		return received{etag: v.ETag, unchanged: true}, true
	}
	var raw []byte
	var etag string
	var notModified bool
	if err == nil {
		raw, etag, notModified, err = f.client.Bundle(cctx, f.etag)
	}
	if err != nil {
		if ctx.Err() != nil {
			// port49d is shutting down: nothing failed, and a line saying the
			// service did not answer would be false at 3am (conflict scan F8).
			return received{}, false
		}
		f.metrics.InventoryFetches.WithLabelValues("failed").Inc()
		if msg := oneLine(err); msg != f.failing {
			f.failing = msg
			fmt.Fprintf(stderr, "port49d: inventory: the inventory service at %s did not answer (%s); the bundle "+
				"in force keeps serving, and port49_inventory_snapshot_age_seconds climbs\n", f.url, msg)
		}
		return received{}, false
	}
	f.answered()
	if notModified {
		f.metrics.InventoryFetches.WithLabelValues("unchanged").Inc()
		return received{etag: etag, unchanged: true}, true
	}
	f.etag = etag
	doc, inv, err := bundle.Open(raw, f.keys())
	if err != nil {
		f.metrics.InventoryFetches.WithLabelValues("invalid").Inc()
		return received{raw: raw, etag: etag, err: err}, true
	}
	f.metrics.InventoryFetches.WithLabelValues("received").Inc()
	return received{pub: &inventory.Published{Raw: raw, Doc: doc, Inv: inv}, raw: raw, etag: etag}, true
}

func (f *fetcher) answered() {
	if f.failing != "" {
		f.failing = ""
		fmt.Fprintf(stderr, "port49d: inventory: the inventory service at %s answers again\n", f.url)
	}
}
```

  Create `cmd/port49d/fetch_test.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

// scriptService answers from fields a test sets, and counts what it was asked.
type scriptService struct {
	raw                 []byte
	versionErr          error
	versions, bundles   int
	lastIfNoneMatch     string
}

func (s *scriptService) Version(context.Context) (inventory.VersionInfo, error) {
	s.versions++
	return inventory.VersionInfo{ETag: bundle.ETag(s.raw)}, s.versionErr
}

func (s *scriptService) Bundle(_ context.Context, etag string) ([]byte, string, bool, error) {
	s.bundles++
	s.lastIfNoneMatch = etag
	if e := bundle.ETag(s.raw); etag == e {
		return nil, e, true, nil
	}
	return s.raw, bundle.ETag(s.raw), false, nil
}

func newFetcher(svc fetchClient, keys []ed25519.PublicKey) *fetcher {
	return &fetcher{client: svc, keys: func() []ed25519.PublicKey { return keys }, url: "https://inv.test:8443",
		interval: time.Hour, metrics: metrics.New(prometheus.NewRegistry())}
}

func TestAnUnchangedVersionCostsOneSmallRequest(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	if d, ok := f.once(context.Background()); !ok || d.pub == nil || d.pub.Doc.Sequence != 1 {
		t.Fatalf("%+v %v", d, ok)
	}
	if d, ok := f.once(context.Background()); !ok || !d.unchanged || svc.bundles != 1 || svc.versions != 2 {
		t.Fatalf("%+v: %d bundle and %d version calls", d, svc.bundles, svc.versions)
	}
}

func TestAFailureIsSaidOnceAndTheRecoveryOnce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2), versionErr: errors.New("dial tcp: connection refused")}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	for i := 0; i < 3; i++ {
		if _, ok := f.once(context.Background()); ok {
			t.Fatal("a failure handed something over")
		}
	}
	svc.versionErr = nil
	f.once(context.Background())
	f.once(context.Background())
	if strings.Count(out.String(), "did not answer (dial tcp: connection refused)") != 1 ||
		strings.Count(out.String(), "answers again") != 1 {
		t.Fatalf("%s", out.String())
	}
	if testutil.ToFloat64(f.metrics.InventoryFetches.WithLabelValues("failed")) != 3 {
		t.Fatal("failed fetches not counted")
	}
}

func TestADocumentThatDoesNotVerifyIsHandedOverWithItsError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, other, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	d, ok := f.once(context.Background())
	if !ok || d.err == nil || d.pub != nil || len(d.raw) == 0 {
		t.Fatalf("%+v", d)
	}
	if testutil.ToFloat64(f.metrics.InventoryFetches.WithLabelValues("invalid")) != 1 {
		t.Fatal("not counted invalid")
	}
}

// A poke (SIGHUP) forgets the etag held, so the document comes whole again.
func TestAPokeFetchesTheDocumentAgain(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	f.once(context.Background())
	f.etag = "" // what run does on a poke
	if d, ok := f.once(context.Background()); !ok || d.pub == nil || svc.lastIfNoneMatch != "" || svc.bundles != 2 {
		t.Fatalf("%+v: If-None-Match %q", d, svc.lastIfNoneMatch)
	}
}
```

- [ ] **Step 5: The reloader takes documents.** In `cmd/port49d/reload.go`, add the fields listed in
  Interfaces, the `case d := <-r.docs: r.receive(ctx, d)` arm to `run`'s select (a nil channel in
  file mode never fires), and:

```go
// receive is one thing the fetcher handed over: a confirmation of the
// document in force, which keeps the snapshot young, or a document, which is
// loaded as a reload.
func (r *reloader) receive(ctx context.Context, d received) {
	if d.unchanged {
		if d.etag == r.inForce {
			r.invSeen.Store(r.now().UnixNano())
			// The service confirms the document in force: nothing it sent
			// is pending refusal, and a cold start's refused copy is behind
			// us (Task 14).
			r.docRefused = ""
			r.metrics.InventoryBundleRefused.Set(0)
			// A persist that failed is tried again at every confirmation,
			// not only at the next document (pre-flight M7).
			if r.persistSaid != "" && r.latestRaw != nil {
				r.persist(r.latestRaw)
			}
		}
		return
	}
	r.latest = &d
	r.loadDocument(ctx, "inventory service", d)
}

// loadDocument puts the service's document in force, as loadInventory puts a
// file (spec §10): parsed against the policy in force, bounded by
// inventory.max_removed_percent, swapped in one pointer, its security changes
// recorded, the refresh run, and the document persisted. One that does not
// open or does not pass changes nothing, is said once per document, and
// holds port49_inventory_bundle_refused at 1.
func (r *reloader) loadDocument(ctx context.Context, trigger string, d received) {
	old := r.broker.Policy.Load()
	label := trigger
	var pol *policy.Policy
	err := d.err
	if err == nil {
		label = fmt.Sprintf("%s, bundle %d", trigger, d.pub.Doc.Sequence)
		pol, err = bundle.Parse(old.Raw(), d.pub.Inv, policy.Env{KeyRefs: r.cfg.KeyRefs()})
		if err == nil {
			err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, "fix the source of truth")
		}
	} else if errors.Is(err, bundle.ErrUnknownKey) {
		err = fmt.Errorf("the document does not open (%w); if the service's signing key was rotated, add its "+
			"public key to inventory.service.verify_key_files and send SIGHUP", err)
	} else {
		// Not a rotation: a signature that does not verify under a key
		// port49d holds is tampering or a foreign signer (pre-flight minor 4).
		err = fmt.Errorf("the document does not open (%w); it was not signed by any key port49d holds for the "+
			"service: investigate", err)
	}
	if err != nil {
		r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		r.metrics.InventoryBundleRefused.Set(1)
		if d.etag != r.docRefused {
			r.docRefused = d.etag
			fmt.Fprintf(stderr, "port49d: inventory reload (%s) refused; still serving bundle %s (%d): %s\n", label,
				old.Bundle, r.seq, oneLine(quotesCut{err}))
		}
		return
	}
	r.docRefused = ""
	r.metrics.InventoryBundleRefused.Set(0)
	if d.pub.Doc.Sequence < r.seq {
		fmt.Fprintf(stderr, "port49d: inventory: the service's sequence went back from %d to %d: its state_dir was "+
			"reset; applying it (spec §10)\n", r.seq, d.pub.Doc.Sequence)
	}
	r.inForce, r.seq, r.latestRaw = d.etag, d.pub.Doc.Sequence, d.pub.Raw
	r.invSeen.Store(r.now().UnixNano())
	r.metrics.InventoryBundleSequence.Set(float64(r.seq))
	r.persist(d.pub.Raw)
	if pol.Bundle == old.Bundle {
		// The same devices under a new sequence: nothing to swap.
		r.metrics.InventoryReloads.WithLabelValues("unchanged").Inc()
		return
	}
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	r.refused = ""
	rep := bundle.Diff(old, pol, now)
	fmt.Fprintf(stderr, "port49d: inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
		"admission\n", label, rep.Summary(), quarantinedAt(pol, now), quarantinedAt(old, now), len(pol.AdmissionRefusals()))
	r.after(ctx, "inventory", rep, pol, now)
}

// persist keeps raw as port49d's copy; a failure is said once and alarmed,
// and serving goes on.
func (r *reloader) persist(raw []byte) {
	if err := persistBundle(r.cfg.InventoryService.StateDir, raw); err != nil {
		if r.metrics.InventoryPersistFailed.Set(1); r.persistSaid != oneLine(err) {
			r.persistSaid = oneLine(err)
			fmt.Fprintf(stderr, "port49d: inventory: state_dir %s: %s; a restart with the service down would start "+
				"from an older copy\n", r.cfg.InventoryService.StateDir, r.persistSaid)
		}
		return
	}
	r.persistSaid = ""
	r.metrics.InventoryPersistFailed.Set(0)
}

// rereadVerifyKeys re-reads inventory.service.verify_key_files from
// port49d.yaml at SIGHUP (Decided 12). A file that does not read keeps the
// keys in force, said.
func (r *reloader) rereadVerifyKeys() {
	if r.cfgPath == "" || r.cfg.InventoryService == nil {
		return
	}
	raw, err := config.ReadRegular(r.cfgPath, config.MaxConfigSize)
	var svc *config.InventoryServiceConfig
	if err == nil {
		svc, err = config.InventoryServiceOf(raw)
	}
	var keys []ed25519.PublicKey
	if err == nil && svc != nil {
		keys, err = config.VerifyKeys(svc.VerifyKeyFiles)
	}
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.service.verify_key_files not re-read from %s (%s); keeping "+
			"the keys in force\n", r.cfgPath, oneLine(err))
	case svc == nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: %s has no inventory.service block; the inventory source is read at "+
			"start only; keeping the keys in force\n", r.cfgPath)
	default:
		r.verifyKeys.Store(&keys)
		fmt.Fprintf(stderr, "port49d: SIGHUP: %d inventory verify key(s) in force\n", len(keys))
	}
}
```

  with `persistSaid string` added to the reloader (`latestRaw` is Task 14's, which `startDocument`
  sets). Add:

```go
// reopenLatest opens the latest document received again under the verify
// keys now in force, when it was refused for its signature: a SIGHUP that
// added the service's new key applies the document it could not open.
func (r *reloader) reopenLatest() {
	if d := r.latest; d != nil && d.err != nil {
		if doc, inv, err := bundle.Open(d.raw, *r.verifyKeys.Load()); err == nil {
			d.pub, d.err = &inventory.Published{Raw: d.raw, Doc: doc, Inv: inv}, nil
		}
	}
}
```

  and make `reload` run in this order (conflict scan F10; Task 17 inserts its combined check at the
  marked line):

```go
func (r *reloader) reload(ctx context.Context, trigger string) {
	r.rereadBound()
	r.rereadVerifyKeys()
	r.reopenLatest()
	// (Task 17: the combined check of both sources goes here.)
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
	if r.cfg.InventoryService != nil {
		if d := r.latest; d != nil && d.etag != r.inForce {
			r.docRefused = ""
			r.loadDocument(ctx, trigger, *d)
		}
		select {
		case r.poke <- struct{}{}:
		default:
		}
		return
	}
	// With inventory_file, the file as plan 6a reads it (unchanged below).
	iraw, iv, ierr := inventoryVersion(r.cfg.InventoryFile)
	if iv != r.inventory {
		r.invPending = ""
		r.loadInventory(ctx, trigger, iraw, iv, ierr)
	}
}
```

  (`rereadVerifyKeys` returns at once in file mode.)

  In `main.go`'s reloader goroutine, in service mode, after Task 14's `r.startDocument(startDoc,
  startFrom)` (not called again here, conflict scan F11), start the fetcher, and **join it** before the
  goroutine closes `reloadDone`, so `run` returns only once the fetcher has (conflict scan F8):

```go
		var fetchDone chan struct{}
		if cfg.InventoryService != nil {
			docs, poke := make(chan received, 1), make(chan struct{}, 1)
			r.docs, r.poke = docs, poke
			keys := verifyKeysAtStart // from Task 14's block
			r.verifyKeys.Store(&keys)
			f := &fetcher{client: client, keys: func() []ed25519.PublicKey { return *r.verifyKeys.Load() },
				url: cfg.InventoryService.URL, interval: cfg.InventoryService.PollInterval, metrics: m}
			f.etag = r.inForce
			fetchDone = make(chan struct{})
			go func() { defer close(fetchDone); f.run(ctx, docs, poke) }()
		}
		r.run(ctx, hup)
		if fetchDone != nil {
			<-fetchDone // ctx is done: the fetcher returns without a line
		}
```

  and add `InventoryFetches` (a `CounterVec` on `outcome`) to `internal/daemon/metrics/metrics.go`
  with its `Help` and registration. Add to `fetch_test.go`:

```go
// Conflict scan F8: an ask cut short by shutdown says nothing.
func TestAShutdownMidAskSaysNothing(t *testing.T) {
	svc := &scriptService{versionErr: context.Canceled}
	f := newFetcher(svc, nil)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := f.once(ctx); ok || out.String() != "" {
		t.Fatalf("%v %q", ok, out.String())
	}
}
```

- [ ] **Step 6: Run them.** `go test ./cmd/port49d/ ./internal/bundle/ ./internal/daemon/metrics/ -count=1`
  Expected: PASS.

- [ ] **Step 7: Commit** (after `make build && make test && make vet`)

```bash
git add cmd/port49d internal/bundle internal/daemon/metrics
git commit -m "feat(port49d): pull the service's bundle, verify it, and reload it as a file is reloaded

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 16: A policy-hash mismatch is said and alarmed, never applied

**Files:**
- Modify: `cmd/port49d/reload.go`, `cmd/port49d/main.go`
- Modify: `internal/daemon/metrics/metrics.go` (`InventoryPolicyMismatch`)
- Test: `cmd/port49d/reload_service_test.go`

**Interfaces:**
- Consumes: `serviceRig`, `rig.doc` (Task 15); `received.pub.Doc.PolicySHA256`; `policy.Policy.Source`.
- Produces: `reloader.docPolicy`, `reloader.mismatch string`; `func (r *reloader) sayPolicyMatch()`;
  `metrics.InventoryPolicyMismatch` (`port49_inventory_policy_mismatch`).

Owner decision 3 of plan 6a, binding (spec §13, decision 29): the service's inventory is applied
against port49d's own policy while the hashes differ; the mismatch is a line and a gauge.

- [ ] **Step 1: Write the failing tests.** Add to `cmd/port49d/reload_service_test.go`:

```go
// Decision 29: a document built against another policy is applied against
// the policy in force, said once per pair, and alarmed until they agree.
func TestAPolicyMismatchIsSaidAndAlarmedAndTheInventoryApplied(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	other := groupedPolicy + "# the service's copy is a commit ahead\n"
	rig.receive(rig.doc(t, 1, other, 2))
	rig.receive(rig.doc(t, 2, other, 3))
	if len(rig.b.Policy.Load().Devices()) != 3 {
		t.Fatalf("the inventory was not applied: %s", rig.out.String())
	}
	if rig.b.Policy.Load().Source != engine.HashOf([]byte(groupedPolicy)) {
		t.Fatal("the policy in force changed")
	}
	out := rig.out.String()
	if n := strings.Count(out, "port49d: inventory: the service built bundle "); n != 1 ||
		!strings.Contains(out, "against policy "+engine.HashOf([]byte(other))) ||
		!strings.Contains(out, "nothing the service sends changes the policy") {
		t.Fatalf("said %d times: %s", n, out)
	}
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 1 {
		t.Fatal("port49_inventory_policy_mismatch is not 1")
	}
	// port49d's own policy reload brings it level: said, and cleared.
	rig.write(t, other)
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 0 ||
		!strings.Contains(rig.out.String(), "port49d: inventory: the service's policy and the policy in force agree again") {
		t.Fatalf("not cleared: %s", rig.out.String())
	}
}

func TestAMatchingPolicyRaisesNothing(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 0 || strings.Contains(rig.out.String(), "service built") {
		t.Fatalf("%s", rig.out.String())
	}
}
```

  (`pollTwice` polls the policy file; in service mode it does not read an inventory file, per Task 14.)

- [ ] **Step 2: Run them.** `go test ./cmd/port49d/ -run 'PolicyMismatch|MatchingPolicy' -count=1`
  Expected: FAIL.

- [ ] **Step 3: Implement.** In `cmd/port49d/reload.go`:

```go
// sayPolicyMatch compares the policy the service built the document in force
// against with the policy in force (spec §13, decision 29). A difference is
// never applied — the inventory is loaded against port49d's own policy — but
// it is said once per pair of hashes, and port49_inventory_policy_mismatch is
// 1 until they agree, which is said too. A rollout in progress holds it
// briefly; one that stays names a service or a daemon deployed from another
// commit of the policy repository.
func (r *reloader) sayPolicyMatch() {
	if r.docPolicy == "" {
		return
	}
	mine := r.broker.Policy.Load().Source
	if r.docPolicy == mine {
		r.metrics.InventoryPolicyMismatch.Set(0)
		if r.mismatch != "" {
			r.mismatch = ""
			fmt.Fprintf(stderr, "port49d: inventory: the service's policy and the policy in force agree again (%s)\n", mine)
		}
		return
	}
	r.metrics.InventoryPolicyMismatch.Set(1)
	if key := r.docPolicy + " " + mine; key != r.mismatch {
		r.mismatch = key
		fmt.Fprintf(stderr, "port49d: inventory: the service built bundle %d against policy %s, and the policy in "+
			"force is %s; its inventory is applied against the policy in force, and nothing the service sends changes "+
			"the policy (spec §13, decision 29)\n", r.seq, r.docPolicy, mine)
	}
}
```

  Set `r.docPolicy = d.pub.Doc.PolicySHA256` in `loadDocument` beside `r.inForce`, and in
  `startDocument`; call `r.sayPolicyMatch()` at the end of `loadDocument`'s success path (before
  either return), at the end of `startDocument`, and in `load` (the policy reload) after a swap. Add
  `InventoryPolicyMismatch prometheus.Gauge` (`port49_inventory_policy_mismatch`, Help "1 while the
  inventory service built the document in force against a policy other than the one in force.") to
  the metrics, registered.

- [ ] **Step 4: Run them.** `go test ./cmd/port49d/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add cmd/port49d internal/daemon/metrics
git commit -m "feat(port49d): a policy-hash mismatch with the service is said and alarmed, never applied

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 17: Both sources at once: the combined reload (plan 6a final review m7)

**Files:**
- Modify: `cmd/port49d/reload.go`
- Test: `cmd/port49d/reload_both_test.go`

**Interfaces:**
- Consumes: `parseBundle`, `swap`, `after`, `policyVersion`, `inventoryVersion`, `admission.ParseFile`;
  `bundle.CheckFrom`, `bundle.CheckAdmission`; `received` (Task 15).
- Produces:
  - `func (r *reloader) settledPolicy() (raw []byte, v string, ok bool)` — the policy file read now,
    when it differs from the policy in force and the last poll agreed on it or it was refused.
  - `func (r *reloader) settledInventory() (inv admission.Inventory, v string, d *received, ok bool)`
    — file mode: the inventory file read now, parsed, when it differs from the one in force and the
    last poll agreed on it or it was refused; service mode: the latest document received, opened, when
    it is not the one in force.
  - `func (r *reloader) loadBoth(ctx context.Context, trigger string, raw []byte, v string, inv
    admission.Inventory, iv string, d *received) bool` — true when it applied.

Spec §10 (Task 1, Step 4): at `SIGHUP`, and whenever a load of one source is refused while the other
has a settled version not in force, port49d tries the two together.

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49d/reload_both_test.go`:

```go
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A whole-fleet re-address with its key group: each file alone admits none,
// so each alone is refused; together they load, as one swap, and alice's
// session survives it.
func TestAWholeFleetReAddressLoadsTogetherAtSIGHUP(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	k := rig.aliceLoggedIn(t)
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, strings.ReplaceAll(withoutGroups, "10.0.0.", "11.0.0."))
	rig.sighupWithBound(t, 10)
	out := rig.out.String()
	// Every swap line ends "… N refused admission"; the refusal forms are what
	// must be absent (conflict scan F3).
	if !strings.Contains(out, "port49d: policy and inventory reloaded together (SIGHUP)") ||
		strings.Contains(out, " refused; ") || strings.Contains(out, "refused together") {
		t.Fatalf("%s", out)
	}
	if d, ok := rig.b.Policy.Load().Device("leaf1"); !ok || d.Addresses[0].String() != "11.0.0.1" ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("not applied: %+v", d)
	}
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the session was revoked: %+v, %v", c, err)
	}
}

// The watch finds the same: the policy settles, alone it is refused, and the
// inventory the last poll agreed on is tried with it.
func TestAWholeFleetReAddressLoadsTogetherFromTheWatch(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, strings.ReplaceAll(withoutGroups, "10.0.0.", "11.0.0."))
	rig.pollTwice()
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reloaded together (file changed)") ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
}

// Together over the bound: neither applies, one line names both, both alarms
// are up.
func TestBothRefusedTogetherApplyNeither(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [11.0.0.1]}\n")
	rig.sighupWithBound(t, 10)
	out := rig.out.String()
	if !strings.Contains(out, "port49d: policy and inventory reload (SIGHUP) refused together; still serving") ||
		!strings.Contains(out, "removes 1 of 2 devices") || rig.b.Policy.Load().Bundle != serving {
		t.Fatalf("%s", out)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 || testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatal("both alarms are not up")
	}
}

// Service mode: a re-addressed document refused alone loads with the policy
// edit that goes with it.
func TestAReAddressFromTheServiceLoadsWithThePolicy(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	readdressed := rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2"))
	rig.receive(readdressed)
	if !strings.Contains(rig.out.String(), "inventory reload (inventory service, bundle 2) refused") {
		t.Fatalf("alone it should be refused: %s", rig.out.String())
	}
	rig.write(t, strings.Replace(groupedPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reloaded together") ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
}
```

  with `deviceAt(name, addr string) admission.Device` (an `arista_eos` device on TCP at addr) added to
  `reload_service_test.go`.

- [ ] **Step 2: Run them.** `go test ./cmd/port49d/ -run 'Together|ReAddress' -count=1`
  Expected: FAIL.

- [ ] **Step 3: Implement.** In `cmd/port49d/reload.go`:

```go
// settledPolicy is the policy file's version not in force that a combined
// load may take: read now, differing from the policy in force, and agreed by
// the last poll (pending) or refused already — never one the watch has seen
// only once, which an editor may still be writing.
func (r *reloader) settledPolicy() ([]byte, string, bool) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	if err != nil || v == r.broker.Policy.Load().Source {
		return nil, "", false
	}
	return raw, v, v == r.pending || v == r.refused
}

// settledInventory is the inventory's version not in force that a combined
// load may take: with inventory_file, the file read now, parsed, and agreed
// by the last poll or refused already; with the service, the latest document
// received that opened and is not the one in force.
func (r *reloader) settledInventory() (admission.Inventory, string, *received, bool) {
	if r.cfg.InventoryService != nil {
		if d := r.latest; d != nil && d.err == nil && d.etag != r.inForce {
			return d.pub.Inv, d.etag, d, true
		}
		return admission.Inventory{}, "", nil, false
	}
	raw, v, err := inventoryVersion(r.cfg.InventoryFile)
	if err != nil || v == r.inventory || (v != r.invPending && v != r.invRefused) {
		return admission.Inventory{}, "", nil, false
	}
	inv, err := admission.ParseFile(raw, "")
	if err != nil {
		return admission.Inventory{}, "", nil, false
	}
	return inv, v, nil, true
}

// loadBoth builds the bundle from a new policy and a new inventory together
// and puts it in force as one swap when it passes both bounds (spec §10;
// plan 6a final review m7): a whole-fleet re-address, which each source alone
// refuses, loads, and no bundle between the two revokes a context the final
// one keeps. Refused, neither is applied, both are marked refused, and one
// line names both. It reports whether it applied.
func (r *reloader) loadBoth(ctx context.Context, trigger string, raw []byte, v string, inv admission.Inventory,
	iv string, d *received) bool {
	old := r.broker.Policy.Load()
	fix := "fix the file"
	if d != nil {
		fix = "fix the source of truth"
	}
	pol, err := parseBundle(r.cfg, raw, inv)
	if err == nil {
		err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, fix)
	}
	if err == nil {
		err = bundle.CheckAdmission(old, pol, r.cfg.MaxRemovedPercent)
	}
	if err != nil {
		r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
		r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		if d != nil {
			r.docRefused = iv
			r.metrics.InventoryBundleRefused.Set(1)
		} else {
			r.invRefused = iv
			r.metrics.InventoryFileRefused.Set(1)
		}
		fmt.Fprintf(stderr, "port49d: policy and inventory reload (%s) refused together; still serving %s (bundle "+
			"%s): %s\n", trigger, old.Source, old.Bundle, oneLine(quotesCut{err}))
		return false
	}
	r.refused, r.changing, r.pending = "", 0, ""
	r.metrics.PolicyFileRefused.Set(0)
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	if d != nil {
		r.inForce, r.seq, r.docRefused, r.docPolicy = d.etag, d.pub.Doc.Sequence, "", d.pub.Doc.PolicySHA256
		r.latestRaw = d.pub.Raw
		r.metrics.InventoryBundleRefused.Set(0)
		r.metrics.InventoryBundleSequence.Set(float64(r.seq))
		r.persist(d.pub.Raw)
	} else {
		r.inventory, r.invRefused, r.invPending = iv, "", ""
		r.metrics.InventoryFileRefused.Set(0)
	}
	r.invSeen.Store(r.now().UnixNano())
	now := r.swap(pol)
	rep := bundle.Diff(old, pol, now)
	fmt.Fprintf(stderr, "port49d: policy and inventory reloaded together (%s): %s replaces %s; %s; %d device(s) "+
		"quarantined now, %d before; %d refused admission\n", trigger, pol.Source, old.Source, rep.Summary(),
		quarantinedAt(pol, now), quarantinedAt(old, now), len(pol.AdmissionRefusals()))
	r.after(ctx, "policy and inventory", rep, pol, now)
	r.sayPolicyMatch()
	return true
}
```

  Then call it in three places:
  1. `reload` (SIGHUP), at the line Task 15 marks — after `rereadBound`, `rereadVerifyKeys` and
     `reopenLatest`, before the separate loads: read the policy (`raw, v, err := policyVersion(...)`);
     if `err == nil && v != old.Source`, and the inventory has a version not in force — file mode:
     `inventoryVersion` read now differs from `r.inventory` and parses; service mode: `r.latest` opened
     (`err == nil`) and not in force — call `loadBoth(ctx, trigger, raw, v, inv, iv, d)` with `d` nil in
     file mode and `r.latest` in service mode, poke the fetcher in service mode, and return whatever it
     did (the separate loads are not tried: the operator's SIGHUP asserts both edits are done).
  2. `load` (a policy reload), where it would say the refusal: first `if inv, iv, d, ok :=
     r.settledInventory(); ok { r.loadBoth(ctx, trigger, raw, v, inv, iv, d); return }`.
  3. `loadInventory` and `loadDocument`, where each would say its refusal: first `if raw, v, ok :=
     r.settledPolicy(); ok { r.loadBoth(ctx, trigger, raw, v, inv, iv, dp); return }`, with `inv` and
     `iv` the inventory that load was refused for, and `dp` nil in `loadInventory` and `&d` in
     `loadDocument` (whose `d` is a value; `loadBoth` takes `*received`). In `loadDocument` the combined
     try applies only when `d.err == nil`.

  The 6a tests of each file alone (`TestTheKeyGroupMoveInEveryOrder` and the bound tests) still pass:
  in each, the other file has no version not in force.

- [ ] **Step 4: Run them.** `go test ./cmd/port49d/ -count=1`
  Expected: PASS, every reload test included.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add cmd/port49d
git commit -m "feat(port49d): a reload of either source tries both together when both have moved

Plan 6a final review m7: a whole-fleet re-address with its key group, where
each file alone admits none, loads as one swap, and no bundle between the two
revokes a context the final one keeps.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 18: The service and port49d together, end to end

**Files:**
- Create: `cmd/port49d/service_e2e_test.go`

**Interfaces:**
- Consumes: everything from Tasks 3–17: `inventory.Syncer`, `API`, `Server`, `FileSource`, `State`,
  `NewMetrics`; `testpki.WriteInventoryLab`; `run`, `writeServiceRunConfig`, `keyPath`, `waitFor`,
  `records`, `readPersisted` (Tasks 14, 15).
- Produces (test helpers): `startService(t, dir, addr string) *e2eService` — the service in-process
  on `addr` (`127.0.0.1:0` for a fresh port) with its file source, policy, state, mirror and PKI in
  `dir`, and `stop()`, `writeSource(t, n int)`, `sync(t) inventory.Result`, `url`, `pubFile`;
  `port49dOn(t, svcURL, pki, pubFile, stateDir, mirrorDir string) (out, log *syncBuffer, stop func())`
  — `pki` is the service's PKI directory, so the two verify each other (pre-flight M8);
  `readyz(t, out *syncBuffer) int`.

No production code: this task proves the pieces meet, with real TLS, real files and `run`. Each test
restores `stderr` and `stdout` as `TestRunServesAPolicyEditToALiveSessionWithNoLogout` does.

- [ ] **Step 1: Write the tests.** Create `cmd/port49d/service_e2e_test.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/keyfile"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

// e2ePolicy is both port49d's policy and the service's copy: they agree.
// 127.0.0.0/8 admits leaf0, which the tests' own TACACS+ client speaks as.
const e2ePolicy = minimalPolicy + "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}, " +
	"{match: {cidr: 127.0.0.0/8}, key_ref: k}]\n"

// e2eService is port49-inventory in-process, as cmd/port49-inventory wires it.
type e2eService struct {
	dir, url, addr, pubFile string
	syncer                  *inventory.Syncer
	srv                     *http.Server
}

// startService runs the service on addr ("127.0.0.1:0" for a fresh port)
// from dir: its file source, policy, state, mirror and PKI, all under dir.
// It publishes bundle 1, two devices, before it returns. A key already in
// dir (a restart) is reused.
func startService(t *testing.T, dir, addr string) *e2eService {
	t.Helper()
	s := &e2eService{dir: dir}
	pki := filepath.Join(dir, "pki")
	if _, err := os.Stat(pki); err != nil {
		if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	keyFile := filepath.Join(dir, "signing.key")
	s.pubFile = filepath.Join(dir, "signing.pub")
	if _, err := os.Stat(keyFile); err != nil {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		privPEM, pubPEM, _ := keyfile.EncodeEd25519(priv)
		os.WriteFile(keyFile, privPEM, 0o600)
		os.WriteFile(s.pubFile, pubPEM, 0o644)
		os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(e2ePolicy), 0o600)
		os.MkdirAll(filepath.Join(dir, "mirror"), 0o755)
		s.writeSource(t, 2)
	}
	key, err := keyfile.LoadEd25519(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, anchor, err := broker.LoadTLS(filepath.Join(pki, testpki.InvServerCert), filepath.Join(pki, testpki.InvServerKey),
		filepath.Join(pki, testpki.InvCA))
	if err != nil {
		t.Fatal(err)
	}
	m := inventory.NewMetrics(prometheus.NewRegistry())
	s.syncer = &inventory.Syncer{Sources: []inventory.Source{inventory.FileSource{SourceName: "lab_file",
		Path: filepath.Join(dir, "inventory.yaml")}}, Bounds: map[string]int{}, Default: 10,
		PolicyFile: filepath.Join(dir, "policy.yaml"), Key: key, Metrics: m, Now: time.Now, Log: io.Discard,
		State: inventory.State{Dir: filepath.Join(dir, "state"), MirrorDir: filepath.Join(dir, "mirror"), Keep: 64}}
	if err := s.syncer.Restore(); err != nil {
		t.Fatal(err)
	}
	api := &inventory.API{Syncer: s.syncer, Readers: []string{testpki.InvDaemonID},
		Syncers: []string{"user:alice@slice.port49.test"}, Now: time.Now, Log: io.Discard, Metrics: m}
	s.srv = inventory.Server(addr, cert, anchor, api.Handler(), log.New(io.Discard, "", 0))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	s.url = "https://" + s.addr
	go s.srv.ServeTLS(ln, "", "")
	t.Cleanup(s.stop)
	if res := s.sync(t); res.Outcome != "published" && res.Outcome != "unchanged" {
		t.Fatalf("the first sync: %+v", res)
	}
	return s
}

func (s *e2eService) stop() { s.srv.Close() }

// pki is the service's PKI directory, which port49d's config must name.
func (s *e2eService) pki() string { return filepath.Join(s.dir, "pki") }

// writeSource writes leaf0 at 127.0.0.1 and n devices, leaf1..leafn at
// 10.0.0.i, under the fence.
func (s *e2eService) writeSource(t *testing.T, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("devices:\n  - {name: leaf0, platform: arista_eos, addresses: [127.0.0.1]}\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: leaf%d, platform: arista_eos, addresses: [10.0.0.%d]}\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "inventory.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *e2eService) sync(t *testing.T) inventory.Result {
	t.Helper()
	return s.syncer.Sync(context.Background(), "api")
}

// port49dOn starts run on a config naming svcURL, stateDir and mirrorDir,
// with the service's own PKI (pki), and returns its stderr, its decision log
// and a stop that waits for it.
func port49dOn(t *testing.T, svcURL, pki, pubFile, stateDir, mirrorDir string) (out, log *syncBuffer, stop func()) {
	t.Helper()
	out, log = &syncBuffer{}, &syncBuffer{}
	e, o := stderr, stdout
	stderr, stdout = out, log
	b := brokerConfig(t, e2ePolicy).Broker
	cfgPath := writeServiceRunConfig(t, b, &config.InventoryServiceConfig{URL: svcURL, StateDir: stateDir,
		MirrorDir: mirrorDir}, pki, pubFile)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("run did not return")
		}
		stderr, stdout = e, o
	}
	t.Cleanup(stop)
	return out, log, stop
}

func readyz(t *testing.T, out *syncBuffer) int {
	t.Helper()
	m := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	resp, err := http.Get("http://" + m[1] + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Spec §10 end to end: port49d starts from the service, follows a sync, and
// writes the inventory_change record a file reload writes.
func TestPort49dFollowsTheService(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	state := filepath.Join(safeDir(t), "state")
	out, log, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 1 (") ||
		!strings.Contains(out.String(), ", the service, published") {
		t.Fatalf("%s", out.String())
	}
	svc.writeSource(t, 3)
	if res := svc.sync(t); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
	// SIGHUP pokes the fetcher, so the test need not wait out poll_interval.
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	waitFor(t, out, "port49d: inventory reloaded (inventory service, bundle 2)")
	if !strings.Contains(log.String(), `"event":"inventory_change"`) || !strings.Contains(log.String(), `"kind":"device_added"`) {
		t.Fatalf("no inventory_change record: %s", log.String())
	}
	keys, err := fence.ReadVerifyKeys("verify_key_files", []string{svc.pubFile})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := readPersisted(state, keys); err != nil || p.Doc.Sequence != 2 {
		t.Fatalf("persisted: %v %v", p, err)
	}
}

// A restart in place with the service down starts from the persisted copy
// and says, once, that the service does not answer.
func TestPort49dRestartsFromItsCopyWithTheServiceDown(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	state := filepath.Join(safeDir(t), "state")
	out, _, stop := port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	stop()
	svc.stop()
	out, _, _ = port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 1 (") ||
		!strings.Contains(out.String(), "the persisted copy") {
		t.Fatalf("%s", out.String())
	}
	if readyz(t, out) != 200 {
		t.Fatal("not ready with the persisted copy")
	}
	waitFor(t, out, "port49d: inventory: the inventory service at "+svc.url+" did not answer")
	time.Sleep(6 * time.Second) // one more poll_interval
	if n := strings.Count(out.String(), "did not answer"); n != 1 {
		t.Fatalf("said %d times: %s", n, out.String())
	}
}

// Spec §14, the snapshot never expires, in service mode (pre-flight minor
// 12): with the service gone, the age climbs and the device is still
// admitted and answered.
func TestTheSnapshotNeverExpiresWithTheServiceDown(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	out, _, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, filepath.Join(safeDir(t), "state"), "")
	waitFor(t, out, "port49d: listening on")
	svc.stop()
	waitFor(t, out, "did not answer")
	time.Sleep(6 * time.Second)
	m := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	resp, err := http.Get("http://" + m[1] + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	age := regexp.MustCompile(`(?m)^port49_inventory_snapshot_age_seconds ([0-9.e+]+)$`).FindSubmatch(body)
	if age == nil || string(age[1]) == "0" {
		t.Fatalf("the age does not climb: %s", body)
	}
	// Admission is unchanged: leaf0's packet is answered (FAIL: no token),
	// not closed.
	tacacs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	dev := tacacsClient{t: t, addr: tacacs[1], key: []byte("run-test-secret")}
	if st := dev.login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("status %d", st)
	}
}

// A fresh port49d, the service down, starts from the mirror's copy.
func TestAFreshPort49dStartsFromTheMirror(t *testing.T) {
	dir := safeDir(t)
	svc := startService(t, dir, "127.0.0.1:0")
	svc.stop()
	out, _, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, filepath.Join(safeDir(t), "state"),
		filepath.Join(dir, "mirror"))
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "the mirror's copy") {
		t.Fatalf("%s", out.String())
	}
}

// A fresh port49d with nothing waits, not ready and not serving, and starts
// when the service does.
func TestAFreshPort49dWithNothingWaitsForTheService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	dir := safeDir(t)
	// The key the service will sign with, written before port49d starts.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, pubPEM, _ := keyfile.EncodeEd25519(priv)
	os.WriteFile(filepath.Join(dir, "signing.key"), privPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "signing.pub"), pubPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(e2ePolicy), 0o600)
	os.MkdirAll(filepath.Join(dir, "mirror"), 0o755)
	(&e2eService{dir: dir}).writeSource(t, 2)
	// The PKI too, before port49d starts: startService reuses what dir holds,
	// so the service port49d later meets is the one its config trusts (M8).
	if err := testpki.WriteInventoryLab(filepath.Join(dir, "pki"), time.Now()); err != nil {
		t.Fatal(err)
	}
	out, _, _ := port49dOn(t, "https://"+addr, filepath.Join(dir, "pki"), filepath.Join(dir, "signing.pub"),
		filepath.Join(safeDir(t), "state"), "")
	waitFor(t, out, "port49d: inventory: no bundle yet")
	if readyz(t, out) != 503 || strings.Contains(out.String(), "port49d: listening on") {
		t.Fatalf("serving with no bundle: %s", out.String())
	}
	startService(t, dir, addr)
	deadline := time.Now().Add(12 * time.Second)
	for !strings.Contains(out.String(), "port49d: listening on") {
		if time.Now().After(deadline) {
			t.Fatalf("did not start once the service answered: %s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "starting from bundle 1 (") || readyz(t, out) != 200 {
		t.Fatalf("%s", out.String())
	}
}
```

  `startService` reuses a key already in `dir`, which is how the last test gives port49d the public
  half before the service exists. `waitFor` is `run_test.go`'s.

- [ ] **Step 2: Run them.** `go test ./cmd/port49d/ -run 'Port49dFollows|RestartsFromItsCopy|FreshPort49d' -count=1 -v`
  Expected: PASS. They wait on real poll intervals: report their durations.

- [ ] **Step 3: Run everything under the race detector.** `go test -race ./cmd/port49d/ ./internal/inventory/ -count=1`
  Expected: PASS. The fetcher and the reloader share only the channel, the poke, and
  `verifyKeys` (an atomic pointer).

- [ ] **Step 4: Commit** (after `make build && make test && make vet`)

```bash
git add cmd/port49d
git commit -m "test(port49d): the inventory service and port49d end to end

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 19: (lab, on beehive) A reset mid-session after a sync, and a quarantine through a sync: L29's reload case and spec §14

**Files:**
- Create: `tests/lab/inventory_test.go` (the harness runs `port49-inventory`)
- Create: `tests/lab/l29_test.go` (`TestL29Reload`, `TestQuarantineThroughASync`)
- Create: `tests/lab/l29_phases_test.go` (the pure helpers `labSource` and `l29Edit`) and
  `tests/lab/l29_unit_test.go` (`make lab-unit` runs them on the real lab inventory)
- Create: `tests/lab/l29/policy.yaml`, `tests/lab/quarantine-sync/policy.yaml`,
  `tests/lab/quarantine-sync/fixed.yaml`
- Modify: `tests/lab/cmd/slice-pki/main.go` (`-inventory` writes `testpki.WriteInventoryLab` too)
- Create (by the runs): `tests/lab/results/L29-reload-<platform>.md`,
  `tests/lab/results/quarantine-sync-<platform>.md`

**Interfaces:**
- Consumes: `bin/port49-inventory`, `bin/port49` (`inventory sync`, `inventory keygen`); the harness's
  `eachPlatform`, `capture`, `captureLine`, `startDaemonWith`, `stopDaemon`, `configPath`,
  `sshCLI`, `nextLogin`, `dial`, `mark`, `drainRecords`, `waitForRecords`, `carriedConfigure`,
  `junosConfigureAdmin`, `result`; `mint` as `TestSliceEndToEnd` mints; `testpki.WriteLab`,
  `WriteInventoryLab`; from Task 20 (committed first): `labShell`, `l.shell`, `singleConnection`,
  `timedLogins`, `firstLine`.
- Produces:
  - `type labInventory struct` and `func (l *lab) startInventory(t *testing.T, source, policy string)
    *labInventory` — the service on `127.0.0.1:18443` (metrics `127.0.0.1:19050`), its file source a
    private copy under `tests/lab/logs/inventory-<platform>/`, keys from `port49 inventory keygen`;
    `(*labInventory).writeSource(t, body)`, `sync(t) string` (runs `bin/port49 inventory sync` as the
    operator and returns its output), `stop()`.
  - `func (l *lab) serviceConfig(t *testing.T, li *labInventory, policy string) string` — the lab's
    port49d.yaml with `inventory_file` removed, the slice broker block with `policy_file: policy`, and
    `inventory.service` naming the lab service, its PKI and key, `poll_interval: 5s`, a state
    directory under the run's logs.
  - `func labSource(inventoryLab string) string` — the lab inventory's devices, `key_groups` dropped,
    padded with ten dummy devices `dummy-01`…`dummy-10` at `10.99.0.101`–`110`, so a phase that takes
    one lab device out of service is 1 of 15 (under the default 10% bound on both the service and
    port49d, which stay under test: pre-flight M9, chosen over raising both bounds to 100).
  - `func l29Edit(src, node, phase string) (string, error)` — one phase's change to the source, pure,
    so `make lab-unit` checks it on every node of the real `inventory-lab.yaml`.

**This task gates the merge** ("The merge gate", at the top): it is the first run of the service path
on devices, and spec §14's quarantine through a sync.

L29's reload case (spec §15): what a device does when port49d resets an open connection at its first
packet after a reload refused, removed, renamed, re-keyed or re-platformed its device — whether the
command in flight fails or falls to the local method, and how long it takes; and whether the next
connection is refused at once, as a refused device's is. Here every reload but the re-key is a sync
through the service, as production's will be. Spec §14: "a sync introducing a device whose platform
fails joint validation publishes the bundle with that device quarantined, the rest of the sync
applies, a connection from the device is closed without a reply and logged `device_quarantined`, the
device falls to its local method in the lab, and the next sync after the named fix admits it."

- [ ] **Step 1: The policies.** Create `tests/lab/l29/policy.yaml`: `tests/lab/slice/policy.yaml`'s
  text with this appended, in **block style**, since the `rekeyed` phase appends an item to the list
  (pre-flight M9: a flow list with a block item after it is not YAML):

```yaml
# The lab inventory's own group, moved to the policy, since the service
# carries none (spec §13, decision 30); and the dummy devices' (labSource).
key_groups:
  - {match: {cidr: 172.100.100.0/24}, key_ref: lab_key}
  - {match: {cidr: 10.99.0.0/24}, key_ref: lab_key}
```

  `key_groups:` must be the file's last block. Create
  `tests/lab/quarantine-sync/policy.yaml`:

```yaml
# Spec §14's quarantine through a sync (plan 6b Task 19). Two probe subjects
# fail joint validation on the lab devices, one way for each platform, and
# reach them by name, so the dummy devices the same sync carries load and are
# served (conflict scan F5):
# - quarantine_probe names @loopback, a class only arista_eos defines, which
#   quarantines nx1, xe1, srx1 and vsrx1 (tests/lab/quarantine/policy.yaml's
#   cause);
# - eos_probe lands alone at a level arista_eos cannot render, which
#   quarantines leaf1 (plan 6a's TestAQuarantinedDeviceDoesNotStopTheStart's
#   cause). An unmapped level is not used on Junos: it renders no level, and
#   decision 26 gives that subject the fail-closed reply, not a quarantine.
# Checked against inventory-lab.yaml on 2026-09-30: all five quarantined,
# fixed.yaml none; l29_unit_test.go asserts both before any run.
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes:
  - {name: all_devices, match: {}}
  - {name: lab_devices, match: {name: [srx1, vsrx1, nx1, xe1]}}
  - {name: lab_eos, match: {name: [leaf1]}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: eos_class_only, privilege: admin, permit: ["show interfaces @loopback"]}
  - {name: unrenderable, privilege: unmapped, permit: ["show version"]}
subjects:
  - {name: slice_operator, identity: ["user:alice@slice.port49.test"], username: slice01,
     enable: token, token_ttl: 60s}
  - {name: quarantine_probe, identity: ["user:probe@slice.port49.test"], username: probe01, token_ttl: 60s}
  - {name: eos_probe, identity: ["user:eosprobe@slice.port49.test"], username: probe02, token_ttl: 60s}
grants:
  - {subject: slice_operator, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: quarantine_probe, scope: lab_devices, roles: [eos_class_only], max_privilege: admin}
  - {subject: eos_probe, scope: lab_eos, roles: [unrenderable]}
key_groups:
  - {match: {cidr: 172.100.100.0/24}, key_ref: lab_key}
  - {match: {cidr: 10.99.0.0/24}, key_ref: lab_key}
```

  and `tests/lab/quarantine-sync/fixed.yaml`, the same without the two probe grants: the named fix.

- [ ] **Step 2: The harness pieces.** Create `tests/lab/inventory_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

const (
	inventoryAddr        = "127.0.0.1:18443"
	inventoryMetricsAddr = "127.0.0.1:19050"
)

// labInventory is port49-inventory as the lab runs it (plan 6b Task 19): on
// the host, its file source a private copy the test edits, the lab inventory
// PKI, and a signing key `port49 inventory keygen` wrote for this run.
type labInventory struct {
	cmd                          *exec.Cmd
	dir, source, policy, pki     string
	pubFile, errPath             string
	done                         chan struct{}
}

// startInventory starts the service with source as its file source's
// content and a copy of policyPath as its policy. It refuses to start beside
// a service this run does not own.
func (l *lab) startInventory(t *testing.T, source, policyPath string) *labInventory {
	t.Helper()
	if c, err := net.DialTimeout("tcp", inventoryAddr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("something already listens on %s, most likely a port49-inventory left by an interrupted run; "+
			"stop it: pkill -f bin/port49-inventory", inventoryAddr)
	}
	logs := filepath.Join(root, "tests", "lab", "logs")
	li := &labInventory{dir: filepath.Join(logs, "inventory-"+l.p.name), pki: filepath.Join(logs, "inventory-pki"),
		errPath: filepath.Join(logs, "port49-inventory-"+l.p.name+".log"), done: make(chan struct{})}
	os.RemoveAll(li.dir)
	for _, d := range []string{li.dir, filepath.Join(li.dir, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(d, 0o755)
	}
	if err := testpki.WriteInventoryLab(li.pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(li.dir, "keys")
	os.MkdirAll(keys, 0o700)
	if out, err := exec.Command(filepath.Join(root, "bin", "port49"), "inventory", "keygen", "--dir", keys).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v: %s", err, out)
	}
	li.pubFile = filepath.Join(keys, "signing.pub")
	li.source, li.policy = filepath.Join(li.dir, "src", "inventory.yaml"), filepath.Join(li.dir, "policy.yaml")
	li.writeSource(t, source)
	li.writePolicy(t, policyPath)
	cfg := filepath.Join(li.dir, "port49-inventory.yaml")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`listen: %s
metrics_listen: %s
tls_cert_file: %s/%s
tls_key_file: %s/%s
client_ca_file: %s/%s
readers: [%q]
syncers: ["user:alice@slice.port49.test"]
signing_key_file: %s/signing.key
policy_file: %s
state_dir: %s/state
sync: [{name: lab_file, type: file, path: %s}]
`, inventoryAddr, inventoryMetricsAddr, li.pki, testpki.InvServerCert, li.pki, testpki.InvServerKey, li.pki,
		testpki.InvCA, testpki.InvDaemonID, keys, li.policy, li.dir, li.source)), 0o600)
	errFile, err := os.Create(li.errPath)
	if err != nil {
		t.Fatal(err)
	}
	li.cmd = exec.Command(filepath.Join(root, "bin", "port49-inventory"), "-config", cfg)
	li.cmd.Dir, li.cmd.Stdout, li.cmd.Stderr = root, errFile, errFile
	if err := li.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { li.cmd.Wait(); errFile.Close(); close(li.done) }()
	t.Cleanup(li.stop)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if resp, err := http.Get("http://" + inventoryMetricsAddr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return li
			}
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(li.errPath)
			t.Fatalf("port49-inventory not ready in 30s:\n%s", raw)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// writeSource writes the file source as a deployment would: 0644 under a
// 0755 directory, which the fence passes.
func (li *labInventory) writeSource(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(li.source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (li *labInventory) writePolicy(t *testing.T, from string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(li.policy, raw, 0o600)
}

// sync runs `port49 inventory sync` as the operator and returns its output.
func (li *labInventory) sync(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command(filepath.Join(root, "bin", "port49"), "inventory", "sync", "--service", "https://"+inventoryAddr,
		"--ca", filepath.Join(li.pki, testpki.InvCA), "--cert", filepath.Join(li.pki, testpki.InvOperatorCert),
		"--key", filepath.Join(li.pki, testpki.InvOperatorKey)).CombinedOutput()
	return string(out)
}

func (li *labInventory) stop() {
	if li.cmd == nil || li.cmd.Process == nil {
		return
	}
	li.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-li.done:
	case <-time.After(10 * time.Second):
		li.cmd.Process.Kill()
		<-li.done
	}
	li.cmd = nil
}

// labSourceFrom is labSource over the real lab inventory.
func labSourceFrom(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return labSource(string(raw))
}

// serviceConfig is the lab's port49d.yaml with its inventory from li: the
// inventory_file line removed, a second key lab_key2 (the rotation key) for
// the re-key phase, the slice's broker block on policy, and inventory.service.
func (l *lab) serviceConfig(t *testing.T, li *labInventory, policy string) string {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
	body := regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(string(raw), "")
	if !strings.Contains(body, l28Anchor) {
		t.Fatalf("%s has no standing lab_key block", base)
	}
	body = strings.Replace(body, l28Anchor, l28Anchor+"  lab_key2:\n    current: {version: 1, secret_env: PORT49_L28_NEW_KEY}\n", 1)
	pki := filepath.Join(root, "tests", "lab", "logs", "slice-pki")
	if err := testpki.WriteLab(pki, "alice@slice.port49.test", time.Now()); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "tests", "lab", "logs", "port49d-state-"+l.p.name)
	os.RemoveAll(state)
	body += fmt.Sprintf(`broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: %[1]s/%[2]s
  tls_key_file: %[1]s/%[3]s
  client_ca_file: %[1]s/%[4]s
  policy_file: %[5]s
  policy_watch_interval: 1s
inventory:
  service:
    url: https://%[6]s
    ca_file: %[7]s/%[8]s
    tls_cert_file: %[7]s/%[9]s
    tls_key_file: %[7]s/%[10]s
    verify_key_files: [%[11]s]
    poll_interval: 5s
    state_dir: %[12]s
`, pki, testpki.LabServerCert, testpki.LabServerKey, testpki.LabCA, policy, inventoryAddr, li.pki, testpki.InvCA,
		testpki.InvDaemonCert, testpki.InvDaemonKey, li.pubFile, state)
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-"+l.p.name+"-service.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
```

  Add `-inventory` to `tests/lab/cmd/slice-pki/main.go`, writing `testpki.WriteInventoryLab` into
  `tests/lab/logs/inventory-pki` for by-hand runs.

- [ ] **Step 3: `TestL29Reload`.** Create `tests/lab/l29_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const l29ReloadClaim = "What a device does when port49d resets an open connection at its first packet after a " +
	"reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync " +
	"through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29)."

type l29Phase struct {
	name   string
	change func(t *testing.T, l *lab, li *labInventory, policy string) (wait string)
}

// l29Phases change the device under test one way each; wait is the
// port49d line the change must produce before the next command. The source
// edits are l29Edit's, which the unit test checks on every node.
func l29Phases(src string) []l29Phase {
	sync := func(phase string) func(*testing.T, *lab, *labInventory, string) string {
		return func(t *testing.T, l *lab, li *labInventory, _ string) string {
			body, err := l29Edit(src, l.p.node, phase)
			if err != nil {
				t.Fatal(err)
			}
			li.writeSource(t, body)
			if out := li.sync(t); !strings.Contains(out, "published bundle") {
				t.Fatalf("the sync did not publish: %s", out)
			}
			return "port49d: inventory reloaded (inventory service, bundle"
		}
	}
	return []l29Phase{
		{"removed", sync("removed")},
		{"renamed", sync("renamed")},
		{"replatformed", sync("replatformed")},
		{"refused", sync("refused")},
		{"rekeyed", func(t *testing.T, l *lab, li *labInventory, p string) string {
			// A reviewed pin (Task 3a) onto the second key, which the device
			// does not hold: key_groups is the policy's last block.
			raw, _ := os.ReadFile(p)
			os.WriteFile(p, append(raw, []byte("  - {match: {name: "+l.p.node+"}, key_ref: lab_key2}\n")...), 0o600)
			return "port49d: policy reloaded"
		}},
	}
}
```

  and create `tests/lab/l29_phases_test.go` (build tag `lab`, pure: no device, no daemon):

```go
//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// labLine is one device line of the lab inventory. The file pads names to
// line up the columns ({name: srx1,  platform: ...}), so the separators take
// any run of spaces (pre-flight M9).
var labLine = regexp.MustCompile(`(?m)^  - \{name: ([^,]+),\s+platform:\s+([a-z_]+),.*\n`)

// labSource is the lab inventory's devices, key groups dropped — the service
// assigns no key (spec §13, decision 30), and the lab's group is in the run's
// policy — padded with ten dummy devices, so taking one lab device out of
// service is 1 of 15, under the default 10% bound on both sides.
func labSource(inventoryLab string) string {
	body, _, _ := strings.Cut(inventoryLab, "key_groups:")
	for i := 1; i <= 10; i++ {
		body += fmt.Sprintf("  - {name: dummy-%02d, platform: arista_eos, addresses: [10.99.0.%d]}\n", i, 100+i)
	}
	return body
}

// labLineOf is node's line in the lab inventory, and labPlatformOf its
// platform: the inventory's (juniper_junos), not the results note's name for
// the image (conflict scan F6).
func labLineOf(t *testing.T, src, node string) string {
	t.Helper()
	for _, m := range labLine.FindAllStringSubmatch(src, -1) {
		if m[1] == node {
			return m[0]
		}
	}
	t.Fatalf("the lab inventory has no device %s", node)
	return ""
}

func labPlatformOf(t *testing.T, src, node string) string {
	t.Helper()
	return labLine.FindStringSubmatch(labLineOf(t, src, node))[2]
}

// l29Edit is one reload phase's change to src for node.
func l29Edit(src, node, phase string) (string, error) {
	var line, platform string
	for _, m := range labLine.FindAllStringSubmatch(src, -1) {
		if m[1] == node {
			line, platform = m[0], m[2]
		}
	}
	if line == "" {
		return "", fmt.Errorf("the lab inventory has no device %s", node)
	}
	var edited string
	switch phase {
	case "removed":
		edited = ""
	case "renamed":
		edited = strings.Replace(line, "{name: "+node+",", "{name: "+node+"-b,", 1)
	case "replatformed":
		other := "arista_eos"
		if platform == "arista_eos" {
			other = "cisco_nxos"
		}
		edited = regexp.MustCompile(`platform:\s+`+platform+`,`).ReplaceAllString(line, "platform: "+other+",")
	case "refused":
		edited = strings.Replace(line, "]}", "], transport: tls}", 1)
	default:
		return "", fmt.Errorf("no source edit for phase %s", phase)
	}
	if edited == line {
		return "", fmt.Errorf("phase %s changed nothing on %s's line", phase, node)
	}
	return strings.Replace(src, line, edited, 1), nil
}
```

  and `tests/lab/l29_unit_test.go`, which `make lab-unit` runs:

```go
//go:build lab

package lab

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/policy"
	"gopkg.in/yaml.v3"
)

// Every reload phase's edit, on every node of the real lab inventory, yields
// an inventory that parses, that the service would publish (no device
// problem), and that differs from the source; and the lab policy takes the
// rekeyed phase's appended item (pre-flight M9).
func TestL29EditsOnTheRealLabInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := labSource(string(raw))
	for _, node := range []string{"leaf1", "srx1", "vsrx1", "nx1", "xe1"} {
		for _, phase := range []string{"removed", "renamed", "replatformed", "refused"} {
			body, err := l29Edit(src, node, phase)
			if err != nil {
				t.Fatalf("%s %s: %v", node, phase, err)
			}
			inv, err := admission.ParseFile([]byte(body), "")
			if err != nil {
				t.Fatalf("%s %s: %v", node, phase, err)
			}
			for _, d := range inv.Devices {
				if why := bundle.DeviceProblem(d); why != "" {
					t.Fatalf("%s %s: %s %s", node, phase, d.Name, why)
				}
			}
			if phase == "removed" && len(inv.Devices) != 14 || phase != "removed" && len(inv.Devices) != 15 {
				t.Fatalf("%s %s: %d devices", node, phase, len(inv.Devices))
			}
		}
	}
	for node, platform := range map[string]string{"leaf1": "arista_eos", "srx1": "juniper_junos",
		"vsrx1": "juniper_junos", "nx1": "cisco_nxos", "xe1": "cisco_iosxe"} {
		if labLineOf(t, src, node) == "" || labPlatformOf(t, src, node) != platform {
			t.Fatalf("%s: %q", node, labPlatformOf(t, src, node))
		}
	}
	pol, err := os.ReadFile(filepath.Join("l29", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		KeyGroups []map[string]any `yaml:"key_groups"`
	}
	if err := yaml.Unmarshal(append(pol, []byte("  - {match: {name: leaf1}, key_ref: lab_key2}\n")...), &f); err != nil ||
		len(f.KeyGroups) != 3 {
		t.Fatalf("the rekeyed phase's policy: %v, %d groups", err, len(f.KeyGroups))
	}
}

// Conflict scan F5: the quarantine-sync policy quarantines each of the five
// lab devices, whatever its platform, and none of the dummies; fixed.yaml
// quarantines none. Checked before any lab night is spent on it.
func TestQuarantineSyncPolicyQuarantinesEveryLabNode(t *testing.T) {
	inv, err := admission.LoadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	devices := append(inv.Devices,
		admission.Device{Name: "dummy-eos", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.99.0.11")}},
		admission.Device{Name: "dummy-xe", Platform: "cisco_iosxe", Addresses: []netip.Addr{netip.MustParseAddr("10.99.0.41")}})
	for file, want := range map[string]int{"policy.yaml": 5, "fixed.yaml": 0} {
		raw, err := os.ReadFile(filepath.Join("quarantine-sync", file))
		if err != nil {
			t.Fatal(err)
		}
		p, err := policy.Parse(raw, policy.Env{Devices: devices})
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		var names []string
		for _, q := range p.Quarantines(time.Now()) {
			if strings.HasPrefix(q.Device, "dummy-") {
				t.Fatalf("%s quarantines %s", file, q.Device)
			}
			names = append(names, q.Device)
		}
		if len(names) != want {
			t.Fatalf("%s quarantines %v, want %d devices", file, names, want)
		}
	}
}
```

  `l.p.node` is the NAS name in the inventory and `l.p.addr` the address it sources TACACS+ from
  (the harness's `platform` fields). Then the test:

```go
func TestL29Reload(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		src := labSourceFrom(t)
		policy := filepath.Join(root, "tests", "lab", "logs", "l29-policy-"+l.p.name+".yaml")
		li := l.startInventory(t, src, filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\n", l.l28Phase(t, "stopped", "", ""))
		for _, ph := range l29Phases(src) {
			raw, _ := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
			os.WriteFile(policy, raw, 0o600)
			li.writeSource(t, src)
			li.sync(t)
			// l28Live restarts port49d and probes until a login reaches it,
			// and says how many probes that took: the C8000V's slow probe
			// plan 6a's Task 21 review carried here (m4) is timed at every phase.
			live := l.l28Live(t, l.serviceConfig(t, li, policy))
			single := l.singleConnection(t)
			stop := l.capture(t, "L29-reload-"+ph.name)
			user, secret := l.nextLogin(t)
			sh, err := l.shell(user, secret)
			if err != nil {
				t.Fatalf("%s: token session: %v", ph.name, err)
			}
			if _, _, err := sh.Run("show version", 30*time.Second); err != nil {
				t.Fatalf("%s: show version before the change: %v", ph.name, err)
			}
			off := l.mark()
			wait := ph.change(t, l, li, policy)
			l.waitForLine(t, wait, 30*time.Second)
			out, took, err := sh.Run("show clock", 60*time.Second)
			inFlight := fmt.Sprintf("printed its output in %s", took.Round(10*time.Millisecond))
			switch {
			case err != nil:
				t.Errorf("%s: show clock not observed in 60s: %v", ph.name, err)
				inFlight = "not observed in 60s"
			case strings.Contains(strings.ToLower(out), "authorization failed") || strings.Contains(out, "% "):
				inFlight = fmt.Sprintf("refused in %s: %q", took.Round(10*time.Millisecond), firstLine(out))
			}
			sh.Close()
			recs := l.drainRecords(off, 10*time.Second)
			next := l.timedLogins(t)
			stop()
			fmt.Fprintf(&obs, "### Phase: %s\n\n%s\n\nSingle-connection: %s. Capture: %s\n\n| step | outcome |\n"+
				"|---|---|\n| `show clock` in the open session | %s |\n| records since the change | %s |\n%s\n",
				ph.name, live, single, l.captureLine(t), inFlight, summarize(recs), next)
		}
		l.result(t, "L29-reload", l29ReloadClaim, obs.String())
	})
}
```

  with one small helper in the same file, `l.waitForLine(t, want, within)` (polls `l.errPath` for
  `want` after the change; fails at `within`); `timedLogins` and `firstLine` are Task 20's. Each phase restarts port49d on a fresh service config, so each starts
  from the source and policy as committed.

- [ ] **Step 4: `TestQuarantineThroughASync`.** In the same file:

```go
const quarantineSyncClaim = "Spec §14: a sync introducing a device whose platform fails joint validation " +
	"publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the " +
	"device is closed without a reply and logged device_quarantined, the device falls to its local method, and " +
	"the next sync after the named fix admits it."

const dummies = "devices:\n" +
	"  - {name: dummy-eos, platform: arista_eos, addresses: [10.99.0.11]}\n" +
	"  - {name: dummy-xe, platform: cisco_iosxe, addresses: [10.99.0.41], attributes: {site: dc1}}\n"

func TestQuarantineThroughASync(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		dir := filepath.Join(root, "tests", "lab", "quarantine-sync")
		policy := filepath.Join(root, "tests", "lab", "logs", "quarantine-sync-policy-"+l.p.name+".yaml")
		raw, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
		os.WriteFile(policy, raw, 0o600)
		li := l.startInventory(t, dummies, policy)
		l.l28Restart(t, l.serviceConfig(t, li, policy))
		stop := l.capture(t, "quarantine-sync")
		defer stop()
		var obs strings.Builder
		// 1. The sync that introduces the device, and changes dummy-xe beside it.
		li.writeSource(t, strings.Replace(dummies, "site: dc1", "site: dc2", 1)+
			labLineOf(t, labSourceFrom(t), l.p.node))
		out := li.sync(t)
		if !strings.Contains(out, "published bundle 2") || !strings.Contains(out, "1 quarantined") {
			t.Fatalf("the sync: %s", out)
		}
		l.waitForLine(t, "port49d: inventory reloaded (inventory service, bundle 2)", 30*time.Second)
		l.waitForLine(t, "device "+l.p.node+" ("+labPlatformOf(t, labSourceFrom(t), l.p.node)+") is quarantined",
			5*time.Second)
		fmt.Fprintf(&obs, "Sync introducing the device:\n\n```\n%s```\n\n", out)
		// 2 and 3. A connection from the device, and break-glass.
		off := l.mark()
		fmt.Fprintf(&obs, "%s\n", l.timedLogins(t))
		recs := l.drainRecords(off, 10*time.Second)
		if !hasReason(recs, "device_quarantined") {
			t.Errorf("no device_quarantined record: %s", summarize(recs))
		}
		fmt.Fprintf(&obs, "Records while quarantined: %s\n\n", summarize(recs))
		// 4. The named fix, in both policy copies, and the next sync.
		fixed, _ := os.ReadFile(filepath.Join(dir, "fixed.yaml"))
		os.WriteFile(policy, fixed, 0o600)
		li.writePolicy(t, policy)
		out = li.sync(t)
		if !strings.Contains(out, "published bundle 3") || !strings.Contains(out, "0 quarantined") {
			t.Fatalf("the sync after the fix: %s", out)
		}
		l.waitForLine(t, "port49d: policy reloaded", 30*time.Second)
		off = l.mark()
		fmt.Fprintf(&obs, "After the fix:\n\n```\n%s```\n\n%s\n", out, l.timedLogins(t))
		fmt.Fprintf(&obs, "Records after the fix: %s\n\nCapture: %s\n", summarize(l.drainRecords(off, 10*time.Second)),
			l.captureLine(t))
		l.result(t, "quarantine-sync", quarantineSyncClaim, obs.String())
	})
}
```

  with `hasReason(recs, reason) bool` beside the helpers. The mint for the device (step 2 of the
  claim) is `sliceToken` after a `port49 login` as `TestSliceEndToEnd` starts it: while quarantined
  its answer is a refusal naming `device_quarantined`; after the fix it is a token that logs in.
  Add both to the observation as two more table rows.

- [ ] **Step 5: Build and dry-run the pure parts.** `make build && make lab-unit && go vet -tags lab ./tests/lab/`
  Expected: PASS.

- [ ] **Step 6: Run the lab, one platform at a time,** under the stall watchdog ("Running the lab"):

```bash
make build
for p in eos nxos iosxe junos; do   # the harness's platform names; vJunos-router for junos
  PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ -run '^(TestL29Reload|TestQuarantineThroughASync)$' \
    -count=1 -v -timeout 120m > tests/lab/logs/l29-reload-$p.log 2>&1
  make evidence
done
```

  (one `go test` at a time, the controller's watchdog armed for each, `pgrep -f bin/port49-inventory`
  empty and port 49 free between runs). A phase whose command never returned is not a result: fix the
  harness, not the note.

- [ ] **Step 7: Commit** the test code, the policies and the notes and evidence the runs wrote, after
  `make build && make test && make vet` (expected: exit 0):

```bash
git add tests/lab/inventory_test.go tests/lab/l29_test.go tests/lab/l29_phases_test.go tests/lab/l29_unit_test.go \
  tests/lab/l29 tests/lab/quarantine-sync \
  tests/lab/cmd/slice-pki tests/lab/results/L29-reload-*.md tests/lab/results/quarantine-sync-*.md tests/lab/evidence
git commit -m "test(lab): L29's reload case and spec §14's quarantine, through the inventory service's syncs

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 20: (lab, on beehive, scheduled) A key version retiring under an open connection at 00:00:00Z: L29's midnight case

**Execute this task straight after Task 2**, before Task 3 ("The merge gate", at the top): it
measures behaviour plan 6a shipped and needs none of this plan's code, so its test and shell helpers
are committed on `feature/inventory-service` first and its four nights run while the code tasks go
on. **A Task 20 night is never the same night as any part of Task 2**, nor overlaps Task 19's runs:
the lab is single-occupant, and Task 2's Docker stacks run by day on days with no night scheduled
across them.

**Files:**
- Create: `tests/lab/l29_shell_test.go` (`labShell`, `l.shell`, `singleConnection`, `timedLogins`,
  `firstLine`; Task 19 uses them too)
- Create: `tests/lab/l29_midnight_test.go` (`TestL29Midnight`)
- Modify: `tests/lab/harness_test.go` (`ptyCommands` builds on `labShell`)
- Create (by the runs): `tests/lab/results/L29-midnight-<platform>.md`

**Interfaces:**
- Consumes: `l28Config`, `l28Restart`, `l28Anchor`, `l.nextLogin`, `l.dial`, `l.loginWithin`,
  `l.sshCLI`, `l.carriedConfigure`, `l.junosConfigureAdmin`, `l.mark`, `l.drainRecords`, `l.capture`,
  `l.captureLine`, `l.result`, `recTime`, `sub`, `str`, `summarize`, `oneLine`, `breakglassUser`,
  `breakglassPassword` (plans 1–6a); `labcreds.RotationKey`.
- Produces:
  - `type labShell` with `Run(cmd string, per time.Duration) (string, time.Duration, error)` and
    `Close()`; `func (l *lab) shell(user, password string) (*labShell, error)` — one interactive
    session that runs commands one at a time, so something can happen between two.
  - `func (l *lab) singleConnection(t *testing.T) string` — turns TACACS+ single-connection on where
    the image offers it, and says what it did.
  - `func (l *lab) timedLogins(t *testing.T) string` — a token login, and a break-glass login with
    three `show version`, timed as `l28Phase` times them, as two table rows.
  - `func firstLine(s string) string`.

L29's `retire_after` clause (spec §15): "at its first packet past the connection's key version's
`retire_after` … whether the command or login in flight fails or falls to the local method, and how
long it takes; … whether the device's next connection, refused at Accept inside the strike's backoff
and then presenting the retired key, behaves as L28 measured. The `retire_after` case needs a run
whose connection is open across 00:00:00Z the day after `retire_after`." The row asks for a real
midnight: the date is port49d's clock against a real day boundary, the path production takes. Each
platform is one night: the lab holds one topology at a time.

- [ ] **Step 0: The shell helpers.** Create `tests/lab/l29_shell_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// labShell is one interactive session, one command at a time, so something
// can happen between two: ptyCommands' loop as a type.
type labShell struct {
	c       *cliConn
	prompts []string
}

func (l *lab) shell(user, password string) (*labShell, error) {
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	sh := &labShell{c: c, prompts: []string{l.p.node + "#", l.p.node + ">"}}
	if _, err := c.expect(60*time.Second, sh.prompts...); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.sendExpect("terminal length 0", 30*time.Second, sh.prompts...); err != nil {
		c.Close()
		return nil, err
	}
	return sh, nil
}

// Run sends cmd and waits up to per for the prompt: its output, how long,
// and the error at the deadline, which a caller reads as "not observed".
func (sh *labShell) Run(cmd string, per time.Duration) (string, time.Duration, error) {
	t0 := time.Now()
	out, err := sh.c.sendExpect(cmd, per, sh.prompts...)
	return out, time.Since(t0), err
}

func (sh *labShell) Close() { sh.c.Close() }

// singleConnection turns the platform's TACACS+ single-connection mode on
// where the image offers it — asked at `?` first, so the image, not this
// code, decides (conflict scan F15) — and says what it did.
func (l *lab) singleConnection(t *testing.T) string {
	t.Helper()
	type way struct {
		enter, ask []string // configuration mode, then the context the keyword is asked in
		set        func()
		said       string
	}
	w := way{enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 172.100.100.1 ?"},
		set: func() { l.carriedConfigure(t, "tacacs-server host 172.100.100.1 single-connection key 0 "+labKeyDefault) },
		said: "`tacacs-server host 172.100.100.1 single-connection`"}
	switch {
	case strings.HasPrefix(l.p.name, "juniper_"):
		w = way{enter: []string{"configure"}, ask: []string{"set system tacplus-server 172.100.100.1 ?"},
			set: func() {
				l.junosConfigureAdmin(t, []string{"set system tacplus-server 172.100.100.1 single-connection"})
			}, said: "`set system tacplus-server 172.100.100.1 single-connection`"}
	case l.p.name == "cisco_iosxe":
		w = way{enter: []string{"configure terminal", "tacacs server port49-host"}, ask: []string{"?"},
			set:  func() { l.carriedConfigure(t, "tacacs server port49-host", "single-connection") },
			said: "`single-connection` under `tacacs server port49-host`"}
	}
	if !l.offered(t, w.enter, w.ask, "single-connection") {
		return "not available on this image (its `?` does not offer single-connection): the phases run on " +
			"whatever connections the device opens"
	}
	w.set()
	return "on: " + w.said
}

// offered asks the device, as break-glass in configuration mode, for the
// help at the end of ask, and reports whether keyword is among the choices.
// The half-typed line is cleared (Ctrl-U) and configuration mode left
// without committing anything.
func (l *lab) offered(t *testing.T, enter, ask []string, keyword string) bool {
	t.Helper()
	sh, err := l.shell(breakglassUser, breakglassPassword)
	if err != nil {
		t.Fatalf("the `?` check: %v", err)
	}
	defer sh.Close()
	cfg := []string{l.p.node + "(config", l.p.node + "#", l.p.node + ">"}
	for _, e := range enter {
		if _, err := sh.c.sendExpect(e, 30*time.Second, cfg...); err != nil {
			t.Fatalf("the `?` check: %s: %v", e, err)
		}
	}
	var help string
	for _, a := range ask {
		out, _ := sh.c.sendExpect(a, 30*time.Second, cfg...)
		help += out
	}
	sh.c.sendExpect("\x15", 10*time.Second, cfg...) // Ctrl-U: clear what `?` left on the line
	leave := "end"
	if strings.HasPrefix(l.p.name, "juniper_") {
		leave = "exit configuration-mode"
	}
	sh.c.sendExpect(leave, 30*time.Second, cfg...)
	return strings.Contains(help, keyword)
}

// timedLogins is a token login, and a break-glass login with three `show
// version`, each timed as l28Phase times them, as two table rows.
func (l *lab) timedLogins(t *testing.T) string {
	t.Helper()
	user, secret := l.nextLogin(t)
	t0 := time.Now()
	tok := "logged in"
	if c, err := l.dial(user, secret, 120*time.Second); err != nil {
		tok = "refused: " + oneLine(err.Error())
	} else {
		c.Close()
	}
	tokTook := time.Since(t0)
	t1 := time.Now()
	bg := "logged in and ran them"
	if _, err := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version",
		"show version"); err != nil {
		bg = "not observed: " + oneLine(err.Error())
	}
	bgTook := time.Since(t1)
	return fmt.Sprintf("| next token login (`%s`) | %s in %s |\n| break-glass login plus three `show version` | %s in %s |\n",
		user, tok, tokTook.Round(10*time.Millisecond), bg, bgTook.Round(10*time.Millisecond))
}

// firstLine is s's first non-empty line, for a table cell.
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}
```

  `singleConnection` asks every image at `?` first (`offered`), NX-OS included, so the image decides
  and the note records what it offered. If `sendExpect` sends the line with a newline after the `?`,
  the device answers the half line with an incomplete-command error, which `offered` ignores; adjust
  the clearing to what the image does and keep the check. Nothing here is a claim: whether a connection
  stayed open across midnight is read from the capture (the same TCP 4-tuple before and after).
  Change `ptyCommands` in `harness_test.go` to build on `labShell` (its loop is `Run` plus the
  `[confirm]` and configuration-prompt handling it has now) and run `make lab-unit` to see nothing else
  moved.

- [ ] **Step 1: Write `TestL29Midnight`.** Create `tests/lab/l29_midnight_test.go` (build tag `lab`,
  package `lab`, importing `fmt`, `os`, `strings`, `testing`, `time` and `labcreds`):

```go
const l29MidnightClaim = "What a device does when port49d resets an open connection at its first packet past the " +
	"connection's key version's retire_after, across a real 00:00:00Z: the command in flight, and the next " +
	"connections, compared with L28's expired phase (spec §15 L29)."

// untilUTC sleeps until at, writing a line a minute so the stall watchdog
// sees a live log.
func untilUTC(t *testing.T, at time.Time) {
	t.Helper()
	for time.Now().Before(at) {
		left := time.Until(at)
		t.Logf("l29: waiting for %s, %s left", at.Format("15:04:05Z"), left.Round(time.Second))
		time.Sleep(min(left, time.Minute))
	}
}

func TestL29Midnight(t *testing.T) {
	if os.Getenv("PORT49_L29_MIDNIGHT") != "1" {
		t.Skip("L29's midnight case runs only across a real 00:00:00Z: set PORT49_L29_MIDNIGHT=1 and start the " +
			"run in the evening (plan 6b Task 20)")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		now := time.Now().UTC()
		midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
		if time.Until(midnight) < 5*time.Minute {
			t.Fatal("the device came up too late for tonight's midnight; start the run earlier")
		}
		untilUTC(t, midnight.Add(-4*time.Minute))
		if os.Getenv("PORT49_L28_NEW_KEY") == "" {
			t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
		}
		// v1, the device's key, admits through the end of today UTC and not after
		// (spec §10, "retire_after is a date, inclusive").
		today := midnight.Add(-time.Hour).Format("2006-01-02")
		l.l28Restart(t, l.l28Config(t, "midnight", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n"+
			"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: "+today+"}]\n"))
		single := l.singleConnection(t)
		stop := l.capture(t, "L29-midnight")
		defer stop()
		untilUTC(t, midnight.Add(-3*time.Minute))
		user, secret := l.nextLogin(t)
		sh, err := l.shell(user, secret)
		if err != nil {
			t.Fatalf("the token session before midnight: %v", err)
		}
		defer sh.Close()
		off := l.mark()
		var before []string
		for _, at := range []time.Duration{-2 * time.Minute, -time.Minute} {
			untilUTC(t, midnight.Add(at))
			if _, took, err := sh.Run("show version", 30*time.Second); err != nil {
				t.Fatalf("show version at %s: %v", midnight.Add(at).Format("15:04Z"), err)
			} else {
				before = append(before, took.Round(10*time.Millisecond).String())
			}
		}
		untilUTC(t, midnight.Add(5*time.Second))
		out, took, err := sh.Run("show clock", 60*time.Second)
		inFlight := fmt.Sprintf("printed its output in %s", took.Round(10*time.Millisecond))
		if err != nil {
			t.Errorf("show clock past midnight not observed in 60s: %v", err)
			inFlight = "not observed in 60s"
		} else if strings.Contains(out, "% ") || strings.Contains(strings.ToLower(out), "authorization failed") {
			inFlight = fmt.Sprintf("refused in %s: %q", took.Round(10*time.Millisecond), firstLine(out))
		}
		recs := l.drainRecords(off, 10*time.Second)
		// The instants the run actually held: the last record v1 admitted,
		// and the first packet refused as retired.
		lastV1, reset := "none", "none"
		for _, r := range recs {
			ts, _ := recTime(r)
			if d := sub(r, "device"); d != nil && d["key_version"] == float64(1) {
				lastV1 = ts.UTC().Format(time.RFC3339Nano)
			}
			if u := sub(r, "unvalidated"); u != nil && reset == "none" && str(u, "diagnosis") == "matches_retired" {
				reset = ts.UTC().Format(time.RFC3339Nano)
			}
		}
		untilUTC(t, midnight.Add(30*time.Second))
		next := l.timedLogins(t)
		stop()
		l.result(t, "L29-midnight", l29MidnightClaim, fmt.Sprintf("retire_after: %s (v1 admits through "+
			"%sT23:59:59.999Z). Last record under v1: %s; first packet refused as retired: %s. Single-connection: "+
			"%s.\n\n| step | outcome |\n|---|---|\n"+
			"| `show version` at 23:58Z and 23:59Z | ran in %s |\n| `show clock` at 00:00:05Z, same session | %s |\n"+
			"| records from 23:57Z | %s |\n%s\nWhether one connection spanned 00:00:00Z is read from the capture's "+
			"4-tuples: %s\n\nCompare `tests/lab/results/L28-%s.md`'s `expired` and `stopped` phases.\n",
			today, today, lastV1, reset, single, strings.Join(before, ", "), inFlight, summarize(recs), next,
			l.captureLine(t), l.p.name))
	})
}
```

  The test does not decide what the device should do: it records it.

- [ ] **Step 2: Build, test, vet, and commit the test before any night.** `make build && make test &&
  make vet && go vet -tags lab ./tests/lab/` (expected: exit 0; `make test` runs `make lab-unit`),
  then, on `feature/inventory-service`:

```bash
git add tests/lab/l29_shell_test.go tests/lab/l29_midnight_test.go tests/lab/harness_test.go
git commit -m "test(lab): L29's midnight case, and the shell helpers it shares with the reload case

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  Code never goes to `main` directly, so the test is on the branch before the first night. Note this
  commit's hash: every night runs from it.

- [ ] **Step 3: Schedule four runs, one a night, from a pinned worktree.** The nights never build in
  the worktree Tasks 3–18 are editing (`.worktrees/inventory-service`): a night built there could run a
  half-edited `bin/port49d` (conflict scan F7). Each night runs from its own worktree, checked out at
  Step 2's commit, where `make build` builds exactly 6a's port49d plus Task 20's test. The controller
  starts each in the background at 23:15Z (the N9Kv at 22:50Z, for its 15-minute boot), under the
  stall watchdog with `STALL=25` (40 on the N9Kv; the minute log lines keep it fed through the wait):

```bash
git worktree add --detach .worktrees/l29-midnight <Step 2's commit>
cd .worktrees/l29-midnight
make build
PORT49_L29_MIDNIGHT=1 PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run '^TestL29Midnight$' \
  -count=1 -v -timeout 150m > tests/lab/logs/l29-midnight-eos.log 2>&1 &
echo $! > tests/lab/logs/l29-midnight-eos.pid
```

  The worktree is kept for all four nights. After each night, run `make evidence` in it, copy its
  raw captures into the main checkout's `tests/lab/captures/` (the labpcap audit reads them there),
  and bring the note and the redacted evidence to Step 4's branch; only after the last night, and
  after the copy, remove the worktree (`git worktree remove .worktrees/l29-midnight`). The next
  night the next platform (`nxos`, `iosxe`, `junos`). A night that
  misses its midnight — the device late, a stall — is run again the next night; it is never read as a
  result. Nothing else runs on beehive's Docker from the start of a night's run to its end: no night
  shares a night with any part of Task 2, or overlaps Task 19's runs; the controller schedules those by
  day, and a Task 2 stack still running at 22:30Z postpones that night's run to the next night.

- [ ] **Step 4: Commit** each night's note and evidence as it lands — on `feature/inventory-service`
  while the branch is open, and after its merge on a `lab/l29-midnight` branch through a pull request,
  as PR #16 landed its lab work (evidence under `tests/lab/evidence` is not docs, so it never goes to
  `main` directly):

```bash
git add tests/lab/results/L29-midnight-<platform>.md tests/lab/evidence
git commit -m "test(lab): L29's midnight case on <platform>

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  This task does not gate the merge; Task 19 does. L29 stays open, with the platforms measured so far,
  until every platform has both its reload and its midnight note (lab register rule 3); the lab pull
  request that lands the last night runs Task 21's Step 1 again and closes the row.

---

### Task 21: Close what the lab measured, and write plan 6b as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L29, L30; §10 where L29 decides)
- Modify: `docs/design/2026-08-21-port49-design.md` (§12, if L29 changes what a row says)
- Modify: `docs/superpowers/plans/README.md`

- [ ] **Step 1: L29.** The row closes only when every platform has both a reload note and a midnight
  note (lab register rule 3): edit its Status to `closed — measured <date>; tests/lab/results/L29-reload-*.md,
  L29-midnight-*.md` with a one-line reading, and add a "measured" paragraph under the register's
  per-row notes: per platform, whether single-connection held one connection across the change, the
  command in flight's outcome and time for each reload phase and at midnight, and the next logins
  against L28's numbers. Replace §10's two "What a device does … is unmeasured (§15 L29, open)"
  sentences with what the notes say, citing them. If a note contradicts a doc — a reset mid-session
  that stalls a device, say — the doc is wrong: fix it, cite the note, and say so in the commit
  (CLAUDE.md, lab register rule 4). Otherwise leave the row open with a paragraph for what was
  measured.

- [ ] **Step 2: L30.** Close it when all five stacks' fixtures and both notes exist and `make
  lab-unit` passes: Status `closed — measured <date>; tests/lab/results/L30-netbox.md,
  L30-nautobot.md`, and a paragraph giving per version whether `next` is absolute and whose host it
  names behind the proxy, whether it paged to the end once, which GraphQL list shape the version took,
  and for Nautobot 3.x how each L27 answer compares with 2.4's. Otherwise leave it open with what was
  measured.

- [ ] **Step 3: The roadmap.** In `docs/superpowers/plans/README.md`, under "## Plan 6": the 6b bullet
  says "merged <date> (PR #N)"; add a "### Plan 6b — As built" section in 6a's form — what shipped task
  by task where it differs from this plan, the owner decisions as ruled, the rows closed and left
  open, and "Carried, for later plans" — and a **Plan 6c** bullet: the NetBox and Nautobot connectors
  (version detection by `/api/status/`; GraphQL first with the shapes L27 and L30 recorded, REST at
  `?depth=1` on Nautobot 2.x and following `next` as L30 found it; the slug alias table with a warning
  on an unknown slug; filters and maps; source credentials by `secret_env`, never inline, through
  `yamlfault`), the webhook trigger (HMAC-SHA512 over the body, verified in constant time; ordered by
  the body's `timestamp`, never arrival; a delivery only triggers a coalesced sync, its body never
  applied), a Nautobot 3.x profile if L30 says one is needed, and its lab run (a NetBox and a Nautobot
  sync end to end to a device). Also for 6c: every connector's `Fetch` returns when its context ends,
  within `sync_timeout` (the `Source` contract this plan writes); and `port49 inventory export --service
  … [--from N]`, writing a published bundle as an inventory file in port49d's schema, so `policy
  replay`, `policy test`, `devices capabilities` and `keys show` keep an `--inventory` when the source
  is NetBox or Nautobot and no file exists (pre-flight minor 16). Update the status line at the top.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: close lab register entries L29 and L30 as measured; plan 6b as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  (Name only the rows actually closed in the subject line.)

---

## Operator-facing notes (for the pull request body)

- **A new service, `port49-inventory`.** It syncs the inventory from its sources (this release: a
  file in port49d's inventory schema; NetBox and Nautobot come in plan 6c), each on its own `interval`
  (default 10m),
  at start, at `SIGHUP`, and on `port49 inventory sync`. It publishes one signed bundle over a
  mutual-TLS API, keeps it in `state_dir`, and writes it to `mirror_dir` when set. Config:
  `port49-inventory.yaml` (spec §10 has the example). Run `port49 inventory keygen --dir DIR` once for
  its signing key; give `signing.key` (0600) to the service and `signing.pub` to every port49d.
- **Who may call it.** `readers` (port49d's workload certificates, by URI SAN) may read the bundle;
  `syncers` (operators and CI, by URI SAN or `user:` email) may also sync. Everything is mutual TLS,
  health included; probes use `/healthz` and `/readyz` on `metrics_listen`.
- **The service bounds each source.** A source that removes, or newly refuses admission to, more
  than its `safety.max_removed_percent` (default 10) of what it gave last time refuses the sync, said
  once, with `port49_inventory_sync_refused` at 1; the last bundle keeps being published. A deliberate
  large removal: raise the bound and restart the service, and raise port49d's
  `inventory.max_removed_percent` and send it `SIGHUP`.
- **The service never assigns a key.** A source file with `key_groups:` or a device `key_ref:` pin
  refuses the sync. Put key groups in the policy file. **A pin is now a policy key group matching the
  device's name**, `{match: {name: leaf-01}, key_ref: prod_key}`, which outranks every attribute and
  CIDR group (tier 1), whatever addresses the device has. Two name groups for one device refuse the
  policy. A `/32` CIDR group is not a pin: an attribute group outranks it, and it follows the address.
  With `inventory_file`, a record pin still works, and one that disagrees with a name group refuses
  that device.
- **port49d can take its inventory from the service.** In port49d.yaml, replace `inventory_file`
  with `inventory: {service: {url, ca_file, tls_cert_file, tls_key_file, verify_key_files, state_dir,
  mirror_dir, poll_interval}}` (a `broker:` block is required). port49d asks every 30 s, applies each new
  bundle exactly as it reloads an inventory file — bounded by its own `inventory.max_removed_percent`,
  its security changes written as `inventory_change` records — and persists it to
  `state_dir/bundle.json`. The policy stays port49d's own `broker.policy_file`: a bundle the service built
  against another policy is applied and alarmed (`port49_inventory_policy_mismatch`), and changes no
  grant.
- **When the service is down, nothing stops.** port49d keeps serving the bundle it holds (the
  snapshot never expires; `port49_inventory_snapshot_age_seconds` climbs), restarts from its persisted
  copy, and a fresh port49d starts from the mirror's — of the two, the one published later. A start
  from a copy counts `port49_inventory_snapshot_age_seconds` from that copy's publication, so a restart
  does not clear a staleness alarm. A mirror mount that hangs is passed over after 10 s, said. The
  service reads and writes the mirror under the same 10 s deadline, with its metrics listener up
  first: a hung mount shows as `port49_inventory_mirror_behind` 1 and a line, holds up no sync, and
  a `SIGTERM` still stops it; with its `state_dir` empty, a hung mirror stops its start, said. With
  neither copy, port49d keeps TACACS+ closed and `/readyz` at 503 until the service answers, saying
  why once per reason: devices find the connection refused and fall to their next server or local
  method.
- **Protect the verify keys like the policy file.** `verify_key_files` on both sides are read
  behind the same write fence: owned by the process's user or root, not writable by group or others. A
  loose one refuses port49d's start, and a `SIGHUP` re-read keeps the keys in force. Protect
  `inventory.service.ca_file` the same way: port49d reads it as a regular file with no owner check,
  and whoever can write it chooses which service port49d trusts. Signatures bound the harm (such a
  service can deny port49d a new bundle, or replay one port49d already refuses), but not the outage.
  The mirror copy is written 0640: give port49d the mount's group.
- **Rotating the service's signing key:** add the new public key to every port49d's
  `verify_key_files` and send `SIGHUP`; add the old public key to the service's own
  `verify_key_files`; switch its `signing_key_file` and restart it: it re-seals the bundle in force
  under the new key as the next sequence, the fleet unchanged, with its per-source bound intact, and
  says `re-sealed as bundle N+1`; wait until every port49d's `port49_inventory_bundle_sequence` shows
  N+1; only then drop the old key from both. Dropped sooner, a port49d that restarts holds only a copy
  the old key signed, opens none, and serves no TACACS+ until the service answers. A bundle signed by a key
  port49d does not hold is refused and alarmed (`port49_inventory_bundle_refused`) with the rotation
  hint; one whose signature does not verify says to investigate. Rotating the service's TLS CA needs
  no signal: port49d reads `ca_file` at each connection.
- **Editing the key groups and the inventory together now works in one step.** At `SIGHUP`, or when
  one alone would be refused and the other has settled, port49d applies both as one swap, so a
  whole-fleet re-address loads and no session is lost between them. The make-before-break order is no
  longer needed.
- **New config keys:** port49-inventory.yaml (all of it, `verify_key_files` and `sync_timeout`
  included; `interval` per source, as spec §10 has it, with a top-level default); port49d.yaml `inventory.service.*`; policy
  `key_groups` `match: {name: …}`.
- **New metrics, the service:** `port49_inventory_syncs_total{trigger,outcome}`,
  `port49_inventory_sync_refused`, `port49_inventory_sync_failing`,
  `port49_inventory_source_errors_total{source}`, `port49_inventory_devices_left_out`,
  `port49_inventory_published_sequence`, `port49_inventory_published_timestamp_seconds`,
  `port49_inventory_devices`, `port49_inventory_last_good_sync_timestamp_seconds`,
  `port49_inventory_mirror_write_failures_total`, `port49_inventory_mirror_behind`,
  `port49_inventory_api_refused_total{reason}`.
  **port49d:** `port49_inventory_fetches_total{outcome}`, `port49_inventory_bundle_refused`,
  `port49_inventory_bundle_sequence`, `port49_inventory_policy_mismatch`,
  `port49_inventory_persist_failed`; `/readyz` on `metrics_listen`.
- **New commands:** `port49 inventory sync`, `port49 inventory diff --service … --from N`,
  `port49 inventory keygen`.
- **No new reason code, decision event or diagnosis.**
- **The lab:** what a device does when port49d resets an open connection after a sync, and when a key
  version retires under it at midnight UTC (spec §15 L29), and spec §14's quarantine through a sync:
  see the results notes Tasks 19 and 20 wrote, and Task 21's register rows.

## Self-review against the spec

- **§10 "The inventory service":** the separate workload (Task 11); the API's six endpoints (Task 10:
  bundle with ETag, version, diff, sync, healthz, devices-by-address as a diagnostic); mutual TLS and
  the two rights (Tasks 1, 10; design §17); consumers pull and cache, never per request (Tasks 14, 15).
- **§10 "One versioned bundle":** the document, its sequence and its name (Tasks 4, 9); quarantine
  published and reported (Task 9's report; each port49d quarantines against its own policy, decision 29);
  the policy reaching the broker from its own file, and the mismatch alarm (Tasks 1, 16; 6a owner
  decision 3 as binding); "key references, never key material", and now no key assignment at all
  (Tasks 3a, 4, 7; owner decision 3, with the pin tier kept in the reviewed policy).
- **§10 "Connectors and sync cadence":** the file connector (Task 7); NetBox and Nautobot, version
  detection, GraphQL first, the slug table and the webhook trigger are plan 6c's by the split, and
  L30 (Task 2) records what they are written against; three of four triggers (Tasks 9, 11, 12);
  bounded change per sync, per source (Task 9).
- **§10 "How a daemon refreshes its snapshot":** the 30 s pull with ETag (Task 15); build fully then
  swap, locally validated (Task 15, through `bundle.Parse`, `CheckFrom`, `swap`); never expires
  (Tasks 14, 15, 18); cold start readiness, the persisted bundle (a MUST) and the shared mirror
  (Tasks 14, 18; owner decisions 1 and 2); key resolution local (unchanged: port49d's keys); every
  swap's summary line (Task 15). The combined reload (Task 17, 6a m7).
- **§10 "Source-of-truth write access":** a synced source never assigns a key (Tasks 4, 7); its
  security changes are the `inventory_change` records a file reload writes (Task 15 reuses `after`), and
  the service says them (Task 9); `bundle/diff` for review (Tasks 10, 12); its file source read behind
  the write fence (Tasks 6, 7).
- **§12:** `port49 inventory sync`, `inventory diff --service`, `inventory keygen` (Tasks 3, 12).
- **§14 "Inventory and capability":** cold start (Tasks 14, 18); snapshot never expires (Task 18);
  snapshot refresh through a pull (Task 15); the quarantine lab assertion through a sync (Task 19); the
  new assertions Task 1 adds — the document verified everywhere (Tasks 4, 14, 15), the mismatch (Task
  16), the per-source bound (Task 9), both sources at once (Task 17), the API rights (Task 10).
- **§15:** L29 (Tasks 19, 20), L30 (Task 2), each with a lab task, closed only when measured (Task 21).
- **Reason codes (§5.7):** none added; no event or diagnosis added (Decided 13).
- **The roadmap's "Carried" list for 6b:** the mirror, the persisted bundle and cold-start readiness
  (Tasks 8, 14); the bundle document and its integer sequence (Tasks 4, 9); owner decision 3's alarm
  (Task 16); `SIGHUP` trying the combined bundle (Task 17); L29 and the C8000V's slow liveness probe —
  Task 19's run times the probe before each phase and its note says what it saw; L30 (Task 2); L27's
  findings — `/api/status/` for detection, `?depth=1`, ordering webhooks by `timestamp` — go to plan
  6c with the connectors, recorded in its brief (Task 21).
- **The pre-flight review:** every finding is resolved ("Revised after the pre-flight review", at the
  top); none is left.
- **Security, per the brief:** the API is mutual TLS only (Task 10); a compromised syncer or source
  is held to port49d's own bound, admission and security records (Task 15), cannot assign a key
  (Tasks 4, 7), cannot change the policy (Task 16), and cannot forge the mirror (owner decision 1);
  no secret reaches a line (keyfile for every key; `yamlfault` for YAML; fixed-text JSON errors; a
  URL with credentials refused unprinted, Task 12); the 3am traces are "What the operator sees".
