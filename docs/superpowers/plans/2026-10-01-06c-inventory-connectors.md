# Plan 6c: The NetBox and Nautobot Connectors, the Webhook Trigger, and `inventory export` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `port49-inventory` reads NetBox and Nautobot as sources of truth, exactly as L27 and L30
measured them: it detects the release from `/api/status/`, reads the device list over GraphQL
(checked against REST's `count`, with GraphQL's `errors` read before its `data` even on HTTP 200),
falls back to REST (following `next` only on the configured base, `?depth=1` on Nautobot 2.x and
3.x), and maps each device through a filter, an attribute map, an address rule and a platform alias
table. A NetBox or Nautobot webhook, authenticated by HMAC-SHA512 of its body, triggers a sync of its
source and nothing more. Every `Fetch` returns within `sync_timeout`, and a source that does not is
abandoned. `port49 inventory export` writes the service's bundle as an inventory file the offline
tools take. The lab measures the connectors as built through two kinds of TLS proxy (L32), the
webhook path from every measured release (L33), and syncs a NetBox and a Nautobot to a vEOS end to
end.

**Architecture:** The connectors are a package of their own, `internal/sot`, the contributable
surface spec §10 isolates: an HTTPS client that holds the source's token and follows no redirect, a
table of profiles keyed by the releases the lab measured, a GraphQL reader, a REST reader, and a
mapping from a source device to `admission.Device`. It imports nothing from `internal/inventory`;
`internal/inventory` builds a `sot.Source` per configured `netbox` or `nautobot` entry and syncs it
like the file source. The syncer bounds every `Fetch` by `sync_timeout` and abandons one that
outlives it. A second listener, `webhook_listen`, takes deliveries over TLS without a client
certificate (no product can present one), authenticates each by its signature, and pokes a
per-source debouncer that runs the source's sync. `inventory export` reads the bundle, or one from
the service's history, over the existing mutual-TLS API and verifies its signature before it writes
anything.

**Tech Stack:** Go 1.22 (the module's `go` line: no `slices.Sorted` or `maps.Keys` iterators), the
standard library (`crypto/hmac`, `crypto/sha512`, `net/http` 1.22 patterns, `net/url`,
`encoding/json` with `UseNumber`), `gopkg.in/yaml.v3` and `prometheus/client_golang` (both already
dependencies). Docker Compose on the lab host (beehive) for Tasks 14 and 15, containerlab for Task
15's device run. **No new module dependencies.**

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §10 ("The inventory service", "Connectors
and sync cadence", "Source-of-truth write access is privilege-granting"), §5.5 (`on_missing`, which
decides what an attribute a source does not give means), §5.7 (no reason code added), §8 ("Unknown
platforms"), §12 (`port49 inventory sync`, `inventory diff --service`), §13 decisions 29 and 30, §14
"Inventory and capability", §15 L27 and L30 (closed; the fixtures this plan is written against). Design
`docs/design/2026-08-21-port49-design.md` §6 (the inventory service), §17 "Internal interfaces".
Roadmap `docs/superpowers/plans/README.md`, "Plan 6", the "Plan 6c" bullet, "Plan 6b — As built"
(its "Carried" list) and "Fix `fix/breakglass-reset` — As built". The merged plan 6b
(`2026-09-30-06b-inventory-service.md`), whose owner decisions 1–3 are binding here.

**Prerequisite:** plan 6b and `fix/breakglass-reset` merged (PR #18, `2075818`). Branch
`feature/inventory-connectors` off `main` at the commit that adds this file.

## Rulings where the spec is silent

Spec §10 names what the connectors do ("version detection", "GraphQL first", "bounded change per
sync", "platform slug translation", "authenticated webhooks") and not how. Each ruling below takes
the option that denies more (security first), is written into the tasks named, and is recorded in
spec §13 as decision 31 by Task 1. None needs an owner decision to proceed; each can be revisited
without touching the others.

1. **The webhook has its own listener, TLS without a client certificate, and is authenticated by
   its signature alone.** The API is mutual TLS on every path (spec §10) and no product can present a
   client certificate: the webhook object L27 and L30 recorded has `ssl_verification` and
   `ca_file_path` and nothing that holds a certificate (`tests/lab/sot/l30/*/webhooks.json`, the
   `webhook` call's body). So `webhook_listen` is a second TLS listener whose one route is
   `POST /v1/webhook/<source>`, and the API's guarantee stays whole. Its certificate defaults to the
   API's and may be its own (`webhook_tls_cert_file`, `webhook_tls_key_file`), since the webhook
   faces the source of truth's network under another name. Plain HTTP is not offered: a delivery
   carries the device the change touched, and the fleet list is not sent in clear. Tasks 9, 12.
2. **A delivery only triggers a sync of its source.** Nothing in the body reaches the bundle: the
   sync reads the source's API, authenticated by its token. So delivery order (Nautobot delivered
   out of change order on 1.6, 2.4 and 3.2, L27 and L30) cannot reorder anything, and the body's
   `timestamp` is read for one purpose, freshness. Tasks 11, 12.
3. **A delivery is refused unless:** its source is configured with `webhook_secret_env`; its
   `Content-Type` is `application/json` (every delivery L27 and L30 recorded); `X-Hook-Signature`
   is 128 hex digits equal, in constant time, to HMAC-SHA512 of the body under that secret (L27,
   L30: 3 of 3 per release); the body is at most 1 MiB (the largest recorded is Nautobot 3.2.6's
   update, 18,972 bytes); its `timestamp` parses in one of the two spellings recorded (NetBox's
   `2026-09-30T15:43:34.000898+00:00`, Nautobot's `2026-09-30 15:52:04.757496+00:00`); and that
   timestamp is within 5 minutes of the service's clock either way (recorded arrivals were 0.03 s to
   9.4 s after it). The checks run cheapest first, and the body is not parsed until its signature
   verifies. A delivery whose signature the service has accepted in the last 10 minutes is answered
   `202 duplicate` and triggers nothing. A refused delivery is answered 401 (unknown source,
   unsigned, bad signature), 413, 415 or 400 (stale, bad body), counted by outcome, and said once
   per source and outcome, naming the source and the sender's address, never the body, the
   signature or the secret. A webhook secret is 32 to 255 printable characters (255 is the products'
   field length). Tasks 9, 11.
4. **A burst is one sync, and a flood costs one sync per 30 s.** The first delivery for a source is
   synced 2 s after it; one arriving during that sync brings one more after it; a source is synced
   from webhooks no sooner than 30 s after its last webhook sync began. At most one sync per source
   is pending, so an authentic flood (a bulk import) cannot queue work. The schedule still runs:
   a refused or lost delivery costs at most the source's `interval`. Task 12.
5. **The connector reads what the lab measured, and a field it does not give fails the sync.** The
   profile comes from `/api/status/` (never `Api-Version`, which Nautobot 1.6 sets to `1.2`, L27):
   NetBox 3.7 is `netbox_3_7`; NetBox 4.x is `netbox_4`; Nautobot 1.6 is `nautobot_1_6`; Nautobot
   2.x and 3.x are `nautobot_2` (L30: 3.2.6 answered every L27 question as 2.4.43 did). A release
   whose minor no lab run measured (NetBox 4.6, Nautobot 2.3) is read with its major's profile and
   said once; a major no lab run measured (NetBox 3.6 or 5.x, Nautobot 1.5 or 4.x) is refused unless
   `profile:` names one, which spec §10 asks for ("an explicit override available"). The attribute
   map's vocabulary is the fields L27 and L30 recorded per profile, not every field the products
   have; a path a profile does not give is refused when the sync detects the profile. Tasks 3, 7.
6. **GraphQL's answer is checked against REST's count.** A GraphQL list may be capped by the server
   or lose a page to a concurrent change (L30, "unmeasured": a list above any server cap, a list
   changing between pages), and a short list would look like devices removed: under the bound, it
   silently de-admits them. So the connector reads `count` from REST (`?limit=1`) before the GraphQL
   list and, when they differ, again after; a list matching neither fails the sync. REST paging
   checks its own total against the last page's `count`. Tasks 5, 6, 8.
7. **`next` is followed only on the configured base; otherwise it is rebuilt on it, and never
   followed elsewhere.** Every product builds `next` from the host the request arrived under (L30),
   so a proxy that rewrites `Host` can send the connector somewhere else (which header each release
   reads is L32's). A `next` whose scheme, host
   and port are the base's is followed; one on another origin is rebuilt on the base (its path and
   query kept) and said once; one whose path is not the base's device list is refused. No redirect is
   followed. The token is sent to the configured base and nowhere else. Task 6.
8. **The source of truth is `https` only, and its CA is named.** `url` is strict `https`;
   `ca_file` is required, read at every handshake as the service client reads its CA (plan 6b Task
   12), and may be the host's own bundle file when the source's certificate is public. Spec §10's
   `token_secret_ref` waits for plan 12's resolvers, so the token is named by `token_secret_env`, as
   port49d's keys are by `secret_env`; the webhook secret by `webhook_secret_env`. Both are read at
   start and never printed (`sot.Secret` prints as `<redacted>` under every verb). A NetBox v2 token
   (`nbt_…`) is sent as `Bearer`, every other as `Token` (L27). Tasks 2, 9.
9. **Filters run in the service, on what was read.** The products' GraphQL filter arguments
   differ per release and L27 measured only `name`'s, so `filter:` is applied to the fetched list:
   `status` (default `[active]`, so a decommissioned device is not admitted), `tags` (every one
   named), `has_primary_ip`. Status is compared in lower case, which takes each recorded spelling
   (`"ACTIVE"`, `"active"`, `{"name": "Active"}`, `{"value": "active"}`). Task 7.
10. **A device's addresses are its primary addresses, and interface addresses only where named.**
    `addresses.primary` defaults to true; `primary: false` is taken only beside interfaces.
    Interface addresses are added to the primary addresses, not used in place of them, and are read
    only when `addresses.interfaces` (exact names) or `addresses.all_interfaces` asks, since every address listed admits its source and an address on
    two devices refuses the sync (spec §10, "Addresses must resolve to one device"): a VRRP address
    or a reused management address in another VRF would otherwise stop every sync. REST does not give
    interface addresses in the device list (L27), so a REST read with interfaces configured fails,
    saying so. Task 7.
11. **An attribute a device does not give is left unset, never invented.** A null or absent custom
    field leaves the attribute out; so does one that is an object or a list, said once. Spec §5.5's
    `on_missing` already decides what a missing attribute means, by the safe direction of each scope.
    `status` may be mapped (normalised to lower case), since spec §5.5 scopes on it; tags are a
    filter, not an attribute, until the spec gives a multi-valued attribute a shape. Task 7.
12. **An unrecognized platform is passed through and said, never dropped or guessed.** The alias
    table maps the spellings real installations use (spec §10's `eos`, `arista-eos`, `arista_eos`,
    `veos`, and the netutils drivers Nautobot reports, `cisco_xe` among them) to port49's names;
    `platform_aliases` adds or overrides per source. A slug neither knows is kept as the platform:
    the device is admitted and served by the generic adapter (spec §8, "Unknown platforms"), and
    every sync that publishes it says so and sets `port49_inventory_generic_platform_devices`, for any
    source, the file source included. Tasks 7, 10.
13. **A `Fetch` that outlives `sync_timeout` is abandoned.** The syncer waits 5 s past the sync's
    deadline, then fails the sync, marks the source `port49_inventory_source_hung{source}` and does
    not ask that source again until the abandoned call returns: a connector that ignores its context
    costs one goroutine, not one per sync. Task 10.
14. **`inventory export` verifies before it writes.** It takes `--verify-key` (the service's public
    key, as port49d holds it), refuses a bundle that does not open, and writes the inventory in
    `inventory_file`'s schema, which carries no key assignment because the document cannot. `--from N`
    reads bundle N from the service's history through a new query on the existing read path,
    `GET /v1/bundle?sequence=N` (a reader's right), since the history already exists for
    `bundle/diff`. Task 13.

**No reason code, decision event or diagnosis is added** (spec §5.7): the service is not a decision
point, and its lines and metrics are its record, as plan 6b ruled.

## Revised after the pre-flight review (2026-10-01)

The pre-flight review (`.superpowers/sdd/2026-10-01-06c-inventory-connectors/preflight-review.md`)
found no critical, three important and seventeen minor problems. Every one is fixed below, with the
review's fix unless the line says otherwise; none was rebutted. The rulings above stand; where an
item here amends one, it says which, and the task text carries the amended rule.

- **I1 (a list that shifts under a delete).** Amends ruling 6. Offset paging that loses a page
  boundary to a concurrent delete returns a list one short whose last count agrees, and drops a live
  device. Now a GraphQL list is taken only when its length equals REST's `count` read before it
  **and** after it (`n == before == after`, the after read always made); a REST read only when every
  page gives the same `count` and the total equals it; and either list only when no device appears
  twice (REST by `id`, GraphQL by name, an empty name skipped). `sottest.Server.DeleteAfterPage`
  replays the shift, and Task 8 tests each reader against it (Tasks 4, 5, 6, 8).
- **I2 (addresses lost under an attribute key group).** New **Task 10a** (6b's `checkSafety` and
  `bundle.CheckFrom`): a device that had an address in the bundle in force and has none in the new
  one counts as out of service in both bounds, beside removed and newly refused, and the refusal
  names it (`leaves N more with no address`). Under an attribute key group such a device stays
  "admitted" while port49d, admitting by address, can no longer reach it.
- **I3 (lab guards that could pass on nothing).** `TestL32FixturesAreWhatTheNotesSay` requires two
  probes, each 200 with a `next` host, and four reads, and scopes "failed" to the read's own line;
  `TestL33FixturesAreWhatTheNotesSay` requires three phases, each published phase's change and
  seconds in the note, an unpublished one on a line with "failed", the webhook calls, and the
  `bad_signature` count (Tasks 14, 15). `TestL33Webhooks` also asserts at least one accepted delivery
  per published phase.
- **M1.** `sot.Secret` holds its value behind a pointer, so a `Secret` reached through an unexported
  field (inside `*sot.Source`) prints as an address, not the value; a test formats `*Source` (Tasks 2,
  8).
- **M2.** `readCA` reads through `config.ReadRegular`, as the service client does, so a FIFO at
  `ca_file` is refused rather than blocking a dial (Task 2).
- **M3.** A fetch reads at most 256 MiB summed over its pages, refused with a line saying so; an
  answer header later than 2 minutes is said with `page_size` named (Tasks 2, 5, 6).
- **M4.** A GraphQL page longer than `page_size` fails the read ("ignored the page size") (Task 5).
- **M5.** The generic-platform line offers a `platforms:` block only when the name fits the policy's
  platform-name shape; otherwise it names `platform_aliases` alone (Task 10; operator notes).
- **M6.** Amends ruling 12: the line is said at each publication that changes the set of generic
  platforms, and the gauge always holds the count (Task 1 text, Task 10).
- **M7.** `export --from N` refuses a bundle whose sequence is not N (Task 13).
- **M8.** `export --out` writes 0600, and the usage says so (Task 13).
- **M9.** Amends ruling 3: every 401 has one body, `{"error":"unauthorized"}`, so a caller cannot
  tell a configured source from another; the outcome stays in the metric and the line (Task 11).
- **M10.** The webhook server's `net/http` error log drops TLS handshake errors and counts them
  (`outcome="tls_handshake"`), and says any other line once (Tasks 11, 12).
- **M11.** A full replay cache evicts its soonest-expiring entry rather than stop remembering
  (Task 11).
- **M12.** An absent `token_secret_env` says it is required, not malformed (Task 9).
- **M13.** Interface reads leave out loopback, link-local, multicast and unspecified addresses, which
  cannot source TACACS+ and repeat across devices, said once (Task 7; operator notes). The test is
  that explicit list rather than the review's `!IsGlobalUnicast() && !IsPrivate()`, which reads the
  same in Go (a private address is global unicast there) but names less of what it leaves out.
- **M14.** When more than half the devices a source keeps give no platform, the source says once to
  map `platform` to another path (Task 8).
- **M15.** Task 1's spec text names the measured release for each paging, depth and status claim and
  says the profile reads the rest of the major the same way, said as unmeasured.
- **M16.** (a) The roadmap's 6c bullet no longer says webhooks are ordered by `timestamp` (edited in
  this revision). (b) Task 4 says the per-device addresses are synthesized for the tests, not seeded.
- **M17.** (a) `run.sh` writes the lab PKI after `trap cleanup EXIT`. (b) L33's note reads a single
  `bad_signature` as "not sent again within 120 s". Also from the review's sections 4 and 5: the
  operator notes say to leave the webhook's body template empty and how to handle a shared primary
  address; the replay's `Status` knob cannot panic on an empty status.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **Normal day:** the service says at start `port49-inventory: … 1 source(s): netbox_prod (netbox);
  webhooks on :8444 for netbox_prod`, then once `port49-inventory: source netbox_prod: NetBox 4.7.1,
  profile netbox_4, over GraphQL`, and the first webhook `port49-inventory: webhook: source
  netbox_prod's deliveries authenticate (first from 10.0.0.9); each triggers a sync of netbox_prod`.
  A device edited in NetBox is published within seconds: `port49-inventory: sync (webhook):
  published bundle 1844 (sha256:…): …: +0 device(s), -0, 1 changed; 0 quarantined`, and each port49d
  reloads it within its 30 s poll.
- **3am, NetBox is down:** `port49-inventory: sync (schedule) failed; still publishing bundle 1843:
  source netbox_prod: GET /api/status/: … connection refused`, once. `port49_inventory_sync_failing`
  is 1 and `port49_inventory_source_errors_total{source="netbox_prod"}` counts. Every port49d keeps
  the bundle in force, which never expires (spec §10). Nothing to do at 3am but restore NetBox.
- **3am, NetBox answers but hangs mid-list:** the sync fails at `sync_timeout` (default 5m):
  `source netbox_prod: did not finish within sync_timeout (5m0s): …`. A connector that ignores its
  context is abandoned 5 s later, `port49_inventory_source_hung{source="netbox_prod"}` is 1, and later
  syncs say `its fetch abandoned at an earlier sync has not returned` until it does.
- **The NetBox token was rotated or revoked:** `source netbox_prod: GET /api/status/ answered HTTP
  403: the token token_secret_env names was refused, or may not read devices; it is not printed`.
  Fix: put the new token in the variable and restart the service.
- **NetBox was upgraded to a release no lab run measured:** said once, `port49-inventory: source
  netbox_prod: NetBox 4.8.0 is not a release a lab run measured (NetBox 3.7, 4.7); it is read with
  profile netbox_4, and a field it does not give fails the sync`. If its GraphQL changed, the sync
  fails naming the first error, e.g. `GraphQL answered HTTP 200 with 1 error(s); the first: Unknown
  argument 'pagination' on field 'Query.device_list'.`; the bundle in force keeps serving. Fix: a
  lab run for the release, or `api: rest` for that source while one is done.
- **A server cap or a concurrent bulk delete cuts the GraphQL list short:** `source netbox_prod:
  GraphQL gave 1000 devices and REST counts 1203 before and 1203 after: a page was lost, a server
  capped the list, or the list changed during the sync; the next sync reads it again`. A delete
  between pages fails the same way (`… gave 1202 devices and REST counts 1203 before and 1202
  after …`), as does a REST page whose `count` moved. Nothing is de-admitted. Fix a persistent cap by
  lowering `page_size`.
- **An IPAM clean-up, or a token that lost its IPAM view, strips every device's address:** the
  sync is refused by the source's bound (`source netbox_prod removes 0 of 203 devices and refuses 0
  more and leaves 203 more with no address (100%) …`), and each port49d bounds it again the same
  way. The bundle in force keeps serving.
- **A reverse proxy in front of NetBox rewrites `Host`:** said once, `source netbox_prod: a page's
  next names another scheme, host or port than url; it is rebuilt on url, and the token is sent
  nowhere else: check the proxy's Host and X-Forwarded-Proto headers`. The sync proceeds.
- **Someone types `filter: {tags: [port-49]}` for `port49`:** the source gives no device, and the
  sync is refused as an empty one is (`the sources name no device`); or, beside another source,
  refused by the source's bound (`source netbox_prod removes 203 of 203 devices …`). Nothing is
  published; `port49_inventory_sync_refused` is 1.
- **A new platform slug appears (`eos-lab`):** the device is admitted and served by the generic
  adapter, and the publication that brings it says `port49-inventory: bundle 1845: platform eos-lab
  (2 device(s)) has no adapter in the policy and is served by the generic one, priv-lvl only (spec
  §8): name it in the source's platform_aliases (a policy platforms: block cannot be named eos-lab)`;
  `port49_inventory_generic_platform_devices` is 2 for as long as it lasts.
- **The webhook secret in NetBox does not match:** `port49-inventory: webhook: refused a delivery
  for source netbox_prod from 10.0.0.9 (bad_signature): the webhook's secret in the source must be
  the value webhook_secret_env names`, once;
  `port49_inventory_webhooks_total{source="netbox_prod",outcome="bad_signature"}` counts. Changes
  still arrive at the source's `interval`.
- **Nautobot's workers are backed up ten minutes, or a clock is wrong:** deliveries are refused
  `stale` (`its timestamp is more than 5m from this host's clock: check NTP on both hosts; the
  scheduled sync covers the change`). The schedule still syncs.
- **A bulk import of 5,000 devices fires 5,000 webhooks:** one sync 2 s after the first, then at most
  one per 30 s while they keep arriving; the bound applies to each.
- **An offline tool needs an inventory and no source is a file:** `port49 inventory export --service
  https://inv:8443 --ca … --cert … --key … --verify-key signing.pub --out inventory.yaml`, then
  `port49 policy test --policy policy.yaml --inventory inventory.yaml`.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–6b, and still binding:

- **Every claim about device or external-system behaviour cites a `tests/lab/results/` note or a
  register row.** A claim cited to an open row is unmeasured; do not "fix" a doc to assert it
  (CLAUDE.md, lab register rules 1–4). NetBox and Nautobot count (L27, L30, and this plan's L32 and
  L33).
- **A released platform set is never edited.** This plan edits none.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **A decode error prints a line and a category, never document text** (`internal/yamlfault`). This
  plan's YAML decodes through it; its JSON decoders print fixed text, and a source's own text (a
  GraphQL error message, a version string) only through `printable`, cut at 200 bytes.
- **Nothing the service sends assigns a key** (plan 6b owner decision 3, spec §13 decision 30). A
  connector's `admission.Device` never has a `KeyRef`, by construction.

New in this plan:

- **No secret reaches a log, an error or an output.** The source token and the webhook secret are
  `sot.Secret` values, read from the environment at start; a configuration error names the YAML key
  (`sync[0].token_secret_env`), never the variable's value. A webhook signature is never printed. A
  test in each task that handles a secret asserts it does not appear in what that task prints.
- **No metric label names a device.** The new labels are `source` (configuration) and `outcome` (a
  closed set).
- **The code blocks are written against `2075818`.** Where the compiler or a test says a block is
  wrong about the tree — a helper's name, an import — fix the block minimally, keep the behaviour
  the step's test asserts, and say so in the task's report and its commit. Never weaken a test to
  make a block pass.
- **Every commit is preceded by `make build && make test && make vet`.** Report their real output.
  Run `gofmt -w` on every Go file a task touches first: the blocks here are not always in gofmt's
  layout (one-line bodies, aligned literals), and `make vet` fails on any file that is not.
- Branch `feature/inventory-connectors`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Running the lab (Tasks 14 and 15)

The lab host is beehive. The owner has given standing consent for lab runs. Docker on beehive holds
one port49 run at a time: a Compose stack (Tasks 14 and 15) and a containerlab topology (Task 15's
device run) belong to the same run or none.

**Every lab run is made from a detached worktree pinned to a commit** (plan 6b Task 19: a mid-run
`make build` in a shared worktree invalidated a run): `git worktree add --detach
../port49-lab-6c <sha>`, `make build` there, and run from there. The note names the commit. Copy the
run's raw captures (Task 15's device run) into the main checkout's `tests/lab/captures/` before
removing the worktree, or the labpcap audit fails.

**Compose runs** go through `tests/lab/sot/run.sh <stack> l32|l33|e2e`, which generates every
credential fresh into a 0600 file outside the repository, gives `/api/status/` 10 minutes, bounds the
recorder and the Go test with `timeout`, and tears the stack down with `down -v` on every exit. The
controller still watches the log: a run that has not written a line in 10 minutes is a stall, and a
stalled run is never read as a result.

**The device run** (Task 15, Step 8) follows plan 5b's "Running the lab": vEOS only
(`PORT49_LAB_PLATFORMS=eos`), the harness's boot budget (6 min) plus up to 8 min for TACACS+
readiness, a deadline on every read, and **a stall watchdog run by the controller for the whole
run** (`STALL=25` minutes), which on a stall destroys the topology and kills `bin/port49d`,
`bin/port49-inventory` and any `tcpdump` on `tests/lab/captures`, and runs `run.sh`'s cleanup
(`docker compose -p port49-l27-<stack> down -v`).

**Evidence.** Tasks 14 and 15 commit their JSON under `tests/lab/sot/l32/` and `tests/lab/sot/l33/`;
neither carries a credential (the tests never record an `Authorization` header or a secret, and a
count-only audit, below, proves it). Task 15's device run runs `make evidence` and commits the
redacted capture under `tests/lab/evidence/`. After every run confirm that no `port49d` holds
`172.100.100.1:49`, no `port49-inventory` is running, the topology is destroyed, and `docker compose
ls` lists no port49 stack.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §10, §12, §13 d31, §14, §15 L32 L33 (Task 1); closed rows (Task 16)
docs/design/2026-08-21-port49-design.md       MOD  §6, §17's internal interfaces (Task 1)
internal/sot/secret.go                        NEW  Secret (Task 2)
internal/sot/client.go                        NEW  client: https only, CA per handshake, no redirect, bounded (Task 2)
internal/sot/sottest/tls.go                   NEW  TLS: a test server under a CA of its own (Task 2)
internal/sot/profile.go                       NEW  Profile, Version, Detect, the measured table, ValidPath (Task 3)
internal/sot/sottest/replay.go                NEW  Server: replays an L30 stack with n devices (Task 4)
internal/sot/graphql.go                       NEW  selection, the list query, errors before data, restCount (Task 5)
internal/sot/rest.go                          NEW  the REST list, follow (Task 6)
internal/sot/device.go, alias.go              NEW  Mapping, Filter, Addresses, the alias table (Task 7)
internal/sot/source.go                        NEW  Config, Source, New, Fetch (Task 8)
internal/inventory/config.go                  MOD  netbox and nautobot sources, webhook_listen (Task 9)
internal/inventory/source.go                  MOD  NewSources builds sot sources (Task 9)
internal/inventory/sync.go                    MOD  fetch within sync_timeout; generic platforms; At (Tasks 10, 13)
internal/inventory/metrics.go                 MOD  source_hung, generic_platform_devices (Task 10); webhooks (Task 11)
internal/inventory/safety.go                  MOD  a device left with no address is out of service (Task 10a)
internal/bundle/diff.go                       MOD  Unaddressed; CheckFrom counts it (Task 10a)
internal/inventory/webhook.go                 NEW  Webhooks, WebhookServer (Task 11)
internal/inventory/trigger.go                 NEW  Debouncer (Task 12)
cmd/port49-inventory/main.go                  MOD  the webhook listener and debouncer (Task 12)
internal/inventory/api.go, client.go          MOD  GET /v1/bundle?sequence=N; BundleAt (Task 13)
internal/admission/encode.go                  NEW  EncodeFile (Task 13)
cmd/port49/inventory.go, main.go              MOD  inventory export; sync prints generic platforms (Tasks 10, 13)
internal/testpki/testpki.go                   MOD  Leaf.DNSNames (Task 14)
tests/lab/cmd/sot-pki/main.go                 NEW  the proxies' and the webhook's lab PKI (Task 14)
tests/lab/sot/compose/*.yml, l32-proxy-*.conf MOD/NEW  the l32 proxies; the worker's CA and host name (Tasks 14, 15)
tests/lab/sot/run.sh, README.md               MOD  l32, l33 and e2e modes (Tasks 14, 15)
tests/lab/l32_test.go, l32_unit_test.go       NEW  the connectors as built, through two proxies (Task 14)
tests/lab/inventory_test.go                   MOD  startInventoryWith (Task 15)
tests/lab/sot_admin_test.go                   NEW  the harness's writes to a stack (Task 15)
tests/lab/l33_test.go, l33_unit_test.go       NEW  webhooks to port49-inventory (Task 15)
tests/lab/sot_e2e_test.go                     NEW  NetBox and Nautobot to vEOS, end to end (Task 15)
tests/lab/sot/l32/, l33/, results/L32-*.md, L33-*.md   NEW  written by the lab runs
docs/superpowers/plans/README.md              MOD  plan 6c as built (Task 16)
```

Seventeen tasks:
- **Task 1** is docs, and comes first: every later task cites the text it writes.
- **Tasks 2–13, with 10a,** are code. Every one leaves `make test` green. Tasks 2–8 are `internal/sot`
  and depend on nothing outside it but `admission`, `bundle`, `config` and `testpki`; Tasks 9–13 wire
  it into the service and the tool; Task 10a amends 6b's two bounds (pre-flight I2).
- **Task 14** is a lab measurement (L32) of Tasks 2–8 as built, on Compose.
- **Task 15** is a lab measurement (L33) of Tasks 9–12 as built, and the device run end to end. It
  gates the merge.
- **Task 16** is lab closure and docs.

---

### Task 1: The spec and the design say what plan 6c builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Each edit is given as the text to find and the text to put in its place; where a paragraph
is new, the text it goes after. Nothing here asserts an unmeasured fact: what L32 and L33 will
measure is written as their open rows, and cited to them.

- [ ] **Step 1: §10, "The inventory service", the API.** Replace the code block that lists the five
  paths with:

  ```
  GET  /v1/bundle                      full bundle; ETag for cheap no-op refresh
  GET  /v1/bundle?sequence=<n>         bundle n from the service's history, for `port49 inventory export`
  GET  /v1/bundle/version              current version, for polling
  GET  /v1/bundle/diff?from=<ver>      for CI and `port49 inventory diff`
  POST /v1/sync                        on-demand trigger
  GET  /v1/devices/{address}           diagnostic only — MUST NOT be used on the hot path

  POST /v1/webhook/{source}            not the API: webhook_listen, TLS without a client certificate (below)
  ```

- [ ] **Step 2: §10, "The inventory service", the triggers.** Replace the paragraph beginning
  "**Four triggers are built in two plans.**" with:

  ```markdown
  **Four triggers are built in two plans.** The schedule (each source's `interval`, default the
  top-level `interval`, default 10 minutes; a sync of one source rebuilds the merged bundle from every
  source's latest fetch), startup, and `port49 inventory sync` are plan 6b's, with the file connector;
  the NetBox and Nautobot connectors and their webhooks are plan 6c's, written against the fixtures
  L27 and L30 recorded (§13, decision 31).

  **A webhook is authenticated by its signature, and only triggers a sync.** No product can present
  a client certificate (the webhook L27 and L30 recorded has `ssl_verification` and `ca_file_path`,
  nothing that holds one), so deliveries arrive on a listener of their own, `webhook_listen`: TLS
  under the service's certificate, or `webhook_tls_cert_file`, and no client certificate; the API
  stays mutual TLS on every path. Its one route is `POST /v1/webhook/<source>`. A delivery is taken
  only for a source configured with `webhook_secret_env`, as `application/json`, at most 1 MiB, with
  an `X-Hook-Signature` equal to HMAC-SHA512 of the body under that secret (L27, L30), and with a
  `timestamp` within 5 minutes of the service's clock either way; one whose signature was taken in
  the last 10 minutes triggers nothing. Anything else is refused (401, 413, 415 or 400; every 401
  with the one body `{"error":"unauthorized"}`, so a caller cannot tell a configured source name from
  another), counted (`port49_inventory_webhooks_total{source, outcome}`) and said once per source and
  outcome, naming the sender's address and never the body, the signature or the secret; a failed TLS
  handshake is counted (`outcome="tls_handshake"`), not logged. A taken delivery triggers a
  sync of its source 2 s later, coalescing a burst; a source is synced from webhooks at most once
  per 30 s, with at most one sync pending. Nothing in a delivery reaches the bundle: the sync reads
  the source's API, so delivery order, which is not change order on Nautobot (L27, L30), orders
  nothing, and the body's `timestamp` is read only for freshness. A refused or lost delivery costs at
  most the source's `interval`, which still runs. Delivery to the listener as built, from each
  measured release, is §15 L33's.
  ```

- [ ] **Step 3: §10, "Connectors and sync cadence".** Replace the text from "Four requirements:"
  through the end of the fenced `yaml` block that begins `# port49-inventory.yaml (plan 6b: the file
  source; netbox and nautobot are plan 6c's)` (the line after its last `#   map:` line) with:

  ````markdown
  Four requirements, as plan 6c builds them (§13, decision 31):

  **Version detection.** NetBox 4.x renamed `device_role` to `role`; Nautobot 2.0 did the same
  and dropped `slug` from most models. The connector reads the release from `/api/status/`
  (`netbox-version`, `nautobot-version`), never `Api-Version` alone, which Nautobot 1.6 sets to `1.2`
  (L27), at every sync, and selects a mapping profile by it: NetBox 3.7 is `netbox_3_7`, NetBox 4.x
  `netbox_4`, Nautobot 1.6 `nautobot_1_6`, Nautobot 2.x and 3.x `nautobot_2` (L30: 3.2.6 answered every
  L27 question as 2.4.43 did, less the device fields `cluster` and `software_image_files`, which no
  profile reads). A release whose minor no lab run measured is read with its major's profile and
  said; a major no lab run measured is refused unless the source names a `profile`, the explicit
  override. A status naming the other product refuses the sync.

  **GraphQL first.** At 10,000 devices, REST pagination is hundreds of round trips per sync.
  Both products expose GraphQL; one query returns devices, addresses, platform, site, role,
  and tags (L27). The connector asks for what its map, filter and address rule read, and reads
  GraphQL's `errors` before its `data`, whatever the HTTP status: NetBox 4.7.1 refuses an unknown
  argument with HTTP 200 and an `errors` list (L30). It pages by `pagination: {offset, limit}`, as
  NetBox 4.7.1 took (L30), by `limit` and `offset`, as Nautobot 1.6.32, 2.4.43 and 3.2.6 took, and not
  at all for NetBox 3.7, whose 3.7.8 took no paging shape tried and returned the whole list (L30); each
  profile reads the other minors of its major the same way, and says such a release is unmeasured. A
  GraphQL list is taken only when its length equals REST's `count` read before it and read after it,
  and no device appears in it twice: a server cap, or a page boundary lost to a concurrent delete,
  would otherwise look like devices removed. A page longer than the page size asked for, or a fetch
  past 256 MiB, fails the sync. REST remains a fallback, taken when GraphQL answers 404 or the source
  says `api: rest`: it reads `?depth=1` under the `nautobot_2` profile, since Nautobot 2.4.43 and 3.2.6
  at default depth named no related object (L27, L30), and follows `next` (below); every page must
  give the same `count`, and the total must equal it, with no device twice. REST does not
  give interface addresses in the device list, so a source that asks for them reads GraphQL only:
  `api: rest` with interfaces is refused at load, and a GraphQL 404 fails the sync rather than
  falling back. The connector's own query, on each measured release, is §15 L32's.

  **`next` is followed only on the configured base.** Every product builds `next` from the host the
  request arrived under (L30), so behind a proxy that rewrites `Host` it can name another origin. A `next`
  whose scheme, host and port are the source `url`'s is followed; one on another origin is rebuilt on
  the `url`, its path and query kept, and said once; one whose path is not the `url`'s device list is
  refused. No redirect is followed: the source's token is sent to `url` and nowhere else. A REST read
  whose total differs from its last page's `count` fails the sync. Which of `Host` and
  `X-Forwarded-Host` each product builds `next` from, and the connector reading through each kind of
  proxy, are §15 L32's.

  **Bounded change per sync.** A sync in which a source takes more than its
  `safety.max_removed_percent` of the devices it gave the last published bundle out of service —
  removed, kept and newly refused admission under the service's policy, or kept with an address in
  the bundle in force and none now (plan 6c: port49d admits by source address, so under an attribute
  key group such a device stays "admitted" and is unreachable) — MUST refuse, retain the
  last good snapshot, and alarm (`port49_inventory_sync_refused`). A source's bound defaults to the
  top-level `safety.max_removed_percent`, default 10. An empty result, and one the service's policy
  admits none of, are refused whatever the bound. A partially-available source of truth or a
  mistyped filter would otherwise silently deauthorize the fleet. Each port49d bounds the document
  again by its own `inventory.max_removed_percent`, counting the same three: a deliberate large
  removal raises both.

  **Platform slug translation.** Real installations say `eos`, `arista-eos`, `arista_eos`, or
  `veos`. The connector ships an alias table (those, and the netutils drivers Nautobot reports in
  `platform.network_driver`, such as `cisco_xe`), a source's `platform_aliases` adds to or overrides
  it, and a slug neither knows is kept as the device's platform: the device is admitted and served by
  the generic adapter (§8, "Unknown platforms"); each publication that changes the set of such
  platforms says so, and `port49_inventory_generic_platform_devices` holds their devices' count
  always, whatever the source, rather than falling back to generic in silence.

  **Filters, maps and addresses run in the service.** A source's `filter` (`status`, default
  `[active]`, compared in lower case so each recorded spelling matches — `"ACTIVE"` on NetBox 3.7.8,
  `"active"` on 4.7.1, `{"name": "Active"}` on every Nautobot measured, L30; `tags`, every one named;
  `has_primary_ip`) is applied to what was read, since the products' filter arguments differ per
  release and L27 measured only `name`'s. Its `map` names, per attribute, a path the profile reads
  (L27, L30): on NetBox `site.slug`, `role.slug`, `platform.slug`; on Nautobot 1.6 those and
  `platform.network_driver`; on Nautobot 2.x and 3.x `location.name`, `role.name`, `platform.name`,
  `platform.network_driver`; on every profile `status` and `custom_fields.<key>`. `platform` names the
  device's platform. A device's addresses are its primary addresses (`primary_ip4`, `primary_ip6`;
  `addresses.primary`, default true) and, where `addresses.interfaces` names interfaces or
  `addresses.all_interfaces` asks for every one, those interfaces' addresses too; `primary: false` is
  taken only beside interfaces. Interface addresses are opt-in, since every address listed admits its
  source and an address on two devices refuses the sync; an interface's loopback, link-local,
  multicast or unspecified address is left out, since it cannot source TACACS+ and repeats across
  devices. An attribute a device does not give — a null custom field, or one that is an object or a
  list — is left unset, never invented, and §5.5's `on_missing` decides what that means. A connector
  returns no key assignment: nothing it reads can carry one (§13, decision 30).

  **Every `Fetch` returns within `sync_timeout`.** Each request is under the sync's deadline, and a
  connector that has not returned 5 s past it is abandoned: the sync fails, the source is marked
  (`port49_inventory_source_hung{source}`), and it is not asked again until the abandoned call
  returns.

  ```yaml
  # port49-inventory.yaml
  listen: ":8443"
  metrics_listen: ":9050"
  webhook_listen: ":8444"           # plan 6c: needed when a source has webhook_secret_env
  tls_cert_file: /etc/port49-inventory/server.pem
  tls_key_file: /etc/port49-inventory/server-key.pem
  # webhook_tls_cert_file, webhook_tls_key_file: the webhook's own; default the API's
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
    - name: netbox_prod
      type: netbox                  # or nautobot
      url: https://netbox.example.com
      ca_file: /etc/ssl/certs/ca-certificates.crt   # required; the CA that issues the source's certificate
      token_secret_env: PORT49_NETBOX_TOKEN         # read at start, never printed; secret_ref waits for plan 12
      webhook_secret_env: PORT49_NETBOX_WEBHOOK     # optional: turns the source's webhooks on
      # profile: netbox_4           # optional override of the detected profile
      # api: auto                   # auto (GraphQL, REST on a 404), graphql, rest
      # page_size: 500
      interval: 10m
      safety: {max_removed_percent: 10}
      filter: {status: [active], tags: [port49], has_primary_ip: true}
      map: {platform: platform.slug, site: site.slug, role: role.slug, os_version: custom_fields.os_version}
      addresses: {primary: true, interfaces: [Loopback0]}
      platform_aliases: {eos-lab: arista_eos}
  ```
  ````

- [ ] **Step 4: §10, "Source-of-truth write access is privilege-granting".** After the bullet
  beginning "Attributes used for security scoping SHOULD come from an attested path", add:

  ```markdown
  - A connector's token MUST be able to read devices and nothing more. The service never writes
    to a source, and a token that can write turns a compromise of the service into one of the source
    of truth. A webhook's secret is readable by anyone the product lets read its webhooks (both
    products return `secret` from their webhook API, `tests/lab/sot/l30/*/webhooks.json`): it lets
    its holder trigger a sync, which is bounded and reads only the source, and nothing more.
  ```

- [ ] **Step 5: §12, after the `port49 inventory keygen` paragraph.** Add:

  ```markdown
  **`port49 inventory export --service <url> --ca <file> --cert <file> --key <file> --verify-key
  <file> [--verify-key <file>] [--from <sequence>] [--out <file>]`** reads the bundle the service
  publishes, or bundle `<sequence>` from its history (`GET /v1/bundle?sequence=<n>`, the read right;
  the service keeps the last 64), opens it against the verify keys as port49d does, and writes its
  inventory in `inventory_file`'s schema to `--out`, written 0600 and never overwritten, or to
  standard output, so the offline tools (`policy test`, `policy diff`, `inventory diff`, `explain`)
  keep an `--inventory` when no source is a file. The file carries no key assignment, since no
  document can. A document that does not open, or whose sequence is not `<sequence>`, is refused and
  nothing is written.
  ```

- [ ] **Step 6: §13, after decision 30.** Add:

  ```markdown
  **31. A connector reads what the lab measured, and a webhook only says "look again".** *Plan 6c,
  2026-10-01, rulings where §10 was silent, each the option that denies more.* The connectors select
  a profile from `/api/status/` by the releases L27 and L30 measured, refuse a major none measured
  unless a profile is named, read only the fields those runs recorded, read GraphQL's `errors`
  before its `data`, take a list only when it equals REST's `count` before and after it with no
  device twice, follow `next` only on the source's `url` (rebuilding it there otherwise) and no
  redirect at all, filter in the service, take primary addresses, and interface addresses only where
  named, leave an attribute a device does not give unset, and pass an unrecognized platform through,
  said. A device left with no address counts against the bound in
  the service and in port49d. A source of truth is `https` with a named CA, its token and
  webhook secret named by `secret_env`-style keys until plan 12's `secret_ref`, and never printed.
  A webhook arrives on its own TLS listener, since no product can present a client certificate, and
  is authenticated by HMAC-SHA512 of its body; it carries nothing into the bundle and only triggers a
  debounced sync of its source, so its order is irrelevant and its `timestamp` is read for freshness
  alone. A `Fetch` past `sync_timeout` is abandoned and its source not asked again until it returns.
  `port49 inventory export` verifies the bundle's signature before it writes.
  ```

- [ ] **Step 7: §14, "Inventory and capability".** After the bullet beginning "**One rule for a
  usable device**", add:

  ```markdown
  - **Connectors read what was measured**: the profile is chosen from `/api/status/`, and a major no
    lab run measured is refused unless a profile is named; GraphQL `errors` fail a fetch even on HTTP
    200; a GraphQL list whose length is not REST's `count` both before and after, a REST page whose
    `count` moved, or a list naming a device twice fails the sync and de-admits nothing; a sync that
    leaves more than the bound's share of a source's devices with no address is refused, by the
    service and by port49d; `next` is
    followed only on the source's `url` and otherwise rebuilt there, and no redirect is followed, so
    the token reaches no other host; a filter, a map path and an address rule each take the
    product's recorded spelling; the token appears in no line and no error.
  - **A webhook only triggers**: an unsigned, mis-signed, stale (more than 5 minutes either way),
    oversized, non-JSON or repeated delivery, or one for a source without a webhook secret, triggers
    nothing and is said without its body, signature or secret; an authentic one triggers one sync of
    its source, a burst one sync, and a flood one sync per 30 s.
  - **Every `Fetch` returns within `sync_timeout`**: a source that ignores its context is abandoned 5 s
    past the deadline, the sync fails and the bundle in force keeps serving, and the source is not
    asked again until the abandoned call returns.
  - **Export verifies**: a bundle that does not open under the verify keys writes nothing, nor one
    whose sequence is not the one `--from` asked for; one that does writes a file `--inventory` loads
    to the same bundle.
  ```

- [ ] **Step 8: §15, the register table.** After the row `| **L31** | … |`, add two rows:

  ```markdown
  | **L32** | What the inventory service's NetBox and Nautobot connectors read as built (plan 6c), from each measured release: the GraphQL list query with every field the connector asks for (`status`, `primary_ip4`, `primary_ip6`, the map's paths, every interface address), paged as the profile pages it, returning every device once and matching REST's `count`; the REST fallback (`?depth=1` under the `nautobot_2` profile) to a null `next`; and both through a TLS-terminating reverse proxy that sends the client's host as `Host` alone, and through one that sends the upstream's name as `Host` and the client's as `X-Forwarded-Host`: which header each release builds `next` from, and whether the connector reads every device through each, following `next` or rebuilding it on its `url`. | Plan 6c's connectors: the query per profile, the count check, following or rebuilding `next` (§10, "Connectors and sync cadence"; §13, decision 31) | NetBox 3.7 and 4.x; Nautobot 1.6, 2.x and 3.x | open |
  | **L33** | What NetBox and Nautobot do delivering a webhook to port49-inventory's `webhook_listen`, per measured release: whether each delivers to an `https` payload URL whose certificate a private CA issued (`ca_file_path`, `ssl_verification` on); whether port49-inventory authenticates every delivery as it arrives (HMAC-SHA512 of the body, `X-Hook-Signature`) and finds its `timestamp` inside the 5-minute window; how long a change takes from the API write to the published bundle; whether a delivery port49-inventory refuses (HTTP 401) is sent again; and, end to end on one device, how long a NetBox and a Nautobot change takes to reach port49d's admission through the webhook. | Plan 6c's webhook trigger: TLS on the webhook listener, the freshness window, the 401 answer (§10; §13, decision 31) | NetBox 3.7 and 4.x; Nautobot 1.6, 2.x and 3.x; vEOS-lab for the device run | open |
  ```

- [ ] **Step 9: §15, the notes under the register.** After the L31 note (the paragraph ending "where
  it cost 16–41 s."), add:

  ```markdown
  - **L32** — added 2026-10-01 by plan 6c, for what L30 left unmeasured outside its question (which of
    `Host` and `X-Forwarded-Host` the products read; following a proxied `next`) and for the
    connector's own query, which asks for fields no L27 or L30 query asked together (`primary_ip6`
    and `status` beside the map's paths). The code does not depend on which header a release reads:
    it follows `next` on its `url` and rebuilds it otherwise (§10). Owned by plan 6c, Task 14.
  - **L33** — added 2026-10-01 by plan 6c. L27 and L30 recorded deliveries to a plain-HTTP listener;
    port49-inventory takes them only over TLS, so whether each release delivers to a private CA's
    certificate is unmeasured, and so is what a release does with a refused delivery. Owned by plan
    6c, Task 15, with the device run end to end.
  ```

- [ ] **Step 10: design §6, "Inventory service".** Replace "and, from plan 6c, the NetBox and
  Nautobot connectors." with:

  ```markdown
  and, from plan 6c, the NetBox and Nautobot connectors, whose webhooks arrive on a TLS listener of
  their own, authenticated by their signature, and only trigger a sync (policy engine spec §10).
  ```

- [ ] **Step 11: design §17, "Internal interfaces".** In the table, after the row `| connector →
  NetBox / Nautobot | … |`, add:

  ```markdown
  | NetBox / Nautobot → inventory service webhook | HMAC-SHA512 of the body under the source's webhook secret, over TLS on `webhook_listen` | trigger a sync of that source; nothing in the delivery reaches the bundle |
  ```

  and replace the connector row's Permitted cell `read devices` with `read devices, with a read-only
  token: the service never writes`. After the table's paragraph
  "**Reading a snapshot is not the same right as triggering a sync.**…", add the paragraph below,
  and change the lead-in "Two consequences worth stating:" to "Three":

  ```markdown
  **A webhook is the one inbound call without a workload identity, and its secret is not a bearer
  token.** No source of truth can present a client certificate (policy engine spec §10), so a
  delivery is authenticated by HMAC-SHA512 of its body. The secret is never sent with a delivery,
  and the service checks the signature in constant time. A host on the network without the secret
  can trigger nothing. A holder of the secret, which includes anyone the product lets read its
  webhooks, can make the service sync one source, which is bounded and reads only that source, and
  nothing else.
  ```

- [ ] **Step 12: Check and commit.** `make test && make vet` (unchanged; report the output). Then:

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: the connectors, the webhook trigger and inventory export, before plan 6c builds them

Spec §10, §12, §13 decision 31, §14, and two open register rows, L32
(the connectors as built, through two kinds of proxy) and L33 (webhooks
to port49-inventory over TLS, and the device run). Design §6 and §17.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: `internal/sot`: a secret that never prints, and a client that sends it to one place

**Files:**
- Create: `internal/sot/secret.go`, `internal/sot/client.go`, `internal/sot/sottest/tls.go`
- Test: `internal/sot/client_test.go`

**Interfaces:**
- Consumes: `testpki.NewCA`, `(*testpki.CA).Issue`, `testpki.Leaf`, `testpki.Loopback`, `(*testpki.CA).PEM`.
- Produces:
  - `type sot.Secret struct{ /* unexported */ }`; `func sot.NewSecret(v string) Secret`;
    `func (Secret) Reveal() string`; `func (Secret) Empty() bool`. Prints `<redacted>` under every
    `fmt` verb and in JSON.
  - `func sot.CheckURL(raw string) error` — the source `url` rule, for the config loader (Task 9).
  - `type client struct{ base *url.URL; auth Secret; http *http.Client }` (unexported);
    `func newClient(base, caFile string, token Secret, product string) (*client, error)`;
    `func (c *client) at(path string, q url.Values) *url.URL`;
    `func (c *client) do(ctx context.Context, method string, u *url.URL, body []byte, full bool) (answer, error)`;
    `func (c *client) getJSON(ctx context.Context, u *url.URL, v any) error`;
    `type answer struct{ status int; body []byte }`;
    `func statusError(what string, status int) error`; `func printable(s string) string`;
    `var maxResponse int64` (64 MiB); `const maxPages = 1000`, `const maxDevices = 100_000`;
    `var maxFetch int64` (256 MiB), `type budget struct{ left int64 }`, `func newBudget() *budget`,
    `func (b *budget) spend(n int) error` (pre-flight M3).
  - Consumes `config.ReadRegular` for the CA file (pre-flight M2).
  - `func sottest.TLS(t testing.TB, h http.Handler) (*httptest.Server, string)` — a server under a CA
    of its own, and a `ca_file` that trusts it.

- [ ] **Step 1: The test server.** Create `internal/sot/sottest/tls.go`:

```go
// Package sottest serves NetBox and Nautobot to the connector's tests: a TLS
// server under a CA of its own, and a replay of a stack L30 recorded
// (replay.go).
package sottest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// TLS serves h over TLS with a certificate for 127.0.0.1 from a CA made for
// it alone, and returns the server and a ca_file that trusts that CA and
// nothing else. httptest's own certificate is the same for every server, so
// it cannot show a CA file refusing a server it did not issue.
func TLS(t testing.TB, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("sottest CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(testpki.Leaf{CommonName: "sottest", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, caFile
}
```

- [ ] **Step 2: Write the failing tests.** Create `internal/sot/client_test.go`:

```go
package sot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

const token = "0123456789abcdef0123456789abcdef01234567"

func TestASecretNeverPrints(t *testing.T) {
	s := struct{ Token Secret }{NewSecret("hunter2-token")}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if out := fmt.Sprintf(verb, s); strings.Contains(out, "hunter2") {
			t.Fatalf("%s printed it: %s", verb, out)
		}
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "hunter2") {
		t.Fatalf("JSON: %s", b)
	}
	if s.Token.Reveal() != "hunter2-token" || s.Token.Empty() || !NewSecret("").Empty() || !(Secret{}).Empty() {
		t.Fatal("Reveal or Empty")
	}
	// Reached through an unexported field, fmt prints a struct field by
	// field: the pointer keeps the value out (pre-flight M1).
	hidden := struct{ cfg struct{ token Secret } }{}
	hidden.cfg.token = NewSecret("hunter2-token")
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, hidden); strings.Contains(out, "hunter2") {
			t.Fatalf("%s printed it through an unexported field: %s", verb, out)
		}
	}
}

// Decision 31: the source of truth is https, and its url carries nothing
// but where it is. An error never quotes what was pasted there.
func TestTheBaseIsStrictHTTPS(t *testing.T) {
	for raw, want := range map[string]string{
		"http://netbox.example.com":                        "must be https://",
		"netbox.example.com":                               "must be https://",
		"https://admin:" + token + "@netbox.example.com":   "user information",
		"https://netbox.example.com/?token=" + token:       "a query or a fragment",
		"https://netbox.example.com/#" + token:             "a query or a fragment",
	} {
		err := CheckURL(raw)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), token) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	if err := CheckURL("https://netbox.example.com/netbox/"); err != nil {
		t.Fatal(err)
	}
}

func TestACAFileIsRequired(t *testing.T) {
	if _, err := newClient("https://netbox.example.com", "", NewSecret(token), "netbox"); err == nil ||
		!strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("got %v", err)
	}
}

// L27: NetBox 4.x provisions v2 tokens, nbt_<key>.<token>, sent as Bearer; a
// v1 token, and every Nautobot token, is sent as Token.
func TestTheTokenSchemeFollowsTheToken(t *testing.T) {
	var got string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	for _, c := range []struct{ product, token, want string }{
		{"netbox", "nbt_abcdefabcdef.0123456789", "Bearer nbt_abcdefabcdef.0123456789"},
		{"netbox", token, "Token " + token},
		{"nautobot", "nbt_looks_like_netbox", "Token nbt_looks_like_netbox"},
	} {
		cl, err := newClient(srv.URL, ca, NewSecret(c.token), c.product)
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil || got != c.want {
			t.Errorf("%s %s: sent %q, %v", c.product, c.token, got, err)
		}
	}
}

// Decision 31: no redirect is followed, so the token goes to the configured
// base alone.
func TestARedirectIsNotFollowed(t *testing.T) {
	elsewhere := 0
	other, _ := sottest.TLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/status/", http.StatusFound)
	}))
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	err = cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if err == nil || !strings.Contains(err.Error(), "a redirect, which is not followed") || elsewhere != 0 {
		t.Fatalf("%v; requests elsewhere: %d", err, elsewhere)
	}
}

// A refusal names the key that holds the token, and never prints it, even
// when the product echoes it.
func TestARefusedTokenIsNamedNeverPrinted(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"detail": "Invalid token %s"}`, r.Header.Get("Authorization"))
	}))
	cl, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	var v map[string]any
	err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if err == nil || !strings.Contains(err.Error(), "answered HTTP 403: the token token_secret_env names") ||
		strings.Contains(err.Error(), token) {
		t.Fatalf("%v", err)
	}
}

func TestAnAnswerPastTheBoundIsRefused(t *testing.T) {
	defer func(m int64) { maxResponse = m }(maxResponse)
	maxResponse = 1024
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"x": "` + strings.Repeat("a", 2048) + `"}`))
	}))
	cl, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil ||
		!strings.Contains(err.Error(), "more than 1024 bytes") {
		t.Fatalf("%v", err)
	}
}

func TestAServerTheCAFileDoesNotTrustIsRefused(t *testing.T) {
	srv, _ := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) }))
	_, otherCA := sottest.TLS(t, http.NotFoundHandler())
	cl, _ := newClient(srv.URL, otherCA, NewSecret(token), "netbox")
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("%v", err)
	}
}

// Pre-flight M2: a FIFO at ca_file is refused, not read until something
// writes to it.
func TestACAFileThatIsAFIFOIsRefused(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := newClient("https://netbox.example.com", fifo, NewSecret(token), "netbox"); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ca_file") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}

// Pre-flight M3: a fetch reads at most maxFetch bytes over all its pages.
func TestABudgetBoundsAFetch(t *testing.T) {
	defer func(m int64) { maxFetch = m }(maxFetch)
	maxFetch = 100
	b := newBudget()
	if err := b.spend(60); err != nil {
		t.Fatal(err)
	}
	if err := b.spend(60); err == nil || !strings.Contains(err.Error(), "the most one sync reads") {
		t.Fatalf("got %v", err)
	}
}

func TestPrintableCutsAndNeutralises(t *testing.T) {
	if got := printable("a\x1b[2Jb\nc"); got != "a?[2Jb?c" {
		t.Fatalf("%q", got)
	}
	if got := printable(strings.Repeat("x", 300)); len(got) > maxPrinted+len("…") {
		t.Fatalf("%d bytes", len(got))
	}
}
```

- [ ] **Step 3: Run them.** `go test ./internal/sot/ -count=1`
  Expected: FAIL (undefined: `Secret`, `CheckURL`, `newClient`, …).

- [ ] **Step 4: Implement.** Create `internal/sot/secret.go`:

```go
// Package sot reads a source of truth, NetBox or Nautobot, into port49's
// inventory facts (spec §10, "Connectors and sync cadence"; §13, decision
// 31). It is the contributable surface the inventory service isolates: it
// holds the source's token, never writes, and returns facts only — no key
// assignment (spec §13, decision 30). It imports nothing from
// internal/inventory, which builds one Source per configured source.
package sot

import (
	"fmt"
	"io"
)

// Secret is a credential read from the environment: a source's API token,
// or its webhook secret. It prints as <redacted> under every fmt verb and in
// JSON, so a configuration printed whole — by a test, a panic, a %+v — never
// carries it. fmt calls Format only on a value it can reach through
// exported fields; reached through an unexported one (a Source's cfg, a
// client's auth) a Secret is printed field by field, so the value sits
// behind a pointer and prints as an address there (pre-flight M1). Reveal is
// the one way to the value, at the one place that sends or checks it.
type Secret struct{ p *string }

// NewSecret holds v.
func NewSecret(v string) Secret { return Secret{&v} }

// Reveal is the value: for the Authorization header, or the HMAC key.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// Empty is whether there is no value.
func (s Secret) Empty() bool { return s.Reveal() == "" }

func (Secret) Format(f fmt.State, _ rune)   { io.WriteString(f, "<redacted>") }
func (Secret) String() string               { return "<redacted>" }
func (Secret) GoString() string             { return "<redacted>" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }
```

  Create `internal/sot/client.go`:

```go
package sot

import (
	"bytes"
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
	"strings"
	"time"
	"unicode"

	"github.com/rhwendt/port49/internal/config"
)

// maxResponse bounds one answer's body: a GraphQL page of page_size devices
// with their interfaces is a few MiB, and 64 MiB is inventory_file's bound.
// A variable for the tests.
var maxResponse int64 = 64 << 20

// maxFetch bounds the bytes one fetch reads summed over its pages
// (pre-flight M3): the page and device caps do not bound bytes, and a broken
// or compromised source must not exhaust the service's memory. A variable
// for the tests.
var maxFetch int64 = 256 << 20

// budget is what is left of maxFetch for one fetch's list.
type budget struct{ left int64 }

func newBudget() *budget { return &budget{left: maxFetch} }

// spend takes n bytes of a page, or refuses the fetch.
func (b *budget) spend(n int) error {
	if b.left -= int64(n); b.left < 0 {
		return fmt.Errorf("the device list is larger than %d MiB, the most one sync reads: filter the source, or "+
			"split it into two sources", maxFetch>>20)
	}
	return nil
}

const (
	// maxErrorBody bounds what is read of an answer that is neither a 200 nor
	// GraphQL's: it is drained, never printed.
	maxErrorBody = 64 << 10
	maxCAFile    = 1 << 20
	// maxPrinted bounds one string of the source's that is printed: a GraphQL
	// error message, a path a next named.
	maxPrinted = 200
	// maxPages and maxDevices bound one list, so a source that pages forever
	// ends the sync rather than the service's memory.
	maxPages   = 1000
	maxDevices = 100_000
)

// dialTimeout bounds a dial and a TLS handshake; the sync's deadline bounds
// the rest. A variable for the tests.
var dialTimeout = 10 * time.Second

// client asks one source of truth over https as one identity, its token. It
// follows no redirect, so the token goes to the configured base and nowhere
// else (decision 31); the CA file is read at each handshake, so a rotated CA
// needs no restart, as the service client's is (plan 6b Task 12).
type client struct {
	base *url.URL
	auth Secret
	http *http.Client
}

// answer is one reply: its status and its body.
type answer struct {
	status int
	body   []byte
}

// CheckURL is the source url rule: https, a host, and no user information,
// query or fragment. A path is kept, for a source served under a prefix. The
// errors quote nothing of raw: user information and a query are where a
// token gets pasted.
func CheckURL(raw string) error {
	_, err := parseBase(raw)
	return err
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("url must be https://host[:port][/path]")
	}
	if u.User != nil {
		return nil, errors.New("url carries user information; the source is asked with the token token_secret_env " +
			"names, so remove it")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("url carries a query or a fragment; it is https://host[:port][/path]")
	}
	u.Path, u.RawPath = strings.TrimSuffix(u.Path, "/"), ""
	return u, nil
}

// newClient is a client of base. product picks the token's scheme: a NetBox
// v2 token (nbt_<key>.<token>) is Bearer, every other is Token (L27).
func newClient(base, caFile string, token Secret, product string) (*client, error) {
	u, err := parseBase(base)
	if err != nil {
		return nil, err
	}
	if _, err := readCA(caFile); err != nil {
		return nil, err
	}
	scheme := "Token "
	if product == "netbox" && strings.HasPrefix(token.Reveal(), "nbt_") {
		scheme = "Bearer "
	}
	host := u.Hostname()
	dialer := &net.Dialer{}
	tr := &http.Transport{
		// Each connection's TLS config is built at its dial from the CA file
		// as it is then; RootCAs is never nil, so never the host's roots
		// unless the CA file is the host's bundle.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pool, err := readCA(caFile)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host})
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 2 * time.Minute, MaxIdleConnsPerHost: 2}
	return &client{base: u, auth: NewSecret(scheme + token.Reveal()), http: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// readCA is the CA file's certificates, read bounded. A file with none is an
// error: an empty pool is never a reason to fall back.
func readCA(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("ca_file: none given; name the CA bundle that issues the source's certificate " +
			"(the host's own bundle file is a valid choice for a public one)")
	}
	// As the service client reads its CA (internal/inventory/client.go): a
	// regular file, opened without blocking and bounded, so a FIFO at ca_file
	// is refused rather than hanging a dial (pre-flight M2). A symbolic link
	// is followed, so a distribution's bundle link still works.
	raw, err := config.ReadRegular(path, maxCAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("ca_file %s holds no PEM certificate", path)
	}
	return pool, nil
}

// at is path under the base, with q as its query.
func (c *client) at(path string, q url.Values) *url.URL {
	u := *c.base
	u.Path, u.RawPath, u.RawQuery = c.base.Path+path, "", q.Encode()
	return &u
}

// what names a request in an error: its method and path. A path a next
// named is the source's text, so it is printed through printable.
func what(method string, u *url.URL) string { return method + " " + printable(u.Path) }

// do sends one request with the token and reads its answer: a 200's body, or
// with full a body whatever the status (GraphQL's errors), up to maxResponse;
// any other answer's up to maxErrorBody, never printed.
func (c *client) do(ctx context.Context, method string, u *url.URL, body []byte, full bool) (answer, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Authorization", c.auth.Reveal())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			// net/http's ResponseHeaderTimeout: the source took over 2
			// minutes to begin an answer, which a large page does (pre-flight
			// M3). A dial or handshake timeout reads otherwise.
			return answer{}, fmt.Errorf("%s: no answer began within 2m: lower page_size", what(method, u))
		}
		return answer{}, clean(err)
	}
	defer resp.Body.Close()
	limit := int64(maxErrorBody)
	if full || resp.StatusCode == http.StatusOK {
		limit = maxResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return answer{}, clean(err)
	}
	if int64(len(raw)) > limit {
		if limit == maxResponse {
			return answer{}, fmt.Errorf("%s answered more than %d bytes", what(method, u), limit)
		}
		raw = raw[:limit]
	}
	return answer{resp.StatusCode, raw}, nil
}

// getJSON GETs u and decodes a 200's JSON into v, numbers as json.Number.
func (c *client) getJSON(ctx context.Context, u *url.URL, v any) error {
	a, err := c.do(ctx, http.MethodGet, u, nil, false)
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return statusError(what(http.MethodGet, u), a.status)
	}
	dec := json.NewDecoder(bytes.NewReader(a.body))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		// Never the body: it is the source's text.
		return fmt.Errorf("%s answered something that is not the JSON asked for", what(http.MethodGet, u))
	}
	return nil
}

// statusError is an answer that is not a 200, with what to do about it.
func statusError(what string, status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%s answered HTTP %d: the token token_secret_env names was refused, or may not read "+
			"devices; it is not printed", what, status)
	case status >= 300 && status < 400:
		return fmt.Errorf("%s answered HTTP %d, a redirect, which is not followed: set url to where it points", what,
			status)
	}
	return fmt.Errorf("%s answered HTTP %d", what, status)
}

// printable is s, the source's text, as one line of at most maxPrinted
// bytes: a control or format character, a line or paragraph separator, or
// an invalid byte is `?`, as inventory.Printable has it.
func printable(s string) string {
	cut := len(s) > maxPrinted
	if cut {
		s = s[:maxPrinted]
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	if cut {
		s += "…"
	}
	return s
}

// cleanError is an error whose text is printable: a TLS error can carry the
// names in a certificate whoever answers the address chose.
type cleanError struct {
	text string
	err  error
}

func (e *cleanError) Error() string { return e.text }
func (e *cleanError) Unwrap() error { return e.err }

func clean(err error) error { return &cleanError{text: printable(err.Error()), err: err} }
```

  `printable` cuts at 200 bytes, so a transport error longer than that is cut and marked; that is
  intended: the line is the operator's, and the URL in it is ours.

- [ ] **Step 5: Run them.** `go test ./internal/sot/... -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): a secret that never prints, and an https client that follows no redirect

The connectors' package (spec §13 decision 31): the source's token is a
sot.Secret, printed as <redacted> under every verb; the client is https
only, reads its named CA at each handshake, sends the token as Bearer for
a NetBox v2 token and Token otherwise (L27), follows no redirect, and
bounds every body.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: Profiles: the releases the lab measured, and the fields each gives

**Files:**
- Create: `internal/sot/profile.go`
- Test: `internal/sot/profile_test.go`

**Interfaces:**
- Consumes: the fixtures `tests/lab/sot/l30/<stack>/status.json` (L30).
- Produces:
  - Profile names: `const sot.NetBox37 = "netbox_3_7"`, `NetBox4 = "netbox_4"`,
    `Nautobot16 = "nautobot_1_6"`, `Nautobot2 = "nautobot_2"`.
  - `type sot.Profile struct { Name, Product string; /* unexported: graphqlPath, list, paging, depthOne, tagKey, status, customFields field; fields map[string]field; defaultMap map[string]string */ }`.
  - `type field struct{ graphql, rest []string }`; `func (f field) over(api string) []string`.
  - `type paging int` with `pageNone`, `pageNested`, `pageArgs`.
  - `type sot.Version struct{ Product, Text string; Major, Minor int }`;
    `func versionOf(status map[string]any, product string) (Version, error)`.
  - `func sot.Detect(v Version, override string) (Profile, bool, error)` — the profile, and whether
    a lab run measured that minor.
  - `func sot.KnownProfile(product, name string) bool`; `func sot.ValidPath(path string) bool`;
    `func (p Profile) paths() []string` (sorted); `func productName(product string) string`.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/profile_test.go`:

```go
package sot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// statusOf is the body of /api/status/ as L30 recorded it for stack.
func statusOf(t *testing.T, stack string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "lab", "sot", "l30", stack, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.Body
}

// L27 and L30: the release is read from /api/status/, and every release they
// measured has its profile.
func TestEachMeasuredReleaseHasItsProfile(t *testing.T) {
	for stack, want := range map[string]string{"netbox-3.7": NetBox37, "netbox-4": NetBox4,
		"nautobot-1.6": Nautobot16, "nautobot-2": Nautobot2, "nautobot-3": Nautobot2} {
		product := strings.SplitN(stack, "-", 2)[0]
		v, err := versionOf(statusOf(t, stack), product)
		if err != nil {
			t.Fatalf("%s: %v", stack, err)
		}
		p, measured, err := Detect(v, "")
		if err != nil || p.Name != want || !measured || p.Product != product {
			t.Errorf("%s (%s): %s measured=%v %v", stack, v.Text, p.Name, measured, err)
		}
	}
}

func TestAnUnmeasuredMinorIsReadWithItsMajorsProfile(t *testing.T) {
	for _, c := range []struct {
		v    Version
		want string
	}{
		{Version{"netbox", "4.6.2", 4, 6}, NetBox4},
		{Version{"nautobot", "2.3.1", 2, 3}, Nautobot2},
		{Version{"nautobot", "3.0.0", 3, 0}, Nautobot2},
	} {
		p, measured, err := Detect(c.v, "")
		if err != nil || p.Name != c.want || measured {
			t.Errorf("%s: %s measured=%v %v", c.v.Text, p.Name, measured, err)
		}
	}
}

// Spec §10: an explicit override is available; without it, a major no lab
// run measured is refused.
func TestAnUnmeasuredMajorIsRefusedUnlessAProfileIsNamed(t *testing.T) {
	for _, v := range []Version{{"netbox", "3.6.9", 3, 6}, {"netbox", "5.0.0", 5, 0}, {"nautobot", "1.5.20", 1, 5},
		{"nautobot", "4.0.0", 4, 0}} {
		if _, _, err := Detect(v, ""); err == nil || !strings.Contains(err.Error(), "no lab run measured") ||
			!strings.Contains(err.Error(), "set profile") {
			t.Errorf("%s: %v", v.Text, err)
		}
	}
	p, measured, err := Detect(Version{"netbox", "3.6.9", 3, 6}, NetBox37)
	if err != nil || p.Name != NetBox37 || measured {
		t.Fatalf("override: %s %v %v", p.Name, measured, err)
	}
	if _, _, err := Detect(Version{"netbox", "4.7.1", 4, 7}, Nautobot2); err == nil ||
		!strings.Contains(err.Error(), "is not a netbox profile") {
		t.Fatalf("a Nautobot profile for NetBox: %v", err)
	}
}

func TestTheStatusMustNameTheProduct(t *testing.T) {
	if _, err := versionOf(statusOf(t, "nautobot-2"), "netbox"); err == nil ||
		!strings.Contains(err.Error(), "answers as Nautobot, and the source's type is netbox") {
		t.Fatalf("got %v", err)
	}
	if _, err := versionOf(map[string]any{}, "netbox"); err == nil || !strings.Contains(err.Error(), "netbox-version") {
		t.Fatalf("got %v", err)
	}
	// A version is the source's text: one that is not a version is refused
	// without being printed.
	if _, err := versionOf(map[string]any{"netbox-version": "4.7.1\x1b[2J"}, "netbox"); err == nil ||
		strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("got %v", err)
	}
}

// Decision 31: the map's vocabulary is what L27 and L30 recorded.
func TestTheVocabularyIsWhatWasRecorded(t *testing.T) {
	for path, ok := range map[string]bool{"site.slug": true, "role.slug": true, "platform.slug": true,
		"platform.network_driver": true, "location.name": true, "role.name": true, "platform.name": true,
		"status": true, "custom_fields.os_version": true, "custom_fields.Asset_Tag_2": true,
		"tenant.slug": false, "site.name": false, "custom_fields.": false, "custom_fields.a-b": false, "name": false} {
		if ValidPath(path) != ok {
			t.Errorf("%s: %v", path, !ok)
		}
	}
	if p := profiles[NetBox4]; strings.Join(p.paths(), ",") != "platform.slug,role.slug,site.slug" {
		t.Fatalf("%v", p.paths())
	}
	if f := profiles[Nautobot16].fields["platform.network_driver"]; f.over("graphql") == nil || f.over("rest") != nil {
		t.Fatal("Nautobot 1.6 gives network_driver over GraphQL only (L27)")
	}
	if !KnownProfile("nautobot", Nautobot2) || KnownProfile("netbox", Nautobot2) || KnownProfile("netbox", "netbox_5") {
		t.Fatal("KnownProfile")
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/ -run 'Profile|Release|Major|Minor|Status|Vocabulary' -count=1`
  Expected: FAIL (undefined: `versionOf`, `Detect`, …).

- [ ] **Step 3: Implement.** Create `internal/sot/profile.go`:

```go
package sot

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The profiles: one per product and the releases whose answers L27 and L30
// recorded as alike.
const (
	NetBox37   = "netbox_3_7"
	NetBox4    = "netbox_4"
	Nautobot16 = "nautobot_1_6"
	// Nautobot2 is 2.x and 3.x: 3.2.6 answered every L27 question as 2.4.43
	// did, less the device fields cluster and software_image_files, which no
	// profile reads (L30).
	Nautobot2 = "nautobot_2"
)

// paging is how a profile's GraphQL list pages (L30).
type paging int

const (
	pageNone   paging = iota // NetBox 3.7.8: no shape tried; the whole list in one answer
	pageNested               // NetBox 4.7.1: pagination: {offset, limit}
	pageArgs                 // every Nautobot: limit, offset
)

// field is where one fact sits in a device, as a path of object keys, over
// GraphQL and over REST. nil is a fact that API does not give on the profile.
type field struct{ graphql, rest []string }

func (f field) over(api string) []string {
	if api == "rest" {
		return f.rest
	}
	return f.graphql
}

func both(path ...string) field { return field{path, path} }

func graphqlOnly(path ...string) field { return field{graphql: path} }

// Profile is how one product's releases are read: the GraphQL endpoint and
// list, how it pages, whether REST needs ?depth=1, where status, tags and
// custom fields sit, and the map's vocabulary — the fields L27 and L30
// recorded, and no others (decision 31).
type Profile struct {
	Name, Product string

	graphqlPath  string
	list         string
	paging       paging
	depthOne     bool
	tagKey       string
	status       field
	customFields field
	fields       map[string]field
	defaultMap   map[string]string
}

var netboxFields = map[string]field{
	"site.slug":     both("site", "slug"),
	"role.slug":     both("role", "slug"),
	"platform.slug": both("platform", "slug"),
}

var profiles = map[string]Profile{
	// L27, L30: NetBox 3.7.8 takes role (and reads device_role beside it),
	// custom_fields as a scalar, status as the upper-case enum name over
	// GraphQL ("ACTIVE") and {value, label} over REST; its GraphQL list took
	// no paging shape tried and returned all 120.
	NetBox37: {Name: NetBox37, Product: "netbox", graphqlPath: "/graphql/", list: "device_list", paging: pageNone,
		tagKey: "slug", status: field{[]string{"status"}, []string{"status", "value"}},
		customFields: both("custom_fields"), fields: netboxFields,
		defaultMap: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: NetBox 4.7.1 as 3.7.8, status "active" over GraphQL, paged
	// by pagination: {offset, limit}.
	NetBox4: {Name: NetBox4, Product: "netbox", graphqlPath: "/graphql/", list: "device_list", paging: pageNested,
		tagKey: "slug", status: field{[]string{"status"}, []string{"status", "value"}},
		customFields: both("custom_fields"), fields: netboxFields,
		defaultMap: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: Nautobot 1.6.32 takes device_role and site; network_driver
	// over GraphQL only; _custom_field_data over GraphQL, custom_fields over
	// REST; status {name} over GraphQL, {value, label} over REST.
	Nautobot16: {Name: Nautobot16, Product: "nautobot", graphqlPath: "/api/graphql/", list: "devices", paging: pageArgs,
		tagKey: "slug", status: field{[]string{"status", "name"}, []string{"status", "value"}},
		customFields: field{[]string{"_custom_field_data"}, []string{"custom_fields"}},
		fields: map[string]field{
			"site.slug":               both("site", "slug"),
			"role.slug":               both("device_role", "slug"),
			"platform.slug":           both("platform", "slug"),
			"platform.network_driver": graphqlOnly("platform", "network_driver"),
		},
		defaultMap: map[string]string{"platform": "platform.network_driver", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: Nautobot 2.4.43 and 3.2.6 take role and location, no slug;
	// REST names a related object only at ?depth=1; status {name} both ways.
	Nautobot2: {Name: Nautobot2, Product: "nautobot", graphqlPath: "/api/graphql/", list: "devices", paging: pageArgs,
		depthOne: true, tagKey: "name", status: both("status", "name"),
		customFields: field{[]string{"_custom_field_data"}, []string{"custom_fields"}},
		fields: map[string]field{
			"location.name":           both("location", "name"),
			"role.name":               both("role", "name"),
			"platform.name":           both("platform", "name"),
			"platform.network_driver": both("platform", "network_driver"),
		},
		defaultMap: map[string]string{"platform": "platform.network_driver", "site": "location.name", "role": "role.name"}},
}

// paths is the profile's vocabulary, sorted, for an error that names it.
func (p Profile) paths() []string {
	out := make([]string, 0, len(p.fields))
	for path := range p.fields {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// customKey is a custom field's key as a map path may name it.
var customKey = regexp.MustCompile(`^custom_fields\.[A-Za-z0-9_]{1,64}$`)

// ValidPath is whether some profile can read path: a field one records,
// status, or custom_fields.<key>. Which profile reads it is known only once
// the release is (Mapping.check).
func ValidPath(path string) bool {
	if path == "status" || customKey.MatchString(path) {
		return true
	}
	for _, p := range profiles {
		if _, ok := p.fields[path]; ok {
			return true
		}
	}
	return false
}

// KnownProfile is whether name is one of product's profiles.
func KnownProfile(product, name string) bool {
	p, ok := profiles[name]
	return ok && p.Product == product
}

// Version is a product's release, as /api/status/ gives it.
type Version struct {
	Product, Text string
	Major, Minor  int
}

// versionShape is a release: digits, a dot, digits, an optional patch and
// suffix. Anything else is not printed.
var versionShape = regexp.MustCompile(`^(\d{1,4})\.(\d{1,4})(\.\d{1,4})?([-+][0-9A-Za-z.+-]{0,32})?$`)

func productName(product string) string {
	if product == "nautobot" {
		return "Nautobot"
	}
	return "NetBox"
}

// versionOf is the release in /api/status/'s body: netbox-version or
// nautobot-version, never Api-Version, which Nautobot 1.6 sets to 1.2 (L27).
func versionOf(status map[string]any, product string) (Version, error) {
	other := "nautobot"
	if product == "nautobot" {
		other = "netbox"
	}
	raw, ok := status[product+"-version"]
	if !ok {
		if _, isOther := status[other+"-version"]; isOther {
			return Version{}, fmt.Errorf("url answers as %s, and the source's type is %s", productName(other), product)
		}
		return Version{}, fmt.Errorf("/api/status/ names no %s-version; is url the %s it should be?", product,
			productName(product))
	}
	text, _ := raw.(string)
	m := versionShape.FindStringSubmatch(text)
	if m == nil {
		return Version{}, fmt.Errorf("/api/status/ gives a %s-version that is not a release number", product)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return Version{Product: product, Text: text, Major: major, Minor: minor}, nil
}

// measured is the minor releases L27 and L30 recorded, by product.
var measured = map[string][]string{"netbox": {"3.7", "4.7"}, "nautobot": {"1.6", "2.4", "3.2"}}

func isMeasured(v Version) bool {
	for _, m := range measured[v.Product] {
		if m == fmt.Sprintf("%d.%d", v.Major, v.Minor) {
			return true
		}
	}
	return false
}

func measuredList(product string) string {
	out := make([]string, len(measured[product]))
	for i, m := range measured[product] {
		out[i] = productName(product) + " " + m
	}
	return strings.Join(out, ", ")
}

// Detect picks v's profile by major and minor, as L27 and L30 measured, and
// says whether a lab run measured that minor. override, a profile name, is
// taken as given (spec §10: "an explicit override available").
func Detect(v Version, override string) (Profile, bool, error) {
	if override != "" {
		if !KnownProfile(v.Product, override) {
			return Profile{}, false, fmt.Errorf("profile %s is not a %s profile", override, v.Product)
		}
		return profiles[override], isMeasured(v), nil
	}
	var name string
	switch {
	case v.Product == "netbox" && v.Major == 3 && v.Minor == 7:
		name = NetBox37
	case v.Product == "netbox" && v.Major == 4:
		name = NetBox4
	case v.Product == "nautobot" && v.Major == 1 && v.Minor == 6:
		name = Nautobot16
	case v.Product == "nautobot" && (v.Major == 2 || v.Major == 3):
		name = Nautobot2
	default:
		return Profile{}, false, fmt.Errorf("%s %s is a release no lab run measured (spec §15 L27, L30: %s); set profile "+
			"to read it with a measured release's fields, at your own risk", productName(v.Product), v.Text,
			measuredList(v.Product))
	}
	return profiles[name], isMeasured(v), nil
}
```

- [ ] **Step 4: Run them.** `go test ./internal/sot/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): profiles by the releases L27 and L30 measured, chosen from /api/status/

NetBox 3.7, NetBox 4.x, Nautobot 1.6, Nautobot 2.x and 3.x (L30: 3.2.6
read as 2.4.43). An unmeasured minor is read with its major's profile; an
unmeasured major is refused unless a profile is named. The map's
vocabulary is the fields the lab recorded (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: `sottest.Server`: a stack L30 recorded, replayed with as many devices as a test asks

**Files:**
- Create: `internal/sot/sottest/replay.go`
- Test: `internal/sot/sottest/replay_test.go`

**Interfaces:**
- Consumes: `sottest.TLS` (Task 2); the fixtures under `tests/lab/sot/l30/<stack>/`: `status.json`,
  `graphql.json`, `graphql-list.json`, `rest-device.json`, and `rest-device-depth1.json` where L30
  recorded one (Nautobot 2 and 3).
- Produces:
  - `type sottest.Request struct{ Method, Path, RawQuery, Host, Authorization, Query string }`.
  - `type sottest.Server struct { Stack, URL, CAFile string; NextHost, NextPath string; GraphQLStatus int; GraphQL200Errors bool; DropFromGraphQL int; Auth string; Status map[int]string; /* unexported */ }`.
  - `func sottest.New(t testing.TB, stack string, devices int) *Server`;
    `func (s *Server) SetDevices(n int)`; `func (s *Server) Requests() []Request`;
    `func (s *Server) Unrecorded() []string` — every identifier a GraphQL query asked for that no
    recorded query of the stack asked for;
    `func sottest.Name(i int) string` — device i's name (`leaf-01`, then `leaf-002`…, as L30 named
    them); `func sottest.Addr(i, which int) string` — device i's address, `which` 5 for Management1
    (the primary) and 6 for Loopback0: `10.<which>.<i/250>.<i%250+1>`. The addresses, and each clone's
    `id`, are synthesized for the tests: L30's seed gave `leaf-002`… no address, interface, custom
    field or tag (`tests/lab/cmd/sot-record/seed.go`).
  - `Server.DeleteAfterPage int` (pre-flight I1).

The connector's tests (Tasks 5–8) and the service's (Tasks 9, 12) talk to this instead of a live
product. Every shape it serves is a recorded one, with the per-device values above synthesized:
leaf-01's GraphQL and REST bodies, the stack's
status, `count`/`next`/`previous`/`results` paging with an absolute `next`, and each stack's
GraphQL paging, refusals included (NetBox 3.7.8: `400` to every paging shape tried; NetBox 4.7.1:
`200` with `errors` to `limit`/`offset`). One shape is not recorded and is marked so: Nautobot's
answer to `pagination:`, which no run asked; it answers as an unknown argument would, `400`.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/sottest/replay_test.go`:

```go
package sottest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func client(t *testing.T, s *Server) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(s.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func get(t *testing.T, c *http.Client, url string, v any) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v != nil {
		json.NewDecoder(resp.Body).Decode(v)
	}
	return resp.StatusCode
}

func post(t *testing.T, c *http.Client, url, query string, v any) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": query})
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, v)
	return resp.StatusCode
}

// The replay serves each stack as L30 recorded it: its release, a REST list
// of n paged to a null next, and its GraphQL list as the stack pages it.
func TestTheReplayIsTheRecordedStack(t *testing.T) {
	for stack, release := range map[string]string{"netbox-3.7": "3.7.8", "netbox-4": "4.7.1",
		"nautobot-1.6": "1.6.32", "nautobot-2": "2.4.43", "nautobot-3": "3.2.6"} {
		s := New(t, stack, 120)
		c := client(t, s)
		product := strings.SplitN(stack, "-", 2)[0]
		var status map[string]any
		if get(t, c, s.URL+"/api/status/", &status) != 200 || status[product+"-version"] != release {
			t.Fatalf("%s: status %v", stack, status[product+"-version"])
		}
		next, n := s.URL+"/api/dcim/devices/?limit=50", 0
		for next != "" {
			var page struct {
				Count   int              `json:"count"`
				Next    *string          `json:"next"`
				Results []map[string]any `json:"results"`
			}
			get(t, c, next, &page)
			n += len(page.Results)
			next = ""
			if page.Next != nil {
				next = *page.Next
			}
		}
		if n != 120 {
			t.Fatalf("%s: REST gave %d", stack, n)
		}
		list, gql := "devices", s.URL+"/api/graphql/"
		if product == "netbox" {
			list, gql = "device_list", s.URL+"/graphql/"
		}
		var r struct {
			Data   map[string][]map[string]any `json:"data"`
			Errors []any                       `json:"errors"`
		}
		if code := post(t, c, gql, "{ "+list+" { name } }", &r); code != 200 || len(r.Data[list]) != 120 {
			t.Fatalf("%s: unpaged GraphQL %d, %d devices", stack, code, len(r.Data[list]))
		}
		if r.Data[list][50]["name"] != Name(51) || Name(51) != "leaf-051" || Name(1) != "leaf-01" {
			t.Fatalf("%s: names", stack)
		}
	}
}

// L30: NetBox 4.7.1 answers limit/offset with HTTP 200 and an errors list,
// and NetBox 3.7.8 every paging shape with 400.
func TestTheReplayRefusesAsTheStackRefused(t *testing.T) {
	var r struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	s4 := New(t, "netbox-4", 3)
	if code := post(t, client(t, s4), s4.URL+"/graphql/", "{ device_list(limit: 50, offset: 0) { name } }", &r); code != 200 ||
		len(r.Errors) != 2 || !strings.Contains(r.Errors[0].Message, "Unknown argument 'limit'") {
		t.Fatalf("netbox-4: %d %+v", code, r)
	}
	s37 := New(t, "netbox-3.7", 3)
	if code := post(t, client(t, s37), s37.URL+"/graphql/", "{ device_list(pagination: {offset: 0, limit: 50}) { name } }",
		&r); code != 400 {
		t.Fatalf("netbox-3.7: %d", code)
	}
}

// What a query asked for that no recorded query did is kept, so a test can
// say the connector asked only for recorded fields.
func TestAnUnrecordedFieldIsNoted(t *testing.T) {
	s := New(t, "nautobot-2", 1)
	var r map[string]any
	post(t, client(t, s), s.URL+"/api/graphql/", "{ devices(limit: 50, offset: 0) { name primary_ip6 { address } role { name } } }", &r)
	if got := strings.Join(s.Unrecorded(), ","); got != "primary_ip6" {
		t.Fatalf("unrecorded: %q", got)
	}
}

func TestAuthIsRequiredWhenSet(t *testing.T) {
	s := New(t, "netbox-4", 1)
	s.Auth = "Token right"
	if code := get(t, client(t, s), s.URL+"/api/status/", nil); code != 401 {
		t.Fatalf("%d", code)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/sottest/ -count=1`
  Expected: FAIL (undefined: `New`, `Name`, …).

- [ ] **Step 3: Implement.** Create `internal/sot/sottest/replay.go`:

```go
package sottest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Request is one request a Server took.
type Request struct {
	Method, Path, RawQuery, Host, Authorization string
	// Query is a GraphQL request's query.
	Query string
}

// Server replays one stack L30 recorded (tests/lab/sot/l30/<stack>/): its
// /api/status/, and n devices shaped as its recorded leaf-01 over GraphQL and
// over REST, paged as the stack paged, each with addresses of its own
// (Addr). Set the knobs before the first request.
type Server struct {
	Stack, URL, CAFile string

	// NextHost is the host every REST next names; "" is the request's own.
	NextHost string
	// NextPath is a path every next names in place of the device list's.
	NextPath string
	// GraphQLStatus, nonzero, is the only answer GraphQL gives.
	GraphQLStatus int
	// GraphQL200Errors makes GraphQL answer HTTP 200 and an errors list, as
	// NetBox 4.7.1 answers an unknown argument (L30).
	GraphQL200Errors bool
	// DropFromGraphQL is how many devices, from the end, GraphQL leaves out.
	DropFromGraphQL int
	// Auth, set, is the one Authorization taken; any other is 401.
	Auth string
	// Status is device i's status, lower case; absent or empty is "active".
	Status map[int]string
	// DeleteAfterPage, nonzero, deletes the list's first device once that
	// many list pages (GraphQL, or REST with a limit other than 1) have been
	// served, so every later page shifts left by one, as offset paging does
	// under a concurrent delete (pre-flight I1).
	DeleteAfterPage int

	product, list, gqlPath string
	status                 map[string]any
	gqlDev                 map[string]any
	restDev, restShallow   map[string]any
	recorded               map[string]bool

	mu         sync.Mutex
	n          int
	deleted    int // devices deleted from the list's head: position j is device j+deleted
	pages      int
	log        []Request
	unrecorded map[string]bool
}

// fixtures is tests/lab/sot/l30, found from this file.
func fixtures() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "lab", "sot", "l30")
}

// ident is a GraphQL identifier.
var ident = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// New replays stack with n devices.
func New(t testing.TB, stack string, n int) *Server {
	t.Helper()
	dir := filepath.Join(fixtures(), stack)
	s := &Server{Stack: stack, product: strings.SplitN(stack, "-", 2)[0], n: n, recorded: map[string]bool{},
		unrecorded: map[string]bool{}, list: "device_list", gqlPath: "/graphql/"}
	if s.product == "nautobot" {
		s.list, s.gqlPath = "devices", "/api/graphql/"
	}
	var status struct {
		Body map[string]any `json:"body"`
	}
	read(t, filepath.Join(dir, "status.json"), &status)
	s.status = status.Body
	// leaf-01 as the stack's GraphQL answered it: the recorded query that
	// returned it, and every identifier that query and the recorded lists
	// asked for.
	var steps []struct {
		Request struct {
			Query string `json:"query"`
		} `json:"request"`
		Status int `json:"status"`
		Body   struct {
			Data map[string][]map[string]any `json:"data"`
		} `json:"body"`
	}
	read(t, filepath.Join(dir, "graphql.json"), &steps)
	for _, st := range steps {
		if st.Status == http.StatusOK && len(st.Body.Data[s.list]) == 1 {
			s.gqlDev = st.Body.Data[s.list][0]
			s.note(st.Request.Query)
		}
	}
	if s.gqlDev == nil {
		t.Fatalf("sottest: %s: no recorded GraphQL query returned leaf-01", stack)
	}
	var lists []struct {
		Query  string `json:"query"`
		Status int    `json:"status"`
		Errors any    `json:"errors"`
	}
	read(t, filepath.Join(dir, "graphql-list.json"), &lists)
	for _, l := range lists {
		if l.Status == http.StatusOK && l.Errors == nil {
			s.note(l.Query)
		}
	}
	s.restShallow = firstResult(t, filepath.Join(dir, "rest-device.json"))
	s.restDev = s.restShallow
	if p := filepath.Join(dir, "rest-device-depth1.json"); exists(p) {
		s.restDev = firstResult(t, p)
	}
	srv, ca := TLS(t, http.HandlerFunc(s.serve))
	s.URL, s.CAFile = srv.URL, ca
	return s
}

func (s *Server) note(query string) {
	for _, tok := range ident.FindAllString(query, -1) {
		s.recorded[tok] = true
	}
}

func read(t testing.TB, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("sottest: %s: %v", path, err)
	}
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// firstResult is results[0] of a recorded REST read, a call or a list of them.
func firstResult(t testing.TB, path string) map[string]any {
	t.Helper()
	type call struct {
		Body struct {
			Results []map[string]any `json:"results"`
		} `json:"body"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var one call
	if json.Unmarshal(raw, &one) == nil && len(one.Body.Results) > 0 {
		return one.Body.Results[0]
	}
	var many []call
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 && len(many[0].Body.Results) > 0 {
		return many[0].Body.Results[0]
	}
	t.Fatalf("sottest: %s holds no recorded device", path)
	return nil
}

// Name is device i's name, as L30 seeded them: leaf-01, then leaf-002...
func Name(i int) string {
	if i == 1 {
		return "leaf-01"
	}
	return fmt.Sprintf("leaf-%03d", i)
}

// Addr is device i's address on Management1 (which 5, the primary) or
// Loopback0 (which 6), with its prefix length, as the products write one.
func Addr(i, which int) string { return fmt.Sprintf("10.%d.%d.%d/32", which, i/250, i%250+1) }

func (s *Server) SetDevices(n int) { s.mu.Lock(); s.n = n; s.mu.Unlock() }

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

func (s *Server) Unrecorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.unrecorded))
	for k := range s.unrecorded {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	req := Request{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Host: r.Host,
		Authorization: r.Header.Get("Authorization")}
	var gql struct {
		Query string `json:"query"`
	}
	if r.Method == http.MethodPost {
		json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&gql)
		req.Query = gql.Query
	}
	s.mu.Lock()
	s.log = append(s.log, req)
	n, del := s.n, s.deleted
	s.mu.Unlock()
	if s.Auth != "" && req.Authorization != s.Auth {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Invalid token"})
		return
	}
	list := false
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/status/":
		writeJSON(w, http.StatusOK, s.status)
	case r.Method == http.MethodGet && r.URL.Path == "/api/dcim/devices/":
		s.rest(w, r, n, del)
		list = r.URL.Query().Get("limit") != "1"
	case r.Method == http.MethodPost && r.URL.Path == s.gqlPath:
		s.graphql(w, gql.Query, n, del)
		list = true
	default:
		http.NotFound(w, r)
	}
	if list {
		s.mu.Lock()
		if s.pages++; s.DeleteAfterPage > 0 && s.pages == s.DeleteAfterPage {
			s.n, s.deleted = s.n-1, s.deleted+1
		}
		s.mu.Unlock()
	}
}

func (s *Server) rest(w http.ResponseWriter, r *http.Request, n, del int) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	// Nautobot 2.x and 3.x name no related object at default depth (L27,
	// L30): without depth=1 a device is the shallow one.
	base, shallow := s.restDev, q.Get("depth") != "1" && s.product == "nautobot" && s.Stack != "nautobot-1.6"
	if shallow {
		base = s.restShallow
	}
	results := []any{}
	for j := offset + 1; j <= n && j <= offset+limit; j++ {
		results = append(results, s.device(base, j+del, "rest", shallow))
	}
	var next any
	if offset+limit < n {
		host := s.NextHost
		if host == "" {
			host = r.Host
		}
		path := "/api/dcim/devices/"
		if s.NextPath != "" {
			path = s.NextPath
		}
		nq := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset + limit)}}
		if d := q.Get("depth"); d != "" {
			nq.Set("depth", d)
		}
		next = (&url.URL{Scheme: "https", Host: host, Path: path, RawQuery: nq.Encode()}).String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n, "next": next, "previous": nil, "results": results})
}

var (
	nested = regexp.MustCompile(`\(pagination: \{offset: (\d+), limit: (\d+)\}\)`)
	args   = regexp.MustCompile(`\(limit: (\d+), offset: (\d+)\)`)
)

func errorsOf(msgs ...string) map[string]any {
	var errs []any
	for _, m := range msgs {
		errs = append(errs, map[string]any{"message": m})
	}
	return map[string]any{"data": nil, "errors": errs}
}

func (s *Server) graphql(w http.ResponseWriter, query string, n, del int) {
	s.mu.Lock()
	for _, tok := range ident.FindAllString(query, -1) {
		if !s.recorded[tok] {
			s.unrecorded[tok] = true
		}
	}
	s.mu.Unlock()
	switch {
	case s.GraphQLStatus != 0:
		w.WriteHeader(s.GraphQLStatus)
		io.WriteString(w, "<html>not here</html>")
		return
	case s.GraphQL200Errors:
		writeJSON(w, http.StatusOK, errorsOf("Unknown argument 'limit' on field 'Query.device_list'.",
			"Unknown argument 'offset' on field 'Query.device_list'."))
		return
	case !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(query), "{")), s.list):
		writeJSON(w, http.StatusBadRequest, errorsOf("Cannot query field on type 'Query'."))
		return
	}
	offset, limit := 0, n
	if m := nested.FindStringSubmatch(query); m != nil {
		if s.Stack != "netbox-4" {
			// NetBox 3.7.8 (L30); Nautobot was never asked, and answers as an
			// unknown argument would.
			writeJSON(w, http.StatusBadRequest, errorsOf("Unknown argument 'pagination' on field 'Query."+s.list+"'."))
			return
		}
		offset, _ = strconv.Atoi(m[1])
		limit, _ = strconv.Atoi(m[2])
	} else if m := args.FindStringSubmatch(query); m != nil {
		switch s.Stack {
		case "netbox-4":
			writeJSON(w, http.StatusOK, errorsOf("Unknown argument 'limit' on field 'Query.device_list'.",
				"Unknown argument 'offset' on field 'Query.device_list'."))
			return
		case "netbox-3.7":
			writeJSON(w, http.StatusBadRequest, errorsOf("Unknown argument 'limit' on field 'Query.device_list'."))
			return
		}
		limit, _ = strconv.Atoi(m[1])
		offset, _ = strconv.Atoi(m[2])
	}
	devs := []any{}
	for j := offset + 1; j <= n-s.DropFromGraphQL && j <= offset+limit; j++ {
		devs = append(devs, s.device(s.gqlDev, j+del, "graphql", false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{s.list: devs}})
}

// device is device i: base with its name, its addresses and its status in
// the stack's spelling for api (L30), and no primary_ip6, as none was set.
func (s *Server) device(base map[string]any, i int, api string, shallow bool) map[string]any {
	d := clone(base)
	// Its own id and name: the connector refuses a list naming a device twice
	// (pre-flight I1), and every clone of leaf-01 would otherwise share its id.
	d["name"], d["id"] = Name(i), i
	if shallow {
		return d // every related object is {id, object_type, url}
	}
	mgmt, lo := Addr(i, 5), Addr(i, 6)
	if p, ok := d["primary_ip4"].(map[string]any); ok {
		p["address"] = mgmt
		if _, ok := p["host"]; ok {
			p["host"] = strings.TrimSuffix(mgmt, "/32")
		}
	}
	if ifs, ok := d["interfaces"].([]any); ok {
		for _, itf := range ifs {
			im, _ := itf.(map[string]any)
			addr := lo
			if im["name"] == "Management1" {
				addr = mgmt
			}
			ips, _ := im["ip_addresses"].([]any)
			for _, ip := range ips {
				if m, ok := ip.(map[string]any); ok {
					m["address"] = addr
				}
			}
		}
	}
	st := "active"
	if v := s.Status[i]; v != "" {
		st = v
	}
	title := strings.ToUpper(st[:1]) + st[1:]
	switch {
	case api == "graphql" && s.Stack == "netbox-3.7":
		d["status"] = strings.ToUpper(st)
	case api == "graphql" && s.product == "netbox":
		d["status"] = st
	case api == "graphql":
		d["status"] = map[string]any{"name": title}
	case s.product == "netbox" || s.Stack == "nautobot-1.6":
		d["status"] = map[string]any{"value": st, "label": title}
	default:
		if m, ok := d["status"].(map[string]any); ok {
			m["name"] = title
		}
	}
	if api == "graphql" {
		d["primary_ip6"] = nil
	}
	return d
}

func clone(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 4: Run them.** `go test ./internal/sot/sottest/ -count=1`
  Expected: PASS. If a stack's recorded leaf-01 lacks `primary_ip4` or `interfaces` where the tests
  of Tasks 5–8 expect them, read the fixture and fix the replay, not the fixture: the fixtures are
  L30's evidence.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot/sottest
git commit -m "test(sot): replay each stack L30 recorded, with as many devices as a test asks

Status, the recorded leaf-01 over GraphQL and REST, paging and refusals
as each release answered them (L30), and the identifiers no recorded
query asked for, so a connector test can say it asked for recorded
fields only.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: GraphQL: one list query per profile, its errors read first, its length checked

**Files:**
- Create: `internal/sot/graphql.go`
- Test: `internal/sot/graphql_test.go`

**Interfaces:**
- Consumes: `client`, `answer`, `statusError`, `printable`, `maxPages`, `maxDevices` (Task 2);
  `Profile`, `paging`, `field` (Task 3); `sottest.New`, `Server.Requests`, `Server.Unrecorded`,
  `Server.GraphQL200Errors`, `Server.GraphQLStatus` (Task 4).
- Produces:
  - `type selection map[string]selection`; `func (s selection) add(path []string)`;
    `func (s selection) String() string` (keys sorted: `a b { c d }`).
  - `func (p Profile) listQuery(sel selection, offset, limit int) string`.
  - `var errNoGraphQL error` — GraphQL answered 404.
  - `func (c *client) graphqlDevices(ctx context.Context, p Profile, sel selection, pageSize int) ([]map[string]any, error)`.
  - `func (p Profile) graphqlPage(a answer) ([]map[string]any, error)`.
  - `func (c *client) restCount(ctx context.Context) (int, error)` — `count` of
    `GET /api/dcim/devices/?limit=1`.
  - `func distinct(devs []map[string]any, key, api string) error` — a list naming one device twice
    fails (pre-flight I1); Task 6 uses it with `"id"`.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/graphql_test.go`:

```go
package sot

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// replay is a client of a sottest.Server for stack with n devices, and the
// profile the stack's status detects.
func replay(t *testing.T, stack string, n int) (*sottest.Server, *client, Profile) {
	t.Helper()
	s := sottest.New(t, stack, n)
	product := strings.SplitN(stack, "-", 2)[0]
	c, err := newClient(s.URL, s.CAFile, NewSecret(token), product)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := c.getJSON(context.Background(), c.at("/api/status/", nil), &status); err != nil {
		t.Fatal(err)
	}
	v, err := versionOf(status, product)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := Detect(v, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, c, p
}

// basic is what every read asks for: name, status, the primary addresses.
func basic(p Profile) selection {
	s := selection{}
	s.add([]string{"name"})
	s.add(p.status.graphql)
	s.add([]string{"primary_ip4", "address"})
	s.add([]string{"primary_ip6", "address"})
	return s
}

func TestASelectionIsSortedAndNested(t *testing.T) {
	s := selection{}
	s.add([]string{"status"})
	s.add([]string{"platform", "slug"})
	s.add([]string{"name"})
	s.add([]string{"platform", "network_driver"})
	if got := s.String(); got != "name platform { network_driver slug } status" {
		t.Fatalf("%q", got)
	}
}

// L30: each profile pages as its release took it, and the query is the
// recorded shape: NetBox 4.7.1 pagination: {offset, limit}, Nautobot
// limit/offset, NetBox 3.7.8 nothing.
func TestEveryStackListsOverGraphQLAsItPages(t *testing.T) {
	for stack, want := range map[string]int{"netbox-3.7": 1, "netbox-4": 3, "nautobot-1.6": 3, "nautobot-2": 3,
		"nautobot-3": 3} {
		s, c, p := replay(t, stack, 120)
		devs, err := c.graphqlDevices(context.Background(), p, basic(p), 50)
		if err != nil || len(devs) != 120 {
			t.Fatalf("%s: %d devices, %v", stack, len(devs), err)
		}
		posts := 0
		for _, r := range s.Requests() {
			if r.Method == http.MethodPost {
				posts++
			}
		}
		if posts != want {
			t.Errorf("%s: %d GraphQL requests, want %d", stack, posts, want)
		}
		// primary_ip6 is L32's to measure: every other identifier was in a
		// recorded query.
		if got := strings.Join(s.Unrecorded(), ","); got != "primary_ip6" {
			t.Errorf("%s: asked for unrecorded %q", stack, got)
		}
	}
}

// L30: NetBox 4.7.1 refuses with HTTP 200 and an errors list. A reader of
// the status alone takes it for an empty inventory; the errors come first.
func TestErrorsAreReadBeforeDataEvenOnA200(t *testing.T) {
	s, c, p := replay(t, "netbox-4", 3)
	s.GraphQL200Errors = true
	_, err := c.graphqlDevices(context.Background(), p, basic(p), 50)
	if err == nil || !strings.Contains(err.Error(), "GraphQL answered HTTP 200 with 2 error(s); the first: "+
		"Unknown argument 'limit' on field 'Query.device_list'.") {
		t.Fatalf("got %v", err)
	}
}

func TestAGraphQL404IsErrNoGraphQL(t *testing.T) {
	s, c, p := replay(t, "nautobot-2", 3)
	s.GraphQLStatus = http.StatusNotFound
	if _, err := c.graphqlDevices(context.Background(), p, basic(p), 50); err != errNoGraphQL {
		t.Fatalf("got %v", err)
	}
	s.GraphQLStatus = http.StatusForbidden
	if _, err := c.graphqlDevices(context.Background(), p, basic(p), 50); err == nil ||
		!strings.Contains(err.Error(), "answered HTTP 403") {
		t.Fatalf("got %v", err)
	}
}

func TestAnErrorMessageIsPrintedSafely(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": null, "errors": [{"message": "bad\u001b[2J` + strings.Repeat("x", 400) + `"}]}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	_, err := c.graphqlDevices(context.Background(), profiles[NetBox4], basic(profiles[NetBox4]), 50)
	if err == nil || strings.Contains(err.Error(), "\x1b") || len(err.Error()) > 400 {
		t.Fatalf("got %q", err)
	}
}

// Pre-flight M4: a release that ignores the page size returns the whole
// list every page; the first long page fails the read.
func TestAPageLongerThanThePageSizeFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": {"devices": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "nautobot")
	if _, err := c.graphqlDevices(context.Background(), profiles[Nautobot2], basic(profiles[Nautobot2]), 2); err == nil ||
		!strings.Contains(err.Error(), "ignored the page size") {
		t.Fatalf("got %v", err)
	}
}

// Pre-flight I1: a list naming one device twice is refused; a device with
// no name is not counted against another.
func TestAListNamingADeviceTwiceFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": {"device_list": [{"name": "a"}, {"name": null}, {"name": null}, {"name": "a"}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, err := c.graphqlDevices(context.Background(), profiles[NetBox37], basic(profiles[NetBox37]), 50); err == nil ||
		!strings.Contains(err.Error(), "GraphQL gave one device twice (name a)") {
		t.Fatalf("got %v", err)
	}
}

func TestRestCountIsTheListsCount(t *testing.T) {
	_, c, _ := replay(t, "nautobot-3", 120)
	if n, err := c.restCount(context.Background()); err != nil || n != 120 {
		t.Fatalf("%d %v", n, err)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/ -run 'Selection|GraphQL|Errors|ErrorMessage|RestCount|Longer|Twice' -count=1`
  Expected: FAIL (undefined: `selection`, `graphqlDevices`, …).

- [ ] **Step 3: Implement.** Create `internal/sot/graphql.go`:

```go
package sot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// errNoGraphQL is a GraphQL endpoint that answered 404: GraphQL is turned
// off, or the release has none. Source.Fetch falls back to REST on it when
// the source's api is auto.
var errNoGraphQL = errors.New("GraphQL answered HTTP 404")

// selection is a GraphQL selection set, built from field paths.
type selection map[string]selection

func (s selection) add(path []string) {
	for _, k := range path {
		next, ok := s[k]
		if !ok {
			next = selection{}
			s[k] = next
		}
		s = next
	}
}

// String is the set with its keys sorted, so a query is the same text for
// the same fields: "a b { c d }".
func (s selection) String() string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k
		if len(s[k]) > 0 {
			parts[i] = k + " { " + s[k].String() + " }"
		}
	}
	return strings.Join(parts, " ")
}

// listQuery is the device list query on p, in the argument spelling and
// order L30 recorded: NetBox 4.7.1 `pagination: {offset, limit}`, Nautobot
// `limit`, `offset`, NetBox 3.7.8 none.
func (p Profile) listQuery(sel selection, offset, limit int) string {
	args := ""
	switch p.paging {
	case pageNested:
		args = fmt.Sprintf("(pagination: {offset: %d, limit: %d})", offset, limit)
	case pageArgs:
		args = fmt.Sprintf("(limit: %d, offset: %d)", limit, offset)
	}
	return fmt.Sprintf("{ %s%s { %s } }", p.list, args, sel)
}

// graphqlDevices is every device over GraphQL, page by page where p pages,
// to a short page. A page longer than pageSize (a release that ignored the
// paging arguments, pre-flight M4), a list past maxFetch bytes (M3), and a
// list naming a device twice (a page boundary shifted under a concurrent
// insert, I1) fail it. The caller checks the count (Source.graphql).
func (c *client) graphqlDevices(ctx context.Context, p Profile, sel selection, pageSize int) ([]map[string]any, error) {
	u := c.at(p.graphqlPath, nil)
	b := newBudget()
	var out []map[string]any
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("GraphQL gave more than %d pages", maxPages)
		}
		body, err := json.Marshal(map[string]string{"query": p.listQuery(sel, len(out), pageSize)})
		if err != nil {
			return nil, err
		}
		a, err := c.do(ctx, http.MethodPost, u, body, true)
		if err != nil {
			return nil, err
		}
		if err := b.spend(len(a.body)); err != nil {
			return nil, err
		}
		devs, err := p.graphqlPage(a)
		if err != nil {
			return nil, err
		}
		if p.paging != pageNone && len(devs) > pageSize {
			return nil, fmt.Errorf("GraphQL page %d gave %d devices for a page of %d: the release ignored the page "+
				"size, so its paging cannot be trusted", page, len(devs), pageSize)
		}
		out = append(out, devs...)
		if len(out) > maxDevices {
			return nil, fmt.Errorf("GraphQL gave more than %d devices", maxDevices)
		}
		if p.paging == pageNone || len(devs) < pageSize {
			return out, distinct(out, "name", "GraphQL")
		}
	}
}

// distinct refuses a list that holds one device twice, by key ("id" over
// REST, "name" over GraphQL, which is not asked for an id: L27 and L30
// recorded none in a query). Offset paging across a concurrent change
// repeats or skips the device at a page boundary (pre-flight I1); a repeat
// fails here, naming the cause, rather than at admission's "two devices are
// both named". An empty key is skipped: NetBox allows a device no name.
func distinct(devs []map[string]any, key, api string) error {
	seen := map[string]bool{}
	for _, d := range devs {
		k := ""
		switch v := d[key].(type) {
		case string:
			k = v
		case json.Number:
			k = v.String()
		}
		if k == "" {
			continue
		}
		if seen[k] {
			return fmt.Errorf("%s gave one device twice (%s %s): the list changed between pages; the next sync "+
				"reads it again", api, key, printable(k))
		}
		seen[k] = true
	}
	return nil
}

// graphqlPage reads one answer: its errors before its data, whatever the
// HTTP status, since NetBox 4.7.1 refuses an argument with HTTP 200 and an
// errors list (L30). An error message is the source's text: printed safely,
// and only the first.
func (p Profile) graphqlPage(a answer) ([]map[string]any, error) {
	var r struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	dec := json.NewDecoder(bytes.NewReader(a.body))
	dec.UseNumber()
	derr := dec.Decode(&r)
	if derr == nil && len(r.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL answered HTTP %d with %d error(s); the first: %s", a.status, len(r.Errors),
			printable(r.Errors[0].Message))
	}
	switch {
	case a.status == http.StatusNotFound:
		return nil, errNoGraphQL
	case a.status != http.StatusOK:
		return nil, statusError("POST "+p.graphqlPath, a.status)
	case derr != nil:
		return nil, errors.New("GraphQL answered something that is not JSON")
	}
	raw, ok := r.Data[p.list]
	if !ok {
		return nil, fmt.Errorf("GraphQL's data has no %s", p.list)
	}
	var devs []map[string]any
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&devs); err != nil {
		return nil, fmt.Errorf("GraphQL's %s is not a list of devices", p.list)
	}
	return devs, nil
}

// restCount is the device count REST gives: GET /api/dcim/devices/?limit=1,
// its count (L27, L30: count/next/previous/results on every release).
func (c *client) restCount(ctx context.Context) (int, error) {
	var page struct {
		Count *int `json:"count"`
	}
	if err := c.getJSON(ctx, c.at("/api/dcim/devices/", url.Values{"limit": {"1"}}), &page); err != nil {
		return 0, err
	}
	if page.Count == nil || *page.Count < 0 {
		return 0, errors.New("GET /api/dcim/devices/ gives no count")
	}
	return *page.Count, nil
}
```

- [ ] **Step 4: Run them.** `go test ./internal/sot/... -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): the GraphQL device list, paged per profile, its errors read first

L30: NetBox 4.7.1 pages by pagination: {offset, limit} and refuses an
unknown argument with HTTP 200 and an errors list; Nautobot pages by
limit/offset; NetBox 3.7.8 by nothing. errors are read before data
whatever the status, and printed safely. restCount gives REST's count,
for the check Source makes (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: REST: `next` followed on the base, rebuilt on it otherwise, never followed elsewhere

**Files:**
- Create: `internal/sot/rest.go`
- Test: `internal/sot/rest_test.go`

**Interfaces:**
- Consumes: `client`, `do`, `statusError`, `what`, `newBudget`, `printable`, `maxPages`, `maxDevices`
  (Task 2); `Profile.depthOne` (Task 3); `sottest.Server.NextHost`, `NextPath`, `Requests` (Task 4);
  `distinct` and `replay` (Task 5).
- Produces:
  - `func (c *client) restDevices(ctx context.Context, p Profile, pageSize int) ([]map[string]any, bool, error)`
    — every device, and whether some `next` was rebuilt.
  - `func (c *client) follow(next string) (*url.URL, bool, error)`.
  - `func portOf(u *url.URL) string`.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/rest_test.go`:

```go
package sot

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// L30: next is absolute and followed to null returns every device once, on
// every release; Nautobot 2.x and 3.x are read at ?depth=1.
func TestEveryStackListsOverRESTToANullNext(t *testing.T) {
	for _, stack := range []string{"netbox-3.7", "netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		s, c, p := replay(t, stack, 120)
		devs, rebuilt, err := c.restDevices(context.Background(), p, 50)
		if err != nil || len(devs) != 120 || rebuilt {
			t.Fatalf("%s: %d devices, rebuilt %v, %v", stack, len(devs), rebuilt, err)
		}
		if devs[119]["name"] != sottest.Name(120) {
			t.Fatalf("%s: last %v", stack, devs[119]["name"])
		}
		for _, r := range s.Requests() {
			if r.Path == "/api/dcim/devices/" && p.depthOne != strings.Contains(r.RawQuery, "depth=1") {
				t.Fatalf("%s: %s?%s", stack, r.Path, r.RawQuery)
			}
		}
	}
}

// L30: behind a proxy, next names the proxy's host and X-Forwarded-Proto's
// scheme. A next on another origin is rebuilt on the base, so every request
// still goes to the base, and the token with it.
func TestANextOnAnotherOriginIsRebuiltOnTheBase(t *testing.T) {
	s, c, p := replay(t, "netbox-4", 120)
	s.NextHost = "netbox.attacker.example:443"
	devs, rebuilt, err := c.restDevices(context.Background(), p, 50)
	if err != nil || len(devs) != 120 || !rebuilt {
		t.Fatalf("%d devices, rebuilt %v, %v", len(devs), rebuilt, err)
	}
	base, _ := url.Parse(s.URL)
	for _, r := range s.Requests() {
		if r.Host != base.Host {
			t.Fatalf("a request went to %s", r.Host)
		}
	}
}

func TestANextOnAnotherPathIsNotFollowed(t *testing.T) {
	s, c, p := replay(t, "nautobot-2", 120)
	s.NextPath = "/api/users/tokens/"
	if _, _, err := c.restDevices(context.Background(), p, 50); err == nil ||
		!strings.Contains(err.Error(), "names another path than the device list under url") {
		t.Fatalf("got %v", err)
	}
	for _, r := range s.Requests() {
		if r.Path == "/api/users/tokens/" {
			t.Fatal("followed it")
		}
	}
}

// Decision 31: a total that differs from count fails the read; nothing is
// returned that would look like devices removed.
func TestARESTListShortOfItsCountFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count": 120, "next": null, "previous": null, "results": [{"name": "leaf-01"}]}`)
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 50); err == nil ||
		!strings.Contains(err.Error(), "REST gave 1 devices and counts 120") {
		t.Fatalf("got %v", err)
	}
}

// Pre-flight I1: an insert between pages shifts the list right and repeats
// a device; it is refused by id.
func TestARESTListRepeatingADeviceFails(t *testing.T) {
	var self string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "" {
			fmt.Fprintf(w, `{"count": 2, "next": %q, "previous": null, "results": [{"id": 7, "name": "a"}]}`, self)
			return
		}
		fmt.Fprint(w, `{"count": 2, "next": null, "previous": null, "results": [{"id": 7, "name": "a"}]}`)
	}))
	self = srv.URL + "/api/dcim/devices/?limit=1&offset=1"
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if devs, _, err := c.restDevices(context.Background(), profiles[NetBox4], 1); err == nil || devs != nil ||
		!strings.Contains(err.Error(), "REST gave one device twice (id 7)") {
		t.Fatalf("%v %v", devs, err)
	}
}

func TestANextThatLoopsIsRefused(t *testing.T) {
	var self string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"count": 120, "next": %q, "previous": null, "results": [{"name": "leaf-01"}]}`, self)
	}))
	self = srv.URL + "/api/dcim/devices/?limit=50&offset=50"
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 50); err == nil ||
		!strings.Contains(err.Error(), "names a page already read") {
		t.Fatalf("got %v", err)
	}
}

func TestFollow(t *testing.T) {
	c := &client{base: &url.URL{Scheme: "https", Host: "nb.example.com", Path: "/netbox"}}
	for next, want := range map[string]string{
		"https://nb.example.com/netbox/api/dcim/devices/?limit=50&offset=50":     "followed",
		"https://NB.example.com:443/netbox/api/dcim/devices/?offset=50":          "followed",
		"http://nb.example.com/netbox/api/dcim/devices/?offset=50":               "rebuilt",
		"https://proxy.internal:8443/netbox/api/dcim/devices/?offset=50":         "rebuilt",
		"https://nb.example.com/api/dcim/devices/?offset=50":                     "another path",
		"https://user:pw@nb.example.com/netbox/api/dcim/devices/?offset=50":      "not an absolute URL",
		"/netbox/api/dcim/devices/?offset=50":                                    "not an absolute URL",
	} {
		u, rebuilt, err := c.follow(next)
		switch {
		case want == "followed" && (err != nil || rebuilt):
			t.Errorf("%s: %v %v", next, rebuilt, err)
		case want == "rebuilt" && (err != nil || !rebuilt || u.Scheme != "https" || u.Host != "nb.example.com" ||
			u.RawQuery != "offset=50"):
			t.Errorf("%s: %v %v %v", next, u, rebuilt, err)
		case want != "followed" && want != "rebuilt" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v", next, err)
		}
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/ -run 'REST|Next|Follow|Repeating' -count=1`
  Expected: FAIL (undefined: `restDevices`, `follow`).

- [ ] **Step 3: Implement.** Create `internal/sot/rest.go`:

```go
package sot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// restDevices is every device over REST, following next to null (L30:
// absolute on every release, and every device once). rebuilt says whether
// some next named another origin and was rebuilt on the base, which the
// caller says once. Every page must give the first page's count, the total
// must equal it, and no device may appear twice by id (pre-flight I1): a
// delete between pages shifts the rest left and drops a live device at the
// boundary, and its count moves. The pages' bytes are bounded together by
// maxFetch (M3).
func (c *client) restDevices(ctx context.Context, p Profile, pageSize int) ([]map[string]any, bool, error) {
	q := url.Values{"limit": {strconv.Itoa(pageSize)}}
	if p.depthOne {
		// Nautobot 2.4.43 and 3.2.6 named no related object at default
		// depth (L27, L30).
		q.Set("depth", "1")
	}
	u := c.at("/api/dcim/devices/", q)
	seen := map[string]bool{}
	b := newBudget()
	var devs []map[string]any
	rebuilt, count := false, -1
	for page := 0; u != nil; page++ {
		if page >= maxPages {
			return nil, rebuilt, fmt.Errorf("REST gave more than %d pages", maxPages)
		}
		if seen[u.String()] {
			return nil, rebuilt, fmt.Errorf("REST page %d's next names a page already read", page)
		}
		seen[u.String()] = true
		a, err := c.do(ctx, http.MethodGet, u, nil, false)
		if err != nil {
			return nil, rebuilt, err
		}
		if a.status != http.StatusOK {
			return nil, rebuilt, statusError(what(http.MethodGet, u), a.status)
		}
		if err := b.spend(len(a.body)); err != nil {
			return nil, rebuilt, err
		}
		var body struct {
			Count   *int             `json:"count"`
			Next    *string          `json:"next"`
			Results []map[string]any `json:"results"`
		}
		dec := json.NewDecoder(bytes.NewReader(a.body))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			return nil, rebuilt, fmt.Errorf("REST page %d is not the JSON asked for", page)
		}
		if body.Count == nil {
			return nil, rebuilt, fmt.Errorf("REST page %d gives no count", page)
		}
		if count >= 0 && *body.Count != count {
			return nil, rebuilt, fmt.Errorf("REST page %d counts %d devices and page 0 counted %d: the list changed "+
				"during the sync; the next sync reads it again", page, *body.Count, count)
		}
		count = *body.Count
		devs = append(devs, body.Results...)
		if len(devs) > maxDevices {
			return nil, rebuilt, fmt.Errorf("REST gave more than %d devices", maxDevices)
		}
		u = nil
		if body.Next != nil && *body.Next != "" {
			next, r, err := c.follow(*body.Next)
			if err != nil {
				return nil, rebuilt, fmt.Errorf("REST page %d: %w", page, err)
			}
			u, rebuilt = next, rebuilt || r
		}
	}
	if len(devs) != count {
		return nil, rebuilt, fmt.Errorf("REST gave %d devices and counts %d: the list changed during the sync, or "+
			"a page was lost; the next sync reads it again", len(devs), count)
	}
	if err := distinct(devs, "id", "REST"); err != nil {
		return nil, rebuilt, err
	}
	return devs, rebuilt, nil
}

// follow is the URL a page's next names: as it is when its scheme, host
// and port are the base's, and otherwise rebuilt on the base, its path and
// query kept (decision 31). Every product builds next from the host the
// request arrived under (L30), so behind a proxy that rewrites Host it names
// another origin, and following it would send the token there. Its path
// must be the base's device list, so a next cannot steer a read anywhere
// else on the source either.
func (c *client) follow(next string) (*url.URL, bool, error) {
	n, err := url.Parse(next)
	if err != nil || !n.IsAbs() || n.Host == "" || n.Opaque != "" || n.User != nil || n.Fragment != "" {
		return nil, false, errors.New("its next is not an absolute URL; not followed")
	}
	if n.Path != c.base.Path+"/api/dcim/devices/" {
		return nil, false, fmt.Errorf("its next names another path than the device list under url (%s); not "+
			"followed", printable(n.Path))
	}
	if n.Scheme == c.base.Scheme && strings.EqualFold(n.Hostname(), c.base.Hostname()) && portOf(n) == portOf(c.base) {
		return n, false, nil
	}
	r := *c.base
	r.Path, r.RawPath, r.RawQuery = n.Path, "", n.RawQuery
	return &r, true, nil
}

// portOf is u's port, its scheme's when it names none.
func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
```

- [ ] **Step 4: Run them.** `go test ./internal/sot/... -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): the REST device list, next followed on the base and rebuilt otherwise

L30: every release builds next from the host the request arrived under.
A next on the base's origin is followed, one on another is rebuilt on
the base, one naming another path is refused, and a loop or a total
short of count fails the read (decision 31). ?depth=1 on Nautobot 2.x
and 3.x (L27, L30).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: The mapping: a filter, an attribute map, an address rule, and the platform alias table

**Files:**
- Create: `internal/sot/device.go`, `internal/sot/alias.go`
- Test: `internal/sot/device_test.go`

**Interfaces:**
- Consumes: `Profile`, `field.over`, `profiles` (Task 3); `selection` (Task 5); `printable` (Task 2);
  `admission.Device`, `admission.TransportTCP`; `bundle.NameOK`.
- Produces:
  - `type sot.Mapping struct { Map map[string]string; Filter Filter; Addresses Addresses; Aliases map[string]string }`.
  - `type sot.Filter struct { Status []string; Tags []string; HasPrimaryIP bool }`.
  - `type sot.Addresses struct { Primary bool; Interfaces []string; AllInterfaces bool }`.
  - `func (m Mapping) mapOf(p Profile) map[string]string`; `func (m Mapping) needsInterfaces() bool`;
    `func (m Mapping) check(p Profile, api string) error`; `func (m Mapping) selection(p Profile) selection`;
    `func (m Mapping) device(p Profile, api string, raw map[string]any) (admission.Device, bool, []string)`
    — the device, whether the filter keeps it, and the notes the caller says once each;
    `func sourceable(a netip.Addr) bool` (pre-flight M13).
  - `func platformName(slug string, overrides map[string]string) string`; `var builtinAliases map[string]string`;
    `var sot.PlatformNameShape *regexp.Regexp` (`^[a-z][a-z0-9_]*$`, the policy's platform name shape),
    for the config loader.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/device_test.go`:

```go
package sot

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The recorded leaf-01 of each profile (tests/lab/sot/l30/<stack>/graphql.json
// and rest-device.json), with status in the release's spelling (L30) and
// primary_ip6 null.
const (
	netbox37GraphQL = `{"name": "leaf-01", "status": "ACTIVE", "platform": {"slug": "eos"}, "site": {"slug": "dc1"},
		"role": {"slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"slug": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
	netbox4GraphQL = `{"name": "leaf-01", "status": "active", "platform": {"slug": "eos"}, "site": {"slug": "dc1"},
		"role": {"slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"slug": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
	nautobot16REST = `{"name": "leaf-01", "status": {"value": "active", "label": "Active"},
		"platform": {"name": "eos", "slug": "eos"}, "site": {"name": "dc1", "slug": "dc1"},
		"device_role": {"name": "leaf", "slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"name": "port49", "slug": "port49"}]}`
	nautobot2GraphQL = `{"name": "leaf-01", "status": {"name": "Active"},
		"platform": {"name": "eos", "network_driver": "arista_eos"}, "location": {"name": "dc1"}, "role": {"name": "leaf"},
		"primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null, "_custom_field_data": {"os_version": "4.31.2F"},
		"tags": [{"name": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
)

func raw(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// active is the default filter Load gives a source (Task 9).
var active = Filter{Status: []string{"active"}}

func addrs(d []netip.Addr) string {
	out := make([]string, len(d))
	for i, a := range d {
		out[i] = a.String()
	}
	return strings.Join(out, ",")
}

// Decision 31: each profile's default map reads its release's recorded
// fields, and a platform slug becomes port49's name.
func TestTheDefaultMapReadsEachProfile(t *testing.T) {
	for _, c := range []struct {
		profile, api, body string
	}{
		{NetBox37, "graphql", netbox37GraphQL},
		{NetBox4, "graphql", netbox4GraphQL},
		{Nautobot2, "graphql", nautobot2GraphQL},
	} {
		m := Mapping{Filter: active, Addresses: Addresses{Primary: true}}
		p := profiles[c.profile]
		if err := m.check(p, c.api); err != nil {
			t.Fatal(err)
		}
		d, keep, notes := m.device(p, c.api, raw(t, c.body))
		if !keep || len(notes) != 0 || d.Name != "leaf-01" || d.Platform != "arista_eos" ||
			d.Attributes["site"] != "dc1" || d.Attributes["role"] != "leaf" || addrs(d.Addresses) != "10.0.1.5" ||
			d.Transport != "tcp" || d.KeyRef != "" {
			t.Errorf("%s: %+v keep=%v %v", c.profile, d, keep, notes)
		}
	}
}

// L27: Nautobot 1.6 gives network_driver over GraphQL only, so its default
// map does not read over REST; a map that names platform.slug does.
func TestAPathAProfileDoesNotGiveIsRefused(t *testing.T) {
	if err := (Mapping{}).check(profiles[Nautobot16], "rest"); err == nil ||
		!strings.Contains(err.Error(), "map.platform: platform.network_driver is not read over REST on profile nautobot_1_6") {
		t.Fatalf("got %v", err)
	}
	m := Mapping{Map: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"},
		Filter: active, Addresses: Addresses{Primary: true}}
	if err := m.check(profiles[Nautobot16], "rest"); err != nil {
		t.Fatal(err)
	}
	d, keep, _ := m.device(profiles[Nautobot16], "rest", raw(t, nautobot16REST))
	if !keep || d.Platform != "arista_eos" || d.Attributes["role"] != "leaf" || d.Attributes["site"] != "dc1" {
		t.Fatalf("%+v", d)
	}
	if err := (Mapping{Map: map[string]string{"platform": "platform.slug", "site": "location.name"}}).check(
		profiles[NetBox4], "graphql"); err == nil ||
		!strings.Contains(err.Error(), "map.site: location.name is not read on profile netbox_4; it reads "+
			"platform.slug, role.slug, site.slug") {
		t.Fatalf("got %v", err)
	}
	if err := (Mapping{Addresses: Addresses{AllInterfaces: true}}).check(profiles[NetBox4], "rest"); err == nil ||
		!strings.Contains(err.Error(), "REST does not give") {
		t.Fatalf("got %v", err)
	}
}

// Decision 31: status is compared in lower case, so every recorded spelling
// matches; a decommissioned device is not admitted by default.
func TestTheStatusFilterKeepsActiveByDefault(t *testing.T) {
	m := Mapping{Filter: active, Addresses: Addresses{Primary: true}}
	for _, body := range []string{netbox37GraphQL, netbox4GraphQL, nautobot2GraphQL} {
		planned := strings.NewReplacer(`"ACTIVE"`, `"PLANNED"`, `"active"`, `"planned"`, `"Active"`, `"Planned"`).Replace(body)
		for _, p := range []Profile{profiles[NetBox37], profiles[NetBox4], profiles[Nautobot2]} {
			if _, keep, _ := m.device(p, "graphql", raw(t, planned)); keep {
				t.Fatalf("%s kept a planned device", p.Name)
			}
		}
	}
	if _, keep, _ := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql",
		raw(t, strings.Replace(netbox4GraphQL, `"active"`, `"planned"`, 1))); !keep {
		t.Fatal("an empty status filter keeps every status")
	}
}

func TestTagsAndHasPrimaryIPFilter(t *testing.T) {
	p := profiles[Nautobot2]
	m := Mapping{Filter: Filter{Tags: []string{"port49"}, HasPrimaryIP: true}, Addresses: Addresses{Primary: true}}
	if _, keep, _ := m.device(p, "graphql", raw(t, nautobot2GraphQL)); !keep {
		t.Fatal("tagged and addressed")
	}
	m.Filter.Tags = []string{"port49", "core"}
	if _, keep, _ := m.device(p, "graphql", raw(t, nautobot2GraphQL)); keep {
		t.Fatal("every tag named is required")
	}
	m.Filter.Tags = nil
	noIP := strings.Replace(nautobot2GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`, `"primary_ip4": null`, 1)
	if _, keep, _ := m.device(p, "graphql", raw(t, noIP)); keep {
		t.Fatal("has_primary_ip")
	}
}

// Decision 31: interface addresses only when named, deduplicated, sorted.
func TestInterfacesAreReadOnlyWhenNamed(t *testing.T) {
	p := profiles[NetBox4]
	for _, c := range []struct {
		a    Addresses
		want string
	}{
		{Addresses{Primary: true}, "10.0.1.5"},
		{Addresses{Primary: true, Interfaces: []string{"Loopback0"}}, "10.0.1.5,10.0.1.6"},
		{Addresses{Interfaces: []string{"Loopback0"}}, "10.0.1.6"},
		{Addresses{Primary: true, AllInterfaces: true}, "10.0.1.5,10.0.1.6"},
	} {
		d, _, _ := (Mapping{Addresses: c.a}).device(p, "graphql", raw(t, netbox4GraphQL))
		if addrs(d.Addresses) != c.want {
			t.Errorf("%+v: %s", c.a, addrs(d.Addresses))
		}
	}
	sel := (Mapping{Addresses: Addresses{Interfaces: []string{"Loopback0"}}}).selection(p).String()
	if !strings.Contains(sel, "interfaces { ip_addresses { address } name }") {
		t.Fatalf("%s", sel)
	}
	if sel := (Mapping{}).selection(p).String(); strings.Contains(sel, "interfaces") || strings.Contains(sel, "tags") {
		t.Fatalf("asked for what nothing reads: %s", sel)
	}
}

// Decision 31: a custom field that is a string, number or boolean is an
// attribute; one that is null is left unset; one that is an object is left
// unset and said; status may be mapped, in lower case.
func TestCustomFieldsAndStatusMapToAttributes(t *testing.T) {
	p := profiles[NetBox4]
	m := Mapping{Map: map[string]string{"platform": "platform.slug", "os_version": "custom_fields.os_version",
		"rack_units": "custom_fields.units", "managed": "custom_fields.managed", "owner": "custom_fields.owner",
		"lifecycle": "status"}}
	body := strings.Replace(netbox4GraphQL, `{"os_version": "4.31.2F"}`,
		`{"os_version": "4.31.2F", "units": 2, "managed": true, "owner": {"id": 7}, "absent": null}`, 1)
	d, _, notes := m.device(p, "graphql", raw(t, body))
	if d.Attributes["os_version"] != "4.31.2F" || d.Attributes["rack_units"] != "2" || d.Attributes["managed"] != "true" ||
		d.Attributes["lifecycle"] != "active" {
		t.Fatalf("%+v", d.Attributes)
	}
	if _, set := d.Attributes["owner"]; set || len(notes) != 1 ||
		!strings.Contains(notes[0], "custom field owner is not a string, number or boolean; attribute owner is left unset") {
		t.Fatalf("%+v %v", d.Attributes, notes)
	}
	if got := m.selection(p).String(); got != "custom_fields name platform { slug } primary_ip4 { address } "+
		"primary_ip6 { address } status" {
		t.Fatalf("%q", got)
	}
}

// Pre-flight M13: an interface's loopback or link-local address is left
// out, said once as a note; the primary is kept whatever it is.
func TestAnInterfaceAddressThatCannotSourceTACACSIsLeftOut(t *testing.T) {
	body := strings.Replace(netbox4GraphQL, `{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]}`,
		`{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}, {"address": "127.0.0.1/8"}, `+
			`{"address": "fe80::1/64"}]}`, 1)
	d, _, notes := (Mapping{Addresses: Addresses{Primary: true, AllInterfaces: true}}).device(profiles[NetBox4],
		"graphql", raw(t, body))
	if addrs(d.Addresses) != "10.0.1.5,10.0.1.6" || len(notes) != 1 ||
		!strings.Contains(notes[0], "cannot source TACACS+") {
		t.Fatalf("%s %v", addrs(d.Addresses), notes)
	}
}

func TestAnAddressThatDoesNotParseIsSaidAndLeftOut(t *testing.T) {
	body := strings.Replace(netbox4GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`, `"primary_ip4": {"address": "ten"}`, 1)
	d, keep, notes := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql", raw(t, body))
	if !keep || len(d.Addresses) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "device leaf-01: primary_ip4 is not an IP address") {
		t.Fatalf("%+v %v", d, notes)
	}
}

// Spec §10: an alias table, overrides, and an unrecognized slug kept.
func TestTheAliasTable(t *testing.T) {
	for slug, want := range map[string]string{"eos": "arista_eos", "EOS": "arista_eos", "arista-eos": "arista_eos",
		"arista_eos": "arista_eos", "veos": "arista_eos", "cisco_xe": "cisco_iosxe", "ios-xe": "cisco_iosxe",
		"nx-os": "cisco_nxos", "cisco_nxos": "cisco_nxos", "junos": "juniper_junos", "juniper_junos": "juniper_junos",
		"cisco_ios": "cisco_ios", "eos-lab": "eos-lab"} {
		if got := platformName(slug, nil); got != want {
			t.Errorf("%s: %s", slug, got)
		}
	}
	if got := platformName("eos", map[string]string{"eos": "arista_eos_lab"}); got != "arista_eos_lab" {
		t.Fatalf("override: %s", got)
	}
	names := map[string]bool{}
	for _, v := range builtinAliases {
		names[v] = true
	}
	if !slices.Equal(sortedKeys(names), []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"}) {
		t.Fatalf("the table maps to %v, which are not the four shipped platforms", sortedKeys(names))
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/ -run 'Map|Path|Filter|Interface|Custom|Address|Alias' -count=1`
  Expected: FAIL (undefined: `Mapping`, `platformName`, …).

- [ ] **Step 3: Implement.** Create `internal/sot/alias.go`:

```go
package sot

import (
	"regexp"
	"sort"
	"strings"
)

// PlatformNameShape is a platform name as the policy writes one; an alias
// override maps to one.
var PlatformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// builtinAliases maps the spellings real installations use to port49's
// platform names (spec §10, "Platform slug translation"): spec §10's own,
// the vendors' hyphenated slugs, and the netutils drivers Nautobot reports
// in platform.network_driver (L27: "arista_eos"). Classic IOS (cisco_ios) is
// not IOS-XE and is not here: a slug the table does not know is kept and
// said, never guessed.
var builtinAliases = map[string]string{
	"arista_eos": "arista_eos", "arista-eos": "arista_eos", "eos": "arista_eos", "veos": "arista_eos",
	"ceos": "arista_eos",
	"cisco_iosxe": "cisco_iosxe", "cisco_xe": "cisco_iosxe", "cisco-ios-xe": "cisco_iosxe",
	"cisco_ios_xe": "cisco_iosxe", "ios-xe": "cisco_iosxe", "iosxe": "cisco_iosxe",
	"cisco_nxos": "cisco_nxos", "cisco-nxos": "cisco_nxos", "cisco-nx-os": "cisco_nxos", "cisco_nx_os": "cisco_nxos",
	"nx-os": "cisco_nxos", "nxos": "cisco_nxos",
	"juniper_junos": "juniper_junos", "juniper-junos": "juniper_junos", "junos": "juniper_junos",
}

// platformName is slug as port49 names the platform: a source's override
// first, then the built-in table, compared in lower case; a slug neither
// knows is kept, lower-cased, so the device is served by the generic
// adapter and the syncer says so (spec §8, "Unknown platforms").
func platformName(slug string, overrides map[string]string) string {
	s := strings.ToLower(slug)
	if name, ok := overrides[s]; ok {
		return name
	}
	if name, ok := builtinAliases[s]; ok {
		return name
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

  Create `internal/sot/device.go`:

```go
package sot

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
)

// Mapping is how a source's devices become port49's (decision 31): which
// are kept (Filter), which facts become attributes (Map), which addresses
// each has (Addresses), and how a platform slug becomes a platform name
// (Aliases, over the built-in table).
type Mapping struct {
	// Map is attribute → path; the attribute "platform" is the device's
	// platform. Empty is the profile's default.
	Map       map[string]string
	Filter    Filter
	Addresses Addresses
	// Aliases are the source's platform_aliases, keys in lower case.
	Aliases map[string]string
}

// Filter keeps a device only when every rule set holds.
type Filter struct {
	// Status is the statuses kept, lower case; empty keeps every status.
	Status []string
	// Tags are tags a device must carry, every one.
	Tags         []string
	HasPrimaryIP bool
}

// Addresses is which of a device's addresses admit it.
type Addresses struct {
	Primary       bool
	Interfaces    []string
	AllInterfaces bool
}

func (m Mapping) needsInterfaces() bool { return m.Addresses.AllInterfaces || len(m.Addresses.Interfaces) > 0 }

// mapOf is the map in force on p.
func (m Mapping) mapOf(p Profile) map[string]string {
	if len(m.Map) > 0 {
		return m.Map
	}
	return p.defaultMap
}

// check says what m asks of p that p does not give over api, before
// anything is read: a path the profile does not record, one it gives over
// GraphQL only, or interfaces over REST.
func (m Mapping) check(p Profile, api string) error {
	if api == "rest" && m.needsInterfaces() {
		return fmt.Errorf("addresses names interfaces, which REST does not give in the device list (L27): use api: " +
			"graphql, or addresses: {primary: true}")
	}
	mp := m.mapOf(p)
	for _, attr := range sortedKeys(mp) {
		path := mp[attr]
		if path == "status" || customKey.MatchString(path) {
			continue
		}
		f, ok := p.fields[path]
		if !ok {
			return fmt.Errorf("map.%s: %s is not read on profile %s; it reads %s", attr, path, p.Name,
				strings.Join(p.paths(), ", "))
		}
		if f.over(api) == nil {
			return fmt.Errorf("map.%s: %s is not read over REST on profile %s; read GraphQL, or map another path",
				attr, path, p.Name)
		}
	}
	return nil
}

// selection is what a GraphQL read asks for under m: name, status, the
// primary addresses, and only what the map, the filter and the address rule
// read.
func (m Mapping) selection(p Profile) selection {
	s := selection{}
	s.add([]string{"name"})
	s.add(p.status.graphql)
	s.add([]string{"primary_ip4", "address"})
	s.add([]string{"primary_ip6", "address"})
	if len(m.Filter.Tags) > 0 {
		s.add([]string{"tags", p.tagKey})
	}
	if m.needsInterfaces() {
		s.add([]string{"interfaces", "name"})
		s.add([]string{"interfaces", "ip_addresses", "address"})
	}
	for _, path := range m.mapOf(p) {
		switch {
		case path == "status":
		case customKey.MatchString(path):
			s.add(p.customFields.graphql)
		default:
			s.add(p.fields[path].graphql)
		}
	}
	return s
}

// device is one source device as port49's, and whether the filter keeps it.
// notes are what could not be read, said once each by the caller; each
// names the device by its name only where the name can reach a line. A
// device never carries a key assignment (spec §13, decision 30).
func (m Mapping) device(p Profile, api string, raw map[string]any) (admission.Device, bool, []string) {
	name, _ := raw["name"].(string)
	d := admission.Device{Name: name, Transport: admission.TransportTCP}
	label := name
	if !bundle.NameOK(name) {
		label = "with an unusable name"
	}
	var notes []string
	status := strings.ToLower(str(lookup(raw, p.status.over(api))))
	if len(m.Filter.Status) > 0 && !slices.Contains(m.Filter.Status, status) {
		return d, false, nil
	}
	if len(m.Filter.Tags) > 0 {
		have := map[string]bool{}
		for _, tag := range list(raw["tags"]) {
			have[str(lookup(asMap(tag), []string{p.tagKey}))] = true
		}
		for _, want := range m.Filter.Tags {
			if !have[want] {
				return d, false, nil
			}
		}
	}
	p4 := str(lookup(raw, []string{"primary_ip4", "address"}))
	p6 := str(lookup(raw, []string{"primary_ip6", "address"}))
	if m.Filter.HasPrimaryIP && p4 == "" && p6 == "" {
		return d, false, nil
	}
	seen := map[netip.Addr]bool{}
	add := func(s, where string) {
		if s == "" {
			return
		}
		a, err := addrOf(s)
		if err != nil {
			notes = append(notes, fmt.Sprintf("device %s: %s is not an IP address; it is left out of the device's "+
				"addresses", label, where))
			return
		}
		if !seen[a] {
			seen[a] = true
			d.Addresses = append(d.Addresses, a)
		}
	}
	if m.Addresses.Primary {
		add(p4, "primary_ip4")
		add(p6, "primary_ip6")
	}
	if m.needsInterfaces() {
		skipped := 0
		for i, itf := range list(raw["interfaces"]) {
			im := asMap(itf)
			if !m.Addresses.AllInterfaces && !slices.Contains(m.Addresses.Interfaces, str(im["name"])) {
				continue
			}
			for j, ip := range list(im["ip_addresses"]) {
				s := str(asMap(ip)["address"])
				// Pre-flight M13: an address that cannot source TACACS+ to
				// port49d, and that every device may hold, is left out; kept,
				// two devices sharing one would refuse every sync.
				if a, err := addrOf(s); err == nil && !sourceable(a) {
					skipped++
					continue
				}
				add(s, fmt.Sprintf("interfaces[%d].ip_addresses[%d]", i, j))
			}
		}
		if skipped > 0 {
			notes = append(notes, "interface addresses that cannot source TACACS+ (loopback, link-local, "+
				"multicast, unspecified) are left out of every device's addresses")
		}
	}
	slices.SortFunc(d.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	mp := m.mapOf(p)
	for _, attr := range sortedKeys(mp) {
		path := mp[attr]
		var v string
		switch {
		case path == "status":
			v = status
		case customKey.MatchString(path):
			key := strings.TrimPrefix(path, "custom_fields.")
			cv, present := asMap(lookup(raw, p.customFields.over(api)))[key]
			var ok bool
			if v, ok = scalar(cv); present && cv != nil && !ok {
				notes = append(notes, fmt.Sprintf("device %s: custom field %s is not a string, number or boolean; "+
					"attribute %s is left unset", label, key, attr))
			}
		default:
			v = str(lookup(raw, p.fields[path].over(api)))
		}
		if v == "" {
			continue // unset: spec §5.5's on_missing decides what that means
		}
		if attr == "platform" {
			d.Platform = platformName(v, m.Aliases)
			continue
		}
		if d.Attributes == nil {
			d.Attributes = map[string]string{}
		}
		d.Attributes[attr] = v
	}
	return d, true, notes
}

// sourceable is whether a can be the source address of a device's TACACS+
// connection to port49d: not loopback (127/8, ::1), link-local (fe80::/10,
// 169.254/16), multicast or unspecified. Private and global unicast are.
func sourceable(a netip.Addr) bool {
	return !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsLinkLocalMulticast() &&
		!a.IsInterfaceLocalMulticast() && !a.IsUnspecified()
}

// addrOf is an address as the products write one, with or without its
// prefix length (L27: "10.0.1.5/32").
func addrOf(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func lookup(v any, path []string) any {
	for _, k := range path {
		v = asMap(v)[k]
	}
	return v
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func list(v any) []any { l, _ := v.([]any); return l }

func str(v any) string { s, _ := v.(string); return s }

// scalar is v as an attribute value: a string as it is, a number as its
// text, a boolean as true or false. Anything else is not one.
func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}
```

  `lookup` on a nil path returns `v` unchanged; every call passes a path the profile defines, and
  `check` has refused a `nil` one before any read.

- [ ] **Step 4: Run them.** `go test ./internal/sot/... -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): the mapping: filter, attribute map, address rule, and the alias table

Filters run on what was read, status in lower case so every recorded
spelling matches (L30), default active; the map's paths are the profile's
recorded fields; primary addresses, and interface addresses only where
named; a custom
field that is not a scalar is left unset and said; an unrecognized
platform slug is kept (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: `sot.Source`: detect, read, check the count, map — against every recorded release

**Files:**
- Create: `internal/sot/source.go`
- Test: `internal/sot/source_test.go`

**Interfaces:**
- Consumes: everything in Tasks 2–7.
- Produces:
  - `type sot.Config struct { Name, Product, URL, CAFile string; Token Secret; Profile, API string; PageSize int; Mapping Mapping; Log io.Writer }`.
  - `type sot.Source struct{ /* unexported */ }`; `func sot.New(cfg Config) (*Source, error)`;
    `func (s *Source) Name() string`; `func (s *Source) Fetch(ctx context.Context) (admission.Inventory, error)`
    — `*Source` is an `inventory.Source`.
  - `const maxNotes = 256` — the notes a source remembers as said.

- [ ] **Step 1: Write the failing tests.** Create `internal/sot/source_test.go`:

```go
package sot

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// source is a Source over a replay of stack, with m as its mapping.
func source(t *testing.T, stack string, n int, api string, m Mapping) (*Source, *sottest.Server, *bytes.Buffer) {
	t.Helper()
	s := sottest.New(t, stack, n)
	out := &bytes.Buffer{}
	src, err := New(Config{Name: "sot_" + strings.NewReplacer("-", "_", ".", "_").Replace(stack),
		Product: strings.SplitN(stack, "-", 2)[0], URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token), API: api,
		PageSize: 50, Mapping: m, Log: out})
	if err != nil {
		t.Fatal(err)
	}
	return src, s, out
}

// Each recorded release, read over GraphQL with its default map and over
// REST with a map REST gives, reads all 120 devices to the same facts.
func TestEveryRecordedReleaseReadsToTheSameFacts(t *testing.T) {
	restMap := map[string]map[string]string{
		"nautobot-1.6": {"platform": "platform.slug", "site": "site.slug", "role": "role.slug"},
	}
	for _, stack := range []string{"netbox-3.7", "netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		for _, api := range []string{"graphql", "rest"} {
			m := Mapping{Map: restMap[stack], Filter: Filter{Status: []string{"active"}}, Addresses: Addresses{Primary: true}}
			if api == "graphql" {
				m.Map = nil
			}
			src, s, out := source(t, stack, 120, api, m)
			inv, err := src.Fetch(context.Background())
			if err != nil || len(inv.Devices) != 120 {
				t.Fatalf("%s %s: %d devices, %v\n%s", stack, api, len(inv.Devices), err, out)
			}
			d := inv.Devices[119]
			if d.Name != sottest.Name(120) || d.Platform != "arista_eos" || d.Attributes["site"] != "dc1" ||
				d.Attributes["role"] != "leaf" || addrs(d.Addresses) != strings.TrimSuffix(sottest.Addr(120, 5), "/32") ||
				d.KeyRef != "" {
				t.Errorf("%s %s: %+v", stack, api, d)
			}
			// Said once: the release, the profile and the API it read.
			if !strings.Contains(out.String(), "port49-inventory: source "+src.Name()+": ") ||
				!strings.Contains(out.String(), "over "+map[string]string{"graphql": "GraphQL", "rest": "REST"}[api]) {
				t.Errorf("%s %s: said %q", stack, api, out)
			}
			for _, r := range s.Requests() {
				if r.Authorization == "" {
					t.Fatalf("%s %s: a request without the token", stack, api)
				}
			}
			if strings.Contains(out.String(), token) {
				t.Fatalf("%s %s: the token was said", stack, api)
			}
		}
	}
}

// Decision 31: a GraphQL list short of REST's count, before and after,
// fails the fetch and returns nothing that would look like devices removed.
func TestAGraphQLListShortOfTheCountFails(t *testing.T) {
	src, s, _ := source(t, "netbox-4", 120, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	s.DropFromGraphQL = 1
	inv, err := src.Fetch(context.Background())
	if err == nil || len(inv.Devices) != 0 ||
		!strings.Contains(err.Error(), "GraphQL gave 119 devices and REST counts 120 before and 120 after") {
		t.Fatalf("%d devices, %v", len(inv.Devices), err)
	}
}

// Pre-flight I1: a delete between pages shifts every later page left and
// drops a live device at the boundary, while the list and the count after
// agree. Neither reader takes such a list.
func TestADeleteBetweenPagesFailsEitherRead(t *testing.T) {
	for api, want := range map[string]string{
		"graphql": "GraphQL gave 119 devices and REST counts 120 before and 119 after",
		"rest":    "REST page 1 counts 119 devices and page 0 counted 120",
	} {
		src, s, _ := source(t, "netbox-4", 120, api, Mapping{Addresses: Addresses{Primary: true}})
		s.DeleteAfterPage = 1
		inv, err := src.Fetch(context.Background())
		if err == nil || len(inv.Devices) != 0 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %d devices, %v", api, len(inv.Devices), err)
		}
	}
}

// Pre-flight M1: a Source printed whole does not print its token.
func TestASourcePrintedWholeHoldsNoToken(t *testing.T) {
	src, _, _ := source(t, "netbox-4", 1, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, src); strings.Contains(out, token) {
			t.Fatalf("%s printed the token", verb)
		}
	}
}

// Pre-flight M14: when most devices give no platform under the map, the
// source says once where to look.
func TestAnEmptyPlatformPathIsPointedAt(t *testing.T) {
	src, _, out := source(t, "nautobot-3", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "platform.name", "site": "location.name"}})
	// platform.name is "eos" on every replayed device: no note.
	src.Fetch(context.Background())
	if strings.Contains(out.String(), "give no") {
		t.Fatalf("%s", out)
	}
	src, _, out = source(t, "nautobot-3", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "custom_fields.no_such_field"}})
	src.Fetch(context.Background())
	if !strings.Contains(out.String(), "3 of 3 device(s) give no custom_fields.no_such_field") {
		t.Fatalf("%s", out)
	}
}

// api auto reads REST when GraphQL answers 404, and says so once; api
// graphql does not.
func TestAMissingGraphQLFallsBackOnlyWhenAuto(t *testing.T) {
	src, s, out := source(t, "nautobot-2", 3, "auto", Mapping{Addresses: Addresses{Primary: true}})
	s.GraphQLStatus = http.StatusNotFound
	inv, err := src.Fetch(context.Background())
	if err != nil || len(inv.Devices) != 3 || !strings.Contains(out.String(), "GraphQL answered HTTP 404, so the "+
		"devices are read over REST") {
		t.Fatalf("%d %v %s", len(inv.Devices), err, out)
	}
	src, s, _ = source(t, "nautobot-2", 3, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	s.GraphQLStatus = http.StatusNotFound
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "GraphQL answered HTTP 404") {
		t.Fatalf("got %v", err)
	}
	// With interfaces asked for, there is no REST to fall back to.
	src, s, _ = source(t, "nautobot-2", 3, "auto", Mapping{Addresses: Addresses{AllInterfaces: true}})
	s.GraphQLStatus = http.StatusNotFound
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "REST does not give") {
		t.Fatalf("got %v", err)
	}
}

// A next on another origin is followed on the base, and said once a source.
func TestARebuiltNextIsSaidOnce(t *testing.T) {
	src, s, out := source(t, "netbox-4", 120, "rest", Mapping{Addresses: Addresses{Primary: true}})
	s.NextHost = "proxy.internal:8443"
	for i := 0; i < 2; i++ {
		if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 120 {
			t.Fatalf("%d %v", len(inv.Devices), err)
		}
	}
	if n := strings.Count(out.String(), "a page's next names another scheme, host or port than url; it is rebuilt "+
		"on url, and the token is sent nowhere else"); n != 1 {
		t.Fatalf("said %d times: %s", n, out)
	}
}

func TestTheProfileOverrideAndTheTypeAreHeld(t *testing.T) {
	s := sottest.New(t, "nautobot-3", 2)
	src, _ := New(Config{Name: "x", Product: "netbox", URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token),
		PageSize: 50, Log: &bytes.Buffer{}})
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "answers as Nautobot") {
		t.Fatalf("got %v", err)
	}
	out := &bytes.Buffer{}
	src, _ = New(Config{Name: "x", Product: "nautobot", URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token),
		Profile: Nautobot2, PageSize: 50, Mapping: Mapping{Addresses: Addresses{Primary: true}}, Log: out})
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 2 ||
		!strings.Contains(out.String(), "Nautobot 3.2.6, profile nautobot_2 (named), over GraphQL") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestTheReleaseIsSaidOnceWhileItHolds(t *testing.T) {
	src, _, out := source(t, "netbox-4", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "platform.slug", "owner": "custom_fields.os_version"}})
	src.Fetch(context.Background())
	src.Fetch(context.Background())
	if strings.Count(out.String(), "port49-inventory: source "+src.Name()+": NetBox 4.7.1") != 1 {
		t.Fatalf("%s", out)
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/sot/ -run 'Recorded|Short|Missing|Rebuilt|Override|Release|Delete|Whole|Platform' -count=1`
  Expected: FAIL (undefined: `New`, `Config`, `Source`).

- [ ] **Step 3: Implement.** Create `internal/sot/source.go`:

```go
package sot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rhwendt/port49/internal/admission"
)

// Config is one netbox or nautobot source as port49-inventory.yaml gives it;
// internal/inventory's Load checks every field before New sees it.
type Config struct {
	Name, Product string
	// URL is https, with a named CAFile (decision 31).
	URL, CAFile string
	Token       Secret
	// Profile, set, is taken in place of the detected one.
	Profile string
	// API is "auto" (GraphQL, REST on a 404), "graphql" or "rest".
	API      string
	PageSize int
	Mapping  Mapping
	// Log is where the source says what it found, once each: its release
	// and profile, a rebuilt next, a fact it could not read.
	Log io.Writer
}

// maxNotes bounds the notes a source remembers as said: past it, a note is
// not said again, and memory stays bounded whatever a source sends.
const maxNotes = 256

// Source is one NetBox or Nautobot source: an inventory.Source.
type Source struct {
	cfg Config
	c   *client

	mu    sync.Mutex
	said  map[string]bool
	shown string // the release, profile and API last said
}

// New is the source cfg describes. It reads the CA file once, so a missing
// one is said at start.
func New(cfg Config) (*Source, error) {
	c, err := newClient(cfg.URL, cfg.CAFile, cfg.Token, cfg.Product)
	if err != nil {
		return nil, fmt.Errorf("source %s: %w", cfg.Name, err)
	}
	return &Source{cfg: cfg, c: c, said: map[string]bool{}}, nil
}

func (s *Source) Name() string { return s.cfg.Name }

// Fetch reads every device: the release from /api/status/ and its profile,
// the list over GraphQL — checked against REST's count — or over REST, and
// each device through the mapping. Every request is under ctx, which the
// syncer bounds by sync_timeout. Nothing it reads can assign a key.
func (s *Source) Fetch(ctx context.Context) (admission.Inventory, error) {
	var status map[string]any
	if err := s.c.getJSON(ctx, s.c.at("/api/status/", nil), &status); err != nil {
		return admission.Inventory{}, err
	}
	v, err := versionOf(status, s.cfg.Product)
	if err != nil {
		return admission.Inventory{}, err
	}
	p, measured, err := Detect(v, s.cfg.Profile)
	if err != nil {
		return admission.Inventory{}, err
	}
	if !measured {
		s.note(fmt.Sprintf("%s %s is not a release a lab run measured (%s); it is read with profile %s, and a field "+
			"it does not give fails the sync", productName(v.Product), v.Text, measuredList(v.Product), p.Name))
	}
	api := s.cfg.API
	if api == "" || api == "auto" {
		api = "graphql"
	}
	if err := s.cfg.Mapping.check(p, api); err != nil {
		return admission.Inventory{}, err
	}
	var raws []map[string]any
	if api == "graphql" {
		raws, err = s.graphql(ctx, p)
		if errors.Is(err, errNoGraphQL) && (s.cfg.API == "" || s.cfg.API == "auto") {
			if cerr := s.cfg.Mapping.check(p, "rest"); cerr != nil {
				return admission.Inventory{}, fmt.Errorf("GraphQL answered HTTP 404, and %w", cerr)
			}
			s.note("GraphQL answered HTTP 404, so the devices are read over REST; set api: rest to say so, or turn " +
				"GraphQL on")
			api = "rest"
		}
	}
	if api == "rest" {
		var rebuilt bool
		raws, rebuilt, err = s.c.restDevices(ctx, p, s.cfg.PageSize)
		if rebuilt {
			s.note("a page's next names another scheme, host or port than url; it is rebuilt on url, and the token " +
				"is sent nowhere else: check the proxy's Host and X-Forwarded-Proto headers")
		}
	}
	if err != nil {
		return admission.Inventory{}, err
	}
	s.show(v, p, api)
	var inv admission.Inventory
	for _, raw := range raws {
		d, keep, notes := s.cfg.Mapping.device(p, api, raw)
		for _, n := range notes {
			s.note(n)
		}
		if keep {
			inv.Devices = append(inv.Devices, d)
		}
	}
	// Pre-flight M14: a default path many installations leave empty
	// (Nautobot's platform.network_driver) leaves every device out, one line
	// each; say once where to look.
	if noPlatform := len(inv.Devices) - withPlatform(inv.Devices); len(inv.Devices) > 0 &&
		noPlatform*2 > len(inv.Devices) {
		s.note(fmt.Sprintf("%d of %d device(s) give no %s, so they have no platform and are left out: map "+
			"platform to another path (map: {platform: ...}, e.g. platform.name or platform.slug)", noPlatform,
			len(inv.Devices), s.cfg.Mapping.mapOf(p)["platform"]))
	}
	return inv, nil
}

func withPlatform(devs []admission.Device) int {
	n := 0
	for _, d := range devs {
		if d.Platform != "" {
			n++
		}
	}
	return n
}

// graphql is the GraphQL list, taken only when its length equals REST's
// count read before it and after it (pre-flight I1, amending decision 31's
// "either"): a server cap, or a page boundary lost to a concurrent delete —
// which shortens the list and the after count alike — would otherwise drop
// a live device. The next sync, or the debouncer's one more, reads it again.
func (s *Source) graphql(ctx context.Context, p Profile) ([]map[string]any, error) {
	before, err := s.c.restCount(ctx)
	if err != nil {
		return nil, err
	}
	devs, err := s.c.graphqlDevices(ctx, p, s.cfg.Mapping.selection(p), s.cfg.PageSize)
	if err != nil {
		return nil, err
	}
	after, err := s.c.restCount(ctx)
	if err != nil {
		return nil, err
	}
	if n := len(devs); n != before || before != after {
		return nil, fmt.Errorf("GraphQL gave %d devices and REST counts %d before and %d after: a page was lost, "+
			"a server capped the list, or the list changed during the sync; the next sync reads it again", n,
			before, after)
	}
	return devs, nil
}

// show says the release, the profile and the API read, when they change.
func (s *Source) show(v Version, p Profile, api string) {
	named := ""
	if s.cfg.Profile != "" {
		named = " (named)"
	}
	over := map[string]string{"graphql": "GraphQL", "rest": "REST"}[api]
	line := fmt.Sprintf("%s %s, profile %s%s, over %s", productName(v.Product), v.Text, p.Name, named, over)
	s.mu.Lock()
	defer s.mu.Unlock()
	if line != s.shown {
		s.shown = line
		fmt.Fprintf(s.cfg.Log, "port49-inventory: source %s: %s\n", s.cfg.Name, line)
	}
}

// note says text once.
func (s *Source) note(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.said[text] || len(s.said) >= maxNotes {
		return
	}
	s.said[text] = true
	fmt.Fprintf(s.cfg.Log, "port49-inventory: source %s: %s\n", s.cfg.Name, text)
}
```

- [ ] **Step 4: Run them.** `go test ./internal/sot/... -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/sot
git commit -m "feat(sot): Source.Fetch: the release, the list, the count check, the mapping

Read against every release L27 and L30 recorded, over GraphQL and over
REST, to the same facts. api auto falls back to REST on a GraphQL 404;
a GraphQL list matching neither REST count fails; the release, a rebuilt
next and a fact that cannot be read are said once each, and the token
never (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: port49-inventory.yaml's `netbox` and `nautobot` sources, their secrets, and `webhook_listen`

**Files:**
- Modify: `internal/inventory/config.go`
- Modify: `internal/inventory/source.go` (`NewSources`)
- Modify: `cmd/port49-inventory/main.go:58,87` and `cmd/port49-inventory/main_test.go:351` (the
  `newSources` signature)
- Test: `internal/inventory/config_test.go`, `internal/inventory/source_test.go`

**Interfaces:**
- Consumes: `sot.Secret`, `sot.NewSecret`, `sot.CheckURL`, `sot.KnownProfile`, `sot.Mapping`,
  `sot.Filter`, `sot.Addresses`, `sot.PlatformNameShape`, `sot.Config`, `sot.New` (Tasks 2–8);
  `bundle.NameOK`, `bundle.TextOK`; `sottest.New` (Task 4).
- Produces:
  - `SourceConfig` gains `URL, CAFile, Profile, API string; PageSize int; Token, WebhookSecret sot.Secret; Mapping sot.Mapping`.
  - `Config` gains `WebhookListen, WebhookTLSCertFile, WebhookTLSKeyFile string`.
  - `func (c Config) WebhookSources() []string` (sorted); `func (c Config) WebhookSecrets() map[string][]byte`.
  - `func NewSources(cfgs []SourceConfig, log io.Writer) ([]Source, error)` — the new signature.
  - `func secretFromEnv(key, name string, min, max int) (sot.Secret, error)`;
    `func sotSource(i int, s sourceYAML) (SourceConfig, error)`; `type sourceYAML`, `filterYAML`,
    `addressesYAML`, `stringList`.

- [ ] **Step 1: Write the failing tests.** In `internal/inventory/config_test.go`, replace the
  `"netbox"` case of `TestWhatTheServiceCannotRunWithoutIsRefused` with:

```go
		"netbox":            {"type: file", "type: netbox", "path is for a file source; a netbox source reads url"},
		"an unknown type":   {"type: file", "type: infrahub", "type must be file, netbox or nautobot"},
```

  and append:

```go
// netboxSource is a second source, under minimalConfig's sync:.
const netboxSource = `  - name: netbox_prod
    type: netbox
    url: https://netbox.example.com
    ca_file: /etc/i/netbox-ca.pem
    token_secret_env: PORT49_TEST_NETBOX_TOKEN
`

const testToken = "0123456789abcdef0123456789abcdef01234567"
const testHookSecret = "l33-unit-test-webhook-secret-0123456789"

func TestANetboxSourceLoadsWithItsDefaults(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	c, err := loadString(t, minimalConfig+netboxSource)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sync[1]
	if s.Type != "netbox" || s.URL != "https://netbox.example.com" || s.API != "auto" || s.PageSize != 500 ||
		s.Interval != 10*time.Minute || s.MaxRemovedPercent != 10 || s.Token.Reveal() != testToken ||
		!s.WebhookSecret.Empty() || strings.Join(s.Mapping.Filter.Status, ",") != "active" ||
		!s.Mapping.Addresses.Primary || s.Mapping.Map != nil {
		t.Fatalf("%+v", s)
	}
	// Decision 31: a config printed whole carries no secret.
	if out := fmt.Sprintf("%+v %#v", c, c); strings.Contains(out, testToken) {
		t.Fatalf("printed the token: %s", out)
	}
}

// Plan 6a Task 15: a secret's variable is named by its key, and its value
// never.
func TestASecretIsNamedByItsKey(t *testing.T) {
	_, err := loadString(t, minimalConfig+netboxSource)
	if err == nil || !strings.Contains(err.Error(), "sync[1].token_secret_env names an environment variable that is "+
		"unset or empty") || strings.Contains(err.Error(), "PORT49_TEST_NETBOX_TOKEN") {
		t.Fatalf("unset: %v", err)
	}
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", "Token "+testToken)
	if _, err := loadString(t, minimalConfig+netboxSource); err == nil ||
		!strings.Contains(err.Error(), "not 1 to 512 printable characters without a space") ||
		strings.Contains(err.Error(), testToken) {
		t.Fatalf("a space: %v", err)
	}
}

// Decision 31: a webhook secret is 32 to 255 printable characters, and a
// source with one needs webhook_listen, as webhook_listen needs a source.
func TestWebhookListenAndAWebhookSourceGoTogether(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret)
	hook := "    webhook_secret_env: PORT49_TEST_NETBOX_HOOK\n"
	if _, err := loadString(t, minimalConfig+netboxSource+hook); err == nil ||
		!strings.Contains(err.Error(), "sync[1] (netbox_prod): webhook_secret_env is set, and webhook_listen is not") {
		t.Fatalf("no listener: %v", err)
	}
	if _, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource); err == nil ||
		!strings.Contains(err.Error(), "webhook_listen is set, and no source has webhook_secret_env") {
		t.Fatalf("no source: %v", err)
	}
	c, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource+hook)
	if err != nil || string(c.WebhookSecrets()["netbox_prod"]) != testHookSecret ||
		strings.Join(c.WebhookSources(), ",") != "netbox_prod" || len(c.WebhookSecrets()) != 1 {
		t.Fatalf("%v %v", c.WebhookSources(), err)
	}
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret[:31])
	if _, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource+hook); err == nil ||
		!strings.Contains(err.Error(), "sync[1].webhook_secret_env names a variable whose value is not 32 to 255") {
		t.Fatalf("short: %v", err)
	}
}

func TestWhatANetboxSourceCannotHave(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	for name, c := range map[string]struct{ from, to, want string }{
		"http":               {"url: https://", "url: http://", "url must be https://"},
		"a token in the url": {"url: https://netbox.example.com", "url: https://netbox.example.com/?t=" + testToken, "a query"},
		"no ca_file":         {"    ca_file: /etc/i/netbox-ca.pem\n", "", "ca_file is required"},
		"no token_secret_env": {"    token_secret_env: PORT49_TEST_NETBOX_TOKEN\n", "", "sync[1].token_secret_env is required"},
		"relative ca_file":   {"ca_file: /etc/i/netbox-ca.pem", "ca_file: netbox-ca.pem", "ca_file is required, an absolute path"},
		"a nautobot profile": {"token_secret_env:", "profile: nautobot_2\n    token_secret_env:", "profile must be one of netbox_3_7, netbox_4"},
		"api":                {"token_secret_env:", "api: soap\n    token_secret_env:", "api must be auto, graphql or rest"},
		"page_size":          {"token_secret_env:", "page_size: 5000\n    token_secret_env:", "page_size must be between 1 and 1000"},
		"map without platform": {"token_secret_env:", "map: {site: site.slug}\n    token_secret_env:", "map must name platform"},
		"map path":           {"token_secret_env:", "map: {platform: platform.slug, x: tenant.slug}\n    token_secret_env:", "map.x names no path a profile reads"},
		"map key name":       {"token_secret_env:", "map: {platform: platform.slug, name: site.slug}\n    token_secret_env:", "map has a key that is not an attribute name"},
		"both interface rules": {"token_secret_env:", "addresses: {interfaces: [Loopback0], all_interfaces: true}\n    token_secret_env:", "one or the other"},
		"no address":         {"token_secret_env:", "addresses: {primary: false}\n    token_secret_env:", "addresses gives no address"},
		"rest and interfaces": {"token_secret_env:", "api: rest\n    addresses: {all_interfaces: true}\n    token_secret_env:", "REST does not give"},
		"an alias":           {"token_secret_env:", "platform_aliases: {eos: Arista EOS}\n    token_secret_env:", "platform_aliases has an entry"},
		"a status":           {"token_secret_env:", "filter: {status: [\"act\\u001bive\"]}\n    token_secret_env:", "filter.status[0] is not a status name"},
	} {
		_, err := loadString(t, minimalConfig+strings.Replace(netboxSource, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, url: https://x.example.com}", 1)); err == nil ||
		!strings.Contains(err.Error(), "are for netbox and nautobot sources") {
		t.Fatalf("a file source with url: %v", err)
	}
}

// Spec §10's example writes `filter: {status: active, has_primary_ip: true}`:
// a status is a string or a list.
func TestTheSpecExamplesFilterLoads(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	c, err := loadString(t, minimalConfig+netboxSource+"    filter: {status: Active, has_primary_ip: true}\n"+
		"    map: {platform: platform.slug, os_version: custom_fields.os_version}\n"+
		"    addresses: {interfaces: [Loopback0]}\n    platform_aliases: {EOS-Lab: arista_eos}\n")
	if err != nil {
		t.Fatal(err)
	}
	m := c.Sync[1].Mapping
	if strings.Join(m.Filter.Status, ",") != "active" || !m.Filter.HasPrimaryIP || m.Map["os_version"] != "custom_fields.os_version" ||
		!m.Addresses.Primary || m.Addresses.Interfaces[0] != "Loopback0" || m.Aliases["eos-lab"] != "arista_eos" {
		t.Fatalf("%+v", m)
	}
}
```

  Add `"fmt"` to the file's imports. In `internal/inventory/source_test.go`, replace
  `TestNewSourcesBuildsEachConfiguredSource` with:

```go
func TestNewSourcesBuildsEachConfiguredSource(t *testing.T) {
	nb := sottest.New(t, "netbox-4", 1)
	srcs, err := NewSources([]SourceConfig{{Name: "a", Type: "file", Path: "/x"},
		{Name: "b", Type: "netbox", URL: nb.URL, CAFile: nb.CAFile, Token: sot.NewSecret("t"), API: "auto", PageSize: 50,
			Mapping: sot.Mapping{Addresses: sot.Addresses{Primary: true}}}}, io.Discard)
	if err != nil || len(srcs) != 2 || srcs[1].Name() != "b" {
		t.Fatalf("%v %v", srcs, err)
	}
	if _, ok := srcs[1].(*sot.Source); !ok {
		t.Fatalf("%T", srcs[1])
	}
	// The CA file is read at start: a missing one stops the start.
	if _, err := NewSources([]SourceConfig{{Name: "b", Type: "netbox", URL: nb.URL, CAFile: "/nonexistent/ca.pem",
		Token: sot.NewSecret("t")}}, io.Discard); err == nil || !strings.Contains(err.Error(), "source b: ca_file") {
		t.Fatalf("got %v", err)
	}
}
```

  with `"io"`, `"github.com/rhwendt/port49/internal/sot"` and
  `"github.com/rhwendt/port49/internal/sot/sottest"` imported.

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ -run 'Netbox|Secret|Webhook|Spec|NewSources|CannotRun' -count=1`
  Expected: FAIL (`NewSources` takes one argument; `SourceConfig` has no `URL`; …).

- [ ] **Step 3: Implement the config.** In `internal/inventory/config.go`:

  Replace the `SourceConfig` type with:

```go
// SourceConfig is one entry of sync: (spec §10, "Connectors and sync
// cadence"): a file source (plan 6b), or a netbox or nautobot source (plan
// 6c, decision 31).
type SourceConfig struct {
	Name, Type, Path string
	// Interval is how often this source is synced (spec §10), default the
	// top-level interval.
	Interval          time.Duration
	MaxRemovedPercent int
	// The netbox and nautobot sources': where and how the source is read,
	// and, when it takes webhooks, the secret its deliveries are signed
	// with. Token and WebhookSecret print as <redacted>.
	URL, CAFile, Profile, API string
	PageSize                  int
	Token, WebhookSecret      sot.Secret
	Mapping                   sot.Mapping
}
```

  In `Config`, after `MetricsListen` and its comment's field line, add:

```go
	// WebhookListen is where NetBox's and Nautobot's deliveries arrive (plan
	// 6c, decision 31): TLS under the API's certificate, or under
	// WebhookTLSCertFile's, and no client certificate, since no product can
	// present one. Empty is no webhook.
	WebhookListen                         string
	WebhookTLSCertFile, WebhookTLSKeyFile string
```

  In `fileConfig`, add after `MetricsListen`:

```go
	WebhookListen      string `yaml:"webhook_listen"`
	WebhookTLSCertFile string `yaml:"webhook_tls_cert_file"`
	WebhookTLSKeyFile  string `yaml:"webhook_tls_key_file"`
```

  and replace the anonymous `Sync []struct{…}` field with `Sync []sourceYAML \`yaml:"sync"\``, adding
  after `safetyYAML`:

```go
// sourceYAML is one entry of sync:. The keys after safety are a netbox or
// nautobot source's (plan 6c).
type sourceYAML struct {
	Name             string            `yaml:"name"`
	Type             string            `yaml:"type"`
	Path             string            `yaml:"path"`
	Interval         time.Duration     `yaml:"interval"`
	Safety           safetyYAML        `yaml:"safety"`
	URL              string            `yaml:"url"`
	CAFile           string            `yaml:"ca_file"`
	TokenSecretEnv   string            `yaml:"token_secret_env"`
	WebhookSecretEnv string            `yaml:"webhook_secret_env"`
	Profile          string            `yaml:"profile"`
	API              string            `yaml:"api"`
	PageSize         int               `yaml:"page_size"`
	Filter           *filterYAML       `yaml:"filter"`
	Map              map[string]string `yaml:"map"`
	Addresses        *addressesYAML    `yaml:"addresses"`
	PlatformAliases  map[string]string `yaml:"platform_aliases"`
}

type filterYAML struct {
	Status       *stringList `yaml:"status"`
	Tags         []string    `yaml:"tags"`
	HasPrimaryIP bool        `yaml:"has_primary_ip"`
}

type addressesYAML struct {
	Primary       *bool    `yaml:"primary"`
	Interfaces    []string `yaml:"interfaces"`
	AllInterfaces bool     `yaml:"all_interfaces"`
}

// stringList is a string or a list of them: spec §10's example writes
// `status: active`.
type stringList []string

func (l *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = []string{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*l = s
	return nil
}
```

  In `Load`, copy the three new fields into `c` beside `MetricsListen`
  (`WebhookListen: f.WebhookListen, WebhookTLSCertFile: f.WebhookTLSCertFile, WebhookTLSKeyFile:
  f.WebhookTLSKeyFile`). In the absolute-path check, after the `mirror_dir` line, add:

```go
	for _, p := range []struct{ key, v string }{{"webhook_tls_cert_file", c.WebhookTLSCertFile},
		{"webhook_tls_key_file", c.WebhookTLSKeyFile}} {
		if p.v != "" {
			paths = append(paths, p)
		}
	}
```

  Replace the per-source `switch s.Type { … }` and the `c.Sync = append(…)` that follows the bound
  and interval with:

```go
		var conn SourceConfig
		switch s.Type {
		case "file":
			if s.Path == "" {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): path is required for a file source", i, s.Name)
			}
			if !filepath.IsAbs(s.Path) {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d].path must be an absolute path", i)
			}
			if s.URL != "" || s.CAFile != "" || s.TokenSecretEnv != "" || s.WebhookSecretEnv != "" || s.Profile != "" ||
				s.API != "" || s.PageSize != 0 || s.Filter != nil || s.Map != nil || s.Addresses != nil ||
				s.PlatformAliases != nil {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): url, ca_file, token_secret_env, "+
					"webhook_secret_env, profile, api, page_size, filter, map, addresses and platform_aliases are for "+
					"netbox and nautobot sources", i, s.Name)
			}
		case "netbox", "nautobot":
			if conn, err = sotSource(i, s); err != nil {
				return Config{}, err
			}
		default:
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type must be file, netbox or nautobot", i, s.Name)
		}
```

  and, after the interval check, in place of the old `c.Sync = append(...)`:

```go
		conn.Name, conn.Type, conn.Path, conn.Interval, conn.MaxRemovedPercent = s.Name, s.Type, s.Path, iv, p
		c.Sync = append(c.Sync, conn)
	}
	// Decision 31: a webhook secret needs a listener, and a listener a
	// source whose deliveries it can authenticate.
	for i, s := range c.Sync {
		if !s.WebhookSecret.Empty() && c.WebhookListen == "" {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): webhook_secret_env is set, and webhook_listen "+
				"is not: no listener would take its deliveries", i, s.Name)
		}
	}
	if c.WebhookListen != "" {
		if len(c.WebhookSources()) == 0 {
			return Config{}, fmt.Errorf("port49-inventory: webhook_listen is set, and no source has webhook_secret_env: " +
				"no delivery could be authenticated")
		}
		if _, port, err := net.SplitHostPort(c.WebhookListen); err != nil || port == "" {
			return Config{}, fmt.Errorf("port49-inventory: webhook_listen must be host:port, such as :8444")
		}
	}
	if (c.WebhookTLSCertFile == "") != (c.WebhookTLSKeyFile == "") {
		return Config{}, fmt.Errorf("port49-inventory: webhook_tls_cert_file and webhook_tls_key_file go together")
	}
	if c.WebhookTLSCertFile != "" && c.WebhookListen == "" {
		return Config{}, fmt.Errorf("port49-inventory: webhook_tls_cert_file is set, and webhook_listen is not")
	}
	return c, nil
}
```

  (The loop's closing brace and `return c, nil` move into this block: delete the old ones.) Add the
  helpers at the end of the file:

```go
var (
	envNameShape = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	attrShape    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	statusShape  = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,63}$`)
)

// secretFromEnv is the value of the environment variable name, named by key
// in port49-inventory.yaml. Its errors name key, never the variable or its
// value (plan 6a Task 15): the value is the secret, and a name is where one
// gets pasted. A value is min to max printable ASCII characters without a
// space, so it cannot split a header.
func secretFromEnv(key, name string, min, max int) (sot.Secret, error) {
	if name == "" {
		// Pre-flight M12: absent, not malformed.
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s is required", key)
	}
	if !envNameShape.MatchString(name) {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s is not an environment variable name (letters, digits "+
			"and _)", key)
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s names an environment variable that is unset or empty",
			key)
	}
	if len(v) < min || len(v) > max || strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s names a variable whose value is not %d to %d printable "+
			"characters without a space", key, min, max)
	}
	return sot.NewSecret(v), nil
}

// sotSource is a netbox or nautobot entry's connection, secrets and mapping,
// with decision 31's defaults: api auto, page_size 500, filter status
// [active], addresses primary. An error names the key at fault; a value is
// quoted only once it has passed its shape.
func sotSource(i int, s sourceYAML) (SourceConfig, error) {
	at := fmt.Sprintf("port49-inventory: sync[%d] (%s): ", i, s.Name)
	fail := func(format string, args ...any) (SourceConfig, error) {
		return SourceConfig{}, fmt.Errorf(at+format, args...)
	}
	if s.Path != "" {
		return fail("path is for a file source; a %s source reads url", s.Type)
	}
	if s.URL == "" {
		return fail("url is required")
	}
	if err := sot.CheckURL(s.URL); err != nil {
		return fail("%s", err)
	}
	if s.CAFile == "" || !filepath.IsAbs(s.CAFile) {
		return fail("ca_file is required, an absolute path: the CA bundle that issues the source's certificate (the " +
			"host's own bundle file for a public one)")
	}
	c := SourceConfig{URL: s.URL, CAFile: s.CAFile, Profile: s.Profile, API: s.API, PageSize: s.PageSize}
	var err error
	if c.Token, err = secretFromEnv(fmt.Sprintf("sync[%d].token_secret_env", i), s.TokenSecretEnv, 1, 512); err != nil {
		return SourceConfig{}, err
	}
	if s.WebhookSecretEnv != "" {
		// 255 is the products' secret field (L27, L30).
		if c.WebhookSecret, err = secretFromEnv(fmt.Sprintf("sync[%d].webhook_secret_env", i), s.WebhookSecretEnv, 32,
			255); err != nil {
			return SourceConfig{}, err
		}
	}
	if c.Profile != "" && !sot.KnownProfile(s.Type, c.Profile) {
		if s.Type == "netbox" {
			return fail("profile must be one of netbox_3_7, netbox_4")
		}
		return fail("profile must be one of nautobot_1_6, nautobot_2")
	}
	switch c.API {
	case "":
		c.API = "auto"
	case "auto", "graphql", "rest":
	default:
		return fail("api must be auto, graphql or rest")
	}
	if c.PageSize == 0 {
		c.PageSize = 500
	}
	if c.PageSize < 1 || c.PageSize > 1000 {
		return fail("page_size must be between 1 and 1000")
	}
	m := sot.Mapping{Filter: sot.Filter{Status: []string{"active"}}, Addresses: sot.Addresses{Primary: true}}
	if f := s.Filter; f != nil {
		if f.Status != nil {
			m.Filter.Status = nil
			for j, st := range *f.Status {
				if st = strings.ToLower(st); !statusShape.MatchString(st) {
					return fail("filter.status[%d] is not a status name", j)
				}
				m.Filter.Status = append(m.Filter.Status, st)
			}
		}
		for j, tag := range f.Tags {
			if !bundle.TextOK(tag) || tag == "" {
				return fail("filter.tags[%d] is not a tag", j)
			}
		}
		m.Filter.Tags, m.Filter.HasPrimaryIP = f.Tags, f.HasPrimaryIP
	}
	if s.Map != nil {
		if _, ok := s.Map["platform"]; !ok {
			return fail("map must name platform: the path the device's platform is read from")
		}
		keys := make([]string, 0, len(s.Map))
		for k := range s.Map {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, attr := range keys {
			if !attrShape.MatchString(attr) || attr == "name" {
				return fail("map has a key that is not an attribute name (lowercase letters, digits and _, starting " +
					"with a letter; not name)")
			}
			if !sot.ValidPath(s.Map[attr]) {
				return fail("map.%s names no path a profile reads (site.slug, role.slug, platform.slug, "+
					"platform.network_driver, location.name, role.name, platform.name, status, custom_fields.<key>)", attr)
			}
		}
		m.Map = s.Map
	}
	if a := s.Addresses; a != nil {
		if a.Primary != nil {
			m.Addresses.Primary = *a.Primary
		}
		if a.AllInterfaces && len(a.Interfaces) > 0 {
			return fail("addresses names interfaces and all_interfaces: one or the other")
		}
		for j, n := range a.Interfaces {
			if n == "" || !bundle.TextOK(n) {
				return fail("addresses.interfaces[%d] is not an interface name", j)
			}
		}
		m.Addresses.Interfaces, m.Addresses.AllInterfaces = a.Interfaces, a.AllInterfaces
	}
	interfaces := len(m.Addresses.Interfaces) > 0 || m.Addresses.AllInterfaces
	if !m.Addresses.Primary && !interfaces {
		return fail("addresses gives no address: set primary: true, interfaces or all_interfaces")
	}
	if c.API == "rest" && interfaces {
		return fail("addresses names interfaces, which REST does not give in the device list (L27): use api: auto or graphql")
	}
	for slug, name := range s.PlatformAliases {
		if !bundle.NameOK(slug) || !sot.PlatformNameShape.MatchString(name) {
			return fail("platform_aliases has an entry that is not slug: platform_name (a platform name is lowercase " +
				"letters, digits and _, as the policy writes one)")
		}
		if m.Aliases == nil {
			m.Aliases = map[string]string{}
		}
		m.Aliases[strings.ToLower(slug)] = name
	}
	c.Mapping = m
	return c, nil
}

// WebhookSources is every source that takes webhooks, by name, sorted.
func (c Config) WebhookSources() []string {
	var out []string
	for _, s := range c.Sync {
		if !s.WebhookSecret.Empty() {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// WebhookSecrets is each webhook source's secret, the HMAC key its
// deliveries are checked with.
func (c Config) WebhookSecrets() map[string][]byte {
	out := map[string][]byte{}
	for _, s := range c.Sync {
		if !s.WebhookSecret.Empty() {
			out[s.Name] = []byte(s.WebhookSecret.Reveal())
		}
	}
	return out
}
```

  Add `"os"`, `"sort"`, `"github.com/rhwendt/port49/internal/bundle"` and
  `"github.com/rhwendt/port49/internal/sot"` to the imports. `Load`'s loop variable `err` is the
  function's; if the compiler says `conn, err = …` shadows nothing, keep it; if it reports `err`
  undeclared in that scope, declare `var err error` before the loop.

- [ ] **Step 4: Implement `NewSources`.** In `internal/inventory/source.go`, replace `NewSources`
  with:

```go
// NewSources builds each configured source; log is where a netbox or
// nautobot source says what it found. Load has refused every type this
// build does not have; a CA file that cannot be read stops the start here.
func NewSources(cfgs []SourceConfig, log io.Writer) ([]Source, error) {
	var out []Source
	for _, c := range cfgs {
		switch c.Type {
		case "file":
			out = append(out, FileSource{SourceName: c.Name, Path: c.Path})
		case "netbox", "nautobot":
			s, err := sot.New(sot.Config{Name: c.Name, Product: c.Type, URL: c.URL, CAFile: c.CAFile, Token: c.Token,
				Profile: c.Profile, API: c.API, PageSize: c.PageSize, Mapping: c.Mapping, Log: log})
			if err != nil {
				return nil, fmt.Errorf("port49-inventory: %w", err)
			}
			out = append(out, s)
		default:
			return nil, fmt.Errorf("port49-inventory: source %s: type %s is not built", c.Name, c.Type)
		}
	}
	return out, nil
}
```

  with `"io"` and `"github.com/rhwendt/port49/internal/sot"` imported. In
  `cmd/port49-inventory/main.go`, change `newSources(cfg.Sync)` to `newSources(cfg.Sync, stderr)`;
  in `main_test.go`, change the swapped function's signature to
  `func([]inventory.SourceConfig, io.Writer) ([]inventory.Source, error)`.

- [ ] **Step 5: Run them.** `go test ./internal/inventory/ ./cmd/port49-inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory cmd/port49-inventory
git commit -m "feat(inventory): netbox and nautobot sources in port49-inventory.yaml, and webhook_listen

url strict https with a named ca_file; the token and the webhook secret
named by token_secret_env and webhook_secret_env, read at start, named
by their key in every error and never printed; filter (status default
active, as a string or a list), map, addresses and platform_aliases
checked at load; a webhook secret needs webhook_listen, and the
listener a source (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: Every `Fetch` within `sync_timeout`, and a generic platform never silent

**Files:**
- Modify: `internal/inventory/sync.go`, `internal/inventory/metrics.go`
- Modify: `cmd/port49/inventory.go` (`printResult`)
- Test: `internal/inventory/sync_test.go`, `cmd/port49/inventory_service_test.go`

**Interfaces:**
- Consumes: `Syncer`, `Result`, `syncRig`, `memSource`, `devices`, `syncPolicy` (plan 6b);
  `(*policy.Policy).PlatformSource`, `(*policy.Policy).Devices`.
- Produces:
  - `var fetchGrace = 5 * time.Second`.
  - `func (s *Syncer) fetch(ctx context.Context, src Source) (admission.Inventory, error)`;
    `func (s *Syncer) timeout() time.Duration`; `Syncer.hung map[string]chan struct{}` (unexported).
  - `type GenericPlatform struct { Platform string \`json:"platform"\`; Devices int \`json:"devices"\` }`;
    `Result.Generic []GenericPlatform \`json:"generic,omitempty"\``; `func genericIn(p *policy.Policy) []GenericPlatform`.
  - Metrics: `SourceHung *prometheus.GaugeVec` (`port49_inventory_source_hung{source}`),
    `GenericDevices prometheus.Gauge` (`port49_inventory_generic_platform_devices`).

- [ ] **Step 1: Write the failing tests.** Append to `internal/inventory/sync_test.go`:

```go
// stuckSource ignores its context until released, as a connector with a
// bug would.
type stuckSource struct {
	name    string
	release chan struct{}
	inv     admission.Inventory
}

func (s *stuckSource) Name() string { return s.name }
func (s *stuckSource) Fetch(context.Context) (admission.Inventory, error) {
	<-s.release
	return s.inv, nil
}

// Spec §10: every Fetch returns within sync_timeout. One that does not is
// abandoned fetchGrace later, the source is marked hung, and it is not asked
// again until the abandoned call returns.
func TestAFetchPastSyncTimeoutIsAbandoned(t *testing.T) {
	defer func(g time.Duration) { fetchGrace = g }(fetchGrace)
	fetchGrace = 20 * time.Millisecond
	rig := newSyncRig(t, syncPolicy, devices(3))
	stuck := &stuckSource{name: "a", release: make(chan struct{}), inv: devices(3)}
	rig.s.Sources, rig.s.Timeout = []Source{stuck}, 50*time.Millisecond
	start := time.Now()
	res := rig.sync(t)
	if res.Outcome != OutcomeFailed || !strings.Contains(res.Reason, "source a: did not return within sync_timeout") ||
		time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %s", res, time.Since(start))
	}
	if testutil.ToFloat64(rig.s.Metrics.SourceHung.WithLabelValues("a")) != 1 {
		t.Fatal("source_hung")
	}
	if res := rig.sync(t); res.Outcome != OutcomeFailed ||
		!strings.Contains(res.Reason, "its fetch abandoned at an earlier sync has not returned") {
		t.Fatalf("asked again while out: %+v", res)
	}
	close(stuck.release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		res := rig.sync(t)
		if res.Outcome == OutcomePublished {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never published once released: %+v", res)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if testutil.ToFloat64(rig.s.Metrics.SourceHung.WithLabelValues("a")) != 0 {
		t.Fatal("source_hung stayed 1")
	}
}

// A source that honours its context and runs out of time says so.
func TestAFetchThatRunsOutOfTimeSaysSo(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.s.Sources = []Source{fetchFunc(func(ctx context.Context) (admission.Inventory, error) {
		<-ctx.Done()
		return admission.Inventory{}, ctx.Err()
	})}
	rig.s.Timeout = 30 * time.Millisecond
	if res := rig.sync(t); res.Outcome != OutcomeFailed ||
		!strings.Contains(res.Reason, "did not finish within sync_timeout (30ms): context deadline exceeded") {
		t.Fatalf("%+v", res)
	}
}

type fetchFunc func(context.Context) (admission.Inventory, error)

func (fetchFunc) Name() string                                         { return "a" }
func (f fetchFunc) Fetch(ctx context.Context) (admission.Inventory, error) { return f(ctx) }

// Spec §8, §10: a platform with no adapter is served by the generic one,
// and that is said, never silent — whatever the source.
func TestAGenericPlatformIsSaidAndCounted(t *testing.T) {
	inv := devices(3)
	inv.Devices[0].Platform, inv.Devices[1].Platform = "eos-lab", "eos-lab"
	rig := newSyncRig(t, syncPolicy, inv)
	res := rig.sync(t)
	if res.Outcome != OutcomePublished || len(res.Generic) != 1 || res.Generic[0] != (GenericPlatform{"eos-lab", 2}) {
		t.Fatalf("%+v %s", res, rig.out)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: bundle 1: platform eos-lab (2 device(s)) has no adapter "+
		"in the policy and is served by the generic one, priv-lvl only (spec §8): name it in the source's "+
		"platform_aliases (a policy platforms: block cannot be named eos-lab)") {
		t.Fatalf("%s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.GenericDevices) != 2 {
		t.Fatal("generic_platform_devices")
	}
	rig.out.Reset()
	if res := rig.sync(t); res.Outcome != OutcomeUnchanged || len(res.Generic) != 1 || rig.out.Len() != 0 {
		t.Fatalf("an unchanged sync said it again: %+v %q", res, rig.out)
	}
	rig.src.inv = devices(3)
	rig.sync(t)
	if testutil.ToFloat64(rig.s.Metrics.GenericDevices) != 0 {
		t.Fatal("the gauge did not fall")
	}
}
```

  In `cmd/port49/inventory_service_test.go`, append:

```go
func TestInventorySyncPrintsAGenericPlatform(t *testing.T) {
	svc := startService(t)
	svc.writeSource(t, "  - {name: leaf-01, platform: eos-lab, addresses: [10.0.0.1]}\n")
	var out, errOut bytes.Buffer
	args := []string{"inventory", "sync", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key}
	if code := run(args, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "  platform eos-lab (1 device(s)) has no adapter in the policy and is served "+
			"by the generic one, priv-lvl only (spec §8)") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ ./cmd/port49/ -run 'Fetch|Generic' -count=1`
  Expected: FAIL (undefined: `fetchGrace`, `SourceHung`, `GenericPlatform`, …).

- [ ] **Step 3: Implement the metrics.** In `internal/inventory/metrics.go`, add to `Metrics`:

```go
	// SourceHung is 1 while a source's fetch, abandoned past sync_timeout,
	// has not returned (spec §10): that source is not asked meanwhile.
	SourceHung *prometheus.GaugeVec
	// GenericDevices is how many devices the last good sync's bundle serves
	// with the generic adapter (spec §8, "Unknown platforms").
	GenericDevices prometheus.Gauge
```

  and to `NewMetrics`, before `reg.MustRegister`:

```go
	m.SourceHung = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_inventory_source_hung",
		Help: "1 while a source's fetch, abandoned past sync_timeout, has not returned."}, []string{"source"})
	m.GenericDevices = prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_generic_platform_devices",
		Help: "Devices in the last good sync whose platform has no adapter in the policy."})
```

  and add `m.SourceHung, m.GenericDevices` to the `reg.MustRegister` call.

- [ ] **Step 4: Implement the bound.** In `internal/inventory/sync.go`:

  Add to `Syncer`, after `fetched`:

```go
	// hung is each source whose fetch was abandoned past sync_timeout, by
	// name: closed when that call returns. Guarded by mu.
	hung map[string]chan struct{}
	// genericSaid is the generic platforms as last said, so each is said
	// when it changes.
	genericSaid string
```

  Add, after `readPolicy`:

```go
// fetchGrace is how long a source has, once its sync's deadline passes, to
// return before it is abandoned (spec §10: every Fetch returns within
// sync_timeout). A variable for the tests.
var fetchGrace = 5 * time.Second

// timeout is one sync's bound: Timeout, or 5m.
func (s *Syncer) timeout() time.Duration {
	if s.Timeout == 0 {
		return 5 * time.Minute
	}
	return s.Timeout
}

// fetch is src.Fetch under ctx, the sync's bounded context, returning
// within the bound and fetchGrace after it whatever src does (decision 31).
// A source that has not returned by then is abandoned: the sync fails, the
// source is marked hung, and it is not asked again until the abandoned call
// returns, so a connector that ignores its context costs one goroutine, not
// one per sync. Called under mu.
func (s *Syncer) fetch(ctx context.Context, src Source) (admission.Inventory, error) {
	name := src.Name()
	if out := s.hung[name]; out != nil {
		select {
		case <-out:
			delete(s.hung, name)
			s.Metrics.SourceHung.WithLabelValues(name).Set(0)
		default:
			return admission.Inventory{}, errors.New("its fetch abandoned at an earlier sync has not returned; it is " +
				"not asked again until it does")
		}
	}
	type got struct {
		inv admission.Inventory
		err error
	}
	ch, done := make(chan got, 1), make(chan struct{})
	go func() {
		inv, err := src.Fetch(ctx)
		ch <- got{inv, err}
		close(done)
	}()
	answer := func(g got) (admission.Inventory, error) {
		if g.err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return g.inv, fmt.Errorf("did not finish within sync_timeout (%s): %w", s.timeout(), g.err)
		}
		return g.inv, g.err
	}
	select {
	case g := <-ch:
		return answer(g)
	case <-ctx.Done():
	}
	grace := time.NewTimer(fetchGrace)
	defer grace.Stop()
	select {
	case g := <-ch:
		return answer(g)
	case <-grace.C:
	}
	if s.hung == nil {
		s.hung = map[string]chan struct{}{}
	}
	s.hung[name] = done
	s.Metrics.SourceHung.WithLabelValues(name).Set(1)
	return admission.Inventory{}, fmt.Errorf("did not return within sync_timeout (%s) and %s after; it is abandoned, "+
		"and asked again once it returns", s.timeout(), fetchGrace)
}
```

  In `syncLocked`, replace the `timeout := s.Timeout` … `if timeout == 0 {…}` lines and the
  `context.WithTimeout(ctx, timeout)` with `context.WithTimeout(ctx, s.timeout())`. In `sync`,
  replace `if got, err = src.Fetch(ctx); err != nil {` with `if got, err = s.fetch(ctx, src); err != nil {`.

- [ ] **Step 5: Implement the generic platforms.** In `internal/inventory/sync.go`, add `Generic` to
  `Result` after `LeftOut`:

```go
	// Generic is each platform the service's policy has no adapter for, with
	// how many devices it serves with the generic one (spec §8, §10).
	Generic []GenericPlatform `json:"generic,omitempty"`
```

  and, after `QuarantinedDevice`:

```go
// GenericPlatform is a platform no adapter in the service's policy renders:
// its devices are admitted and served by the set's generic adapter, priv-lvl
// only (spec §8, "Unknown platforms"), which spec §10 says is never silent.
type GenericPlatform struct {
	Platform string `json:"platform"`
	Devices  int    `json:"devices"`
}

// genericIn is every generic platform in p, by name.
func genericIn(p *policy.Policy) []GenericPlatform {
	count := map[string]int{}
	for _, d := range p.Devices() {
		if p.PlatformSource(d.Platform) == "generic" {
			count[d.Platform]++
		}
	}
	out := make([]GenericPlatform, 0, len(count))
	for name, n := range count {
		out = append(out, GenericPlatform{Platform: name, Devices: n})
	}
	slices.SortFunc(out, func(a, b GenericPlatform) int { return strings.Compare(a.Platform, b.Platform) })
	return out
}
```

  In `sync`, after `checkSafety` passes and `quarantined := quarantinedIn(next, now)`, add:

```go
	generic := genericIn(next)
	total := 0
	for _, g := range generic {
		total += g.Devices
	}
	s.Metrics.GenericDevices.Set(float64(total))
```

  and set `Generic: generic` in the three results that follow (the unchanged one, and both published
  ones). In `say`, at the end of the `OutcomePublished` case and of the `OutcomeUnchanged` case, add
  `s.sayGeneric(res)`, and add:

```go
// sayGeneric says each generic platform when the set of them changes.
func (s *Syncer) sayGeneric(res Result) {
	key := fmt.Sprint(res.Generic)
	if key == s.genericSaid {
		return
	}
	s.genericSaid = key
	for _, g := range res.Generic {
		// A policy platforms: block is named as a policy platform is
		// (^[a-z][a-z0-9_]*$); most slugs are hyphenated, and the hint must
		// not send an operator to a policy load error (pre-flight M5).
		fix := "name it in the source's platform_aliases, or give it a platforms: block in the policy"
		if !sot.PlatformNameShape.MatchString(g.Platform) {
			fix = "name it in the source's platform_aliases (a policy platforms: block cannot be named " + g.Platform + ")"
		}
		fmt.Fprintf(s.Log, "port49-inventory: bundle %d: platform %s (%d device(s)) has no adapter in the policy and is "+
			"served by the generic one, priv-lvl only (spec §8): %s\n", res.Sequence, g.Platform, g.Devices, fix)
	}
}
```

  A platform name reaches a line only once `bundle.DeviceProblem` has passed it (printable ASCII, no
  space), so it is printed as it is. `sync.go` imports `github.com/rhwendt/port49/internal/sot` for
  `PlatformNameShape` (Task 9 already made `internal/inventory` depend on it).

- [ ] **Step 6: `inventory sync` prints them.** In `cmd/port49/inventory.go`'s `printResult`, in the
  `"published"` case after the quarantined loop, and in the `"unchanged"` case after its line, add:

```go
		for _, g := range res.Generic {
			fmt.Fprintf(w, "  platform %s (%d device(s)) has no adapter in the policy and is served by the generic "+
				"one, priv-lvl only (spec §8)\n", inventory.Printable(g.Platform), g.Devices)
		}
```

- [ ] **Step 7: Run them.** `go test ./internal/inventory/ ./cmd/port49/ ./cmd/port49-inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 8: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory cmd/port49
git commit -m "feat(inventory): every fetch within sync_timeout, and a generic platform said

A source that has not returned 5s past the sync's deadline is abandoned:
the sync fails, port49_inventory_source_hung{source} is 1, and it is not
asked again until the call returns. A platform the policy has no adapter
for is said at each publication that changes the set, counted in
port49_inventory_generic_platform_devices, and printed by inventory sync
(spec §8, §10; decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10a: A device left with no address is out of service, in both bounds (pre-flight I2)

**Files:**
- Modify: `internal/bundle/diff.go` (`Unaddressed`, `CheckFrom`)
- Modify: `internal/inventory/safety.go` (`checkSafety`)
- Test: `internal/bundle/diff_test.go`, `internal/inventory/sync_test.go`

**Interfaces:**
- Consumes: `bundle.NewlyRefused`, `byName`, `CheckFrom` (plan 6a); `checkSafety` (plan 6b);
  `bundle.Parse`; `policy.Env`; the sync rig (plan 6b).
- Produces: `func bundle.Unaddressed(old, new *policy.Policy) []string` — sorted names;
  `func nameList(names []string) string` (unexported; up to five, and how many more).

The bounds count a device out of service when it is removed or newly refused. port49d admits a
connection by its source address, so a device kept under its name, still admitted by an attribute key
group (tier 2, which outranks every CIDR group), but now with **no address** is out of service too,
and neither bound sees it. Plan 6c makes attribute groups the natural shape and adds ways for
addresses to vanish while names stay: an IPAM clean-up, a token that lost its IPAM view (whether
the related object then reads as null is unmeasured), an unmeasured release's address shape. This task
is 6b's code, changed here because 6c is what exposes it; its text in spec §10 is Task 1's.

- [ ] **Step 1: Write the failing tests.** Append to `internal/inventory/sync_test.go`:

```go
// attrPolicy admits by attribute: an address-less device stays admitted.
const attrPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {attributes: {site: dc1}}, key_ref: lab_key}]
`

func sited(inv admission.Inventory, addressed bool) admission.Inventory {
	for i := range inv.Devices {
		inv.Devices[i].Attributes = map[string]string{"site": "dc1"}
		if !addressed {
			inv.Devices[i].Addresses = nil
		}
	}
	return inv
}

// Pre-flight I2: a source that strips every device's address, the names
// and the key group's attribute kept, is refused by its bound.
func TestASourceThatStripsEveryAddressIsRefused(t *testing.T) {
	rig := newSyncRig(t, attrPolicy, sited(devices(20), true))
	if res := rig.sync(t); res.Outcome != OutcomePublished {
		t.Fatalf("%+v", res)
	}
	rig.src.inv = sited(devices(20), false)
	res := rig.sync(t)
	if res.Outcome != OutcomeRefused || !strings.Contains(res.Reason,
		"source a removes 0 of 20 devices and refuses 0 more and leaves 20 more with no address (100%)") {
		t.Fatalf("%+v", res)
	}
	// One device of twenty is under the 10% bound.
	one := sited(devices(20), true)
	one.Devices[0].Addresses = nil
	rig.src.inv = one
	if res := rig.sync(t); res.Outcome != OutcomePublished {
		t.Fatalf("one device: %+v", res)
	}
}
```

  Append to `internal/bundle/diff_test.go`:

```go
// Pre-flight I2: port49d's bound counts a device left with no address, as
// the service's does, and names it.
func TestCheckCountsADeviceLeftWithNoAddress(t *testing.T) {
	pol := []byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {attributes: {site: dc1}}, key_ref: lab_key}]
`)
	inv := func(addressed bool) admission.Inventory {
		var out admission.Inventory
		for i := 1; i <= 3; i++ {
			d := admission.Device{Name: fmt.Sprintf("leaf-%02d", i), Platform: "arista_eos",
				Attributes: map[string]string{"site": "dc1"}, Transport: admission.TransportTCP}
			if addressed {
				d.Addresses = []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}
			}
			out.Devices = append(out.Devices, d)
		}
		return out
	}
	env := policy.Env{KeyRefs: []string{"lab_key"}}
	old, err := Parse(pol, inv(true), env)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := Parse(pol, inv(false), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(Unaddressed(old, bare), ","); got != "leaf-01,leaf-02,leaf-03" {
		t.Fatalf("Unaddressed: %q", got)
	}
	err = CheckFrom(old, bare, 10, "fix the source of truth")
	if err == nil || !strings.Contains(err.Error(), "removes 0 of 3 devices and refuses 0 more and leaves 3 more with "+
		"no address (100%)") || !strings.Contains(err.Error(), "left with no address: leaf-01, leaf-02, leaf-03") {
		t.Fatalf("got %v", err)
	}
	if err := CheckFrom(old, bare, 100, "fix the source of truth"); err != nil {
		t.Fatalf("a bound of 100 is off: %v", err)
	}
	if got := Unaddressed(bare, old); len(got) != 0 {
		t.Fatalf("gaining addresses is not losing them: %v", got)
	}
}
```

  with `"fmt"`, `"net/netip"`, `"strings"`, `"github.com/rhwendt/port49/internal/admission"` and
  `"github.com/rhwendt/port49/internal/policy"` imported where the file lacks them.

- [ ] **Step 2: Run them.** `go test ./internal/bundle/ ./internal/inventory/ -run 'NoAddress|StripsEveryAddress' -count=1`
  Expected: FAIL (undefined: `Unaddressed`; the strip publishes).

- [ ] **Step 3: Implement.** In `internal/bundle/diff.go`, after `NewlyRefused`, add:

```go
// Unaddressed is every device, by name and sorted, that old gives at least
// one address and new keeps under its name with none, and that new does not
// newly refuse (NewlyRefused counts those). port49d admits a connection by
// its source address, so such a device is out of service even while an
// attribute key group keeps it "admitted" (plan 6c, pre-flight I2).
func Unaddressed(old, new *policy.Policy) []string {
	before := byName(old.Devices())
	refused := map[string]bool{}
	for _, r := range NewlyRefused(old, new) {
		refused[r.Device.Name] = true
	}
	var out []string
	for _, d := range new.Devices() {
		if o, ok := before[d.Name]; ok && len(o.Addresses) > 0 && len(d.Addresses) == 0 && !refused[d.Name] {
			out = append(out, d.Name)
		}
	}
	slices.Sort(out)
	return out
}

// nameList is up to five names, and how many more.
func nameList(ns []string) string {
	if len(ns) > 5 {
		return strings.Join(ns[:5], ", ") + fmt.Sprintf(" and %d more", len(ns)-5)
	}
	return strings.Join(ns, ", ")
}
```

  In `CheckFrom`, replace the lines from `refused := NewlyRefused(old, new)` through the `msg :=
  fmt.Sprintf(…)` statement with:

```go
	refused := NewlyRefused(old, new)
	bare := Unaddressed(old, new)
	if gone := removed + len(refused) + len(bare); gone*100 > was*maxRemovedPercent {
		msg := fmt.Sprintf("the new inventory removes %d of %d devices and refuses %d more", removed, was, len(refused))
		if len(bare) > 0 {
			msg += fmt.Sprintf(" and leaves %d more with no address", len(bare))
		}
		msg += fmt.Sprintf(" (%d%%), more than inventory.max_removed_percent (%d%%)", gone*100/was, maxRemovedPercent)
		if len(bare) > 0 {
			msg += "; left with no address: " + nameList(bare)
		}
```

  (the `if len(refused) > 0 {…}` block and the `return errors.New(msg + …)` that follow stay as
  they are). With no device left bare, every line reads as before, so 6a's and 6b's tests stand.
  Add `"slices"` to the imports if `diff.go` lacks it.

  In `internal/inventory/safety.go`'s `checkSafety`, after the `newly` map is filled, add:

```go
	bare := map[string]bool{}
	for _, name := range bundle.Unaddressed(prevPol, next) {
		bare[name] = true
	}
```

  and replace the counting loop and the refusal with:

```go
		removed, refused, unaddressed := 0, 0, 0
		for _, d := range was {
			switch {
			case !now[d]:
				removed++
			case newly[d]:
				refused++
			case bare[d]:
				unaddressed++
			}
		}
		if gone := removed + refused + unaddressed; gone*100 > len(was)*b {
			what := fmt.Sprintf("source %s removes %d of %d devices and refuses %d more", name, removed, len(was), refused)
			if unaddressed > 0 {
				// Pre-flight I2: port49d admits by address.
				what += fmt.Sprintf(" and leaves %d more with no address", unaddressed)
			}
			return fmt.Errorf("%s (%d%%), more than its safety.max_removed_percent (%d%%); fix the source, or, if "+
				"the change is meant, raise safety.max_removed_percent in port49-inventory.yaml and restart "+
				"port49-inventory", what, gone*100/len(was), b)
		}
```

  The words with nothing left bare are 6b's, unchanged.

- [ ] **Step 4: Run them.** `go test ./internal/bundle/ ./internal/inventory/ ./cmd/... -count=1`
  Expected: PASS, 6a's and 6b's bound tests among them.

- [ ] **Step 5: Commit** (after `make build && make test && make vet`)

```bash
git add internal/bundle internal/inventory
git commit -m "fix(inventory): a device left with no address is out of service in both bounds

port49d admits a connection by its source address, so a device kept
under its name by an attribute key group but stripped of every address
is out of service; checkSafety and bundle.CheckFrom now count it beside
removed and newly refused, and name it (plan 6c pre-flight I2).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: The webhook: authenticated by its signature, fresh, once, and only a trigger

**Files:**
- Create: `internal/inventory/webhook.go`
- Modify: `internal/inventory/metrics.go`
- Test: `internal/inventory/webhook_test.go`

**Interfaces:**
- Consumes: `Metrics`, `writeJSON`, `maxTold` (plan 6b); the deliveries L27 and L30 recorded,
  `tests/lab/sot/{fixtures,l30}/*/webhooks.json`.
- Produces:
  - Outcomes: `const HookAccepted = "accepted"`, `HookDuplicate = "duplicate"`, `HookStale = "stale"`,
    `HookBadSignature = "bad_signature"`, `HookUnsigned = "unsigned"`, `HookTooLarge = "too_large"`,
    `HookBadBody = "bad_body"`, `HookBadContentType = "bad_content_type"`,
    `HookUnknownSource = "unknown_source"`, `HookBadPath = "bad_path"`, `HookTLSHandshake = "tls_handshake"`.
  - `type Webhooks struct { Secrets map[string][]byte; Notify func(source string); Now func() time.Time; Log io.Writer; Metrics *Metrics; /* unexported */ }`;
    `func (h *Webhooks) Handler() http.Handler`.
  - `func WebhookServer(addr string, cert tls.Certificate, h http.Handler, errLog *log.Logger) *http.Server`;
    `func WebhookErrorLog(m *Metrics, out io.Writer) *log.Logger` (pre-flight M10).
  - `func parseHookTime(s string) (time.Time, error)`; `const maxWebhookBody`, `webhookWindow`, `maxSeen`.
  - Metric: `Webhooks *prometheus.CounterVec` (`port49_inventory_webhooks_total{source, outcome}`).

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/webhook_test.go`:

```go
package inventory

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const hookSecret = "l33-unit-test-webhook-secret-0123456789"

type hookRig struct {
	h        *Webhooks
	now      time.Time
	notified []string
	out      *bytes.Buffer
}

func newHookRig(now time.Time) *hookRig {
	rig := &hookRig{now: now, out: &bytes.Buffer{}}
	rig.h = &Webhooks{Secrets: map[string][]byte{"netbox_prod": []byte(hookSecret)},
		Notify: func(s string) { rig.notified = append(rig.notified, s) }, Now: func() time.Time { return rig.now },
		Log: rig.out, Metrics: NewMetrics(prometheus.NewRegistry())}
	return rig
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (rig *hookRig) deliver(path string, body []byte, sig, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.9:51000"
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if sig != "" {
		req.Header.Set("X-Hook-Signature", sig)
	}
	w := httptest.NewRecorder()
	rig.h.Handler().ServeHTTP(w, req)
	return w
}

func (rig *hookRig) count(source, outcome string) float64 {
	return testutil.ToFloat64(rig.h.Metrics.Webhooks.WithLabelValues(source, outcome))
}

func body(ts string) []byte {
	return []byte(`{"event": "updated", "timestamp": "` + ts + `", "object_type": "dcim.device", "data": {"name": "leaf-01"}}`)
}

// L27, L30: every delivery recorded, re-signed with this test's secret and
// read at the instant it arrived, is taken — both timestamp spellings,
// NetBox's (T) and Nautobot's (space).
func TestTheRecordedDeliveriesAuthenticate(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "tests", "lab", "sot", "*", "*", "webhooks.json"))
	if len(files) < 6 {
		t.Fatalf("found %d recorded webhooks.json", len(files))
	}
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Deliveries []struct {
				At   time.Time       `json:"at"`
				Body json.RawMessage `json:"body"`
			} `json:"deliveries"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		for _, d := range rec.Deliveries {
			rig := newHookRig(d.At)
			if w := rig.deliver("/v1/webhook/netbox_prod", d.Body, sign(d.Body, hookSecret), "application/json"); w.Code !=
				http.StatusAccepted || len(rig.notified) != 1 {
				t.Fatalf("%s: %d %s", f, w.Code, w.Body)
			}
			n++
		}
	}
	if n < 15 {
		t.Fatalf("only %d deliveries read", n)
	}
}

// Decision 31: an unsigned or mis-signed delivery triggers nothing, is said
// once per source and outcome, and the log never holds the secret, the
// signature or the body.
func TestAnUnsignedOrMisSignedDeliveryTriggersNothing(t *testing.T) {
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	rig := newHookRig(now)
	b := body("2026-10-01T02:00:00.000000+00:00")
	bad := sign(b, "a-different-secret-of-thirty-two-chars")
	for i := 0; i < 3; i++ {
		if w := rig.deliver("/v1/webhook/netbox_prod", b, "", "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("unsigned: %d", w.Code)
		}
		if w := rig.deliver("/v1/webhook/netbox_prod", b, bad, "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("mis-signed: %d", w.Code)
		}
		if w := rig.deliver("/v1/webhook/netbox_prod", b, "zz", "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("not hex: %d", w.Code)
		}
	}
	if len(rig.notified) != 0 || rig.count("netbox_prod", HookUnsigned) != 3 || rig.count("netbox_prod", HookBadSignature) != 6 {
		t.Fatalf("%v %v %v", rig.notified, rig.count("netbox_prod", HookUnsigned), rig.count("netbox_prod", HookBadSignature))
	}
	log := rig.out.String()
	if strings.Count(log, "(bad_signature)") != 1 || strings.Count(log, "(unsigned)") != 1 ||
		!strings.Contains(log, "port49-inventory: webhook: refused a delivery for source netbox_prod from 10.0.0.9 "+
			"(bad_signature): the webhook's secret in the source must be the value webhook_secret_env names") {
		t.Fatalf("%s", log)
	}
	for _, leak := range []string{hookSecret, bad, "leaf-01", "updated"} {
		if strings.Contains(log, leak) {
			t.Fatalf("the log holds %q: %s", leak, log)
		}
	}
}

func TestAStaleDeliveryTriggersNothing(t *testing.T) {
	b := body("2026-10-01 02:00:00.000000+00:00")
	for _, now := range []time.Time{time.Date(2026, 10, 1, 2, 5, 1, 0, time.UTC), time.Date(2026, 10, 1, 1, 54, 59, 0, time.UTC)} {
		rig := newHookRig(now)
		if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code !=
			http.StatusBadRequest || len(rig.notified) != 0 || rig.count("netbox_prod", HookStale) != 1 {
			t.Fatalf("%s: %d", now, w.Code)
		}
	}
	rig := newHookRig(time.Date(2026, 10, 1, 2, 4, 59, 0, time.UTC))
	if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code != http.StatusAccepted {
		t.Fatalf("inside the window: %d", w.Code)
	}
}

// A delivery taken once is not taken again inside the window: a replay, or
// a product's retry of one it did not see answered, triggers once.
func TestARepeatedDeliveryTriggersOnce(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	for i := 0; i < 3; i++ {
		if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code != http.StatusAccepted {
			t.Fatalf("%d", w.Code)
		}
	}
	if len(rig.notified) != 1 || rig.count("netbox_prod", HookDuplicate) != 2 || rig.count("netbox_prod", HookAccepted) != 1 {
		t.Fatalf("%v", rig.notified)
	}
}

func TestWhatIsNotADeliveryIsRefusedUnread(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	big := append([]byte(`{"timestamp": "2026-10-01T02:00:00+00:00", "x": "`), bytes.Repeat([]byte("a"), maxWebhookBody)...)
	big = append(big, `"}`...)
	for name, c := range map[string]struct {
		path  string
		body  []byte
		sig   string
		ctype string
		code  int
		label string
	}{
		"too large":    {"/v1/webhook/netbox_prod", big, sign(big, hookSecret), "application/json", 413, HookTooLarge},
		"not json":     {"/v1/webhook/netbox_prod", b, sign(b, hookSecret), "text/plain", 415, HookBadContentType},
		"no timestamp": {"/v1/webhook/netbox_prod", []byte(`{"event": "x"}`), sign([]byte(`{"event": "x"}`), hookSecret), "application/json", 400, HookBadBody},
		"unknown source": {"/v1/webhook/evil%1Bsource", b, sign(b, hookSecret), "application/json", 401, HookUnknownSource},
		"not a webhook":  {"/v1/bundle", b, sign(b, hookSecret), "application/json", 404, HookBadPath},
		"unclean path":   {"/v1/webhook/../webhook/netbox_prod", b, sign(b, hookSecret), "application/json", 404, HookBadPath},
	} {
		if w := rig.deliver(c.path, c.body, c.sig, c.ctype); w.Code != c.code {
			t.Errorf("%s: %d", name, w.Code)
		}
		src := "netbox_prod"
		if c.label == HookUnknownSource || c.label == HookBadPath {
			src = "" // the caller's text is never a label value
		}
		if rig.count(src, c.label) < 1 {
			t.Errorf("%s: not counted as %s", name, c.label)
		}
	}
	if len(rig.notified) != 0 {
		t.Fatalf("%v", rig.notified)
	}
	if strings.Contains(rig.out.String(), "evil") {
		t.Fatalf("echoed the path: %s", rig.out)
	}
}

// The first delivery a source authenticates is said, and so is the first
// after a refusal was said.
func TestAuthenticationIsSaidOnceAndAgainAfterARefusal(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	for i, ts := range []string{"2026-10-01T02:00:00.1+00:00", "2026-10-01T02:00:00.2+00:00"} {
		b := body(ts)
		rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
		if n := strings.Count(rig.out.String(), "deliveries authenticate"); n != 1 {
			t.Fatalf("delivery %d: said %d times", i, n)
		}
	}
	b := body("2026-10-01T02:00:00.3+00:00")
	rig.deliver("/v1/webhook/netbox_prod", b, "", "application/json")
	b = body("2026-10-01T02:00:00.4+00:00")
	rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
	if !strings.Contains(rig.out.String(), "port49-inventory: webhook: source netbox_prod's deliveries authenticate "+
		"again (from 10.0.0.9)") {
		t.Fatalf("%s", rig.out)
	}
}

// Pre-flight M9: every 401 has one body, so a wrong name and a right one
// read alike.
func TestEvery401ReadsAlike(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	for _, path := range []string{"/v1/webhook/netbox_prod", "/v1/webhook/not_a_source"} {
		w := rig.deliver(path, b, sign(b, "a-different-secret-of-thirty-two-chars"), "application/json")
		if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"error":"unauthorized"}` {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

// Pre-flight M11: a full cache still remembers the newest delivery.
func TestAFullReplayCacheRemembersTheNewest(t *testing.T) {
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	h := &Webhooks{}
	for i := 0; i < maxSeen; i++ {
		h.remember(fmt.Sprintf("k%d", i), now.Add(time.Duration(i)*time.Millisecond))
	}
	if !h.remember("newest", now.Add(time.Second)) || h.remember("newest", now.Add(time.Second)) {
		t.Fatal("the newest delivery was not remembered")
	}
	if len(h.seen) != maxSeen {
		t.Fatalf("%d remembered", len(h.seen))
	}
}

// Pre-flight M10: a handshake error is counted and not logged; another line
// is said once.
func TestTheWebhookErrorLogCountsHandshakes(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	var out bytes.Buffer
	l := WebhookErrorLog(m, &out)
	for i := 0; i < 3; i++ {
		l.Printf("http: TLS handshake error from 10.0.0.%d:5000: EOF", i)
		l.Printf("http: Accept error: too many open files")
	}
	if testutil.ToFloat64(m.Webhooks.WithLabelValues("", HookTLSHandshake)) != 3 ||
		strings.Count(out.String(), "Accept error") != 1 || strings.Contains(out.String(), "handshake") {
		t.Fatalf("%s", out.String())
	}
}

func TestBothRecordedTimestampSpellingsParse(t *testing.T) {
	for _, s := range []string{"2026-09-30T15:43:34.000898+00:00", "2026-09-30 15:52:04.757496+00:00",
		"2026-09-30T15:43:34+00:00"} {
		if _, err := parseHookTime(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := parseHookTime("yesterday"); err == nil {
		t.Fatal("parsed nonsense")
	}
}
```

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ -run 'Deliver|Stale|Repeated|Authenticat|Timestamp|Signed|401|Cache|ErrorLog' -count=1`
  Expected: FAIL (undefined: `Webhooks`, `parseHookTime`, …).

- [ ] **Step 3: Implement the metric.** In `internal/inventory/metrics.go`, add to `Metrics`:

```go
	// Webhooks counts deliveries on webhook_listen, by source (configuration;
	// "" when the path names none) and outcome (accepted, duplicate, stale,
	// bad_signature, unsigned, too_large, bad_body, bad_content_type,
	// unknown_source, bad_path).
	Webhooks *prometheus.CounterVec
```

  and to `NewMetrics`, before `reg.MustRegister`, registering it there too:

```go
	m.Webhooks = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_webhooks_total",
		Help: "Webhook deliveries, by source and outcome."}, []string{"source", "outcome"})
```

- [ ] **Step 4: Implement the handler.** Create `internal/inventory/webhook.go`:

```go
package inventory

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// maxWebhookBody bounds one delivery: the largest L27 and L30 recorded,
	// Nautobot 3.2.6's device update, is 18,972 bytes.
	maxWebhookBody = 1 << 20
	// webhookWindow is how far a delivery's timestamp may be from this
	// host's clock, either way. L27 and L30 recorded arrivals 0.03 s to 9.4 s
	// after it; a delivery older than the window is a replay or a backlog the
	// schedule covers.
	webhookWindow = 5 * time.Minute
	// maxSeen bounds the signatures remembered against a replay.
	maxSeen = 4096
)

// Webhook outcomes: port49_inventory_webhooks_total's outcome label.
const (
	HookAccepted       = "accepted"
	HookDuplicate      = "duplicate"
	HookStale          = "stale"
	HookBadSignature   = "bad_signature"
	HookUnsigned       = "unsigned"
	HookTooLarge       = "too_large"
	HookBadBody        = "bad_body"
	HookBadContentType = "bad_content_type"
	HookUnknownSource  = "unknown_source"
	HookBadPath        = "bad_path"
	// HookTLSHandshake counts a TLS handshake that failed: counted, never
	// logged, since the listener faces the source of truth's network and a
	// scanner would otherwise write a line per probe (pre-flight M10).
	HookTLSHandshake = "tls_handshake"
)

// hookHint is what a refusal's line tells the operator to do.
var hookHint = map[string]string{
	HookStale: "its timestamp is more than 5m from this host's clock: check NTP on both hosts; the scheduled sync " +
		"covers the change",
	HookBadSignature:   "the webhook's secret in the source must be the value webhook_secret_env names",
	HookUnsigned:       "set the webhook's secret in the source; port49-inventory takes only signed deliveries",
	HookTooLarge:       "a delivery is at most 1 MiB",
	HookBadBody:        "its body has no timestamp port49-inventory reads",
	HookBadContentType: "the webhook's HTTP content type must be application/json",
	HookUnknownSource:  "no source of that name takes webhooks: the payload URL ends /v1/webhook/<source name>",
	HookBadPath:        "the payload URL is https://<webhook_listen>/v1/webhook/<source name>",
}

// Webhooks takes NetBox's and Nautobot's deliveries (spec §10; decision 31).
// A delivery is authenticated by X-Hook-Signature, HMAC-SHA512 of its body
// under its source's webhook secret (L27, L30), and then only triggers a
// sync of that source (Notify): nothing in it reaches the bundle, so its
// order, which is not change order on Nautobot (L27, L30), orders nothing,
// and its timestamp is read only for freshness.
type Webhooks struct {
	Secrets map[string][]byte
	Notify  func(source string)
	Now     func() time.Time
	Log     io.Writer
	Metrics *Metrics

	mu   sync.Mutex
	seen map[string]time.Time
	told map[string]bool
	ok   map[string]bool
}

func (h *Webhooks) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/webhook/{source}", h.deliver)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { h.refuse(w, r, "", HookBadPath, http.StatusNotFound) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A path that is not clean is refused before the mux, which would
		// answer it with a redirect.
		if p := r.URL.Path; p == "" || p[0] != '/' || path.Clean(p) != p {
			h.refuse(w, r, "", HookBadPath, http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// deliver checks a delivery cheapest first, and reads its body only after
// its signature verifies.
func (h *Webhooks) deliver(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	secret, ok := h.Secrets[source]
	if !ok {
		// The name is the caller's text: neither counted under it nor said.
		h.refuse(w, r, "", HookUnknownSource, http.StatusUnauthorized)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		h.refuse(w, r, source, HookBadContentType, http.StatusUnsupportedMediaType)
		return
	}
	sigHex := r.Header.Get("X-Hook-Signature")
	if sigHex == "" {
		h.refuse(w, r, source, HookUnsigned, http.StatusUnauthorized)
		return
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sha512.Size {
		h.refuse(w, r, source, HookBadSignature, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			h.refuse(w, r, source, HookTooLarge, http.StatusRequestEntityTooLarge)
			return
		}
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha512.New, secret)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), sig) {
		h.refuse(w, r, source, HookBadSignature, http.StatusUnauthorized)
		return
	}
	var b struct {
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(body, &b) != nil {
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	at, err := parseHookTime(b.Timestamp)
	if err != nil {
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	now := h.Now()
	if d := now.Sub(at); d > webhookWindow || d < -webhookWindow {
		h.refuse(w, r, source, HookStale, http.StatusBadRequest)
		return
	}
	if !h.remember(source+"\x00"+hex.EncodeToString(sig), now) {
		h.Metrics.Webhooks.WithLabelValues(source, HookDuplicate).Inc()
		writeJSON(w, http.StatusAccepted, map[string]string{"outcome": HookDuplicate})
		return
	}
	h.accepted(source, r)
	h.Notify(source)
	writeJSON(w, http.StatusAccepted, map[string]string{"outcome": HookAccepted})
}

// hookLayouts are the two timestamp spellings L27 and L30 recorded:
// NetBox's (2026-09-30T15:43:34.000898+00:00) and Nautobot's
// (2026-09-30 15:52:04.757496+00:00).
var hookLayouts = []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999Z07:00"}

func parseHookTime(s string) (time.Time, error) {
	for _, l := range hookLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("not a timestamp")
}

// remember reports whether key, a source and a signature, is new inside
// twice the window — the span a delivery stays fresh — and remembers it.
// At maxSeen, expired keys are dropped, and then the soonest to expire.
func (h *Webhooks) remember(key string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[string]time.Time{}
	}
	if until, ok := h.seen[key]; ok && now.Before(until) {
		return false
	}
	if len(h.seen) >= maxSeen {
		for k, until := range h.seen {
			if !now.Before(until) {
				delete(h.seen, k)
			}
		}
	}
	if len(h.seen) >= maxSeen {
		// Still full of live entries (a bulk import): the soonest to expire
		// goes, so the newest delivery is always remembered (pre-flight M11).
		var oldest string
		for k, until := range h.seen {
			if oldest == "" || until.Before(h.seen[oldest]) {
				oldest = k
			}
		}
		delete(h.seen, oldest)
	}
	h.seen[key] = now.Add(2 * webhookWindow)
	return true
}

// refuse answers code, counts the outcome, and says it once per source and
// outcome while fewer than maxTold are remembered. The line names the
// source (configuration) and the sender's address, never the body, the
// signature, the secret or the path.
func (h *Webhooks) refuse(w http.ResponseWriter, r *http.Request, source, outcome string, code int) {
	h.Metrics.Webhooks.WithLabelValues(source, outcome).Inc()
	h.mu.Lock()
	if h.told == nil {
		h.told = map[string]bool{}
	}
	key := outcome + "\x00" + source
	say := !h.told[key] && len(h.told) < maxTold
	if say {
		h.told[key] = true
	}
	h.mu.Unlock()
	if say {
		what := "a delivery for source " + source
		if source == "" {
			what = "a delivery that names no source taking webhooks"
		}
		fmt.Fprintf(h.Log, "port49-inventory: webhook: refused %s from %s (%s): %s\n", what, remoteHost(r), outcome,
			hookHint[outcome])
	}
	// Every 401 has one body, so an unauthenticated caller cannot tell a
	// configured source's name (unsigned, bad_signature) from another
	// (unknown_source); the outcome is the metric's and the line's
	// (pre-flight M9).
	body := outcome
	if code == http.StatusUnauthorized {
		body = "unauthorized"
	}
	writeJSON(w, code, map[string]string{"error": body})
}

// accepted counts a delivery taken, and says the first a source sends, and
// the first after a refusal of that source was said.
func (h *Webhooks) accepted(source string, r *http.Request) {
	h.Metrics.Webhooks.WithLabelValues(source, HookAccepted).Inc()
	h.mu.Lock()
	if h.ok == nil {
		h.ok = map[string]bool{}
	}
	first, again := !h.ok[source], false
	h.ok[source] = true
	for k := range h.told {
		if strings.HasSuffix(k, "\x00"+source) {
			delete(h.told, k)
			again = true
		}
	}
	h.mu.Unlock()
	switch {
	case first:
		fmt.Fprintf(h.Log, "port49-inventory: webhook: source %s's deliveries authenticate (first from %s); each "+
			"triggers a sync of %s\n", source, remoteHost(r), source)
	case again:
		fmt.Fprintf(h.Log, "port49-inventory: webhook: source %s's deliveries authenticate again (from %s)\n", source,
			remoteHost(r))
	}
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "an unknown address"
	}
	return host
}

// WebhookServer serves h on addr over TLS under cert, asking no client
// certificate: no product can present one (decision 31). HTTP/1.1 only.
func WebhookServer(addr string, cert tls.Certificate, h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ErrorLog: errLog,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10, DisableGeneralOptionsHandler: true,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.NoClientCert},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}

// WebhookErrorLog is the webhook server's net/http error log: a TLS
// handshake error is counted (outcome tls_handshake, source "") and dropped;
// any other line is said once, while fewer than maxTold are remembered
// (pre-flight M10).
func WebhookErrorLog(m *Metrics, out io.Writer) *log.Logger {
	return log.New(&errorLine{m: m, out: out, said: map[string]bool{}}, "", 0)
}

type errorLine struct {
	m    *Metrics
	out  io.Writer
	mu   sync.Mutex
	said map[string]bool
}

func (e *errorLine) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "TLS handshake error") {
		e.m.Webhooks.WithLabelValues("", HookTLSHandshake).Inc()
		return len(p), nil
	}
	e.mu.Lock()
	say := !e.said[line] && len(e.said) < maxTold
	if say {
		e.said[line] = true
	}
	e.mu.Unlock()
	if say {
		fmt.Fprintf(e.out, "port49-inventory: webhook: %s\n", line)
	}
	return len(p), nil
}
```

  `"unclean path"` in the test is `/v1/webhook/../webhook/netbox_prod`: `httptest.NewRequest` keeps
  it as written, and `path.Clean` differs, so it is refused before the mux. If `NewRequest` cleans it
  on this Go version, change that case's path to `/v1/webhook//netbox_prod`.

- [ ] **Step 5: Run them.** `go test ./internal/inventory/ -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory
git commit -m "feat(inventory): webhook deliveries authenticated by HMAC-SHA512, fresh and once

POST /v1/webhook/<source>: a configured source, application/json, at
most 1 MiB, X-Hook-Signature equal in constant time to HMAC-SHA512 of
the body (L27, L30), a timestamp in either recorded spelling within 5m,
and not taken in the last 10m. Only then is the source notified. Each
refusal is counted by source and outcome and said once, naming the
sender's address, never the body, the signature or the secret
(decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: The debouncer, and `port49-inventory` serving webhooks

**Files:**
- Create: `internal/inventory/trigger.go`
- Modify: `cmd/port49-inventory/main.go`
- Test: `internal/inventory/trigger_test.go`, `cmd/port49-inventory/main_test.go`

**Interfaces:**
- Consumes: `Webhooks`, `WebhookServer` (Task 11); `Config.WebhookListen`, `WebhookTLSCertFile`,
  `WebhookTLSKeyFile`, `WebhookSources`, `WebhookSecrets` (Task 9); `keyfile.LoadX509KeyPair`;
  `broker.Limit`; `sottest.New` (Task 4); the test helpers `newFixture`, `start`, `waitFor`,
  `fixture.client`, `syncBuffer` (plan 6b).
- Produces:
  - `type Debouncer struct{ /* unexported */ }`;
    `func NewDebouncer(sources []string, settle, gap time.Duration, fire func(context.Context, string)) *Debouncer`;
    `func (d *Debouncer) Notify(source string)`; `func (d *Debouncer) Run(ctx context.Context, wg *sync.WaitGroup)`.
  - In `cmd/port49-inventory`: `var webhookSettle, webhookGap = 2 * time.Second, 30 * time.Second`;
    `var onWebhook func(addr string)`; `const maxWebhookConns = 64`.

- [ ] **Step 1: Write the failing tests.** Create `internal/inventory/trigger_test.go`:

```go
package inventory

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fires struct {
	mu sync.Mutex
	at []time.Time
}

func (f *fires) fire(context.Context, string) { f.mu.Lock(); f.at = append(f.at, time.Now()); f.mu.Unlock() }
func (f *fires) n() int                       { f.mu.Lock(); defer f.mu.Unlock(); return len(f.at) }

func runDebouncer(t *testing.T, d *Debouncer) func() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.Run(ctx, &wg)
	return func() { cancel(); wg.Wait() }
}

// Decision 31: a burst is one sync.
func TestABurstOfDeliveriesIsOneSync(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, 50*time.Millisecond, time.Hour, f.fire)
	stop := runDebouncer(t, d)
	for i := 0; i < 5; i++ {
		d.Notify("nb")
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	stop()
	if f.n() != 1 {
		t.Fatalf("%d syncs", f.n())
	}
}

// Decision 31: a flood costs one sync per gap.
func TestAFloodIsOneSyncPerGap(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, 5*time.Millisecond, 100*time.Millisecond, f.fire)
	stop := runDebouncer(t, d)
	for end := time.Now().Add(450 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		d.Notify("nb")
	}
	stop()
	if f.n() < 2 || f.n() > 6 {
		t.Fatalf("%d syncs in 450ms with a 100ms gap", f.n())
	}
	for i := 1; i < len(f.at); i++ {
		if gap := f.at[i].Sub(f.at[i-1]); gap < 90*time.Millisecond {
			t.Fatalf("syncs %s apart", gap)
		}
	}
}

// A delivery during a sync brings exactly one more after it: the change it
// announces may have come after the sync read the source.
func TestADeliveryDuringASyncBringsOneMore(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{}, 4)
	var f fires
	d := NewDebouncer([]string{"nb"}, time.Millisecond, time.Millisecond, func(ctx context.Context, s string) {
		f.fire(ctx, s)
		started <- struct{}{}
		<-release
	})
	stop := runDebouncer(t, d)
	d.Notify("nb")
	<-started
	d.Notify("nb")
	d.Notify("nb")
	d.Notify("nb")
	release <- struct{}{}
	<-started
	release <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	stop()
	if f.n() != 2 {
		t.Fatalf("%d syncs", f.n())
	}
}

func TestAnUnknownSourceIsIgnored(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, time.Millisecond, time.Millisecond, f.fire)
	stop := runDebouncer(t, d)
	d.Notify("other")
	time.Sleep(20 * time.Millisecond)
	stop()
	if f.n() != 0 {
		t.Fatalf("%d syncs", f.n())
	}
}
```

  Append to `cmd/port49-inventory/main_test.go`:

```go
const testHookSecret = "l33-unit-test-webhook-secret-0123456789"

func signHook(body []byte) string {
	mac := hmac.New(sha512.New, []byte(testHookSecret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Spec §10, decision 31: a NetBox source, its webhook on a TLS listener of
// its own, and an authentic delivery that syncs the source; a mis-signed one
// syncs nothing.
func TestAWebhookTriggersASyncOfItsSource(t *testing.T) {
	defer func(s, g time.Duration) { webhookSettle, webhookGap = s, g }(webhookSettle, webhookGap)
	webhookSettle, webhookGap = 10*time.Millisecond, 10*time.Millisecond
	const token = "nbt_abcdefabcdef.0123456789abcdef0123456789abcdef01234567"
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", token)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret)
	nb := sottest.New(t, "netbox-4", 3)
	nb.Auth = "Bearer " + token
	f := newFixture(t, 0o600)
	raw, err := os.ReadFile(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "sync: [{name: lab_file, type: file, path: "+f.source+"}]",
		fmt.Sprintf("webhook_listen: 127.0.0.1:0\nsync:\n  - {name: netbox_prod, type: netbox, url: %q, ca_file: %s, "+
			"token_secret_env: PORT49_TEST_NETBOX_TOKEN, webhook_secret_env: PORT49_TEST_NETBOX_HOOK}\n", nb.URL,
			nb.CAFile), 1)
	if cfg == string(raw) {
		t.Fatal("the fixture's sync line moved; update this test")
	}
	if err := os.WriteFile(f.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	hooks := make(chan string, 1)
	onWebhook = func(addr string) { hooks <- addr }
	defer func() { onWebhook = nil }()
	var out syncBuffer
	start(t, f, &out, make(chan os.Signal, 1))
	addr := <-hooks
	waitFor(t, &out, "sync (startup): published bundle 1")
	waitFor(t, &out, "webhooks on "+addr+" for netbox_prod")
	nb.SetDevices(4)
	c := f.client(t, testpki.InvOperatorCert, testpki.InvOperatorKey)
	post := func(sig string) int {
		b := []byte(`{"event": "created", "timestamp": "` +
			time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00") + `", "object_type": "dcim.device"}`)
		if sig == "" {
			sig = signHook(b)
		}
		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/webhook/netbox_prod", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Hook-Signature", sig)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(strings.Repeat("ab", 64)); code != http.StatusUnauthorized {
		t.Fatalf("mis-signed: %d", code)
	}
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(out.String(), "sync (webhook)") {
		t.Fatalf("a mis-signed delivery synced: %s", out)
	}
	if code := post(""); code != http.StatusAccepted {
		t.Fatalf("signed: %d", code)
	}
	waitFor(t, &out, "sync (webhook): published bundle 2")
	for _, leak := range []string{token, testHookSecret} {
		if strings.Contains(out.String(), leak) {
			t.Fatalf("the log holds a secret: %s", out)
		}
	}
}
```

  with `"bytes"`, `"crypto/hmac"`, `"crypto/sha512"`, `"encoding/hex"` and
  `"github.com/rhwendt/port49/internal/sot/sottest"` added to its imports.

- [ ] **Step 2: Run them.** `go test ./internal/inventory/ ./cmd/port49-inventory/ -run 'Burst|Flood|During|Unknown|Webhook' -count=1`
  Expected: FAIL (undefined: `NewDebouncer`, `webhookSettle`, `onWebhook`).

- [ ] **Step 3: Implement the debouncer.** Create `internal/inventory/trigger.go`:

```go
package inventory

import (
	"context"
	"sync"
	"time"
)

// Debouncer turns webhook deliveries into syncs of their source (decision
// 31). The first delivery is synced settle after it, so a burst is one
// sync; a source is synced from webhooks no sooner than gap after its last
// webhook sync began; a delivery during a sync brings one more after it,
// since the change it announces may have come after the sync read the
// source. At most one sync per source is pending, so a flood of authentic
// deliveries costs one sync per gap and queues nothing.
type Debouncer struct {
	settle, gap time.Duration
	fire        func(ctx context.Context, source string)
	kick        map[string]chan struct{}
}

func NewDebouncer(sources []string, settle, gap time.Duration, fire func(context.Context, string)) *Debouncer {
	d := &Debouncer{settle: settle, gap: gap, fire: fire, kick: map[string]chan struct{}{}}
	for _, s := range sources {
		d.kick[s] = make(chan struct{}, 1)
	}
	return d
}

// Notify asks for a sync of source. It never blocks: a source with a sync
// pending is not asked twice, and one Run does not know is ignored.
func (d *Debouncer) Notify(source string) {
	if ch, ok := d.kick[source]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Run starts one goroutine per source, each added to wg and ended by ctx.
func (d *Debouncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	for name, ch := range d.kick {
		wg.Add(1)
		go func(name string, ch chan struct{}) {
			defer wg.Done()
			var last time.Time
			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
				}
				wait := d.settle
				if !last.IsZero() {
					if g := time.Until(last.Add(d.gap)); g > wait {
						wait = g
					}
				}
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
				// Deliveries during the wait are covered by the sync about to
				// start; only those during the sync bring another.
				select {
				case <-ch:
				default:
				}
				last = time.Now()
				d.fire(ctx, name)
			}
		}(name, ch)
	}
}
```

- [ ] **Step 4: Wire it into the binary.** In `cmd/port49-inventory/main.go`:

  After `var onListening func(api, metrics string)`, add:

```go
// onWebhook is told the webhook listener's address; a test's hook.
var onWebhook func(addr string)

// webhookSettle and webhookGap are the debouncer's (decision 31): a burst is
// one sync 2s after its first delivery, and a source is synced from webhooks
// at most once per 30s. Variables for the tests.
var webhookSettle, webhookGap = 2 * time.Second, 30 * time.Second

// maxWebhookConns caps the webhook listener's connections: its callers are a
// source of truth's few workers.
const maxWebhookConns = 64
```

  After the `broker.LoadTLS` block, add:

```go
	// The webhook's certificate: the API's, or its own (decision 31), read
	// before any listener opens.
	wcert := cert
	if cfg.WebhookTLSCertFile != "" {
		if wcert, err = keyfile.LoadX509KeyPair(cfg.WebhookTLSCertFile, cfg.WebhookTLSKeyFile); err != nil {
			return fmt.Errorf("webhook_tls_cert_file %s, webhook_tls_key_file %s: %w", cfg.WebhookTLSCertFile,
				cfg.WebhookTLSKeyFile, err)
		}
	}
```

  Move the `syncNow` closure (and its comment) up to just after `srv.BaseContext = …`, and move
  `var tickers sync.WaitGroup` (and its comment) up to just before the API's `ln, err := net.Listen`.
  After `go func() { apiErr <- srv.ServeTLS(broker.Limit(ln, maxConns), "", "") }()`, add:

```go
	// Webhooks (decision 31): a TLS listener of their own, asking no client
	// certificate, and a debouncer per source, joined with the tickers.
	var webhookErr chan error // nil, so never ready, with no webhook source
	var wsrv *http.Server
	webhooks := ""
	if cfg.WebhookListen != "" {
		wln, err := net.Listen("tcp", cfg.WebhookListen)
		if err != nil {
			srv.Close()
			<-apiErr
			stopMetrics()
			return fmt.Errorf("webhook_listen %s: %w", cfg.WebhookListen, err)
		}
		deb := inventory.NewDebouncer(cfg.WebhookSources(), webhookSettle, webhookGap,
			func(_ context.Context, name string) { syncNow("webhook", name) })
		hooks := &inventory.Webhooks{Secrets: cfg.WebhookSecrets(), Notify: deb.Notify, Now: time.Now, Log: stderr,
			Metrics: m}
		wsrv = inventory.WebhookServer(cfg.WebhookListen, wcert, hooks.Handler(), inventory.WebhookErrorLog(m, stderr))
		webhookErr = make(chan error, 1)
		go func() { webhookErr <- wsrv.ServeTLS(broker.Limit(wln, maxWebhookConns), "", "") }()
		deb.Run(ctx, &tickers)
		webhooks = fmt.Sprintf("; webhooks on %s for %s", wln.Addr(), strings.Join(cfg.WebhookSources(), ", "))
		if onWebhook != nil {
			onWebhook(wln.Addr().String())
		}
	}
```

  Give `shutdown` a third parameter and close the webhook server with the others:

```go
	shutdown := func(apiDone, metricsDone, webhookDone bool) {
		cancel()
		shut, done := context.WithTimeout(context.Background(), grace)
		defer done()
		if err := srv.Shutdown(shut); err != nil {
			srv.Close()
		}
		if err := msrv.Shutdown(shut); err != nil {
			msrv.Close()
		}
		if wsrv != nil {
			if err := wsrv.Shutdown(shut); err != nil {
				wsrv.Close()
			}
		}
		reqs.wait()
		if !apiDone {
			<-apiErr
		}
		if !metricsDone {
			<-metricsErr
		}
		if wsrv != nil && !webhookDone {
			<-webhookErr
		}
		tickers.Wait()
	}
```

  Append `webhooks` to the start line: change its format's tail `"%d source(s): %s\n"` to
  `"%d source(s): %s%s\n"` and add `webhooks` as its last argument. In the main loop, change
  `shutdown(false, false)` to `shutdown(false, false, false)`, `shutdown(true, false)` to
  `shutdown(true, false, false)`, `shutdown(false, true)` to `shutdown(false, true, false)`, and add:

```go
		case err := <-webhookErr:
			shutdown(false, false, true)
			return fmt.Errorf("webhook_listen %s: %w", cfg.WebhookListen, err)
```

  A delivery only calls `Notify`, which never blocks; every sync it brings runs under `ctx` through
  `syncNow`, so a shutdown ends it as it ends a scheduled one, and the debouncer's goroutines are
  joined with the tickers.

- [ ] **Step 5: Run them.** `go test ./internal/inventory/ ./cmd/port49-inventory/ -count=1` and
  `go test -race ./internal/inventory/ ./cmd/port49-inventory/ -count=1`
  Expected: PASS, with no race reported.

- [ ] **Step 6: Commit** (after `make build && make test && make vet`)

```bash
git add internal/inventory cmd/port49-inventory
git commit -m "feat(inventory): port49-inventory takes webhooks and syncs their source, debounced

webhook_listen is a TLS listener of its own (no product can present a
client certificate); an authentic delivery notifies a per-source
debouncer: one sync 2s after a burst's first delivery, at most one per
30s, one more for a delivery during a sync, none queued. Its goroutines
and server are joined at shutdown (decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: `port49 inventory export`, verified, from the bundle published or the history

**Files:**
- Create: `internal/admission/encode.go`
- Modify: `internal/inventory/api.go` (`bundle`), `internal/inventory/sync.go` (`At`),
  `internal/inventory/client.go` (`BundleAt`)
- Modify: `cmd/port49/inventory.go` (`inventoryCmd`, `inventoryExport`, `stringsFlag`),
  `cmd/port49/main.go` (the usage text)
- Test: `internal/admission/encode_test.go`, `internal/inventory/api_test.go`,
  `cmd/port49/inventory_service_test.go`

**Interfaces:**
- Consumes: `bundle.Open`, `bundle.ID`, `bundle.MaxDocument`; `keyfile.ParseEd25519Public`,
  `keyfile.EncodeEd25519`; `State.At`, `ErrNotKept`, `ErrNoBundle`; `Client.do`, `answer`,
  `readBounded`, `clean`; `serviceFlags`, `diffWait`, `startService` (plan 6b).
- Produces:
  - `func admission.EncodeFile(inv Inventory) ([]byte, error)` — `ParseFile` reads it back to the
    same devices.
  - `func (s *Syncer) At(seq int64) (*Published, error)`.
  - `GET /v1/bundle?sequence=N` (the read right): 200 and the sealed bundle, 400 `not_a_sequence`,
    404 `not_kept`, 503 `no_bundle`.
  - `func (c *Client) BundleAt(ctx context.Context, seq int64) ([]byte, error)`.
  - `port49 inventory export --service URL --ca FILE --cert FILE --key FILE --verify-key FILE [--verify-key FILE] [--from SEQUENCE] [--out FILE]`;
    `func inventoryExport(args []string, stdout, stderr io.Writer) int`; `type stringsFlag []string`.
  - `testService` gains `pub string` (its `signing.pub`).

- [ ] **Step 1: Write the failing tests.** Create `internal/admission/encode_test.go`:

```go
package admission

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestAnEncodedFileReadsBackToTheSameDevices(t *testing.T) {
	inv := Inventory{Devices: []Device{
		{Name: "leaf-02", Platform: "arista_eos", Transport: TransportTCP,
			Addresses:  []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("10.0.0.2")},
			Attributes: map[string]string{"site": "dc1", "os_version": "4.31.2F", "flag": "true", "n": "42"}},
		{Name: "leaf-01", Platform: "eos-lab", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "tls-01", Platform: "arista_eos", Transport: TransportTLS},
	}}
	raw, err := EncodeFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(raw), "leaf-01") > strings.Index(string(raw), "leaf-02") ||
		!strings.Contains(string(raw), "transport: tls") || strings.Contains(string(raw), "transport: tcp") {
		t.Fatalf("%s", raw)
	}
	back, err := ParseFile(raw, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	byName := map[string]Device{}
	for _, d := range back.Devices {
		byName[d.Name] = d
	}
	for _, d := range inv.Devices {
		got := byName[d.Name]
		want := d
		if len(want.Addresses) > 1 && want.Addresses[0].Compare(want.Addresses[1]) > 0 {
			want.Addresses = []netip.Addr{want.Addresses[1], want.Addresses[0]}
		}
		if got.Platform != want.Platform || got.Transport != want.Transport || !reflect.DeepEqual(got.Attributes, want.Attributes) ||
			len(got.Addresses) != len(want.Addresses) || (len(got.Addresses) > 0 && !reflect.DeepEqual(got.Addresses, want.Addresses)) {
			t.Errorf("%s: %+v, want %+v", d.Name, got, want)
		}
	}
	if _, err := EncodeFile(Inventory{KeyGroups: []KeyGroup{{Name: "leaf-01", KeyRef: "k"}}}); err == nil {
		t.Fatal("encoded key groups")
	}
}
```

  Append to `internal/inventory/api_test.go`:

```go
// Spec §12: inventory export --from reads a bundle from the history, with
// the read right.
func TestABundleFromTheHistoryIsServedToAReader(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle?sequence=1", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if doc, inv, err := bundle.Open(body, rig.pubs()); err != nil || doc.Sequence != 1 || len(inv.Devices) != 3 {
		t.Fatalf("%v %v", doc.Sequence, err)
	}
	for path, code := range map[string]int{"/v1/bundle?sequence=2": 200, "/v1/bundle?sequence=99": 404,
		"/v1/bundle?sequence=x": 400, "/v1/bundle?sequence=0": 400, "/v1/bundle?sequence=1&x=2": 400} {
		if resp, body := rig.do(t, rig.reader, "GET", path, nil); resp.StatusCode != code {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if resp, _ := rig.do(t, rig.nobody, "GET", "/v1/bundle?sequence=1", nil); resp.StatusCode != 403 {
		t.Fatalf("nobody: %d", resp.StatusCode)
	}
}
```

  In `cmd/port49/inventory_service_test.go`, give `testService` a `pub string` field and, in
  `startService`, replace `_, key, _ := ed25519.GenerateKey(rand.Reader)` with:

```go
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, pubPEM, err := keyfile.EncodeEd25519(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.pub"), pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
```

  and set `pub: filepath.Join(dir, "signing.pub")` in the `testService` literal. Append:

```go
func exportArgs(svc *testService, more ...string) []string {
	return append([]string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key, "--verify-key", svc.pub}, more...)
}

// Spec §12: the export is a file the offline tools take, for the same
// bundle the service published, and it never writes over a file.
func TestInventoryExportWritesWhatTheOfflineToolsRead(t *testing.T) {
	svc := startService(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2, \"2001:db8::2\"], "+
		"attributes: {site: dc1}}\n")
	svc.sync(t)
	out := filepath.Join(t.TempDir(), "inventory.yaml")
	var stdout, stderr bytes.Buffer
	if code := run(exportArgs(svc, "--out", out), &stdout, &stderr); code != 0 ||
		!strings.Contains(stderr.String(), "port49 inventory export: bundle 1, 2 device(s), written to "+out) {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the export's mode is %v, not 0600", fi.Mode().Perm()) // pre-flight M8
	}
	inv, err := admission.LoadFile(out)
	if err != nil || len(inv.Devices) != 2 {
		t.Fatalf("%+v %v", inv, err)
	}
	pol, err := os.ReadFile(filepath.Join(svc.dir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := bundle.ID(pol, inv), svc.syncer.Current().Doc.Bundle; got != want {
		t.Fatalf("the export is bundle %s, the service published %s", got, want)
	}
	stderr.Reset()
	if code := run(exportArgs(svc, "--out", out), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "exists") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestInventoryExportReadsTheHistory(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	var stdout, stderr bytes.Buffer
	if code := run(exportArgs(svc, "--from", "1"), &stdout, &stderr); code != 0 ||
		!strings.HasPrefix(stdout.String(), "# port49 inventory export: bundle 1 (sha256:") ||
		!strings.Contains(stdout.String(), "name: leaf-01") || strings.Contains(stdout.String(), "leaf-02") {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run(exportArgs(svc, "--from", "99"), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "answered 404 (not_kept)") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// Decision 31: a bundle that does not open under the verify keys writes
// nothing.
func TestInventoryExportVerifiesBeforeItWrites(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPEM, _ := keyfile.EncodeEd25519(other)
	otherPub := filepath.Join(t.TempDir(), "other.pub")
	if err := os.WriteFile(otherPub, otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "inventory.yaml")
	args := []string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key,
		"--verify-key", otherPub, "--out", out}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "does not open under "+
		"--verify-key") || stdout.Len() != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("wrote a file")
	}
	if code := run([]string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key}, &stdout, &stderr); code != 2 {
		t.Fatalf("no --verify-key: exit %d", code)
	}
}

// Pre-flight M7: a genuine bundle that is not the one --from asked for is
// refused. The stub answers bundle 2 to every ask.
func TestInventoryExportFromChecksTheSequence(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	two := svc.syncer.Current().Raw
	stub := serveTLS(t, filepath.Join(svc.dir, "pki"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(two)
	}))
	out := filepath.Join(t.TempDir(), "inventory.yaml")
	args := []string{"inventory", "export", "--service", stub, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key,
		"--verify-key", svc.pub, "--from", "1", "--out", out}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "the service answered bundle 2 for --from 1") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("wrote a file")
	}
}
```

  with `"github.com/rhwendt/port49/internal/admission"`, `"github.com/rhwendt/port49/internal/bundle"`
  and `"github.com/rhwendt/port49/internal/keyfile"` imported.

- [ ] **Step 2: Run them.** `go test ./internal/admission/ ./internal/inventory/ ./cmd/port49/ -run 'Encoded|History|Export' -count=1`
  Expected: FAIL (undefined: `EncodeFile`; `/v1/bundle?sequence=1` serves the published bundle; no
  `export` subcommand).

- [ ] **Step 3: Implement `EncodeFile`.** Create `internal/admission/encode.go`:

```go
package admission

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// EncodeFile is inv as an inventory file, the schema ParseFile reads:
// devices in name order, each one's addresses sorted, its transport left out
// when it is tcp. ParseFile reads it back to the same devices. Key groups are
// not written: the one caller, `port49 inventory export`, writes a bundle
// document's inventory, which carries none (spec §13, decision 30), so an
// inventory with key groups is an error rather than a file that drops them.
func EncodeFile(inv Inventory) ([]byte, error) {
	if len(inv.KeyGroups) > 0 {
		return nil, errors.New("admission: EncodeFile writes devices only, and this inventory carries key_groups")
	}
	type device struct {
		Name       string            `yaml:"name"`
		Platform   string            `yaml:"platform"`
		Addresses  []string          `yaml:"addresses"`
		Attributes map[string]string `yaml:"attributes,omitempty"`
		KeyRef     string            `yaml:"key_ref,omitempty"`
		Transport  string            `yaml:"transport,omitempty"`
	}
	out := struct {
		Devices []device `yaml:"devices"`
	}{Devices: []device{}}
	devs := slices.Clone(inv.Devices)
	slices.SortFunc(devs, func(a, b Device) int { return strings.Compare(a.Name, b.Name) })
	for _, d := range devs {
		e := device{Name: d.Name, Platform: d.Platform, Addresses: []string{}, Attributes: d.Attributes, KeyRef: d.KeyRef}
		if d.Transport != "" && d.Transport != TransportTCP {
			e.Transport = d.Transport
		}
		addrs := slices.Clone(d.Addresses)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, a := range addrs {
			e.Addresses = append(e.Addresses, a.String())
		}
		out.Devices = append(out.Devices, e)
	}
	return yaml.Marshal(out)
}
```

- [ ] **Step 4: Implement the history read.** In `internal/inventory/sync.go`, after `Diff`, add:

```go
// At is bundle seq: the one published, or one state_dir's history keeps,
// opened against the service's own keys (spec §12, `inventory export
// --from`). ErrNoBundle before the first; ErrNotKept for one not kept.
func (s *Syncer) At(seq int64) (*Published, error) {
	cur := s.current.Load()
	if cur == nil {
		return nil, ErrNoBundle
	}
	if cur.Doc.Sequence == seq {
		return cur, nil
	}
	return s.State.At(seq, s.keys())
}
```

  In `internal/inventory/api.go`, replace `bundle` with:

```go
// bundle is GET /v1/bundle: the bundle published, or with ?sequence=N bundle
// N from the history (spec §12, `inventory export --from`). The query takes
// sequence alone.
func (a *API) bundle(w http.ResponseWriter, r *http.Request, caller string) {
	p := a.Syncer.Current()
	if q := r.URL.Query(); len(q) > 0 {
		v, ok := q["sequence"]
		seq, err := int64(0), error(nil)
		if ok && len(q) == 1 && len(v) == 1 {
			seq, err = strconv.ParseInt(v[0], 10, 64)
		}
		if !ok || len(q) != 1 || len(v) != 1 || err != nil || seq < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not_a_sequence"})
			return
		}
		switch p, err = a.Syncer.At(seq); {
		case errors.Is(err, ErrNoBundle):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
			return
		case errors.Is(err, ErrNotKept):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_kept"})
			return
		case err != nil:
			// The service's own text, for its operator, once per caller.
			if a.tell("bundle_at_failed " + caller) {
				fmt.Fprintf(a.Log, "port49-inventory: api: bundle %d: %s\n", seq, oneLine(err))
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
	}
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
```

  In `internal/inventory/client.go`, after `bundle`, add:

```go
// BundleAt is bundle seq from the service's history, sealed and not yet
// trusted: the caller opens it (bundle.Open) against its verify keys.
func (c *Client) BundleAt(ctx context.Context, seq int64) ([]byte, error) {
	resp, err := c.do(ctx, "GET", "/v1/bundle", url.Values{"sequence": {strconv.FormatInt(seq, 10)}}, nil)
	if err != nil {
		return nil, clean(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, clean(answer(resp, nil, 0))
	}
	defer resp.Body.Close()
	raw, err := readBounded(resp.Body, bundle.MaxDocument)
	if err != nil {
		return nil, clean(err)
	}
	return raw, nil
}
```

- [ ] **Step 5: Implement the command.** In `cmd/port49/inventory.go`, add to `inventoryCmd` beside
  the others:

```go
	if len(args) > 0 && args[0] == "export" {
		return inventoryExport(args[1:], stdout, stderr)
	}
```

  and add:

```go
// stringsFlag is a flag given once per value.
type stringsFlag []string

func (f *stringsFlag) String() string     { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(v string) error { *f = append(*f, v); return nil }

// inventoryExport is `port49 inventory export` (spec §12): the bundle the
// service publishes, or bundle --from from its history, opened against
// --verify-key as port49d opens it (decision 31), and its inventory written
// in inventory_file's schema — to --out, never over an existing file, or to
// standard output — so the offline tools keep an --inventory when no source
// is a file. A bundle that does not open writes nothing.
func inventoryExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	svc := serviceFlags(fs)
	var verify stringsFlag
	fs.Var(&verify, "verify-key", "the service's public key (signing.pub), as port49d's verify_key_files holds it; "+
		"once per key")
	from := fs.Int64("from", 0, "a bundle's sequence in the service's history (default: the bundle it publishes)")
	outPath := fs.String("out", "", "the file to write, which must not exist, mode 0600 (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !svc.complete() || len(verify) == 0 || fs.NArg() != 0 || *from < 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var keys []ed25519.PublicKey
	for _, p := range verify {
		raw, err := os.ReadFile(p)
		var k ed25519.PublicKey
		if err == nil {
			k, err = keyfile.ParseEd25519Public(raw, p)
		}
		if err != nil {
			fmt.Fprintln(stderr, "port49 inventory export: --verify-key:", err)
			return 1
		}
		keys = append(keys, k)
	}
	c, err := inventory.NewClient(svc.url, svc.ca, svc.cert, svc.key)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), diffWait)
	defer cancel()
	var raw []byte
	if *from > 0 {
		raw, err = c.BundleAt(ctx, *from)
	} else {
		raw, _, _, err = c.Bundle(ctx, "")
	}
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		fmt.Fprintf(stderr, "port49 inventory export: the service's bundle does not open under --verify-key: %s; "+
			"nothing is written\n", inventory.Printable(err.Error()))
		return 1
	}
	if *from > 0 && doc.Sequence != *from {
		// A genuine bundle, but not the one asked for (pre-flight M7).
		fmt.Fprintf(stderr, "port49 inventory export: the service answered bundle %d for --from %d; nothing is "+
			"written\n", doc.Sequence, *from)
		return 1
	}
	body, err := admission.EncodeFile(inv)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	header := fmt.Sprintf("# port49 inventory export: bundle %d (%s), published %s, from %s.\n"+
		"# The inventory service's facts only: no key assignment (spec §13, decision 30).\n", doc.Sequence, doc.Bundle,
		doc.PublishedAt.Format(time.RFC3339), inventory.Printable(svc.url))
	body = append([]byte(header), body...)
	where := ""
	if *outPath == "" {
		stdout.Write(body)
	} else {
		if err := writeNew(*outPath, body); err != nil {
			fmt.Fprintln(stderr, "port49 inventory export:", err)
			return 1
		}
		where = ", written to " + *outPath
	}
	fmt.Fprintf(stderr, "port49 inventory export: bundle %d, %d device(s)%s\n", doc.Sequence, len(inv.Devices), where)
	return 0
}

// writeNew writes body to path, which must not exist, 0600, and syncs it; a
// failure removes what it wrote. 0600: the fleet list and its addresses are
// not for the world, as plan 6b made the mirror 0640 (pre-flight M8).
func writeNew(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists; an export is written beside no old one", path)
		}
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
```

  with `"github.com/rhwendt/port49/internal/admission"` imported. In `cmd/port49/main.go`'s usage
  text, after the `port49 inventory sync …` line, add:

```
  port49 inventory export --service URL --ca FILE --cert FILE --key FILE --verify-key FILE [--from SEQUENCE] [--out FILE]
      (--out is written 0600, never over an existing file)
```

- [ ] **Step 6: Run them.** `go test ./internal/admission/ ./internal/inventory/ ./cmd/port49/ -count=1`
  Expected: PASS.

- [ ] **Step 7: Commit** (after `make build && make test && make vet`)

```bash
git add internal/admission internal/inventory cmd/port49
git commit -m "feat(port49): inventory export, verified, from the published bundle or the history

GET /v1/bundle?sequence=N serves a kept bundle to a reader. export opens
the bundle against --verify-key before it writes anything, and writes
its inventory in inventory_file's schema, which reads back to the same
bundle, to standard output or a new --out file (spec §12; decision 31).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: (lab, on beehive, Compose) The connectors as built, through two kinds of TLS proxy: L32

**Files:**
- Modify: `internal/testpki/testpki.go` (`Leaf.DNSNames`)
- Create: `tests/lab/cmd/sot-pki/main.go`
- Create: `tests/lab/sot/compose/l32-proxy-host.conf`, `tests/lab/sot/compose/l32-proxy-xfh.conf`
- Modify: `tests/lab/sot/compose/netbox-3.7.yml`, `netbox-4.yml`, `nautobot-1.6.yml`, `nautobot-2.yml`,
  `nautobot-3.yml`; `tests/lab/sot/run.sh`; `tests/lab/sot/README.md`
- Create: `tests/lab/l32_test.go`, `tests/lab/l32_unit_test.go`
- Create (by the runs): `tests/lab/sot/l32/<stack>/connector.json`; `tests/lab/results/L32-netbox.md`,
  `tests/lab/results/L32-nautobot.md`

**Interfaces:**
- Consumes: `sot.New`, `sot.Config`, `sot.Mapping`, `sot.NewSecret` (Tasks 2–8); `testpki.NewCA`,
  `Issue`, `PEMs`; `run.sh`'s stacks and recorder (plan 6a Task 2, plan 6b Task 2).
- Produces:
  - `testpki.Leaf.DNSNames []string`.
  - `go run ./tests/lab/cmd/sot-pki -dir DIR` — `ca.pem`, `proxy.pem`/`proxy-key.pem` (127.0.0.1,
    `localhost`), `webhook.pem`/`webhook-key.pem` (`port49-inventory.lab`, 127.0.0.1); keys 0600.
  - `run.sh <stack> l32|l33|e2e`: the `l32` Compose profile (`proxy_host` on port+2000, `proxy_xfh` on
    port+3000), 120 devices seeded by the recorder into `tests/lab/logs/<mode>-<stack>-seed/` (never
    committed), then `go test -tags lab -run '^TestL32Connector$'` (or Task 15's tests) with
    `L32_STACK`, `L32_PRODUCT`, `L32_CA`, `L32_HOST_URL`, `L32_XFH_URL`, `L33_DIRECT_URL`, `L33_PKI`,
    `L33_HOOK_BIND` in its environment and `L27_TOKEN` inherited.
  - `type l32Record`, `l32Probe`, `l32Read`; `func l32Map(stack string) map[string]string`;
    `func TestL32Connector(t *testing.T)`; `func TestL32FixturesAreWhatTheNotesSay(t *testing.T)`.

The row's question is L30's remainder and the connector's own query. The proxy that sends the
client's host as `Host` alone (`proxy_host`) is the shape L30 measured, now with TLS; the one that
sends the upstream's name as `Host` and the client's as `X-Forwarded-Host` (`proxy_xfh`) separates the
two headers. Whichever a release reads, the connector must read all 120 devices through both, and say
a rebuilt `next` where it rebuilt one.

- [ ] **Step 1: The lab PKI.** In `internal/testpki/testpki.go`, add `DNSNames []string` to `Leaf`
  (after `Emails`) and `DNSNames: l.DNSNames,` to the `x509.Certificate` literal in `Issue`. Create
  `tests/lab/cmd/sot-pki/main.go`:

```go
// Command sot-pki writes the L32 and L33 lab PKI into -dir (plan 6c Tasks 14
// and 15): one CA (ca.pem); the TLS proxies' certificate (proxy.pem,
// proxy-key.pem: 127.0.0.1 and localhost, which the connector dials); and
// port49-inventory's webhook certificate (webhook.pem, webhook-key.pem:
// port49-inventory.lab, the name the stack's worker resolves to the host,
// and 127.0.0.1). Valid for a day; keys 0600. run.sh writes it into the
// run's private temporary directory and removes it on exit.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func main() {
	dir := flag.String("dir", "", "the directory to write into")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "sot-pki: -dir is required")
		os.Exit(2)
	}
	if err := write(*dir, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "sot-pki:", err)
		os.Exit(1)
	}
}

func write(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := testpki.NewCA("port49 lab sot CA", nb, na)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), ca.PEM(), 0o644); err != nil {
		return err
	}
	for _, l := range []struct {
		leaf      testpki.Leaf
		cert, key string
	}{
		{testpki.Leaf{CommonName: "l32 proxy", IPs: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}},
			"proxy.pem", "proxy-key.pem"},
		{testpki.Leaf{CommonName: "port49-inventory webhook", IPs: []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames: []string{"port49-inventory.lab"}}, "webhook.pem", "webhook-key.pem"},
	} {
		l.leaf.NotBefore, l.leaf.NotAfter = nb, na
		c, err := ca.Issue(l.leaf)
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := testpki.PEMs(c)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, l.cert), certPEM, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, l.key), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 2: The proxies.** Create `tests/lab/sot/compose/l32-proxy-host.conf`:

```
# L32: a TLS-terminating reverse proxy that forwards the client's Host and says
# the client spoke https; no X-Forwarded-Host. run.sh substitutes nautobot:8080
# for Nautobot.
server {
    listen 8443 ssl;
    ssl_certificate     /etc/port49-lab/proxy.pem;
    ssl_certificate_key /etc/port49-lab/proxy-key.pem;
    location / {
        proxy_pass http://netbox:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

  and `tests/lab/sot/compose/l32-proxy-xfh.conf`:

```
# L32: a TLS-terminating reverse proxy that sends the upstream's own name as
# Host and the client's host as X-Forwarded-Host, so which one a release builds
# next from can be told apart. run.sh substitutes nautobot:8080 for Nautobot.
server {
    listen 8443 ssl;
    ssl_certificate     /etc/port49-lab/proxy.pem;
    ssl_certificate_key /etc/port49-lab/proxy-key.pem;
    location / {
        proxy_pass http://netbox:8080;
        proxy_set_header Host netbox:8080;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

  In each of the five compose files, after the `proxy:` service, add (with `nautobot` for
  `netbox` in `depends_on` in the three Nautobot files):

```yaml
  proxy_host:
    profiles: ["l32"]
    image: docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10   # tag 1.27-alpine
    ports: ["127.0.0.1:${L32_HOST_PORT:?}:8443"]
    volumes: ["${L32_HOST_CONF:?}:/etc/nginx/conf.d/default.conf:ro", "${L32_PKI:?}:/etc/port49-lab:ro"]
    depends_on: [netbox]
  proxy_xfh:
    profiles: ["l32"]
    image: docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10   # tag 1.27-alpine
    ports: ["127.0.0.1:${L32_XFH_PORT:?}:8443"]
    volumes: ["${L32_XFH_CONF:?}:/etc/nginx/conf.d/default.conf:ro", "${L32_PKI:?}:/etc/port49-lab:ro"]
    depends_on: [netbox]
```

  and to the worker service (`netbox-worker`, `nautobot-worker`), for Task 15's deliveries:

```yaml
    extra_hosts: ["port49-inventory.lab:host-gateway"]
    volumes: ["${L32_PKI:?}/ca.pem:/etc/port49-lab/ca.pem:ro"]
```

  Compose interpolates every service, profiled or not, so `run.sh` sets every `L32_*` variable on
  every run, as it does L30's.

- [ ] **Step 3: `run.sh`'s new modes.** In `tests/lab/sot/run.sh`:

  Change the second-argument check to accept `l32`, `l33` and `e2e` beside `legacy` and `l30`, and its
  usage line to `[legacy|l30|l32|l33|e2e]`. Directly after `trap 'exit 3' TERM INT` (so the cleanup
  trap already removes `$tmp`, key material included, if anything below fails: pre-flight M17a; the
  env file does not exist yet, so the cleanup calls no `docker compose` without these variables),
  add:

```bash
# L32 and L33 (plan 6c): two TLS proxies in the l32 profile, and the lab PKI they
# and port49-inventory's webhook present. Set on every run, as L30's are.
pki=$tmp/pki
go run ./tests/lab/cmd/sot-pki -dir "$pki"
export L32_PKI=$pki L32_HOST_PORT=$((port + 2000)) L32_XFH_PORT=$((port + 3000))
export L32_HOST_CONF=$tmp/l32-proxy-host.conf L32_XFH_CONF=$tmp/l32-proxy-xfh.conf
sed "s/netbox:8080/$upstream:8080/g" "$root/tests/lab/sot/compose/l32-proxy-host.conf" >"$L32_HOST_CONF"
sed "s/netbox:8080/$upstream:8080/g" "$root/tests/lab/sot/compose/l32-proxy-xfh.conf" >"$L32_XFH_CONF"
chmod 644 "$L32_HOST_CONF" "$L32_XFH_CONF"
```

  After the `if [ "$legacy" = l30 ]; then … fi` block, add:

```bash
case $legacy in
l32 | l33 | e2e)
	# The recorder seeds 120 devices and records into logs, never into the
	# committed fixtures; the Go test after it is the run's measurement.
	out=$root/tests/lab/logs/$legacy-$stack-seed
	log=$root/tests/lab/logs/$legacy-$stack.log
	flags+=(-devices 120 -page-limit 50)
	[ "$stack" = nautobot-1.6 ] && flags+=(-prefer-legacy)
	profile=(--profile l32)
	;;
esac
```

  Replace the script's last three lines (from `echo "run.sh: recorder exit $rc …"`) with:

```bash
echo "run.sh: recorder exit $rc at $(date -u +%FT%TZ)" | tee -a "$log"
grep -E '^sot-record: (netbox|nautobot) at ' "$log" || true
case $legacy in l32) test=TestL32Connector ;; l33) test=TestL33Webhooks ;; e2e) test=TestSoTDeviceEndToEnd ;; *) test="" ;; esac
if [ "$rc" = 0 ] && [ -n "$test" ]; then
	# The host's docker0 address: host-gateway, as the worker resolves
	# port49-inventory.lab.
	bridge=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
	extra=()
	[ "$legacy" = e2e ] && extra=(PORT49_LAB_PLATFORMS=eos)
	env "${extra[@]}" L32_STACK="$stack" L32_PRODUCT="$product" L32_CA="$pki/ca.pem" \
		L32_HOST_URL="https://127.0.0.1:$L32_HOST_PORT" L32_XFH_URL="https://127.0.0.1:$L32_XFH_PORT" \
		L33_DIRECT_URL="http://127.0.0.1:$port" L33_PKI="$pki" L33_HOOK_BIND="$bridge:18444" \
		timeout 3600 go test -tags lab ./tests/lab/ -run "^$test\$" -count=1 -timeout 55m -v >>"$log" 2>&1 || rc=$?
	echo "run.sh: $test exit $rc at $(date -u +%FT%TZ)" | tee -a "$log"
fi
exit "$rc"
```

  `L27_TOKEN` reaches the test from the sourced env file; the test sends it and records no
  `Authorization` header. In `tests/lab/sot/README.md`, add the three modes to "Running" with one
  line each, and a paragraph: "`l32`, `l33` and `e2e` (plan 6c) seed 120 devices into
  `tests/lab/logs/<mode>-<stack>-seed/`, which is never committed, bring up the `l32` profile's two
  TLS proxies, and run one Go test against the stack: `TestL32Connector` writes
  `tests/lab/sot/l32/<stack>/connector.json`, `TestL33Webhooks` writes
  `tests/lab/sot/l33/<stack>/webhooks.json`, and `TestSoTDeviceEndToEnd` (with the vEOS topology)
  writes its results note."

- [ ] **Step 4: The measurement.** Create `tests/lab/l32_test.go`:

```go
//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/sot"
)

// l32Record is one stack's L32 run: what `next` named through each proxy,
// and what the connector, as built, read through each, over GraphQL and REST.
type l32Record struct {
	Stack  string     `json:"stack"`
	At     time.Time  `json:"at"`
	Built  string     `json:"built"`
	Probes []l32Probe `json:"probes"`
	Reads  []l32Read  `json:"reads"`
}

// l32Probe is the first page of the device list read through a proxy: the
// scheme and host its next names, and the host its first result's url names.
type l32Probe struct {
	Proxy      string `json:"proxy"`
	Status     int    `json:"status"`
	NextScheme string `json:"next_scheme"`
	NextHost   string `json:"next_host"`
	ResultHost string `json:"result_host"`
}

// l32Read is one Fetch by the connector as built.
type l32Read struct {
	Proxy   string         `json:"proxy"`
	API     string         `json:"api"`
	Seconds float64        `json:"seconds"`
	Devices int            `json:"devices"`
	Said    []string       `json:"said"`
	Leaf01  map[string]any `json:"leaf_01,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// l32Map is what an L32 read maps on stack: the paths both APIs give on its
// profile (Nautobot 1.6 gives network_driver over GraphQL only), and the
// recorded custom field.
func l32Map(stack string) map[string]string {
	if stack == "nautobot-2" || stack == "nautobot-3" {
		return map[string]string{"platform": "platform.network_driver", "site": "location.name", "role": "role.name",
			"os_version": "custom_fields.os_version"}
	}
	return map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug",
		"os_version": "custom_fields.os_version"}
}

// l32Client trusts the run's lab CA alone.
func l32Client(t *testing.T) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("L32_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw)
	return &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// l32Auth is the Authorization the connector sends (L27): never recorded.
func l32Auth() string {
	tok := os.Getenv("L27_TOKEN")
	if os.Getenv("L32_PRODUCT") == "netbox" && strings.HasPrefix(tok, "nbt_") {
		return "Bearer " + tok
	}
	return "Token " + tok
}

func l32ProbeNext(t *testing.T, proxy, base string) l32Probe {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/dcim/devices/?limit=50", nil)
	req.Header.Set("Authorization", l32Auth())
	resp, err := l32Client(t).Do(req)
	if err != nil {
		t.Fatalf("probe through %s: %v", proxy, err)
	}
	defer resp.Body.Close()
	var page struct {
		Next    string `json:"next"`
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	}
	json.NewDecoder(resp.Body).Decode(&page)
	p := l32Probe{Proxy: proxy, Status: resp.StatusCode}
	if u, err := url.Parse(page.Next); err == nil {
		p.NextScheme, p.NextHost = u.Scheme, u.Host
	}
	if len(page.Results) > 0 {
		if u, err := url.Parse(page.Results[0].URL); err == nil {
			p.ResultHost = u.Host
		}
	}
	return p
}

// TestL32Connector reads one running stack (run.sh <stack> l32) through
// both proxies, over GraphQL (every interface address asked for) and over
// REST, 50 to a page, with the connector as built, and writes
// tests/lab/sot/l32/<stack>/connector.json. A read that fails, or reads
// other than the 120 devices the run seeded, fails the test: the claim the
// code rests on is then wrong (CLAUDE.md lab rule 4).
func TestL32Connector(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> l32")
	}
	rec := l32Record{Stack: stack, At: time.Now().UTC(), Built: l29Built()}
	for _, px := range []struct{ name, url string }{{"host", os.Getenv("L32_HOST_URL")}, {"xfh", os.Getenv("L32_XFH_URL")}} {
		rec.Probes = append(rec.Probes, l32ProbeNext(t, px.name, px.url))
		for _, api := range []string{"graphql", "rest"} {
			var said bytes.Buffer
			src, err := sot.New(sot.Config{Name: "l32", Product: os.Getenv("L32_PRODUCT"), URL: px.url,
				CAFile: os.Getenv("L32_CA"), Token: sot.NewSecret(os.Getenv("L27_TOKEN")), API: api, PageSize: 50,
				Mapping: sot.Mapping{Map: l32Map(stack), Filter: sot.Filter{Status: []string{"active"}},
					Addresses: sot.Addresses{Primary: true, AllInterfaces: api == "graphql"}}, Log: &said})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			t0 := time.Now()
			inv, err := src.Fetch(ctx)
			cancel()
			r := l32Read{Proxy: px.name, API: api, Seconds: time.Since(t0).Seconds(),
				Said: strings.Split(strings.TrimSpace(said.String()), "\n")}
			if err != nil {
				r.Error = err.Error()
				t.Errorf("%s through %s over %s: %v", stack, px.name, api, err)
			} else {
				r.Devices = len(inv.Devices)
				for _, d := range inv.Devices {
					if d.Name == "leaf-01" {
						var as []string
						for _, a := range d.Addresses {
							as = append(as, a.String())
						}
						r.Leaf01 = map[string]any{"platform": d.Platform, "attributes": d.Attributes, "addresses": as}
					}
				}
				wantAddrs := "10.0.1.5"
				if api == "graphql" {
					wantAddrs = "10.0.1.5 10.0.1.6"
				}
				if r.Devices != 120 || r.Leaf01 == nil || r.Leaf01["platform"] != "arista_eos" ||
					strings.Join(r.Leaf01["addresses"].([]string), " ") != wantAddrs {
					t.Errorf("%s through %s over %s: %d devices, leaf-01 %v", stack, px.name, api, r.Devices, r.Leaf01)
				}
			}
			rec.Reads = append(rec.Reads, r)
		}
	}
	dir := filepath.Join(root, "tests", "lab", "sot", "l32", stack)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "connector.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
```

  Create `tests/lab/l32_unit_test.go`:

```go
//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// noteLine is whether one line of note holds every needle: a register
// note's table row, checked against its record cell by cell, so a word
// elsewhere in the note cannot stand in for it (pre-flight I3).
func noteLine(note string, needles ...string) bool {
	for _, line := range strings.Split(note, "\n") {
		all := true
		for _, n := range needles {
			all = all && n != "" && strings.Contains(line, n)
		}
		if all {
			return true
		}
	}
	return false
}

// TestL32FixturesAreWhatTheNotesSay reads every L32 record: it carries no
// credential; it holds two probes, each answered 200 with a next naming a
// host, and four reads; and its product's note names its directory, has a
// row per probe naming the stack, the proxy and the host next named, and a
// row per read naming the stack, the proxy, the API and either the device
// count or "failed" (pre-flight I3).
func TestL32FixturesAreWhatTheNotesSay(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("sot", "l32", "*", "connector.json"))
	if len(files) == 0 {
		t.Skip("no L32 records yet")
	}
	for _, f := range files {
		stack := filepath.Base(filepath.Dir(f))
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"Authorization", "nbt_", "Token "} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("%s carries %q", f, leak)
			}
		}
		var rec l32Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		note, err := os.ReadFile(filepath.Join("results", "L32-"+strings.SplitN(stack, "-", 2)[0]+".md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l32/"+stack+"/") {
			t.Errorf("the note does not name tests/lab/sot/l32/%s/", stack)
		}
		if len(rec.Probes) != 2 || len(rec.Reads) != 4 {
			t.Fatalf("%s: %d probes and %d reads, want 2 and 4", stack, len(rec.Probes), len(rec.Reads))
		}
		for _, p := range rec.Probes {
			if p.Status != 200 || p.NextHost == "" {
				t.Errorf("%s: the %s probe answered %d with next host %q: it measured nothing", stack, p.Proxy,
					p.Status, p.NextHost)
			}
			if !noteLine(string(note), stack, "proxy_"+p.Proxy, p.NextHost) {
				t.Errorf("%s: no note row says next named %s through proxy_%s", stack, p.NextHost, p.Proxy)
			}
		}
		for _, r := range rec.Reads {
			want := strconv.Itoa(r.Devices)
			if r.Error != "" {
				want = "failed"
			} else if r.Devices != 120 {
				t.Errorf("%s %s %s: %d devices and no error", stack, r.Proxy, r.API, r.Devices)
			}
			if !noteLine(string(note), stack, "proxy_"+r.Proxy, r.API, want) {
				t.Errorf("%s: no note row names the %s read through proxy_%s with %q", stack, r.API, r.Proxy, want)
			}
		}
	}
}
```

- [ ] **Step 5: Commit the harness.** `make build && make test && make vet` (report them), then:

```bash
git add internal/testpki tests/lab/cmd/sot-pki tests/lab/sot tests/lab/l32_test.go tests/lab/l32_unit_test.go
git commit -m "test(lab): L32's harness: the connectors as built, through two TLS proxies

run.sh <stack> l32 seeds 120 devices, brings up a proxy that forwards
the client's Host and one that sends the upstream's name as Host and the
client's as X-Forwarded-Host, and runs TestL32Connector, which reads the
stack with sot.Source over GraphQL and REST through each and records
what next named (spec §15 L32).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

- [ ] **Step 6: Run it** from a detached worktree pinned to the Step 5 commit ("Running the lab"),
  one stack at a time, each 3–6 minutes once the images are pulled:

```bash
git worktree add --detach ../port49-lab-6c <step-5-sha> && cd ../port49-lab-6c && make build
for s in netbox-3.7 netbox-4 nautobot-1.6 nautobot-2 nautobot-3; do
  L27_ENV_DIR=$(mktemp -d) tests/lab/sot/run.sh "$s" l32 || echo "FAILED: $s"
done
```

  Watch `tests/lab/logs/l32-<stack>.log`; a log with no new line in 10 minutes is a stall. After each
  stack, run the count-only audit from `tests/lab/sot/README.md` over `tests/lab/sot/l32` with that
  run's `L27_ENV_DIR`; it must print 0. Copy `tests/lab/sot/l32/` back to the branch's checkout.

  **If a read fails** (a GraphQL error naming a field, a count that does not match, a `next` refused),
  the code is wrong about the release, not the release about the code (CLAUDE.md lab rule 4). Keep
  the record as it is, fix the profile or the reader on the branch with a test that replays the
  failure through `sottest`, commit the fix, and rerun that stack from a worktree pinned to the fix.

- [ ] **Step 7: Write the notes.** Write `tests/lab/results/L32-netbox.md` and `L32-nautobot.md` in
  `L30-netbox.md`'s form: date; versions (from each record's said line, `NetBox 4.7.1, profile
  netbox_4, over GraphQL`); images (the compose files' digests, nginx's among them); the two proxy
  configs; the runs (`run.sh <stack> l32`, at the worktree's commit, the record's `built`); the
  capture pointer (`tests/lab/sot/l32/<stack>/`); the credentials statement (random per run, no
  `Authorization` recorded, the audit's 0); and **Status: measured; closed by plan 6c Task 16**. Its
  Observation table has, per stack: `next` through `proxy_host` (scheme and host); `next` through
  `proxy_xfh` (scheme and host), and so which header the release builds `next` from — the client's
  host there means `X-Forwarded-Host`, `netbox:8080` or `nautobot:8080` means `Host`; each of the
  four reads' device count and seconds; whether a rebuilt `next` was said; leaf-01 as read. Its "Not
  observed" lists what the run did not ask (a GraphQL list above any server cap; a list changing
  between pages). Quote every value from the record; infer nothing the record does not hold. The
  unit test reads the rows (pre-flight I3), so write one row per probe, `| <stack> | proxy_<host|xfh>
  | next: <scheme>://<next_host> | … |`, and one per read, `| <stack> | proxy_<host|xfh> |
  <graphql|rest> | <devices> devices, <seconds> s | … |`, with `failed: <error>` in place of the
  count for a read that failed.

- [ ] **Step 8: Check and commit the evidence.** `make lab-unit` (runs `TestL32FixturesAreWhatTheNotesSay`),
  `make test && make vet`, then:

```bash
git add tests/lab/sot/l32 tests/lab/results/L32-netbox.md tests/lab/results/L32-nautobot.md
git commit -m "test(lab): L32 measured: the connectors read every release through both proxies

Five releases, two TLS proxies, GraphQL and REST, 50 to a page: <one
line per product from the notes: which header next is built from, and
the reads' counts>. The row closes in Task 16.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  (The `<…>` in the message is filled from the notes when the commit is made; it is the one part of
  this plan written after a measurement.)

---

### Task 15: (lab, on beehive) Webhooks to port49-inventory from every release, and a NetBox and a Nautobot to vEOS: L33

**Files:**
- Modify: `tests/lab/inventory_test.go` (`startInventory` split into `newLabInventory` and
  `startInventoryWith`; `labInventory.mark`, `waitLine`)
- Create: `tests/lab/sot_admin_test.go`, `tests/lab/l33_test.go`, `tests/lab/l33_unit_test.go`,
  `tests/lab/sot_e2e_test.go`
- Create (by the runs): `tests/lab/sot/l33/<stack>/webhooks.json`; `tests/lab/results/L33-netbox.md`,
  `L33-nautobot.md`, `L33-e2e-netbox-arista_eos.md`, `L33-e2e-nautobot-arista_eos.md`;
  `tests/lab/evidence/L33-e2e-*.pcap` (redacted)

**Interfaces:**
- Consumes: Task 14's `run.sh` modes and environment, `l32Map`, `l29Built`; Tasks 9–12's
  `port49-inventory`; the harness's `eachPlatform`, `l.serviceConfig`, `l.l28Restart`, `l.errMark`,
  `l.waitForLine`, `l.timedLogins`, `l.capture`, `l.dial`, `l29Agent`, `l29Mint`, `l29Heartbeat`,
  `l29RestoreStanding`, `l.l29Note`, `privateDir`, `writeAtomic`, `oneLine`, `sliceUser` (plans 6b,
  6b1).
- Produces:
  - `func newLabInventory(t *testing.T, name string) *labInventory`;
    `func startInventoryWith(t *testing.T, li *labInventory, policyPath, syncYAML string, env []string) *labInventory`;
    `func (li *labInventory) mark() int64`;
    `func (li *labInventory) waitLine(t *testing.T, from int64, want string, within time.Duration) (time.Time, bool)`.
  - `type sotAdmin`; `func newSoTAdmin(t *testing.T) *sotAdmin`; its `call`, `first`, `webhook`,
    `removeWebhooks`, `createDevice`, `patchDevice`, `deleteDevice`, `addPrimary`, `statusWord`.
  - `type l33Record`, `l33Phase`; `func TestL33Webhooks(t *testing.T)`;
    `func TestL33FixturesAreWhatTheNotesSay(t *testing.T)`; `func TestSoTDeviceEndToEnd(t *testing.T)`.

L33 asks four things of each release: does it deliver to an `https` URL under a private CA
(`ca_file_path`, verification on); does port49-inventory authenticate what arrives; how long from the
API write to the published bundle; is a refused (401) delivery sent again. The device run then takes
the whole path once per product: a change in NetBox 4.7.1 and in Nautobot 3.2.6 reaching vEOS's
admission through the webhook, the service and port49d.

- [ ] **Step 1: Split `startInventory`.** In `tests/lab/inventory_test.go`, replace `startInventory`
  with the three functions below. The body is plan 6b's, divided where the file source's line was;
  the readiness wait grows to 2 minutes, since a source of truth's first sync reads 120 devices.

```go
// newLabInventory is a labInventory's directories, the inventory lab PKI and
// a signing key `port49 inventory keygen` wrote, named for name. Nothing is
// started. It refuses to go on beside a service this run does not own.
func newLabInventory(t *testing.T, name string) *labInventory {
	t.Helper()
	if c, err := net.DialTimeout("tcp", inventoryAddr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("something already listens on %s, most likely a port49-inventory left by an interrupted run; "+
			"stop it: pkill -f bin/port49-inventory", inventoryAddr)
	}
	logs := filepath.Join(root, "tests", "lab", "logs")
	li := &labInventory{dir: filepath.Join(logs, "inventory-"+name), pki: filepath.Join(logs, "inventory-pki"),
		errPath: filepath.Join(logs, "port49-inventory-"+name+".log"), done: make(chan struct{})}
	if err := os.RemoveAll(li.dir); err != nil {
		t.Fatal(err)
	}
	// 0755 whatever the umask: the file source is read behind the fence,
	// which refuses a group-writable directory (spec §5.1.3).
	for _, d := range []string{li.dir, filepath.Join(li.dir, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := testpki.WriteInventoryLab(li.pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(li.dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	// Its output names the files and the key_id, never the key; it is
	// printed only on a failure.
	kctx, kcancel := context.WithTimeout(context.Background(), 30*time.Second)
	out, err := exec.CommandContext(kctx, filepath.Join(root, "bin", "port49"), "inventory", "keygen", "--dir", keys).CombinedOutput()
	kcancel()
	if err != nil {
		t.Fatalf("port49 inventory keygen (run `make build` first): %v: %s", err, out)
	}
	li.pubFile = filepath.Join(keys, "signing.pub")
	li.source, li.policy = filepath.Join(li.dir, "src", "inventory.yaml"), filepath.Join(li.dir, "policy.yaml")
	return li
}

// startInventory starts the service with source as its file source's
// content and a copy of policyPath as its policy. The service syncs at
// start, so it is ready — /readyz 200 — once it has published bundle 1.
func (l *lab) startInventory(t *testing.T, source, policyPath string) *labInventory {
	t.Helper()
	li := newLabInventory(t, l.p.name)
	li.writeSource(t, source)
	return startInventoryWith(t, li, policyPath,
		fmt.Sprintf("sync: [{name: lab_file, type: file, path: %s}]\n", li.source), nil)
}

// startInventoryWith starts li's service with a copy of policyPath as its
// policy and syncYAML as the end of its configuration (its sync: block, and
// any webhook keys), with env added to its environment (a webhook secret's
// variable; never logged), and waits until it is ready.
func startInventoryWith(t *testing.T, li *labInventory, policyPath, syncYAML string, env []string) *labInventory {
	t.Helper()
	li.writePolicy(t, policyPath)
	keys := filepath.Dir(li.pubFile)
	cfg := filepath.Join(li.dir, "port49-inventory.yaml")
	body := fmt.Sprintf(`listen: %s
metrics_listen: %s
tls_cert_file: %s/%s
tls_key_file: %s/%s
client_ca_file: %s/%s
readers: [%q]
syncers: ["user:alice@slice.port49.test"]
signing_key_file: %s/signing.key
policy_file: %s
state_dir: %s/state
`, inventoryAddr, inventoryMetricsAddr, li.pki, testpki.InvServerCert, li.pki, testpki.InvServerKey, li.pki,
		testpki.InvCA, testpki.InvDaemonID, keys, li.policy, li.dir) + syncYAML
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	errFile, err := os.Create(li.errPath)
	if err != nil {
		t.Fatal(err)
	}
	li.cmd = exec.Command(filepath.Join(root, "bin", "port49-inventory"), "-config", cfg)
	li.cmd.Dir, li.cmd.Stdout, li.cmd.Stderr = root, errFile, errFile
	if env != nil {
		li.cmd.Env = append(os.Environ(), env...)
	}
	if err := li.cmd.Start(); err != nil {
		errFile.Close()
		t.Fatal(err)
	}
	go func() { li.cmd.Wait(); errFile.Close(); close(li.done) }()
	t.Cleanup(li.stop)
	probe := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if resp, err := probe.Get("http://" + inventoryMetricsAddr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("port49-inventory ready on %s (log %s)", inventoryAddr, li.errPath)
				return li
			}
		}
		select {
		case <-li.done:
			raw, _ := os.ReadFile(li.errPath)
			t.Fatalf("port49-inventory exited during startup:\n%s", raw)
		default:
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(li.errPath)
			t.Fatalf("port49-inventory not ready in 2m:\n%s", raw)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// mark is the end of the service's log now, for waitLine.
func (li *labInventory) mark() int64 {
	fi, err := os.Stat(li.errPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// waitLine polls the service's log, after from, for a line containing want.
func (li *labInventory) waitLine(t *testing.T, from int64, want string, within time.Duration) (time.Time, bool) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if raw, err := os.ReadFile(li.errPath); err == nil && int64(len(raw)) >= from &&
			strings.Contains(string(raw[from:]), want) {
			return time.Now(), true
		}
	}
	t.Logf("port49-inventory did not say %q within %s", want, within)
	return time.Time{}, false
}
```

  Run `make lab-unit` and `go vet -tags lab ./tests/lab/` to show the split compiles and the L29
  helpers still read the same.

- [ ] **Step 2: The harness's hands on a stack.** Create `tests/lab/sot_admin_test.go`:

```go
//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// sotAdmin is the harness's hands on a running stack (run.sh <stack> l33 or
// e2e): the writes a test makes so the connector has something to read,
// over the stack's own plain-HTTP port, as the recorder seeds it. It is
// never the connector's path. Its errors carry status codes and the
// product's error text, never the token.
type sotAdmin struct {
	stack, product, base, auth string
	c                          *http.Client
}

func newSoTAdmin(t *testing.T) *sotAdmin {
	t.Helper()
	stack := os.Getenv("L32_STACK")
	return &sotAdmin{stack: stack, product: strings.SplitN(stack, "-", 2)[0], base: os.Getenv("L33_DIRECT_URL"),
		auth: l32Auth(), c: &http.Client{Timeout: time.Minute}}
}

// nautobot2 is a stack that spells Nautobot 2.x's way (L27, L30): role,
// location, statuses by name.
func (a *sotAdmin) nautobot2() bool { return a.stack == "nautobot-2" || a.stack == "nautobot-3" }

// statusWord is s as the stack writes a status: "Active" on Nautobot 2.x
// and 3.x, "active" elsewhere (L27).
func (a *sotAdmin) statusWord(s string) string {
	if a.nautobot2() {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func (a *sotAdmin) call(method, path string, body any) (int, map[string]any, error) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", a.auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var m map[string]any
	json.Unmarshal(raw, &m)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, m, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, oneLine(string(raw)))
	}
	return resp.StatusCode, m, nil
}

// first is results[0] of a GET.
func (a *sotAdmin) first(path string) (map[string]any, error) {
	_, m, err := a.call(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	rs, _ := m["results"].([]any)
	if len(rs) == 0 {
		return nil, fmt.Errorf("GET %s: no results", path)
	}
	r, _ := rs[0].(map[string]any)
	return r, nil
}

func idOf(v any) any { m, _ := v.(map[string]any); return m["id"] }

// removeWebhooks deletes every event rule (NetBox) and webhook named name:
// the recorder's, which point at a listener that has gone.
func (a *sotAdmin) removeWebhooks(name string) error {
	paths := []string{"/api/extras/webhooks/"}
	if a.product == "netbox" {
		paths = []string{"/api/extras/event-rules/", "/api/extras/webhooks/"}
	}
	for _, p := range paths {
		_, m, err := a.call(http.MethodGet, p+"?name="+url.QueryEscape(name), nil)
		if err != nil {
			return err
		}
		rs, _ := m["results"].([]any)
		for _, r := range rs {
			if _, _, err := a.call(http.MethodDelete, fmt.Sprintf("%s%v/", p, idOf(r)), nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// webhook creates a webhook for device create, update and delete, to
// payload, signed with secret, verified against the CA at caPath inside the
// worker; NetBox also needs an event rule, in its release's spelling (L27).
// It returns each call's status, for the note.
func (a *sotAdmin) webhook(name, payload, secret, caPath string) ([]string, error) {
	hook := map[string]any{"name": name, "payload_url": payload, "http_method": "POST",
		"http_content_type": "application/json", "secret": secret, "ssl_verification": true, "ca_file_path": caPath,
		"enabled": true}
	if a.product == "nautobot" {
		hook["content_types"] = []any{"dcim.device"}
		hook["type_create"], hook["type_update"], hook["type_delete"] = true, true, true
	}
	status, m, err := a.call(http.MethodPost, "/api/extras/webhooks/", hook)
	calls := []string{fmt.Sprintf("webhook %d", status)}
	if err != nil || a.product == "nautobot" {
		return calls, err
	}
	rule := map[string]any{"name": name, "action_type": "webhook", "action_object_type": "extras.webhook",
		"action_object_id": m["id"], "enabled": true}
	if a.stack == "netbox-3.7" {
		rule["content_types"] = []any{"dcim.device"}
		rule["type_create"], rule["type_update"], rule["type_delete"] = true, true, true
	} else {
		rule["object_types"] = []any{"dcim.device"}
		rule["event_types"] = []any{"object_created", "object_updated", "object_deleted"}
	}
	status, _, err = a.call(http.MethodPost, "/api/extras/event-rules/", rule)
	return append(calls, fmt.Sprintf("event_rule %d", status)), err
}

// createDevice creates name as leaf-01 is: its type, role, site or location
// and platform, status active.
func (a *sotAdmin) createDevice(name string) (any, error) {
	leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"name": name, "device_type": idOf(leaf["device_type"]), "platform": idOf(leaf["platform"]),
		"status": a.statusWord("active")}
	switch {
	case a.product == "netbox":
		body["role"], body["site"] = idOf(leaf["role"]), idOf(leaf["site"])
	case a.stack == "nautobot-1.6":
		body["device_role"], body["site"] = idOf(leaf["device_role"]), idOf(leaf["site"])
	default:
		body["role"], body["location"] = idOf(leaf["role"]), idOf(leaf["location"])
	}
	_, m, err := a.call(http.MethodPost, "/api/dcim/devices/", body)
	if err != nil {
		return nil, err
	}
	return m["id"], nil
}

func (a *sotAdmin) patchDevice(id any, body map[string]any) error {
	_, _, err := a.call(http.MethodPatch, fmt.Sprintf("/api/dcim/devices/%v/", id), body)
	return err
}

func (a *sotAdmin) deleteDevice(id any) error {
	_, _, err := a.call(http.MethodDelete, fmt.Sprintf("/api/dcim/devices/%v/", id), nil)
	return err
}

// addPrimary gives device id an interface Management1 holding addr, and
// makes addr its primary IPv4, as the recorder's seed does per release
// (tests/lab/cmd/sot-record/seed.go): Nautobot 2.x and 3.x need the address's
// parent prefix and bind it through ip-address-to-interface.
func (a *sotAdmin) addPrimary(id any, addr string) error {
	itf := map[string]any{"device": id, "name": "Management1", "type": "virtual"}
	if a.product == "nautobot" {
		itf["status"] = a.statusWord("active")
	}
	_, m, err := a.call(http.MethodPost, "/api/dcim/interfaces/", itf)
	if err != nil {
		return err
	}
	ifID := m["id"]
	var ipID any
	if a.nautobot2() {
		prefix := strings.Join(strings.Split(strings.TrimSuffix(addr, "/32"), ".")[:3], ".") + ".0/24"
		a.call(http.MethodPost, "/api/ipam/prefixes/", map[string]any{"prefix": prefix, "status": "Active"})
		p, err := a.first("/api/ipam/prefixes/?prefix=" + url.QueryEscape(prefix))
		if err != nil {
			return err
		}
		_, ip, err := a.call(http.MethodPost, "/api/ipam/ip-addresses/", map[string]any{"address": addr,
			"status": "Active", "parent": p["id"]})
		if err != nil {
			return err
		}
		ipID = ip["id"]
		if _, _, err := a.call(http.MethodPost, "/api/ipam/ip-address-to-interface/",
			map[string]any{"ip_address": ipID, "interface": ifID}); err != nil {
			return err
		}
	} else {
		ip := map[string]any{"address": addr, "assigned_object_type": "dcim.interface", "assigned_object_id": ifID}
		if a.product == "nautobot" {
			ip["status"] = "active"
		}
		_, m, err := a.call(http.MethodPost, "/api/ipam/ip-addresses/", ip)
		if err != nil {
			return err
		}
		ipID = m["id"]
	}
	return a.patchDevice(id, map[string]any{"primary_ip4": ipID})
}
```

- [ ] **Step 3: The webhook measurement.** Create `tests/lab/l33_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/inventory"
)

// l33Record is one stack's L33 run.
type l33Record struct {
	Stack        string     `json:"stack"`
	At           time.Time  `json:"at"`
	Built        string     `json:"built"`
	WebhookCalls []string   `json:"webhook_calls"`
	Phases       []l33Phase `json:"phases"`
	// Refused is the wrong-secret webhook's run: bad_signature deliveries
	// counted in the 120s after one change, so 1 is "not sent again".
	RefusedChange string `json:"refused_change"`
	BadSignature  int    `json:"bad_signature"`
	Stale         int    `json:"stale"`
}

// l33Phase is one change in the source of truth and what followed it.
type l33Phase struct {
	Change    string  `json:"change"`
	Accepted  int     `json:"accepted"`
	Published bool    `json:"published"`
	Seconds   float64 `json:"seconds"` // the API write to the service's "sync (webhook): published" line
}

// l33Policy is the service's policy for L33: every device the stack's map
// puts at site dc1 is admitted, so a sync is never refused as admitting
// none.
const l33Policy = `scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {attributes: {site: dc1}}, key_ref: lab_key}]
`

// l33Secret is a random webhook secret for one run: 48 of [A-Za-z0-9].
func l33Secret(t *testing.T) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 48)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

// l33SyncYAML is the sync: block and webhook keys for a stack as source
// l33, through the host proxy, read on a 24h interval so every publication
// after the first is a webhook's.
func l33SyncYAML(stack, product string) string {
	pki := os.Getenv("L33_PKI")
	var m []string
	for k, v := range l32Map(stack) {
		m = append(m, k+": "+v)
	}
	return fmt.Sprintf(`webhook_listen: %s
webhook_tls_cert_file: %s/webhook.pem
webhook_tls_key_file: %s/webhook-key.pem
sync:
  - name: l33
    type: %s
    url: %s
    ca_file: %s/ca.pem
    token_secret_env: L27_TOKEN
    webhook_secret_env: L33_WEBHOOK_SECRET
    interval: 24h
    map: {%s}
`, os.Getenv("L33_HOOK_BIND"), pki, pki, product, os.Getenv("L32_HOST_URL"), pki, strings.Join(m, ", "))
}

// l33Counts is port49_inventory_webhooks_total{source="l33"} by outcome.
func l33Counts(t *testing.T) map[string]int {
	t.Helper()
	resp, err := http.Get("http://" + inventoryMetricsAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]int{}
	re := regexp.MustCompile(`port49_inventory_webhooks_total\{outcome="([a-z_]+)",source="l33"\} (\d+)`)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		n, _ := strconv.Atoi(m[2])
		out[m[1]] = n
	}
	return out
}

// TestL33Webhooks runs one stack (run.sh <stack> l33) into port49-inventory
// with webhooks on, and writes tests/lab/sot/l33/<stack>/webhooks.json.
func TestL33Webhooks(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" || os.Getenv("L33_HOOK_BIND") == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> l33")
	}
	a := newSoTAdmin(t)
	rec := l33Record{Stack: stack, At: time.Now().UTC(), Built: l29Built()}
	policy := filepath.Join(privateDir(t, "l33-"+stack), "policy.yaml")
	writeAtomic(t, policy, []byte(l33Policy), 0o600)
	secret := l33Secret(t)
	li := newLabInventory(t, "l33-"+stack)
	startInventoryWith(t, li, policy, l33SyncYAML(stack, a.product), []string{"L33_WEBHOOK_SECRET=" + secret})
	if err := a.removeWebhooks("l27"); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(os.Getenv("L33_HOOK_BIND"))
	payload := "https://port49-inventory.lab:" + port + "/v1/webhook/l33"
	calls, err := a.webhook("port49-l33", payload, secret, "/etc/port49-lab/ca.pem")
	rec.WebhookCalls = calls
	if err != nil {
		t.Fatalf("creating the webhook: %v", err)
	}
	var created any
	for _, ch := range []struct {
		name string
		do   func() error
	}{
		{"update leaf-01's os_version", func() error {
			leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
			if err != nil {
				return err
			}
			return a.patchDevice(leaf["id"], map[string]any{"custom_fields": map[string]any{"os_version": "4.33.0F"}})
		}},
		{"create leaf-200", func() (err error) { created, err = a.createDevice("leaf-200"); return err }},
		{"delete leaf-200", func() error { return a.deleteDevice(created) }},
	} {
		before, mark := l33Counts(t)[inventory.HookAccepted], li.mark()
		t0 := time.Now()
		if err := ch.do(); err != nil {
			t.Fatalf("%s: %v", ch.name, err)
		}
		at, ok := li.waitLine(t, mark, "sync (webhook): published bundle", 2*time.Minute)
		ph := l33Phase{Change: ch.name, Published: ok, Accepted: l33Counts(t)[inventory.HookAccepted] - before}
		if ok {
			ph.Seconds = at.Sub(t0).Seconds()
			if ph.Accepted < 1 {
				// The interval is 24h, so only a webhook publishes; a
				// publication with no accepted delivery is not one.
				t.Errorf("%s: published with no accepted delivery counted", ch.name)
			}
		} else {
			t.Errorf("%s: no publication through the webhook in 2m", ch.name)
		}
		rec.Phases = append(rec.Phases, ph)
		// Past the debouncer's 30s gap, so the next change's time is its own.
		time.Sleep(35 * time.Second)
	}
	// A webhook with the wrong secret: refused 401, and counted for 120s to
	// see whether the release sends it again.
	if err := a.removeWebhooks("port49-l33"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.webhook("port49-l33-wrong", payload, l33Secret(t), "/etc/port49-lab/ca.pem"); err != nil {
		t.Fatal(err)
	}
	before := l33Counts(t)[inventory.HookBadSignature]
	rec.RefusedChange = "update leaf-01's os_version, under the wrong secret"
	leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
	if err == nil {
		err = a.patchDevice(leaf["id"], map[string]any{"custom_fields": map[string]any{"os_version": "4.33.1F"}})
	}
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Second)
	counts := l33Counts(t)
	rec.BadSignature, rec.Stale = counts[inventory.HookBadSignature]-before, counts[inventory.HookStale]
	if rec.BadSignature < 1 {
		t.Errorf("no bad_signature delivery arrived in 120s")
	}
	a.removeWebhooks("port49-l33-wrong")
	if raw, _ := os.ReadFile(li.errPath); strings.Contains(string(raw), secret) {
		t.Fatal("the service's log holds the webhook secret")
	}
	dir := filepath.Join(root, "tests", "lab", "sot", "l33", stack)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "webhooks.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
```

  Create `tests/lab/l33_unit_test.go`:

```go
//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestL33FixturesAreWhatTheNotesSay reads every L33 record: no secret or
// token in it; three phases and the webhook's create calls; and in its
// product's note, its directory, a row per published phase naming the
// stack, the change and its seconds to two places, a row per unpublished
// phase naming the stack, the change and "failed", and a row naming the
// stack and the bad_signature count (pre-flight I3; noteLine is
// l32_unit_test.go's).
func TestL33FixturesAreWhatTheNotesSay(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("sot", "l33", "*", "webhooks.json"))
	if len(files) == 0 {
		t.Skip("no L33 records yet")
	}
	for _, f := range files {
		stack := filepath.Base(filepath.Dir(f))
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"secret\":", "Authorization", "nbt_", "X-Hook-Signature"} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("%s carries %q", f, leak)
			}
		}
		var rec l33Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		note, err := os.ReadFile(filepath.Join("results", "L33-"+strings.SplitN(stack, "-", 2)[0]+".md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l33/"+stack+"/") {
			t.Errorf("the note does not name tests/lab/sot/l33/%s/", stack)
		}
		if len(rec.Phases) != 3 || len(rec.WebhookCalls) == 0 {
			t.Fatalf("%s: %d phases and %d webhook calls, want 3 and some", stack, len(rec.Phases), len(rec.WebhookCalls))
		}
		for _, p := range rec.Phases {
			want := fmt.Sprintf("%.2f", p.Seconds)
			if !p.Published {
				want = "failed"
			} else if p.Accepted < 1 {
				t.Errorf("%s: %q published with no accepted delivery counted", stack, p.Change)
			}
			if !noteLine(string(note), stack, p.Change, want) {
				t.Errorf("%s: no note row names %q with %q", stack, p.Change, want)
			}
		}
		if !noteLine(string(note), stack, "bad_signature", strconv.Itoa(rec.BadSignature)) {
			t.Errorf("%s: no note row gives bad_signature %d", stack, rec.BadSignature)
		}
	}
}
```

- [ ] **Step 4: The device run.** Create `tests/lab/sot_e2e_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sotE2EClaim = "A change in a source of truth reaches a device's admission through the webhook, the " +
	"inventory service and port49d (spec §15 L33, the device run): the device in NetBox or Nautobot, synced by the " +
	"connector, admits a token login; an attribute change, a status change that the default filter removes, and " +
	"the status restored each publish through the webhook and reload in port49d, and break-glass logs in while " +
	"the device is removed."

// TestSoTDeviceEndToEnd runs one stack (run.sh <netbox-4|nautobot-3> e2e,
// with PORT49_LAB_PLATFORMS=eos) to vEOS.
func TestSoTDeviceEndToEnd(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" || os.Getenv("L33_HOOK_BIND") == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> e2e")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skip("the end-to-end run is vEOS's")
		}
		pr := l29Heartbeat(t)
		defer pr.end()
		var failed []string
		fail := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			failed = append(failed, msg)
			t.Error(msg)
		}
		a := newSoTAdmin(t)
		node := l.p.node
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\nSource of truth: %s (`run.sh %s e2e`), beside the 120 devices the run seeded.\n\n",
			l29Built(), stack, stack)

		// 1. The device in the source of truth: leaf-01's facts, its own
		// name, and the address it sources TACACS+ from as its primary.
		pr.at(t, "the device in %s", stack)
		id, err := a.createDevice(node)
		if err == nil {
			err = a.addPrimary(id, l.p.addr+"/32")
		}
		if err != nil {
			t.Fatalf("seeding %s: %v", node, err)
		}

		// 2. The service with the stack as its one source and its webhook;
		// port49d pulling it, on the lab policy with an attribute group for
		// site dc1 beside its CIDR group, so the 120 seeded devices are
		// admitted and removing this one is under every bound.
		raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		withSite := strings.Replace(string(raw), "key_groups:\n",
			"key_groups:\n  - {match: {attributes: {site: dc1}}, key_ref: lab_key}\n", 1)
		if withSite == string(raw) {
			t.Fatal("tests/lab/l29/policy.yaml has no key_groups: block to add to")
		}
		policy := filepath.Join(privateDir(t, "sot-e2e-"+l.p.name), "policy.yaml")
		writeAtomic(t, policy, []byte(withSite), 0o600)
		secret := l33Secret(t)
		li := newLabInventory(t, l.p.name)
		startInventoryWith(t, li, policy, l33SyncYAML(stack, a.product), []string{"L33_WEBHOOK_SECRET=" + secret})
		l29RestoreStanding(t, l)
		if err := a.removeWebhooks("l27"); err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(os.Getenv("L33_HOOK_BIND"))
		if _, err := a.webhook("port49-e2e", "https://port49-inventory.lab:"+port+"/v1/webhook/l33", secret,
			"/etc/port49-lab/ca.pem"); err != nil {
			t.Fatal(err)
		}
		stop := l.capture(t, "L33-e2e")
		defer stop()
		l.l28Restart(t, l.serviceConfig(t, li, policy))
		agent, stopAgent := l29Agent(t)
		defer stopAgent()
		login := func() string {
			said, tok := l29Mint(agent, node)
			if tok == "" {
				return "no token: " + oneLine(said)
			}
			t0 := time.Now()
			c, err := l.dial(sliceUser, tok, 120*time.Second)
			if err != nil {
				return fmt.Sprintf("refused in %s: %s", time.Since(t0).Round(10*time.Millisecond), oneLine(err.Error()))
			}
			c.Close()
			return fmt.Sprintf("logged in in %s", time.Since(t0).Round(10*time.Millisecond))
		}
		pr.at(t, "a token login with the device synced from %s", stack)
		first := login()
		fmt.Fprintf(&obs, "Token login, the device synced at start: %s.\n\n", first)
		if !strings.HasPrefix(first, "logged in") {
			fail("the token login after the first sync did not log in: %s", first)
		}

		// 3. Each change through the webhook: its time to the service's
		// publication and to port49d's reload, and what a login then does.
		obs.WriteString("| change | to the service's publication | to port49d's reload | token login after | break-glass after |\n|---|---|---|---|---|\n")
		for _, ch := range []struct {
			name     string
			body     map[string]any
			admitted bool
		}{
			{"os_version 4.99.0F", map[string]any{"custom_fields": map[string]any{"os_version": "4.99.0F"}}, true},
			{"status offline (the default filter removes it)", map[string]any{"status": a.statusWord("offline")}, false},
			{"status active again", map[string]any{"status": a.statusWord("active")}, true},
		} {
			pr.at(t, "%s", ch.name)
			time.Sleep(35 * time.Second) // past the debouncer's gap
			mark, errOff := li.mark(), l.errMark()
			t0 := time.Now()
			if err := a.patchDevice(id, ch.body); err != nil {
				t.Fatalf("%s: %v", ch.name, err)
			}
			pub, okPub := li.waitLine(t, mark, "sync (webhook): published bundle", 2*time.Minute)
			rel, okRel := l.waitForLine(t, errOff, "port49d: inventory reloaded (inventory service, bundle", 2*time.Minute)
			cell := func(ok bool, at time.Time) string {
				if !ok {
					return "not observed"
				}
				return fmt.Sprintf("%.2f s", at.Sub(t0).Seconds())
			}
			if !okPub || !okRel {
				fail("%s: published %v, reloaded %v", ch.name, okPub, okRel)
			}
			after, glass := login(), "not tried"
			if !ch.admitted {
				out := l.timedLogins(t)
				glass = "logged in"
				if !strings.Contains(out, "| break-glass login plus three `show version` | logged in") {
					glass = "did not log in"
					fail("%s: break-glass did not log in while the device is removed", ch.name)
				}
			}
			if ch.admitted != strings.HasPrefix(after, "logged in") {
				fail("%s: the token login after it: %s", ch.name, after)
			}
			fmt.Fprintf(&obs, "| %s | %s | %s | %s | %s |\n", ch.name, cell(okPub, pub), cell(okRel, rel), after, glass)
		}
		if raw, _ := os.ReadFile(li.errPath); strings.Contains(string(raw), secret) {
			fail("the service's log holds the webhook secret")
		}
		pr.end()
		l.l29Note(t, "L33-e2e-"+a.product, sotE2EClaim, obs.String(), failed)
	})
}
```

- [ ] **Step 5: Commit the harness.** `make build && make test && make vet && go vet -tags lab ./tests/lab/`
  (report them), then:

```bash
git add tests/lab/inventory_test.go tests/lab/sot_admin_test.go tests/lab/l33_test.go tests/lab/l33_unit_test.go \
  tests/lab/sot_e2e_test.go
git commit -m "test(lab): L33's harness: webhooks to port49-inventory, and a source of truth to vEOS

TestL33Webhooks makes three changes and one under a wrong secret in a
running stack, its webhook pointed at port49-inventory over TLS under
the lab CA, and records what arrived and when it published.
TestSoTDeviceEndToEnd takes NetBox or Nautobot to vEOS's admission
through the webhook, the service and port49d (spec §15 L33).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

- [ ] **Step 6: Run the webhooks** from a detached worktree pinned to the Step 5 commit, one stack at
  a time (each about 10 minutes):

```bash
for s in netbox-3.7 netbox-4 nautobot-1.6 nautobot-2 nautobot-3; do
  L27_ENV_DIR=$(mktemp -d) tests/lab/sot/run.sh "$s" l33 || echo "FAILED: $s"
done
```

  Audit each run as in Task 14 Step 6, over `tests/lab/sot/l33`. **If no delivery arrives** for a
  stack (every phase `published: false`, nothing in the service's log after its start), read the
  worker's log in `tests/lab/logs/l33-<stack>.log.compose`: an SSL error means the release did not
  take `ca_file_path` for a private CA, a connection error that `port49-inventory.lab` did not reach
  the host. Record which in the note; it is the row's answer for that release, not a harness fault to
  be worked around. The operator notes then say that release needs a webhook certificate from a CA
  in its own trust store. Never turn `ssl_verification` off to get a delivery through.

- [ ] **Step 7: Run the device**, after the Compose runs and with the lab otherwise empty, from the
  same worktree, with the controller's stall watchdog armed ("Running the lab") and the harness's
  usual environment (`PORT49_LAB_KEY`, the slice PKI):

```bash
for s in netbox-4 nautobot-3; do
  L27_ENV_DIR=$(mktemp -d) tests/lab/sot/run.sh "$s" e2e || echo "FAILED: $s"
done
make evidence
```

  Each run deploys the vEOS topology through the harness and destroys it at the end. Copy the raw
  captures into the branch checkout's `tests/lab/captures/` before removing the worktree.

- [ ] **Step 8: Write the notes.** `tests/lab/results/L33-netbox.md` and `L33-nautobot.md` in
  `L30-netbox.md`'s form, from the records: per release, the webhook's create calls
  (`webhook_calls`), and for each of the three changes whether it published through the webhook, the
  seconds from the API write, and the accepted deliveries counted; the wrong secret's
  `bad_signature` count in 120 s (1: not sent again within 120 s, since a retry with a longer backoff
  would not be seen; more: sent again that many times within it); `stale`
  (0 expected); the capture pointer `tests/lab/sot/l33/<stack>/`; **Status: measured; closed by plan
  6c Task 16**. The unit test reads the rows (pre-flight I3), so write one row per change,
  `| <stack> | <change, as the record spells it> | <seconds to two places> s | <accepted> accepted |`,
  with `failed` in place of the seconds for a change that did not publish, and one row
  `| <stack> | bad_signature | <count> in 120 s | … |`. The device notes (`L33-e2e-<product>-arista_eos.md`) were written by the test; add
  nothing to them but the controller's reading below the table if a cell needs one. Run
  `make lab-unit`.

- [ ] **Step 9: Commit the evidence.** `make test && make vet`, then:

```bash
git add tests/lab/sot/l33 tests/lab/results/L33-*.md tests/lab/evidence
git commit -m "test(lab): L33 measured: webhooks from every release, and NetBox and Nautobot to vEOS

<one line per product from the notes: delivered over TLS under the lab
CA, seconds to publication, whether a 401 is sent again; and the device
run's times to port49d's reload>. The row closes in Task 16.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

  **This task gates the merge:** it is the first run of a source of truth through port49-inventory
  to a device.

---

### Task 16: Close what the lab measured, and write plan 6c as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 rows L32, L33 and their notes; §10
  where a result says otherwise)
- Modify: `docs/superpowers/plans/README.md`

- [ ] **Step 1: Close the rows** (CLAUDE.md lab register rule 3), each only if every release its row
  names was measured:
  - L32's Status: `closed — measured <date>; tests/lab/results/L32-netbox.md, L32-nautobot.md`, then
    one sentence per product from the notes: which header `next` is built from, and that the
    connector read all 120 through both proxies over GraphQL and REST.
  - L33's Status: `closed — measured <date>; tests/lab/results/L33-netbox.md, L33-nautobot.md,
    L33-e2e-netbox-arista_eos.md, L33-e2e-nautobot-arista_eos.md`, with the delivery over TLS, the
    seconds to publication and to port49d's reload, and whether a 401 is sent again.
  - Under each row's note, a "**Measured <date>**" paragraph in L30's form: a table per release, and
    what stayed unmeasured.

- [ ] **Step 2: Mend what a result contradicts** (rule 4). Where §10 says a question is "§15 L32's"
  or "L33's", replace it with the measured answer and its citation. If a release did not deliver
  under a private CA, §10's webhook paragraph and the operator notes say that release needs a
  certificate its own trust store holds; if a read failed and Task 14 fixed the code, §10 says what
  the release does. Say each in the commit message.

- [ ] **Step 3: Plan 6c as built.** In `docs/superpowers/plans/README.md`, set the Plan 6c bullet's
  status to `Executed <date> (as built, below); merged <date> (PR #<n>)` once merged, and add
  "### Plan 6c — As built" after "Fix `fix/breakglass-reset` — As built", in that section's form:
  what differs from this plan's text, task by task; the rulings as made (decision 31); rows L32 and
  L33 closed; and **Carried, for later plans**:
  - **Plan 12:** `token_secret_ref:` and `webhook_secret_ref:` with the `secret_ref:` resolvers; the
    service honouring an outbound HTTP proxy for its sources (it dials each source directly).
  - **Later, unassigned:** tags as an attribute, once the spec gives a multi-valued attribute a
    shape; server-side GraphQL filters, once a lab run records each release's filter arguments; a
    GraphQL list above a server cap and a list changing between pages, which the count check turns
    into a failed sync rather than a silent loss but no run measured; further connectors (Infrahub,
    Ansible inventory), which take the same `inventory.Source`.

- [ ] **Step 4: Check and commit.** `make test && make vet`, then:

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/superpowers/plans/README.md
git commit -m "docs: close lab register entries L32 and L33; plan 6c as built

<what each row measured, one line each; any §10 sentence a result
corrected, cited to its note>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Operator-facing notes (for the pull request body)

Material for the user and admin documentation (roadmap plan 13). Each paragraph stands alone.

**Adding a NetBox or Nautobot source.** Give port49-inventory a read-only API token: it reads
`/api/status/`, `/api/dcim/devices/` and GraphQL, and never writes. Put the token in an environment
variable and name the variable in `token_secret_env`; port49 never prints it, and a configuration
error names the key, not the variable. `url` is `https://` only, and `ca_file` is required: the CA
that issues the source's certificate, or the host's bundle (`/etc/ssl/certs/ca-certificates.crt`) for
a public one. A source served under a path prefix keeps it in `url` (`https://tools.example.com/netbox`).

**Releases.** The connector reads NetBox 3.7 and 4.x and Nautobot 1.6, 2.x and 3.x, as the lab
measured them (NetBox 3.7.8 and 4.7.1; Nautobot 1.6.32, 2.4.43 and 3.2.6). It reads the release from
`/api/status/` at every sync and says it once, with the profile it chose. Another minor of a measured
major is read with that major's profile and said; another major is refused until you set `profile:`,
which you do at your own risk. If an upgrade breaks a sync, the line names GraphQL's first error, the
bundle in force keeps serving, and `api: rest` for that source is the stopgap (primary addresses
only).

**What a device becomes.** By default a source gives the devices whose status is `active`, each with
its primary IPv4 and IPv6 addresses, its platform (NetBox `platform.slug`; Nautobot
`platform.network_driver`), and the attributes `site` and `role` (Nautobot 2.x and 3.x: `location.name`
and `role.name`). `filter` changes which devices (`status`, `tags`, `has_primary_ip`); `map` replaces
the attributes entirely and must name `platform`; `custom_fields.<key>` maps a custom field;
`status` maps the status, lower case. `addresses.interfaces` adds the addresses on named interfaces
(say `[Loopback0]` when TACACS+ is sourced from a loopback); `all_interfaces` adds every one, which
fails the whole sync if any address sits on two devices (a VRRP address, a reused management
address), so prefer named interfaces. An interface's loopback, link-local, multicast or unspecified
address is never taken: it cannot source TACACS+, and every device has the same ones. A device left
with no address counts against the source's bound like a removed one, so an IPAM clean-up that
strips addresses is refused, not published. Nautobot installations that leave a platform's network
driver empty should set `map: {platform: platform.name, ...}`; the service says so when most devices
give no platform. A custom field that is empty, or not a string, number or
boolean, leaves its attribute unset; your scopes' `on_missing` decides what that means.

**Platforms.** `eos`, `arista-eos`, `veos`, `cisco_xe`, `ios-xe`, `nx-os`, `junos` and the like map to
port49's names. Anything else is kept as it is: the device is admitted on the generic adapter
(priv-lvl only), the publication that brings a new one says so, and
`port49_inventory_generic_platform_devices` counts them for as long as they last. Map your own
spelling with `platform_aliases: {eos-lab: arista_eos}`. A `platforms:` block in the policy is the
other way only for a name of lowercase letters, digits and `_` (`eos_lab`, never `eos-lab`): the
policy refuses any other platform name, and the service's line says which way is open.

**Two devices with one primary address** (a virtual-chassis member, a management address reused in
another VRF) refuse every sync of the source, as spec §10 requires: the bundle in force keeps
serving. Filter one of them out (a tag, or a status), or give it another primary address.

**Webhooks.** Set `webhook_listen` (for example `:8444`) and, per source, `webhook_secret_env`
naming a variable that holds 32 to 255 printable characters. Point the product at
`https://<the service's webhook name>:8444/v1/webhook/<source name>`, with the same secret, SSL
verification on, and the CA file that issued the webhook's certificate (the API's, or
`webhook_tls_cert_file`'s); the certificate must name the host the product dials.
- NetBox 4.x: a webhook (`POST`, `application/json`, the secret), and an event rule on
  `dcim.device` for created, updated and deleted, acting on that webhook.
- NetBox 3.7: the same webhook, and an event rule in 3.7's spelling (`content_types`, `type_create`,
  `type_update`, `type_delete`).
- Nautobot: one webhook on `dcim.device` with create, update and delete ticked.
Leave the webhook's body template empty: the service reads the default body's `timestamp`, and a
template without one is refused (`bad_body`) at every delivery. Every refused delivery is answered
401 with the same body, whatever the reason; the service's line and
`port49_inventory_webhooks_total{outcome}` give the reason.
A delivery only makes the service sync that source, 2 s after it; a burst is one sync, and a source
syncs from webhooks at most every 30 s. Nothing in a delivery is trusted. A delivery more than 5
minutes from the service's clock is refused (`stale`): keep NTP on both hosts. Anyone who can read
webhooks in the product can read the secret, and with it make the service sync; that is all it
grants. Missed or refused deliveries are covered by the source's `interval`.

**Behind a reverse proxy.** Have the proxy pass the client's `Host` and `X-Forwarded-Proto: https`.
If it rewrites the host, the service says once that it rebuilt a page's `next` on `url`, and goes on:
it never sends the token anywhere but `url`, and never follows a redirect.

**Metrics to alert on.** `port49_inventory_sync_failing` (a source or the policy did not answer),
`port49_inventory_sync_refused` (a bound or an empty result), `port49_inventory_source_hung{source}`
(a fetch abandoned past `sync_timeout`), `port49_inventory_generic_platform_devices` (above zero:
an unmapped platform), and `port49_inventory_webhooks_total{source,outcome}` by outcome: a rise in
`bad_signature`, `unsigned` or `stale` is a misconfiguration or someone else knocking, and
`tls_handshake` (source `""`) counts failed handshakes, which are not logged.

**An inventory for the offline tools.** `port49 inventory export --service https://inv:8443 --ca
ca.pem --cert me.pem --key me-key.pem --verify-key signing.pub --out inventory.yaml` writes the
published bundle's inventory, verified against the service's public key, in `inventory_file`'s
schema, mode 0600 (the fleet list is not for the world); `--from N` takes bundle N from the
service's last 64, and is refused if the service answers another. Use it with `port49 policy test`,
`policy diff`, `inventory diff` and `explain`.

**At 3am.** See "What the operator sees" in the plan, which the docs should carry whole: each line
there is what the service says, and what to do.

## Self-review against the spec

- **§10 "Connectors and sync cadence", the four triggers:** schedule, startup and `inventory sync`
  were 6b's; the webhook is Tasks 11–12, measured in Task 15.
- **Version detection:** Task 3 (profiles, `/api/status/`, override), Task 8 (said, per sync).
- **GraphQL first, REST fallback:** Tasks 5, 6, 8; `?depth=1` on Nautobot 2.x and 3.x (Task 6);
  `next` on the base (Task 6); `errors` before `data` (Task 5); the count check (Task 8).
- **Bounded change per sync:** 6b's, fed by the connectors (Task 9's `NewSources`), now counting a
  device left with no address in the service and in port49d (Task 10a, pre-flight I2); a list that is
  short, shifted, or names a device twice cannot reach it as removals (Tasks 5, 6, 8; pre-flight I1).
- **Platform slug translation:** the table and overrides (Task 7), the warning for any source
  (Task 10).
- **Filters and maps:** Task 7, configured in Task 9.
- **Credentials:** `token_secret_env`, `webhook_secret_env`, `sot.Secret` (Tasks 2, 9); spec §10's
  `token_secret_ref` is plan 12's (Task 1 edits the example to say so).
- **"Fetch MUST return when ctx ends", within `sync_timeout`:** Task 10.
- **`port49 inventory export --service … [--from N]`:** Task 13, with §12's text in Task 1.
- **Authenticated webhooks:** Tasks 11–12; §13 decision 31 records the rulings (Task 1).
- **§14 assertions added by Task 1:** connectors (Tasks 5–8), webhooks (Tasks 11–12), `Fetch` bound
  (Task 10), export (Task 13), each with a test that fails without its code.
- **§15:** L32 and L33 opened by Task 1, measured by Tasks 14 and 15, closed by Task 16; nothing
  cites them as measured before then.
- **Reason codes:** none added. **Metric labels:** `source` and `outcome` only. **Secrets in logs:**
  every task that handles one tests that it does not appear.
- **Placeholder scan:** the only text left to fill is the two lab commit messages' summary lines
  and the notes, which are written from the measurements they report.

