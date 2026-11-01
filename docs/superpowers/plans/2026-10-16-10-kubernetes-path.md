# The Kubernetes path: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A workload in a Kubernetes pod mints device tokens with its projected ServiceAccount
token alone: the broker validates the token against the cluster's published JWKS and gives the
principal `system:serviceaccount:<namespace>:<name>` in the machines trust domain (design §7,
"Machine identity" option 1; spec §2; design §19 step 10).

**Architecture:** A `k8s` verifier joins `broker.identity.machines` beside `x509` and `oidc`. It
is an `oidc.Verifier` of a second kind: one `oidc.Set` routes every bearer by its `iss`, as
decision 39 ruling 2 already does, and the k8s kind reads its keys from the configured `jwks`
URL directly (design §7's `{type: k8s, jwks: …}`), not through discovery, because a cluster's
issuer is often a name nothing outside the cluster resolves. The k8s claim rules live in one new
file, `internal/oidc/k8s.go`; the principal's form lives in one new package, `internal/k8sid`, which
the policy, the verifier and a revocation share (as `internal/spiffe` is shared, decision 40
ruling 4). `port49 workload` gains `--token-file`, which presents the projected token as a bearer
and reads it again at each request, so the kubelet's rotation needs nothing from the workload.

**Tech Stack:** Go 1.26 (module `github.com/blanketfish/port49`), the standard library only, no new
module; `internal/oidc`, `internal/config`, `internal/broker`, `internal/port49d`,
`internal/workload`, `cmd/port49`, `internal/policy`; the lab on kind (`tests/lab`, build tag
`lab`, `kind` v0.29.0, `kindest/node:v1.33.1`).

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md`:
- §2, the principal table (:94) and "A subject MAY list several identities" (:57);
- §5.1.4, the `credential` block (:920);
- §5.7, the reason rows `identity_unmapped` (:2413) and `trust_domain_unresolved` (:2416), and the
  `auth.oidc` field (:2348);
- §13 decisions 16 (:6799), 39 (:8003; rulings 1–6, 9, 10, 17, 18, 22), 40 (rulings 4, 15, 16);
- §15 (the register's rules, :10627) and L39 (:10698).

Design `docs/design/2026-08-21-port49-design.md` §7 "Machine identity" (:422) and "Trust domain
separation" (:447), §17 (the error list, :2025), §19 step 10 (:2390). The roadmap's
"Plan 10" and "Plan 8 — As built", "Carried forward" (`docs/superpowers/plans/README.md`).

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo, no new module. Before any "done": `make test &&
  make vet`, and report the real output.
- Data is snake_case: the config keys `jwks`, `audience`, `namespaces`, `ca_file`, `algorithms`;
  the config key `cluster`; the record fields `auth.k8s.cluster`, `serviceaccount_uid`, `pod`,
  `pod_uid`, `node`, `jti`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds
  none: a refused cluster token is `trust_domain_unresolved` or `identity_unmapped`, a revoked
  principal `credential_revoked`. Task 1 extends those rows' text before any code relies on it.
  §12's warning codes are policy-tooling codes; this plan adds none.
- The log never contains a token. A token that did not verify has no claim said, recorded or
  counted (decision 39 ruling 18), its `iss` included. `credential_sha256` is the only form a
  presented credential takes, and a mint record has none (`internal/decision/log.go:139`).
- No device identity and no principal in a metric label. A namespace or a service account is a
  principal's part, so it is never a label either.
- `port49 workload` never prints, logs or writes a token it read; the token file is never
  copied.
- The lab register is the source of truth: a claim about cluster behaviour cites L69 or L70,
  and one cited to an open row is unmeasured. Until Task 11 closes L69, every such claim reads
  "provisional on L69 (<cell>)", never "measured"; Task 11 Step 5 turns each into "measured on
  kind (L69 (<cell>))", and nothing more while L70 (managed clusters) is open. If a result
  contradicts a doc, the doc is wrong: fix it, cite the note, say so in the commit.
- Lab runs: single occupant; the STOP sentinel `/tmp/port49-STOP-LAB` checked before every cell
  (`labGuardAt`); a background stall watchdog, re-armed on every wake; a detached run worktree
  pinned at the commit. An INVALID run writes no note. The harness never prints a token: every
  token it reads is held in memory, written only to a 0600 file under `t.TempDir()`, and
  registered with the note's leak check (`labcreds.Contains`).
- Commits: Conventional Commits, one per step that says Commit, on `feature/kubernetes-path`.
  Each message ends with only `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`: no
  `Claude-Session:` line and no claude.ai link.

## Rulings (planner, 2026-10-16, security-first where the spec is silent; R4 and Q1, Q2 ruled 2026-10-16)

Recorded as spec §13 decision 49 by Task 1. Each rests on reasoning unless it says data.

- **R1. The verifier.** `type: k8s` under `broker.identity.machines` only (a cluster's service
  accounts are workloads; under `humans` it is a load error). It takes `issuer` (required, an
  https URL: the cluster's `--service-account-issuer`, compared byte for byte with a token's
  `iss`), `cluster` (required: the cluster's name on the port49 side, a CRL source's name shape
  `^[a-z][a-z0-9_]{0,63}$`, e.g. `us_east`), `jwks` (required, an https URL with no userinfo,
  query or fragment), `audience` (required), `namespaces` (required), `ca_file` and `algorithms`
  (default `[RS256]`, decision 39 ruling 3), and nothing else. Any number may be listed, one per
  cluster. `cluster` is unique across k8s verifiers, a repeat refused at load, except two
  verifiers on the same `jwks` (one cluster under two issuers during a migration, R4), which
  share it. It is configuration alone: nothing in a workload's manifests changes, and it is not
  part of the principal. It is what the operator reads: the record's `auth.k8s.cluster`, the
  start's lines, and every refusal and warning a k8s verifier says, with the issuer beside it
  where it helps debugging.
- **R2. Keys come from `jwks`, never from discovery.** Design §7 names the JWKS, and a cluster's
  issuer is often `https://kubernetes.default.svc.cluster.local`, which nothing outside the
  cluster resolves. The fetch, refresh, refetch-on-unknown-`kid`, `jwks_max_age`, persistence and
  timings are decision 39 ruling 4's, unchanged. After each JWKS fetch the broker reads the
  discovery document at the JWKS URL's own origin (`/.well-known/openid-configuration`), after
  the fetch's outcome is out and on its own 3s timeout, only to say, once per change: an `issuer`
  other than the configured one and other than any issuer another k8s verifier on the same `jwks`
  names (every token will be refused); no `issuer` at all; or that discovery could not be read.
  Its `jwks_uri` is not compared: a self-managed cluster's names the issuer's host, which the
  broker reaches by the API server's address instead, so the note would fire on every correct
  config. Discovery never decides a key, never fails a fetch and never holds one. The
  fetch is anonymous: the broker holds no cluster credential (design §7, "no secret at rest").
  A self-managed cluster publishes its keys to it with one ClusterRoleBinding of
  `system:service-account-issuer-discovery` to `system:unauthenticated`, which Task 9 ships as a
  manifest (anonymous discovery denied by default and allowed after the binding is L69 cell c).
- **R3. One issuer, one cluster.** Two k8s verifiers with one issuer (or two spellings
  `issuerForm` folds together) are a load error, and so is a k8s issuer an `oidc` verifier also
  names. kubeadm's default issuer is the same on every cluster, so the start's error says to set
  `--service-account-issuer` per cluster. Keys, the kept key file and the metrics are keyed by
  issuer, so this also keeps them one cluster's each.
- **R4. `namespaces` is required; several clusters may list the same one** (ruled 2026-10-16,
  Q1). It lists the namespaces whose service accounts the cluster may name, by name, no
  wildcard. Two k8s verifiers may list one namespace: a workload deployed from the same
  manifests to several clusters (`netops:oxidized` in `us_east`, `eu_west` and `ap_south`) is
  one identity, `system:serviceaccount:netops:oxidized`, minted by whichever cluster's pod
  asks. A compromised cluster already holds a genuine token for that workload, so refusing the
  overlap buys nothing, and a namespace per cluster is fleet toil (every manifest overlaid per
  cluster, three identities per subject). Where a namespace means different tenants in
  different clusters, the operator lists different namespaces per verifier. The overlap is
  made visible, not refused: the start names, for each namespace, every cluster that vouches
  for it (R13), and every record carries `auth.k8s.cluster`, `issuer`, `pod` and `node`
  (R9), so audit tells the clusters apart. A cluster-qualified principal is a future opt-in
  (left for later), which would use `cluster`. Two verifiers with the same `jwks` and different
  issuers are one cluster changing its issuer (Kubernetes accepts several
  `--service-account-issuer` flags during a migration).
- **R5. The audience.** A token's `aud` must be exactly one value, the configured `audience`. A
  token another audience also accepts is one that audience's service could replay here. Design
  §7's example value is `port49`; the error message suggests it.
- **R6. The claims**, as decision 39 ruling 5 has them: `iss` exact; `exp` required; `nbf`
  honoured; `iat` required, ahead of the broker's clock by no more than `clock_skew`, and no older
  than `max_token_age`; a date that is a JSON string refused; a claim name repeated in two cases
  refused; header `typ` absent or `JWT` (never `at+jwt`); a person's session or delegation claim
  (`auth_time`, `sid`, `nonce`, `scp`, `amr`, `act`, `may_act`) refused. The refusal for an `iat`
  past `max_token_age` adds, for a k8s token: "the kubelet refreshes a projected token at about 80% of
  its expirationSeconds, so keep expirationSeconds at or under 3600" (measured on kind, L69 (b)).
- **R7. A projected token, bound to a pod.** The `kubernetes.io` claim is required and read by
  exact name at every level: its `namespace` and `serviceaccount.name` equal the `sub`'s parts,
  `serviceaccount.uid` and `pod.name` and `pod.uid` are present, and `secret` is absent. A token
  bound to a Secret, or to no object (`kubectl create token` with no `--bound-object-kind`), is
  refused `trust_domain_unresolved`: design §7 is the projected token, which the kubelet writes
  and rotates, and a pod-bound token stops being issued once its pod is gone. `node` and `jti` are
  recorded when present. No group, role or username is ever read from the token (design §7).
- **R8. The principal.** `system:serviceaccount:<namespace>:<name>` from `sub`, verbatim, through
  `k8sid.Parse`: the namespace an RFC 1123 label (1–63 bytes of `a-z 0-9 -`, alphanumeric at both
  ends), the name an RFC 1123 subdomain (1–253 bytes, labels joined by `.`), upper case refused,
  never folded. A `sub` outside the form, or a namespace the verifier does not list, is
  `identity_unmapped`. One parser for the policy, the verifier, a revocation and an explain: the
  policy's load tightens from `^system:serviceaccount:[^:\s]+:[^:\s]+$` to it, so a policy naming
  an identity no cluster can give fails CI rather than minting for no one (decision 40 ruling 4's
  reasoning). A principal may be up to 339 bytes, past `printableID`'s 255, so the k8s path never
  goes through it.
- **R9. The credential and the record.** The store's credential is `{method: k8s, iss, sub}`
  (spec §5.1.4: identity for attribution, nothing that re-verifies). A record of a k8s caller
  carries `auth: {method: k8s, k8s: {cluster, issuer, sub, serviceaccount_uid, pod, pod_uid,
  node, jti}}`, `cluster` the accepting verifier's configured name and the rest each a verified
  value: which cluster and pod minted is unrecoverable afterwards, the reason §5.1.4 records
  `amr`. A bearer that did not verify is recorded `auth: {method: k8s}` when every verifier its
  routing `iss` reached is a k8s one (or, when its `iss` reached none, when every configured
  verifier is a k8s one), else `{method: oidc}` as today: the method is configuration's word,
  and nothing of the token is recorded.
- **R10. The session clock is `iat`**, as for a machine OIDC token (decision 39 ruling 9). No
  owner record is written and no logout reaches it (machines, ruling 11).
- **R11. A deleted service account or pod.** Validation is against the JWKS alone, as the design
  says; the broker never calls the cluster's TokenReview. A token the cluster issued stays valid at
  port49 until `exp`, or `iat` + `max_token_age` (2h), whichever is first, after its pod or
  service account is deleted (L69 cell e measures both sides). `port49 revoke --principal
  system:serviceaccount:<ns>:<name>` ends it at once, and its answer says so and that the mark
  stands for a service account re-created under the same name until lifted. Ruled 2026-10-16
  (Q2): no TokenReview.
- **R12. Metrics.** The k8s verifiers share `port49_oidc_tokens_total{issuer,outcome}`,
  `port49_oidc_keys_last_success_timestamp_seconds{issuer}` and
  `port49_oidc_keys_fetch_failures_total{issuer}`, labelled by the configured issuer (a few per
  deployment, configuration not identity); their help text says "OIDC or cluster". A token whose
  `iss` names no verifier stays `issuer="unknown"`. The label stays `issuer`, not `cluster`:
  the cardinality is the same, but the series are shared with OIDC verifiers, the key set (the
  thing the keys metrics describe) is keyed by issuer, and during a migration one cluster has
  two key sets. `cluster` is never a metric label.
- **R13. The start says what it trusts.** One line per k8s verifier, led by its `cluster`; one
  line that a k8s verifier trusts its cluster's administrators (whoever can create a pod or a
  token for a service account in a listed namespace mints as it) and states R11's window; one
  line naming, for each listed namespace, every cluster that vouches for it (`identity: k8s
  namespaces: backup: us_east; netops: ap_south, eu_west, us_east`), so an unexpected overlap is
  visible at every start; and the policy's
  `system:serviceaccount:` identities no verifier can give (no k8s verifier, or none lists that
  namespace), as decision 40 ruling 16 does for `spiffe://`.
- **R14. The client.** `port49 workload token` and `identity` take `--token-file PATH` in place of
  `--cert` and `--key`. It presents the token as `Authorization: Bearer` over https with
  `--broker-ca` alone (decision 40 ruling 10), reads the file at every request attempt so a
  rotation between retries is picked up, and never prints it. It is refused beside `--cert`,
  `--key` or `--touch-key` (a touch proof is bound to the workload certificate's key, decision 45).
  An unreadable, empty or over-16-KiB file, or one holding whitespace inside the token, is exit 2
  at the start; the same mid-run stops the run, final. The exit codes are decision 40 ruling 10's.
- **R15. A per-login requirement on a k8s workload** (decision 45 ruling 21) is never proved: a
  bearer workload has no touch key, so such a device is reported `per_login_mfa_required` and not
  minted, as for any workload without `--touch-key`. The operator notes say so.
- **R16. The lab.** L69 is opened and measured on kind (the cluster behaviour R2, R6, R7 and R11
  rest on). L70 is opened for managed clusters (EKS, GKE, AKS) and left open: plan 10 has no
  account on any of them. Until Task 11 closes L69 the docs say "provisional on L69 (<cell>)";
  after, "measured on kind" and nothing more until L70 closes.

## Questions for Ryan

None open. Both were ruled 2026-10-16:

- **Q1. One namespace in several clusters** (R4): allowed. Several k8s verifiers may list the
  same namespace; the principal stays `system:serviceaccount:<ns>:<name>` (no spec §2 change);
  each verifier gets a required port49-side `cluster` name, recorded and said at the start. The
  reasoning is R4's. A cluster-qualified principal is left for later as an opt-in.
- **Q2. Immediate effect of a deleted service account** (R11): no TokenReview. Calling the
  cluster's TokenReview at each mint would refuse a deleted pod's token at once, but puts every
  cluster's API server on the mint path (a control-plane outage at 3am stops every k8s workload's
  mints, where today keys held for 24h carry it) and needs a broker credential with
  `tokenreviews: create` on each cluster, a secret at rest the design §7 path avoids. The window
  is at most 2h, and `port49 revoke --principal` closes it at once.

## The operator at 3am

Each case says what the operator sees: the workload's stderr (`port49 workload` prints the
broker's detail through `printsafe`), the broker's log line, the record and the metric. A k8s
verifier's lines and refusals name it `cluster <name> (<issuer>)`, written `<cluster>` below; a
k8s record carries `auth.k8s.cluster`; the metrics stay labelled by issuer (R12).

- **The first start, no kept keys, and the JWKS unreachable.** The broker says `identity:
  <cluster>: no keys fetched yet (<the error>); every token from it is refused
  identity_provider_unavailable until a fetch succeeds`, and retries on the refetch schedule.
  The workload gets 503 `identity_provider_unavailable`, retries within `--deadline` and exits
  75; the record is `deny trust_domain_unresolved`, `auth: {method: k8s}`, as past 24h below.
  `port49_oidc_keys_fetch_failures_total{issuer}` climbs and
  `port49_oidc_keys_last_success_timestamp_seconds{issuer}` stays 0 (set at construction), so
  the staleness alert fires at once. Fix the path to `jwks` (the start's "is fetched directly /
  through the proxy" line names the JWKS host the broker dials).
- **The cluster's JWKS unreachable** (the API server down, a network cut, an expired binding).
  The broker keeps the keys it holds (and restores them across a restart from its state
  directory) and accepts tokens signed by them until `jwks_max_age` (24h) after the last good
  fetch. Log: `identity: <cluster>: keys not refreshed since <t> (the last error: GET <jwks>: …);
  tokens signed by the 2 keys held are accepted until <t+24h> …`, once an hour.
  `port49_oidc_keys_fetch_failures_total{issuer}` climbs, and the alert on
  `time() - port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age/2` fires at 12h. Past
  24h: every token from that cluster is refused 503 `identity_provider_unavailable`; the workload
  retries within `--deadline` and exits 75; the record is `deny trust_domain_unresolved`, `auth:
  {method: k8s}`. Live device sessions are untouched. Other clusters and every other verifier are
  untouched.
- **Key rotation at the cluster.** A token signed by a key the broker has not fetched triggers one
  refetch (at most one a minute per issuer); a fetch that finds it mints at once, with no restart
  and no operator step (L69 cell d). A rotation done wrong (the signing key switched before its
  public key was published) refuses that cluster's new tokens 401 `trust_domain_unresolved` "no
  one key of <cluster> matches its key id", exit 77, until the cluster publishes the key; a cluster
  unreachable at that moment is 503 instead, retried. A key the cluster stops publishing is gone
  at the next refresh (1h).
- **Clock skew.** A token issued ahead of the broker's clock by more than `clock_skew` (60s) is
  refused 401 `trust_domain_unresolved` "it was issued at <t>, ahead of the broker's clock by more
  than broker.identity.clock_skew (1m0s)", exit 77: fix the broker host's clock (the cluster's API
  server stamped `iat`). A broker clock ahead by more than `exp` − `clock_skew` reads every token
  expired: "it expired at <t>".
- **A token from the wrong cluster.** Its `iss` names no verifier: 401 `trust_domain_unresolved`
  "no configured verifier accepts its issuer", the metric under `issuer="unknown"`, nothing of the
  token said. A token from a listed cluster for an unlisted namespace: 401 `identity_unmapped`
  "its namespace <ns> is not one <cluster> lists in namespaces", exit 77; the record's
  `auth.method` is `k8s`.
- **A namespace more clusters vouch for than expected.** Not refused (R4): the start's line
  `identity: k8s namespaces: netops: ap_south, eu_west, us_east; …` names every cluster that
  may mint as a namespace's service accounts. A namespace that should be one cluster's but
  shows two is a configuration slip: remove it from the other verifier's `namespaces` and
  restart. Which cluster minted any one token is the record's `auth.k8s.cluster` (with
  `issuer`, `pod` and `node`).
- **A token for the wrong audience.** 401 `trust_domain_unresolved` "its aud is not exactly
  [<audience>]", exit 77: the pod's projected volume names another `audience`, or the workload is
  reading the default `kube-api-access` token (its `aud` is the API server's; L69 cell h).
- **A deleted service account or pod.** Mints go on with the token in hand until its `exp` or
  `iat` + 2h (R11; L69 cell e); the kubelet writes no new one. Stop it at once with `port49 revoke
  --principal system:serviceaccount:<ns>:<name>`; the answer says the mark also stands for a
  service account re-created under that name until `port49 revoke --lift`.
- **Discovery names another issuer.** Keys still come from `jwks`, and each change is said once:
  `identity: <cluster>: the cluster's discovery (<origin>/.well-known/openid-configuration) names
  issuer <X>: its tokens carry that iss, so each is refused until
  broker.identity.machines[].issuer is <X>`. Not said when `<X>` is another k8s verifier's issuer
  on the same `jwks` (an issuer migration). A discovery document with no `issuer` says "names no
  issuer"; one the broker cannot read (anonymous access denied, 404, a 3s timeout) is said once
  and changes nothing. Discovery is read after the key fetch is done, so a slow discovery
  endpoint never holds a mint. Its `jwks_uri` is never compared (it names the issuer's host,
  which the broker reaches by another address).
- **A token past `max_token_age`.** 401 `trust_domain_unresolved` "issued 2h41m ago, past
  broker.identity.max_token_age (2h0m0s); the kubelet refreshes a projected token at about 80% of its
  expirationSeconds, so keep expirationSeconds at or under 3600": the pod's volume asks for too
  long a token, or its kubelet has stopped rotating.

## Review Focus

The five uncovered inputs most likely to bite, each pinned by a test in its owning task:

1. **A `kubernetes.io` claim spelled in another case or nested member repeated** (`Kubernetes.io`,
   `"pod":{"Name":…}`): `encoding/json` folds case, so a forged-shape token could pass a binding
   check while its real binding says otherwise. Expected: refused, every level read by exact name.
   Test: Task 5, `TestAK8sBindingIsReadByExactName`.
2. **The kubelet rotating the token between a 503 and its retry.** Expected: the retry presents
   the new token. Test: Task 8, `TestTheTokenFileIsReadAtEveryAttempt`.
3. **A cluster that publishes only an ES256 key while the verifier pins RS256.** Expected: every
   token refused "its algorithm is not one … pins", never a panic or an accepted mismatch, and the
   start line names the algorithms. Test: Task 5, `TestAK8sTokenUnderAnUnpinnedAlgorithmIsRefused`.
4. **An issuer migration**: two verifiers on one `jwks` with two issuers and the same namespaces.
   Expected: loads; one issuer twice is refused. Test: Task 3, `TestAK8sIssuerMigrationLoads`.
5. **A service account name of 253 bytes** (a principal of 339): Expected: it verifies, mints,
   revokes and is recorded whole, never cut at 255. Tests: Task 2, `TestTheLongestServiceAccountParses`;
   Task 5, `TestALongServiceAccountVerifies`; Task 6, `TestALongServiceAccountRevokes`.

---

## File map

| File | Change |
|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md` | §2, §5.1.4, §5.7, decisions 39 and 40 pointers, new decision 49, §15 L69 and L70 (Task 1) |
| `docs/design/2026-08-21-port49-design.md` | §7 "as built" pointers (Task 1), as built (Task 12) |
| `internal/k8sid/k8sid.go`, `k8sid_test.go` | new: the principal's one parser (Task 2) |
| `internal/policy/load.go`, `member.go`, `load_test.go` | the parser at load; `ServiceAccountIdentities` (Task 2) |
| `internal/oidc/config.go` | `KindK8s`, `VerifierConfig.Kind/JWKS/Namespaces`, `Config.K8s` (Task 3) |
| `internal/config/identity.go`, `config.go`, `identity_test.go` | `type: k8s` (Task 3) |
| `internal/oidc/keyset.go`, `keyset_k8s_test.go`, `export_test.go`, `oidctest/issuer.go` | `KeySetConfig.JWKS` and `Migrating`, the discovery check (Task 4) |
| `internal/oidc/k8s.go`, `verify.go`, `k8s_test.go`, `oidctest/issuer.go` | the k8s claims (Task 5) |
| `internal/decision/log.go`, `internal/broker/oidc.go`, `revoke.go`, `k8s_test.go`, `revoke_test.go` | the record, the principal in revoke and explain (Task 6) |
| `internal/port49d/identity.go`, `main.go`, `identity_test.go`, `identity_linux_test.go`, `internal/daemon/metrics/metrics.go`, `internal/oidc/keyset.go` (`ProxyFor`) | key sets, start lines (Task 7) |
| `internal/workload/client.go`, `client_token_test.go`, `cmd/port49/workload.go`, `workload_test.go` | `--token-file` (Task 8) |
| `examples/kubernetes/` | the binding, a CronJob, a policy snippet, the README (Task 9) |
| `tests/lab/l69_test.go`, `l69_unit_test.go`, `tests/lab/k8s/`, `Makefile`, `tests/lab/README.md` | the L69 harness (Task 10) |
| `tests/lab/results/L69-kind.md`, `tests/lab/evidence/L69-kind.json` | the run (Task 11) |
| `docs/superpowers/plans/README.md` | Plan 10 — As built (Task 12) |

---

### Task 1: The spec and the design first

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§2 :94, §5.1.4 :920, §5.7 :2348, :2413,
  :2416, decision 39 ruling 1 :8009, decision 40 ruling 15 :8231, new decision 49 before `## 14.`
  (:9955), §15 after L68 (:10727))
- Modify: `docs/design/2026-08-21-port49-design.md` (§7 :472)

**Interfaces:**
- Consumes: nothing.
- Produces: decision 49 (R1–R16 as its rulings 1–16), L69 and L70, the reason rows every later
  task's refusals cite.

- [ ] **Step 1: §2's principal table.** Replace the Kubernetes row (:94) with:

```markdown
| Kubernetes | `system:serviceaccount:<namespace>:<name>` from the token's `sub`, verbatim: a projected service account token bound to a pod, verified against its cluster's JWKS; the namespace an RFC 1123 label, the name an RFC 1123 subdomain, upper case refused; a namespace the cluster's `broker.identity.machines[]` `k8s` verifier does not list in `namespaces` is `identity_unmapped` (§13 decision 49 rulings 7 and 8) |
```

  And after "A `spiffe://` identity must be a SPIFFE ID with a path … never folded to fit (§13
  decision 40 ruling 4)." add: "A `system:serviceaccount:` identity must be
  `system:serviceaccount:<namespace>:<name>` with a namespace of 1–63 bytes of `a-z 0-9 -`,
  alphanumeric at both ends, and a name of such labels joined by `.`, at most 253 bytes: one outside
  it is a load error, never folded (§13 decision 49 ruling 8)."

- [ ] **Step 2: §5.1.4's `credential` block.** After the `# oidc` lines (:933) add:

```
  # k8s (plan 10; §13 decision 49 ruling 9)
  iss          https://l69-a.port49.lab      the cluster's service account issuer
  sub          system:serviceaccount:netops:oxidized
```

  and after the paragraph on `amr` and `acr`: "**A cluster token** records `iss` and `sub`
  alone: its cluster, its pod and the service account's `uid` are in the mint's record
  (`auth.k8s`, §5.7), for attribution, and nothing re-verifies them."

- [ ] **Step 3: §5.7.** After the `auth.oidc` bullet (:2348) add:

```markdown
- `auth.k8s`: on a broker event whose caller presented a Kubernetes service account token (plan
  10), `{cluster, issuer, sub, serviceaccount_uid, pod, pod_uid, node, jti}`: `cluster` the
  accepting `k8s` verifier's configured name, the rest each from the verified token (`node` and
  `jti` when it carries them). Several clusters may vouch for one namespace (§13 decision 49
  ruling 4), so `cluster` is what tells them apart. A bearer that did not verify is recorded `auth: {method:
  k8s}` when every verifier its `iss` reached is a `k8s` one (or, when it reached none, every
  configured verifier is), else `{method: oidc}`, with no principal: none of its claims is a
  validated value (§13 decision 49 ruling 9).
```

  In the `identity_unmapped` row (:2413), after "or a machine token with neither `azp` nor
  `client_id` (§13 decision 39);" insert: "or a Kubernetes service account token that verified
  but whose `sub` is not `system:serviceaccount:<namespace>:<name>` in the form §2 gives, or whose
  namespace the cluster's `k8s` verifier does not list in `namespaces` (§13 decision 49 ruling 8);".

  In the `trust_domain_unresolved` row (:2416), after "or carrying a person's session claim or an
  `idtyp` other than `app`) (§13 decision 39);" insert: "or a Kubernetes service account token
  the cluster's `k8s` verifier does not accept: a bad signature, an algorithm it does not pin, an
  `iss` it does not name, an `aud` other than exactly its `audience`, a token expired, not yet
  valid, ahead of the broker's clock or older than `max_token_age`, a `typ` other than `JWT`, a
  person's session claim, or a token not bound to a pod (no `kubernetes.io` claim, its namespace or
  service account not the `sub`'s, no `pod`, or a `secret` binding) (§13 decision 49 rulings 5–7);".

- [ ] **Step 4: the pointers.** Decision 39 ruling 1 (:8009): replace "`k8s` is refused, plan
  10." with "`k8s` under `machines` is plan 10's (decision 49).". Decision 40 ruling 15 (:8231):
  replace "`system:serviceaccount:` stays plan 10's." with "`system:serviceaccount:` is plan 10's
  (decision 49 ruling 8).". Design §7 (:472): replace "`k8s` is refused until plan 10." with
  "`k8s` is plan 10's (policy engine spec §13 decision 49): `issuer`, `cluster`, `jwks`,
  `audience` and `namespaces`, the keys read from `jwks`."

- [ ] **Step 5: decision 49.** Insert before `## 14. Required test assertions`:

```markdown
**49. Kubernetes service accounts: a named verifier per cluster, keys from its JWKS, a pod-bound
token, and a namespace several clusters may vouch for.** *Plan 10, 2026-10-16.* Rulings rest on
reasoning unless they say data. The planner ruled each where this document was silent; ruling 4
and ruling 11's TokenReview question were ruled for Ryan on 2026-10-16, and Ryan may override
any.

- **1. The verifier.** `type: k8s` under `broker.identity.machines` alone: `issuer` (an https
  URL, the cluster's `--service-account-issuer`, compared with `iss` byte for byte), `cluster`
  (the cluster's port49-side name, `^[a-z][a-z0-9_]{0,63}$` as a CRL source's name, unique
  across `k8s` verifiers except two on one `jwks`, which are one cluster under two issuers),
  `jwks` (an https URL with no userinfo, query or fragment), `audience`, `namespaces`,
  `ca_file`, `algorithms` (decision 39 ruling 3), nothing else; one per cluster, any number.
  `cluster` is configuration alone (no workload manifest changes) and not part of the
  principal; the record's `auth.k8s.cluster`, the start's lines and every refusal and warning a
  `k8s` verifier says name it, the issuer beside it.
- **2. Keys from `jwks`.** Decision 39 ruling 4's fetch, refresh, refetch, `jwks_max_age`,
  persistence and timings, from the configured URL, never from discovery (a cluster's issuer is
  often a name only the cluster resolves). After each fetch, once its outcome is out, the
  discovery document at the JWKS URL's origin is read to say, once per change, an `issuer` other
  than the configured one (and than another `k8s` verifier's on the same `jwks`), no `issuer`, or
  that it could not be read; its `jwks_uri` is not compared; it decides no key, fails no fetch and
  holds none. The fetch is anonymous: the broker holds no cluster credential. Provisional on L69
  (c).
- **3. One issuer, one cluster.** Two `k8s` verifiers with one issuer, or a `k8s` issuer an `oidc`
  verifier names, refuse the start.
- **4. Several clusters may vouch for one namespace.** `namespaces` is required, by name, no
  wildcard. Two `k8s` verifiers may list the same namespace: a workload deployed from the same
  manifests to several clusters is one identity, `system:serviceaccount:<ns>:<name>`; a
  compromised cluster already holds a genuine token for it, so refusing the overlap buys nothing,
  and a namespace per cluster is fleet toil. Where a namespace means different tenants in
  different clusters, the operator lists different namespaces per verifier. The overlap is made
  visible instead: the start names every cluster vouching for each namespace (ruling 13), and the
  record's `auth.k8s` carries `cluster`, `issuer`, `pod` and `node`. A cluster-qualified principal
  is a future opt-in, not this decision. Two verifiers with one `jwks` and different issuers are
  one cluster's issuer migration.
- **5. The audience.** `aud` is exactly one value, the configured `audience`.
- **6. The claims.** Decision 39 ruling 5's, with `typ` absent or `JWT` and decision 39 ruling 21's
  session and delegation claims refused. Past `max_token_age`, the refusal names the kubelet's
  refresh at about 80% of expirationSeconds (measured on kind, L69 (b)).
- **7. Bound to a pod.** `kubernetes.io` required and read by exact name at every level: its
  `namespace` and `serviceaccount.name` the `sub`'s, `serviceaccount.uid`, `pod.name` and
  `pod.uid` present, `secret` absent. No group, role or username is read (design §7). Provisional
  on L69 (a) and (g).
- **8. The principal.** `system:serviceaccount:<namespace>:<name>` from `sub` through one parser
  (`internal/k8sid`) for the policy, the verifier, `port49 revoke` and `port49 explain`; a `sub`
  outside it or an unlisted namespace is `identity_unmapped`.
- **9. The credential and the record.** `{method: k8s, iss, sub}`; `auth.k8s` with `cluster`
  (§5.7); an unverified bearer recorded by configuration's method alone.
- **10. The session clock** is `iat`; no owner record; no logout.
- **11. A deleted service account or pod.** No TokenReview call (ruled 2026-10-16: it would put
  every cluster's API server, and a stored cluster credential, on the mint path): a token stays valid at port49
  until `exp` or `iat` + `max_token_age` (measured on kind, L69 (e)); `port49 revoke --principal` ends it
  at once, and says the mark stands for a re-created account of that name until lifted.
- **12. Metrics.** `port49_oidc_*`, labelled by the configured issuer (shared with OIDC
  verifiers, and the key set's own key); no cluster, principal, namespace or device label.
- **13. The start** says each `k8s` verifier by its `cluster`, that it trusts the cluster's
  administrators and ruling 11's window, every cluster vouching for each namespace, and the
  `system:serviceaccount:` identities no verifier can give.
- **14. The client.** `port49 workload token|identity --token-file`: the bearer read at every
  attempt, never printed; refused beside `--cert`, `--key`, `--touch-key`; decision 40 ruling 10's
  exits, an unusable file exit 2.
- **15. Per-login MFA** on a `k8s` workload is never proved: `per_login_mfa_required`, not minted.
- **16. The lab.** L69 on kind; L70 (managed clusters) open.

*Left for later:* a cluster-qualified principal (`system:serviceaccount:<ns>:<name>` qualified
by `cluster`), as an opt-in, for an operator whose clusters' namespaces mean different tenants
and who would rather name them apart than list different namespaces.
```

- [ ] **Step 6: §15.** After the L68 row add (one line each in the file):

```markdown
| **L69** | A Kubernetes cluster's service account tokens as port49's `k8s` verifier meets them (plan 10), on kind: (a) a projected token's claims for `audience: port49-lab`, `expirationSeconds: 600` (`iss`, `aud`, `exp` − `iat`, `nbf`, `sub`, `kubernetes.io` with `namespace`, `serviceaccount`, `pod`, `node`, `jti`; the header's `alg`, `kid` and `typ`); (b) when the kubelet rewrites the file, as a fraction of `expirationSeconds`; (c) the issuer discovery document and `/openid/v1/jwks` read anonymously before and after binding `system:service-account-issuer-discovery` to `system:unauthenticated`, and discovery's `issuer` and `jwks_uri` against the API server's flags; (d) a signing key rotated at the API server, and whether port49 mints with the new key's token without a restart; (e) a token after its pod, then its service account, is deleted: what TokenReview answers and what port49 does; (f) a second cluster's token at a broker that lists only the first, for a namespace only the first lists, and for a namespace both list; (g) a token for another audience, an unbound `kubectl create token`, a Secret-bound and a Node-bound `kubectl create token`, and a legacy Secret token; (h) the default `kube-api-access` token's `aud` and lifetime. | §13 decision 49 rulings 2, 6, 7 and 11; `examples/kubernetes` | kind v0.29.0 (`kindest/node:v1.33.1`) | open |
| **L70** | L69's (a), (c) and (d) on managed clusters: whether EKS, GKE and AKS publish issuer discovery and the JWKS anonymously over the internet, the form of their issuer and `kid`, and how they rotate signing keys. | decision 49 ruling 2's anonymous fetch on managed clusters; the docs' managed-cluster section | EKS, GKE, AKS | open |
```

- [ ] **Step 7: Check and commit.**

Run: `grep -n "decision 49" docs/design/2026-08-23-policy-engine-spec.md | wc -l` (expect at least 8) and
`grep -n "k8s\` is refused" docs/design/*.md` (expect nothing).

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 49, the Kubernetes path, with L69 and L70

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: `internal/k8sid`, one parser for the principal

**Files:**
- Create: `internal/k8sid/k8sid.go`, `internal/k8sid/k8sid_test.go`
- Modify: `internal/policy/load.go:1369-1405` (the `serviceAccount` regexp), `internal/policy/member.go:293`
- Test: `internal/policy/load_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `k8sid.Prefix = "system:serviceaccount:"`, `k8sid.MaxLen = 339`, `type ID struct{ Namespace, Name string }`,
  `func (ID) String() string`, `func Parse(s string) (ID, error)`, `func CheckNamespace(ns string) error`,
  `var ErrNotServiceAccount`; `(*policy.Policy).ServiceAccountIdentities() map[string]string`.

- [ ] **Step 1: Write the failing tests.** `internal/k8sid/k8sid_test.go`:

```go
package k8sid

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]ID{
		"system:serviceaccount:netops:oxidized":      {"netops", "oxidized"},
		"system:serviceaccount:a:b":                  {"a", "b"},
		"system:serviceaccount:net-ops-1:backup.v2":  {"net-ops-1", "backup.v2"},
		"system:serviceaccount:kube-system:default":  {"kube-system", "default"},
	} {
		got, err := Parse(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"", "system:serviceaccount:", "system:serviceaccount:netops", "system:serviceaccount:netops:",
		"system:serviceaccount::oxidized", "System:serviceaccount:netops:oxidized",
		"system:serviceaccount:NetOps:oxidized", "system:serviceaccount:netops:Oxidized",
		"system:serviceaccount:-netops:oxidized", "system:serviceaccount:netops-:oxidized",
		"system:serviceaccount:netops:oxidized:extra", "system:serviceaccount:net_ops:oxidized",
		"system:serviceaccount:netops:a..b", "system:serviceaccount:netops:.a", "system:serviceaccount:netops:a.",
		"system:serviceaccount:" + strings.Repeat("a", 64) + ":x",
		"system:serviceaccount:netops:" + strings.Repeat("a", 254),
		"system:serviceaccount:netops:oxi dized", "system:serviceaccount:netops:oxidized\n",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
	if _, err := Parse("user:alice@example.com"); !errors.Is(err, ErrNotServiceAccount) {
		t.Fatalf("another form: %v", err)
	}
}

// Review Focus 5: a name of 253 bytes, the principal 339, parses whole.
func TestTheLongestServiceAccountParses(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	ns := strings.Repeat("n", 63)
	p := Prefix + ns + ":" + name
	if len(name) != 253 || len(p) != MaxLen {
		t.Fatalf("lengths %d %d", len(name), len(p))
	}
	if id, err := Parse(p); err != nil || id.Name != name || id.Namespace != ns {
		t.Fatalf("%v %v", id, err)
	}
}
```

  In `internal/policy/load_test.go` add:

```go
// The policy's load reads a service account as the verifier will give it
// (decision 49 ruling 8): one that no cluster can name fails CI.
func TestAServiceAccountIdentityIsTheVerifiersForm(t *testing.T) {
	for _, id := range []string{"system:serviceaccount:NetOps:oxidized", "system:serviceaccount:netops:a_b",
		"system:serviceaccount:netops:oxidized:x"} {
		src := strings.Replace(good, "system:serviceaccount:netops:oxidized", id, 1)
		if _, err := Parse([]byte(src), env()); err == nil || !strings.Contains(err.Error(), "system:serviceaccount:<namespace>:<name>") {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestServiceAccountIdentities(t *testing.T) {
	p := mustParse(t, good)
	if got := p.ServiceAccountIdentities(); len(got) != 1 || got["system:serviceaccount:netops:oxidized"] != "svc_oxidized" {
		t.Fatalf("%v", got)
	}
}
```

  `good` is the package const at `load_test.go:61` (spec §11's shape; its `svc_oxidized` subject
  lists `system:serviceaccount:netops:oxidized` and a `spiffe://` ID); `mustParse` and `env()` are
  the file's helpers (`Parse(raw []byte, env Env)`, `load.go:305`).

- [ ] **Step 2: Run them to see them fail.**

Run: `go test ./internal/k8sid/ ./internal/policy/ -run 'TestParse|TestTheLongest|TestAServiceAccount|TestServiceAccountIdentities' -count=1`
Expected: FAIL: `package internal/k8sid` has no Go files; `p.ServiceAccountIdentities undefined`.

- [ ] **Step 3: Implement.** `internal/k8sid/k8sid.go`:

```go
// Package k8sid is a Kubernetes service account principal (spec §2; §13
// decision 49 ruling 8): system:serviceaccount:<namespace>:<name>, as a
// cluster names it in a token's sub. One parser for the policy, the k8s
// verifier, port49 revoke and port49 explain, so each reads one string the
// same way. Nothing is folded: a cluster never names an account in upper case.
package k8sid

import (
	"errors"
	"fmt"
	"strings"
)

// Prefix begins every service account principal.
const Prefix = "system:serviceaccount:"

// MaxLen is the longest principal: a 63-byte namespace and a 253-byte name.
const MaxLen = len(Prefix) + 63 + 1 + 253

// ErrNotServiceAccount is a string that does not begin with Prefix.
var ErrNotServiceAccount = errors.New("k8sid: not a system:serviceaccount: principal")

// ID is a service account: its namespace and its name.
type ID struct{ Namespace, Name string }

func (id ID) String() string { return Prefix + id.Namespace + ":" + id.Name }

// Parse reads s as system:serviceaccount:<namespace>:<name>: the namespace an
// RFC 1123 label, the name an RFC 1123 subdomain, as Kubernetes validates them.
func Parse(s string) (ID, error) {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return ID{}, ErrNotServiceAccount
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok {
		return ID{}, errors.New("no name after the namespace")
	}
	if err := CheckNamespace(ns); err != nil {
		return ID{}, err
	}
	if len(name) == 0 || len(name) > 253 {
		return ID{}, fmt.Errorf("the name is %d bytes; a service account's is 1 to 253", len(name))
	}
	for _, l := range strings.Split(name, ".") {
		if !label(l) {
			return ID{}, fmt.Errorf("the name %q is not an RFC 1123 subdomain (a-z, 0-9, - and ., each part beginning "+
				"and ending with a letter or digit)", name)
		}
	}
	return ID{Namespace: ns, Name: name}, nil
}

// CheckNamespace is a namespace as Kubernetes validates one: an RFC 1123 label.
func CheckNamespace(ns string) error {
	if !label(ns) {
		return fmt.Errorf("the namespace %q is not an RFC 1123 label (1 to 63 of a-z, 0-9 and -, beginning and ending "+
			"with a letter or digit)", ns)
	}
	return nil
}

func label(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (c != '-' || i == 0 || i == len(l)-1) {
			return false
		}
	}
	return true
}
```

  In `internal/policy/load.go`, delete `var serviceAccount = regexp.MustCompile(...)` (:1369) and
  replace the `case serviceAccount.MatchString(id), strings.HasPrefix(id, "app:") …` arm with:

```go
	case strings.HasPrefix(strings.ToLower(id), k8sid.Prefix):
		// A cluster's service account (plan 10): checked as the verifier
		// checks it, so a policy naming one no cluster can give fails CI
		// (decision 49 ruling 8).
		if _, err := k8sid.Parse(id); err != nil {
			return "", fmt.Errorf("identity %q: a service account's principal is "+
				"system:serviceaccount:<namespace>:<name>, as its cluster names it (spec §2; §13 decision 49): %w", id, err)
		}
		return DomainMachines, nil
	case strings.HasPrefix(id, "app:") && len(id) > len("app:"):
		return DomainMachines, nil
```

  (drop the `regexp` import if nothing else uses it). In `internal/policy/member.go` after
  `SPIFFEIdentities`:

```go
// ServiceAccountIdentities is every system:serviceaccount: identity a subject
// lists, with the subject that lists it: the ones the start checks against
// the k8s verifiers' namespaces (decision 49 ruling 13).
func (p *Policy) ServiceAccountIdentities() map[string]string {
	out := map[string]string{}
	for id, name := range p.byID {
		if strings.HasPrefix(id, k8sid.Prefix) {
			out[id] = name
		}
	}
	return out
}
```

- [ ] **Step 4: Run the tests.**

Run: `go test ./internal/k8sid/ ./internal/policy/ -count=1`
Expected: PASS (every existing policy test too: they name `netops:oxidized`, which parses).

- [ ] **Step 5: Commit.**

```bash
git add internal/k8sid internal/policy/load.go internal/policy/member.go internal/policy/load_test.go
git commit -m "feat: internal/k8sid, one parser for a service account principal

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 3: `type: k8s` in the config

**Files:**
- Modify: `internal/oidc/config.go`, `internal/config/identity.go:31-51, 159-268, 390-485, 640-651`,
  `internal/config/config.go:1719-1729, 1842-1845`
- Test: `internal/config/identity_test.go`

**Interfaces:**
- Consumes: `k8sid.CheckNamespace` (Task 2).
- Produces: `oidc.KindK8s = "k8s"`; `oidc.VerifierConfig` fields `Kind string` (`""` is an oidc
  verifier), `Cluster string`, `JWKS string`, `Namespaces []string`; `oidc.Config.K8s
  []oidc.VerifierConfig` (each `Domain: oidc.Machines, Kind: oidc.KindK8s`); `func
  (oidc.VerifierConfig) ListsNamespace(ns string) bool`; `func (oidc.VerifierConfig) Who()
  string` (`cluster <name> (<issuer>)` for a k8s verifier, the issuer otherwise).

- [ ] **Step 1: Write the failing tests.** In `internal/config/identity_test.go`, remove the
  `"k8s"` case from `TestIdentityRefusals` (:101) and add:

```go
const k8sCluster = `  identity:
    machines:
      - type: k8s
        cluster: l69_a
        issuer: https://l69-a.port49.lab
        jwks: https://10.0.0.10:6443/openid/v1/jwks
        audience: port49
        namespaces: [netops, backup]
`

func TestAK8sVerifierLoads(t *testing.T) {
	c, err := loadWith(t, brokerWithIdentity(k8sCluster))
	if err != nil {
		t.Fatal(err)
	}
	id := c.Broker.Identity
	if len(id.K8s) != 1 || len(id.OIDC) != 0 {
		t.Fatalf("identity %+v", id)
	}
	v := id.K8s[0]
	if v.Domain != oidc.Machines || v.Kind != oidc.KindK8s || v.Cluster != "l69_a" || v.Issuer != "https://l69-a.port49.lab" ||
		v.JWKS != "https://10.0.0.10:6443/openid/v1/jwks" || v.Audience != "port49" ||
		strings.Join(v.Namespaces, " ") != "netops backup" || len(v.Algorithms) != 1 || v.Algorithms[0] != oidc.RS256 {
		t.Fatalf("k8s %+v", v)
	}
	if !v.ListsNamespace("netops") || v.ListsNamespace("kube-system") {
		t.Fatal("ListsNamespace")
	}
	if v.Who() != "cluster l69_a (https://l69-a.port49.lab)" {
		t.Fatal(v.Who())
	}
}

func TestK8sRefusals(t *testing.T) {
	ok := "type: k8s, cluster: l69_a, issuer: \"https://l69-a.port49.lab\", jwks: \"https://10.0.0.10:6443/openid/v1/jwks\", audience: port49, namespaces: [netops]"
	// b is another cluster: its own name, issuer and jwks.
	b := "type: k8s, cluster: l69_b, issuer: \"https://l69-b.port49.lab\", jwks: \"https://10.0.0.20:6443/openid/v1/jwks\", audience: port49"
	for name, c := range map[string]struct{ block, want string }{
		"under humans":   {"  identity:\n    humans: [{" + ok + "}]\n", "broker.identity.humans[0]: k8s is a machine verifier"},
		"no issuer":      {"  identity:\n    machines: [{type: k8s, cluster: c, jwks: \"https://h/j\", audience: a, namespaces: [n]}]\n", "broker.identity.machines[0].issuer must be an https URL"},
		"no cluster":     {"  identity:\n    machines: [{" + strings.Replace(ok, "cluster: l69_a, ", "", 1) + "}]\n", "broker.identity.machines[0].cluster is required"},
		"bad cluster":    {"  identity:\n    machines: [{" + strings.Replace(ok, "cluster: l69_a", "cluster: US-East", 1) + "}]\n", "broker.identity.machines[0].cluster must match"},
		"cluster twice":  {"  identity:\n    machines: [{" + ok + "}, {" + strings.Replace(b, "cluster: l69_b", "cluster: l69_a", 1) + ", namespaces: [backup]}]\n",
			"broker.identity.machines[1].cluster l69_a is also broker.identity.machines[0]'s: each cluster's name is its own (decision 49 ruling 1)"},
		"one jwks, two names": {"  identity:\n    machines: [{" + ok + "}, {" + strings.Replace(strings.Replace(ok, "l69_a", "l69_c", 1), "https://l69-a", "https://l69-new", 1) + "}]\n",
			"read one jwks, so they are one cluster under two issuers"},
		"http jwks":      {"  identity:\n    machines: [{" + strings.Replace(ok, "https://10.0.0.10", "http://10.0.0.10", 1) + "}]\n", "broker.identity.machines[0].jwks must be an https URL"},
		"jwks query":     {"  identity:\n    machines: [{" + strings.Replace(ok, "/jwks\"", "/jwks?x=1\"", 1) + "}]\n", "broker.identity.machines[0].jwks must be an https URL"},
		"no jwks":        {"  identity:\n    machines: [{type: k8s, cluster: c, issuer: \"https://l69-a.port49.lab\", audience: a, namespaces: [n]}]\n", "broker.identity.machines[0].jwks is required"},
		"no audience":    {"  identity:\n    machines: [{" + strings.Replace(ok, "audience: port49, ", "", 1) + "}]\n", "broker.identity.machines[0].audience is required"},
		"no namespaces":  {"  identity:\n    machines: [{" + strings.Replace(ok, ", namespaces: [netops]", "", 1) + "}]\n", "broker.identity.machines[0].namespaces is required"},
		"bad namespace":  {"  identity:\n    machines: [{" + strings.Replace(ok, "[netops]", "[NetOps]", 1) + "}]\n", "broker.identity.machines[0].namespaces: \"NetOps\""},
		"wildcard":       {"  identity:\n    machines: [{" + strings.Replace(ok, "[netops]", "[\"*\"]", 1) + "}]\n", "broker.identity.machines[0].namespaces: \"*\""},
		"clients":        {"  identity:\n    machines: [{" + ok + ", clients: [{client_id: x, sub: y}]}]\n", "broker.identity.machines[0]: type k8s takes issuer, cluster, jwks, audience, namespaces, ca_file and algorithms alone"},
		"trust anchor":   {"  identity:\n    machines: [{" + ok + ", trust_anchor_file: /a.pem}]\n", "type k8s takes issuer, cluster, jwks, audience, namespaces, ca_file and algorithms alone"},
		"cluster on oidc": {"  identity:\n    machines: [{type: oidc, cluster: x, issuer: \"https://idp.example.com\", audience: x, clients: [{client_id: c, sub: s}]}]\n",
			"broker.identity.machines[0]: jwks, namespaces and cluster are a k8s verifier's"},
		"HS256":          {"  identity:\n    machines: [{" + ok + ", algorithms: [HS256]}]\n", "broker.identity.machines[0].algorithms: HS256 is refused"},
		"one issuer twice": {"  identity:\n    machines: [{" + ok + "}, {" + strings.Replace(strings.Replace(ok, "[netops]", "[backup]", 1), "l69_a", "l69_c", 1) + "}]\n",
			"broker.identity.machines[1].issuer https://l69-a.port49.lab is also broker.identity.machines[0]'s"},
		"issuer folds":   {"  identity:\n    machines: [{" + ok + "}, {" + strings.Replace(strings.Replace(strings.Replace(ok, "https://l69-a", "HTTPS://L69-A", 1), "[netops]", "[backup]", 1), "l69_a", "l69_c", 1) + "}]\n",
			"differ only by a trailing slash or by case"},
		"an oidc issuer": {"  identity:\n    machines: [{" + ok + "}, {type: oidc, issuer: \"https://l69-a.port49.lab\", audience: x, clients: [{client_id: c, sub: s}]}]\n",
			"broker.identity.machines[1].issuer https://l69-a.port49.lab is also broker.identity.machines[0]'s, a k8s verifier's"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadWith(t, brokerWithIdentity(c.block))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// Several clusters may vouch for one namespace (decision 49 ruling 4, ruled
// 2026-10-16): a workload deployed to each region is one identity.
func TestTwoClustersMayListOneNamespace(t *testing.T) {
	block := `  identity:
    machines:
      - {type: k8s, cluster: us_east, issuer: "https://us-east.k8s.example.com", jwks: "https://10.0.0.10:6443/openid/v1/jwks", audience: port49, namespaces: [netops]}
      - {type: k8s, cluster: eu_west, issuer: "https://eu-west.k8s.example.com", jwks: "https://10.1.0.10:6443/openid/v1/jwks", audience: port49, namespaces: [backup, netops]}
`
	c, err := loadWith(t, brokerWithIdentity(block))
	if err != nil || len(c.Broker.Identity.K8s) != 2 {
		t.Fatalf("%v", err)
	}
	for _, v := range c.Broker.Identity.K8s {
		if !v.ListsNamespace("netops") {
			t.Fatalf("%s does not list netops", v.Cluster)
		}
	}
}

// Review Focus 4: one cluster under two issuers (a migration) loads, its
// two verifiers sharing the cluster's name.
func TestAK8sIssuerMigrationLoads(t *testing.T) {
	block := `  identity:
    machines:
      - {type: k8s, cluster: l69_a, issuer: "https://old.port49.lab", jwks: "https://10.0.0.10:6443/openid/v1/jwks", audience: port49, namespaces: [netops]}
      - {type: k8s, cluster: l69_a, issuer: "https://new.port49.lab", jwks: "https://10.0.0.10:6443/openid/v1/jwks", audience: port49, namespaces: [netops]}
`
	c, err := loadWith(t, brokerWithIdentity(block))
	if err != nil || len(c.Broker.Identity.K8s) != 2 {
		t.Fatalf("%v", err)
	}
}

// The kept key files of a k8s issuer are in the collision lists, as an OIDC
// issuer's are (pre-flight M-11 of plan 7h).
func TestAK8sIssuersKeyFileIsChecked(t *testing.T) {
	c, err := loadWith(t, brokerWithIdentity(k8sCluster))
	if err != nil {
		t.Fatal(err)
	}
	if got := identityIssuers(c.Broker); len(got) != 1 || got[0] != "https://l69-a.port49.lab" {
		t.Fatalf("%v", got)
	}
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `go test ./internal/config/ -run 'TestAK8s|TestK8sRefusals|TestTwoClusters' -count=1`
Expected: FAIL: `id.K8s undefined`, `oidc.KindK8s undefined`.

- [ ] **Step 3: Implement.** In `internal/oidc/config.go`, add to `VerifierConfig` (after `CAFile`):

```go
	// Kind is "" for an oidc verifier and KindK8s for a cluster's (plan 10;
	// spec §13 decision 49): a k8s verifier is a machine verifier keyed by
	// Issuer, named Cluster on the port49 side, its keys fetched from JWKS,
	// its principals in Namespaces.
	Kind       string
	Cluster    string
	JWKS       string
	Namespaces []string
```

  and:

```go
// KindK8s is a Kubernetes cluster's verifier (decision 49 ruling 1).
const KindK8s = "k8s"

// ListsNamespace reports whether a k8s verifier may name ns's service
// accounts (decision 49 ruling 8).
func (v VerifierConfig) ListsNamespace(ns string) bool { return slices.Contains(v.Namespaces, ns) }

// Who is how the operator's lines name v: a k8s verifier by its cluster,
// the issuer beside it; any other by its issuer (decision 49 ruling 1).
func (v VerifierConfig) Who() string {
	if v.Kind == KindK8s {
		return "cluster " + v.Cluster + " (" + v.Issuer + ")"
	}
	return v.Issuer
}
```

  and to `Config`, after `OIDC`: `K8s []VerifierConfig // the k8s verifiers, one per cluster (plan 10)`.

  In `internal/config/identity.go`: add to `identityVerifierYAML` `Cluster string
  \`yaml:"cluster"\``, `JWKS string \`yaml:"jwks"\`` and `Namespaces []string
  \`yaml:"namespaces"\``, and:

```go
// k8sKeys reports whether v sets a key only a k8s verifier takes.
func (v identityVerifierYAML) k8sKeys() bool { return v.Cluster != "" || v.JWKS != "" || v.Namespaces != nil }

// clusterName is a k8s verifier's cluster: a CRL source's name shape
// (config.go's crlName), since it is configuration's word for a cluster, not
// the cluster's own (decision 49 ruling 1).
var clusterName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
```

  Add `|| v.k8sKeys()` to the x509 machine, x509 human and directory_password refusal
  conditions, and to `checkOIDCVerifier`'s first refusal (`"config: %s: jwks, namespaces and
  cluster are a k8s verifier's"`). Replace the `case v.Type == "k8s":` arm with:

```go
			case v.Type == "k8s" && list.domain == oidc.Humans:
				return nil, fmt.Errorf("config: %s: k8s is a machine verifier: a cluster's service accounts are "+
					"workloads; list it under machines", at)
			case v.Type == "k8s":
				vc, err := checkK8sVerifier(at, v)
				if err != nil {
					return nil, err
				}
				out.K8s = append(out.K8s, vc)
```

  change the default arm's text to `"one of x509, oidc, k8s or directory_password"`, the
  accepts-no-one condition to add `&& len(out.K8s) == 0`, and after `distinctVerifiers` add
  `if err := distinctClusters(out.K8s, out.OIDC, *y); err != nil { return nil, err }`. Then:

```go
// checkK8sVerifier resolves a k8s verifier (plan 10; spec §13 decision 49
// rulings 1, 4 and 5). Its namespaces may be another cluster's too (ruling 4).
func checkK8sVerifier(at string, v identityVerifierYAML) (oidc.VerifierConfig, error) {
	if v.TrustAnchorFile != "" || v.SPIFFETrustDomains != nil || v.Directory != nil || v.ClientID != "" ||
		v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil || v.passwordKeys() {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s: type k8s takes issuer, cluster, jwks, audience, namespaces, "+
			"ca_file and algorithms alone", at)
	}
	if !httpsURL(v.Issuer) {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.issuer must be an https URL with no userinfo, query or "+
			"fragment: the cluster's --service-account-issuer, as its tokens carry it in iss", at)
	}
	switch {
	case v.Cluster == "":
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.cluster is required: this cluster's name in port49's "+
			"records and lines (us_east, say); nothing in the cluster changes", at)
	case !clusterName.MatchString(v.Cluster):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.cluster must match %s", at, clusterName)
	case v.JWKS == "":
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.jwks is required: the URL the cluster's keys are read "+
			"from (the API server's https://<host>:<port>/openid/v1/jwks, or where your cluster publishes them)", at)
	case !httpsURL(v.JWKS):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.jwks must be an https URL with no userinfo, query or fragment", at)
	case !printableKey(v.Audience):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is required: the audience your pods' projected "+
			"token volume asks for (port49 in the examples)", at)
	case len(v.Namespaces) == 0:
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.namespaces is required: the namespaces whose service "+
			"accounts this cluster may name, by name", at)
	}
	var nss []string
	for _, ns := range v.Namespaces {
		if err := k8sid.CheckNamespace(ns); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.namespaces: %q: %v", at, ns, err)
		}
		if !slices.Contains(nss, ns) {
			nss = append(nss, ns)
		}
	}
	algs, err := oidc.ParseAlgs(v.Algorithms)
	if err != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.algorithms: %w", at, err)
	}
	if v.CAFile != "" {
		if err := readableFile(at+".ca_file", v.CAFile); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %w", err)
		}
	}
	return oidc.VerifierConfig{Domain: oidc.Machines, Kind: oidc.KindK8s, Issuer: v.Issuer, Cluster: v.Cluster,
		JWKS: v.JWKS, Audience: v.Audience, Namespaces: nss, Algorithms: algs, CAFile: v.CAFile}, nil
}

// httpsURL is an https URL with a host and no userinfo, query or fragment.
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return s != "" && err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// distinctClusters is decision 49 rulings 1 and 3: one issuer per cluster,
// never an oidc verifier's issuer, and one name per cluster. Two verifiers on
// one jwks are one cluster under two issuers (a migration), and share its
// name. Namespaces are not compared: several clusters may vouch for one
// (ruling 4), which the start says.
func distinctClusters(ks, os []oidc.VerifierConfig, y identityYAML) error {
	at := func(i int) string {
		n := -1
		for j, v := range y.Machines {
			if v.Type == "k8s" {
				if n++; n == i {
					return fmt.Sprintf("broker.identity.machines[%d]", j)
				}
			}
		}
		return "broker.identity.machines[?]"
	}
	// oidcAt is where the oidc verifier of issuer iss is listed.
	oidcAt := func(iss string) string {
		for j, v := range y.Humans {
			if v.Type == "oidc" && issuerForm(v.Issuer) == issuerForm(iss) {
				return fmt.Sprintf("broker.identity.humans[%d]", j)
			}
		}
		for j, v := range y.Machines {
			if v.Type == "oidc" && issuerForm(v.Issuer) == issuerForm(iss) {
				return fmt.Sprintf("broker.identity.machines[%d]", j)
			}
		}
		return "an oidc verifier"
	}
	for i, b := range ks {
		for _, o := range os {
			if issuerForm(o.Issuer) == issuerForm(b.Issuer) {
				return fmt.Errorf("config: %s.issuer %s is also %s's, a k8s verifier's: one issuer is one cluster's "+
					"or one provider's (decision 49 ruling 3)", oidcAt(o.Issuer), o.Issuer, at(i))
			}
		}
		for j := range i {
			a := ks[j]
			switch {
			case a.Issuer == b.Issuer:
				return fmt.Errorf("config: %s.issuer %s is also %s's: each cluster needs its own "+
					"--service-account-issuer (kubeadm's default is the same on every cluster) (decision 49 ruling 3)",
					at(i), b.Issuer, at(j))
			case issuerForm(a.Issuer) == issuerForm(b.Issuer):
				return fmt.Errorf("config: %s.issuer and %s.issuer differ only by a trailing slash or by case in the "+
					"scheme or host; list each issuer once, spelled as the cluster spells it", at(i), at(j))
			case a.Cluster == b.Cluster && a.JWKS != b.JWKS:
				return fmt.Errorf("config: %s.cluster %s is also %s's: each cluster's name is its own (decision 49 "+
					"ruling 1); two verifiers share one only on the same jwks, one cluster under two issuers",
					at(i), b.Cluster, at(j))
			case a.Cluster != b.Cluster && a.JWKS == b.JWKS:
				return fmt.Errorf("config: %s and %s read one jwks, so they are one cluster under two issuers: give "+
					"them one cluster name, not %s and %s", at(j), at(i), a.Cluster, b.Cluster)
			}
		}
	}
	return nil
}
```

  Import `internal/k8sid`.

  `identityIssuers` (:640): loop over `append(slices.Clone(b.Identity.OIDC), b.Identity.K8s...)`.
  `config.go:1726`: the `ca_file` collision loop likewise covers `b.Identity.K8s`.

- [ ] **Step 4: Run the tests.**

Run: `go test ./internal/config/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/oidc/config.go internal/config/identity.go internal/config/config.go internal/config/identity_test.go
git commit -m "feat: config takes a k8s verifier under broker.identity.machines

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: Keys from a configured JWKS, and the discovery check

**Files:**
- Modify: `internal/oidc/keyset.go` (`KeySetConfig`, `KeySet`, `fetch`, `fetchOnce`)
- Create: `internal/oidc/keyset_k8s_test.go`
- Modify: `internal/oidc/oidctest/issuer.go` (`DiscoveryStatus`, `HoldDiscovery`), `internal/oidc/export_test.go` (`WaitDiscoveryForTest`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `KeySetConfig.JWKS string`: when set, keys are fetched from it, and discovery is read
  at its origin, after the fetch's outcome is out, only to say (decision 49 ruling 2);
  `KeySetConfig.Migrating []string`, the other issuers on the same `jwks` (Task 7 fills it).

- [ ] **Step 1: Write the failing tests.** `internal/oidc/keyset_k8s_test.go`:

```go
package oidc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

const k8sIssuer = "https://kubernetes.default.svc.cluster.local"

// clusterKeys is a key set reading iss's /jwks directly, configured with
// k8sIssuer, which nothing resolves; migrating are the other issuers on the
// same jwks.
func clusterKeys(t *testing.T, iss *oidctest.Issuer, c *clock, s *said, migrating ...string) *oidc.KeySet {
	t.Helper()
	return oidc.NewKeySet(oidc.KeySetConfig{Issuer: k8sIssuer, JWKS: iss.URL + "/jwks", Migrating: migrating,
		Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now,
		M: metrics.New(prometheus.NewRegistry()), Say: s.Say})
}

// fetch fetches once and waits for the discovery read that follows it, which
// runs after Fetch returns (pre-flight I8).
func fetch(t *testing.T, ks *oidc.KeySet) {
	t.Helper()
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks.WaitDiscoveryForTest()
}

// A discovery that agrees is silent, and so is its jwks_uri naming the
// issuer's host, as every self-managed cluster's does (pre-flight I7): the
// configured jwks is the API server's address, which discovery never names.
func TestAClusterKeySetReadsTheConfiguredJWKS(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = k8sIssuer; d["jwks_uri"] = k8sIssuer + "/openid/v1/jwks" })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	if keys, _, _ := ks.Status(); len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	if strings.Contains(s.all(), "discovery") || strings.Contains(s.all(), "jwks_uri") {
		t.Fatalf("a matching discovery is said: %s", s.all())
	}
}

// The keys come from jwks whatever discovery says: an unreachable discovery
// changes nothing, and is said once.
func TestAClusterKeySetNeedsNoDiscovery(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.DiscoveryStatus(http.StatusForbidden)
	ks := clusterKeys(t, iss, c, s)
	for range 2 {
		fetch(t, ks)
	}
	if n := strings.Count(s.all(), "the cluster's discovery at "+iss.URL+"/.well-known/openid-configuration could not be read"); n != 1 {
		t.Fatalf("said %d times: %s", n, s.all())
	}
}

func TestAClusterKeySetSaysADifferentIssuer(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = "https://l69-a.port49.lab" })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	want := "names issuer https://l69-a.port49.lab: its tokens carry that iss, so each is refused until " +
		"broker.identity.machines[].issuer is https://l69-a.port49.lab"
	if !strings.Contains(s.all(), want) {
		t.Fatalf("said %s", s.all())
	}
}

// During an issuer migration (decision 49 ruling 4) discovery names the
// other configured issuer: no false alarm (pre-flight I7).
func TestAClusterKeySetIsQuietDuringAMigration(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = "https://new.port49.lab" })
	ks := clusterKeys(t, iss, c, s, "https://new.port49.lab")
	fetch(t, ks)
	if strings.Contains(s.all(), "names issuer") {
		t.Fatalf("said %s", s.all())
	}
}

// A discovery document with no issuer says so, not "names issuer :"
// (pre-flight M2).
func TestAClusterKeySetSaysNoIssuer(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { delete(d, "issuer") })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	if !strings.Contains(s.all(), "names no issuer") || strings.Contains(s.all(), "names issuer :") {
		t.Fatalf("said %s", s.all())
	}
}

// A stalled discovery holds no mint: the fetch's outcome is out before
// discovery is read (pre-flight I8).
func TestAStalledDiscoveryHoldsNoFetch(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	_, release := iss.HoldDiscovery()
	defer release()
	ks := clusterKeys(t, iss, c, s)
	done := make(chan error, 1)
	go func() { done <- ks.Fetch(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Fetch waited on a stalled discovery")
	}
}

// A failed JWKS fetch is a failed fetch, counted, as for an OIDC issuer; a
// failed discovery is not.
func TestAClusterJWKSOutageKeepsTheHeldKeys(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := clusterKeys(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Fail(http.StatusServiceUnavailable)
	c.Add(2 * time.Hour)
	if err := ks.Fetch(context.Background()); err == nil {
		t.Fatal("a 503 JWKS fetch succeeded")
	}
	if k, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil || k.Kid != "k1" {
		t.Fatalf("the held key: %v %v", k, err)
	}
	if !strings.Contains(s.all(), "keys not refreshed since") {
		t.Fatalf("said %s", s.all())
	}
}
```

  `oidctest.Issuer.Fail` today fails discovery and /jwks together; add
  `func (i *Issuer) DiscoveryStatus(status int)`, which fails discovery alone (a field read by the
  discovery handler only), and make `Fail` set both as before. Add
  `func (i *Issuer) HoldDiscovery() (arrived <-chan struct{}, release func())`, `Hold`'s twin for
  the discovery handler (its own gate fields, the handler waiting on the gate or the request's
  context). In `export_test.go` add `func (s *KeySet) WaitDiscoveryForTest() { s.noted.Wait() }`.

- [ ] **Step 2: Run them to see them fail.**

Run: `go test ./internal/oidc/ -run 'TestACluster' -count=1`
Expected: FAIL: `unknown field JWKS in struct literal` (and `Migrating`, `HoldDiscovery`, `WaitDiscoveryForTest`).

- [ ] **Step 3: Implement.** In `KeySetConfig` add:

```go
	// JWKS, when set, is where keys are fetched from, directly: a k8s
	// verifier's (decision 49 ruling 2). Discovery is then read at its
	// origin only to say where it differs, never to find a key.
	JWKS string
	// Migrating are the issuers of the other k8s verifiers on this JWKS:
	// one cluster under several issuers (decision 49 ruling 4). A
	// discovery naming one of them is not said.
	Migrating []string
	// Who names the key set in every line it says and every error it
	// gives: VerifierConfig.Who, "cluster us_east (<issuer>)" for a k8s
	// verifier (decision 49 ruling 1). "" is the issuer, as today.
	Who string
```

  Every `s.c.Say("identity: %s: …", iss, …)` in `keyset.go` (`fetchOnce`, `save`, `sayStale`,
  and the new `sayDiscovery`) names `s.who()` (`cmp.Or(s.c.Who, s.c.Issuer)`) in place of the
  issuer; the metric labels stay `s.c.Issuer` (decision 49 ruling 12).

  In `KeySet` add `disco string // the last discovery note said, "" for none` and
  `noted sync.WaitGroup // discovery reads under way, for WaitDiscoveryForTest`, and a constant
  `discoveryTimeout = 3 * time.Second`. `fetch` keeps its five returns; its k8s arm comes first:

```go
func (s *KeySet) fetch(ctx context.Context) (string, []byte, []Key, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	if s.c.JWKS != "" {
		body, keys, skipped, err := s.readJWKS(ctx, s.c.JWKS)
		if err != nil {
			return "", nil, nil, nil, err
		}
		return s.c.JWKS, body, keys, skipped, nil
	}
	// … the existing discovery-then-jwks_uri body, unchanged, its JWKS read and
	// parse moved into readJWKS …
}

// readJWKS is one JWKS read: a set with no usable key is a failed fetch.
func (s *KeySet) readJWKS(ctx context.Context, u string) ([]byte, []Key, []string, error) {
	body, err := s.get(ctx, u)
	if err != nil {
		return nil, nil, nil, err
	}
	keys, skipped, err := ParseJWKS(body)
	switch {
	case err != nil:
		return nil, nil, nil, err
	case len(keys) == 0:
		return nil, nil, nil, fmt.Errorf("the JWKS holds no key port49 can verify with (%d skipped)", len(skipped))
	}
	return body, keys, skipped, nil
}

// discoveryNote is what a cluster's discovery says against the configured
// issuer, read at the jwks URL's origin: "" when it agrees, or when it names
// another issuer configured on this jwks (a migration). It never fails the
// fetch (decision 49 ruling 2). jwks_uri is not compared: a self-managed
// cluster's names the issuer's host, which the broker reaches by another
// address, so the note would fire on every correct config (pre-flight I7).
func (s *KeySet) discoveryNote(ctx context.Context) string {
	u, _ := url.Parse(s.c.JWKS)
	at := u.Scheme + "://" + u.Host + "/.well-known/openid-configuration"
	raw, err := s.get(ctx, at)
	if err != nil {
		return fmt.Sprintf("the cluster's discovery at %s could not be read (%s): its issuer is not checked against "+
			"the configured one; keys are still read from jwks", at, printsafe.Line(err.Error(), 200))
	}
	doc, err := exactObject(raw)
	if err != nil {
		return fmt.Sprintf("the cluster's discovery at %s is not a JSON object of distinct members; keys are still "+
			"read from jwks", at)
	}
	iss, ok := discoveryMember(doc, "issuer")
	switch {
	case !ok:
		return fmt.Sprintf("the cluster's discovery (%s) names no issuer: its issuer is not checked against the "+
			"configured one; keys are still read from jwks", at)
	case iss == s.c.Issuer || slices.Contains(s.c.Migrating, iss):
		return ""
	}
	return fmt.Sprintf("the cluster's discovery (%s) names issuer %s: its tokens carry that iss, so each is "+
		"refused until broker.identity.machines[].issuer is %s", at, printsafe.Line(iss, 200), printsafe.Line(iss, 200))
}

// sayDiscovery reads discovery after the fetch's outcome is out, on its own
// short timeout, and says a note that changed. A slow or dropped discovery
// endpoint then holds no mint waiting on a refetch (pre-flight I8).
func (s *KeySet) sayDiscovery() {
	defer s.noted.Done()
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	note := s.discoveryNote(ctx)
	s.mu.Lock()
	changed := note != s.disco
	s.disco = note
	s.mu.Unlock()
	if changed && note != "" {
		s.c.Say("identity: %s: %s", s.who(), note)
	}
}
```

  In `fetchOnce`, before `close(ch)`: `disco := err == nil && s.c.JWKS != ""; if disco {
  s.noted.Add(1) }`; and at the end of the success path (after the `saySkips` lines, before the
  save): `if disco { go s.sayDiscovery() }`. The JWKS read's outcome and its waiters are released
  first, and the save does not wait either, so a mint waiting on a refetch never waits on
  discovery; the read is counted in no metric. (The discovery's `issuer` is a public document's value from a URL configuration names,
  not a token's claim, so ruling 18 of decision 39 does not reach it; it is bounded by
  `printsafe.Line`.)

- [ ] **Step 4: Run the tests.**

Run: `go test ./internal/oidc/ -count=1`
Expected: PASS, the OIDC key set tests included (their path is unchanged).

- [ ] **Step 5: Commit.**

```bash
git add internal/oidc/keyset.go internal/oidc/keyset_k8s_test.go internal/oidc/oidctest/issuer.go
git commit -m "feat: a key set reads a cluster's JWKS directly and says where discovery differs

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: The k8s claims

**Files:**
- Create: `internal/oidc/k8s.go`, `internal/oidc/k8s_test.go`
- Modify: `internal/oidc/verify.go` (`refusal`, `Assertion`, `Credential`, `Set.verify`, `Verifier.verify`),
  `internal/oidc/oidctest/issuer.go` (`ServiceAccountToken`)

**Interfaces:**
- Consumes: `oidc.VerifierConfig.Kind/Namespaces/ListsNamespace` (Task 3), `KeySetConfig.JWKS`
  (Task 4), `k8sid.Parse` (Task 2).
- Produces: `oidc.K8sBinding{Cluster, ServiceAccountUID, Pod, PodUID, Node, JTI string}` (`Cluster`
  the accepting verifier's configured name);
  `Assertion.K8s *K8sBinding` (non-nil exactly when a k8s verifier accepted); `Credential()`
  gives `Method: "k8s"` for it; `func MethodOf(err error) string` (`"k8s"` or `"oidc"`);
  `func (i *oidctest.Issuer) ServiceAccountToken(t testing.TB, kid, issuer, aud, ns, sa string, now time.Time, extra map[string]any) string`.

- [ ] **Step 1: The test helper.** In `oidctest/issuer.go`:

```go
// ServiceAccountToken is a projected service account token as a cluster
// issues one (L69 (a) records a real one): iss, aud [aud], sub, iat, nbf,
// exp (now+10m), jti, and kubernetes.io binding it to a pod on a node; extra
// overrides, a nil value deleting. The pod is sa-7d9f, cut at 253 bytes
// (Kubernetes' own pod-name limit), so a 253-byte account's pod is still one
// a cluster could name (pre-flight I5).
func (i *Issuer) ServiceAccountToken(t testing.TB, kid, issuer, aud, ns, sa string, now time.Time, extra map[string]any) string {
	pod := sa + "-7d9f"
	if len(pod) > 253 {
		pod = pod[:253]
	}
	c := map[string]any{"iss": issuer, "aud": []string{aud}, "sub": "system:serviceaccount:" + ns + ":" + sa,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": "6f1c2d3e-0000-4000-8000-000000000069",
		"kubernetes.io": map[string]any{"namespace": ns,
			"serviceaccount": map[string]any{"name": sa, "uid": "0b5d7c1a-0000-4000-8000-000000000001"},
			"pod":            map[string]any{"name": pod, "uid": "9e1c4b2d-0000-4000-8000-000000000002"},
			"node":           map[string]any{"name": "l69-a-worker", "uid": "44aa1f3b-0000-4000-8000-000000000003"}}}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return i.Token(t, kid, c)
}
```

- [ ] **Step 2: Write the failing tests.** `internal/oidc/k8s_test.go`:

```go
package oidc_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

func cluster(ns ...string) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Machines, Kind: oidc.KindK8s, Cluster: "l69_a", Issuer: k8sIssuer, Audience: "port49",
		Namespaces: ns, Algorithms: []oidc.Alg{oidc.RS256}}
}

func k8sSet(t *testing.T, iss *oidctest.Issuer, c *clock, v oidc.VerifierConfig) *oidc.Set {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	v.JWKS = iss.URL + "/jwks"
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: v.Issuer, JWKS: v.JWKS, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	return &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m, Verifiers: []*oidc.Verifier{{VerifierConfig: v, Keys: ks}}}
}

func TestAServiceAccountTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	a, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "oxidized", c.Now(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Machines || a.Principal != "system:serviceaccount:netops:oxidized" || !a.AuthTime.Equal(c.Now()) ||
		a.K8s == nil || a.K8s.Pod != "oxidized-7d9f" || a.K8s.PodUID == "" || a.K8s.ServiceAccountUID == "" ||
		a.K8s.Node != "l69-a-worker" || a.K8s.JTI == "" || a.K8s.Cluster != "l69_a" {
		t.Fatalf("assertion %+v %+v", a, a.K8s)
	}
	if cred := a.Credential(); cred.Method != "k8s" || cred.Iss != k8sIssuer || cred.Sub != a.Principal || cred.Sid != "" {
		t.Fatalf("credential %+v", cred)
	}
}

func TestK8sRefusals(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	now := c.Now()
	bind := func(f func(m map[string]any)) map[string]any {
		m := map[string]any{"namespace": "netops",
			"serviceaccount": map[string]any{"name": "oxidized", "uid": "u1"},
			"pod":            map[string]any{"name": "p", "uid": "u2"}}
		f(m)
		return map[string]any{"kubernetes.io": m}
	}
	for name, tc := range map[string]struct {
		extra map[string]any
		kind  error
		want  string
	}{
		"two audiences":    {map[string]any{"aud": []string{"port49", "vault"}}, oidc.ErrInvalid, "its aud is not exactly [port49]"},
		"another audience": {map[string]any{"aud": "https://kubernetes.default.svc"}, oidc.ErrInvalid, "its aud is not exactly [port49]"},
		"no exp":           {map[string]any{"exp": nil}, oidc.ErrInvalid, "it has no exp"},
		"no iat":           {map[string]any{"iat": nil}, oidc.ErrInvalid, "it has no iat"},
		"old":              {map[string]any{"iat": now.Add(-3 * time.Hour).Unix(), "exp": now.Add(time.Hour).Unix()}, oidc.ErrInvalid,
			"the kubelet refreshes a projected token at about 80% of its expirationSeconds, so keep expirationSeconds at or under 3600"},
		"ahead":            {map[string]any{"iat": now.Add(2 * time.Minute).Unix()}, oidc.ErrInvalid, "ahead of the broker's clock"},
		"a session claim":  {map[string]any{"auth_time": now.Unix()}, oidc.ErrInvalid, "it carries auth_time"},
		"no binding":       {map[string]any{"kubernetes.io": nil}, oidc.ErrInvalid, "it carries no kubernetes.io claim"},
		"no pod":           {bind(func(m map[string]any) { delete(m, "pod") }), oidc.ErrInvalid, "it is not bound to a pod"},
		"secret-bound":     {bind(func(m map[string]any) { m["secret"] = map[string]any{"name": "s", "uid": "u"} }), oidc.ErrInvalid, "it is bound to a Secret"},
		"another account":  {bind(func(m map[string]any) { m["serviceaccount"] = map[string]any{"name": "other", "uid": "u"} }), oidc.ErrInvalid, "does not name its sub's service account"},
		"another ns":       {bind(func(m map[string]any) { m["namespace"] = "backup" }), oidc.ErrInvalid, "does not name its sub's service account"},
		"no sa uid":        {bind(func(m map[string]any) { m["serviceaccount"] = map[string]any{"name": "oxidized"} }), oidc.ErrInvalid, "no serviceaccount uid"},
		"not a sa sub":     {map[string]any{"sub": "admin"}, oidc.ErrUnmapped, "its sub is not system:serviceaccount:<namespace>:<name>"},
		"unlisted ns":      {map[string]any{"sub": "system:serviceaccount:kube-system:default", "kubernetes.io": map[string]any{"namespace": "kube-system",
			"serviceaccount": map[string]any{"name": "default", "uid": "u"}, "pod": map[string]any{"name": "p", "uid": "u"}}},
			oidc.ErrUnmapped, "its namespace kube-system is not one cluster l69_a (" + k8sIssuer + ") lists in namespaces"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "oxidized", now, tc.extra))
			if !errors.Is(err, tc.kind) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %v %q", err, tc.kind, tc.want)
			}
			if oidc.MethodOf(err) != "k8s" {
				t.Fatalf("method %q", oidc.MethodOf(err))
			}
		})
	}
}

// A typ of at+jwt is a provider's access token, never a cluster's.
func TestAK8sTokenTypIsJWTOrNone(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	claims := map[string]any{"iss": k8sIssuer, "aud": []string{"port49"}, "sub": "system:serviceaccount:netops:oxidized",
		"iat": c.Now().Unix(), "exp": c.Now().Add(time.Minute).Unix(), "kubernetes.io": map[string]any{"namespace": "netops",
			"serviceaccount": map[string]any{"name": "oxidized", "uid": "u"}, "pod": map[string]any{"name": "p", "uid": "u"}}}
	for typ, ok := range map[string]bool{"JWT": true, "application/jwt": true, "at+jwt": false, "logout+jwt": false} {
		_, err := set.Verify(context.Background(), iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, claims))
		if (err == nil) != ok {
			t.Errorf("typ %s: %v", typ, err)
		}
	}
}

// Review Focus 1: the binding is read by exact name at every level.
func TestAK8sBindingIsReadByExactName(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	now := c.Now()
	for name, body := range map[string]string{
		"Kubernetes.io": `"Kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"}}`,
		"Pod":           `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"Pod":{"name":"p","uid":"u"}}`,
		"Name":          `"kubernetes.io":{"namespace":"netops","serviceaccount":{"Name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"}}`,
		"two pods":      `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"},"pod":{"name":"q","uid":"v"}}`,
	} {
		raw := iss.TokenRaw(t, "k1", fmt.Sprintf(`{"iss":%q,"aud":["port49"],"sub":"system:serviceaccount:netops:oxidized",`+
			`"iat":%d,"exp":%d,%s}`, k8sIssuer, now.Unix(), now.Add(time.Minute).Unix(), body))
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Review Focus 3: a cluster signing ES256 under the default RS256 pin.
func TestAK8sTokenUnderAnUnpinnedAlgorithmIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	iss.AddKey(t, "e1", oidc.ES256)
	set := k8sSet(t, iss, c, cluster("netops"))
	_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "e1", k8sIssuer, "port49", "netops", "oxidized", c.Now(), nil))
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "its algorithm is not one") {
		t.Fatalf("%v", err)
	}
}

// Review Focus 5: a 253-byte name verifies whole.
func TestALongServiceAccountVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	a, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", name, c.Now(), nil))
	if err != nil || a.Principal != "system:serviceaccount:netops:"+name {
		t.Fatalf("%v %q", err, a.Principal)
	}
}

// On a broker whose verifiers are all k8s, a token from an unknown cluster
// is recorded k8s: oidc is a word its operator never configured (pre-flight M1).
func TestAnUnknownIssuerAtAClusterOnlySetIsK8s(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", "https://elsewhere.port49.lab", "port49", "netops", "oxidized", c.Now(), nil))
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "no configured verifier accepts its issuer") ||
		oidc.MethodOf(err) != "k8s" {
		t.Fatalf("%v %q", err, oidc.MethodOf(err))
	}
}

// A refusal never quotes an unverified token, a cluster's either.
func TestAForgedClusterTokenIsNotQuoted(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	forger := oidctest.NewIssuer(t)
	raw := forger.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "marker-sa", c.Now(), nil)
	_, err := set.Verify(context.Background(), raw)
	if !errors.Is(err, oidc.ErrInvalid) || strings.Contains(err.Error(), "marker-sa") {
		t.Fatalf("%v", err)
	}
}
```

  (Add `"fmt"` to the imports.)

- [ ] **Step 3: Run them to see them fail.**

Run: `go test ./internal/oidc/ -run 'TestAServiceAccount|TestK8s|TestAK8s|TestALongService|TestAForgedCluster' -count=1`
Expected: FAIL: `a.K8s undefined`, `oidc.MethodOf undefined`.

- [ ] **Step 4: Implement.** `internal/oidc/k8s.go`:

```go
package oidc

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/blanketfish/port49/internal/k8sid"
	"github.com/blanketfish/port49/internal/printsafe"
)

// K8sBinding is what a verified service account token binds it to (spec
// §13 decision 49 rulings 7 and 9): recorded for attribution, never
// re-verified.
type K8sBinding struct {
	Cluster, ServiceAccountUID, Pod, PodUID, Node, JTI string
}

// boundObject is {name, uid}, each read by exact name.
type boundObject struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// object reads raw as {name, uid} by exact name. ok is false for anything
// else: not an object, a repeated member (exactObject refuses it), or a
// member that is name or uid in another case, which encoding/json would
// have read for it. A member port49 does not read is left alone.
func object(raw json.RawMessage) (boundObject, bool) {
	all, err := exactObject(raw)
	if err != nil || !exactNamesOnly(all, "name", "uid") {
		return boundObject{}, false
	}
	var o boundObject
	if exact(all, &o, []string{"name", "uid"}) != nil {
		return boundObject{}, false
	}
	return o, true
}

// exactNamesOnly is false when all holds a member equal to one of names in
// another case.
func exactNamesOnly(all map[string]json.RawMessage, names ...string) bool {
	for k := range all {
		for _, n := range names {
			if k != n && strings.EqualFold(k, n) {
				return false
			}
		}
	}
	return true
}

// serviceAccount is decision 49 rulings 6 to 8 for a k8s verifier, on a
// token whose signature, iss, aud and dates have verified: the principal and
// its binding, or the refusal.
func (v *Verifier) serviceAccount(all map[string]json.RawMessage, sub string) (string, *K8sBinding, *refusal) {
	for _, name := range MachineSessionClaims {
		if _, ok := all[name]; ok {
			return "", nil, refuseK8s(ErrInvalid, "invalid", "it carries %s, a person's session or delegated grant: a "+
				"cluster's service account token carries none (decision 49 ruling 6)", name)
		}
	}
	id, err := k8sid.Parse(sub)
	if err != nil {
		return "", nil, refuseK8s(ErrUnmapped, "unmapped", "its sub is not system:serviceaccount:<namespace>:<name> "+
			"(%s)", printsafe.Line(err.Error(), 120))
	}
	if !v.ListsNamespace(id.Namespace) {
		return "", nil, refuseK8s(ErrUnmapped, "unmapped", "its namespace %s is not one %s lists in namespaces "+
			"(decision 49 ruling 8)", id.Namespace, v.Who())
	}
	raw, ok := all["kubernetes.io"]
	if !ok || !exactNamesOnly(all, "kubernetes.io") {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it carries no kubernetes.io claim: it is not a projected "+
			"service account token (decision 49 ruling 7)")
	}
	b, err := exactObject(raw)
	if err != nil || !exactNamesOnly(b, "namespace", "serviceaccount", "pod", "node", "secret") {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io claim is not an object of distinct, "+
			"exactly named members")
	}
	var ns string
	sa, saOK := object(b["serviceaccount"])
	switch {
	case json.Unmarshal(b["namespace"], &ns) != nil || ns != id.Namespace || !saOK || sa.Name != id.Name:
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io binding does not name its sub's service "+
			"account")
	case !printableID(sa.UID):
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io binding has no serviceaccount uid")
	}
	if _, ok := b["secret"]; ok {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it is bound to a Secret, not a pod: a projected token "+
			"is bound to its pod (decision 49 ruling 7)")
	}
	pod, ok := object(b["pod"])
	if !ok || !printableID(pod.Name) || !printableID(pod.UID) {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it is not bound to a pod: request it through a projected "+
			"serviceAccountToken volume, not `kubectl create token` (decision 49 ruling 7)")
	}
	out := &K8sBinding{Cluster: v.Cluster, ServiceAccountUID: sa.UID, Pod: pod.Name, PodUID: pod.UID}
	if node, ok := object(b["node"]); ok && printableID(node.Name) {
		out.Node = node.Name
	}
	var jti string
	if json.Unmarshal(all["jti"], &jti) == nil && printableID(jti) {
		out.JTI = jti
	}
	return id.String(), out, nil
}

// refuseK8s is a refusal a k8s verifier makes: its record's method is k8s.
func refuseK8s(kind error, outcome, format string, args ...any) *refusal {
	r := refuse(kind, outcome, format, args...)
	r.method = KindK8s
	return r
}

// MethodOf is a Verify error's record method: k8s when only k8s verifiers
// judged the token, else oidc (decision 49 ruling 9).
func MethodOf(err error) string {
	var r *refusal
	if errors.As(err, &r) && r.method == KindK8s {
		return KindK8s
	}
	return "oidc"
}
```

  (`payload` already refuses two top-level members that fold together; `exactNamesOnly` on the
  top level catches `Kubernetes.io` standing alone.) Then, in `verify.go`:

  - `refusal` gains `method string`, and `refuse` leaves it empty.
  - `Assertion` gains `K8s *K8sBinding`; `Credential()` becomes:

```go
func (a Assertion) Credential() store.Credential {
	if a.K8s != nil {
		return store.Credential{Method: KindK8s, Iss: a.Issuer, Sub: a.Subject}
	}
	return store.Credential{Method: "oidc", Iss: a.Issuer, Sub: a.Subject, Sid: store.SidKey(a.Issuer, a.Sid),
		AMR: slices.Clone(a.AMR), ACR: a.ACR}
}
```

  - `Set.verify`: when every verifier in `vs` has `Kind == KindK8s`, set the method of the
    refusals it builds itself (the "unavailable" and "two verifiers" ones, and the default
    `first`) to `KindK8s`. The "no configured verifier accepts its issuer" refusal is `KindK8s`
    when every verifier in `s.Verifiers` is k8s (no verifier was reached, and `oidc` is a word a
    k8s-only broker's operator never configured; pre-flight M1), else empty.
  - `Verifier.verify`, in order:
    - the `typ` allowlist becomes `typ == "" || typ == "jwt" || (v.Domain == Machines && v.Kind
      != KindK8s && typ == "at+jwt")`;
    - in the audience switch, `case Machines:` checks first
      `if v.Kind == KindK8s { if len(auds) != 1 || auds[0] != v.Audience { return refuseK8s(ErrInvalid,
      "invalid", "its aud is not exactly [%s]: a token another audience accepts could be replayed
      here (decision 49 ruling 5)", v.Audience) } }`, else the existing check;
    - the `now.Sub(iat) > t.MaxTokenAge` refusal appends, for a k8s verifier, "; the kubelet
      refreshes a projected token at about 80% of its expirationSeconds, so keep expirationSeconds at or
      under 3600";
    - the `printableID(c.Sub)` check is skipped for a k8s verifier (`k8sid.Parse` bounds it, up to
      `k8sid.MaxLen`);
    - the key refusals ("its algorithm is not one %s's …", "the keys of %s are not available",
      "no one key of %s matches its key id", "its signature does not verify under the keys of
      %s") name `v.Who()`: in `Verifier.signature` (`verify.go:286`), `iss := v.Who()`, so a k8s
      one names its cluster (decision 49 ruling 1); an OIDC verifier's `Who()` is its issuer,
      unchanged;
    - in the domain switch, `case Machines:` begins:

```go
		if v.Kind == KindK8s {
			p, b, r := v.serviceAccount(all, c.Sub)
			if r != nil {
				return Assertion{}, r
			}
			a.Principal, a.AuthTime, a.K8s, a.Sid = p, iat, b, ""
			return a, nil
		}
```

    - every refusal `Verifier.verify` makes for a k8s verifier before that point (signature,
      typ, payload, iss, dates) carries `method: KindK8s`. Rename the existing function
      `verifyClaims` and make `verify` the one `Set.verify` calls, so no single return is missed:

```go
// verify is verifyClaims with a k8s verifier's refusals marked k8s, for the
// record's method (decision 49 ruling 9).
func (v *Verifier) verify(ctx context.Context, j *JWS, t Timing, now time.Time) (Assertion, error) {
	a, err := v.verifyClaims(ctx, j, t, now)
	var r *refusal
	if errors.As(err, &r) && v.Kind == KindK8s {
		r.method = KindK8s
	}
	return a, err
}
```

- [ ] **Step 5: Run the tests.**

Run: `go test ./internal/oidc/... -count=1`
Expected: PASS, every existing OIDC test included.

- [ ] **Step 6: Commit.**

```bash
git add internal/oidc
git commit -m "feat: the k8s verifier: a pod-bound token, exact audience, a listed namespace

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 6: The broker: records, revoke and explain

**Files:**
- Modify: `internal/decision/log.go:137-186`, `internal/broker/oidc.go:37-160`, `internal/broker/revoke.go:96-182`
  and the revocation report's text (`RevokeReport.Text`, where the `workload` note is added)
- Create: `internal/broker/k8s_test.go`
- Modify: `internal/broker/revoke_test.go:1091-1106`, `internal/broker/fixture_test.go` (`withCluster`)

**Interfaces:**
- Consumes: `oidc.Assertion.K8s`, `oidc.MethodOf` (Task 5), `k8sid` (Task 2).
- Produces: `decision.K8s{Cluster, Issuer, Sub, ServiceAccountUID, Pod, PodUID, Node, JTI string}` with
  JSON `cluster, issuer, sub, serviceaccount_uid, pod, pod_uid, node, jti`; `decision.Auth.K8s *K8s` (`k8s`);
  `normalPrincipal` accepting `system:serviceaccount:`.

- [ ] **Step 1: The fixture.** In `fixture_test.go`:

```go
// withCluster adds a k8s verifier for iss's keys, cluster l69_a, issuer
// k8sTestIssuer, audience port49, namespaces netops, to f's set.
const k8sTestIssuer = "https://l69-a.port49.lab"

func (f *fixture) withCluster(t *testing.T) *oidctest.Issuer {
	t.Helper()
	return f.withClusterNamed(t, "l69_a", k8sTestIssuer)
}

// withClusterNamed adds another cluster's verifier, listing netops too.
func (f *fixture) withClusterNamed(t *testing.T, cluster, issuer string) *oidctest.Issuer {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	v := oidc.VerifierConfig{Domain: oidc.Machines, Kind: oidc.KindK8s, Cluster: cluster, Issuer: issuer,
		JWKS: iss.URL + "/jwks", Audience: "port49", Namespaces: []string{"netops"}, Algorithms: []oidc.Alg{oidc.RS256}}
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: issuer, JWKS: v.JWKS, Who: v.Who(),
		Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: f.b.Now, M: f.b.Metrics})
	if f.b.Identity == nil {
		f.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: f.b.Now, M: f.b.Metrics}
	}
	f.b.Identity.Verifiers = append(f.b.Identity.Verifiers, &oidc.Verifier{VerifierConfig: v, Keys: ks})
	return iss
}
```

- [ ] **Step 2: Write the failing tests.** `internal/broker/k8s_test.go`:

```go
package broker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

const clusterPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: backup, identity: ["system:serviceaccount:netops:oxidized"], username: svc-backup, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func TestAServiceAccountMints(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != "system:serviceaccount:netops:oxidized" || resp.Results[0].Username != "svc-backup" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth := recs[len(recs)-1]["auth"].(map[string]any)
	k := auth["k8s"].(map[string]any)
	if auth["method"] != "k8s" || auth["oidc"] != nil || k["cluster"] != "l69_a" || k["issuer"] != k8sTestIssuer ||
		k["sub"] != "system:serviceaccount:netops:oxidized" || k["pod"] != "oxidized-7d9f" || k["pod_uid"] == "" ||
		k["serviceaccount_uid"] == "" || k["node"] != "l69-a-worker" || k["jti"] == "" {
		t.Fatalf("the record's auth: %v", auth)
	}
	if strings.Contains(f.log.String(), raw) {
		t.Fatal("the token was logged")
	}
}

// Two clusters listing netops both mint as its service account (decision 49
// ruling 4, ruled 2026-10-16), and each record says which cluster minted.
func TestTwoClustersMintAsOneServiceAccount(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	east := f.withClusterNamed(t, "us_east", "https://us-east.port49.lab")
	west := f.withClusterNamed(t, "eu_west", "https://eu-west.port49.lab")
	for _, c := range []struct {
		iss            *oidctest.Issuer
		cluster, issuer string
	}{{east, "us_east", "https://us-east.port49.lab"}, {west, "eu_west", "https://eu-west.port49.lab"}} {
		raw := c.iss.ServiceAccountToken(t, "k1", c.issuer, "port49", "netops", "oxidized", f.b.Now(), nil)
		w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
		if resp := decodeMint(t, w); w.Code != 200 || resp.Principal != "system:serviceaccount:netops:oxidized" {
			t.Fatalf("%s: %s", c.cluster, shown(w))
		}
		recs := eventsOf(f.records(t), decision.EventMint)
		k := recs[len(recs)-1]["auth"].(map[string]any)["k8s"].(map[string]any)
		if k["cluster"] != c.cluster || k["issuer"] != c.issuer {
			t.Fatalf("%s: the record's auth.k8s %v", c.cluster, k)
		}
	}
}

// A refused cluster token is recorded method k8s, with nothing of the token.
func TestARefusedClusterTokenIsRecordedAsK8s(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "vault", "netops", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) ||
		!strings.Contains(w.Body.String(), "its aud is not exactly [port49]") {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	last := recs[len(recs)-1]
	if last["principal"] != nil || last["auth"].(map[string]any)["method"] != "k8s" || last["auth"].(map[string]any)["k8s"] != nil {
		t.Fatalf("the refusal's record: %v", last)
	}
}

// A k8s identity_unmapped refusal reaches the workload with its reason: it
// names only the caller's own verified namespace and the configured issuer
// (pre-flight I1; the 3am section and L69 (f) rely on it).
func TestAnUnlistedNamespaceIsUnmapped(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "backup", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) ||
		!strings.Contains(w.Body.String(), "its namespace backup is not one cluster l69_a ("+k8sTestIssuer+") lists in namespaces") {
		t.Fatalf("%s", shown(w))
	}
}

// A mark on the principal refuses the cluster path, and the answer says the
// mark outlives a re-created account (decision 49 ruling 11).
func TestRevokingAServiceAccountRefusesItsToken(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: "system:serviceaccount:netops:oxidized",
		Origin: "admin_socket uid 0"})
	if err != nil {
		t.Fatal(err)
	}
	if text := rep.Text(); !strings.Contains(text, "a token its cluster issued stays valid at port49 until its exp") ||
		!strings.Contains(text, "re-created under that name") {
		t.Fatalf("%s", text)
	}
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%s", shown(w))
	}
}

// Review Focus 5: a 339-byte principal revokes whole.
func TestALongServiceAccountRevokes(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	p := "system:serviceaccount:" + strings.Repeat("n", 63) + ":" + name
	if got, err := normalPrincipal(p); err != nil || got != p {
		t.Fatalf("%q %v", got, err)
	}
}

func TestAServiceAccountPrincipalIsVerbatimOrRefused(t *testing.T) {
	if got, err := normalPrincipal("system:serviceaccount:netops:oxidized"); err != nil || got != "system:serviceaccount:netops:oxidized" {
		t.Fatalf("%q %v", got, err)
	}
	for _, in := range []string{"System:ServiceAccount:netops:oxidized", "system:serviceaccount:NetOps:oxidized",
		"system:serviceaccount:netops", "system:serviceaccount:netops:a_b"} {
		if _, err := normalPrincipal(in); !errors.Is(err, ErrBadRevocation) {
			t.Errorf("%s: %v", in, err)
		}
	}
}
```

  In `revoke_test.go:1100`, remove `"system:serviceaccount:netops:oxidized"` from the refused
  list of `TestASpiffePrincipalIsNormalisedVerbatimOrRefused`.

- [ ] **Step 3: Run them to see them fail.**

Run: `go test ./internal/broker/ -run 'TestAServiceAccount|TestTwoClustersMint|TestARefusedClusterToken|TestAnUnlistedNamespace|TestRevokingAServiceAccount|TestALongServiceAccount' -count=1`
Expected: FAIL: `auth["k8s"]` is nil; `normalPrincipal` refuses `system:serviceaccount:`.

- [ ] **Step 4: Implement.** `internal/decision/log.go`, after `OIDC`:

```go
// K8s is a verified service account token's identity on a broker event (plan
// 10; spec §5.7 auth.k8s): which cluster and pod minted, unrecoverable
// afterwards. Cluster is the accepting verifier's configured name: several
// clusters may vouch for one namespace (decision 49 ruling 4).
type K8s struct {
	Cluster           string `json:"cluster"`
	Issuer            string `json:"issuer"`
	Sub               string `json:"sub"`
	ServiceAccountUID string `json:"serviceaccount_uid"`
	Pod               string `json:"pod"`
	PodUID            string `json:"pod_uid"`
	Node              string `json:"node,omitempty"`
	JTI               string `json:"jti,omitempty"`
}
```

  and in `Auth`, after `OIDC`: `K8s *K8s \`json:"k8s,omitempty"\``.

  `internal/broker/oidc.go`:

```go
func (c caller) auth() *decision.Auth {
	a := &decision.Auth{Method: c.cred.Method, Fingerprint: c.cred.Fingerprint}
	switch {
	case c.oidc != nil && c.oidc.K8s != nil:
		a.K8s = k8sAuth(*c.oidc)
	case c.oidc != nil:
		a.OIDC = oidcAuth(*c.oidc)
	}
	// … the directory_password branch, unchanged …
}

// k8sAuth is auth.k8s (spec §5.7; decision 49 ruling 9).
func k8sAuth(a oidc.Assertion) *decision.K8s {
	return &decision.K8s{Cluster: a.K8s.Cluster, Issuer: a.Issuer, Sub: a.Subject, ServiceAccountUID: a.K8s.ServiceAccountUID,
		Pod: a.K8s.Pod, PodUID: a.K8s.PodUID, Node: a.K8s.Node, JTI: a.K8s.JTI}
}
```

  In `bearerCaller`, `deny`'s `Auth{Method: "oidc"}` becomes `Auth{Method: method}` where `method`
  starts as `"oidc"` and is set to `oidc.MethodOf(err)` after `Verify`; on a verified token,
  `method = a.Credential().Method` and the record's auth comes from `c.auth()` (as it does for a
  revoked caller now), so a k8s deny past verification carries `auth.k8s`, not `auth.oidc`. The
  `b.Identity == nil` text becomes "no oidc or k8s verifier is configured under broker.identity".
  The `ErrUnmapped` arm answers a k8s refusal with its own text (pre-flight I1):

```go
	case errors.Is(err, oidc.ErrUnmapped):
		deny(decision.IdentityUnmapped, "", nil)
		b.sayOnce("oidc_unmapped", sayEvery, "identity: a bearer token was refused (identity_unmapped): %s",
			printsafe.Line(err.Error(), 300))
		why := "your token names no principal this broker can use; tell the operator"
		if oidc.MethodOf(err) == oidc.KindK8s {
			// A k8s refusal names only the caller's own verified sub or
			// namespace and the configured issuer (decision 49 ruling 8).
			why = err.Error()
		}
		writeError(w, http.StatusUnauthorized, string(decision.IdentityUnmapped), why)
		return caller{}, false
```

  An OIDC `ErrUnmapped` keeps the generic answer: its text can name claims of a provider's
  token the operator mapped, which is the operator's to read, not the caller's.
  The `MaxSessionAge` refusal, for `a.Domain == oidc.Machines`, says "your token was issued at %s,
  more than max_session_age (%s) ago; a workload's platform renews its token" instead of naming
  `port49 login`.

  `internal/broker/revoke.go`, in `normalPrincipal` before the `spiffe` branch:

```go
	if strings.HasPrefix(strings.ToLower(p), k8sid.Prefix) {
		// Verbatim: a cluster names accounts in lower case alone, and the
		// verifier gives one only in the form k8sid.Parse accepts (decision 49
		// ruling 8).
		id, err := k8sid.Parse(p)
		if err != nil {
			return "", fmt.Errorf("%w: %s is not a service account as its cluster names one (%v)", ErrBadRevocation,
				printsafe.Line(p, 200), err)
		}
		return id.String(), nil
	}
```

  Add `k8sid.Prefix` to `principalPrefixes` (its comment loses "system:serviceaccount: is refused
  until its verifier exists") and `system:serviceaccount:netops:oxidized` to the error's examples.
  In `RevokeReport.markText` (`revoke.go:602`), the text is chosen by the principal's prefix, as
  the spiffe line is; no new flag. The `spelled` switch gains, beside the `spiffe.Scheme` arm,
  `case strings.HasPrefix(r.Request.Principal, k8sid.Prefix): spelled = "a service account's
  principal is system:serviceaccount:<namespace>:<name>, verbatim, as its token's sub names it"`.
  And for a principal mark whose principal begins `k8sid.Prefix`, after the `revoked …` line, add:
  "\na token its cluster issued stays valid at port49 until its exp, or max_token_age after it
  was issued, whatever the cluster does; this mark refuses it now, and stands for a service
  account re-created under that name until `port49 revoke --lift`".

- [ ] **Step 5: Run the tests.**

Run: `go test ./internal/broker/ ./internal/decision/ -count=1`
Expected: PASS (the broker package takes about 9 minutes; run it whole once here).

- [ ] **Step 6: Commit.**

```bash
git add internal/decision/log.go internal/broker
git commit -m "feat: the broker mints for a service account and records auth.k8s

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 7: port49d and port49-broker: key sets and the start's lines

**Files:**
- Modify: `internal/port49d/identity.go` (`openOIDC`, `runKeySets`, `announceIdentity`; new
  `announceServiceAccountIdentities`), `internal/port49d/main.go:370-378`,
  `internal/daemon/metrics/metrics.go:334-345, 681-689`, `internal/oidc/keyset.go` (`ProxyFor`'s parameter name and comment)
- Test: `internal/port49d/identity_test.go`, `internal/port49d/identity_linux_test.go`

**Interfaces:**
- Consumes: `oidc.Config.K8s` (Task 3), `KeySetConfig.JWKS` and `KeySetConfig.Migrating` (Task 4), `Policy.ServiceAccountIdentities` (Task 2).
- Produces: `announceServiceAccountIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy)`.

- [ ] **Step 1: Write the failing tests.** In `identity_test.go` (it builds `cfg` with
  `config.Config{Broker: &config.BrokerConfig{Identity: …}}`; follow the existing tests at :40-170):

```go
func k8sConfig() config.Config {
	return config.Config{Broker: &config.BrokerConfig{Identity: &oidc.Config{Timing: oidc.DefaultTiming,
		K8s: []oidc.VerifierConfig{{Domain: oidc.Machines, Kind: oidc.KindK8s, Cluster: "l69_a", Issuer: "https://l69-a.port49.lab",
			JWKS: "https://10.0.0.10:6443/openid/v1/jwks", Audience: "port49", Namespaces: []string{"netops"},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: "/etc/port49/l69-a-ca.pem"}}}}}
}

func TestTheStartSaysEachCluster(t *testing.T) {
	var out strings.Builder
	announceIdentity(&out, "port49-broker", k8sConfig(), nil)
	for _, want := range []string{
		"port49-broker: identity: machines: k8s cluster l69_a (issuer https://l69-a.port49.lab; keys from " +
			"https://10.0.0.10:6443/openid/v1/jwks; audience port49; namespaces netops; principal " +
			"system:serviceaccount:<namespace>:<name>; algorithms RS256)",
		"port49-broker: identity: k8s namespaces: netops: l69_a\n",
		"a k8s verifier trusts its cluster's administrators: whoever can create a pod or a token for a service account in a " +
			"listed namespace mints as it",
		"a token stays valid here until its exp or max_token_age after its pod or service account is deleted; " +
			"port49 revoke --principal ends it at once",
		// The egress line is computed for the jwks host the fetch dials, and
		// names it (pre-flight I9).
		"identity: cluster l69_a (https://l69-a.port49.lab) is fetched directly (no HTTPS_PROXY) (its jwks host 10.0.0.10:6443)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "is trusted through the system's root certificates") {
		t.Fatal("a ca_file was set")
	}
}

// Every cluster vouching for a namespace is named, so an overlap is seen at
// every start (decision 49 rulings 4 and 13); a migration's two verifiers on
// one jwks are one cluster, named once.
func TestTheStartNamesEveryClusterVouchingForANamespace(t *testing.T) {
	cfg := k8sConfig()
	a := cfg.Broker.Identity.K8s[0]
	b := a
	b.Cluster, b.Issuer, b.JWKS, b.Namespaces = "eu_west", "https://eu-west.port49.lab", "https://10.1.0.10:6443/openid/v1/jwks", []string{"backup", "netops"}
	m := a
	m.Issuer = "https://l69-a-new.port49.lab" // l69_a migrating its issuer
	cfg.Broker.Identity.K8s = []oidc.VerifierConfig{a, b, m}
	var out strings.Builder
	announceIdentity(&out, "port49-broker", cfg, nil)
	if want := "port49-broker: identity: k8s namespaces: backup: eu_west; netops: eu_west, l69_a\n"; !strings.Contains(out.String(), want) {
		t.Fatalf("missing %q in\n%s", want, out.String())
	}
}

func TestServiceAccountsNoClusterCanGiveAreSaid(t *testing.T) {
	pol, err := policy.Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: a, identity: ["system:serviceaccount:netops:oxidized"], username: a}
  - {name: b, identity: ["system:serviceaccount:kube-system:default"], username: b}
grants:
  - {subject: a, scope: all_devices, roles: [r], max_privilege: admin}
  - {subject: b, scope: all_devices, roles: [r], max_privilege: admin}
`), policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	announceServiceAccountIdentities(&out, "port49d", k8sConfig(), pol)
	want := "port49d: policy: 1 service account identities mint for no one: system:serviceaccount:kube-system:default " +
		"(subject b): no k8s verifier lists namespace kube-system\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
	out.Reset()
	cfg := k8sConfig()
	cfg.Broker.Identity.K8s = nil
	cfg.Broker.Identity.X509AnchorFile = "/a.pem"
	announceServiceAccountIdentities(&out, "port49d", cfg, pol)
	if !strings.Contains(out.String(), "2 service account identities mint for no one") ||
		!strings.Contains(out.String(), "no broker.identity.machines k8s verifier is configured") {
		t.Fatalf("%q", out.String())
	}
}

```

  In `identity_linux_test.go`, beside the existing `openOIDC` tests (they set up the state
  directory `ownStateDir` checks; mirror `TestOpenOIDCSharesOneKeySetPerIssuer`'s setup):

```go
// openOIDC builds a key set for a k8s verifier, reading its jwks.
func TestOpenOIDCBuildsAClusterKeySet(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := k8sConfig()
	cfg.Broker.Identity.K8s[0].JWKS, cfg.Broker.Identity.K8s[0].CAFile = iss.URL+"/jwks", caFile
	cfg.Broker.StateDir = t.TempDir()
	set, err := openOIDC(cfg, cfg.Broker.StateDir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil || set == nil || len(set.Verifiers) != 1 || set.Verifiers[0].Kind != oidc.KindK8s {
		t.Fatalf("%v %+v", err, set)
	}
	if err := set.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}
```

  (`os.Chmod(cfg.Broker.StateDir, 0o700)` if `ownStateDir` asks for it; mirror the existing
  `openOIDC` test's setup.) The first block's imports are `identity_test.go`'s; the second needs
  `oidctest`, `os`, `filepath` and `context` in `identity_linux_test.go` if it lacks them.

- [ ] **Step 2: Run them to see them fail.**

Run: `go test ./internal/port49d/ -run 'TestTheStartSaysEachCluster|TestTheStartNamesEveryCluster|TestServiceAccountsNoCluster|TestOpenOIDCBuildsACluster' -count=1`
Expected: FAIL: `announceServiceAccountIdentities undefined`; `openOIDC` returns nil for a k8s-only config.

- [ ] **Step 3: Implement.** In `openOIDC`: `vs := append(slices.Clone(id.OIDC), id.K8s...)`;
  return nil when `len(vs) == 0`; loop over `vs`; pass `JWKS: v.JWKS` and `Who: v.Who()` in the
  `KeySetConfig`, and for a k8s verifier `Migrating`: the issuers of the other k8s verifiers in `id.K8s` with the same
  `JWKS` (decision 49 ruling 4's migration; Task 4 stays quiet when discovery names one); its
  `ca_file` error names `broker.identity machines k8s verifier %d` for a k8s one. In
  `announceIdentity`, after the oidc machine lines:

```go
	for _, v := range id.K8s {
		machines = append(machines, fmt.Sprintf("k8s cluster %s (issuer %s; keys from %s; audience %s; namespaces %s; "+
			"principal system:serviceaccount:<namespace>:<name>; algorithms %s)", v.Cluster, v.Issuer, v.JWKS,
			v.Audience, strings.Join(v.Namespaces, ", "), algs(v.Algorithms)))
	}
```

  and, after the machines line is printed:

```go
	if len(id.K8s) > 0 {
		fmt.Fprintf(w, "%s: identity: a k8s verifier trusts its cluster's administrators: whoever can create a pod or a "+
			"token for a service account in a listed namespace mints as it; a token stays valid here until its exp or "+
			"max_token_age after its pod or service account is deleted; port49 revoke --principal ends it at once\n", proc)
		fmt.Fprintf(w, "%s: identity: k8s namespaces: %s\n", proc, vouching(id.K8s))
	}
```

```go
// vouching is, for each namespace a k8s verifier lists, every cluster that
// vouches for it: "backup: eu_west; netops: eu_west, us_east". Several
// clusters may list one namespace (decision 49 ruling 4); the start says
// which, so an overlap nobody meant is seen (ruling 13). A cluster under two
// issuers is named once.
func vouching(ks []oidc.VerifierConfig) string {
	by := map[string][]string{}
	for _, v := range ks {
		for _, ns := range v.Namespaces {
			if !slices.Contains(by[ns], v.Cluster) {
				by[ns] = append(by[ns], v.Cluster)
			}
		}
	}
	var parts []string
	for _, ns := range slices.Sorted(maps.Keys(by)) {
		slices.Sort(by[ns])
		parts = append(parts, ns+": "+strings.Join(by[ns], ", "))
	}
	return strings.Join(parts, "; ")
}
```

  The once-per-issuer "is fetched …" and "… system's root certificates" loops iterate
  `append(slices.Clone(id.OIDC), id.K8s...)`, and both name `v.Who()` (a k8s verifier by its
  cluster, the issuer beside it; an OIDC one by its issuer, as today). For a k8s verifier the fetch dials `v.JWKS`, not the
  issuer (often a name only the cluster resolves), so its egress line is computed with
  `oidc.ProxyFor(v.JWKS)` and names that host (pre-flight I9):

```go
		target, host := v.Issuer, ""
		if v.Kind == oidc.KindK8s {
			target = v.JWKS
			if u, err := url.Parse(v.JWKS); err == nil {
				host = " (its jwks host " + u.Host + ")"
			}
		}
		how := "directly (no HTTPS_PROXY)"
		if u, err := oidc.ProxyFor(target); err == nil {
		// … unchanged …
		fmt.Fprintf(w, "%s: identity: %s is fetched %s%s\n", proc, v.Who(), how, host)
```

  (`ProxyFor`'s parameter is a URL; rename it `target` in `keyset.go`, its comment saying a k8s
  verifier's is the JWKS URL.) `announceServiceAccountIdentities` mirrors
  `announceWorkloadIdentities`:

```go
// announceServiceAccountIdentities says the policy's system:serviceaccount:
// identities no verifier can give (decision 49 ruling 13): with no k8s
// verifier, all of them; with some, those whose namespace none lists.
func announceServiceAccountIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	ids := pol.ServiceAccountIdentities()
	if len(ids) == 0 || cfg.Broker == nil {
		return
	}
	var ks []oidc.VerifierConfig
	if cfg.Broker.Identity != nil {
		ks = cfg.Broker.Identity.K8s
	}
	var lines []string
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		parsed, err := k8sid.Parse(id)
		switch {
		case err != nil:
			continue // the policy's load refused it already
		case len(ks) == 0:
			lines = append(lines, fmt.Sprintf("%s (subject %s): no broker.identity.machines k8s verifier is configured",
				id, ids[id]))
		case !slices.ContainsFunc(ks, func(v oidc.VerifierConfig) bool { return v.ListsNamespace(parsed.Namespace) }):
			lines = append(lines, fmt.Sprintf("%s (subject %s): no k8s verifier lists namespace %s", id, ids[id],
				parsed.Namespace))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintf(w, "%s: policy: %d service account identities mint for no one: %s\n", proc, len(lines),
			strings.Join(lines, "; "))
	}
}
```

  Call it in `main.go` right after `announceWorkloadIdentities` (:370). In `metrics.go`, the three
  `port49_oidc_*` help strings say "OIDC or cluster issuer" and the comments add "(plan 10: a k8s
  verifier's issuer too)".

- [ ] **Step 4: Run the tests.**

Run: `go test ./internal/port49d/ ./internal/daemon/metrics/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/port49d internal/daemon/metrics/metrics.go internal/oidc/keyset.go
git commit -m "feat: port49d builds each cluster's key set and says what it trusts

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 8: `port49 workload --token-file`

**Files:**
- Modify: `internal/workload/client.go` (`Config`, `New`, `do`; new `TokenFileError`, `readToken`)
- Create: `internal/workload/client_token_test.go`
- Modify: `cmd/port49/workload.go:44-127, 168-176` and the `identity` command's error handling; `cmd/port49/workload_test.go`

**Interfaces:**
- Consumes: the broker's bearer path (Task 6).
- Produces: `workload.Config.TokenFile string`; `type TokenFileError struct{ File string; Err error }`
  (final; `cmd` exits 2 at New, the run stops final mid-run); `MaxTokenFile = 16 << 10`.

- [ ] **Step 1: Write the failing tests.** First, in `client_test.go`, give `fakeBroker` an
  `auths []string` field and record `r.Header.Get("Authorization")` in `ServeHTTP` beside
  `presents` (for `/v1/tokens` requests: append in the `"/v1/tokens"` case, after `f.keys`).
  Then `internal/workload/client_token_test.go`:

```go
package workload

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/testpki"
)

// tokenHarness is a TLS broker that asks for no client certificate, as an
// OIDC-only or k8s-only broker does, and a Config presenting a token file.
func tokenHarness(t *testing.T, f *fakeBroker, token string) (Config, string) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("broker", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Broker: srv.URL, BrokerCA: ca.Pool(), TokenFile: p, Deadline: time.Minute}, p
}

func TestATokenFileIsPresentedAsABearer(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cfg, _ := tokenHarness(t, f, "eyJ.a.b\n")
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	if len(f.auths) != 1 || f.auths[0] != "Bearer eyJ.a.b" {
		t.Fatalf("%q: the file's trailing newline is trimmed, nothing else", f.auths)
	}
	if len(f.presents) != 0 {
		t.Fatal("a certificate was presented beside the token")
	}
}

// Review Focus 2: a retry presents the token the kubelet wrote since.
func TestTheTokenFileIsReadAtEveryAttempt(t *testing.T) {
	var p string
	rotate := func(w http.ResponseWriter, req api.MintRequest) {
		if err := os.WriteFile(p, []byte("second.a.b"), 0o600); err != nil {
			t.Error(err)
		}
		refuse(http.StatusServiceUnavailable, "identity_provider_unavailable", "1")(w, req)
	}
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){rotate, permitAll}}
	cfg, file := tokenHarness(t, f, "first.a.b")
	p = file
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	if len(f.auths) != 2 || f.auths[0] != "Bearer first.a.b" || f.auths[1] != "Bearer second.a.b" {
		t.Fatalf("%q", f.auths)
	}
}

func TestATokenFileIsRefusedBesideACertificate(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cfg, _ := tokenHarness(t, f, "a.b.c")
	cfg.CertFile, cfg.KeyFile = "/c.pem", "/k.pem"
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "a certificate or a token file, not both") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnusableTokenFileIsRefusedAtTheStart(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	for name, body := range map[string]string{"empty": "", "spaced": "a.b c", "too long": strings.Repeat("a", MaxTokenFile+1)} {
		cfg, _ := tokenHarness(t, f, body)
		_, err := New(cfg)
		var te *TokenFileError
		if !errors.As(err, &te) || strings.Contains(err.Error(), "a.b c") {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg, p := tokenHarness(t, f, "a.b.c")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	var te *TokenFileError
	if _, err := New(cfg); !errors.As(err, &te) {
		t.Fatalf("missing: %v", err)
	}
}
```

  In `cmd/port49/workload_test.go`, add a test that `port49 workload token --broker … --broker-ca …
  --token-file <missing> leaf1` exits 2 and its stderr names the file and never its content, and
  that `--token-file` with `--cert`, and `--token-file` with `--touch-key pkcs11:nothing-here`,
  each exit 2 with "a certificate or a token file, not both" (the second proves the refusal comes
  before any key is opened: an unopenable reference would otherwise say `--touch-key: …`).

- [ ] **Step 2: Run them to see them fail.**

Run: `go test ./internal/workload/ ./cmd/port49/ -run 'TokenFile|TestATokenFile|TestTheTokenFile|TestAnUnusableTokenFile' -count=1`
Expected: FAIL: `unknown field TokenFile`.

- [ ] **Step 3: Implement.** In `internal/workload/client.go`:

```go
// MaxTokenFile is the most a token file may hold: a JWS port49 accepts is
// at most 16 KiB (decision 39 ruling 3).
const MaxTokenFile = 16 << 10

// TokenFileError is a token file the client cannot present: unreadable,
// empty, over MaxTokenFile, or holding whitespace inside the token. It never
// carries the file's content.
type TokenFileError struct {
	File string
	Err  error
}

func (e *TokenFileError) Error() string {
	return fmt.Sprintf("the token file %s: %v (a projected service account token, as the pod's volume writes it)",
		e.File, e.Err)
}

func (e *TokenFileError) Unwrap() error { return e.Err }

// readToken reads the file once, as it is now: the kubelet replaces it whole
// (decision 49 ruling 14). One trailing newline is trimmed.
func readToken(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		// The bare errno, so the message does not repeat the path; a fixed
		// text when err is not an *os.PathError (pre-flight M5).
		why := errors.Unwrap(err)
		if why == nil {
			why = errors.New("it could not be opened")
		}
		return "", &TokenFileError{File: file, Err: why}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxTokenFile+1))
	switch {
	case err != nil:
		return "", &TokenFileError{File: file, Err: errors.New("it could not be read")}
	case len(b) > MaxTokenFile:
		return "", &TokenFileError{File: file, Err: fmt.Errorf("it is over %d bytes", MaxTokenFile)}
	}
	tok := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	switch {
	case tok == "":
		return "", &TokenFileError{File: file, Err: errors.New("it is empty")}
	case strings.IndexFunc(tok, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0:
		return "", &TokenFileError{File: file, Err: errors.New("it holds whitespace or a character no token has")}
	}
	return tok, nil
}
```

  (`errors.Unwrap` of an `*os.PathError` is the bare errno, so the message does not repeat the
  path. Import `os`.) `Config` gains:

```go
	// TokenFile, in place of CertFile and KeyFile, is a projected service
	// account token presented as a bearer, read at every request (plan 10;
	// decision 49 ruling 14).
	TokenFile string
```

  In `New`, before `LoadCertificate`:

```go
	if cfg.TokenFile != "" {
		if cfg.CertFile != "" || cfg.KeyFile != "" || cfg.TouchKey != nil {
			return nil, errors.New("a workload presents a certificate or a token file, not both (and a touch key is " +
				"bound to a certificate's key)")
		}
		if _, err := readToken(cfg.TokenFile); err != nil {
			return nil, err
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.BrokerCA,
			VerifyConnection: verifyOf(cfg)}}
		hc := &http.Client{Transport: tr, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return &Client{cfg: cfg, http: hc, sleep: sleepCtx}, nil
	}
```

  lifting the existing `verify` closure into `func verifyOf(cfg Config) func(tls.ConnectionState) error`
  so both paths share it. In `do`, after setting `Idempotency-Key`:

```go
		if c.cfg.TokenFile != "" {
			tok, err := readToken(c.cfg.TokenFile)
			if err != nil {
				return err // final: the file went away under the run
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
```

  `proveTouch` is unreachable in token mode (no `TouchKey`); leave it.

  In `cmd/port49/workload.go`: `workloadFlags` gains `tokenFile string`, registered as
  `fs.StringVar(&w.tokenFile, "token-file", "", "a projected service account token (the pod's "+
  "serviceAccountToken volume), read at every request, in place of --cert and --key")`.
  `errWorkloadUsage` becomes `"--broker and --broker-ca are required, with --cert and --key or
  --token-file"`. `client()` checks `w.broker == "" || w.brokerCA == "" || (w.tokenFile == "") ==
  (w.cert == "" && w.key == "")`: usage when neither or both, with the "not both" text when both;
  and `w.tokenFile != "" && w.touchKey != ""` is refused there too, with the same "not both" text,
  before `clientkey.Open(w.touchKey, …)` (`workload.go:113`) runs, so no key is opened for a run
  that is refused (pre-flight M3); `New`'s own check stays as the library's guard. It passes
  `TokenFile: w.tokenFile`. At both `client()` call sites a `*workload.TokenFileError`
  exits 2 (it already falls to `return 2`; add a test that pins it). In `stopOf`, a
  `*workload.TokenFileError` is `failAgent, "the token file could not be read during the run; see
  stderr"`. The usage text names `--token-file`.

- [ ] **Step 4: Run the tests.**

Run: `go test ./internal/workload/ ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/workload cmd/port49/workload.go cmd/port49/workload_test.go
git commit -m "feat: port49 workload presents a projected service account token with --token-file

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 9: `examples/kubernetes`

**Files:**
- Create: `examples/kubernetes/README.md`, `examples/kubernetes/issuer-discovery.yaml`,
  `examples/kubernetes/backup-cronjob.yaml`, `examples/kubernetes/port49d-identity.yaml`,
  `examples/kubernetes/policy.yaml`
- Create: `examples/kubernetes/examples_test.go` (package `kubernetes_test`; parses the YAML files)

**Interfaces:**
- Consumes: Tasks 3, 8.
- Produces: the manifests L69 (Task 10) applies, so the example is what is measured.

- [ ] **Step 1: Write the failing test.** `examples/kubernetes/examples_test.go`:

```go
package kubernetes_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The CronJob's token volume asks for the audience the identity snippet names,
// a lifetime the broker keeps accepting through the kubelet's refresh (decision
// 49 ruling 6), and runs port49 workload with --token-file on that path.
func TestTheCronJobMatchesTheIdentitySnippet(t *testing.T) {
	var cj struct {
		Spec struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Spec struct {
							AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
							ServiceAccountName           string `yaml:"serviceAccountName"`
							Containers                   []struct {
								Command      []string `yaml:"command"`
								VolumeMounts []struct {
									Name      string `yaml:"name"`
									MountPath string `yaml:"mountPath"`
								} `yaml:"volumeMounts"`
							} `yaml:"containers"`
							Volumes []struct {
								Name      string `yaml:"name"`
								Projected struct {
									Sources []struct {
										ServiceAccountToken struct {
											Audience          string `yaml:"audience"`
											ExpirationSeconds int    `yaml:"expirationSeconds"`
											Path              string `yaml:"path"`
										} `yaml:"serviceAccountToken"`
									} `yaml:"sources"`
								} `yaml:"projected"`
							} `yaml:"volumes"`
						} `yaml:"spec"`
					} `yaml:"template"`
				} `yaml:"spec"`
			} `yaml:"jobTemplate"`
		} `yaml:"spec"`
	}
	readSecond(t, "backup-cronjob.yaml", &cj)
	pod := cj.Spec.JobTemplate.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("the default API token is mounted: the example never mounts it (L69 (h))")
	}
	sat := pod.Volumes[0].Projected.Sources[0].ServiceAccountToken
	if sat.Audience != "port49" || sat.ExpirationSeconds != 3600 || sat.Path != "token" {
		t.Fatalf("%+v", sat)
	}
	cmd := strings.Join(pod.Containers[0].Command, " ")
	if !strings.Contains(cmd, "workload token") || !strings.Contains(cmd, "--token-file /var/run/secrets/port49/token") {
		t.Fatalf("%s", cmd)
	}
	var id struct {
		Broker struct {
			Identity struct {
				Machines []struct {
					Type, Cluster, Audience string
					Namespaces              []string
				} `yaml:"machines"`
			} `yaml:"identity"`
		} `yaml:"broker"`
	}
	read(t, "port49d-identity.yaml", &id)
	// Every region's verifier names its cluster, asks the CronJob's audience
	// and lists netops: one manifest, every cluster (decision 49 ruling 4).
	for _, m := range id.Broker.Identity.Machines {
		if m.Type != "k8s" || m.Cluster == "" || m.Audience != sat.Audience || !slices.Contains(m.Namespaces, "netops") {
			t.Fatalf("%+v", m)
		}
	}
}

func read(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// readSecond decodes the file's second YAML document into v.
func readSecond(t *testing.T, file string, v any) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	var first map[string]any
	if err := d.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}
```

  (`gopkg.in/yaml.v3` v3.0.1 is already a direct requirement in `go.mod`. The CronJob file holds
  the ServiceAccount first and the CronJob second, so `read` decodes the second document: use a
  `yaml.NewDecoder` and decode twice, the first into a `map[string]any`.)

- [ ] **Step 2: Run it to see it fail.**

Run: `go test ./examples/kubernetes/ -count=1`
Expected: FAIL: `open backup-cronjob.yaml: no such file or directory`.

- [ ] **Step 3: Write the files.** `issuer-discovery.yaml`:

```yaml
# Lets port49-broker read this cluster's service account keys without a
# credential (spec §13 decision 49 ruling 2): issuer discovery and the JWKS
# are public keys. Provisional on L69 (c) until Task 11 closes it (then
# "measured on kind, L69 (c)"); managed clusters are L70, open.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: port49-service-account-issuer-discovery
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:service-account-issuer-discovery
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: system:unauthenticated
```

  `backup-cronjob.yaml`:

```yaml
# A nightly backup's tokens, minted with the pod's projected token alone
# (design §7). The default API token is not mounted: its audience is the API
# server's and port49 refuses it (measured on kind, L69 (h)). This example stops
# at the mint: /work/tokens.tsv is on an emptyDir, so the job that reads the
# tokens (your backup tool) runs in this pod, after this container, sharing
# the work volume; it is not shown here.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: oxidized
  namespace: netops
automountServiceAccountToken: false
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: port49-backup-tokens
  namespace: netops
spec:
  schedule: "15 2 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: oxidized
          automountServiceAccountToken: false
          restartPolicy: Never
          containers:
            - name: tokens
              image: port49:local
              command: ["/usr/local/bin/port49", "workload", "token",
                        "--broker", "https://port49-broker.netops.svc:8443",
                        "--broker-ca", "/etc/port49/broker-ca.pem",
                        "--token-file", "/var/run/secrets/port49/token",
                        "--devices-file", "/etc/port49/devices",
                        "--purpose", "nightly backup", "--out", "/work/tokens.tsv"]
              volumeMounts:
                - {name: port49-token, mountPath: /var/run/secrets/port49, readOnly: true}
                - {name: port49-config, mountPath: /etc/port49, readOnly: true}
                - {name: work, mountPath: /work}
          volumes:
            - name: port49-token
              projected:
                sources:
                  - serviceAccountToken:
                      audience: port49
                      expirationSeconds: 3600
                      path: token
            - name: port49-config
              configMap: {name: port49-backup}
            - name: work
              emptyDir: {}
```

  `port49d-identity.yaml` (a fragment for `port49-broker.yaml`):

```yaml
# One k8s verifier per cluster (decision 49). cluster is port49's name for it,
# in records and log lines (nothing in the cluster changes); issuer is the
# cluster's --service-account-issuer, set per cluster; jwks is where the
# broker reads its keys (the API server's own address); namespaces are the
# ones whose service accounts it may name. The same workload deployed to both
# regions is one identity, so both list netops (decision 49 ruling 4): list
# different namespaces where a namespace means different tenants per cluster.
broker:
  identity:
    machines:
      - type: k8s
        cluster: us_east
        issuer: https://us-east.k8s.example.com
        jwks: https://10.20.0.10:6443/openid/v1/jwks
        ca_file: /etc/port49/us-east-cluster-ca.pem
        audience: port49
        namespaces: [netops]
      - type: k8s
        cluster: eu_west
        issuer: https://eu-west.k8s.example.com
        jwks: https://10.40.0.10:6443/openid/v1/jwks
        ca_file: /etc/port49/eu-west-cluster-ca.pem
        audience: port49
        namespaces: [netops]
```

  `policy.yaml`:

```yaml
subjects:
  - name: svc_backup
    identity:
      - "system:serviceaccount:netops:oxidized"
    username: svc-backup
    token_ttl: 900s
```

  `README.md`, sections, each short, every cluster claim cited to L69 or L70 and written
  "provisional on L69 (<cell>)" until Task 11 closes the row (Task 11 Step 5 rewrites them):
  1. **What it is**: the projected token as the workload's identity; no CA, no secret at rest.
  2. **The cluster**:
     - Set `--service-account-issuer` per cluster (kubeadm's default is the same everywhere, and
       port49 refuses one issuer twice). This is the main onboarding cost for a self-managed
       fleet, so give the safe sequence (pre-flight M13): add the new issuer as the *first*
       `--service-account-issuer` flag with the old one kept as a second (the API server signs
       with the first and accepts both); list both issuers in port49 as two `k8s` verifiers on
       the same `jwks` (decision 49 ruling 4's migration case); roll the pods; after the longest
       `expirationSeconds` in use has passed, remove the old flag and the old verifier.
     - Apply `issuer-discovery.yaml` (measured on kind, L69 (c); managed clusters unmeasured, L70).
       Issuer discovery needs `--anonymous-auth` on; a CIS-hardened cluster turns it off. On 1.32+
       use the structured authentication configuration (`AuthenticationConfiguration`'s
       `anonymous.conditions`) to allow anonymous requests to `/.well-known/openid-configuration`
       and `/openid/v1/jwks` alone (pre-flight M12).
     - `jwks` is the API server's own address, not the issuer's host (discovery's `jwks_uri`
       names the issuer's host, which nothing outside the cluster may resolve, the reason ruling
       2 reads `jwks` directly): `$(kubectl config view --minify -o
       jsonpath='{.clusters[0].cluster.server}')/openid/v1/jwks` (pre-flight I7). It may be any
       https mirror of the keys (a bucket, a reverse proxy) for a cluster whose API server the
       broker must not reach.
     - The cluster CA for `ca_file`: `kubectl config view --raw --minify -o
       jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d`.
  3. **The broker**: the `port49d-identity.yaml` fragment and what each key means; one verifier
     per cluster, each with its own `cluster` name (port49's word, in records and log lines; the
     cluster's manifests do not change). Several clusters may list one namespace (decision 49
     ruling 4): the same CronJob deployed to every region is one identity,
     `system:serviceaccount:netops:oxidized`, and one policy subject; no per-cluster namespace
     or overlay. Each record's `auth.k8s.cluster` says which region minted, and the start's
     `identity: k8s namespaces: netops: eu_west, us_east` line says which clusters vouch for
     each namespace: check it after adding a cluster. Where a namespace means different tenants
     in different clusters, list different namespaces per verifier. Why the overlap is allowed:
     a compromised cluster already holds a genuine token for its own copy of the workload, so
     refusing the overlap would buy nothing.
  4. **The workload**: the CronJob; `automountServiceAccountToken: false`; `expirationSeconds:
     3600` and why (the kubelet refreshes at about 80% of it, measured on kind, L69 (b), against
     `max_token_age`); the example stops at the mint (the consumer runs in the same pod, sharing
     the work volume, not shown); the image is the repository's `Dockerfile` target `port49`
     (`docker build --target port49 -t port49:local .`).
  5. **The policy**: the subject; `username:` required; `port49 policy test`.
  6. **3am**: every case of this plan's "The operator at 3am", as the operator sees them.
  7. **Stopping a workload**: `port49 revoke --principal system:serviceaccount:netops:oxidized`,
     and why deleting the service account alone is not immediate (R11; measured on kind, L69 (e)).
  8. **What is not measured**: managed clusters (L70); a CronJob run in a cluster against a
     broker outside it is plan 12's deployment test.

- [ ] **Step 4: Run the test.**

Run: `go test ./examples/kubernetes/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add examples/kubernetes
git commit -m "docs: examples/kubernetes, the projected-token CronJob and the broker's k8s verifier

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 10: The L69 harness on kind

**Files:**
- Create: `tests/lab/k8s/kind-a.yaml`, `tests/lab/k8s/kind-b.yaml`, `tests/lab/k8s/workload.yaml`,
  `tests/lab/l69_test.go`, `tests/lab/l69_unit_test.go`
- Modify: `Makefile` (target `lab-k8s`), `tests/lab/README.md` (section "Kubernetes (L69)")

**Interfaces:**
- Consumes: `bin/port49d`, `bin/port49` (`make build`), `startLocalBroker`'s pattern
  (`tests/lab/localbroker_test.go`), `labGuardAt`, `labcreds.Contains`, `labcreds.RedactNote`,
  `examples/kubernetes/issuer-discovery.yaml` (Task 9).
- Produces: `TestL69` (the run), `l69Claim` (the row's claim, held equal to spec §15 by a unit
  test), the evidence file `tests/lab/evidence/L69-kind.json` and the note
  `tests/lab/results/L69-kind.md`.

The harness drives the `kind` and `kubectl` binaries (no Kubernetes Go module). It runs a local
port49d with a broker (as L48's `startLocalBroker` does: memory store, one inventory device
`leaf1` at 127.0.0.1, no device behind it; a mint touches no device), its identity two k8s
verifiers or one as each cell needs. Every token it reads (`kubectl exec … cat`, `kubectl create
token`) stays in memory and goes to a 0600 file under `t.TempDir()` for `port49 workload
--token-file`; it is appended to the run's secret list, and the note and the evidence are checked
with `labcreds.Contains` before they are written. The evidence keeps a token's decoded claims and
header (neither is a credential without the signature), its `sha256`, and never the compact
token.

- [ ] **Step 1: The kind configurations.** `tests/lab/k8s/kind-a.yaml`:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: l69-a
networking: {apiServerAddress: 127.0.0.1, apiServerPort: 16443}
nodes:
  - role: control-plane
    image: kindest/node:v1.33.1
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            service-account-issuer: https://l69-a.port49.lab
```

  kind v0.29.0 generates kubeadm `v1beta3` for every Kubernetes 1.23+ (its
  `pkg/cluster/internal/kubeadm/config.go` has no `v1beta4` template, checked 2026-10-16), so
  `extraArgs` is a map, as above; the patch sets no `apiVersion`, so it matches by kind alone.
  `up(t)` checks the flag took (`docker exec <name>-control-plane grep -q -- '--service-account-issuer=<issuer>'
  /etc/kubernetes/manifests/kube-apiserver.yaml`) and fails as a harness fault before any cell
  if not (pre-flight M11).

  `kind-b.yaml` is the same with `name: l69-b`, port `16444`, issuer `https://l69-b.port49.lab`,
  and `service-account-jwks-uri: https://l69-b.invalid/openid/v1/jwks` (cell c records a discovery
  `jwks_uri` that differs from the configured `jwks`; port49 does not compare it). `workload.yaml` holds namespaces `netops` and `backup`,
  service account `netops:oxidized`, and pod `netops/oxidized` (`busybox:1.36.1`, `sleep
  infinity`, `automountServiceAccountToken: false`) with the projected volume of
  `examples/kubernetes/backup-cronjob.yaml` but `audience: port49-lab` and
  `expirationSeconds: 600` (the API server's minimum, so cell b's rotation is measured within
  10 minutes), and a second pod `netops/defaulted` with the default `kube-api-access` volume
  (cell h).

- [ ] **Step 2: Write the failing unit tests.** `tests/lab/l69_unit_test.go` (`//go:build lab`),
  pure helpers only:

```go
//go:build lab

package lab

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// The claim in the harness is spec §15's L69 row, word for word.
func TestL69ClaimIsTheRegisters(t *testing.T) {
	spec, err := os.ReadFile("../../docs/design/2026-08-23-policy-engine-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(spec), "| **L69** | "+l69Claim+" |") {
		t.Fatal("l69Claim differs from spec §15's L69 row")
	}
}

// tokenFacts decodes a token's header and claims and keeps its sha256, never
// the token or its signature.
func TestTokenFactsKeepsNoToken(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"abc"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://l69-a.port49.lab","aud":["port49-lab"],"iat":100,"exp":700}`))
	raw := h + "." + p + ".c2lnbmF0dXJl"
	f, err := tokenFacts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Header["kid"] != "abc" || f.Claims["iss"] != "https://l69-a.port49.lab" || f.Lifetime != 600 ||
		len(f.SHA256) != 64 {
		t.Fatalf("%+v", f)
	}
	if b, _ := json.Marshal(f); strings.Contains(string(b), "c2lnbmF0dXJl") || strings.Contains(string(b), raw) {
		t.Fatal("the facts carry the signature or the token")
	}
}

// rotationFraction is when the file changed, as a fraction of the lifetime
// of the token it replaced.
func TestRotationFraction(t *testing.T) {
	iat := time.Unix(1000, 0)
	if got := rotationFraction(iat, 600*time.Second, iat.Add(480*time.Second)); got != 0.8 {
		t.Fatalf("%v", got)
	}
}

func TestKindAndNodeArePinned(t *testing.T) {
	for _, f := range []string{"k8s/kind-a.yaml", "k8s/kind-b.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), "image: "+l69NodeImage) {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if l69KindVersion != "v0.29.0" {
		t.Fatal(l69KindVersion)
	}
}
```

  (import `encoding/json`.)

- [ ] **Step 3: Run them to see them fail.**

Run: `go test -tags lab ./tests/lab/ -run '^(TestL69ClaimIsTheRegisters|TestTokenFactsKeepsNoToken|TestRotationFraction|TestKindAndNodeArePinned)$' -count=1`
Expected: FAIL: `l69Claim undefined`.

- [ ] **Step 4: Write the harness.** `tests/lab/l69_test.go` (`//go:build lab`). Its parts:

  - Constants: `l69Claim` (the row's claim text, exactly), `l69KindVersion = "v0.29.0"`,
    `l69NodeImage = "kindest/node:v1.33.1"`, `l69Audience = "port49-lab"`, the issuers, the
    API ports 16443 and 16444, `l69DiskFloorMB = 20480`.
  - `type tokenFactsT struct { Header, Claims map[string]any; Lifetime int64; SHA256 string }` and
    `func tokenFacts(raw string) (tokenFactsT, error)` (split on `.`, decode the first two parts,
    `Lifetime = exp − iat`, `SHA256` of the raw token); `func rotationFraction(iat time.Time,
    life time.Duration, changedAt time.Time) float64`, `changedAt.Sub(iat) / life` rounded to two
    places: measured against the old token's `iat`, never against when polling began (pre-flight
    I4, M10).
  - `type kindCluster struct{ name, kubeconfig string; apiPort int }` with `up(t)` (`kind create
    cluster --config … --kubeconfig <tmp>`; refuses to start when `kind version` is not
    `l69KindVersion`; records `docker image inspect --format '{{index .RepoDigests 0}}'` of the
    node image into the evidence), `down()` (`kind delete cluster --name …`, registered with
    `t.Cleanup` before `up` returns), `kubectl(args ...string) (string, error)` (stdout only;
    never logged by the harness when the args read a token), `caPEM()` (from the kubeconfig's
    `certificate-authority-data`), `jwksURL()` (`https://127.0.0.1:<port>/openid/v1/jwks`),
    `podToken(ns, pod string) (string, error)` (`kubectl exec -n ns pod -- cat
    /var/run/secrets/port49/token`), `tokenHash(ns, pod)` (`kubectl exec … sha256sum …`: the
    rotation poll reads the hash alone).
  - `startK8sBroker(t, dir string, verifiers []k8sVerifier) *localBroker`: L48's
    `localBrokerFiles` pattern with `broker.identity.machines` set to the verifiers given
    (cluster `l69_a` or `l69_b`, issuer, jwks, ca_file, audience `port49-lab`, namespaces) and `certificate_status`
    `disabled: true` (no x509 verifier), and a policy whose subject `svc_backup` lists
    `system:serviceaccount:netops:oxidized` with `username: svc-backup` and `token_ttl: 60s`.
    It adds `admin_socket: <dir>/admin.sock` to the config (`localBrokerFiles` sets none), and
    `(*localBroker).revoke(args ...string)` runs `revokeCLI(<dir>/admin.sock, args...)`
    (`tests/lab/revoke_test.go:93`, `port49 revoke --socket …`) for cell (e) (pre-flight M8).
    `(*localBroker).workloadTokenFile(tokenFile string) (exit int, stdout, stderr string)` runs
    `bin/port49 workload token --broker … --broker-ca … --token-file … leaf1`; the harness keeps
    exit and stderr, and drops stdout after checking it is non-empty on exit 0.
  - `TestL69`, guarded by `PORT49_LAB_K8S=1`, `labGuardAt(l66StopSentinel, "/", l69DiskFloorMB)`
    before each cell (`l69DiskFloorMB = 20480`: two kind node images, their containers and the
    clusters' etcd want several GB; the sentinel is `/tmp/port49-STOP-LAB`), cells in order, each
    an `l69Cell{Name, Observed map[string]any, Pass bool, Why string}` in the evidence:
    - **(a) claims.** Up cluster A, apply `workload.yaml`, wait for `netops/oxidized` Ready; read
      its token; record `tokenFacts`. Pass when `iss` is A's issuer, `aud` is exactly
      `[port49-lab]`, `exp − iat` is 600, `sub` is `system:serviceaccount:netops:oxidized`,
      `kubernetes.io` has `namespace`, `serviceaccount{name,uid}`, `pod{name,uid}`, and the
      header has `alg` `RS256` and a `kid`. Record (not judged) `node`, `jti`, `nbf`, `typ`,
      `warnafter`.
    - **(c) discovery.** Anonymous `GET https://127.0.0.1:16443/.well-known/openid-configuration`
      and `/openid/v1/jwks` with A's CA and no credential: record both statuses. Apply
      `examples/kubernetes/issuer-discovery.yaml`; again: record both statuses and discovery's
      `issuer` and `jwks_uri`. Pass when the second pair is 200 and discovery's `issuer` is A's.
      Start a broker with A's verifier (`jwks` A's API server, `https://127.0.0.1:16443/…`, while
      discovery's `jwks_uri` names A's issuer host): pass when its stderr has no "names issuer"
      and no "jwks_uri" line, the correct config silent (pre-flight I7). Up cluster B (one at a
      time is simpler): record B's discovery `jwks_uri` (expect
      `https://l69-b.invalid/openid/v1/jwks`); start a broker with B's verifier (`jwks` B's API
      server); pass when a B token mints exit 0 and its stderr says nothing of B's `jwks_uri`
      (the configured `jwks` is used, never discovery's).
    - **port49 mints** (the precondition of b, d, e, f, g): a broker with A's verifier; A's pod
      token mints exit 0.
    - **(b) rotation.** Read A's pod token afresh at the start of (b) (the one (a) read may have
      rotated during (c)) and keep its facts; poll its hash every 10s for up to 660s; at the first
      change, record `rotationFraction(iat, 600s, changedAt)` with the old token's `iat` and the
      poll time the change was seen, read the new token, and mint with it (exit 0). Pass when the
      file changed, the new token minted, and the fraction is in [0.75, 0.97] (the kubelet checks
      a token's age on its volume sync, every 60–90s, so it lands at about 0.80–0.95, almost never
      exactly 0.80); record the fraction (the docs' "about 80%" is provisional until this records
      it).
    - **(d) key rotation.** On A's control plane (`docker exec l69-a-control-plane`): generate
      `/etc/kubernetes/pki/sa2.key` and `sa2.pub` (`openssl genrsa 2048`; `openssl rsa -pubout`);
      edit `/etc/kubernetes/manifests/kube-apiserver.yaml` so `--service-account-key-file` is given
      twice (`sa.pub`, then `sa2.pub`) and `--service-account-signing-key-file` is `sa2.key`; wait
      for the API server to answer `/readyz`. Delete and re-create `netops/oxidized`; read its new
      token; record its `kid` and whether it differs from (a)'s. Mint with it on the broker started
      before the rotation, without a restart: pass when exit 0 within 70s (one refetch, at most
      one a minute). Record the JWKS key count before and after (expect 1, then 2).
    - **(e) deletion.** Read the pod's token (T1); delete `netops/oxidized` (the pod); submit a
      TokenReview for T1 (`kubectl create -f -` with a `TokenReview` whose `spec.token` is T1 and
      `audiences: [port49-lab]`, its output parsed for `status.authenticated` and
      `status.error`; the request body and the output never logged), record it; mint with T1:
      record the exit. Re-create the pod, read T2, delete the service account `netops/oxidized`;
      TokenReview T2; mint with T2. Then `port49 revoke --socket <dir>/admin.sock --principal
      system:serviceaccount:netops:oxidized` (`(*localBroker).revoke`) and mint with T2 again.
      Pass when TokenReview answered `authenticated: false` for each, port49 minted with each
      (exit 0, the window R11 states), and after the revoke refused it (exit 77, stderr
      `credential_revoked`). Record the revoke's answer text.
    - **(f) another cluster.** Re-create the service account and pod on A. Broker with A's
      verifier alone: B's pod token (B has `workload.yaml` too) exits 77, stderr
      `trust_domain_unresolved` and "no configured verifier accepts its issuer". Broker with A
      (`namespaces: [netops]`) and B (`namespaces: [backup]`): B's `netops` token exits 77,
      stderr `identity_unmapped` "its namespace netops is not one cluster l69_b
      (https://l69-b.port49.lab) lists in namespaces". Broker with A and B both listing
      `netops` (decision 49 ruling 4): its start's stderr has `identity: k8s namespaces:
      netops: l69_a, l69_b`; A's and B's `netops` tokens each mint exit 0, and the broker's
      records name `auth.k8s.cluster` `l69_a` and `l69_b` respectively. Pass when all three.
    - **(g) shapes refused.** On A: `kubectl create token oxidized -n netops --audience other
      --bound-object-kind Pod --bound-object-name oxidized` (wrong audience); `kubectl create
      token oxidized -n netops --audience port49-lab` (unbound); a Secret `netops/l69-bound`
      (an Opaque Secret, created for the purpose) and `kubectl create token oxidized -n netops
      --audience port49-lab --bound-object-kind Secret --bound-object-name l69-bound`
      (Secret-bound: the shape ruling 7's `secret` check assumes, pre-flight I6); `kubectl create
      token oxidized -n netops --audience port49-lab --bound-object-kind Node
      --bound-object-name l69-a-control-plane` (Node-bound, 1.33); and a Secret of type
      `kubernetes.io/service-account-token` for `oxidized`, its `.data.token` read (a legacy
      token). Each minted with: pass when all five exit 77 with `trust_domain_unresolved`, the
      details "its aud is not exactly", "it is not bound to a pod" (unbound), "it is bound to a
      Secret" (Secret-bound; record its `kubernetes.io.secret` member as the cluster wrote it),
      "it is not bound to a pod" (Node-bound; record its `kubernetes.io.node` member), and
      (legacy) "no configured verifier accepts its issuer" (its `iss` is
      `kubernetes/serviceaccount`). Record each token's facts.
    - **(h) the default token.** `netops/defaulted`'s
      `/var/run/secrets/kubernetes.io/serviceaccount/token`: record `aud`, `exp − iat` and
      `warnafter`; mint with it: pass when exit 77 "its aud is not exactly".
  - At the end: write `tests/lab/evidence/L69-kind.json` (cells, kind version, node image
    digest, the k8s server version `kubectl version -o json`'s `serverVersion.gitVersion`) and
    `tests/lab/results/L69-kind.md` through `labcreds.RedactNote`, each checked with
    `labcreds.Contains` against every token read; a run with a leak, a skipped cell or a harness
    fault is INVALID and writes neither. The note's form is `workloadNote`'s
    (`tests/lab/stepca_test.go:117`): platform `kind`, image version, observation per cell, the
    evidence path.

  `Makefile`:

```make
# L69 (plan 10): a Kubernetes cluster's service account tokens, on two kind
# clusters and a local port49d, no devices. Needs Docker, kind v0.29.0 on PATH
# (go install sigs.k8s.io/kind@v0.29.0), kubectl and `make build`; see
# tests/lab/README.md, "Kubernetes (L69)".
lab-k8s:
	PORT49_LAB_K8S=1 go test -tags lab ./tests/lab/ -run '^TestL69$$' -count=1 -v -timeout 60m
```

  `tests/lab/README.md`, "Kubernetes (L69)": what it needs, what each cell does, that it reads
  tokens into memory only, that the clusters are deleted at the end (and `kind delete cluster
  --name l69-a` / `l69-b` by hand after a killed run), and that it never touches a device.

- [ ] **Step 5: Run the unit tests and vet.**

Run: `make lab-unit && go vet -tags lab ./tests/lab/`
Expected: PASS, the four new tests among them.

- [ ] **Step 6: Commit.**

```bash
git add tests/lab/k8s tests/lab/l69_test.go tests/lab/l69_unit_test.go Makefile tests/lab/README.md
git commit -m "test: the L69 harness, service account tokens on two kind clusters

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 11: The L69 run

**Files:**
- Create: `tests/lab/results/L69-kind.md`, `tests/lab/evidence/L69-kind.json`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L69's Status; decision 49's
  "provisional on L69" words where a cell measured them), `examples/kubernetes/` (the README and
  the manifests' comments: "provisional on L69" becomes "measured on kind", and anything a cell
  contradicts) and this plan's operator notes likewise

**Interfaces:**
- Consumes: Task 10's harness at this branch's head.

- [ ] **Step 1: Prepare.** A detached run worktree at the head commit; `make build` in it;
  kind is not installed on the lab host: `go install sigs.k8s.io/kind@v0.29.0`, check
  `$(go env GOPATH)/bin` is on `PATH` (`command -v kind`), then `kind version` prints `v0.29.0`
  (kubectl, docker and openssl are present); `docker pull kindest/node:v1.33.1`; no other lab run active
  (single occupant); a background stall watchdog armed (re-armed on every wake); the STOP
  sentinel absent.
- [ ] **Step 2: Run.** `make lab-k8s` in the run worktree. Expected: PASS, every cell.
- [ ] **Step 3: Judge.** A failed cell is real or harness. A harness fault: fix the harness in its
  own commit (`test:`), reviewed, and run again; nothing is committed from the faulted run. A real
  result that contradicts R2, R6, R7 or R11's text: the doc is wrong. Fix decision 49, the README
  and the operator notes to the note, and say so in the commit. If (b) records a fraction outside
  [0.75, 0.97], "about 80%" is wrong: the refusal's hint text (Task 5) and the README change to
  the measured range in the same commit. A fraction inside it keeps "about 80%".
- [ ] **Step 4: Copy the results to the branch** (they are in the run worktree), then remove the
  run worktree.
- [ ] **Step 5: Close the row.** Spec §15 L69's Status becomes `closed — measured <date>;
  tests/lab/results/L69-kind.md`, followed by one sentence per cell of what was measured, as L48's
  row does. L70 stays open. Every "provisional on L69 (x)" written before this run becomes
  "measured on kind, L69 (x)": decision 49's rulings, R-text quoted in the spec, the
  `examples/kubernetes/issuer-discovery.yaml` and `backup-cronjob.yaml` comments,
  `examples/kubernetes/README.md`, and this plan's operator notes (pre-flight I2). Check: `grep -rn "provisional on L69"
  docs/design examples/kubernetes` prints nothing.

```bash
git add tests/lab/results/L69-kind.md tests/lab/evidence/L69-kind.json docs/design/2026-08-23-policy-engine-spec.md examples/kubernetes
git commit -m "docs: close lab register entry L69 on kind

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 12: The roadmap's record and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (a "Plan 10 — As built" section under "Plan 10")
- Modify: `docs/design/2026-08-21-port49-design.md` §7 (one "As built (plan 10)" paragraph after
  option 1, as option 2 has for plan 8)

**Interfaces:** none.

- [ ] **Step 1: Design §7.** After option 1's paragraph: "As built (plan 10; policy engine spec §13
  decision 49): `k8s` under `broker.identity.machines`, one per cluster, with `issuer`, `cluster`,
  `jwks`, `audience` and `namespaces`; keys read from `jwks` directly, discovery read only to say
  where it differs; the token bound to a pod and its `aud` exactly the audience; the principal
  `system:serviceaccount:<namespace>:<name>` from `sub`; several clusters may vouch for one
  namespace, the start naming them and each record its `auth.k8s.cluster`.
  `port49 workload token --token-file` presents the projected token. A deleted service account's
  token stays valid at port49 until its `exp` or `max_token_age` (measured on kind, L69);
  `port49 revoke --principal` ends it at once."
- [ ] **Step 2: The roadmap.** "Plan 10 — As built", in plan 8's form: the branch and base, each
  task's commits and what differs from this plan's text, the rulings as made, Q1 and Q2 as ruled
  2026-10-16, L69's result and L70 open, the interfaces added (`internal/k8sid`, `oidc.KindK8s`,
  `VerifierConfig.Kind/Cluster/JWKS/Namespaces`, `VerifierConfig.Who`, `Config.K8s`,
  `KeySetConfig.JWKS/Migrating/Who`, `K8sBinding`,
  `Assertion.K8s`, `MethodOf`, `decision.K8s`, `workload.Config.TokenFile`, `TokenFileError`,
  `Policy.ServiceAccountIdentities`), "Carried forward" (below), and the operator notes (below,
  as shipped). The roadmap's top status line gains "**10 executed <date>** …".
- [ ] **Step 3: Check and commit.**

Run: `make test && make vet`
Expected: PASS; report the real output.

```bash
git add docs/superpowers/plans/README.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: roadmap records plan 10 as built

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

**Carried forward (for the As built section):**
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

---

## Operator notes (for the pull request body)

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
    `examples/kubernetes/issuer-discovery.yaml` (measured on kind, L69 (c);
    managed clusters are L70, unmeasured). Issuer discovery needs anonymous access to two paths;
    a CIS-hardened cluster with `--anonymous-auth=false` allows them through the 1.32+ structured
    authentication configuration.
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
- **What is refused, and how it reads:** another audience, an unbound, Secret- or Node-bound token, a
  token older than `max_token_age` (2h), a namespace the cluster does not list, a cluster not
  configured. Each is 401 with the reason and a detail naming the check.
- **A cluster's API server unreachable:** keys held are used for `jwks_max_age` (24h) after the
  last good fetch, said hourly and on `port49_oidc_keys_fetch_failures_total{issuer}`; then 503
  `identity_provider_unavailable`, retried by `port49 workload`.
- **Key rotation at the cluster** needs nothing from port49: a new key is fetched on first sight
  (measured on kind, L69 (d)).
- **To stop a workload at once:** `port49 revoke --principal system:serviceaccount:<ns>:<name>`.
  Deleting its service account or pod is not immediate at port49: a token already issued stays
  valid until its `exp` or 2h after issue (measured on kind, L69 (e)). The mark also stands for a service
  account re-created under that name until `port49 revoke --lift`, and, since the principal names
  no cluster, for that service account in every cluster that lists its namespace.
- **Records:** a cluster caller's records carry `auth: {method: k8s, k8s: {cluster, issuer, sub,
  serviceaccount_uid, pod, pod_uid, node, jti}}`: which cluster and pod minted. Log lines and
  refusals name a cluster as `cluster us_east (<issuer>)`.
- **Metrics:** the `port49_oidc_*` series cover clusters, labelled by the configured issuer (not
  by `cluster`).
- **Per-login MFA** applying to machines cannot be proved by a k8s workload: such a device is
  reported `per_login_mfa_required`, not minted.
- **Lab:** L69 (kind v0.29.0, Kubernetes v1.33.1); L70 (managed clusters) open.
