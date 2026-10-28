# Deployment Artifacts, Release and Publishing Implementation Plan (plan 12b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship port49's three peer deployment shapes, each with its artifact, an end-to-end CI smoke test and a README:
- systemd units, delivered in `.deb`/`.rpm` packages;
- the container image and compose stack (plan 7f's), with secrets moved to files;
- a Helm chart, with an External Secrets Operator example.

Also:
- a release pipeline that runs on tags only and publishes the packages, the image, the chart, PyPI `port49` and Galaxy `port49.client`;
- `make test`/`make vet` in GitHub-hosted CI;
- the four items 12a carried: the in-place rotation warning, CI test time, flake hit 8, and the ACL test's package.

**Architecture:**
- Most of this plan is files outside Go: units, Dockerfile, compose, Helm templates, workflows and GoReleaser.
- Each artifact is pinned two ways. A Go test under a build tag (`systemd`, `helm`, `kind`, `image`, `compose`) parses it or runs it. A `make` target runs that test, and a workflow runs the target.
- The smoke tests share one helper package, `tests/shapes/shapetest`, factored out of `tests/compose`. It holds the TACACS+ device, the token mint, readiness and the key-rotation cell.
- There are three Go changes from 12a's carries, and one from Ryan's ruling of 2026-10-27 (Tasks 3a–3g): admin-level operations move from the admin sockets to the broker API, each needing a security key press bound to its request, and the sockets are removed.
- The 12a carries are:
  - `liveKeys.rewritten` and the reloader's re-read of held `file:` keys (spec §12);
  - a witness-follower test hook;
  - two CI helpers, `tests/ci/cmd/testshard` and `tests/ci/cmd/mustpass`, plus `tests/ci/cmd/versioncheck`.
- Third-party behaviour that the artifacts rest on, and that nobody has measured, gets its own lab row (L82–L85). A README names a mechanism only after its row closes.

**Tech Stack:**
- Go 1.26: the standard library, `gopkg.in/yaml.v3` and `github.com/prometheus/client_golang`, all already in go.mod. No new module.
- systemd 257 (Debian 13 "trixie") in the smoke container.
- Docker with Compose v2.24.4+.
- Helm 3, kind v0.29.0 and kubectl.
- GoReleaser v2 (nfpm inside).
- GitHub Actions: `pypa/gh-action-pypi-publish`, `actions/attest-build-provenance`, `docker/build-push-action`.

Every tool and action is pinned to an exact version: the Makefile pins tools by sha256, as it does gitleaks, and the workflows pin actions by commit SHA.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §10, "Version sets, and no cutover" (a version's secret never changes);
  - §12, which Task 1 extends with "A key secret rewritten in place";
  - §13 decision 53 (its rulings 1, 2, 8 and 12, and the 12a hand-offs), and decision 54, which Task 1 writes from the rulings below;
  - §15, rows L39, L60, L62, L69 and L82–L86;
  - §2's rights table, §5.1.4, §5.1.5 (`hardware_key_touch`, decision 45 rulings 12 and 14), §5.7 and §12, which Task 3a amends for admin calls (ruling 5).
- `docs/design/2026-08-21-port49-design.md` §13:
  - the source address;
  - "The policy file is a privilege";
  - two independently upgraded server groups;
  - replica separation;
  - connection handling;
  - the anycast note;
  - the etcd floor and backups.
- The roadmap, `docs/superpowers/plans/README.md`:
  - "Plan 12 — Deployment": the 12b entry, the four requirements every shape states, and "Deployment shapes";
  - "Plan 12a — As built": Operator notes, Carried forward and Hand-offs.
- The inventory, `.superpowers/sdd/plan12-inputs.md`: themes A and E, and the rulings of 2026-10-26 at its end.

## Rulings this plan is written under

Ryan's rulings, from memory and the roadmap:
- **Not prescriptive.** systemd, container and Kubernetes are peers. Kubernetes is native, never required.
- **The CI hold is lifted** (2026-10-24). Release jobs run on tags only. PyPI uses trusted publishing. Galaxy uses an API-token repository secret.
- **`secret_ref` is `env:` and `file:` only.** A secret store reaches port49 as a file its agent renders.
- **An ESO `ExternalSecret` example**, with one remote key and one file per key version, never rewritten in place, and a kind lab row (2026-10-26).
- **The issuing CA's key stays on each broker's state volume.** It is copied once to every broker.
- **No deprecation before beta.**

The team lead's rulings:
- 12b ships each artifact's README; plan 13 writes the docs-site pages.
- MetalLB anycast is offered only once a lab row measures `externalTrafficPolicy: Local`.

This plan's rulings. Task 1 writes them into the spec as decision 54.

1. **Each shape is one artifact, one smoke and one README.**
   - **systemd:** `deploy/systemd/`, in the `port49-server` package. Smoke: `make systemd-smoke`, real systemd as PID 1 in a container.
   - **Container:** `Dockerfile` and `deploy/compose/`. Smokes: `make compose-smoke` and `make image-check`.
   - **Kubernetes:** `deploy/helm/port49/`. Smoke: `make kind-smoke`.
   - A shape whose smoke does not pass in CI is not shipped.
2. **Where each shape keeps its secrets** (12a hand-off):
   - **systemd:**
     - `key_secret_refs.file_dir: /etc/port49/keys`. `/run` is cleared at reboot, and `RuntimeDirectory=` at every stop.
     - The directory is `root:port49d 0750` and each key file `root:port49d 0440`.
     - The encryption key is `/etc/port49/secrets/encryption.key`, `port49d:port49d 0400`, and for the broker `/etc/port49/secrets/broker-encryption.key`, owned by port49-broker. Both sit outside `file_dir` (decision 53, re-review N1).
   - **Compose** (decides A29):
     - The env files are removed.
     - `setup.sh` writes the device keys into a `port49d-keys` volume, mounted read-only at `/run/port49/keys`, the directory `root:65532 0750` and the files `root:65532 0440`.
     - It writes each encryption key into the component's configuration volume, at `/etc/port49/secrets/encryption.key`, `65532 0400`.
     - Nothing secret is left in `docker inspect`.
   - **Kubernetes** (the key volume is provisional on L82):
     - A Secret volume mounted whole at `/run/port49/keys` (never by `subPath`), `defaultMode: 0440`, mounted in port49d's pod alone. The broker loads no device key.
     - port49d's pod sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch`.
     - The broker's pod sets no `fsGroup` (plan 7e Rulings 12 and 18).
     - The encryption key comes from a second Secret, mounted at `/etc/port49/secrets`.
     - **Each etcd client identity is its own Secret** (plan 7e ruling 1, pre-flight C1): `etcd.port49d.existingSecret` is mounted only in port49d, `etcd.broker.existingSecret` only in the broker, and `etcd.caSecret` (the CA certificate alone) in both. No pod holds the other's etcd key.
   - **Credential mechanisms:** `LoadCredential=`, Compose `secrets:`, the Vault Agent injector and the Secrets Store CSI driver are named in a README only after L83 or L84 closes with them passing. Rotation is a reload, never a restart (Ryan, 2026-10-26). A mechanism that fails the cell "a version added reaches the running process with no restart" may be named for the encryption key only, never for device keys.
3. **No read-only hardening of a path the fence reads.** The fence excuses a directory's mode on a read-only mount (12a operator notes). `ProtectSystem=strict` or `full`, or `ReadOnlyPaths=/etc`, would mount `/etc` read-only inside the unit, so a group-writable `/etc/port49` on the host would pass. The units set `ProtectSystem=true` (only `/usr`, `/boot` and `/efi` are read-only). They never set `ReadOnlyPaths=`, `BindReadOnlyPaths=`, `ProtectHome=read-only`, an `:ro` `TemporaryFileSystem=` or `InaccessiblePaths=` over a path port49 reads. They do set the hardening that leaves `/etc` writable: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` for port49d (empty for the broker). The unit test asserts each. The systemd smoke makes an *ancestor*, `/etc`, group-writable under the shipped unit and asserts the start is refused. A read-only mount excuses an ancestor's mode, never the holding directory's (`fence_linux.go:105–112`), so only an ancestor can show the excuse. The Helm chart's ConfigMap and Secret volumes are read-only, but the kubelet writes them, which is the trusted writer `tests/lab/results/configmap-mounts.md` measured.
4. **Two users on a systemd host:** `port49d` and `port49-broker`, each in its own group. This applies plan 7e ruling 1 (no process holds both etcd identities) to one host. The packages create them with `sysusers.d`.
5. **Admin operations go over the broker API, each with a security key press** (Ryan, 2026-10-27; this replaces the socket ruling the plan first carried, and Task 3a writes it into the spec as decision 54 ruling 15).
   - **The factor** is §5.1.5's `hardware_key_touch` (decision 45 ruling 12): an always-touch slot's signature over the connection's TLS exporter, with attestations chaining to the configured roots, from the token that holds the session key. Each admin-level call needs its right and a fresh proof bound to that one request: the challenge carries the operation and the target, and the signature covers `SHA-256` of the exact method, path and body (Task 3a's §5.1.6). There is no reuse window, so it is one touch per operation. An exposed admin certificate, bearer token or agent session alone authorizes nothing admin-level.
   - **What is admin-level:** a call that writes, lifts or removes state belonging to another principal or to the server's trust. Reads (`explain_others`, the revocation list) and the caller's own (`mine`) are not, and neither is an install-time init that refuses when anything is there. So `revoke_others` needs the touch, and `explain_others` does not. A host-local command run as the service's user or root, against the process's own files or store credentials (the offline revoke with the brokers stopped, the issuer and init commands, `store-roles`, `export-enrollments`, `keys-diagnose`), is admin by host access: not an API call and no touch. Where it writes a record, the origin is `offline uid <n>` (team lead, amendment pre-flight A-I4).
   - **The inventory** (every operation the two sockets answered, and the rest of the admin surface):

     | Operation today | Verdict |
     |---|---|
     | `port49 revoke --principal` (socket) and `--via-agent --principal` | API `POST /v1/tokens/revoke`, `revoke_others`, touch |
     | `port49 revoke --cert` / `--cert-issuer --cert-serial` (socket) | API, same endpoint, new body, `revoke_others`, touch |
     | `--via-agent --device --username`; `{sid, issuer}` | API as today, `revoke_others`, now with a touch |
     | `port49 revoke --lift` (socket) | API `POST /v1/revocations/lift`, new right `lift_revocations`, touch |
     | `port49 revoke --list` (socket) | API `GET /v1/revocations`, `revoke_others` or `lift_revocations`, no touch (read) |
     | `port49 directory forget` (socket) | API `POST /v1/directory/forget`, new right `forget_principals`, touch |
     | `port49 directory reset-second-factor <p>` and `--all` (socket) | API `POST /v1/directory/reset-second-factor`, new right `reset_second_factor`, touch |
     | `port49 directory unlock` (socket) | API `POST /v1/directory/unlock`, new right `unlock_sign_in`, touch |
     | `port49 directory import [--replace]` (socket) | API `POST /v1/directory/import`, new right `import_enrollments`, touch |
     | `port49 directory init-enrollments` (socket) | local subcommand `port49-broker init-enrollments` / `port49d init-enrollments`, install-time like `init-revocations` |
     | `port49 directory export` (socket) | local subcommand `port49-broker export-enrollments` / `port49d export-enrollments`: reads sealed bytes with the process's own store identity, so backups need no admin credential |
     | `port49 store status` (both sockets) | `GET /store/status` on each process's metrics listener, read-only counts, no right; `port49 store status --metrics ADDR` |
     | `port49 keys diagnose` (port49d's socket) | local subcommand `port49d keys-diagnose --device D --capture FILE`, offline from a pcap; port49d stops holding an unvalidated packet in memory |
     | `port49 revoke --mine`; `explain_others` | unchanged, no touch |
     | `/v1/logout` (back-channel logout) | unchanged: the provider's signed act, not an admin call; no right, no touch |
     | `forget-issuer`, `init-issuer`, `rotate-issuer`, `init-revocations`, `store-roles` | unchanged local subcommands: they run with the brokers stopped or before any admin exists, and were never socket operations |
     | `port49-broker revoke --offline [--lift]` | the break-glass, unchanged, plus `--list`; and a new `port49d revoke --offline` for a port49d with its broker in process |

   - **The admin socket is removed outright** (pre-beta, no deprecation). `admin_socket` in either config file is refused by name. No operation keeps a socket (Ryan's addendum, 2026-10-27: only a compelling reason the API and a touch cannot serve would keep one). Each row above was checked for one, and none has it. The two that cannot reach a running broker have homes that need no socket: the break-glass revoke runs offline with the brokers stopped, and `keys diagnose` runs offline from a capture. `store status` is a read with no authority, so it goes on the metrics port.
   - **Per shape,** an operator runs `port49 revoke …` and `port49 directory …` on their own workstation, through their agent. No shape needs `sudo`, `docker exec` or `kubectl exec` for an admin call. The break-glass, with every broker stopped, as root or the broker's user:
     - **systemd:** `systemctl stop port49-broker` on every broker host, then `port49-broker revoke --offline …`, then start.
     - **Compose:** `docker compose stop port49-broker`, then `docker compose run --rm --no-deps port49-broker revoke --offline …`, then start.
     - **Kubernetes:** `deploy/helm/port49/scripts/revoke-offline.sh <namespace> <release> -- <revoke flags>`. It scales the broker StatefulSet to 0, runs the command in a one-shot pod on broker-0's PVC and config (as `copy-issuer.sh` runs `init-issuer`), then scales back.
   - **The 3am view** is Task 3a's table: an unattested key, a touch timeout, the identity provider down (the admin's certificate still revokes), and the roots missing. Each shape README carries it.
6. **Packages.**
   - **The two packages:**
     - `port49-server` ships the static build: `port49d`, `port49-broker`, `port49-inventory` and `port49`, with the units, `sysusers.d` and `tmpfiles.d`.
     - `port49` ships the client build (`-tags hwkey_dlopen`), as `/usr/bin/port49`.
     - The two conflict on `/usr/bin/port49`: decision 45 ruling 22 keeps the static and client builds apart.
   - **Modes:** every binary is installed 0755, owned by root, with no setuid or setgid bit and no file capability. port49d binds 49 through the unit's `AmbientCapabilities=CAP_NET_BIND_SERVICE`, never a file capability.
   - **The client's config file:** the client package ships `/etc/port49/config.yaml` as a conffile, root 0644. It is a commented template that sets nothing. It lists, commented, the A13 keys `broker`, `broker_ca`, `broker_crl`, `touch_key`, `key` and `issued_key_store`. A site's broker URL and CA are config management's job, and no package can know them.
   - **The Python library and the collection** (roadmap, plan 9d carry): the client package installs both beside the client build.
     - The collection goes at `/usr/share/ansible/collections/ansible_collections/port49/client/`, which is on ansible-core's default collections path, in both formats.
     - The `.deb` installs the library (pure Python, `dependencies = []`) at `/usr/lib/python3/dist-packages/port49/`, Debian's version-independent path.
     - **The `.rpm` does not install the library yet.** RPM distributions have no version-independent `site-packages`: the path is `/usr/lib/python3.<minor>/site-packages`, and one nfpm package cannot name the target's minor version. Installing it on a path Python does not search would ship a library that does not import. So the `.rpm` leaves the library to `pip install port49`, and the client README says so (team lead, 2026-10-27; Ryan may override, see "Open for Ryan").
     - `TestClientPackageContents` asserts each path. A Debian-container test imports `port49` with the system `python3`, and `ansible-doc port49.client.token` finds the collection.
   - **Not done by the client package:**
     - adding a user to `tss`, since a package cannot know which user (the README says `usermod -aG tss <user>`);
     - installing a polkit rule for pcscd, which stays a host install (A11).
   - **macOS:** the client build for darwin/arm64 and darwin/amd64 ships as a tarball, unsigned. L63, signing, stays open.
7. **Release.**
   - **The pipeline:** GoReleaser runs on `v*` tags only, and makes:
     - the archives and packages;
     - `SHA256SUMS`;
     - build provenance through `actions/attest-build-provenance`.
   - **The image:** `ghcr.io/rhwendt/port49:<version>`, for linux/amd64 and linux/arm64, cross-compiled in the build stage (`--platform=$BUILDPLATFORM`).
   - **The chart:** `oci://ghcr.io/rhwendt/charts/port49`, at the release version.
   - **Build apart from publish** (pre-flight I1):
     - `build-python` and `build-galaxy` build with tools pinned by hash (`packaging/requirements-release.txt`, installed `--require-hashes`) and hand the result on through `actions/upload-artifact`. They hold no token.
     - `pypi` and `galaxy` only download and publish.
     - Every checkout in `release.yml` sets `persist-credentials: false`, except `goreleaser`'s.
     - GoReleaser runs from the sha256-pinned `bin/goreleaser-$(GORELEASER_VERSION)`, never an action fetching `latest`.
   - **PyPI:** trusted publishing from the `pypi` environment, with `skip-existing: true` so a re-run after a later job fails is not refused. Three jobs hold `id-token: write`: `pypi`, to publish, and `goreleaser` and `image`, for provenance attestations. No other job in any workflow holds it, and no workflow sets it, or `write-all`, at workflow level.
   - **Galaxy:** `ansible-galaxy collection publish` with `secrets.GALAXY_API_KEY`, in the `galaxy` environment. On a re-run, "already exists" for this version is success.
   - **No workflow uses `pull_request_target`.**
   - **One version:** the tag `vX.Y.Z` equals `clients/python/pyproject.toml`'s `version`, `galaxy.yml`'s `version`, and `Chart.yaml`'s `version` and `appVersion`. `versioncheck` checks this on every pull request (all agree) and at the tag (all equal the tag).
8. **CI.**
   - **`make test` stays the whole suite**, with its timeout raised to 30m.
   - **CI splits it into a partition of its own:**
     - `test-rest` runs every package but `internal/port49d`;
     - `test-shard` runs `internal/port49d` in three shards, cut by `testshard` from `go test -list`;
     - `test-root` runs, as root, the tests that skip when run as a user.
   - **A shard that runs nothing fails** (pre-flight I3). `testshard` exits non-zero when `go test -list` fails or lists nothing, and on an empty shard. `testshard -check` asserts the shards' union equals the list.
   - **No `t.Parallel`:** the tests swap package variables (12a carry).
   - **The `acl` package** is installed, and `mustpass` requires `TestAnACLGrantingWriteIsRefused` to pass, never skip.
9. **Kubernetes shape.**
   - **Workloads:** port49d and port49-broker are each a StatefulSet with a PersistentVolumeClaim (PVC) per replica: one for the spool, one for `state_dir`.
     - Each data directory is a 0700 subdirectory an initContainer makes.
     - The update strategy is `RollingUpdate`, never `Recreate` or `OnDelete`.
     - A PodDisruptionBudget of `maxUnavailable: 1`.
     - Preferred pod anti-affinity, and a zone topology spread with `whenUnsatisfiable: ScheduleAnyway`, so a cluster with no zone labels still schedules.
     - `terminationGracePeriodSeconds: 60`.
     - Neither StatefulSet sets `persistentVolumeClaimRetentionPolicy`. Kubernetes' default retains the PVCs, so a scale-down (the HPA's included) leaves a spool PVC with unsent accounting until a scale-up takes it back. The README says so.
   - **Probes** (A16): readiness `/readyz` and liveness `/healthz`, as plain HTTP `httpGet` on each process's metrics port. No probe needs a client certificate, and none touches TACACS+ or the broker API.
     - Liveness sets `periodSeconds: 10` and `failureThreshold: 6` (60 s), with the template comment `# /healthz is unbound for seconds between runs after a store loss (internal/port49d/main.go:727-731)`. Kubernetes' default 10 s × 3 would let the kubelet kill port49d mid etcd outage (pre-flight re-review R1).
   - **Issuer discovery** (plan 10 carry): `issuerDiscovery.enabled` renders the `system:service-account-issuer-discovery` ClusterRoleBinding of `examples/kubernetes/issuer-discovery.yaml`, in each cluster whose workloads mint, off by default.
   - **Pod Security:** the initContainers and `copy-issuer.sh`'s pods run as root, so the namespace needs the `baseline` level, not `restricted`. The README says so.
   - **Binding 49 as non-root:** the pod sysctl `net.ipv4.ip_unprivileged_port_start=0`, a safe sysctl.
   - **Services:** TACACS+ 49, and the TLS listener's port (default 300) when `tlsListener.enabled`, each with `externalTrafficPolicy: Local`. Whether that keeps the source is L39 (b), still open and 12c's. The README says so.
   - **Autoscaling:** an optional HPA on `port49_connections`, off by default. It needs a custom-metrics adapter, so it is rendered and tested, never exercised. Design §13 says to scale on connections, never CPU.
   - **Two server groups** are two releases (design §13).
   - **etcd is not in the chart.** `deploy/helm/port49/examples/etcd/` is a reference StatefulSet with an `etcd-init` Job, and the smoke uses it.
   - **The broker's site:** `broker.site` sets `PORT49_SITE`, and `broker.directory.keytabSecret` mounts a keytab (A23).
10. **Issuing CA copies.**
    - **Kubernetes:** `deploy/helm/port49/scripts/copy-issuer.sh`.
      - It runs `init-issuer` once, in a one-shot pod from the port49 image that mounts broker-0's PVC and config. It never uses `kubectl exec` into broker-0, which may be the one crash-looping.
      - It copies `state/issuing-ca.pem` and `state/issuing-ca.key` (the PVC's `state/` subdirectory is `broker.state_dir`) to every other broker's PVC. If `state/` is missing there, it creates it `65532:65532 0700`.
      - Each side is a root debug pod on that PVC's node: `kubectl cp` cannot work against a distroless broker, or one crash-looping "behind a promotion".
      - The key travels inside one kubectl exec stream (`set -o pipefail`) and is written 0600, owned by 65532.
    - **systemd and compose:** the READMEs give the `install -m 0600` copy.
11. **The in-place rewrite warns and never refuses** (12a carry).
    - At every SIGHUP, after every swap and every `keyRetryInterval` (30 s), port49d reads each held `file:` key reference again.
    - Changed bytes or an unreadable file is said in §12's words, at most every 10 minutes per reference, and at every SIGHUP.
    - The held bytes stay in force.
    - `port49_key_secret_files_changed` (a gauge, no label) counts the key versions whose held file is in either state.
12. **MetalLB anycast is gated on L85.**
    - If L85 measures the source kept under `Local`, the route withdrawn when a pod goes, and a rolling restart under the PDB with no failed login past one retry, the chart gains `anycast.enabled` (Task 16).
    - Otherwise nothing ships, L85 records why, and the roadmap carries it.
    - Design §13's note stands: under anycast prefer per-transaction. NX-OS's single-connect offer is a device choice the README names.
13. **Store examples are shared.**
    - `deploy/examples/stores/single-site/` and `multi-region/` hold port49d.yaml and port49-broker.yaml fragments at the systemd paths. A test loads them through `config.Load`/`LoadBroker`. The compose and systemd READMEs point at them.
    - The chart's `examples/values-multi-region.yaml` is the Kubernetes form, rendered by the helm tests.
    - The examples also carry backups:
      - an etcd snapshot timer under `UMask=0077`;
      - a `port49-broker export-enrollments` timer under `UMask=0077`;
      - the Kubernetes CronJob form.

      Velero for the chart's PVCs is carried to 12c: naming it needs a measurement (pre-flight M10).
    - **Each shape README carries the `encryption:` key rotation runbook** (A20; roadmap R27's three steps), with one key everywhere from one secret. It is written for that shape's secret files.
    - **Each shape README has a "When it will not start" table** (pre-flight I12). Its columns are the refusal, the exact line, where to read it, and the fix. Its rows:
      - a secret file missing or unreadable;
      - the CA differs;
      - etcd below the floor;
      - the fence refuses;
      - a per-shape tail:
        - systemd: `journalctl -u port49d -b`, and `systemctl reset-failed port49d && systemctl start port49d` after `StartLimitBurst`;
        - compose: `docker compose logs port49d`, and `restart: unless-stopped` loops without limit;
        - Kubernetes: `kubectl logs --previous`, `kubectl describe pod` for a missing Secret (a `ContainerCreating` event, never a port49 line), and `CrashLoopBackOff`.
14. **The etcd floor in every smoke.** Each smoke configures every member's URL, never a Service or VIP, and asserts port49d's start line `etcd …, at or above the floor` names all three.

## Open for Ryan

The `.rpm` item is ruled by the team lead (2026-10-27) and written into ruling 6. Ryan may override it. The admin revoke over the API is decided (ruling 5, Ryan 2026-10-27).

- **The Python library in the `.rpm`** (ruling 6). RPM `site-packages` is per Python minor version, so one package cannot install an importable library. Ruled: the `.rpm` leaves the library to `pip install port49`, and the README says so. The alternatives, if Ryan overrides:
  - per-distribution RPMs, each naming its `python3.<minor>`;
  - a `%post` running `pip`.

  The `.deb` and the collection follow the roadmap as written.
- **Note, not a question: one agent per user** (Task 3h). With no socket flag, one user runs one agent, so one identity and one broker at a time. A second `port49 login` is refused until the first agent is stopped. This is intended, and spec §12 says so.
- **No automated admin call** (ruling 5's consequence). A machine principal cannot press a key, so a SOAR playbook or an HR offboarding hook can no longer revoke another principal through `revoke_others`. Recommended: keep it so. Offboarding goes through the identity provider, whose back-channel logout (`/v1/logout`) needs no right, and the disabled account cannot sign in again. The alternative is a revoke-only machine right with no touch, which would make an exposed workload token able to lock people out.
- **One-time actions before the first tag:**
  - register the PyPI trusted publisher: project `port49`, repository `rhwendt/port49`, workflow `release.yml`, environment `pypi`;
  - create the `galaxy` environment holding the secret `GALAXY_API_KEY`;
  - create the `release` environment (goreleaser, image and chart jobs) with Ryan as its required reviewer, so no tag publishes without approval;
  - restrict the `pypi`, `galaxy` and `release` environments' deployment branches and tags to `v*` tags;
  - add a repository tag ruleset protecting `v*`;
  - make the GHCR package `port49` and the chart public when the repository goes public.

## Global Constraints

- **Toolchain.**
  - Go 1.26+, module `github.com/rhwendt/port49`.
  - `gofmt` and `go vet` clean.
  - No cgo, and no new Go module.
  - Linux-only test code goes in `_linux.go` files or behind a build tag, so `make check-darwin` stays clean.
- **snake_case** for every data key:
  - port49's own: `key_secret_refs.file_dir`, `limits.max_connections`, `tls_listener.listen`.
  - The new metrics: `port49_key_secret_files_changed` and `port49_admin_touch_total{outcome}`.
  - The new rights: `lift_revocations`, `forget_principals`, `reset_second_factor`, `unlock_sign_in`, `import_enrollments`.
  - Helm values follow Helm's camelCase convention, because they are the chart's interface rather than port49's data. Every port49 config key they render stays snake_case.
- **Reason codes** come only from spec §5.7. Task 3a adds `admin_touch_required`, `admin_touch_proved`, `admin_touch_refused` and `admin_touch_unavailable` there before Task 3b emits them.
- **Warnings** come only from spec §12. The two rewrite lines are written into §12 by Task 1, before Task 2 emits them.
- **Metrics:** no device identity in any label. `port49_key_secret_files_changed` has no label, and `port49_admin_touch_total` has only `outcome`.
- **Proof material is never logged:** no record, log line or test failure carries an admin challenge, signature or attestation (Task 3b's `TestTheRecordHoldsNoProofMaterial`).
- **No socket is user-facing** (Ryan, 2026-10-27). No command has a socket flag, and no README, help text or example names a socket path or `PORT49_TEST_AGENT_SOCKET`, the tests' only override (Task 3h).
- **Hardware.** Agents never run `ykman`, `tpm2_*` or `pkcs11-tool`; a real YubiKey and TPM are present. Unit tests use `testpki.NewPIV` and software signers. Only Task 3g touches a real key, with Ryan present.
- **Secrets never printed or committed.**
  - No secret appears in an example, a values file, a workflow, a log line or a test failure message.
  - An example uses visibly fake material: `example.com`, `not-a-real-key-v1`, PEMs generated at test time by `internal/testpki`. Never a committed private key.
  - A test that asserts a secret is absent from a line checks that before printing the line (12a's N10 rule).
  - Kubernetes Secrets are created only with `--from-file`, never `--from-literal`.
  - Every failure dump in a smoke or lab harness (logs, events) goes through `tests/qual/secret-filter.sh`. The `vault` namespace is never dumped.
  - `make leaks` passes after every commit.
- **Measure first.**
  - No README asserts the behaviour of a third-party mechanism without its lab row closed or a smoke assertion. The mechanisms are Secret-volume modes, `subPath` updates, ESO, the Vault Agent injector's uid, the CSI driver's modes, `LoadCredential=`, Compose `secrets:` and MetalLB.
  - Where a row is open, the README says "unmeasured (L<N>)".
- **Pins.**
  - Every downloaded tool is pinned by version and sha256 in the Makefile, as gitleaks is: GoReleaser, Helm, kind, kubectl.
  - Every GitHub Action is pinned by full commit SHA, with the tag in a comment.
  - Every image is pinned by tag, and by digest where a workflow publishes from it.
- **Workflow permissions.** The default is `permissions: {contents: read}`. A job widens only what it uses: `packages: write` for the image and chart, `attestations: write` with `id-token: write` for attestations, and `id-token: write` for the PyPI publish. No job prints a secret, and none runs `set -x`.
- **Files never read:** `*.env`, `*.keytab`, `*-key.pem`, `realm.json`, `router.db`, `/tmp/port49-lab-tokens.jsonl`, `tests/lab/logs/**`. A smoke reads only the key files it generated itself, under `t.TempDir()`.
- **Lab tasks** (3g, 13, 14, 15, 16) run on the lab host under the lab lock, with the stall watchdog. Each closes or updates its row by CLAUDE.md's rule: a results note under `tests/lab/results/`, the §15 Status edited, and a `docs: close lab register entries ...` commit.
- **Commits.**
  - Conventional Commits, one per task step that says "Commit".
  - Each ends with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, naming the implementing model.
  - No `Claude-Session:` line and no claude.ai link.
- **Verification.** Run `make test && make vet` before each commit, plus each task's own target, and report the real output.

## Review Focus

These are the conditions most likely to bite an operator that no single task's happy path exercises. Each has its test in the named task.

1. **A hardening option makes the fence blind.** A unit or pod mounts the config path read-only, so the fence excuses a group-writable directory on the host. *Pinned:*
   - Task 7's unit test refuses `ProtectSystem=strict|full`, `ReadOnlyPaths=`, `BindReadOnlyPaths=`, `ProtectHome=read-only`, `:ro` `TemporaryFileSystem=` and `InaccessiblePaths=`;
   - Task 9's smoke runs `chmod g+w /etc` (an ancestor) under the shipped unit, and asserts the start is refused with a journal line naming `/etc` and `writable by others`. It also shows the cell can fail: under a `ProtectSystem=strict` drop-in the same start passes.
2. **A refused start loops forever.** A CA mismatch, an etcd below the floor or a policy with no `keys:` must not loop. *Pinned:* Task 9's smoke starts a unit on a policy with no `keys:` and asserts `NRestarts` ≤ `StartLimitBurst` and `ActiveState=failed` within `StartLimitIntervalSec`.
3. **A pod restart makes `state_dir` group-writable** (`fsGroupChangePolicy: Always`), so the broker refuses it. *Pinned:*
   - Task 10's helm test asserts that the broker pod has no `fsGroup`, and that port49d's sets `OnRootMismatch`;
   - Task 11's kind smoke deletes the broker pod and asserts that the restarted broker says no `state_dir` refusal.
4. **A key version is added at 3am by rewriting a file in place.** A restarted replica diverges from the others. *Pinned:*
   - Task 2's tests: warned, never refused, held bytes kept;
   - every smoke's rotation cell adds a version under a new name and asserts it is in force without a restart.
5. **A release publishes from the wrong ref or the wrong version**, or a pull request job gains `id-token`. *Pinned:*
   - Task 12's `TestReleaseRunsOnTagsOnly`, `TestOnlyThreeJobsHoldIDToken`, `TestPublishJobsBuildNothing` and `versioncheck` at the tag;
   - Task 4's `versions` job on every pull request.
6. **A captured admin proof is replayed against another call**: the same proof for another target, another operation, another connection, or a second time. *Pinned:* Task 3b's `TestAProofIsBoundToItsRequest`, `TestAProofIsBoundToItsConnection`, `TestAProofIsSpentOnce` and `TestAPerLoginProofIsNotAnAdminProof`.

---

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md` | §10 sentence, §12 paragraph, decision 54, rows L82–L85 | 1 |
| `internal/port49d/livekeys.go`, `reload.go`, `internal/daemon/metrics/metrics.go` | re-read held `file:` keys, warn | 2 |
| `internal/port49d/witness.go`, `restoreguard.go`, `brokerd.go` and four tests | witness-follower hook | 3 |
| `docs/design/2026-08-23-policy-engine-spec.md` | §2 rights, §5.1.6 admin calls, §5.7, §10, §12, decision 54 ruling 15, row L86 | 3a |
| `internal/broker/adminproof.go`, `internal/broker/api/admin.go`, `internal/mfatouch/` | the request-bound admin proof | 3b |
| `internal/broker/admin_api.go`, `internal/policy/load.go` | admin endpoints, the five rights | 3c |
| `internal/agent/`, `cmd/port49/revoke.go`, `directory.go` | admin calls through the agent | 3d |
| `internal/daemon/admin/` (deleted), `internal/config/`, `internal/port49d/` | sockets removed; offline and local subcommands; store status on the metrics port | 3e |
| `internal/port49d/keysdiagnose.go`, `pcap.go` | keys-diagnose from a capture | 3f |
| `tests/lab/l86_admin_touch.go`, `tests/lab/results/L86-ser8.md` | lab row L86 | 3g |
| `internal/agent/socket.go`, `cmd/port49/*`, `clients/python`, `clients/ansible`, the tests that pass `--socket` | no socket flag on any command | 3h (runs before 3g) |
| `tests/ci/testshard/`, `tests/ci/cmd/{testshard,mustpass,versioncheck}/`, `Makefile`, `.github/workflows/test.yml` | CI split, root tests, versions | 4 |
| `Dockerfile`, `tests/image/` | multi-arch build, image layout check | 5 |
| `tests/shapes/shapetest/`, `tests/compose/`, `deploy/compose/`, `internal/testpki/compose.go` | shared smoke helpers; compose secrets as files | 6 |
| `deploy/systemd/`, `deploy/examples/stores/`, `tests/shapes/examples_test.go` | units, configs, examples | 7 |
| `.goreleaser.yaml`, `packaging/`, `tests/packages/`, `internal/userconfig/conffile_test.go` | packages, client conffile, the Python library and the collection in the client package | 8 |
| `tests/systemd/` | systemd smoke | 9 |
| `deploy/helm/port49/`, `tests/helm/` | chart, render tests, ESO example | 10 |
| `tests/kind/`, `tests/kind/kindtest/`, `internal/testpki/kind.go` | kind smoke, its CronJob cell, the shared bring-up | 11 |
| `.github/workflows/kind.yml` | the kind smoke in CI, after L82 is measured | 13 |
| `.github/workflows/release.yml`, `tests/ci/workflows_test.go`, `packaging/requirements-release.txt` | release and publishing, build apart from publish | 12 |
| `tests/lab/` L82–L85 harnesses, `tests/lab/results/` | lab rows | 13–16 |
| `docs/superpowers/plans/README.md` | As built, operator notes | 17 |

---

### Task 1: Spec: the rewrite warning, decision 54, rows L82–L85

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §10, "Version sets, and no cutover";
  - §12, after "Connection shedding";
  - §13, after decision 53;
  - §15, after L81.

- [ ] **Step 1: In §10, after "port49 reads no store directly (decision 53 ruling 5)." (spec line 5140), add:**

  > A version's file rewritten in place is not re-read. port49d keeps the bytes it read and warns (§12), so a restart is the only thing that would take the new bytes, and only on the replica restarted.

- [ ] **Step 2: In §12, after "Connection shedding", add the paragraph "A key secret rewritten in place."**

  The paragraph's text, verbatim:

  > **A key secret rewritten in place.** At every SIGHUP, after every swap, and every 30 s, port49d reads each held `file:` key reference again (decision 54 ruling 11). For a file whose bytes differ from those it holds it says, per version that names it: `port49d: keys.<ref> version <n>: <path> has changed since port49d read it; port49d keeps the secret it read, and a restart would take the new one on that replica alone; a version's secret never changes (§10): put the new secret in a new file under a new version`. For one it can no longer read: `port49d: keys.<ref> version <n>: <path> can no longer be read (<error>); port49d keeps the secret it read, but a restart will refuse to start until the file is back or the policy no longer names the version`. Each line is said when first seen, then at most every 10 minutes per reference, and at every SIGHUP. `port49_key_secret_files_changed`, a gauge with no label, is the number of key versions whose held file is in either state. Neither refuses a reload. An `env:` reference is never re-read: a variable cannot change in a running process.

- [ ] **Step 3: Write decision 54, "Deployment shapes, release and publishing (plan 12b)".**

  - Rulings 1–14 as this plan states them, one paragraph each.
  - Its "Open" line names the admin revoke over the API. (Merged so; Task 3a removes it, since Ryan decided it on 2026-10-27.)

- [ ] **Step 4: Add rows L82–L85 to §15, each with Status `open`.**

  Every cell carries its own PASS condition, so "closed" means each cell has a PASS or a FAIL, and the claim column says which results the dependent text may cite.
  - A FAIL is a measured answer, not an open row.
  - A row closes when every cell has a PASS or a FAIL.
  - A README names a mechanism only where every one of its cells is PASS.

  | ID | Claim to measure (each cell: what is recorded; PASS iff) | What rests on it | Platforms |
  |---|---|---|---|
  | **L82** | Kubernetes Secret volumes as port49d's key directory, on kind. (a) The owner, group and mode of the mount's directory, its `..data` link and each key file under `defaultMode: 0440`, `fsGroup: 65532`, `fsGroupChangePolicy: OnRootMismatch`. PASS iff port49d starts with the key (`fence.ReadSecret` accepts). (b) A key added to the Secret reaching a whole-volume mount: the delay. PASS iff the file appears within 180 s. (c) A `subPath` mount of the same Secret after an update. PASS iff the `subPath` file is unchanged after 180 s while the whole mount changed: that confirms "never `subPath`". (d) An External Secrets Operator `ExternalSecret` (`fake` provider), one remote key per version. PASS iff a version added to the ExternalSecret reaches the mounted Secret, and a policy naming it is in force with no container restart (`restartCount` and start time unchanged) within 240 s. | Decision 54 ruling 2's Kubernetes key volume (provisional on this row); the ESO example; 12a's whole-volume hand-off | kind (node image recorded), ESO version recorded |
  | **L83** | Secret-store agents rendering port49d's keys, on kind. (a) The Vault Agent injector's rendered file with `perms = "0440"`: owner, group, mode and the agent's uid (documented as 100), with and without `agent-run-as-same-user`. PASS iff port49d starts with the key. (b) The Secrets Store CSI driver with the Vault provider: the files' owner and mode with and without the provider's file-permission setting. PASS iff port49d starts with the key. (c) For each mechanism that passed (a) or (b): a version added at the store reaches the running process with no restart. PASS iff a policy naming the new version is in force with no container restart within 300 s. A mechanism that fails (c) may be named for the encryption key only, never for device keys. | Whether a README may name Vault Agent or the CSI driver (decision 54 ruling 2) | kind; Vault, injector, CSI driver and provider versions recorded |
  | **L84** | Host credential mechanisms against `fence.ReadSecret`. (a) systemd `LoadCredential=`: `$CREDENTIALS_DIRECTORY`'s path, owner and mode, and the files'. PASS iff port49d starts with `key_secret_refs.file_dir` naming it, and again on a second start. (b) Compose file-backed `secrets:`, long syntax `uid: "0"`, `gid: "65532"`, `mode: 0440`, and the short syntax (documented 0444): the mounted file's owner and mode. PASS iff port49d starts with the key. (c) For each mechanism that passed (a) or (b): a version added reaches the running process with no restart. PASS iff a policy naming it is in force with `ExecMainStartTimestamp` or `StartedAt` unchanged within 120 s. A mechanism that fails (c) may be named for the encryption key only, never for device keys. | Whether the systemd and compose READMEs may offer these (decision 54 ruling 2) | systemd 257 (Debian 13); Docker and Compose versions recorded |
  | **L85** | MetalLB in BGP mode as an anycast VIP for port49d, on kind with an FRR peer. (a) The source address port49d sees under `externalTrafficPolicy: Local`. PASS iff it is the device's own address and the device-binding check passes. (b) Which nodes advertise the VIP. PASS iff exactly the nodes running a ready port49d pod. (c) A port49d pod deleted: the withdrawal time, and what an open single-connection session and a per-transaction client see. PASS iff the route is withdrawn within 10 s, and the per-transaction client's next login passes. (d) A rolling restart under the chart's PDB, with one login a second. PASS iff no login fails past one retry. | Whether the chart offers anycast (decision 54 ruling 12; Plan 12 rulings, B2); design §13's anycast note | kind; MetalLB and FRR versions recorded |

- [ ] **Step 5: Check the edit and commit.**

  - Run `make test && make vet`. Expected: PASS (`lab-unit` reads §15 through `notediff`'s tests).
  - Commit:

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md
  git commit -m "docs: decision 54, the in-place key rewrite warning, and lab rows L82-L85"
  ```

---

### Task 2: Warn when a held key file is rewritten in place

**Files:**
- Modify: `internal/port49d/livekeys.go`, `internal/port49d/reload.go` (`reload`, `poll`, `swap`, the `reloader` struct), `internal/daemon/metrics/metrics.go`
- Test: `internal/port49d/livekeys_test.go`, `internal/port49d/keyretry_test.go`

**Interfaces:**
- Consumes:
  - `secretref.Parse(string) (Ref, error)`;
  - `(*secretref.Resolver).Resolve(Ref, within string) (Secret, error)`;
  - `Secret.Bytes() []byte`;
  - `keyRetryInterval`, `keyRetrySayEvery` (keyretry.go);
  - `r.sayf`.
- Produces:
  - `type keyFileState int` with `keyFileSame`, `keyFileChanged`, `keyFileUnreadable`;
  - `type keyFileFinding struct{ Ref string; Version int; Path string; State keyFileState; Err error }`;
  - `func (k *liveKeys) rewritten() []keyFileFinding`, which is nil-safe and returns findings sorted by Ref then Version, only for `file:` references in the build in force, `keyFileSame` omitted;
  - `func (r *reloader) rereadKeyFiles(trigger string)`;
  - metric field `KeySecretFilesChanged prometheus.Gauge`, registered as `port49_key_secret_files_changed`.

- [ ] **Step 1: Write the failing tests in `livekeys_test.go`.**

  - `TestAKeyFileRewrittenInPlaceIsFoundAndNotRead`:
    - Build a policy with `keys.k` version 1 at `file:<dir>/k_v1` holding `not-a-real-key-v1`, and `put` it.
    - Rewrite the file to `not-a-real-key-v1-rewritten`.
    - `rewritten()` returns `[{Ref:"k", Version:1, Path:<dir>/k_v1, State:keyFileChanged}]`.
    - `k.Set("k")` still validates with the original bytes and not the new ones. Compare lengths and a boolean; never print either value.
  - `TestAKeyFileRemovedIsFoundUnreadable`: remove the file. One finding with `State == keyFileUnreadable` and a non-nil `Err` whose text does not contain the secret (checked before any print).
  - `TestAnEnvKeyIsNeverReread`: an `env:PORT49_KEY_T` version; change the variable with `t.Setenv`; `rewritten()` is empty.
  - `TestAnUnchangedKeyFileIsNotAFinding`: `rewritten()` is empty.

- [ ] **Step 2: Write the failing tests in `keyretry_test.go`, with the reloader harness `keyretry_test.go` already uses.**

  - `TestARewriteIsSaidThenRateLimited`:
    - After a swap, rewrite the file.
    - `r.poll` at T+30s: one line containing `keys.k version 1:` and `has changed since port49d read it`, and the gauge reads 1.
    - At T+60s: no new line.
    - `r.reload(ctx, "SIGHUP")`: the line again.
    - At T+11m: the line again.
    - Restore the original bytes: the gauge reads 0 at the next poll.
  - `TestARewriteNeverRefusesAReload`: with version 1 rewritten, a policy edit adding version 2 (`file:<dir>/k_v2`, present) swaps in. The policy-reload counter's success value rises, as `keyretry_test.go` already reads it, and `PolicyFileRefused` stays 0.
  - `TestTheRewriteLineCarriesNoSecret`: neither byte string appears in stderr. Check with `bytes.Contains` and fail with the lengths only.

- [ ] **Step 3: Run the tests and see them fail.**

  Run `go test ./internal/port49d/ -run 'TestAKeyFile|TestAnEnvKey|TestAnUnchanged|TestARewrite|TestTheRewrite' -count=1`. Expected: FAIL to compile (`rewritten` undefined).

- [ ] **Step 4: Implement `rewritten` in `livekeys.go`.**

  - Under `k.mu`, for each `ref → version → text` in `k.in.Load().refs`, parse `text`. For a `file:` reference, `Resolve` it with `k.allow.FileDir` as `within`.
  - A read error is `keyFileUnreadable`, with the error.
  - Different bytes are `keyFileChanged`. Compare with `subtle.ConstantTimeCompare` against `k.held[text].Bytes()`.
  - Never store the bytes read.

- [ ] **Step 5: Implement `rereadKeyFiles` in `reload.go`.**

  - Add `keyFilesNext time.Time` and `keyFilesSaid map[string]time.Time` (keyed `ref/version`) to `reloader`.
  - `rereadKeyFiles` sets the gauge to `len(findings)`. For each finding it says §12's line (Task 1, Step 2, verbatim). The format string starts at `keys.`, because `sayf` adds the `port49d: ` prefix itself. It says the line when the trigger is `"SIGHUP"`, or when the finding was never said or was said ≥ `keyRetrySayEvery` ago.
  - It drops `keyFilesSaid` entries for findings now gone.
  - Call it:
    - in `reload` after `rereadVerifyKeys()`, with the trigger;
    - at the end of `swap`, with `"reload"`;
    - in `poll` when `r.now()` ≥ `keyFilesNext`, then set `keyFilesNext = now + keyRetryInterval`.
  - `r.keys == nil` (port49-broker) does nothing.

- [ ] **Step 6: Register the gauge.**

  Register `port49_key_secret_files_changed` in `metrics.go`, with help text "Key versions whose held file: secret has changed or can no longer be read (spec §12); the held secret stays in force."

- [ ] **Step 7: Run the tests and see them pass.**

  - Run the Step 3 command. Expected: PASS.
  - Then `make test && make vet`. Expected: PASS.

- [ ] **Step 8: Commit.**

  ```bash
  git add internal/port49d/livekeys.go internal/port49d/reload.go internal/daemon/metrics/metrics.go internal/port49d/livekeys_test.go internal/port49d/keyretry_test.go
  git commit -m "feat: warn when a held key file is rewritten in place, never refusing the reload"
  ```

---

### Task 3: Flake hit 8: wait on the witness follower, not a sleep

**Files:**
- Modify:
  - `internal/port49d/witness.go`;
  - `internal/port49d/restoreguard.go:167`;
  - `internal/port49d/brokerd.go:564`;
  - the tests at `internal/port49d/brokerd_test.go:2114`, `:2206`, `:2293` and `internal/port49d/split_e2e_test.go:55`.

**Interfaces:**
- Produces:
  - `var witnessFollowed = func(rec *witnessRecord, rev uint64) {}`, called after the record's `Saw`, from the follower's callback.
  - `var restorePassed = func(g *restoreGuard) {}`, called at the end of each completed `restoreGuard.pass`.
  - Both hooks are keyed by pointer, not by process name, because one test process may run several in-process daemons (`startSplitDaemon(..., 3)`). Only tests swap them.
  - Test helpers:
    - `followWitness(t *testing.T) func(t *testing.T, rec *witnessRecord, atLeast uint64)` installs a recording hook, restored in `t.Cleanup`, and returns a wait that blocks until `rec` has followed a revision ≥ `atLeast`. It fails after 10 s, naming the highest revision seen.
    - `countPasses(t *testing.T) func(t *testing.T, g *restoreGuard, n int)` returns a wait for `n` more completed passes of `g` after the call, failing after 10 s.
  - The tests reach a daemon's `*witnessRecord` and `*restoreGuard` through the accessors the harness already exposes. If none exists, add an unexported field to the test harness's daemon handle, never to production types.

- [ ] **Step 1: Write the failing tests.**

  - `TestTheWitnessHookSeesWhatTheFollowerSaw` in `witness_test.go`: drive the follower against the `etcdtest` store, write `meta/witness`, and wait. The wait returns once the hook reports a revision ≥ the write's.
  - `TestRestorePassedCountsPasses`: two passes of a guard on the `etcdtest` store are counted, and a second guard's passes are not.

- [ ] **Step 2: Run the test and see it fail.**

  Run `go test ./internal/port49d/ -run TestTheWitnessHookSeesWhatTheFollowerSaw -count=1`. Expected: FAIL to compile (`witnessFollowed` undefined).

- [ ] **Step 3: Implement the hook.**

  - Wrap both `FollowWitness` callbacks to call `witnessFollowed(record, rev)` after `Saw`. Call `restorePassed(g)` at the end of `pass` when it returns true.
  - `brokerd_test.go:2206` and `:2293` ("port49d follows it"): replace the sleep with `followWitness`'s wait for the revision the step before wrote. Read `meta/witness`'s `ModRevision` through `root`, as `witnessAt` does.
  - `brokerd_test.go:2114` and `split_e2e_test.go:55`: there is no new witness write to wait for. The sleep gives later restore-guard passes the chance to find nothing, so replace it with `countPasses`'s wait for two completed passes of each running daemon's guard.

- [ ] **Step 4: Verify.**

  - Run `go test ./internal/port49d/ -run 'TestTheWitnessHook|<the four tests by name>' -count=20`. Expected: PASS, 20 of 20.
  - Then `make test && make vet`. Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  git commit -am "test: wait on the witness follower's hook instead of sleeping two witness periods"
  ```

---

### Task 3a: Spec: admin calls over the API, each with a security key press

Ryan's ruling of 2026-10-27 (ruling 5) replaces the admin sockets. **First merge `main` into the branch**, which holds this amended plan; decision 54 exists only on the branch (A-M5). This task writes the ruling into the spec before any code (rights first in §2, reasons first in §5.7, warnings first in §12). Task 1 is merged on the branch, so this task amends decision 54 in place.

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2, the rights table;
  - §5.1.4, every sentence that sends a lift, a certificate or a list to "the admin socket";
  - a new §5.1.6, "Admin calls";
  - §5.7, the events table, the reason codes table and the `origin` vocabulary;
  - §10, "Cross-group probing is manual";
  - §12, the `port49 revoke`, `port49 directory`, `port49 keys diagnose` and `port49 store status` entries, and the line "`port49-broker --config port49-broker.yaml` is the broker on etcd";
  - §13, decision 34's "Others" bullet (a note pointing at decision 54 ruling 15), decision 54 (ruling 5 struck through to ruling 15, ruling 15 added, its "Open" line), and decision 36's "The sockets." bullet (the same note);
  - §15, row L86 after L85.

- [ ] **Step 1: §2, the rights table.** Add these rows after `explain_others`, and the "admin-level" paragraph under the table:

  | Right | Unlocks | Admin-level |
  |---|---|---|
  | `revoke_others` | (as today), plus a revocation by certificate (`{"cert_issuer", "cert_serial"}`), and `GET /v1/revocations` | yes, except the list |
  | `lift_revocations` | `POST /v1/revocations/lift`, by principal or certificate; and `GET /v1/revocations` | yes, except the list |
  | `forget_principals` | `POST /v1/directory/forget` | yes |
  | `reset_second_factor` | `POST /v1/directory/reset-second-factor`, one principal or `all` | yes |
  | `unlock_sign_in` | `POST /v1/directory/unlock` | yes |
  | `import_enrollments` | `POST /v1/directory/import` | yes |

  Add an "Admin-level" column to the existing rows: `explain_others` no; `sync`, `keys_show` and `replay` reserved.

  The paragraph, verbatim:

  > **Admin-level calls.** A call is admin-level when it writes, lifts or removes state that belongs to another principal or to the server's trust: a revocation of another principal, a certificate, a `(device, username)` key or an OIDC session; a lift; a directory pin; a second factor or a sign-in lockout; the enrollment store. A call that only reads (`explain_others`, the revocation list) or acts on the caller alone (`mine`) is not, and neither is an install-time initialization that refuses when anything is there (`init-revocations`, `init-enrollments`, `init-issuer`). An admin-level call needs its right and a fresh `hardware_key_touch` proof bound to that one request (§5.1.6). So an admin's certificate, bearer token or agent session, exposed alone, authorizes nothing admin-level.
  >
  > **Host-local authority.** A host-local command, run as the service's user or root against the process's own files or store credentials, is not an API call. Its authority is the host's, and it needs no touch. Where it writes a decision record (the offline revoke and lift), the record's origin is `offline uid <n>`. This covers `revoke --offline`, `init-issuer`, `rotate-issuer`, `forget-issuer`, `store-roles`, `init-revocations`, `init-enrollments`, `export-enrollments` and `keys-diagnose`, each run with access to the broker or port49d host, and the offline ones with the brokers stopped. A provider-signed back-channel logout (`/v1/logout`) is the provider's act, authenticated by the provider's signature, not an admin call, and needs no right and no touch.

  A certificate revocation stays under `revoke_others` rather than a right of its own: it reaches a subset of what a revocation of the certificate's principal reaches, so a separate right would grant nothing `revoke_others` does not. A lift is its own right because it is the one call that weakens.

- [ ] **Step 2: §5.1.6, "Admin calls".** Write it with these rules, one paragraph each:

  - **The challenge.** An admin-level request carrying no `Port49-Admin-Proof` header is answered `401 admin_touch_required` with `{"admin": {"operation", "target", "challenge", "expires_at"}}`: 32 random bytes, kept 2 minutes in the answering broker's memory, never the store, one per connection (a new one replaces the last). The operations are `revoke_principal`, `revoke_certificate`, `revoke_key`, `revoke_sid`, `lift`, `forget_principal`, `reset_second_factor`, `reset_second_factor_all`, `unlock_sign_in` and `import_enrollments`. The target is the principal, the certificate's issuer and serial, the `device/username` key, the `sid` and issuer, `all`, or for an import `replace` or `merge` followed by the first 12 hex digits of the body's SHA-256, so the prompt shows that a replace wipes the store. The record is keyed by `SHA-256(challenge ‖ 0 ‖ exporter ‖ 0 ‖ principal ‖ 0 ‖ fingerprint ‖ 0 ‖ request_sha256)`, so any other caller, connection or request misses it.
  - **The request binding.** `request_sha256 = SHA-256("port49 admin request v1\0" ‖ method ‖ 0 ‖ path ‖ 0 ‖ body)`, over the exact body bytes, where `path` is `r.URL.RequestURI()` (path and query) on both sides, so `?replace=` is bound. The proved retry sends the same method, path and body bytes, so a proof made for "revoke bob" verifies against nothing but "revoke bob" on that connection.
  - **The proof.** The touch key signs `"port49 admin v1\0" ‖ challenge ‖ request_sha256 ‖ exporter`, where `exporter` is the connection's TLS exporter value under the label `EXPORTER-port49-admin` (32 bytes). Its own label and prefix mean a per-login proof (§5.1.5) is never an admin proof, or the reverse. The header is base64url JSON `{"challenge", "signature", "attestation": [touch slot, f9, session slot]}`. The broker verifies the attestations exactly as decision 45 ruling 12 does, against `broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file`: the chain to the roots, the touch policy `always`, one device serial for both slots, and the session slot's key equal to this connection's client key. Then it takes the challenge record (single use) and runs the operation.
  - **No reuse.** A proof covers the one request it was made for, once. There is no `reuse_for` for admin calls, so each operation is one touch.
  - **Order.** The proof is judged before the request takes the revocation slot or touches the store, so a touch never holds the slot, and a refused proof changes nothing.
  - **Who cannot prove.** A caller with no client certificate on the connection (a bearer, a workload's fresh connection), or whose session key is not on the attested token, cannot prove. Such a request gets no challenge: it is refused `401 admin_touch_refused`, naming why. A broker with no attestation roots answers every admin-level call `503 admin_touch_unavailable` and says so at start and at every reload.
  - **Presence, not intent.** A touch proves that a person is at the token. It does not say what they meant: the CLI's prompt carries the intent, so the agent builds the prompt from its own request, never from the broker's answer. It derives the operation and target from the request it is sending, refuses a challenge whose `operation` or `target` differs from them, and computes `request_sha256` itself. It holds one touch at a time: a second admin call while one waits on the key is refused, `another touch is waiting on your key`.
  - **The agent.** `port49 revoke` and `port49 directory` send admin calls through the operator's agent (`POST /admin` on the agent's socket). The agent sends the request, takes the challenge, prints `touch your key to <operation> <target>`, signs over the exporter value read with the wire (released for the touch, as decision 45 ruling 14 does), and sends the retry only over the connection it signed over (`mfatouch.Post`'s rule, through Task 3b's `PostRequest`). Otherwise it says "the connection changed during the touch; run it again", posting nothing. An agent whose `touch_key_unusable` is set refuses an admin call before sending anything, naming why, so no `admin_touch_refused` fires for an operator whose key cannot touch.
  - **The 3am view**, as a table in this section (the exact lines are the CLI's):

    | Condition | What the operator sees | What to do |
    |---|---|---|
    | Session key not on a security key (TPM, Secure Enclave, file) | `port49: admin operations need a security key press, and your session key is in the TPM: a touch proves only from the token that holds it` (the agent's `touch_key_unusable` text); exit 1, nothing sent | log in with a session key on the security key (`key: pkcs11:…`, or `issued_key_store: pkcs11`) |
    | Attestation does not chain (a newer firmware's intermediate missing) | `401 admin_touch_refused: the touch slot's attestation does not verify: …`; exit 1; the alert fires | add the root or intermediate to `attestation_roots_file`, then reload |
    | No touch in time | `hwkey: no touch within 15s; touch the key when it blinks and try again` (decision 45 ruling 14; the timing is provisional on L60, measured 14.4 s on one token); exit 1, nothing done, no alert; the challenge expires unspent | run it again |
    | The connection changed during the touch | `the connection changed during the touch; run it again`; exit 1, nothing posted, no alert | run it again |
    | The identity provider is down | Nothing: the admin's port49 certificate is still valid, `port49 login` reuses it without the provider (decision 43 rulings 12 and 17), and neither the touch nor the call needs the provider | revoke as usual |
    | The admin's certificate has expired and the provider is down | `port49 login --oidc` cannot sign in | another on-call admin with a valid certificate revokes as usual; break-glass (`port49-broker revoke --offline`, or `port49d revoke --offline`, with every broker stopped, which also stops issuance fleet-wide) only when none can |
    | `forget`, `unlock` or `reset-second-factor` wanted with every broker down | no offline form exists | none is needed: while every broker is down nobody signs in, so none of the three can matter until a broker is back, and then the API serves them |
    | A right held through a `group:` subject, with the directory down | the right resolves as the directory cache allows (decisions 38 and 51); past that, `403 api_right_missing` | name at least two on-call admins by `identity:` as well (the shape READMEs say so) |
    | No attestation roots configured | `503 admin_touch_unavailable: no attestation roots are configured (broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file); admin operations need them` | set the file |
    | The store is down | the proof needs no store; the operation answers `503 store_unavailable`, as today | `revoke --offline` when the store is back but the brokers are not; etcd's own `rv/` path otherwise (decision 36) |

- [ ] **Step 3: §5.7.** Add:
  - the event `admin_touch` (broker): an admin-level call's proof outcome, carrying `admin: {operation, target, challenge_sha256}`, never the challenge, the signature or the attestations;
  - the reason codes:
    - `admin_touch_required` (`admin_touch`): an admin-level call carried no proof; a challenge was issued, nothing done;
    - `admin_touch_proved` (`admin_touch`): the proof verified, and the operation's own record follows;
    - `admin_touch_refused` (`admin_touch`): the proof did not verify (an unknown, spent, expired, or another caller's, connection's or request's challenge; a signature not over this exporter and request; an attestation that does not chain, is not always-touch, or is not the session key's token's), or the caller cannot prove (no client certificate). API 401 with the cause. **Alertable on its own**, as `per_login_mfa_refused` is;
    - `admin_touch_unavailable` (`admin_touch`): no attestation roots loaded. A configuration fault, alertable;
  - in the `origin` vocabulary: remove `admin_socket uid <n>`. Admin calls carry `api <principal>`; `offline uid <n>` stays.
  - the metric `port49_admin_touch_total{outcome}`, `outcome` one of `required`, `proved`, `refused`, `unavailable`. No device or principal label.

- [ ] **Step 4: §10, "Cross-group probing is manual".** Replace the socket sentences with: `port49d keys-diagnose --device <name> --capture <file.pcap>`, run as port49d's user on a port49d host (or by `kubectl exec` in a port49d pod), with port49d's config and environment. It reads the first TACACS+ packet from that device's address in a classic pcap file the operator captured (`--capture -` reads standard input, so on Kubernetes, whose image is distroless and has no `tar` for `kubectl cp`: `kubectl exec -i <pod> -- port49d keys-diagnose --device D --capture - < f.pcap`), and tries every key the policy names, retired versions included. It prints only the group and version that validated, or `no key port49d holds validates this packet`. It never prints a packet byte or a key. The running port49d no longer keeps an unvalidated packet in memory. The rest of the paragraph (manual, never automatic, a CPU amplifier on an unauthenticated listener) stands.

- [ ] **Step 5: §12.** Rewrite these entries:
  - `port49 revoke (--principal | --cert | --cert-issuer --cert-serial) [--lift]` and `port49 revoke --list`: through the agent, under the rights of §2 and the touch of §5.1.6. Exit codes as today, plus 1 for a touch not made. `--via-agent` is removed (pre-beta, no alias), and an unknown flag exits 2. `--mine` and `--device/--username` keep their meaning: `--mine` needs no right and no touch, while a key needs `revoke_others` and a touch.
  - `port49 directory forget | reset-second-factor | unlock | import`: through the agent, each under its right and a touch.
  - **No socket is user-facing** (Ryan, 2026-10-27, superseding the pre-flight's A-M4). No command has a `--socket` or `--agent-socket` flag: `login`, `token`, `refresh`, `identity`, `ssh`, `explain`, `revoke`, `directory`, `store status` and `keys` lose theirs, and the agent's §12 synopses drop `[--socket PATH]`. The agent and every client find the agent's socket at its per-user default (`$XDG_RUNTIME_DIR/port49/agent.sock`, else `/tmp/port49-<uid>/agent.sock`). The Python library's `socket=` argument and the collection's `socket` option go too. Tests override the path with one environment variable, named only in `agent.SocketPath()`'s Go comment, the tests and the lab runbooks, and never in the spec, so the docs site (plan 13) cannot render it. No README, help text, example or operator page names it. One agent per user is intended: a second `port49 login` while an agent holds a session is refused, and the remedy is to stop that agent first.
  - `port49-broker init-enrollments` and `port49d init-enrollments` (install-time, as the broker's or port49d's user, refused when a store or mark is there).
  - `port49-broker export-enrollments` and `port49d export-enrollments` (reads the sealed store through the process's own store identity, writes it to stdout, refuses a terminal). Neither is admin-level: one creates nothing that exists, and the other reads sealed bytes.
  - `port49 store status --metrics <addr>`: reads `GET /store/status` on the process's metrics listener (plain HTTP, beside `/readyz`), with the same output and exit codes. One status runs at a time per process, and a second request is answered 429. The metrics listener has no authentication, so the answer is store health alone, from a fixed allowlist: per role, the backend, `<answering>/<listed> members`, reachability, the directory cache's age, the names of the feeds down, the count of logouts pending, and a reason from `outageCause`'s fixed words. Never a member URL, an etcd error's text, a certificate, a principal, a mark or a key. Everything else stays behind the API: the revocation list is `GET /v1/revocations` under its right. The same counts are already on `/metrics` as gauges.
  - `port49-broker revoke --offline` gains `--list`. `port49d revoke --offline [--config FILE] (--principal P | --cert-issuer I --cert-serial S) [--lift] | --list` is added, for a port49d with its broker in process, run with port49d stopped. It writes the store or `broker.revocations_file`, as port49d's user or root.
  - `admin_socket`, in port49d.yaml or port49-broker.yaml, is refused at load: `admin_socket was removed: admin operations go over the broker API with a security key press (spec §5.1.6); delete the key`. The rule "etcd requires admin_socket" is deleted.
  - Add the warning `port49-broker: no attestation roots are configured (broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file): every admin operation will be refused until they are`, said at start and at every reload while a policy subject holds an admin-level right. The same warning is said by port49d when its broker is in process.

- [ ] **Step 6: Decision 54.** Strike ruling 5's socket text and say "replaced by ruling 15". Add **ruling 15**, written from this plan's ruling 5, with its inventory table. Remove the admin revoke from its "Open" line. Add a one-line note to decision 34's "Others" bullet and to decision 36's "The sockets." bullet: "superseded by decision 54 ruling 15".

- [ ] **Step 7: §15, row L86, Status `open`.**

  | ID | Claim to measure (each cell: what is recorded; PASS iff) | What rests on it | Platforms |
  |---|---|---|---|
  | **L86** | An admin call's touch on a real YubiKey, on the SER8 (needs Ryan present). (a) Two admin calls 5 s apart under touch policy `always`: whether the second blinks again. PASS iff each call needs its own touch, and the second fails without one. (b) No touch: the time to failure and the words. PASS iff the CLI prints the timeout line, exits 1, and `port49 revoke --list` shows no mark. (c) An OIDC-issued session key in the token's slot (`issued_key_store: pkcs11`, L60's open issued-key cell): an admin call. PASS iff it succeeds with one touch. (d) The key unplugged with the agent running: an admin call. PASS iff the CLI says to insert the key, nothing is sent, and the broker's log has no `admin_touch_refused`. Cites L60 (partial: the touch policy byte, the attestation chain and serial, a 14.4 s timeout on one token) and L62 (TPM session keys, which this path refuses before sending). | §5.1.6's "one touch per operation" and its 3am table; decision 54 ruling 15 | YubiKey 5 (firmware recorded), libykcs11 (version recorded), SER8 |

- [ ] **Step 8: Check and commit.**

  Run `make test && make vet` (the spec is not compiled, but the reason-code test reads §5.7: `internal/decision` must still pass). Commit:

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md
  git commit -m "docs: admin calls over the broker API with a security key press; the admin socket removed; row L86"
  ```


---

### Task 3b: The admin proof in the broker

**Files:**
- Create: `internal/broker/adminproof.go`, `internal/broker/adminproof_test.go`, `internal/broker/api/admin.go`
- Modify: `internal/broker/mfa.go` (split `verifyTouch` so it verifies a message under a label), `internal/broker/revoke_api.go` (the `revoke_others` forms go through the gate), `internal/decision/reasons.go` (the four reasons), `internal/daemon/metrics/metrics.go` (`port49_admin_touch_total`), `internal/mfatouch/mfatouch.go` (`PostRequest`)

**Interfaces:**
- Produces:
  - in `api`: `const AdminExporterLabel = "EXPORTER-port49-admin"`; `const AdminProofHeader = "Port49-Admin-Proof"`; `func AdminRequestSHA256(method, path string, body []byte) [32]byte`; `func AdminMessage(challenge []byte, request [32]byte, ekm []byte) []byte`; `type AdminChallenge struct{ Operation, Target, Challenge string; ExpiresAt time.Time }` (JSON `operation`, `target`, `challenge`, `expires_at`); `type AdminProof struct{ Challenge, Signature string; Attestation []string }`.
  - in `broker`: `func (b *Broker) adminGate(w http.ResponseWriter, r *http.Request, body []byte, op, target string) bool`. It returns true only when a proof for this exact request verified and was taken. Otherwise it has written the 401 or 503 and the `admin_touch` record.
  - `func (b *Broker) verifyTouchMessage(r *http.Request, p *touchProof, label string, msg func(ekm []byte) []byte, now time.Time) string`. `verifyTouch` becomes a call to it with the per-login label and `api.MFAMessage`.
  - in `mfatouch`: `func PostRequest(ctx context.Context, do func(*http.Request) (*http.Response, error), req *http.Request, body, ekm []byte, state func(net.Conn) (tls.ConnectionState, bool)) (*http.Response, error)`, which carries the caller's method, URL and headers under `Post`'s connection rule. `Post` becomes a call to it, so its callers (`internal/agent/agent.go:1321`, `internal/workload/client.go:481`) are unchanged.

- [ ] **Step 1: Write the failing tests** in `adminproof_test.go`. Use `testpki.NewPIV` for the attestations and a software signer for the touch slot with policy `always`:
  - `TestAnAdminCallWithNoProofGetsAChallenge`: `POST /v1/tokens/revoke {"principal":"user:bob@example.com"}` under `revoke_others` is answered 401 `admin_touch_required`, with `operation: revoke_principal` and `target: user:bob@example.com`. No mark is written.
  - `TestAProvedAdminCallRuns`: the retry with the proof revokes. The records are `admin_touch` `admin_touch_proved`, then `revoke`.
  - `TestAProofIsBoundToItsRequest`: a proof made for bob, sent with a body naming carol, is refused `admin_touch_refused`, and carol is not revoked. The same holds for a lift path given a revoke's proof.
  - `TestAProofIsSpentOnce`: the same proved request sent twice. The second is `admin_touch_refused`.
  - `TestAProofIsBoundToItsConnection`: a challenge taken on one connection, proved and sent on another. Refused.
  - `TestAPerLoginProofIsNotAnAdminProof`: a signature over `api.MFAMessage` for the same challenge is refused.
  - `TestABearerCannotProve`: a request with no client certificate gets no challenge. It is refused 401 `admin_touch_refused`, and the record says why.
  - `TestNoRootsMeansUnavailable`: with no roots, 503 `admin_touch_unavailable`. The start warning of §12 is said once.
  - `TestARefusedProofTakesNoSlot`: while a refused proof is judged, a concurrent principal revocation takes the slot at once.
  - `TestMineNeedsNoTouch`: `{"mine": true}`, and `{"principal": <the caller's own>}`, are answered as today, with no challenge.
  - `TestARightlessCallerGetsNoChallenge`: on `/v1/tokens/revoke`, each other-principal form (principal, certificate, key, `sid`) without `revoke_others` is 403 `api_right_missing` with no challenge issued.
  - `TestTheRecordHoldsNoProofMaterial`: no `admin_touch` record contains the challenge, the signature or an attestation's base64. Assert this before printing any record.

- [ ] **Step 2: Run them and see them fail.** Run `go test ./internal/broker/ -run 'Admin|Proof|Bearer|NoRoots|Mine|RefusedProof|TheRecordHolds' -count=1`. Expected: FAIL (undefined).

- [ ] **Step 3: Implement.**
  - The challenge store is a map under one mutex, keyed as §5.1.6 says. It holds at most one entry per connection: the connection's exporter value is in the key, and the map drops an entry by its connection's close and by expiry. The close hook chains into the server's existing `ConnState`, `closeIdleWithoutCertificate` (`internal/broker/server.go:148`), and never replaces it (A-M2).
  - `tokensRevoke` reads the body once. In every form, the `sid` form included, the right check (`mayOthers`, `revoke_api.go:107`) comes first and `adminGate` second, both before `acquireRevoke`. `mine`, and a `principal` equal to the caller's (the self-revocation at `revoke_api.go:160`), get no gate and no touch.
  - The 401 and 503 bodies use `api.Error` with the §5.7 reason as `error`.

- [ ] **Step 4: Run them and see them pass.** Also run the existing `mfa_test.go` and `revoke_api_test.go` (PASS: `verifyTouch` is unchanged for per-login), then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/broker internal/decision internal/daemon/metrics internal/mfatouch
  git commit -m "feat: an admin-level call proves a touch bound to its own request"
  ```

---

### Task 3c: The admin endpoints and their rights

**Files:**
- Modify: `internal/policy/load.go` (the five rights; `apiRights`), `internal/policy/lint.go` (admin-level rights named in the `api_rights` finding), `internal/broker/broker.go` (routes), `internal/broker/revoke_api.go` (a certificate body), `internal/broker/api/` (request and response types)
- Create: `internal/broker/admin_api.go`, `internal/broker/admin_api_test.go`

**Interfaces:**
- Consumes: Task 3b's `adminGate`; the existing `Revoke`, `Lift`, `Forget`, `ResetSecondFactor`, `UnlockSignIn` and `ImportEnrollments`, with origin `api <caller>`.
- Produces:
  - `policy.RightLiftRevocations = "lift_revocations"`, `RightForgetPrincipals = "forget_principals"`, `RightResetSecondFactor = "reset_second_factor"`, `RightUnlockSignIn = "unlock_sign_in"`, `RightImportEnrollments = "import_enrollments"`;
  - the routes:
    - `POST /v1/tokens/revoke` gains `{"cert_issuer", "cert_serial"}`;
    - `POST /v1/revocations/lift` takes `{"principal"}` or `{"cert_issuer", "cert_serial"}`;
    - `GET /v1/revocations` returns `api.RevocationList`, whose marks are those `--list` prints, with the same fields;
    - `POST /v1/directory/forget` takes `{"principal"}`;
    - `POST /v1/directory/reset-second-factor` takes `{"principal"}` or `{"all": true}`;
    - `POST /v1/directory/unlock` takes `{"principal"}`;
    - `POST /v1/directory/import?replace=true|false` takes the sealed export as its body, at most 16 MiB. The route sets its own read deadline of 120 s (`http.ResponseController.SetReadDeadline`), since the server's 30 s `readTimeout` (`server.go:291`) would bound a 16 MiB body to about 4.5 Mbit/s (A-M7).

- [ ] **Step 1: Write the failing tests.**
  - `TestEachAdminRouteNeedsItsRight`: table-driven over the six write routes. Without the right, 403 `api_right_missing`, recorded, and no challenge is issued: the right is checked before the gate, so a caller without it never blinks.
  - `TestEachAdminRouteNeedsATouch`: with the right and no proof, 401 `admin_touch_required`, with the operation and target of §5.1.6.
  - `TestTheListNeedsARightAndNoTouch`: `GET /v1/revocations` under `revoke_others` or `lift_revocations` answers 200. With neither, 403.
  - `TestALiftIsNotARevokeRight`: `revoke_others` alone cannot lift (403).
  - `TestAnUnknownRightStillFailsLoad`: `api: [lift_revocation]` (misspelt) is a load error naming the list.
  - `TestImportIsBounded`: a 17 MiB body is answered 413, with no challenge issued.

- [ ] **Step 2: Run them and see them fail.** Run `go test ./internal/broker/ ./internal/policy/ -run 'AdminRoute|TheList|ALift|UnknownRight|ImportIsBounded' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.** The order on each handler is: right, body bound, `adminGate`, then the operation (and the revocation slot for revoke and lift). The responses carry the same text the socket printed (`text` in the JSON), so the CLI prints them unchanged.

- [ ] **Step 4: Run them and see them pass.** Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/policy internal/broker
  git commit -m "feat: admin endpoints for lift, list, certificates, forget, second-factor reset, unlock and import"
  ```

---

### Task 3d: The agent and the CLI make admin calls

**Files:**
- Modify: `internal/agent/agent.go` (`POST /admin` on the agent's socket; `func (a *Agent) Admin(ctx context.Context, req AdminRequest) (AdminResponse, error)`), `cmd/port49/revoke.go`, `cmd/port49/directory.go`, `cmd/port49/main.go` (usage)
- Create: `internal/agent/admin_test.go`, `cmd/port49/admin_test.go`

**Interfaces:**
- Consumes: `api.AdminChallenge`, `api.AdminProof`, `api.AdminMessage`, `api.AdminRequestSHA256` and `mfatouch.PostRequest` (Task 3b); the routes of Task 3c.
- Produces:
  - `agent.AdminRequest{Method, Path string; Body []byte}`. The agent refuses any path not in its allowlist: the seven routes of Task 3c, and `/v1/tokens/revoke` other than `mine`.
  - `agent.AdminResponse{Status int; Body []byte}`.

- [ ] **Step 1: Write the failing tests.**
  - In `internal/agent/admin_test.go`, against a test broker with `testpki.NewPIV` and a software touch signer:
    - `TestTheAgentTouchesOncePerCall`: two calls make two signatures, each over its own request.
    - `TestAnUnusableTouchKeySendsNothing`: with `touchUnusable` set, `Admin` returns the reason, and the broker saw no request.
    - `TestAChangedConnectionPostsNothing`: the connection is replaced between the challenge and the retry. The result is `ErrConnectionChanged`, and the broker recorded no `admin_touch_refused`.
    - `TestThePathIsAllowlisted`: `/v1/tokens` through `POST /admin` is refused by the agent.
  - In `cmd/port49/admin_test.go`:
    - `TestRevokeHasNoSocketFlag`: `port49 revoke --socket X`, `--agent-socket X` and `--via-agent` each exit 2 as unknown flags; the same for `port49 directory --socket X`;
    - `TestAChallengeForAnotherTargetIsRefused`: a test broker answers a challenge naming carol for a request naming bob. The agent refuses it, prints nothing to touch, and signs nothing;
    - `TestOneTouchAtATime`: a second `POST /admin` while one waits on the touch is refused `another touch is waiting on your key`;
    - `TestTheImportPromptShowsReplace`: `port49 directory import --replace` prints `touch your key to import_enrollments replace <12 hex>`;
    - `TestRevokePrintsTheTouchPrompt`: the prompt names the operation and the target before the touch.

- [ ] **Step 2: Run them and see them fail.** Run `go test ./internal/agent/ ./cmd/port49/ -run 'Admin|Touch|Socket|Allowlisted|ChangedConnection' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `port49 revoke` sends every form through the agent: the principal, the certificate (read from `--cert` as today), the key, the lift and the list. There is no socket flag (Task 3h); `--agent-socket` and `--via-agent` are removed.
  - The agent computes the operation, target and `request_sha256` from its own request, refuses a differing challenge, and holds one touch at a time under a mutex (§5.1.6, "Presence, not intent").
  - The agent sends admin calls on a client of their own, `a.adminClient`, with one connection (`MaxConnsPerHost: 1`), as `a.mfaClient` does, so the challenge, the exporter value and the retry are one connection's.
  - The y/N prompt for a principal stays, and is asked before the touch.
  - `port49 directory forget|reset-second-factor|unlock|import` go through the agent as well. `export` and `init-enrollments` are refused here, naming `port49-broker export-enrollments` and `port49-broker init-enrollments`.

- [ ] **Step 4: Run them and see them pass.** Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/agent cmd/port49
  git commit -m "feat: port49 revoke and port49 directory make admin calls through the agent with a touch"
  ```

---

### Task 3e: Remove the admin sockets; the offline and local subcommands

**Files:**
- Delete: `internal/daemon/admin/` (the package and its tests), `cmd/port49/store.go`'s socket path
- Modify:
  - `internal/config/config.go`: `admin_socket` refused by name in both files, and the "etcd requires admin_socket" rule deleted;
  - `internal/port49d/main.go`, `brokerd.go`, `revocations.go`, `offline.go`: remove the socket; add `port49d revoke --offline`, `--list` on both offline commands, and `init-enrollments` and `export-enrollments` on both binaries;
  - `internal/port49d/storestatus.go` and the metrics listener's mux: `GET /store/status`;
  - `cmd/port49/store.go`: `--metrics ADDR` (an address, not a socket);
  - `deploy/compose/config/port49d.yaml` and `port49-broker.yaml`: the `admin_socket` lines deleted;
  - every test fixture and lab config that sets `admin_socket`: grep the whole tree, `tests/lab/` included, and change each;
  - every caller that drives the socket from the CLI (A-I3, A-M8): `tests/lab/revoke_test.go:97` (`revokeCLI`) and its callers in `api_revoke_test.go`, `l69_test.go:498`, `l74_test.go`, `l75_test.go`, `split_test.go` and `compose_test.go`, and `tests/compose/smoke_test.go`. Each becomes an API admin call through a lab helper with a software touch signer and `testpki.NewPIV` roots, or `revoke --offline` where a closed row measured the mark itself. `tests/compose/smoke_test.go`'s revoke step becomes the offline form here, so the compose workflow is green between this task and Task 6;
  - `internal/agent/agent.go:175` (`revokeWait`): `admin.OpTimeout` and `admin.PersistTimeout` move to `internal/broker/api` before the package is deleted (A-M3).
- Create: `internal/port49d/offline_port49d_test.go`, `internal/port49d/enrollcmd_test.go`, `internal/config/adminsocket_test.go`

**Interfaces:**
- Produces:
  - `port49d revoke --offline [--config FILE] (--principal P | --cert-issuer I --cert-serial S) [--lift] | --list`;
  - `port49-broker revoke --offline … --list`;
  - `port49-broker|port49d init-enrollments [--config FILE]`;
  - `port49-broker|port49d export-enrollments [--config FILE]`;
  - `GET /store/status` (text/plain, the lines §12 shows; 503 when a store does not answer, 429 while one runs).

- [ ] **Step 1: Write the failing tests.**
  - `TestAdminSocketIsRefusedByName`: in each file, the load error is the §12 text.
  - `TestOfflineRevokeOnPort49d`: a combined port49d config on the memory store with a `revocations_file`. `port49d revoke --offline --principal user:bob@example.com` writes the mark. A start then refuses bob's mint with `credential_revoked`. `--lift` removes the mark, and `--list` names it while it stands.
  - `TestOfflineListOnTheBroker`: over the etcd test cluster (`storetest`'s), `--list` prints each mark with its origin.
  - `TestInitAndExportEnrollments`: init once (exit 0), and a second time (exit 1, "already"). Export to a pipe gives sealed bytes that `ImportEnrollments` accepts. Export to a terminal is refused.
  - `TestStoreStatusOnTheMetricsListener`: the body matches the socket's former text; a second concurrent request gets 429; the body holds no `https://`, no `http://`, no `:2379`, no `-----BEGIN`, no `user:`, `app:` or `spiffe://`, and no `rv/`. Every reason line is one of `outageCause`'s fixed words (`not opened yet`, `permission denied`, `timed out`, `unreachable`), never an error's text.
  - `TestNoAdminSocketRemains`: no file under `internal/` or `cmd/` imports `internal/daemon/admin`, and no config under `deploy/` or `tests/` holds `admin_socket:`. This is a tree walk. (Task 3h's `TestNoSocketFlagAnywhere` covers `--socket`.)

- [ ] **Step 2: Run them and see them fail.** Run `go test ./internal/config/ ./internal/port49d/ -run 'AdminSocket|Offline|Enrollments|StoreStatus|NoAdminSocket' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.** Delete the socket and its wiring. The offline port49d command reuses `offline.go`'s flow with port49d's config and its broker block. It refuses when port49d answers on its metrics listener (`/readyz`), the same "with every broker down" rule, and refuses a port49d with no broker block, naming `port49-broker revoke --offline`.

- [ ] **Step 4: Run them and see them pass.** Then `make test && make vet`, and `make check-darwin` (the deleted `peer_other.go` was the darwin build's).

- [ ] **Step 5: Commit.**

  ```bash
  git add -A internal cmd deploy/compose/config tests
  git commit -m "feat: remove the admin sockets; offline revoke on port49d, offline list, local enrollment init and export, store status on the metrics port"
  ```

---

### Task 3f: `port49d keys-diagnose` from a capture

**Files:**
- Create: `internal/port49d/keysdiagnose.go`, `internal/port49d/keysdiagnose_test.go`, `internal/port49d/pcap.go` (the classic pcap reader: the global header, the record headers, Ethernet, IPv4 or IPv6, and TCP to port 49; no new module)
- Modify: `internal/port49d/main.go` (the subcommand), `internal/daemon/server/server.go:54` (the `Held` field removed) and `conn.go:80` (`conn.unvalidated` keeps its record and metric and drops only the bytes), `cmd/port49/keys.go` (`keys diagnose` refused, naming `port49d keys-diagnose`)

**Interfaces:**
- Produces: `port49d keys-diagnose --device <name> --capture <file|-> [--config FILE]`; `-` reads standard input. It exits 0 when a key validates, 1 when none does or the capture holds no packet from the device, and 2 on usage.

- [ ] **Step 1: Write the failing tests.** Generate captures at test time with a `devicemock` login written as pcap records, in `t.TempDir()`. Never put a capture under `tests/lab/`, and agents never run `keys-diagnose` on a lab capture: the no-decode rule applies to agents even though the tool prints nothing (A-M9).
  - `TestDiagnoseNamesTheMatchingGroup`: a packet under a retired version of another group. The output is `group <g> version <n> validates this packet` and nothing else.
  - `TestDiagnoseNamesNone`: a packet under an unknown key gives `no key port49d holds validates this packet`.
  - `TestDiagnosePrintsNoPacketByte`: the output holds no byte of the packet in hex or base64, and no key. Assert this before printing it.
  - `TestDiagnoseRefusesAPcapng`: a pcapng file is refused, naming `tcpdump -w`'s classic format.
  - `TestNoUnvalidatedPacketIsHeld`: `server.Server` no longer has a `Held` field (by reflection over the struct), and an unvalidated packet still writes its `unvalidated` record and counts its metric.
  - `TestDiagnoseReadsStandardInput`: `--capture -` with the capture piped in gives the same output as the file.

- [ ] **Step 2–4:** Run them and see them fail; implement; run them and see them pass. Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/port49d cmd/port49/keys.go
  git commit -m "feat: keys-diagnose reads a capture offline; port49d holds no unvalidated packet"
  ```

---

### Task 3h: No socket flag on any command

Ryan's rule (2026-10-27): no user ever types or knows a socket path. Run this after 3f and before 3g. 3g needs Ryan present and may wait, so 3h does not wait for it.

**Files:**
- Modify:
  - `internal/agent/socket.go`: `SocketPath()` returns `$PORT49_TEST_AGENT_SOCKET` when it is set, and otherwise the per-user default as today;
  - every `fs.String("socket", …)` in `cmd/port49/` (`refresh.go`, `identity.go`, `ssh.go`, `policy.go`, `main.go`'s login and token, `revoke.go`, `directory.go`, `keys.go`, `store.go`), each deleted;
  - the usage text in `cmd/port49/main.go`;
  - `clients/python/src/port49/client.py` (the `socket=` argument removed) and `clients/python/tests/test_agent.py`;
  - `clients/ansible/ansible_collections/port49/client/plugins/lookup/token.py` (the `socket` option removed) and its tests;
  - `sessionFlags.args()` (`cmd/port49/main.go:410`), which passes `--socket` to the hidden `agent` child; without this, `login` breaks;
  - the two error lines that name the flag: `cmd/port49/issue.go:104` becomes `port49 login: <other> already holds the agent; run 'port49 refresh' to extend that session, or stop that agent first`, and `cmd/port49/ssh.go:741` becomes `the askpass socket directory <dir> is too long for a Unix socket; set XDG_RUNTIME_DIR to a shorter directory`;
  - `deploy/compose/README.md:118`: delete the `--socket /run/port49/port49-broker.sock` instruction, and say in ruling 5's words that admin calls go through the agent (Task 6 rewrites the section later);
  - the cmd/port49 tests that pass the flag: `api_linux`, `broker_ca_fd_linux`, `config`, `directory_linux`, `issue_login_linux`, `keys_diagnose_linux`, `main`, `mfa_fallback`, `mfa`, `revoke_linux`, `signin_login_linux`, `ssh`, `store_linux`, `token_json` and `token_retry` (`_test.go` each), and `internal/agent/mfa_touch_test.go`;
  - every test that passes `--socket` to `port49`: `internal/agent/agent_test.go`, `internal/port49d/daemon_test.go`, `offline_test.go`, `tests/compose/smoke_test.go`, and in `tests/lab/` `l56`, `l67`, `slice`, `l78`, `qualify`, `l75`, `directory_e2e`, `l29`, `l64_l65`, `projection`, `l74`, `session`, `revoke`, `compose` and `l60/*`. Each sets `PORT49_TEST_AGENT_SOCKET` in the child's environment instead. In `tests/lab/runbooks/L62-ser8.md:352` and `:358`, the second, foreign agent's commands drop the flag and take a `PORT49_TEST_AGENT_SOCKET=/tmp/l62-foreign.sock` prefix, so the two agents stay apart. A lab runbook is not an operator page, so naming the variable there keeps the rule. Captures under `tests/lab/captures/` are records, so they are left unchanged.
- Create: `cmd/port49/nosocket_test.go`

**Interfaces:**
- Produces: `PORT49_TEST_AGENT_SOCKET`, read only by `agent.SocketPath()`, documented only in its Go comment. It is never in the spec or on the docs site.

- [ ] **Step 1: Write the failing tests** in `cmd/port49/nosocket_test.go`:
  - `TestNoCommandTakesASocket`: for each subcommand, `--socket X` and `--agent-socket X` exit 2 as unknown flags.
  - `TestNoHelpNamesASocket`: the usage text and each subcommand's `-h` output contain no `socket` and no `PORT49_TEST_AGENT_SOCKET`.
  - `TestTheTestVariableMovesTheAgent`: with the variable set to a temp path, `port49 identity` reaches a test agent there.
  - `TestNoSocketFlagAnywhere`: a tree walk. No file under `cmd/`, `internal/`, `tests/`, `clients/`, `deploy/` or `examples/` holds `"--socket"`, `--socket ` or `--agent-socket`. Three exemptions, each by name and no other: `cmd/port49/nosocket_test.go` and `cmd/port49/admin_test.go`, which must pass the flag to see it refused, and `tests/lab/captures/`, which are records. No file under `deploy/`, `examples/`, `docs/` or `clients/` other than tests, and no `README.md` anywhere, names `PORT49_TEST_AGENT_SOCKET`. The one exemption is `tests/lab/runbooks/`, which are lab-only and may name it.
  - `TestNoErrorNamesASocketFlag`: the login refusal for a second agent and the long-askpass-path error hold no `--socket`.
  - In Python: `test_agent.py` asserts the argv holds no `--socket`. Keep `test_agent.py:279`, which passes `"--socket=/tmp/x"` as a device name after `--`: it guards argument injection, and the walk's patterns do not match it. `Agent(socket=…)` raises `TypeError`.

- [ ] **Step 2: Run them and see them fail.** Run `go test ./cmd/port49/ -run 'Socket|TestVariable|NoHelp' -count=1` and `make python-test` (or the `python.yml` command). Expected: FAIL.

- [ ] **Step 3: Implement.** Delete each flag. The lab and test callers set the variable. Run `go vet -tags lab ./tests/lab/...` (compile only) to catch every lab caller.

- [ ] **Step 4: Run them and see them pass.** Then `make test && make vet`, the Python and collection tests, and `go vet -tags lab ./tests/lab/...`.

- [ ] **Step 5: Commit.**

  ```bash
  git add internal/agent cmd/port49 clients tests internal/port49d
  git commit -m "feat: no socket flag on any command; the CLI finds its agent at the per-user default"
  ```

---

### Task 3g: Lab L86: an admin touch on a real YubiKey

Needs Ryan present with a YubiKey 5 on the SER8. It runs on the lab host under the lab lock, with the stall watchdog. Agents never run `ykman`, `tpm2_*` or `pkcs11-tool`: Ryan provisions the slots, and the harness uses only `port49`.

**Files:**
- Create: `tests/lab/l86_admin_touch.go` (`//go:build lab`), `tests/lab/results/L86-ser8.md`
- Modify: spec §15 row L86's Status, and §5.1.6's "provisional on L60" timing where L86 measures it

- [ ] **Step 1: Run the four cells of row L86** against a broker on the SER8 with Yubico's PIV roots in `attestation_roots_file`. Record each cell's PASS or FAIL, with the firmware and libykcs11 version.
- [ ] **Step 2: Write `L86-ser8.md`**, close or update the row by CLAUDE.md's rule, and fix any doc a FAIL contradicts, citing the note.
- [ ] **Step 3: Commit** `docs: close lab register entries L86 ...`, or `docs: lab register L86 partial ...` if a cell waits on a second token.

---

### Task 4: CI: `make test` and `make vet` on GitHub-hosted runners

**Files:**
- Create:
  - `tests/ci/testshard/testshard.go` and `testshard_test.go`;
  - `tests/ci/cmd/testshard/main.go`;
  - `tests/ci/cmd/mustpass/main.go` and `main_test.go`;
  - `tests/ci/versions/versions.go` and `versions_test.go`;
  - `tests/ci/cmd/versioncheck/main.go`;
  - `.github/workflows/test.yml`.
- Modify: `Makefile` (`test`, new `test-rest`, `test-shard`, `test-root`); `.github/workflows/compose.yml` (its stale first comment).

**Interfaces:**
- Produces:
  - `testshard.Partition(names []string, i, n int) ([]string, error)`. It sorts the names and keeps those at index `k` with `k % n == i-1`. It refuses `n < 1`, and `i` outside `1..n`.
  - `testshard.Regex(names []string) (string, error)`, which returns `^(A|B)$`. An empty list is an error, never `^$`.
  - `testshard` CLI: `-pkg ./internal/port49d -shard i/n` prints the regex. It runs `go test -list . <pkg>` and keeps names starting `Test`, `Fuzz` or `Example`. It exits non-zero, naming why, when `go test -list` fails, lists nothing, or the shard is empty.
  - `testshard -pkg P -check -n N` exits non-zero unless the union of shards 1..N is exactly the list.
  - `mustpass` CLI: `-tests A,B` reads `go test -json` on stdin. It exits 1 unless every named test has an `Action:"pass"` event, and it names each test that skipped, failed or never ran.
  - `versions.Read(root string) (Versions, error)`, with `Versions{PyPI, Galaxy, Chart, ChartApp string}`.
    - `Chart` is read from `deploy/helm/port49/Chart.yaml`. Until Task 10 creates that file, it is optional and read as absent.
    - Task 10 makes it required, removing the optional path outright (no deprecation before beta).
  - `versions.Check(v Versions, tag string) []string`. Its findings:
    - with an empty tag, every value present must agree;
    - with a tag, every value must be present and equal the tag with its `v` stripped.
    - PyPI's value is compared after PEP 440 normalisation, so `v0.1.0-rc1` matches pyproject's `0.1.0rc1` while Galaxy and the chart keep `0.1.0-rc1`.
  - `versioncheck` CLI: `[-tag vX.Y.Z]`.

- [ ] **Step 1: Write the failing tests.**

  - `TestShardsPartitionTheList`: for `n` in 1..5 over 17 names, the union of the shards is the list and no name appears twice.
  - `TestABadShardIsRefused`: `0/2`, `3/2` and `x` are refused.
  - `TestTheRegexIsAnchored`.
  - `TestMustpassFailsASkip`: a JSON stream with `{"Action":"skip","Test":"A"}` exits 1 and names A.
  - `TestMustpassFailsAMissingTest`.
  - `TestMustpassPassesWhenAllPass`.
  - `TestVersionsDisagreeingIsAFinding`.
  - `TestATagMustEqualEveryVersion`: `v0.1.0` against `0.1.0` everywhere passes; against `0.2.0` it gives four findings, each naming its file.
  - `TestAPreReleaseTagIsNormalisedForPyPI`: `v0.1.0-rc1` with pyproject `0.1.0rc1` and the others `0.1.0-rc1` passes.
  - `TestAnEmptyShardIsAnError`, and `TestCheckFindsAMissingName`.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `go test ./tests/ci/... -count=1`. Expected: FAIL to compile.

- [ ] **Step 3: Implement the three packages and the three commands.**

- [ ] **Step 4: Change the Makefile.**

  - `test` keeps `lab-unit test-python` and runs `go test ./... -count=1 -timeout 30m`. Update the comment: `internal/port49d` took about 943 s against 20m (12a).
  - `test-rest`: `lab-unit test-python`, then `go test $$(go list ./... | grep -vx 'github.com/rhwendt/port49/internal/port49d') -count=1 -timeout 30m`.
  - `test-shard`:

    ```make
    @test -n "$(SHARD)" || { echo "usage: make test-shard SHARD=i/n"; exit 2; }
    @re=$$(go run ./tests/ci/cmd/testshard -pkg ./internal/port49d -shard $(SHARD)) || exit 1; \
      go test ./internal/port49d/ -count=1 -timeout 30m -run "$$re"
    ```

  - `test-rest` also runs `go test -json ./internal/fence/ -run '^TestAnACLGrantingWriteIsRefused$$' -count=1 | go run ./tests/ci/cmd/mustpass -tests TestAnACLGrantingWriteIsRefused`, so a skip ("setfacl is not installed", or a filesystem with no ACL) fails CI.
  - `vet` gains `go vet -tags systemd,helm,kind,image,packages ./tests/...` and `go vet -tags lab ./tests/lab/`, so the new tagged files are vetted.

  - `ROOT_TESTS = TestAKeyFileTheBrokerDidNotWriteIsRefused` (`internal/port49d/identity_linux_test.go:165`). `TestAnotherUIDIsRefused` went with `internal/daemon/admin/` in Task 3e (amendment pre-flight A-I1).
  - `test-root` refuses unless `id -u` is 0, then runs:

    ```make
    go test -json ./internal/port49d/ -run '^(TestAKeyFileTheBrokerDidNotWriteIsRefused)$$' -count=1 | go run ./tests/ci/cmd/mustpass -tests $(ROOT_TESTS)
    ```

  - Add each new target to `.PHONY`.

- [ ] **Step 5: Write `.github/workflows/test.yml`.**

  - Triggers: `push` to `main` and `pull_request`. Permissions: `contents: read`.
  - Every job: `ubuntu-24.04`, `actions/checkout` and `actions/setup-go` pinned by SHA (`go-version-file: go.mod`), `timeout-minutes: 30`.
  - The jobs:
    - `vet`: `make vet` and `make check-static`.
    - `rest`: `sudo apt-get install -y acl`, `actions/setup-python` (3.12), then `make test-rest`.
    - `port49d`: a matrix over `shard: [1/3, 2/3, 3/3]`, running `make test-shard SHARD=${{ matrix.shard }}`.
    - `shards`: `go run ./tests/ci/cmd/testshard -pkg ./internal/port49d -check -n 3`.
    - `root`: `sudo apt-get install -y acl`, then `sudo -E env "PATH=$PATH" make test-root`.
    - `versions`: `go run ./tests/ci/cmd/versioncheck`.
  - In `compose.yml`, replace "The repository's only workflow: `make test` needs the lab's captures…" with "The container shape's smoke; test.yml runs `make test` and `make vet`." The labpcap evidence test skips without captures (`tests/lab/labpcap/evidence_test.go:49`).

- [ ] **Step 6: Verify.**

  - Run `go test ./tests/ci/... -count=1` (PASS), `make test-shard SHARD=1/3` (PASS), and `sudo -E env "PATH=$PATH" make test-root` (PASS, with the test passing and no skip), then `make test && make vet`.
  - Push the branch and read the `test` workflow's run with `gh run watch`. A test that fails only on the hosted runner is a finding: fix it test-first in this task. Never skip it by name.

- [ ] **Step 7: Commit.**

  ```bash
  git add tests/ci Makefile .github/workflows/test.yml .github/workflows/compose.yml
  git commit -m "ci: make test and make vet on hosted runners, port49d sharded, root-only tests run as root"
  ```

---

### Task 5: The image: multi-arch build and a layout check

**Files:**
- Modify: `Dockerfile` (build stage), `.dockerignore` (add `.claude/`, `.worktrees/` and `**/tests/lab/logs/`, so worktrees and their lab logs never enter the build context), `Makefile` (`image-check`), `.github/workflows/compose.yml` (a step)
- Create: `tests/image/image_test.go` (`//go:build image`)

**Interfaces:**
- Produces: `make image-check`, which builds `--target port49` and runs `go test -tags image ./tests/image/ -count=1 -v`.

- [ ] **Step 1: Write the failing test, `TestTheImageLayout`.**

  The test runs `docker create port49:dev`, streams `docker export` into `archive/tar`, and asserts:
  - every directory is owned by uid 0 or 65532, with no group or world write bit, unless it is sticky and owned by root (`/tmp`);
  - `/var/lib/port49-broker`, `/var/spool/port49d` and `/run/port49` are `65532:65532` and `0700`;
  - each of the four binaries is `0755`, owned by root, with no setuid or setgid bit and no `SCHILY.xattr.security.capability` PAX record;
  - the failure message names the path and its mode.

  Its comment states that an OpenShift-style `chmod g=u` rebuild fails here, and that the fence refuses it at start for the same reason.

- [ ] **Step 2: Make the build stage cross-compile.**

  - `FROM --platform=$BUILDPLATFORM golang:1.26 AS build`, with `ARG TARGETOS TARGETARCH`.
  - Build with `GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build …`. Nothing else changes.

- [ ] **Step 3: Verify.**

  - Run `make image-check`. Expected: PASS.
  - Run `docker buildx build --platform linux/arm64 --target port49 .`. Expected: builds.
  - Then `make test && make vet`.

- [ ] **Step 4: Wire it into CI.**

  Add `- run: make image-check` before `make compose-smoke` in `compose.yml`.

- [ ] **Step 5: Commit.**

  ```bash
  git add Dockerfile .dockerignore Makefile tests/image .github/workflows/compose.yml
  git commit -m "feat: a multi-arch image build and a check of the image's directory and binary modes"
  ```

---

### Task 6: Shared smoke helpers; compose secrets as files, rotation and the floor

**Files:**
- Create: `tests/shapes/shapetest/shapetest.go`, a plain package with no build tag, imported only by tagged tests.
- Modify:
  - `tests/compose/client_test.go` and `smoke_test.go`, which now import `shapetest`;
  - `internal/testpki/compose.go` and `internal/testpki/compose_test.go`. The test now asserts `keys/tacacs_v1` (0600) and the two `secrets/*.key` files (0600), and no `*.env` file.
  - `deploy/compose/setup.sh`, `compose.yaml` (also its header comment, "the PKI and the env files"), `config/port49d.yaml`, `config/port49-broker.yaml`, `config/policy.yaml` and `README.md`;
  - `.gitignore`, whose line for the compose env files now names `deploy/compose/local/`.

**Interfaces:**
- Produces, in `shapetest`:
  - `type Device struct{ T *testing.T; Addr string; Key []byte }`, with `Login(user, password string) uint8` and `Permits(user string, words ...string) bool`, moved from `tests/compose/client_test.go`;
  - `Mint(t *testing.T, brokerDir, brokerAddr, device string) string`;
  - `Ready(t *testing.T, metricsAddr string)`;
  - `WaitFor(t *testing.T, what string, within time.Duration, ok func() bool)`;
  - `FloorLine(t *testing.T, log string, members []string)`, which fails unless one line matches `etcd .*, at or above the floor` and names every member URL;
  - `Gauge(t *testing.T, metricsAddr, name string) float64`, which reads one unlabelled metric;
  - `AdminSetup(t *testing.T, dir string) (rootsFile string, policySubject string)`: writes a `testpki.NewPIV` root as the file `attestation_roots_file` names, and a generated operator certificate whose principal the returned policy fragment grants `api: [revoke_others]`. Every smoke (compose here, systemd in Task 9, kind in Task 11) calls it and renders both into its broker config and policy, so the admin cell answers 401, not 503 `admin_touch_unavailable` or 403 (A-I2);
  - `AdminNeedsTouch(t *testing.T, brokerDir, brokerAddr, principal string)`: with `AdminSetup`'s operator certificate under `revoke_others`, `POST /v1/tokens/revoke` naming `principal` is answered 401 `admin_touch_required` with a challenge, and a mint by `principal` still succeeds afterwards (ruling 5; Task 3b);
  - `OfflineRevoked(t *testing.T, brokerDir, brokerAddr, principal string)`: a mint by `principal` is refused `credential_revoked`;
  - `RotateCell(t *testing.T, d Device, user string, mint func() string, metricsAddr string, within time.Duration, r Rotator)`, with:

    ```go
    type Rotator interface {
        KeyDir() string                            // file_dir as port49d sees it: /run/port49/keys or /etc/port49/keys
        BasePolicy() []byte                        // the policy in force, keys.k at version 1 only
        WritePolicy(policyYAML []byte) error       // atomically, as the shape's operator would
        WriteKey(name string, secret []byte) error // into the key directory, root:<port49d gid> 0440
        StartedAt() string                         // the process's start identity, unchanged across a reload
    }
    ```

    The cell runs in this order:
    1. It writes `BasePolicy()` with version 2 added to `keys.k.accept` (`{version: 2, secret_ref: file:<KeyDir>/tacacs_v2}`), while that file is absent. The key set's schema is `current`, `accept` and `retired`.
    2. It asserts a login with a `Device` keyed v2 fails, and one keyed with `d.Key` (v1) still passes.
    3. It writes `tacacs_v2`, a fresh `testpki` random secret.
    4. It waits up to `within` for a v2 login to pass.
    5. It asserts `StartedAt` is unchanged, and `port49_key_secret_files_changed` reads 0 (no file was rewritten).

    Compose and systemd pass `within` = 90 s; Kubernetes passes 180 s.
- `testpki.WriteCompose` now writes `keys/tacacs_v1`, `secrets/port49d-encryption.key` and `secrets/broker-encryption.key` in place of the two env files. The device key is `secret(32)`.

- [ ] **Step 1: Write the failing test.**

  - In `TestComposeSmoke`:
    - after the first login, call `shapetest.FloorLine` on `docker compose logs port49d` with the three member URLs;
    - after the recreate, call `RotateCell`, with a `composeRotator` that writes through `docker run --rm -v port49_port49d-keys:/k -v port49_port49d-etc:/e -v port49_broker-etc:/b port49-setup:dev`, and reads `StartedAt` from `docker inspect -f '{{.State.StartedAt}}'` of port49d. `WritePolicy` writes the policy into both `-etc` volumes, since the broker reads the key names from it, each by a temporary file and `mv`.
  - After `RotateCell`, the admin cells (ruling 5), with `AdminSetup`'s roots and subject in the broker config and policy: `AdminNeedsTouch` for `user:bob@example.com`; then `docker compose stop port49-broker`, `docker compose run --rm --no-deps port49-broker revoke --offline --principal user:bob@example.com` (exit 0), `docker compose start port49-broker`, and `OfflineRevoked`; then the same with `--lift`, and bob mints again.
  - Add `TestTheStackHasNoEnvSecret`: `docker inspect` of each running container shows no `PORT49_KEY_` or `PORT49_ENC` variable. On a failure it prints the variable *names* only, never a value.

- [ ] **Step 2: Run the test and see it fail.**

  Run `make compose-smoke`. Expected: FAIL, since the env files are still used.

- [ ] **Step 3: Change the compose stack.**

  - **Configs:**
    - `port49d.yaml` sets `encryption.current.secret_ref: file:/etc/port49/secrets/encryption.key`.
    - `port49-broker.yaml` sets the same.
    - `policy.yaml` sets `keys.k.current: {version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}`.
  - **`setup.sh`** writes:
    - the keys volume: `install -d -o 0 -g 65532 -m 0750 /vol/port49d-keys`, then each `keys/*` file `-o 0 -g 65532 -m 0440`;
    - the `secrets/` directory into each `-etc` volume, `0755 root`, holding the key `65532 0400`.
  - **`compose.yaml`:**
    - drops both `env_file:` entries;
    - mounts `port49d-keys:/run/port49/keys:ro` in port49d and `/vol/port49d-keys` in setup;
    - declares the volume.
  - **README:**
    - "The files" table gains `port49d-keys`.
    - The `docker inspect` paragraph becomes: no secret is in any container's environment, and a key version is added by writing a new file into `port49d-keys` and the policy, with no restart (Task 6's cell).
    - Add a section on the issuing CA for a second broker service: `docker run --rm -v port49_broker-state:/a -v port49_broker2-state:/b alpine:3.22 sh -c 'install -o 65532 -g 65532 -m 0600 /a/issuing-ca.key /b/ && install -o 65532 -g 65532 -m 0644 /a/issuing-ca.pem /b/'`, after `docker compose exec port49-broker port49-broker init-issuer`.
    - Add a pointer to `deploy/examples/stores/` (Task 7).
    - Replace every `docker compose exec … port49 revoke` and `port49 directory` instruction with ruling 5's: admin calls from the workstation through the agent with a key press, the compose break-glass, and Task 3a's 3am table. `init-enrollments` and `export-enrollments` are `docker compose run --rm port49-broker <subcommand>`.
    - Note that the compose example lists all three member URLs, never a VIP.
    - Add the `encryption:` rotation runbook (ruling 13) and the "When it will not start" table (ruling 13).

- [ ] **Step 4: Verify.**

  Run `make compose-smoke` (PASS), then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/shapes tests/compose internal/testpki/compose.go internal/testpki/compose_test.go deploy/compose .gitignore
  git commit -m "feat: compose reads its secrets from files, adds a key version without a restart, and asserts the etcd floor"
  ```

---

### Task 7: systemd units, configs and the shared store examples

**Files:**
- Create:
  - `deploy/systemd/port49d.service`, `port49-broker.service`;
  - `deploy/systemd/sysusers.d/port49.conf`, `tmpfiles.d/port49.conf`;
  - `deploy/systemd/config/{port49d.yaml,port49-broker.yaml,policy.yaml,inventory.yaml}`;
  - `deploy/systemd/examples/{etcd@.service,sysusers-etcd.conf,etcd-1.yaml,etcd-2.yaml,etcd-3.yaml,port49-etcd-snapshot.service,port49-etcd-snapshot.timer,port49-enrollments-export.service,port49-enrollments-export.timer}`;
  - `deploy/systemd/README.md`;
  - `deploy/examples/stores/single-site/{port49d.yaml,port49-broker.yaml}`, `multi-region/{port49d.yaml,port49-broker.yaml}` and `README.md`;
  - `tests/shapes/units_test.go` and `tests/shapes/examples_test.go`, untagged (they parse files only).

**Interfaces:**
- Produces: the unit files and configs the package (Task 8) installs and the smoke (Task 9) runs.

- [ ] **Step 1: Write the failing tests.**

  - `TestTheUnitsCarryTheirLimits`. It parses each `.service` as INI and asserts these exact values:

    | Key | port49d | port49-broker |
    |---|---|---|
    | `[Unit] StartLimitIntervalSec` | `300` | `300` |
    | `[Unit] StartLimitBurst` | `5` | `5` |
    | `[Service] Restart` | `on-failure` | `on-failure` |
    | `RestartSec` | `10s` | `10s` |
    | `LimitNOFILE` | `65536` | `65536` |
    | `User`/`Group` | `port49d` | `port49-broker` |
    | `ExecReload` | `/bin/kill -HUP $MAINPID` | same |
    | `UMask` | `0077` | `0077` |
    | `AmbientCapabilities` | `CAP_NET_BIND_SERVICE` | absent |
    | `RuntimeDirectory` | absent | absent |
    | `StateDirectory` / `Mode` | absent | `port49-broker` / `0700` |
    | `ProtectSystem` | `true` | `true` |
    | `NoNewPrivileges` | `yes` | `yes` |
    | `PrivateTmp` | `yes` | `yes` |
    | `ProtectHome` | `yes` | `yes` |
    | `CapabilityBoundingSet` | `CAP_NET_BIND_SERVICE` | empty (`CapabilityBoundingSet=`) |

    It also asserts there is none of:
    - `ProtectSystem=strict|full`;
    - `ReadOnlyPaths=`, `BindReadOnlyPaths=` or `InaccessiblePaths=`;
    - `ProtectHome=read-only`;
    - a `TemporaryFileSystem=` entry ending `:ro`;
    - an `ExecStartPre=` naming `init-revocations` or `init-enrollments` (A14, A16).
  - `TestTheSystemdConfigsLoad`. It follows the lab unit tests' pattern (`tests/lab/directory_e2e_unit_test.go:56`): `strings.ReplaceAll` each absolute root (`/etc/port49`, `/var/spool/port49d`, `/var/lib/port49-broker`) into `t.TempDir()`, and writes `testpki` PEMs and fixture secrets there at the fence's modes. Then it calls `config.Load` and `config.LoadBroker` and asserts:
    - `KeySecretRefs.FileDir` is the rewritten `/etc/port49/keys`;
    - neither file holds `admin_socket` (Task 3e refuses it);
    - the etcd endpoints are three member URLs;
    - `limits.max_connections` is unset (the default, sized from `LimitNOFILE`).
  - `TestTheTLSListenerIsCommentedOut`: the raw text holds a commented `# tls_listener:` block with `listen: ":300"`. Uncommented, it loads again.
  - `TestTheStoreExamplesLoad`: both example pairs load, by the same rewrite. `multi-region` has `stores.directory` with three member URLs, one per region, and `stores.session` with its own endpoints.
  - `TestNoExampleHoldsASecret`: no file under `deploy/` contains `-----BEGIN` followed by `PRIVATE KEY`, or a `secret_ref` that is not `env:PORT49_` or `file:`.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `go test ./tests/shapes/ -count=1`. Expected: FAIL (files absent).

- [ ] **Step 3: Write the files.**

  - **`sysusers.d`:** `u port49d - "port49 TACACS+ server"` and `u port49-broker - "port49 broker"`.
  - **`tmpfiles.d`:**
    - `d /etc/port49 0755 root root -`
    - `d /etc/port49/keys 0750 root port49d -`
    - `d /etc/port49/secrets 0755 root root -`
    - `d /var/spool/port49d 0700 port49d port49d -`
    - `d /var/backups/port49 0700 root root -`
  - **The etcd examples** are for etcd hosts, not port49 hosts:
    - `etcd@.service`: `ExecStart=/usr/local/bin/etcd --config-file /etc/etcd/%i.yaml`, `User=etcd`.
    - `examples/sysusers-etcd.conf` creates the `etcd` user.
    - `etcd-1.yaml`, `etcd-2.yaml` and `etcd-3.yaml` each set `auto-compaction-mode: periodic`, `auto-compaction-retention: "1h"` and `quota-backend-bytes: 8589934592`, with TLS and client-cert auth.
  - **Backup units:**
    - The snapshot unit is an etcd-host example, since it needs etcd root's certificate. Its `ExecStart=/bin/sh -c 'etcdctl snapshot save /var/backups/port49/etcd-$$(date +%%F).db'` runs under `UMask=0077`. systemd does no `$(…)` or redirection itself.
    - The export unit runs on a broker host as `User=port49-broker`, `ExecStart=/usr/bin/port49-broker export-enrollments` with `StandardOutput=file:/var/backups/port49/directory-export.json`, under `UMask=0077`.
    - The timers are `OnCalendar=hourly` and `daily`.
  - **README sections:**
    - install and `systemctl enable --now`;
    - where secrets live, and adding a key version;
    - `init-issuer` on one broker, then `install -o port49-broker -g port49-broker -m 0600` to the others;
    - `forget-issuer`;
    - admin calls from the operator's workstation through the agent, the security key press, the break-glass `port49-broker revoke --offline` with every broker stopped, and Task 3a's 3am table (ruling 5);
    - `attestation_roots_file` with Yubico's PIV roots, and at least two on-call admins named by `identity:`;
    - `init-revocations` once at install, never `ExecStartPre=`;
    - `port49-broker init-enrollments` once;
    - the directory keytab and `PORT49_SITE` through `systemctl edit port49-broker`;
    - the CRL file or `SSL_CERT_FILE` (A25);
    - the four requirements of the roadmap's "Deployment shapes";
    - the etcd floor, with every member URL listed;
    - two independently upgraded server groups as two hosts;
    - port 300;
    - why `ProtectSystem=true` and not `strict` (ruling 3);
    - `LoadCredential=` named "unmeasured (L84)";
    - the `encryption:` rotation runbook and the "When it will not start" table (ruling 13).

- [ ] **Step 4: Verify.**

  Run `go test ./tests/shapes/ -count=1` (PASS), then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add deploy/systemd deploy/examples tests/shapes/units_test.go tests/shapes/examples_test.go
  git commit -m "feat: systemd units, configs and store examples for the systemd shape"
  ```

---

### Task 8: Packages: GoReleaser, `port49-server` and the `port49` client

**Files:**
- Create:
  - `.goreleaser.yaml`;
  - `packaging/client/config.yaml`, the template conffile;
  - `packaging/README.md`;
  - `tests/packages/packages_test.go` (`//go:build packages`);
  - `internal/userconfig/conffile_test.go`.
- Modify: `Makefile` (`bin/goreleaser-$(GORELEASER_VERSION)` pinned by sha256, `packages`, `.PHONY`)

**Interfaces:**
- Produces: `make packages`, which runs `goreleaser release --snapshot --clean --skip=publish,sign` and writes `dist/`. Task 9 installs `dist/port49-server_*_amd64.deb`.

- [ ] **Step 1: Write the failing tests, which read `dist/`.**

  - `TestServerPackageContents`: `dpkg-deb -c` of the server `.deb` lists:
    - `/usr/bin/{port49d,port49-broker,port49-inventory,port49}`, each `-rwxr-xr-x root/root`;
    - `/usr/lib/systemd/system/port49d.service` and `port49-broker.service` (the merged-`/usr` path, for deb and rpm alike);
    - `/usr/lib/sysusers.d/port49.conf` and `/usr/lib/tmpfiles.d/port49.conf`.

    Its control file says `Conflicts: port49`. No file has the `s` bit. `readelf -l` on each of the four extracted server binaries shows no program interpreter.
  - `TestClientPackageContents`:
    - `/usr/bin/port49` is `-rwxr-xr-x root/root`;
    - `/etc/port49/config.yaml` is in `conffiles` and is `-rw-r--r-- root/root`;
    - `/usr/share/ansible/collections/ansible_collections/port49/client/galaxy.yml` is present;
    - in the `.deb`, `/usr/lib/python3/dist-packages/port49/__init__.py` is present;
    - `Conflicts: port49-server`.
  - `TestTheClientPackageImportsAndFindsTheCollection`: in a `debian:trixie-slim` container with `python3` and `ansible-core` (pinned), `apt-get install ./port49_*.deb`. Then `python3 -c 'import port49'` exits 0, and `ansible-doc -t lookup port49.client.token` exits 0.
  - `TestTheClientConffileSetsNothing`, in `internal/userconfig/conffile_test.go`: `parse("../../packaging/client/config.yaml", "system config", false)` returns the zero `File`. The test reads the raw text and finds each A13 key (`broker`, `broker_ca`, `broker_crl`, `touch_key`, `key`, `issued_key_store`) as a commented line.
  - `TestTheRPMsMatch`: `rpm -qlpv` shows the same paths and modes, except the Python library, which the `.rpm` omits (ruling 6).
  - `TestTheDarwinClientArchivesExist`: `dist/port49_*_darwin_{arm64,amd64}.tar.gz` exist.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `go test -tags packages ./tests/packages/ -count=1`. Expected: FAIL (no `dist/`).

- [ ] **Step 3: Write `.goreleaser.yaml` (version 2).**

  - **builds**, one `main` each:
    - IDs `port49d`, `port49-broker`, `port49-inventory` and `port49-static` (`./cmd/port49`, `binary: port49`): `CGO_ENABLED=0`, no tags, linux/amd64 and linux/arm64, `-trimpath -s -w`.
    - `port49-client`: `./cmd/port49`, `binary: port49`, `-tags hwkey_dlopen`, `CGO_ENABLED=0`, linux and darwin, amd64 and arm64.
  - **archives:**
    - `server` (`ids: [port49d, port49-broker, port49-inventory, port49-static]`), linux only;
    - `client` (`ids: [port49-client]`), named `port49_{{.Version}}_{{.Os}}_{{.Arch}}`.

    The two never share an archive, so the two `port49` binaries never collide.
  - **checksum:** `SHA256SUMS`.
  - **nfpms:**
    - `port49-server` (the four server IDs):
      - contents: the units at `/usr/lib/systemd/system/`, `sysusers.d` and `tmpfiles.d` from `deploy/systemd/`, and the example configs at `/usr/share/doc/port49-server/examples/`;
      - postinstall runs `systemd-sysusers` and `systemd-tmpfiles --create`, and never enables or starts a unit.
    - `port49` (`ids: [port49-client]`):
      - `packaging/client/config.yaml` as `type: config|noreplace` at `/etc/port49/config.yaml`;
      - `clients/ansible/ansible_collections/port49/client/` (tests excluded) at `/usr/share/ansible/collections/ansible_collections/port49/client/`;
      - for the `deb` format only (nfpm's per-format `packager: deb` on the content entry), `clients/python/src/port49/` at `/usr/lib/python3/dist-packages/port49/`.
    - Both set `file_info.mode: 0755` for binaries, and `deb` and `rpm` formats.
  - **release:** draft false, GitHub. **changelog:** use `git`.
  - `packaging/README.md` covers:
    - the two packages and why they conflict;
    - 0755 with no setgid and no capabilities, and why `port49 ssh`'s askpass needs that (9a P15);
    - `usermod -aG tss <user>` for a TPM;
    - the pcscd polkit rule as a host install;
    - where the client package puts the Python library and the collection, and that on an `.rpm` host the library comes from `pip install port49` (ruling 6);
    - macOS unsigned (L63).

- [ ] **Step 4: Verify.**

  - Run `make packages && go test -tags packages ./tests/packages/ -count=1`. Expected: PASS.
  - Run `bin/goreleaser-$(GORELEASER_VERSION) check`. Expected: no error.
  - Then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add .goreleaser.yaml packaging tests/packages internal/userconfig/conffile_test.go Makefile
  git commit -m "feat: deb and rpm packages for the server and the client, built by a pinned GoReleaser"
  ```

---

### Task 9: The systemd smoke

**Files:**
- Create: `tests/systemd/Dockerfile`, `tests/systemd/smoke_test.go` (`//go:build systemd`), `.github/workflows/systemd.yml`
- Modify: `Makefile` (`systemd-smoke: packages`)

**Interfaces:**
- Consumes:
  - `shapetest.Device`, `Mint`, `FloorLine`, `RotateCell` and `Rotator` (Task 6);
  - `testpki.WriteCompose`'s layout (etcd PKI, broker PKI, keys) (Task 6);
  - Task 8's `.deb`.

- [ ] **Step 1: Write `tests/systemd/Dockerfile`.**

  - `FROM debian:trixie-slim`, with `systemd systemd-sysv dbus ca-certificates` installed.
  - `COPY --from=gcr.io/etcd-development/etcd:v3.6.15 /usr/local/bin/etcd /usr/local/bin/etcdctl /usr/local/bin/`.
  - `STOPSIGNAL SIGRTMIN+3`, `CMD ["/sbin/init"]`.
  - The `.deb` and the PKI are copied in at run time, never baked.

- [ ] **Step 2: Write `TestSystemdSmoke`.**

  1. Build the image, then run it: `docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock -p 127.0.0.1:49:49 -p 127.0.0.1:8443:8443`.
  2. `docker cp` the `.deb` and the generated PKI. `apt-get install ./port49-server_*.deb`.
  3. Create the `etcd` user from `examples/sysusers-etcd.conf`. Install three `etcd@{1,2,3}` instances from `deploy/systemd/examples` with the three member configs, each with its own client and peer port (2379/2380, 2479/2480, 2579/2580). Apply `port49d store-roles` output with `etcdctl`.
  4. Copy `deploy/systemd/config/*` with the smoke's endpoints, and the keys and secrets, with the modes ruling 2 states.
  5. Run `systemctl enable --now port49-broker port49d`.
  6. Assert:
     - the login and `Permits` pass, and `FloorLine` passes on `journalctl -u port49d`;
     - `systemctl restart port49d port49-broker`, then the session's next command is permitted;
     - `/var/lib/port49-broker` is `port49-broker 700` and the journal has no `state_dir` refusal;
     - `RotateCell` passes, with a rotator writing through `docker exec … install`, and `StartedAt` from `systemctl show -p ExecMainStartTimestamp port49d`;
     - **Review Focus 1:** `chmod g+w /etc`, an ancestor of every config path, and restart port49d.
       - The unit fails, and the journal's refusal names `/etc` and contains `writable by others`.
       - Then, with a drop-in of `ProtectSystem=strict` and `ReadWritePaths=/var/spool/port49d`, and `/etc` still g+w, the same restart *passes*. This proves the cell can tell the two settings apart.
       - Remove the drop-in, restore `/etc`'s mode in a `t.Cleanup` that runs even on failure, and restart.
     - **Review Focus 2:** write a policy with no `keys:` and restart. Within 360 s, `systemctl show -p NRestarts,ActiveState port49d` reads `NRestarts` ≤ 5 and `ActiveState=failed`. Restore the policy, then `systemctl reset-failed`.
     - **Admin calls:** with `AdminSetup`'s roots and subject in the installed configs (step 4), `AdminNeedsTouch` for `user:bob@example.com`. Then the break-glass: `systemctl stop port49-broker`, `port49-broker revoke --offline --principal user:bob@example.com` as root (exit 0), `systemctl start port49-broker`, and `OfflineRevoked`. Then `--lift` the same way, and bob mints again.
  7. On failure, log the journal of every port49 unit through `tests/qual/secret-filter.sh`. Always remove the container.

- [ ] **Step 3: Verify.**

  Run `make systemd-smoke`. Expected: PASS. Then `make test && make vet`.

- [ ] **Step 4: Add `.github/workflows/systemd.yml`.**

  It runs on `push` to `main` and `pull_request`, permissions `contents: read`, with `timeout-minutes: 40`. Its steps are pinned checkout and setup-go, then `make systemd-smoke`.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/systemd Makefile .github/workflows/systemd.yml
  git commit -m "test: the systemd shape end to end under systemd, from the server package"
  ```

---

### Task 10: The Helm chart and the External Secrets example

**Files:**
- Create:
  - `deploy/helm/port49/Chart.yaml` (`version` and `appVersion` equal to pyproject's, today `0.1.0`), `values.yaml`, `values.schema.json`;
  - `templates/{_helpers.tpl,port49d-statefulset.yaml,broker-statefulset.yaml,services.yaml,configmaps.yaml,pdb.yaml,hpa.yaml,serviceaccount.yaml,issuer-discovery.yaml,NOTES.txt}`;
  - `deploy/helm/port49/examples/{external-secret.yaml,values-multi-region.yaml,backup-cronjob.yaml}`, `examples/etcd/{statefulset.yaml,service.yaml,etcd-init-job.yaml}`;
  - `deploy/helm/port49/scripts/copy-issuer.sh` and `revoke-offline.sh` (ruling 5's break-glass: scale the brokers to 0, a one-shot pod on broker-0's PVC and config running `port49-broker revoke --offline`, scale back, every pod deleted by a trap);
  - `deploy/helm/port49/README.md`;
  - `tests/helm/render_test.go` (`//go:build helm`).
- Modify: `Makefile` (pinned `bin/helm-$(HELM_VERSION)`, `helm-test`); `tests/ci/versions/versions.go` and its test (`Chart` required now, the optional path removed)

**Interfaces:**
- Produces, for Task 11:
  - values keys `image.repository`, `image.tag`, `port49d.replicas` (default 2), `broker.replicas` (default 2);
  - `keys.existingSecret` (required), `encryption.existingSecret` (required);
  - `etcd.endpoints` (a list, required, `minItems: 3`, `uniqueItems: true`). A schema cannot tell a Service name from a pod's, so the smokes' `FloorLine` pins the rest.
  - `etcd.caSecret` (the CA certificate only, mounted in both);
  - `etcd.port49d.existingSecret` (port49d's client certificate and key, mounted only in port49d);
  - `etcd.broker.existingSecret` (the broker's, mounted only in the broker);
  - `issuerDiscovery.enabled` (default false);
  - `broker.attestationRootsConfigMap` (optional): mounts the attestation roots and renders `attestation_roots_file`. Unset, the broker warns and refuses admin calls 503 (§12), and the README says to set it (A-I2);
  - `config.port49d`, `config.broker` (YAML merged into each rendered config), `policy`, `inventory`;
  - `tlsListener.enabled`;
  - `service.externalTrafficPolicy` (default `Local`);
  - `autoscaling.enabled` (default false);
  - `broker.site`, `broker.directory.keytabSecret`;
  - resource names `<release>-port49d` and `<release>-broker`.
  - `copy-issuer.sh <namespace> <release>`.

- [ ] **Step 1: Write the failing render tests.**

  Each test runs `helm template t deploy/helm/port49 -f <values>` and decodes every document.
  - `TestTheBrokerPodHasNoFSGroup`: the broker pod spec has no `fsGroup`. An initContainer runs `install -d -m 0700 -o 65532 -g 65532 /var/lib/port49-broker/state`, and `broker.state_dir` in the rendered config is `/var/lib/port49-broker/state`.
  - `TestPort49dSetsOnRootMismatch`:
    - `fsGroup: 65532` and `fsGroupChangePolicy: OnRootMismatch`;
    - the spool is a 0700 subdirectory made the same way;
    - the keys volume is a Secret mounted at `/run/port49/keys` with no `subPath` and `defaultMode: 0440` (decimal 288 in the rendered JSON);
    - `key_secret_refs.file_dir` is `/run/port49/keys`.
  - `TestBothAreStatefulSetsWithAPVCPerReplica`: both have `volumeClaimTemplates` and `updateStrategy.type: RollingUpdate`. No Deployment, and no `Recreate` or `OnDelete`.
  - `TestServicesKeepTheSource`:
    - the TACACS+ Service has port 49, and port 300 only with `tlsListener.enabled`;
    - `externalTrafficPolicy: Local`;
    - the pod sets the sysctl `net.ipv4.ip_unprivileged_port_start: "0"`;
    - the containers run as non-root with `allowPrivilegeEscalation: false` and drop `ALL` capabilities.
  - `TestSeparationAndDisruption`: a PDB with `maxUnavailable: 1` for each StatefulSet, preferred pod anti-affinity on hostname, and a topology spread on `topology.kubernetes.io/zone` with `whenUnsatisfiable: ScheduleAnyway`. No `persistentVolumeClaimRetentionPolicy` is set.
  - `TestNoPodHoldsTheOthersEtcdIdentity` (pre-flight C1):
    - port49d's pod mounts `etcd.port49d.existingSecret` and not the broker's, and the broker's pod the reverse;
    - both mount `etcd.caSecret`;
    - the device-keys Secret is mounted only in port49d's pod.
  - `TestProbesNeverNeedAClientCertificate`: every container's readiness probe is `httpGet` `/readyz` and its liveness probe `httpGet` `/healthz`, scheme `HTTP`, on the metrics port. No probe names port 49, 300 or the broker API port, and none is `exec` or `tcpSocket`. No rendered config holds `admin_socket`. Every liveness probe has `periodSeconds × failureThreshold ≥ 60` (re-review R1).
  - `TestAMissingChartIsAFinding`, in `tests/ci/versions`: `Read` of a tree without `Chart.yaml` is an error (pre-flight M3).
  - `TestIssuerDiscoveryIsOptIn`: off, no ClusterRoleBinding renders. On, one binds `system:service-account-issuer-discovery` to `system:unauthenticated`, matching `examples/kubernetes/issuer-discovery.yaml`.
  - `TestTheHPAScalesOnConnections`: with `autoscaling.enabled: true`, an `autoscaling/v2` HPA whose single metric is type `Pods`, named `port49_connections`. There is no `Resource` metric.
  - `TestEveryEtcdMemberIsListed`: the rendered `stores.directory.etcd.endpoints` equal the values list. A values file giving one URL, or a repeated one, is refused by `helm template` through the schema.
  - `TestTheMultiRegionExampleRenders`: `examples/values-multi-region.yaml` renders with `stores.session`, and the rendered config loads through `config.Load` (by Task 7's path rewrite).
  - `TestTheExternalSecretOneKeyPerVersion`: `examples/external-secret.yaml` decodes as `external-secrets.io/v1` `ExternalSecret`. Each `data[]` entry has a distinct `secretKey` matching `^[a-z0-9_]+_v[0-9]+$` and a distinct `remoteRef.key`. The target name equals `keys.existingSecret` in the chart's README example.
  - `TestRenderedConfigsLoad`: the rendered port49d.yaml and port49-broker.yaml load through `config.Load` and `LoadBroker`. It uses Task 7's pattern: each absolute root rewritten into `t.TempDir()`, with `testpki` PEMs and fixture secrets written at the fence's modes.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `make helm-test`. Expected: FAIL (no chart).

- [ ] **Step 3: Write the chart, the examples and the script.**

  - **`external-secret.yaml`:**
    - `refreshInterval: 1h`;
    - a `ClusterSecretStore` named `port49-vault`, with fake values (`https://vault.example.com`);
    - `data` entries `core_v1 → port49/devices/core-v1` and `core_v2 → port49/devices/core-v2`;
    - `target: {name: port49-device-keys, creationPolicy: Owner, deletionPolicy: Retain}`.
    - Its comment says: a new version is a new remote key and a new `data` entry, never a rewritten one; ESO's refresh rewrites the Secret, and port49d never re-reads a version (spec §10, §12).
  - **`copy-issuer.sh`**, in bash:
    - `set -euo pipefail`, with no `set -x`.
    - It runs `init-issuer` in a one-shot pod from the port49 image (uid 65532), on broker-0's PVC's node, mounting `data-<release>-broker-0` at `/var/lib/port49-broker` and the broker's ConfigMap at `/etc/port49`. The pod runs `port49-broker init-issuer --config /etc/port49/port49-broker.yaml`. It never uses `kubectl exec` into broker-0.
    - For each other ordinal `i`, it finds each PVC's node and starts a root `alpine:3.22` pod pinned there for each side, the source with its PVC read-only. Then it pipes `kubectl exec src -- tar c -C /s/state issuing-ca.pem issuing-ca.key` into `kubectl exec -i dst -- sh -c 'install -d -o 65532 -g 65532 -m 0700 /d/state && tar x -C /d/state && chown 65532:65532 /d/state/issuing-ca.* && chmod 0600 /d/state/issuing-ca.key'`.
    - It deletes every pod it started on every exit (trap).
    - It prints each broker's fingerprint line from its next start.
  - **`backup-cronjob.yaml`:** the etcd snapshot, with `umask 077` in the command.
  - **The probes and `issuer-discovery.yaml`**, per ruling 9.
  - **The README** covers:
    - the install;
    - the two releases for two server groups;
    - the four requirements;
    - Secrets and rotation, with ESO;
    - "Vault Agent and the CSI driver: unmeasured (L83)";
    - `subPath` never used;
    - the issuing CA (`copy-issuer.sh`) and `forget-issuer`;
    - admin calls through the agent with a key press, `revoke-offline.sh` as the break-glass, and Task 3a's 3am table (ruling 5);
    - `init-revocations` and `port49-broker init-enrollments` as one-off Jobs, never initContainers;
    - backups (the CronJob running `port49-broker export-enrollments` under `umask 077`, with the broker's own etcd Secret);
    - `externalTrafficPolicy: Local` with "source preservation unmeasured on Kubernetes (L39 b, c)";
    - port 300;
    - the image is not `g=u`, and a `g=u` rebuild (as some OpenShift guides advise) is refused by the fence at start. No claim about any platform's admission policy;
    - the HPA's adapter requirement, and that a scale-down retains the spool PVC (ruling 9);
    - Pod Security `baseline` for the namespace (ruling 9);
    - `issuerDiscovery.enabled` per cluster;
    - the key volume provisional on L82 until Task 13 closes it;
    - the `encryption:` rotation runbook and the "When it will not start" table (ruling 13);
    - etcd as port49's own cluster, never the control plane's.

- [ ] **Step 4: Verify.**

  Run `make helm-test` (PASS), `bin/helm-$(HELM_VERSION) lint deploy/helm/port49 -f <ci values>` (no error), and `go run ./tests/ci/cmd/versioncheck` (PASS), then `make test && make vet`.

- [ ] **Step 5: Commit.**

  ```bash
  git add deploy/helm tests/helm tests/ci/versions Makefile
  git commit -m "feat: a Helm chart for port49d and port49-broker, with an External Secrets example and the CA copy script"
  ```

---

### Task 11: The kind smoke

**Files:**
- Create:
  - `tests/kind/kindtest/kindtest.go`, the cluster bring-up and teardown that Tasks 13–16 reuse;
  - `tests/kind/smoke_test.go` (`//go:build kind`);
  - `tests/kind/kind.yaml`: one control plane and two workers, the workers labelled `topology.kubernetes.io/zone: a` and `b`, with no `extraPortMappings`;
  - `internal/testpki/kind.go` and `kind_test.go`.
- Modify: `Makefile` (pinned `bin/kind-v0.29.0`, `bin/kubectl-$(KUBECTL_VERSION)`, and `kind-smoke: image`, which also runs `docker build --target setup -t port49-setup:dev .`)

The workflow `.github/workflows/kind.yml` lands in Task 13, after L82 closes. The rotation cell here is the same measurement as L82 (b) and (d), so CI does not assert it before the row is measured (pre-flight I11).

**Interfaces:**
- Consumes:
  - Task 10's values and names, and `copy-issuer.sh`;
  - Task 6's `shapetest`;
  - the `setup` image target, which carries etcdctl.
- Produces:
  - `testpki.WriteKind(dir, namespace string, members int, email string, now time.Time) error`. It writes `WriteCompose`'s layout, but with member certificates whose SANs are `etcd-<i>.etcd.<namespace>.svc` and `etcd-<i>.etcd.<namespace>.svc.cluster.local` for `i` in `0..members-1`. Its test asserts those SANs.
  - `kindtest.Up(t *testing.T, name string) *Cluster`, with `Cluster.Kubectl(args ...string) string`, `Cluster.Dump(t)` (through `tests/qual/secret-filter.sh`, never the `vault` namespace), and teardown in `t.Cleanup`.

- [ ] **Step 1: Write `TestKindSmoke`.**

  1. **Set up.**
     - `kindtest.Up` with `tests/kind/kind.yaml`.
     - `kind load docker-image port49:dev port49-setup:dev`.
     - Generate the PKI with `testpki.WriteKind(dir, "port49", 3, …)` into `t.TempDir()`.
     - Create every Secret with `--from-file` only:
       - the etcd member certificates;
       - `etcd-ca` (certificate only);
       - `etcd-port49d` and `etcd-broker`, one identity each;
       - `port49-device-keys` with `tacacs_v1`;
       - the encryption keys.
     - Apply `examples/etcd/` and wait for the `etcd-init` Job.
     - `helm install t deploy/helm/port49`, with `etcd.endpoints` set to the three pod URLs `https://etcd-<i>.etcd.port49.svc:2379` and `service.type: NodePort`.
  2. **Log in.**
     - The device is `shapetest.Device`. It dials the `.status.hostIP` (the node's container address) of the port49d pod it targets, on the NodePort, looked up again after every restart. Under `externalTrafficPolicy: Local` only a node running port49d answers.
     - The inventory lists the kind network's gateway (`docker network inspect kind`). Under `externalTrafficPolicy: Local` that is the source if kube-proxy does not rewrite it.
     - The login passes. If it is refused `device_unknown`, the test fails saying so; it is L39 (b)'s question, and 12c owns the row.
     - `FloorLine` passes on `kubectl logs t-port49d-0`.
  3. **Restart.** `kubectl delete pod t-port49d-0 t-broker-0`, then wait Ready.
     - The session's next command is permitted.
     - The broker's log has no `state_dir` refusal (Review Focus 3).
     - `stat` through a debug pod on that PVC shows `65532 65532 700` for `state/`.
  4. **Rotate.** `RotateCell` with `within` = 180 s (the kubelet's sync plus the 30 s retry), and a rotator that:
     - patches the `port49-device-keys` Secret to add `tacacs_v2`, from a file;
     - applies a ConfigMap with the new policy;
     - reads `StartedAt` as the pod's `.status.containerStatuses[0].state.running.startedAt` plus `restartCount`, which must be unchanged.
  5. **subPath cell** (L82 (c), asserted here):
     - Run a pod mounting `port49-device-keys` key `tacacs_v1` by `subPath` and the whole volume beside it.
     - Patch `tacacs_v1`'s value to a second fake value. Do this only in this cell's own Secret copy, `port49-subpath-probe`, never the real keys.
     - Wait 180 s. Read both files' sha256 inside the pod, never the bytes.
     - Record whether the whole mount changed and the `subPath` file did not, and log the observation for L82.
  6. **Copy the CA.** `copy-issuer.sh port49 t`. The sha256 of `issuing-ca.pem` matches on both brokers' PVCs, and `issuing-ca.key` is `65532 600` on each.
  7. **Revoke.** With `AdminSetup`'s roots in a ConfigMap (values `broker.attestationRootsConfigMap`, Task 10) and its subject in the policy, `AdminNeedsTouch` for `user:bob@example.com` through a port-forward to the broker Service. Then `revoke-offline.sh port49 t -- --principal user:bob@example.com` exits 0, the brokers come back ready, and `OfflineRevoked` holds.
  8. **The CronJob, inside and outside** (plan 10 carry):
     - The broker gets a `k8s` verifier for the kind cluster, with `issuerDiscovery.enabled: true`, and the policy gets the subject of `examples/kubernetes/policy.yaml`.
     - **Inside:** a Job made from `examples/kubernetes/backup-cronjob.yaml`'s template (`kubectl create job --from=cronjob/…`) mints with `port49 workload token --token-file` against the in-cluster broker Service. PASS iff the Job completes, and the broker logs the service account's principal.
     - **Outside:** a `port49-broker` started on the host from `make build`, with the cluster's `jwks` URL and CA (as L69 ran), and the same Job pointed at it through the kind network gateway. Kind's etcd is not reachable from the host, so this broker uses the memory store. Its server certificate comes from `testpki` with the kind gateway IP (from `docker network inspect kind`) as an IP SAN, and it listens on that gateway address. PASS iff the Job completes.

  On failure the test calls `Cluster.Dump`. It always deletes the cluster.

- [ ] **Step 2: Verify.**

  Run `make kind-smoke`. Expected: PASS. Then `make test && make vet`.

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/kind internal/testpki/kind.go internal/testpki/kind_test.go Makefile
  git commit -m "test: the Kubernetes shape end to end on kind, with rotation, restart, the CA copy, the offline revoke and a CronJob"
  ```

---

### Task 12: The release workflow and publishing

**Files:**
- Create: `.github/workflows/release.yml`, `tests/ci/workflows_test.go` (untagged; parses YAML), `packaging/requirements-release.txt` (`build`, `setuptools` and `ansible-core` with every transitive dependency, generated by `pip-compile --generate-hashes`; the file's header records the exact command, and a regeneration is that command re-run, never a hand edit)
- Modify: `clients/python/pyproject.toml` (classifiers and URLs only, if missing; `requires` pinned to the setuptools version in `requirements-release.txt`), `clients/ansible/ansible_collections/port49/client/galaxy.yml` (`build_ignore` for tests), `.github/workflows/lab-free.yml` (no change to `on:`; its tag trigger stays)

**Interfaces:**
- Consumes: `make check-static`, `make packages`'s `.goreleaser.yaml`, `versioncheck`, `Chart.yaml`.

- [ ] **Step 1: Write the failing tests.**

  - `TestReleaseRunsOnTagsOnly`: `release.yml`'s `on` is exactly `push: {tags: ['v*']}`, with no `pull_request`, `workflow_dispatch` or branch trigger.
  - `TestOnlyThreeJobsHoldIDToken`:
    - every workflow's top-level `permissions` is `contents: read`, never `id-token` or `write-all`;
    - `id-token: write` appears only in release.yml's jobs `pypi`, `goreleaser` and `image` (the last two for attestations), and in no other workflow file;
    - `pypi` has `environment: pypi`; `galaxy` has `environment: galaxy`, and reads `secrets.GALAXY_API_KEY` only in its publish step's `env:`; no other job names an environment or that secret;
    - no workflow has a `pull_request_target` trigger.
  - `TestPublishJobsBuildNothing`:
    - neither `pypi` nor `galaxy` has a checkout;
    - `pypi` has exactly a `download-artifact` step and the publish action;
    - `galaxy` has a `download-artifact` step and one `run:` step, whose commands are only the hash-pinned `pip install --require-hashes -r` (fetched as `requirements-release.txt` in the artifact) and `ansible-galaxy collection publish`;
    - `build-python` and `build-galaxy` hold no `id-token` and no environment, and install only with `pip install --require-hashes -r packaging/requirements-release.txt`.
  - `TestCheckoutsKeepNoCredentials`: every `actions/checkout` in `release.yml` sets `persist-credentials: false`, except in `goreleaser`.
  - `TestGoReleaserIsThePinnedBinary`: no job uses `goreleaser/goreleaser-action`; the `goreleaser` job runs `make bin/goreleaser-$(GORELEASER_VERSION)` and then that binary.
  - `TestEveryActionIsPinnedBySHA`: every `uses:` in every workflow matches `@[0-9a-f]{40}`.
  - `TestNoWorkflowTracesShell`: no `set -x` and no `ACTIONS_STEP_DEBUG` in any workflow.

- [ ] **Step 2: Run the tests and see them fail.**

  Run `go test ./tests/ci/ -count=1`. Expected: FAIL.

  Then pin by SHA the workflows that predate this plan (`compose`, `hwkeys`, `lab-free`, `leaks`, `python`, `qual`), which use tags such as `@v4`, so `TestEveryActionIsPinnedBySHA` passes. Tasks 4, 9 and 11 pin their own workflows when they write them.

- [ ] **Step 3: Write `release.yml`.**

  Every checkout sets `persist-credentials: false`, except `goreleaser`'s. The jobs, in order through `needs:`:
  1. **`check`** runs:
     - `go run ./tests/ci/cmd/versioncheck -tag "$GITHUB_REF_NAME"`;
     - `make vet`;
     - `make check-static`;
     - `make check-darwin`.
  2. **`goreleaser`** (`contents: write`, `attestations: write`, `id-token: write`) runs `make bin/goreleaser-$(GORELEASER_VERSION)`, then that binary's `release --clean` with `GITHUB_TOKEN`. Then it runs `actions/attest-build-provenance` over `dist/*.tar.gz`, `dist/*.deb`, `dist/*.rpm` and `dist/SHA256SUMS`.
  3. **`image`** (`packages: write`, `attestations: write`, `id-token: write`) uses `docker/setup-buildx-action` and `docker/build-push-action`, with:
     - `--target port49`;
     - `platforms: linux/amd64,linux/arm64`;
     - tags `ghcr.io/rhwendt/port49:${version}` and `:latest`, but `:latest` only when the tag has no `-` (a pre-release does not move it);
     - an attestation pushed to the registry.
  4. **`chart`** (`packages: write`) runs `helm package deploy/helm/port49` and `helm push … oci://ghcr.io/rhwendt/charts`, with the pinned `bin/helm`.
  5. **`build-python`** (no token): `pip install --require-hashes -r packaging/requirements-release.txt`, then `python -m build --no-isolation clients/python`. It uploads `clients/python/dist/`.
  6. **`pypi`** (`environment: pypi`, `id-token: write`): `actions/download-artifact`, then `pypa/gh-action-pypi-publish` with `packages-dir: dist`, `skip-existing: true`.
  7. **`build-galaxy`** (no token): the same pinned install, then `ansible-galaxy collection build clients/ansible/ansible_collections/port49/client`. It uploads the tarball together with `packaging/requirements-release.txt`.
  8. **`galaxy`** (`environment: galaxy`): `actions/download-artifact`, then one `run:` step, with `env: {GALAXY_API_KEY: ${{ secrets.GALAXY_API_KEY }}}`:
     - `pip install --require-hashes -r requirements-release.txt`;
     - `ansible-galaxy collection publish port49-client-*.tar.gz --token "$GALAXY_API_KEY"`.

     Output naming this version as already existing is success on a re-run.

- [ ] **Step 4: Verify.**

  - Run `go test ./tests/ci/ -count=1` (PASS), and `actionlint` (pinned, run through `go run github.com/rhysd/actionlint/cmd/actionlint@<version>` only if it adds no module; otherwise the pinned release binary, as gitleaks), with no error. Then `make test && make vet`.
  - Do not push a tag. The first release is Ryan's, after "Open for Ryan".

- [ ] **Step 5: Commit.**

  ```bash
  git add .github/workflows tests/ci/workflows_test.go packaging/requirements-release.txt clients/python/pyproject.toml clients/ansible/ansible_collections/port49/client/galaxy.yml
  git commit -m "ci: a tag-only release of packages, image, chart, PyPI and Galaxy, with provenance"
  ```

---

### Task 13: Lab L82: Secret volumes and External Secrets on kind

**Files:**
- Create: `tests/lab/l82_test.go` (`//go:build lab`), `tests/lab/results/L82-kind.md`, `.github/workflows/kind.yml`
- Modify: `Makefile` (`lab-l82`), the spec's §15 L82 Status, `deploy/helm/port49/README.md`

This task runs straight after Task 11, before any later task, because Task 11's rotation and `subPath` cells measure the same thing. The kind workflow lands here, once the row is measured.

- [ ] **Step 1: Write `TestL82`.**

  - It uses `kindtest.Up` (Task 11).
  - It installs the External Secrets Operator chart (pinned), and a `ClusterSecretStore` with the `fake` provider holding `port49/devices/core-v1` and `core-v2`. Their values are fake, generated at run time.
  - Every cell writes PASS or FAIL against §15 L82's condition, beside its observation:
    - **(a)** `stat -c '%U %G %a %F'` of the mount's directory, `..data` and each file, through a pod with the chart's securityContext; and whether port49d starts with the key.
    - **(b)** The delay from the Secret update to the file's change (PASS ≤ 180 s).
    - **(c)** The `subPath` cell, as in Task 11.
    - **(d)** An `ExternalSecret` with `core_v1`, then `core_v2` added. The Secret gains `core_v2`, and a policy naming it is in force with no restart, measured by the cell's v2 login and an unchanged `restartCount` (PASS ≤ 240 s).
  - It records: kind and node image, ESO chart and app versions, each stat line, and each delay.

- [ ] **Step 2: Run the lab.**

  Run `make lab-l82` under the lab lock, with the watchdog. Expected: every cell gives a PASS or a FAIL.

- [ ] **Step 3: Write the results note and close or update the row.**

  - Write `tests/lab/results/L82-kind.md` with platform, versions, observations, and the run log's path as the capture pointer. There is no pcap; the kubectl outputs go in the note.
  - Edit L82's Status to `closed — measured <date>; tests/lab/results/L82-kind.md`, or to open with what was measured.
  - If a cell contradicts the chart (a mode the fence refuses, or no update on a whole mount), the chart is wrong. Fix it test-first in `tests/helm` and `tests/kind`, cite the note, and say so in the commit.
  - Update the chart README's ESO and Secret-volume lines to cite L82, and drop "provisional on L82".

- [ ] **Step 4: Wire the kind smoke into CI.**

  - Add `.github/workflows/kind.yml`: `push` to `main` and `pull_request`, permissions `contents: read`, `timeout-minutes: 45`, pinned checkout and setup-go, `make kind-smoke`.
  - Push and read its run with `gh run watch`. Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/lab/l82_test.go tests/lab/results/L82-kind.md docs/design/2026-08-23-policy-engine-spec.md deploy/helm/port49/README.md Makefile .github/workflows/kind.yml
  git commit -m "docs: close lab register entries L82 (Secret volumes and External Secrets on kind)"
  ```

---

### Task 14: Lab L83: Vault Agent injector and the Secrets Store CSI driver

**Files:**
- Create: `tests/lab/l83_test.go` (`//go:build lab`), `tests/lab/results/L83-kind.md`
- Modify: `Makefile` (`lab-l83`), §15 L83, `deploy/helm/port49/README.md`

- [ ] **Step 1: Write `TestL83`.**

  - It uses `kindtest.Up`. It installs the Vault chart in dev mode, and the injector, `secrets-store-csi-driver` and `vault-csi-provider`, all pinned.
  - Vault's root token is generated at run time into a `t.TempDir()` file and passed as `-dev-root-token-id` from a Secret made `--from-file`. Dev mode then prints only that value, and the `vault` namespace is never dumped (`Cluster.Dump` excludes it). The token is never printed or written elsewhere.
  - It writes the fake keys `port49/devices/core-v1`, and later `core-v2`.
  - Every cell writes PASS or FAIL against §15 L83's condition:
    - **(a)** A port49d pod annotated for the injector, with the template's `perms = "0440"`: `stat` of the rendered file and the agent's uid, with and without `vault.hashicorp.com/agent-run-as-same-user: "true"`, and whether port49d starts with the key.
    - **(b)** A `SecretProviderClass` mount: `stat` with the provider's default permission and with `filePermission: 0440`, and whether port49d starts.
    - **(c)** For each configuration that passed (a) or (b): `core-v2` is written at Vault, the injector template or the `SecretProviderClass` gains it, and the policy names it. PASS iff it is in force within 300 s with `restartCount` and start time unchanged. The CSI driver needs its rotation feature, so record whether it was enabled.

- [ ] **Step 2: Run the lab, write the note, update the row and the README.**

  - Run it; write `tests/lab/results/L83-kind.md`; update §15.
  - In the README:
    - name a mechanism for device keys only if (a) or (b) and (c) are PASS, with its exact settings and the note;
    - name one that passed (a) or (b) but failed (c) for the encryption key only, saying why: a new device-key version would need a restart;
    - name one that failed (a) or (b) as refused, with the fence's line.

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/lab/l83_test.go tests/lab/results/L83-kind.md docs/design/2026-08-23-policy-engine-spec.md deploy/helm/port49/README.md Makefile
  git commit -m "docs: close lab register entries L83 (Vault Agent and the CSI driver against the fence)"
  ```

---

### Task 15: Lab L84: `LoadCredential=` and Compose `secrets:`

**Files:**
- Create: `tests/lab/l84_test.go` (`//go:build lab`), `tests/lab/results/L84-systemd-docker.md`
- Modify: `Makefile` (`lab-l84`), §15 L84, `deploy/systemd/README.md`, `deploy/compose/README.md`

- [ ] **Step 1: Write `TestL84`.**

  Every cell writes PASS or FAIL against §15 L84's condition.
  - **(a)** It uses Task 9's container, with a drop-in `LoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1` and `key_secret_refs.file_dir: /run/credentials/port49d.service`. It records `stat` of the directory and the file, the start's result, and a second start's.
  - **(b)** It uses a compose override, with the long syntax (`uid: "0"`, `gid: "65532"`, `mode: 0440`) and the short syntax beside it. It records `stat` inside the container and the start's result.
  - **(c)** For each mechanism that passed (a) or (b): add `tacacs_v2` (a second `LoadCredential=` line, or a second `secrets:` entry) and a policy naming it, *without* restarting the unit or container. PASS iff it is in force within 120 s with the start identity unchanged.

    The expectation, which the cell tests rather than assumes, is FAIL: both mechanisms are fixed at start.
  - It records the Docker, Compose and systemd versions.

- [ ] **Step 2: Run the lab, write the note, update the row and the READMEs.**

  - Run it; write the note; update the row.
  - The READMEs name a mechanism for device keys only if (a) or (b) and (c) are PASS. One that failed (c) is named for the encryption key only, saying why.

- [ ] **Step 3: Commit.**

  ```bash
  git add tests/lab/l84_test.go tests/lab/results/L84-systemd-docker.md docs/design/2026-08-23-policy-engine-spec.md deploy/systemd/README.md deploy/compose/README.md Makefile
  git commit -m "docs: close lab register entries L84 (systemd credentials and compose secrets against the fence)"
  ```

---

### Task 16: Lab L85: MetalLB anycast, and the chart's option if it passes

**Files:**
- Create: `tests/lab/l85_test.go` (`//go:build lab`), `tests/lab/results/L85-kind.md`
- Modify: `Makefile` (`lab-l85`), §15 L85. If L85 passes: `deploy/helm/port49/templates/services.yaml`, `values.yaml`, `values.schema.json`, `README.md`, `tests/helm/render_test.go`.

- [ ] **Step 1: Write `TestL85`.**

  - The cluster is kind with three workers. It installs MetalLB in BGP mode (pinned), and an FRR container (pinned) on the kind network that peers with every node and runs ECMP.
  - The device client is a `shapetest.Device` in a container behind the FRR router, so its traffic is routed to the VIP.
  - It uses `kindtest.Up`, whose failure dump goes through the secret filter.
  - Every cell writes PASS or FAIL against §15 L85's condition:
    - **(a)** The source port49d records under `externalTrafficPolicy: Local`, against the device's own address.
    - **(b)** FRR's `show ip bgp <vip>`: the next hops and nodes.
    - **(c)** Delete one port49d pod. Record the withdrawal time, and what a single-connection session and a per-transaction client see.
    - **(d)** `kubectl rollout restart statefulset/t-port49d`, with one login a second: count the failures, and the logins that pass on one retry.

- [ ] **Step 2: Run the lab and write the note; update the row.**

- [ ] **Step 3: Gate the chart option on the result.**

  Per ruling 12, only if all four cells are PASS:
  - Test-first in `tests/helm`: `TestAnycastIsLoadBalancerLocal`. With `anycast.enabled: true` and `anycast.address`, the TACACS+ Service is `type: LoadBalancer` with `externalTrafficPolicy: Local`, the `metallb.universe.tf/loadBalancerIPs` annotation set to the address, and `spec.loadBalancerIP` unset.
  - Add the values and schema.
  - In the README: the measured result; design §13's per-transaction advice, and that NX-OS honours single-connect (L80); and that two releases (two server groups) still need two addresses (design §13).

  Otherwise nothing ships, and the note says what failed.

- [ ] **Step 4: Commit.**

  ```bash
  git add tests/lab/l85_test.go tests/lab/results/L85-kind.md docs/design/2026-08-23-policy-engine-spec.md Makefile deploy/helm tests/helm
  git commit -m "docs: close lab register entries L85 (MetalLB anycast on kind)"
  ```

  If it did not pass, use `docs: record lab register entry L85 (MetalLB anycast not offered)`.

---

### Task 17: The roadmap's record and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line, the 12b entry, a new "Plan 12b — As built" before "Plan 13", the 12c entry's "Hands on")

- [ ] **Step 1: Write "Plan 12b — As built".**

  It holds:
  - each task's commits;
  - what changed in review;
  - "Carried forward": anything not done, and L82–L86's states;
  - "Operator notes", true of the code as built, each a line:
    - the three shapes and their make targets;
    - where secrets live per shape;
    - the rewrite warning and its gauge;
    - `ProtectSystem=true` and why;
    - two users;
    - admin calls over the API with a key press, the rights, the break-glass per shape, and the 3am table;
    - the packages and their conflict;
    - 0755 with no setgid or capabilities;
    - the client conffile;
    - `copy-issuer.sh`;
    - the release artifacts and where they publish;
    - the one-version rule;
    - the CI jobs;
    - what is unmeasured.
  - "Hand-offs":
    - **12c:**
      - an alarm on `port49_key_secret_files_changed > 0` for 10m;
      - L39 (b), with Task 11's login cell as its first evidence;
      - the reference configs;
      - load;
      - **the Oxidized `secure: true` follow-up** (plan 9d carry): measure Oxidized's host-key options against accept-new, and change `examples/oxidized` or say why not;
      - **a Velero example** for the chart's PVCs, with a measurement behind it (pre-flight M10);
      - whatever L83, L84 or L85 left FAIL that a later platform change might reopen.
    - **Plan 13:** install pages from each README, the "When it will not start" tables, and the `encryption:` rotation runbook.
    - **Ryan:** the open items of this plan's "Open for Ryan", as ruled or still open.

- [ ] **Step 2: Verify.**

  Run `make test && make vet` (PASS) and `make leaks` (no finding).

- [ ] **Step 3: Commit.**

  ```bash
  git add docs/superpowers/plans/README.md
  git commit -m "docs: plan 12b as built, its operator notes and hand-offs"
  ```
