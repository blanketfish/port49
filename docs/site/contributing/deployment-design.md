---
title: Deployment design
description: Why the deployments are built the way they are, how their smoke tests run, and how README sections feed the site.
---

# Deployment design

The choices behind the three deployments, for someone changing the units, the Compose stack or the chart.

## systemd

The `port49-server` package gives two units. `port49d.service` runs as `port49d` and
`port49-broker.service` runs as `port49-broker`. The two users are separate on purpose, so no process
holds both etcd identities. The package creates them with `sysusers.d`, and `tmpfiles.d` makes
`/etc/port49` and its `keys`, `secrets`, `etcd` and `broker` subdirectories.

`port49d` needs no file capability to bind port 49. The unit grants `CAP_NET_BIND_SERVICE` as an
ambient capability and bounds the process to it.

### ProtectSystem=true, not strict

The secret-file fence refuses a key or secret directory that a group or another user can write. It
excuses that check on a read-only mount, since nothing there can change. `ProtectSystem=strict` or
`full`, or `ReadOnlyPaths=/etc`, would make `/etc` read-only inside the unit, so a group-writable
`/etc/port49` on the host would pass the fence. `ProtectSystem=true` makes only `/usr`, `/boot` and
`/efi` read-only. The units also set `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes` and a
capability bound, which leave `/etc` writable. The unit test in `tests/shapes` holds each of these.

## Helm: the volume root

The chart sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch`, and `fsGroup` also acts on a
PVC's root. Two rules meet there.

With `OnRootMismatch`, the kubelet walks the whole volume at a pod's start unless the root is group
65532, includes 0770 and has setgid. Its walk adds group write to everything it reaches. port49's file
fence refuses a group-writable directory above a file it reads, unless the directory is sticky and
root-owned.

So the `data-dir` init container, running as root before the process starts, does three things:

1. It sets the volume root to `root:65532` mode 3770. The kubelet then never walks it again, and the
   fence excuses it.
2. It makes the data directory with an explicit `chmod 0700`.
3. It repairs everything below the data directory to owner-only, so a walk that happens anyway (a
   restore, or a driver that walks regardless) changes nothing the process sees.

No fenced file (policy, inventory, device keys, the sealing key) lives on a PVC. A cluster that forbids
root init containers needs a volume root provisioned 3770 `root:65532` instead. If `data-dir` fails,
the pod sits in `Init:` and `kubectl describe pod` says why, so nothing starts half-fenced. That the
key Secret volume is readable under `fsGroup` was measured in [L82](../reference/lab-register.md#l82).

## Smoke tests

Each deployment has a smoke test that CI runs.

| Target | What it does |
|---|---|
| `make systemd-smoke` | Installs the package under systemd in a container and drives it. CI runs it from `.github/workflows/systemd.yml`. |
| `make compose-smoke` | Brings the Compose stack up on a fresh PKI, logs a device in, recreates every container with its volumes kept, and checks that the session, a token minted before the recreate and the broker's `broker.state_dir` survived. It also checks that port49d names all three etcd members at or above the version floor, that a device key version added by writing a file takes effect with no restart, that an admin revoke with no key press is refused, that the break-glass revoke and lift work, and that no secret is in any container's environment. CI runs it on every pull request. |
| `make kind-smoke`, `make kind-smoke-red` | Run the chart on a kind cluster, whose nodes are privileged containers. CI runs them from `.github/workflows/kind.yml`. |

The kind smoke checks the volume root against a real kubelet. Its two-generation cell uses a volume type
the kubelet applies `fsGroup` to (a `local` volume or csi-hostpath, never kind's default hostPath
class, which never applies it). It installs, deletes the pod, and checks that the broker starts again,
the root is `3770 root:65532`, and `state/issuing-ca.key` is still 0600. Run first with the old 2755
root and issuance on, it must leave `issuing-ca.key` unusable after the walk, which proves the cell
detects the fault. The broker says so and issues nothing, and it does not crash-loop.

The systemd and kind smokes refuse to start locally on a host with a TPM or a security key
(`/dev/tpm0`, `/dev/tpmrm0`, a Yubico device on the USB bus). Their container holds `CAP_SYS_ADMIN`
with no AppArmor profile and is not an isolation boundary. The refusal is one line that names the
device it found.

## The chart's checks

The chart's render checks run on a Go stand-in renderer (`make test`) and on real helm 3.22.0
(`make helm-test`, a CI job). The kind smoke installs the chart on a cluster with port49's own etcd
(green in CI, run 41155086403).

## How READMEs feed the site

The install, upgrade and troubleshoot pages of each deployment are sections of that deployment's
README under `deploy/`, so the README read on GitHub and the page read on the site cannot drift. A
section is marked in the README with `<!-- --8<-- [start:install] -->` and `[end:install]`, and a page
includes it with `--8<-- "deploy/systemd/README.md:install"` on a line of its own. Edit the README,
not the page.
