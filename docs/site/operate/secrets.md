---
title: Secrets
description: Where port49's secrets live, who may read them, and how they are rotated.
---

# Secrets

port49 holds three kinds of secret: the shared keys it shares with devices, the key that seals its stored
records, and the keys that talk to etcd and TLS. None is ever written in a configuration file, the
policy, or a container's environment listing. A file that CI and every operator read carries only a
**name** for the secret, and the secret itself is a file that a mount, a package or a secret agent puts
on disk. This page says what the names look like, which files port49 will agree to read, and which
mounting mechanisms were measured.

Rotation is on [Key rotation](../admin/key-rotation.md).

## The secret reference

A key version in the policy names its secret with `secret_ref`. There are two forms:

| Form | Example | Meaning |
|---|---|---|
| `env:NAME` | `env:PORT49_KEY_CORE_V1` | The environment variable `NAME`, read once, exactly as set. |
| `file:/absolute/path` | `file:/etc/port49/keys/core-v1` | A file, with one trailing newline removed. The path must be absolute and already clean (no `..`, no doubled `/`). |

```yaml
keys:
  core:
    current: {version: 2, secret_ref: "file:/etc/port49/keys/core-v2"}
    accept:
      - {version: 1, secret_ref: "file:/etc/port49/keys/core-v1", retire_after: "2027-01-31"}
```

Two rules apply to both forms.

- **A reference that does not parse is refused without being printed.** The likeliest cause is the secret
  itself, pasted where its name goes. Rotate that secret.
- **An empty secret is refused.**

`encryption.current.secret_ref` and `encryption.previous.secret_ref` take the same two forms and must
come to exactly 32 bytes. They are listed in the [`encryption` reference](../reference/config/port49d.md#encryption).

### Where a policy may point: `key_secret_refs`

The policy file is written by the people who edit policy, and it is committed and reviewed. It must not be
able to choose which of the host's secrets becomes a device key. `port49d.yaml` therefore carries an
allowance, `key_secret_refs`, and a device key's `secret_ref` outside it is refused before anything is read:

| Key | Default | Allows |
|---|---|---|
| `key_secret_refs.env_prefix` | `PORT49_KEY_` | `env:` variables that start with it and are longer than it. At least 4 characters, ending in `_`. |
| `key_secret_refs.file_dir` | `/run/port49/keys` | `file:` paths below this directory. Absolute, clean, never `/`. |

Both need a restart; the full entries are in the [reference](../reference/config/port49d.md#key_secret_refs).
`port49-broker` refuses the key: it never holds a device key. `port49 policy test --config port49d.yaml`
checks a policy against your allowance in CI; without `--config` it checks the defaults and says so.

The three shapes set it like this:

| Shape | `key_secret_refs` | Key files |
|---|---|---|
| systemd | `file_dir: /etc/port49/keys` (the shipped `port49d.yaml`) | The directory is `root:port49d` mode 0750 and each file `root:port49d` 0440. `/run` is cleared at reboot, so the keys are not kept there. |
| Container (Compose) | the default, `/run/port49/keys` | A `port49d-keys` volume mounted read-only: directory `root:65532` 0750, files `root:65532` 0440. |
| Helm | the default, `/run/port49/keys` | One Secret mounted whole, one Secret key per version, in port49d's pod only. |

The encryption key is never under the key directory. A policy may name any file below `file_dir`, so a
sealing key kept there could be named as a device key. port49d's lives at `/etc/port49/secrets/encryption.key`
on all three shapes. On systemd the broker's copy, the same 32 bytes, is `/etc/port49/secrets/broker-encryption.key`. A port49d configuration that names key material inside `file_dir` is refused at start.

Prefer `file:`. An `env:` variable is read once and never again, and a new one cannot be added to a
running process, so a version that needs an `env:` name needs a restart. A file can be added while port49d
runs.

## The secret-file rule

Whoever can write a file decides who gets access to what it grants, so port49 reads a secret file only
when the file and everything above it are fenced. For a `file:` reference, port49d requires:

- **Owner.** The user port49 runs as, or root. Any other owner is refused with the uid named.
- **Mode.** No world bit, and no write bit for anyone but the owner. `0440` and `0600` pass. `0644`,
  `0660` and `0666` do not.
- **Group read needs a group port49 is in.** A group-readable file is accepted only when its group is
  the process's own group or one of its supplementary groups, such as Kubernetes' `fsGroup`. A file
  readable by a group the process is not in, such as Debian's `ssl-cert`, is refused: its members could
  read the secret too. `chgrp` it to the service's group.
- **ACLs.** A POSIX ACL is judged by its entries, not the mode. An entry naming any user but the
  process's or root, a group the process is not in, anyone with write, or other with anything, is refused.
- **Stay inside the allowed directory.** A link is followed (a Kubernetes Secret volume is made of links),
  but the file it comes to must lie inside `file_dir`. A link out to the TLS key is refused.
- **The directory holding the file.** Owned by the service user or root, and writable by nobody else. A
  read-only mount does **not** excuse it. The one excuse is a sticky directory (mode with the `t` bit, such
  as the Vault injector's 1777 volume) that the service user or root owns, and then only for a file with
  a single hard link.
- **The directories above it, and the directories that hold a link on the way.** Each is owned by the
  service user or root. An ancestor that others can write passes only if it is sticky or on a read-only
  mount; a directory holding a link passes on a read-only mount. A read-only mount trusts whoever writes
  its source, so bind only a directory that root or the service user alone can write.

Every refusal names the file and the fix, and none prints a byte of the secret. The text you will see is
like `... is group-readable by gid N, which this process is not in (gid M) ... chgrp it to the service's
group`; for a wrong owner, `... must belong to the user this process runs as ... or to root - chown it`.

## When a key file is not there yet

A key version whose file cannot be read yet (a Secret volume or an agent has not rendered it, a mode is
wrong) is a refusal that port49d tries again. A new policy that names such a file is not put in force;
the policy already serving stays. port49d tries again every 30 seconds until the file reads or the
policy file changes, and says so on the first refusal and then at most every ten minutes. A SIGHUP says
it again at once.

At a **start** the same file is not retried: a policy that names a file that is not there makes the start
refuse, and the unit or pod crash-loops until the file is back or the policy line is out. So put the key
file in place first and add the policy line second. To remove a key, take the policy line out first.

Once read, a file is never read as a key again. If a held file is later rewritten in place, or can no
longer be read, port49d keeps the secret it already holds and counts the version in
`port49_key_secret_files_changed` ([alert](../reference/alerts.md#port49_key_secret_files_changed)).
A restart would take the new bytes on that replica alone, which is how a fleet ends up with two replicas
holding two secrets. The cure is a new file under a new version, never an edit
([Key rotation](../admin/key-rotation.md#add-a-version-with-a-new-file)).

## Kubernetes

The chart mounts the device keys from one Secret, whole, at `/run/port49/keys` in port49d's pod only. The
pod sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch` and the volume `defaultMode` is
`0440`, so the files are owned by root, group 65532, mode 0440: the process's own group. Measured on
kind ([L82](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L82-kind.md), kind v0.29.0 with node image v1.33.1):

- With `defaultMode: 0440` and `fsGroup: 65532` the key file is `root` `0440` and port49d starts with it.
- A key added to the Secret appeared in a **whole** volume mount, and a login keyed with the new version
  passed with no container restart through External Secrets.
- A **`subPath`** mount of the same Secret did not change after three minutes while the whole mount did.
  Never mount device keys with `subPath`; the kubelet updates only a whole mount in place.

The broker's pod loads no device key. Each etcd client identity is its own Secret,
so neither pod holds the other's etcd key.

### Secret agents

port49 holds no client for any secret store. A store reaches it as a file that its own agent renders,
and the file has to pass the secret-file rule. Two agents were measured on kind
([L83](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L83-kind.md)):

| Mechanism | Device keys | Encryption key | Why |
|---|---|---|---|
| External Secrets syncing into a Secret volume | Supported | Supported | Measured in L82: a new version reaches a running process. |
| Vault Agent injector | **No** | Yes, with `vault.hashicorp.com/agent-run-as-same-user: "true"` | By default the agent is uid 100 and owns the rendered file, and port49d crash-loops on the owner rule. With `agent-run-as-same-user: "true"` the file is port49d's own and it starts. But a new version is a pod rollout, not a reload, so it fails the "no restart" requirement for a device key. |
| Secrets Store CSI driver | **No** | **No** | Its files are `root` mode `0644` (a world bit: refused), or `0440` with the provider's file permission set, which the process's user cannot read; the driver sets no group for `fsGroup` to act on. |

A device key must reach a running process with no restart, which is why only a mechanism that passes that
test is offered for one. The encryption key changes rarely, and a rollout is acceptable for it.

## systemd and containers

Both were measured in [L84](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L84-systemd-docker.md)
(systemd 255 and Docker Compose).

- **systemd.** `LoadCredential=` renders a file that passes the rule and may carry the encryption key for
  `port49d`. It cannot add a credential to a running unit, so device keys stay in `/etc/port49/keys`.
- **Compose `secrets:`.** The file must be `root:65532` mode 0440 on the host; Compose does not apply
  the long syntax's `uid`, `gid` or `mode`, and a `0444` file is refused. Adding a secret recreates
  port49d. It is not used for device keys.
- Never leave a secret in `docker inspect` output or a unit's `Environment=` line.

The install pages hold the exact commands for each shape: [systemd](install/systemd.md),
[container](install/container.md), [Helm](install/helm.md).
