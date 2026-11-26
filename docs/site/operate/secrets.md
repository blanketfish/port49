---
title: Secrets
description: Where port49's secrets live, who may read them, and how they are mounted on each deployment.
---

# Secrets

port49 holds three kinds of secret: the shared keys it shares with devices, the key that seals its stored
records, and the keys it uses for etcd and TLS. No secret is written in a configuration file, the policy or
a container's environment listing. Those carry only a name for the secret. The secret is a file that a
mount, a package or a secret agent puts on disk. Rotation is on [Key rotation](../admin/key-rotation.md).

## The secret reference

A key version in the policy names its secret with `secret_ref`:

| Form | Example | Meaning |
|---|---|---|
| `env:NAME` | `env:PORT49_KEY_CORE_V1` | The environment variable `NAME`, read once, exactly as set. |
| `file:/absolute/path` | `file:/etc/port49/keys/core-v1` | A file, with one trailing newline removed. The path must be absolute and clean (no `..`, no doubled `/`). |

```yaml
keys:
  core:
    current: {version: 2, secret_ref: "file:/etc/port49/keys/core-v2"}
    accept:
      - {version: 1, secret_ref: "file:/etc/port49/keys/core-v1", retire_after: "2027-01-31"}
```

A reference that does not parse is refused without being printed, because the likeliest cause is the secret
pasted where its name goes: rotate that secret. An empty secret is refused. Prefer `file:`: a file can be
added while port49d runs, but an `env:` variable is read once, so a new one needs a restart.
`encryption.current.secret_ref` and `encryption.previous.secret_ref` take the same forms and must be exactly
32 bytes ([`encryption` reference](../reference/config/port49d.md#encryption)).

### Where a policy may point: `key_secret_refs`

The policy is committed and reviewed, so it must not pick which of the host's secrets becomes a device key.
`port49d.yaml` carries an allowance, and a `secret_ref` outside it is refused before anything is read. The
keys need a restart ([reference](../reference/config/port49d.md#key_secret_refs)):
`key_secret_refs.env_prefix` (default `PORT49_KEY_`) and `key_secret_refs.file_dir` (default
`/run/port49/keys`; absolute, clean, never `/`). `port49-broker` refuses the key. `port49 policy test
--config port49d.yaml` checks a policy against your allowance in CI.

The encryption key is never under `file_dir`, because a policy could then name it as a device key. It is
`/etc/port49/secrets/encryption.key`, and on systemd the broker's copy is
`/etc/port49/secrets/broker-encryption.key`.

## The secret-file rule

Whoever can write a file decides who gets what it grants, so port49d reads a `file:` secret only when the
file and everything above it are fenced:

- Owner: the user port49 runs as, or root.
- Mode: no world bit, and no write bit for anyone but the owner. `0440` and `0600` pass; `0644` does not.
- Group read needs a group the process is in (its own, or a supplementary one such as Kubernetes'
  `fsGroup`). A file readable by another group, such as Debian's `ssl-cert`, is refused: `chgrp` it.
- A POSIX ACL is judged by its entries: any other user, a group the process is not in, anyone with write,
  or other with anything is refused.
- A link is followed, but the file it comes to must lie inside `file_dir`.
- The directory holding the file, and every directory above it, is owned by the service user or root and
  not writable by others. A read-only mount does not excuse the holding directory. The one excuse is a
  sticky directory the service user or root owns (the Vault injector's 1777 volume), for a file with one
  hard link.

Every refusal names the file and the fix, and none prints a byte of the secret.

## When a key file is not there yet

Put the key file in place first, then add the policy line. To remove a key, take the policy line out first.

While port49d runs, a new policy that names a missing file is not put in force and the policy already
serving stays. port49d retries every 30 seconds and says so on the first refusal, then at most every ten
minutes. At a start, a missing file is not retried: the unit or pod crash-loops until the file is back or
the policy line is out.

Once read, a file is never read as a key again. If a held file is rewritten in place, port49d keeps the
secret it holds and counts the version in `port49_key_secret_files_changed`
([alert](../reference/alerts.md#port49_key_secret_files_changed)), because a restart would give one replica
the new bytes. The cure is a new file under a new version
([Key rotation](../admin/key-rotation.md#add-a-version-with-a-new-file)).

## What each deployment does

systemd keeps device keys in `/etc/port49/keys` (`file_dir` is set there in the shipped config), containers
and Helm in `/run/port49/keys`. The install pages hold the commands:
[systemd](systemd/install.md), [containers](containers/install.md), [Helm](helm/install.md). The key that
seals records is made by `port49d key sealing` in each install.

### systemd: LoadCredential=

Measured in [L84](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L84-systemd-docker.md)
(systemd 255, Ubuntu 24.04, the shipped unit): systemd renders `LoadCredential=` files `root:root` 0440 with
an ACL granting only `port49d`, and the fence reads the ACL, so it passes. Use it for port49d's encryption
key, so the file on disk need not be readable by `port49d`:

1. In a drop-in (`systemctl edit port49d`), add
   `LoadCredential=encryption.key:/etc/port49/secrets/encryption.key`.
2. In `port49d.yaml`, set `encryption.current.secret_ref` to
   `file:/run/credentials/port49d.service/encryption.key`. Leave `file_dir` as shipped.

Device keys stay in `/etc/port49/keys`: systemd cannot add a credential to a running unit, and a restart
closes every session in flight. The broker's unit form was not measured, so the broker keeps a file
readable by `port49-broker`.

### Compose secrets

Compose's `secrets:` was measured in the same [L84](../reference/lab-register.md#l84) note. The host file must be `root:65532` mode 0440,
because Compose applies no `uid`, `gid` or `mode` from the long syntax and the fence refuses `0444`. Adding
a secret recreates port49d, so it is not used for device keys. It may carry the encryption key, which was
not measured on its own.

### Kubernetes

The chart mounts every secret as a file, never an environment variable, and never with `subPath`. The pod
sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch`, and the volume's `defaultMode` is `0440`,
so files are `root:65532` 0440. Measured on kind
([L82](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L82-kind.md), kind v0.29.0, node
image v1.33.1):

- A key added to the Secret appeared in a whole mount, and a login keyed with the new version passed with no
  restart through External Secrets.
- A `subPath` mount of the same Secret did not change after three minutes while the whole mount did, because
  the kubelet updates only a whole mount in place.

### Secret agents

port49 has no client for any secret store. A store reaches it as a file its agent renders, and the file has
to pass the secret-file rule. Two agents were measured on kind
([L83](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L83-kind.md)):

| Mechanism | Device keys | Encryption key | Why |
|---|---|---|---|
| External Secrets into a Secret volume | Yes | Yes | A new version reaches a running process ([L82](../reference/lab-register.md#l82)). `examples/external-secret.yaml` has one Secret key per version. |
| Vault Agent injector | No | Yes, with `vault.hashicorp.com/agent-run-as-same-user: "true"` | By default the agent is uid 100 and owns the file, and port49d refuses the owner. With the annotation the file is port49d's own. A new version is a pod rollout, not a reload, which fails a device key's no-restart need. |
| Secrets Store CSI driver | No | No | Its files are `root` 0644 (a world bit: refused), or 0440, which the process's user cannot read. The driver sets no group for `fsGroup` to act on. |

The encryption key changes rarely, so a rollout is acceptable for it.
