---
title: Key rotation
description: Rotating the devices' shared secrets and port49's encryption setting without locking anyone out.
---

# Key rotation

Four things rotate, each on its own schedule and each safe in only one order:

1. the **device keys**, the secrets shared with RFC 8907 devices (a policy edit, no restart);
2. the **`encryption:` key** that seals port49's stored records (three config steps, each a restart);
3. the **issuing CA**, when the broker issues certificates (`rotate-issuer`);
4. the inventory service's **signing key**, when you run one.

A device on TLS (RFC 9887) has no shared key to rotate: its credential is its certificate ([TLS](../operate/tls.md)).
Where the secrets live and which files port49 will read is on [Secrets](../operate/secrets.md).

## Device keys

A device's key is a named **key set** in the policy's `keys:` block. A set has one `current` version, any number of
`accept` versions that still admit a device, and `retired` versions kept so a log line can name the key a device tried.
Key groups, the inventory pin and the device's own record decide which set a device is admitted under. Every key and
field is in the [policy reference](../reference/config/policy.md).

```yaml
keys:
  core:
    current: {version: 2, secret_ref: "file:/etc/port49/keys/core-v2"}
    accept:
      - {version: 1, secret_ref: "file:/etc/port49/keys/core-v1", retire_after: "2027-01-31"}
```

### Add a version with a new file

port49d reads each key file once, when the version comes into force, and holds what it read. So a new version is a new
file, never an edit.

1. Make the new key as a **new file**, owned and moded as
   [the secret-file rule](../operate/secrets.md#the-secret-file-rule) says. The command refuses a name that exists,
   prints where the key is and never the key. The key is 32 hex characters you can type into the device's CLI (`tacacs-server key`, `key`, `secret`); the
   newline the file ends in is dropped when it is read. Type it in from the file.

    === "systemd"

        ```sh
        sudo port49d key device core-v2   # a new name for every version
        ```

        It writes `/etc/port49/keys/core-v2`, `root:port49d` 0440.

    === "Containers"

        From the repository root, with the project name `port49` (`docker compose -p` changes the volume prefix):

        ```sh
        docker run --rm -v port49_port49d-keys:/k --entrypoint port49d port49-setup:dev \
          key device tacacs_v2 --dir /k --device-owner 0 --device-group 65532
        ```

        The file is `0:65532`, 0440, in the `port49d-keys` volume. The policy names it as
        `file:/run/port49/keys/tacacs_v2`.

    === "Helm"

        Add the key to the device keys Secret as `<ref>_v<N>`, for example `core_v2` (recreate the Secret with both
        `--from-file` entries, never a literal), or add a remote key and an entry to the ExternalSecret.

2. Edit the policy: the new version becomes `current`, the old one moves to `accept` with a `retire_after` date. Run
   `port49 policy test` and `port49 policy diff` in CI. `policy test` refuses a `secret_ref` outside
   `key_secret_refs`, and `diff` names any version that now points at a different reference.
3. Apply the policy. A new version is in force for the next packet, and no open connection is cut.

    === "systemd"

        `systemctl reload port49d`. port49d also reads the policy on its watch interval.

    === "Containers"

        `docker compose up -d` copies `config/policy.yaml` into both `-etc` volumes. port49d reads it at
        `policy.watch_interval` (5 s here), so `port49_key_secret_files_changed` stays 0.

    === "Helm"

        `helm upgrade` with `--set-file policy=policy.yaml`.

4. Put the new key on each device. `port49 keys show --policy FILE --inventory FILE DEVICE` says which key set a device
   is admitted under, by which rule, and which version to provision. It never prints the secret.
5. Watch the old version empty out (below), then remove it.

!!! warning "File first, policy line second"
    Put the key file in place first, then add the policy line that names it. To remove a key, take the policy line out
    first, then the file. The other order is a 3am outage: a policy line naming a file that is not there makes port49d
    refuse its start (`lstat ...: no such file`), so on a restart it crash-loops until you restore the file or take the
    line out. On systemd, `Restart=` keeps retrying and the journal repeats the line. In Compose, `docker compose ps`
    shows a restarting container and `docker compose logs port49d` the line. On Helm the pod shows `CrashLoopBackOff`
    and `kubectl logs --previous` repeats it.

A running port49d is not harmed by a policy line that is early: the policy already serving stays in force, and the
refusal is tried again every 30 seconds until the file reads or the policy file changes (a SIGHUP tries at once). On
Kubernetes this is normal for a couple of minutes after you add a key to a Secret (the kubelet took 1m34s in the
[L82](../reference/lab-register.md#l82) run).

**Never edit a key file in place, and never point an existing version at another reference.** port49d refuses a policy
that gives a version a different `secret_ref` than the one it has held since it started. A rewritten file sets
`port49_key_secret_files_changed` above 0 (alert
[port49_key_secret_files_changed](../reference/alerts.md#port49_key_secret_files_changed)): put the new bytes in a new
file under a new version.

??? info "When a held key file changes or goes missing"
    port49d keeps the bytes it holds and says `keys.<name> version N: <path> has changed since port49d read it` (or
    `... can no longer be read (...); port49d keeps the secret it read, but a restart will refuse to start until the
    file is back or the policy no longer names the version`). A restart would take the new bytes on that replica alone,
    leaving two replicas with two secrets for one version.

### Phase out the old version

`retire_after` is the last day (UTC) an `accept` version admits a device. From midnight after it, the version admits
none: the device's next packet on it is a struck failure and the connection is reset at once, so its next connections
meet the strike backoff (`held_refused`). A policy edit that removes a version or moves it to `retired` resets
connections on it at their next packet, with no strike. `port49 policy test` reports an `accept` version with no
`retire_after` as indefinitely accepted, which is what rotation exists to prevent.

To see who is still on the old version:

```sh
port49 keys status --policy policy.yaml --inventory inventory.yaml /var/log/port49/port49d.log
```

It infers, from each device's latest validated login, which version the device presented. The same fact is the gauge
`port49_key_version_devices{key_ref,version}` and, for how long is left, `port49_key_retirement_seconds`. The alerts
[port49_key_retirement_within_7d](../reference/alerts.md#port49_key_retirement_within_7d) and
[port49_key_retirement_within_1d](../reference/alerts.md#port49_key_retirement_within_1d) fire before a device is locked
out ([metrics](../reference/metrics.md)).

A device that cannot log in after a rotation: `port49d keys-diagnose --device NAME --capture FILE` takes a capture of the
device's first packet, tries every version port49d holds, retired ones included, and says which validates. It prints no
byte of the packet or of a key.

A key held by exactly one device is reported under `key_ref="single_device"` and `version="any"`, because a metric label never names a
device: `port49 keys status` says which device is on which version. The name is reserved
([inventory](../reference/config/inventory.md), [metrics](../reference/metrics.md)).

## The `encryption:` key

port49 seals tokens, receipts, contexts, directory memberships and pins, and second-factor records at rest under
`encryption.current`. `encryption.previous` is an optional second key that records can still be opened with, which is
what makes rotation possible. Both are 32 bytes ([reference](../reference/config/port49d.md#encryption)). Every region
holds the same set, and the key is the same value in port49d and in the broker.

**Always give a new key a new id.** The ids label every sealed record. port49 refuses a `previous` whose id equals
`current`'s, but it cannot see a new secret put under an old id: records sealed earlier then fail to open, with no
warning at the start.

Rotation is three steps. **Finish each step in every region, on every port49d and every port49-broker, before you
begin the next.** Each is a configuration change and a restart.

1. **Add the new key as `previous`** everywhere. The old key stays `current`. Nothing is sealed under the new key yet,
   but every process can now open what either key seals.
2. **Swap.** The new key becomes `current` and the old key `previous`, everywhere. A process that has not swapped yet
   can still open the new records, because step 1 gave it the key.
3. **Remove `previous`** everywhere, only when [the waits below](#before-step-3) are over.

The order cannot change. In step 1 no process seals under the new key. In step 2 every process holds both keys, so the
swap can go one process at a time. Step 3 is the only step that makes records unreadable, so it is last: run early, it
opens nothing a not-yet-swapped neighbor still seals under the old key.

=== "systemd"

    Make the new key once, on one host: `sudo port49d key sealing --id e2` leaves `encryption-e2.key` and
    `broker-encryption-e2.key` beside the old, which it never touches. On every other host, install it with `--import`
    (see [Put the secrets in place](../operate/systemd/install.md)) and never run `key sealing` there. Add it to every
    `port49d.yaml` and `port49-broker.yaml` as `previous:` in every region, and run `systemctl restart` on each service.
    For step 2, swap `current:` and `previous:` in both files; for step 3, remove `previous:` and the old file.

=== "Containers"

    One command makes the pair, in the setup image, from any directory (project `port49`; `docker compose -p` changes
    the volume prefix). It refuses a name that exists, never replaces one and leaves nothing behind on a failure.

    ```sh
    docker run --rm -v port49_port49d-etc:/e -v port49_broker-etc:/b --entrypoint port49d port49-setup:dev \
      key sealing --id c2 --dir /e/secrets --broker-dir /b/secrets --daemon-user 65532 --broker-user 65532
    ```

    Add `previous: {id: c2, secret_ref: file:/etc/port49/secrets/encryption-c2.key}` to `config/port49d.yaml` and the
    same with `file:/etc/port49/secrets/broker-encryption-c2.key` to `config/port49-broker.yaml`, run
    `docker compose up -d` (setup copies the config files), then `docker compose restart port49d port49-broker`. Step 2
    makes `c2` `current:` and `c1` `previous:` in both files. For step 3, remove the old key from `local/secrets/` **first** (`encryption.key` and
    `broker-encryption.key` are the old key's), so an `up` in between cannot install it again, then from the volumes:
    `docker run --rm -v port49_port49d-etc:/e -v port49_broker-etc:/b alpine:3.22 rm /e/secrets/encryption.key /b/secrets/broker-encryption.key`,
    with the old file's name. Setup skips a sealing key that is in neither place, so once the config no longer names the old file, every later `up`
    starts clean and the old key stays gone.

=== "Helm"

    The Secret holds each key as its own file, and `encryption.key` and `encryption.previous.key` name them. For step 1,
    add `encryption-e2` to the Secret (32 bytes, `--from-file`, never a literal), keep the old `encryption.key`, and
    upgrade with `--set encryption.previous.id=e2 --set encryption.previous.key=encryption-e2`. For step 2, upgrade with
    `--set encryption.id=e2 --set encryption.key=encryption-e2 --set encryption.previous.id=<old id>
    --set encryption.previous.key=encryption.key`. For step 3, remove `encryption.previous` and the old file. The chart
    refuses a `previous` with no file, the same id, or the same file as `current`.

A process whose keys lack the id the directory store currently holds refuses to start, naming the store and the id. See
also [Stores](../operate/stores.md#one-set-of-encryption-keys-everywhere).

??? info "A process that starts without the session store's key"
    The start goes on: port49d (and `port49-broker`, in its own name) says so, sessions sealed under that key are
    denied `store_unavailable`, none is revoked, and `port49_crypt_store_key_unknown` is 1
    ([alert](../reference/alerts.md#port49_crypt_store_key_unknown)). If the key was retired by mistake, set it as
    `previous` again and restart. Two store blocks reaching one etcd cluster at one prefix are refused.

### Before step 3

Do not remove `previous` until every record sealed under the old key is gone or re-sealed. Second factors and pins are
re-sealed by the broker's scheduled directory pass (every `refresh_interval`); tokens, receipts and contexts expire.

!!! warning "Step 3 is the only step that loses data"
    Records still under the old key after step 3 do not open. A token is dropped and counted in
    `port49_crypt_open_failures_total{record="token"}`, a session's context is denied `store_unavailable`, and a
    second factor is never treated as "not enrolled": run `port49 directory reset-second-factor` for it.

??? info "Second factors"
    With directory password sign-in, second-factor records and the enrollment mark are re-sealed by the scheduled pass.
    Wait for a pass to complete after step 2. If the broker says `the re-seal could not open N second factors;
    encryption.previous cannot be retired while they are sealed under it`, do not run step 3.

??? info "Tokens, receipts and contexts"
    The scheduled pass does not re-seal these. After step 2 has finished everywhere, wait for the **largest** of:

    - `session.max_session_age_default` plus `session.grace_window` (12 hours plus 10 minutes by default; a policy role
      can only lower it);
    - `receipt_max_age` (2 hours by default);
    - `session.staleness_ceiling` (4 hours by default, the age of the snapshots a stopped process is read from);
    - 20 minutes (a token lives at most 15, and the idempotency records that carry minted tokens are kept under 20);
    - the **directory membership lease** (24 hours: `broker.directory.grace` is capped at 24 hours, and the lease is
      the larger of the two).

    The lease counts because every verify reads a principal's membership record before it rewrites it, so a record sealed
    under the old key keeps failing for that principal until its lease runs out. This holds on a single shared store
    too. Tokens are also purged at every start on etcd.

??? info "Directory pins"
    Pins (on a directory store of its own: a split, or more than one region) are re-sealed by the same pass. A pin has
    no expiry, so it never ages out. After step 2 has finished everywhere, wait for a pass that ended after the last
    step-2 restart (`port49_directory_pins_reseal_last_complete_timestamp_seconds` later than that restart) **with
    `port49_directory_pins_sealed_previous` at 0.**

    - Read both on the replica that holds the keyspace (`port49_store_keyspace_held` 1), because a replica that handed
      it over keeps its last pass's values until it restarts. Any region's holder will do.
    - The gauges are absent until a runner completes its first pass after it starts, and on a single shared store,
      where a membership record has a lease and there is no pin to re-seal.

    Its budget is half `refresh_interval`, so a large fleet can take several intervals to finish its first pass. While
    step 2 rolls out, regions on different `current` keys move pins back and forth: finish step 2 promptly. The lines
    the pass prints are in the
    [3am index](../operate/troubleshooting/index.md#a-directory-pin-is-not-re-sealed-or-does-not-open).

??? info "A pin that opens under neither key"
    A key was retired while it still sealed pins: `port49_directory_pins_unopenable` counts them, and bind, mint and
    refresh fail for that principal. The fix is in the
    [3am index](../operate/troubleshooting/index.md#a-directory-pin-is-not-re-sealed-or-does-not-open).

### Rotating again

There is one `previous` slot, so a rotation's step 1 drops whatever key `previous` held. Begin a rotation only after the
last one's step 3. Only pins have a gauge; a second factor is under `current` once a pass has completed without the
`could not open N second factors` line and without `sign-in: the re-seal of second factors stopped`.

### Backups and exports need every key that sealed their records

Keep every old key file, offline, as long as any backup that holds its records is kept
([Backup and restore](../operate/backup-and-restore.md#what-to-back-up)).

## The issuing CA

This applies only when the broker issues certificates (`broker.identity.issuance` is set). Every broker on one store
must issue from the same CA: two files in `broker.state_dir`, `issuing-ca.pem` and `issuing-ca.key`. The store records
the CA's fingerprint, never its key. First install is a step in each install guide: run `init-issuer` **once**, on one
broker, then copy both files to the others and never run `init-issuer` on a second broker, which would make a different
CA. Each broker's start prints `issuing as <subject> (sha256:<fingerprint>), valid until <date>`; the fingerprints must
match on every broker.

A broker whose CA does not match the record refuses to start, and the line, from `issuance:` in the broker's journal or
`kubectl logs`, names what to do. Do **not** reach for `forget-issuer` for any of them. It is for one case only: every
broker lost the CA and no copy exists.

A start that fails with `issuance: this broker's issuing CA (<fingerprint>) is ...` means this broker holds a
different CA than the store records, or missed a promotion: copy the files from a broker that holds the recorded
one, and never run `init-issuer`. The `kept changing under this start` line means two brokers wrote the record at
once: start again. The lines are in [Helm troubleshooting](../operate/helm/troubleshoot.md) ("behind a
promotion") and [systemd troubleshooting](../operate/systemd/troubleshoot.md) ("The issuing CA differs").

??? info "forget-issuer"
    ```sh
    port49-broker forget-issuer --current sha256:<fingerprint>
    ```

    It removes the store's record of the CA so a new one can be made: then `init-issuer` on one broker and a copy to the
    others. The fingerprint is the one a broker's start line prints, and a record that holds a different CA is kept.
    After it, every certificate the old CA issued stops working. Stop every broker on the store before starting one on
    another CA.

### `rotate-issuer`

`rotate-issuer` replaces the CA with an overlap, so certificates already issued stay valid. Run it on **one** broker,
twice, with copies between:

1. **Stage.** `rotate-issuer` makes `issuing-ca-next.pem` and `issuing-ca-next.key`. Copy the **certificate only**
   (`issuing-ca-next.pem`) to every other broker and restart each, so every broker trusts it. The key stays on this
   broker, which loads the CA only at its start, so restart it too before it promotes.
2. **Promote.** Run `rotate-issuer` again on the same broker. The current certificate becomes `issuing-ca-previous.pem`
   and the staged pair becomes current. Copy `issuing-ca.pem`, `issuing-ca.key` and `issuing-ca-previous.pem` to every
   other broker, remove the staged `issuing-ca-next.pem` there, and restart each, and this one too. Each issues with the
   new CA and still trusts the previous one.
3. **Retire.** After `certificate_lifetime` has passed since the promotion, remove `issuing-ca-previous.pem` from every
   broker and restart each.

Step 1 before step 2 keeps anyone out: a broker that trusts the staged certificate can verify a certificate issued under
it the moment another broker promotes. A promotion is refused while a previous CA from an earlier rotation is still
there. An interrupted promotion, or an expired CA, is recovered by running `rotate-issuer` again (twice for an expired
CA), restarting every broker after each. The alerts
[port49_issuing_ca_expiring](../reference/alerts.md#port49_issuing_ca_expiring) and
[port49_issuing_ca_missing](../reference/alerts.md#port49_issuing_ca_missing) say when.

## The inventory service's signing key

The inventory service signs each bundle with `signing_key_file`. port49d verifies every bundle against the public keys in
`inventory.service.verify_key_files`: list two while the key rotates, the old key's and the new key's, and SIGHUP
re-reads the list. The fields are in the [service reference](../reference/config/port49-inventory.md) and the
[port49d reference](../reference/config/port49d.md).

A bundle names its signing key by an id, the first 8 bytes of the SHA-256 of the public key. If two files in the list
carry the same id (one key listed under two paths), the last one listed is what a document is checked against, so list
each public key once. A document that does not verify is refused with `the document's signature by <id> does not
verify`, and one signed by a key no file holds with `the document is signed by <id>, which no verify key holds`.
