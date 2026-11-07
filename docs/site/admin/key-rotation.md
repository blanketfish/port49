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

A device on TLS (RFC 9887) has no shared key to rotate. Its credential is its certificate; see [TLS](../operate/tls.md).
Where the secrets live and which files port49 will read is on [Secrets](../operate/secrets.md).

## Device keys

A device's key is a named **key set** in the policy's `keys:` block. A set has one `current` version, any
number of `accept` versions that still admit a device, and `retired` versions kept so a log line can name
the key a device tried. Key groups, the inventory pin and the device's own record decide which set a
device is admitted under; the set is where the versions live. Every key and its fields are in the
[policy reference](../reference/config/policy.md).

```yaml
keys:
  core:
    current: {version: 2, secret_ref: "file:/etc/port49/keys/core-v2"}
    accept:
      - {version: 1, secret_ref: "file:/etc/port49/keys/core-v1", retire_after: "2027-01-31"}
```

### Add a version with a new file

A version's secret never changes. port49d reads each key file once, when the version comes into force, and
holds what it read. So:

1. Make the new secret as a **new file** (`core-v2`) under the key directory, owned and moded as
   [the secret-file rule](../operate/secrets.md#the-secret-file-rule) says. Put the file in place first.
2. Edit the policy: the new version becomes `current`; the old one moves to `accept` with a `retire_after`
   date. Run `port49 policy test` and `port49 policy diff` in CI. `policy test` refuses a `secret_ref`
   outside `key_secret_refs`, and `diff` names any version that now points at a different reference.
3. port49d reads the policy file on its watch interval and at SIGHUP. A new version is in force for
   the next packet. Nothing restarts, and no open connection is cut by adding a version.
4. Put the new key on each device. `port49 keys show --policy FILE --inventory FILE DEVICE` says which
   key set a device is admitted under, by which rule, and which version to provision. It never prints the secret.
5. Watch the old version empty out (below), then remove it.

Never edit a key file in place, and never point an existing version at another reference. port49d refuses
a policy that gives a version a different `secret_ref` than the one it has held since it started. If a held
file is rewritten anyway, or can no longer be read, port49d keeps the bytes it holds, says
`keys.<name> version N: <path> has changed since port49d read it` (or, for an unreadable file,
`... can no longer be read (...); port49d keeps the secret it read, but a restart will refuse to start until
the file is back or the policy no longer names the version`), and sets
`port49_key_secret_files_changed` above 0 (alert
[port49_key_secret_files_changed](../reference/alerts.md#port49_key_secret_files_changed)). A restart would
take the new bytes on that replica alone, so two replicas would then hold two secrets for one version.
Put the new bytes in a new file under a new version number.

### If the file is not there yet

Adding the policy line before the file exists does not take effect, and does no harm to a running port49d:
the policy already serving stays in force, and the refusal is tried again every 30 seconds until the file
reads or the policy file changes. On Kubernetes this is the normal case for up to a couple of minutes after
you add a key to a Secret (the kubelet took 1m34s in the L82 run). A SIGHUP tries at once. After a restart the same mistake is a refused start, so a pod
crash-loops until the file is restored or the policy line is taken out.

To remove a key, take the policy line out first, then the file.

### Phasing out the old version

`retire_after` is the last day (UTC) an `accept` version admits a device. From midnight after it, the
version admits none: the device's next packet on it is a struck failure and the connection is reset at
once, so its next connections meet the strike backoff (`held_refused`). A policy edit that removes a
version or moves it to `retired` resets connections on it at their next packet with no strike. An `accept` version
with no `retire_after` is reported by `port49 policy test` as an indefinitely accepted version, which is
what rotation exists to prevent.

To see who is still on the old version, run `port49 keys status` against the port49d log and the policy:

```sh
port49 keys status --policy policy.yaml --inventory inventory.yaml /var/log/port49/port49d.log
```

It infers, from each device's latest validated login, which version the device presented. The same fact is
the gauge `port49_key_version_devices{key_ref,version}` and, for how long is left,
`port49_key_retirement_seconds`; the alerts
[port49_key_retirement_within_7d](../reference/alerts.md#port49_key_retirement_within_7d) and
[port49_key_retirement_within_1d](../reference/alerts.md#port49_key_retirement_within_1d) fire before a
device is locked out. The series are in the [metrics reference](../reference/metrics.md).

A device that cannot log in after a rotation is the usual question. `port49d keys-diagnose --device NAME
--capture FILE` takes a capture of the device's first packet, tries every version port49d holds, retired
ones included, and says which one validates. It prints no byte of the packet or of a key.

### `single_device`

The key metrics are labelled by `key_ref`. A name that admits exactly one device would be that device's
name in a metric, and port49 puts no device identity in a metric label. So a key held by exactly one
device (a pin, or a key group of one) is reported under `key_ref="single_device"` and `version="any"`.
For those, `port49_key_version_devices` counts the single-device keys on a version that has a
`retire_after`, and `port49_key_retirement_seconds` is the least time left among them. Which device is on
which version is `port49 keys status`'s answer. A key held by two or more devices keeps its own label.

`single_device` is therefore a reserved name: a policy or an inventory that names it as a `key_ref` is
refused at load. Pick another name for the set.

## The `encryption:` key

port49 seals tokens, receipts, contexts and second-factor records at rest under `encryption.current`.
`encryption.previous` is an optional second key that records can still be opened with, which is what makes
rotation possible. The ids label every sealed record, so the new key needs a **new id**. port49 refuses a
`previous` whose id equals `current`'s, but it cannot see a new secret put under an old id: records
sealed earlier then fail to open, with no warning at the start. Always give a new key a new id. Both keys are 32 bytes; their fields are in the
[reference](../reference/config/port49d.md#encryption). Every region holds the same set, and the key
is the same value in port49d and in the broker.

Rotation is three steps. **Finish each step in every region, on every port49d and every port49-broker,
before you begin the next.** Each step is a configuration change and a restart.

1. **Add the new key as `previous`** everywhere. The old key stays `current`. Nothing is sealed under the
   new key yet, but every process can now open what either key seals.
2. **Swap.** The new key becomes `current` and the old key `previous`, everywhere. New records are sealed
   under the new key, and a process that has not swapped yet can still open them, because step 1 gave it
   that key.
3. **Remove `previous`** everywhere, only when the conditions below hold. Keep the old key file as
   described there.

Why the order cannot be changed. In step 1 no process seals under the new key, so a process that has not
restarted yet is never handed a record it cannot open. In step 2 every process already holds both keys, so
the swap can happen one process at a time. Step 3 is the only step that makes records unreadable, so it
comes last. Run step 3 on one process early and that process opens nothing a not-yet-swapped neighbour
still seals under the old key.

Do not run step 3 until the records sealed under the old key are gone or re-sealed:

- With directory password sign-in, second-factor records and the enrollment mark are re-sealed by the
  broker's scheduled directory pass (every `refresh_interval`). Wait for a pass to complete after step 2.
  If the broker says `the re-seal could not open N second factors; encryption.previous cannot be retired
  while they are sealed under it`, do not run step 3.
- Tokens, receipts and contexts are short-lived, and the scheduled pass above does not re-seal them. Wait
  after step 2 finished everywhere for the **largest** of: `session.max_session_age_default` plus
  `session.grace_window` (port49d.yaml; 12 hours plus 10 minutes by default, and a policy role can only
  lower it), `receipt_max_age` (2 hours by default), `session.staleness_ceiling` (4 hours by default, the
  age of the snapshots a stopped process is read from), 20 minutes (a token lives at most 15, and the
  idempotency records that carry minted tokens are kept under 20), and the **directory membership lease**,
  (24 hours: `broker.directory.grace` is capped at 24 hours, and the lease is the larger of the two). Every verify reads a principal's membership record before it
  rewrites it, so a record sealed under the old key keeps failing, for that principal, until its lease runs
  out; this holds on a single shared store as well as on a split. Tokens are also purged at every start on etcd. Records still under the old key after step 3 do not open: a token is dropped
  from the candidates and counted in `port49_crypt_open_failures_total{record="token"}`, a session's context is
  denied `store_unavailable`, and a second factor is never treated as "not enrolled". For that second factor an
  operator runs `port49 directory reset-second-factor`.
- **Directory pins are never re-sealed. On a directory store that holds pins (a split, or more than one
  region), do not run step 3 at all: keep the old key as `encryption.previous`.** A pin is kept with no
  expiry, and an unchanged pin is never written again, so a pin sealed under the old key stays sealed under
  it. Drop that key and reading the pin fails with an unknown-key error (`ErrUnknownKey`). That failure is
  not "not found" and not "unavailable", so the pin write for that principal fails too, and a broker on
  the split cannot mint or refresh for anyone pinned before the rotation. The hourly directory check
  does **not** warn about this, because the recorded current key is the new one and is held. What you see:
  the broker's scheduled refresh line `broker: refresh: the directory failed for <principal> (crypt: opening
  membership: ...); its contexts are left unstamped and unrevoked`, the counter
  `port49_crypt_open_failures_total{record="membership"}` rising, and bind, mint and refresh failing for
  the pinned principals. Sessions already open are, by my reading of the code, left as they are until
  `session.staleness_ceiling` (4 hours by default) and then denied `context_stale`; I did not measure that.
  The cure is to put the old key back as `previous` and restart; nothing was deleted.
- **A store that holds pins can rotate once.** There is one `previous` slot. A second rotation's step 1
  must put the newer key in it, which drops the first key and strands the pins sealed under it, exactly as
  step 3 would. If you must rotate again anyway (a key you believe is exposed), the way out for each
  stranded principal is `port49 directory forget <principal>`. It does not need to open the record: it
  deletes the pin, and the person's next verification pins whatever entry the directory then gives them.
  The cost is the pin's protection: a pin exists so a principal cannot silently move to another directory
  entry, so confirm each is the same person first, as on [Stores](../operate/stores.md). A forget needs the
  `forget_principals` right, and each use takes a security-key press. Do it for every pinned principal;
  there is no bulk form. This region's own session copy of the record, sealed under the dropped key, is
  deleted by the forget only if it opens; otherwise it keeps failing until its 24-hour lease ends.
  **The admin has to be able to open their own pin.** The forget call first resolves the caller's own
  membership, to check the right, and an admin whose own pin is sealed under the dropped key is refused
  there. There is no offline forget on `port49-broker`. Before a second rotation, confirm that at least one
  admin's own pin still opens: an admin first pinned after the earlier rotation's step 2, or one whose pin
  has been rewritten since. If none does, do not rotate; if every admin is stranded, put the dropped key back
  as `previous`, which opens every pin again.
- **Backups and exports need every key that sealed their records.** An etcd snapshot and a Velero backup
  are the raw stores, and each record in them keeps the key that was current when that record was written.
  An enrollment export (`port49-broker export-enrollments`) keeps each record's seal too, and seals only
  its envelope under the key current at export time. So a backup taken between steps 2 and 3 needs both
  keys, and any backup needs every key that was current while its records were written.
  `port49 directory import` refuses a file sealed under a key the broker does not hold and tells you to set
  that key as `previous`. Keep every old key file, offline, as long as any backup that holds its records is
  kept; restoring without it loses the second factors and pins sealed under it, and each enrolled person must
  then run `port49 directory reset-second-factor`. Velero also stores the encryption Secret in the bucket, so
  a Velero restore brings back the key its backup was taken with, and that bucket must be guarded like the key.

If a process starts without a key the store was last written under, what you see depends on the store:

- On a directory store of its own, the start is refused, naming the store and the key id. Fix `encryption:`
  and start again.
- On the session store, the start goes on. port49d (and `port49-broker`, in its own name) says that the store was last written by a process whose
  current key it does not hold, the sessions sealed under that key are denied `store_unavailable`, none is
  revoked, and `port49_crypt_store_key_unknown` is 1
  ([alert](../reference/alerts.md#port49_crypt_store_key_unknown)). If the key was retired by mistake, set it
  as `previous` again and restart.

The recipes that make the key file, with the right owner and mode and without ever overwriting an old one,
are in each shape's install page: [systemd](../operate/install/systemd.md),
[container](../operate/install/container.md), [Helm](../operate/install/helm.md).
See also [Stores](../operate/stores.md#one-set-of-encryption-keys-everywhere).

## The issuing CA

This applies only when the broker issues certificates (`broker.identity.issuance` is set). Every broker on
one store must issue from the same CA. The CA is two files in `broker.state_dir`, `issuing-ca.pem` and
`issuing-ca.key`, and the store holds a record of the CA's fingerprint, never its key.

### First install

Run `init-issuer` **once**, on one broker, as that broker's user:

```sh
sudo -u port49-broker port49-broker init-issuer
```

(`port49d init-issuer` does the same under port49d's configuration.) It writes the key first, then the
certificate, owner-only. It refuses a configuration without `issuance:`. Run again where a whole CA already
is, it writes nothing and says so; a half CA (a key without the certificate, or the reverse) it refuses,
and it never replaces one.

Then **copy both files to every other broker's `broker.state_dir`**, keeping them private (`0600`, the
broker's user), and restart each. Never run `init-issuer` on a second broker: that would make a different
CA. The Helm chart's `scripts/copy-issuer.sh` does the copying and refuses to overwrite a different CA.

**Compare the fingerprints.** Each broker's start prints a line like
`issuing as <subject> (sha256:<fingerprint>), valid until <date>`. Read that line on every broker; the
fingerprints must be identical. The first broker to start on a store writes its fingerprint as the store's
record, and every later broker is held to it.

### The three refusals

A broker whose CA does not match the record refuses to start, and the line names what to do. At 3am
there are three, all from `issuance:` in the broker's journal or `kubectl logs`:

| You see | It means | Do |
|---|---|---|
| `issuance: this broker's issuing CA (<fingerprint>) is behind a promotion: the store records <fingerprint>, promoted from it by <broker> at <time>. Copy issuing-ca.pem, issuing-ca.key and issuing-ca-previous.pem from that broker into broker.state_dir, then start` | A rotation was promoted on another broker and this one missed the copy. | Copy those three files from the broker named, then start. |
| `issuance: this broker's issuing CA (<fingerprint>) is not the one the store records (<fingerprint>, by <broker> at <time>): every broker on one store issues from one CA. Copy issuing-ca.pem and issuing-ca.key from a broker that holds it ...` | This broker holds a different CA than the store records, usually a second `init-issuer` or a restored old volume. | Copy `issuing-ca.pem` and `issuing-ca.key` from a broker that holds the recorded one. Do not run `init-issuer`. |
| `issuance: the store's issuing CA record kept changing under this start; start again` | Two brokers were writing the record at once. | Start again. |

Do **not** reach for `forget-issuer` for any of these. It is for one case only: every broker lost the CA
and no copy exists.

### `forget-issuer`

```sh
port49-broker forget-issuer --current sha256:<fingerprint>
```

It removes the store's record of the CA so a new one can be made, then `init-issuer` on one broker and a
copy to the others. It names the fingerprint it forgets, so a record that holds a different CA is kept; and
it deletes at the revision it read, so a broker that recorded in the meantime keeps its record. After it,
every certificate the old CA issued stops working. Stop every broker on the store before starting one on
another CA. The current fingerprint is the one a broker's start line prints.

### `rotate-issuer`

`rotate-issuer` replaces the CA with an overlap, so the certificates already issued stay valid. It is run on
**one** broker, twice, with copies between:

1. **Stage.** `rotate-issuer` makes `issuing-ca-next.pem` and `issuing-ca-next.key`. Copy the **certificate
   only** (`issuing-ca-next.pem`) to every other broker and restart each, so every broker trusts it. The key
   stays on this broker. This broker loads the CA only at its start, so restart it too before it promotes.
2. **Promote.** Run `rotate-issuer` again on the same broker. The current certificate becomes
   `issuing-ca-previous.pem`, the staged pair becomes current. Copy `issuing-ca.pem`, `issuing-ca.key` and
   `issuing-ca-previous.pem` to every other broker, remove the staged `issuing-ca-next.pem` there, and restart each,
   and restart this one too, which holds the old CA in memory until it does.
   Each issues with the new CA and still trusts the previous one.
3. **Retire.** After `certificate_lifetime` has passed since the promotion, remove
   `issuing-ca-previous.pem` from every broker and restart each.

Step 1 before step 2 is what keeps anyone out: a broker that trusts the staged certificate can verify a
certificate issued under it the moment another broker promotes. A promotion is refused while a previous CA
from an earlier rotation is still there, since certificates it issued may still be valid. An interrupted
promotion is finished by running it again. An expired CA is recovered the same way: run `rotate-issuer`
twice, restarting every broker after each. The alerts
[port49_issuing_ca_expiring](../reference/alerts.md#port49_issuing_ca_expiring) and
[port49_issuing_ca_missing](../reference/alerts.md#port49_issuing_ca_missing) say when.

## The inventory service's signing key

The inventory service signs each bundle with `signing_key_file`. port49d verifies every bundle against the public keys in
`inventory.service.verify_key_files`: list two while the key rotates, the old key's public key and the
new key's, and SIGHUP re-reads the list. The fields are in the
[service reference](../reference/config/port49-inventory.md) and the
[port49d reference](../reference/config/port49d.md).

A bundle names its signing key by an id, the first 8 bytes of the SHA-256 of the public key. A verifier
picks the verify key with that id; if two files in the list carry the same id (the same key listed under
two paths), the last one listed is the one a document is checked against. List each public key once. A
document that does not verify is refused with `the document's signature by <id> does not verify`, and one
signed by a key no file holds with `the document is signed by <id>, which no verify key holds`.
