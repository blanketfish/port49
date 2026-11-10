# port49 on systemd

One peer shape beside containers and Kubernetes; nothing in port49 requires it. The
`port49-server` package (or the files here, copied by hand) gives you two units, one for each
process on etcd:

| Unit | Runs as | Does |
|---|---|---|
| `port49d.service` | `port49d` | TACACS+ on 49 (and, if you turn it on, TACACS+ over TLS on 300) |
| `port49-broker.service` | `port49-broker` | the login broker on 8443, the issuing CA, the directory |

The two users are separate on purpose: no process holds both etcd identities. The package creates them with `sysusers.d`; `tmpfiles.d` makes the directories, `/etc/port49` and its
`keys`, `secrets`, `etcd` and `broker` subdirectories among them.

## The four things every shape needs

1. **The device's source address reaches port49d unrewritten**. On a host this is
   the default; a NAT or a proxy in front of port 49 breaks it, because the inventory matches a
   device by the address port49d sees.
2. **On etcd, two processes.** port49d and port49-broker run apart, as the two units do. The
   memory store is one process and is for a trial.
3. **`broker.state_dir` survives a restart.** It holds `marks.json`, `witness.json` and the issuing
   CA. The unit's `StateDirectory=port49-broker` makes `/var/lib/port49-broker` 0700 and owned by
   `port49-broker`, and it is kept across restarts. Back it up with the host.
4. **etcd is port49's own cluster**, never another system's. It needs port49's roles, compaction,
   a quota and backups (below). It needs etcd 3.4.24, 3.5.8 or 3.6 or later: port49d refuses a
   member below that, and says which.

## Install

```sh
apt install ./port49-server_<version>_amd64.deb      # or the .rpm; it creates the users and directories
systemctl daemon-reload
```

The package never enables or starts a unit: configure first (below), then

```sh
systemctl enable --now port49d port49-broker
```

Without the package: put the four binaries in `/usr/bin`, the two `.service` files in
`/usr/lib/systemd/system/`, `sysusers.d/port49.conf` in `/usr/lib/sysusers.d/`,
`tmpfiles.d/port49.conf` in `/usr/lib/tmpfiles.d/`, then `systemd-sysusers` and
`systemd-tmpfiles --create`. Copy `config/` to `/etc/port49/` and edit it. The package puts it, this file, the etcd, snapshot
and export units and the store examples under `/usr/share/doc/port49-server/` (`examples/config/`,
`examples/systemd/`, `examples/stores/`, `README.systemd.md`).

Binding port 49 as `port49d` needs no file capability: the unit grants `CAP_NET_BIND_SERVICE`
as an ambient capability, and bounds the process to it.

## Where the secrets live

Every secret is a file; no secret is written into a config file, an environment variable or a
unit.

| File | Owner and mode | Holds |
|---|---|---|
| `/etc/port49/keys/` | `root:port49d` 0750 | the device keys, one file per version |
| `/etc/port49/keys/<name>-v<N>` | `root:port49d` 0440 | one version of a device's shared secret |
| `/etc/port49/secrets/encryption.key` | `port49d:port49d` 0400 | port49d's 32-byte sealing key |
| `/etc/port49/secrets/broker-encryption.key` | `port49-broker:port49-broker` 0400 | the broker's, the same 32 bytes |
| `/etc/port49/etcd/*-key.pem` | each process's own, 0400 | its etcd client key |
| `/etc/port49/broker/broker-key.pem` | `port49-broker:port49-broker` 0400 | the broker's TLS key; a root-owned 0600 file passes the key-file rule and then cannot be read by the broker |
| `/etc/port49/directory/svc-port49.keytab` | `port49-broker:port49-broker` 0600 | the directory's Kerberos keytab, if you use one |

The two encryption files hold one value and are owned apart, so neither process can read the
other's copy. They sit outside the key directory because a policy may name any file under
`key_secret_refs.file_dir`. Never put them there.

Make a sealing key (32 raw bytes) **once**, and install it for both processes. The recipe runs in
the destination directory, never in `/tmp` or under a name another user could have planted: each
temporary file is new and private, and is linked into place only after every step passed. It draws
again until the last byte is not a newline (a key file loses one trailing newline when it is read,
so such a key would load a byte short, one time in 256), gives up after ten draws, and exits
non-zero if anything fails, leaving no temporary file. It never overwrites: a hard link fails if
the name exists, so a key that is already there is refused ("... exists; pick a new key id"), never
replaced. `KEY_ID` names the key: empty makes `encryption.key` and `broker-encryption.key`, and
`e2` makes `encryption-e2.key` and `broker-encryption-e2.key`. Never reuse an id.

```sh
(
  KEY_ID=   # empty for the first key; e2, e3, ... for a rotation (below)
  umask 077 && cd /etc/port49/secrets || exit 1
  n=encryption${KEY_ID:+-$KEY_ID}.key; b=broker-encryption${KEY_ID:+-$KEY_ID}.key
  for f in "$n" "$b"; do
    [ ! -e "$f" ] && [ ! -L "$f" ] || { echo "port49: $f exists; pick a new key id" >&2; exit 1; }
  done
  t=; u=; trap 'rm -f "$t" "$u"' EXIT; trap 'exit 1' INT TERM HUP
  t=$(mktemp ./.key.XXXXXX) && u=$(mktemp ./.key.XXXXXX) || exit 1
  ok=
  for i in 1 2 3 4 5 6 7 8 9 10; do
    head -c 32 /dev/urandom > "$t" && [ "$(wc -c < "$t")" -eq 32 ] &&
      [ "$(tail -c1 "$t" | od -An -tx1 | tr -d ' ')" != 0a ] && ok=1 && break
  done
  [ -n "$ok" ] || { echo "port49: no usable 32-byte key in 10 draws" >&2; exit 1; }
  cat "$t" > "$u" && chown port49d:port49d "$t" && chown port49-broker:port49-broker "$u" &&
    chmod 0400 "$t" "$u" || { echo "port49: the sealing key was not made" >&2; exit 1; }
  ln "$t" "$n" || { echo "port49: $n exists; pick a new key id" >&2; exit 1; }
  ln "$u" "$b" || { rm -f "$n"; echo "port49: $b exists; pick a new key id" >&2; exit 1; }
)
```

**One key across hosts.** Running the recipe on a second host makes a *different* key, and the two
hosts could not open each other's records. Generate once; then copy the same two files to every
other host over a private channel (`scp encryption.key broker-encryption.key host:`), and on that
host install them with their owners, refusing to replace one:

```sh
(
  KEY_ID=   # the same as where it was made
  cd /etc/port49/secrets || exit 1
  pairs="encryption${KEY_ID:+-$KEY_ID}.key:port49d broker-encryption${KEY_ID:+-$KEY_ID}.key:port49-broker"
  for pair in $pairs; do   # refuse before installing either, so a host never holds half a pair
    f=${pair%%:*}
    if [ -e "$f" ] || [ -L "$f" ]; then echo "port49: $f exists" >&2; exit 1; fi
  done
  for pair in $pairs; do
    f=${pair%%:*}; o=${pair##*:}
    install -o "$o" -g "$o" -m 0400 "$HOME/$f" "$f" || { echo "port49: install of $f failed" >&2; exit 1; }
  done
)
```

Then `shred -u` the two copies in `$HOME`.

### Adding a key version

A device key is a file named in the policy. Add a version by writing a new file and a new
line; never rewrite a file in place. Hex gives 32 characters you can type into the device's CLI
(`tacacs-server key`, `key`, `secret`), and the newline the file ends in is dropped when it is read.

```sh
(
  DEVICE_KEY=core-v2   # a new name for every version: never an existing one
  umask 077 && cd /etc/port49/keys || exit 1
  [ ! -e "$DEVICE_KEY" ] && [ ! -L "$DEVICE_KEY" ] || { echo "port49: $DEVICE_KEY exists; pick a new key id" >&2; exit 1; }
  t=; trap 'rm -f "$t"' EXIT; trap 'exit 1' INT TERM HUP
  t=$(mktemp ./.key.XXXXXX) || exit 1
  openssl rand -hex 16 > "$t" && [ "$(wc -c < "$t")" -eq 33 ] && chown root:port49d "$t" && chmod 0440 "$t" ||
    { echo "port49: the device key was not made" >&2; exit 1; }
  ln "$t" "$DEVICE_KEY" || { echo "port49: $DEVICE_KEY exists; pick a new key id" >&2; exit 1; }
)
```

Then add `{version: 2, secret_ref: "file:/etc/port49/keys/core-v2"}` to the key set in the
policy under `current:` (moving the old one to `accept:` until each device carries the new key)
and `systemctl reload port49d`. Rotation is a reload, never a restart. port49d reads each key
file once; if one changes on disk afterwards it keeps the bytes it holds and says so (spec
§12), which is why a new version is a new file.

**Order matters.** Put the key file in place first, then add the policy line that names it. To remove a
key, take the policy line out first, then the file. The other order is a 3am outage: a policy line naming a
file that is not there makes port49d refuse its start (`lstat ...: no such file`), so on a restart it
crash-loops until you restore the file under `/etc/port49/keys` or take the policy line out; `Restart=` keeps retrying and the journal repeats the line.

## Issuing CA

`port49-broker init-issuer` makes the issuing CA on one broker, as the broker's user:

```sh
sudo -u port49-broker port49-broker init-issuer
```

Every further broker on the same etcd must hold the same CA, or it refuses to start. Copy both
files, from the first broker's `/var/lib/port49-broker/` to each other's, keeping them private:

```sh
install -o port49-broker -g port49-broker -m 0600 issuing-ca.pem issuing-ca.key /var/lib/port49-broker/
```

If every broker lost the CA, `port49-broker forget-issuer --current sha256:<fingerprint>` removes the
store's record of it, once; then `init-issuer` on one broker and copy again. `rotate-issuer`
rotates with an overlap (spec §13 decision 53).

## Admin operations

You run `port49 revoke` and `port49 directory ...` on your own workstation, through your agent;
nothing is run on the host. Each admin-level call asks for a press of your
security key, once per operation. An exposed certificate or token alone authorizes nothing admin-level.

For that, the broker needs three things.

- **Attestation roots**, so it can check your key: Yubico's PIV roots, in a PEM file, named from an
  `identity:` block (which replaces `client_ca_file`):

    ```yaml
    broker:
      identity:
        humans:
          - {type: x509, trust_anchor_file: /etc/port49/broker/client-ca.pem}
        per_login_mfa:
          hardware_key_touch: {attestation_roots_file: /etc/port49/broker/attestation-roots.pem}
    ```

- **The right**, in the policy, on subjects that name people by `identity:`:

    ```yaml
    subjects:
      - {name: oncall_a, identity: ["user:a@example.com"], api: [revoke_others, lift_revocations]}
      - {name: oncall_b, identity: ["user:b@example.com"], api: [revoke_others, lift_revocations]}
    ```

    Name at least two on-call admins by `identity:`, even if a `group:` subject also holds the
    right: a group's rights resolve through the directory, which may be down when you need them.

- **A session key on the security key**, from `port49 login` (`key: pkcs11:...`).

**Break-glass.** With every broker stopped, on a broker host, as the broker's user:

```sh
systemctl stop port49-broker              # on every broker host
sudo -u port49-broker port49-broker revoke --offline --principal user:bob@example.com
systemctl start port49-broker
```

`port49-broker revoke --offline --list` shows the marks. This stops issuance fleet-wide while the
brokers are down, so use it only when no admin can reach a running broker. A port49d that runs its broker
in process has `port49d revoke --offline`. Each needs the uid that owns the files it
writes, and as root refuses, revokes nothing and names the `sudo -u` line: `port49-broker revoke --offline` writes
`broker.state_dir` (the broker's user owns it), and `port49d revoke --offline` writes
`broker.revocations_file`.

### The 3am table

| Condition | What you see | What to do |
|---|---|---|
| Session key not on a security key (TPM, Secure Enclave, file) | `port49: admin operations need a security key press, and your session key is in the TPM: ...`; exit 1, nothing sent | log in with a session key on the security key |
| Attestation does not chain | `401 admin_touch_refused: the touch slot's attestation does not verify: ...` | add the root or intermediate to `attestation_roots_file`, then `systemctl reload port49-broker` |
| No touch in time | `hwkey: no touch within 15s; touch the key when it blinks and try again` | run it again |
| The identity provider is down | nothing: your port49 certificate is still valid | revoke as usual |
| Your certificate expired and the provider is down | `port49 login --oidc` cannot sign in | another on-call admin revokes; break-glass only if none can |
| No attestation roots configured | `503 admin_touch_unavailable: no attestation roots are configured ...` | set the file |
| The store is down | `503 store_unavailable` | `revoke --offline` once the store is back but the brokers are not |

## The directory, and the site

`broker.directory` is off. Turn it on from `deploy/compose/config/port49-broker.yaml`'s commented
block. A directory with a Kerberos bind needs a keytab: put it at `/etc/port49/directory/svc-port49.keytab`
(0600, owned by `port49-broker`) and the `krb5.conf` beside it. Set this broker's site, and any
other environment, with `systemctl edit port49-broker`:

```ini
[Service]
Environment=PORT49_SITE=hq
```

Run `port49-broker init-enrollments` once, as `port49-broker`, if you use directory password
sign-in, before the first start: a broker that is already running finds the new store within 30 seconds
(`port49-broker` says so), and until then its sign-ins answer `enrollment_store_lost`. Run `port49d init-revocations` once at install only for a port49d that holds its broker
in process (`broker.revocations_file`). Neither belongs in `ExecStartPre=`: they refuse when
anything is already there, and a unit must never initialize.

## Certificate status: the CRL and the roots

The broker checks whether a client certificate is revoked through `certificate_status`. The
shipped file asks each certificate's own OCSP responder. To use CRLs instead, name each under
`crls:` with a `file:` the broker can read (or a `url:`); a CRL served over https from a private
CA needs that CA's root in the broker's trust store, which is the system's, or a file named by
`SSL_CERT_FILE` in the unit (`systemctl edit port49-broker`). If your CA has no OCSP responder (AD CS
and step-ca often have none), switch to `crls:` before the first sign-in: the shipped setting
refuses every certificate whose CA names no responder, and the broker's log says why. Never set `disabled: true` outside a
trial.

## etcd

The two examples in `examples/` are for your etcd hosts. The three `etcd-N.yaml` files each set
`auto-compaction-mode: periodic`, `auto-compaction-retention: "10m"` and an 8 GiB quota, with TLS
and client-certificate auth. Install etcd 3.6.15 or later at `/usr/local/bin/etcd`, create the user
(`sysusers-etcd.conf`) and its data directory (`tmpfiles-etcd.conf`, `/var/lib/etcd` 0700; it also makes `/etc/etcd/pki` for the certificates), copy `etcd@.service`, and `systemctl enable --now etcd@etcd-1` on the first host, and so
on.

**etcd's disk.** etcd needs a disk with sustained WAL fsync p99 under 10 ms (etcd's own guidance;
datacenter NVMe or a cloud SSD volume). A drive that stalls pushes port49's store calls past the
500 ms call timeout in bursts. The `etcd_disk_slow` alert (`deploy/alerts`) fires when the WAL fsync
or backend commit p99 stays over its bound for 10 minutes. On a GCE pd-ssd (400 GB, declared by the operator) the load run passed every cell with a WAL fsync mean of 0.72 to 0.86 ms; a consumer QLC drive failed it (the notes are the `load-*` files in `tests/lab/results/`).
port49d's accounting spool directory needs the same, under 10 ms (port49's alert threshold, not etcd's figure): each accounting record is acked only after an fsync, so a slow-fsync disk caps accounting latency. The `port49_accounting_spool_disk_slow` alert watches it.

Then apply the roles once per cluster:

```sh
port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml
```

It prints the `etcdctl` commands that create the two roles; run them as etcd's root, once per
cluster (a directory with its own store prints two sections, one per cluster).

After a port49 upgrade that changes the roles, apply them again by hand; it is never done for you.

**Every config names every member's URL**, never a load balancer or a VIP, as both shipped files
do. port49d's start line names the members it checked: `port49d: stores.directory: etcd
https://etcd-1.example.com:2379 3.6.15, ... at or above the floor (3.4.24, 3.5.8 or 3.6)`.

Single-site and multi-region store blocks, complete files, are in
`deploy/examples/stores/single-site/` and `multi-region/`.

### Backups

`examples/port49-etcd-snapshot.{service,timer}` take an hourly snapshot into
`/var/backups/port49` (0700 root, `UMask=0077`), on an etcd host, since it needs etcd's root
certificate; it needs `examples/tmpfiles-etcd.conf` (the directory) and keeps two weeks.
`examples/port49-enrollments-export.{service,timer}` export the directory's sealed
enrollment store daily from a broker host, into a dated file in `/var/backups/port49-broker` (0700,
the broker's): the unit writes a temporary file and renames it, because systemd's `StandardOutput=file:`
does not truncate and a shorter export would keep the older one's tail. Run each once by hand before you
rely on its timer.
Each cluster has its own snapshot: the directory etcd's, and each region's session etcd.

## Two groups of servers

Two independently upgraded groups are two hosts, each with its own listen address, spool and
config; a second unit beside the first on one host needs its own `listen`, `metrics_listen` and
spool directory. Replace one at a time: start the new beside the old, then stop the old.

## TACACS+ over TLS on port 300

Uncomment `tls_listener:` in `port49d.yaml`, put the server certificate, its key and the device CA
in `/etc/port49/tls/` (the key 0400 owned by `port49d`), and open TCP 300 from your devices. It also
needs `certificate_status` (the block names it).

## Why `ProtectSystem=true`, not `strict`

The fence refuses a key or secret directory a group or another user can write. It excuses that
check on a read-only mount, since nothing there can change. `ProtectSystem=strict` or `full`, or
`ReadOnlyPaths=/etc`, would make `/etc` read-only inside the unit, so a group-writable
`/etc/port49` on the host would pass. `ProtectSystem=true` makes only `/usr`, `/boot` and `/efi`
read-only. The units set `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes` and a capability
bound, which leave `/etc` writable. The unit test (`tests/shapes`) holds each of these.

### `LoadCredential=` for the encryption key

Measured (lab [L84](https://blanketfish.github.io/port49/latest/reference/lab-register/#l84), `tests/lab/results/L84-systemd-docker.md`: systemd 255, Ubuntu 24.04, the shipped
unit's hardening): port49d reads a file that systemd renders from `LoadCredential=`. systemd gives the
credential `root:root 0440` with an ACL granting only `port49d`, in a directory with an ACL too, and
the fence reads the ACL's entries, so it passes. Use it for the encryption key, so the file on disk
need not be readable by `port49d`:

1. In a drop-in (`systemctl edit port49d`), add
   `LoadCredential=encryption.key:/etc/port49/secrets/encryption.key`; systemd reads the source as root.
2. In `/etc/port49/port49d.yaml`, set `encryption.current.secret_ref` to
   `file:/run/credentials/port49d.service/encryption.key`. Leave `key_secret_refs.file_dir` as
   shipped: the credentials directory is not a place a policy may name a device key from.

Device keys stay in `/etc/port49/keys`: adding a credential needs `systemctl restart port49d`. systemd
refuses `systemctl set-property LoadCredential=`, and a drop-in with `systemctl daemon-reload` does
not reach the running unit (its credentials directory keeps the files it started with). A restart
closes every session in flight, so adding a device credential that way would cost those sessions
each time. A host whose systemd renders no credentials directory (a container's did not) cannot use this.

This recipe is `port49d`'s alone. The broker's copy of the encryption key stays the file readable by
`port49-broker`: [L84](https://blanketfish.github.io/port49/latest/reference/lab-register/#l84) did not measure the broker unit's shape, so `LoadCredential=` is not claimed for it.

## Rotating the `encryption:` key

One key, everywhere, from one secret, in three steps. In each, `reload` is `systemctl reload`.

1. Make the new key once, on one host, with the recipe above and `KEY_ID=e2`: it leaves
   `encryption-e2.key` and `broker-encryption-e2.key` beside the old, which it never touches. Copy those two files to
   every other host ("One key across hosts"), never re-run the recipe there. Add it to every
   `port49d.yaml` and `port49-broker.yaml` as `previous:`, in every region, and reload
   everything. Every process now opens what either key sealed.
2. Swap: make `e2` `current:` and `e1` `previous:`, everywhere, and reload.
3. Remove `previous:` and the old file only after the scheduled directory pass (every
   `refresh_interval`) has re-sealed the second-factor records under `e2`: it marks a record it
   opened under the previous key and seals it again. A record that opens under neither key is
   never "not enrolled": that sign-in is `503 store_unavailable`, and the broker's line names
   `port49 directory reset-second-factor`.

A process whose window lacks the directory's current key id refuses to start, naming the
directory store and the id. Two store blocks reaching one etcd cluster at one prefix are
refused too.

## When it will not start

<!-- --8<-- [start:will_not_start] -->
`journalctl -u port49d -b` (or `-u port49-broker`) holds the line. Fix the cause and the next try
starts.

The units set no start limit, so a start that fails is tried again every ten seconds. A port49d whose
etcd is down at boot comes back on its own when etcd does. journald rate-limits a repeated line.

| Refusal | The line | Where | Fix |
|---|---|---|---|
| A secret file missing or unreadable | `config: encryption.current.secret_ref (id "e1") file:/etc/port49/secrets/encryption.key: open ...` naming the file; a key file: `config: keys.k version 1 secret_ref file:...: ...` | `journalctl -u port49d -b` | create it, owned and moded as the table above |
| The fence refuses a directory | `...is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it ...` | same | `chmod go-w` the directory the line names, or an ancestor of it |
| A key readable by a group the service is not in | `...is group-readable by gid N, which this process is not in (gid M); members of that group could read the secret too - chgrp it to the service's group ...` | same | `chgrp port49d` (or `port49-broker`) the file the line names. `chmod 0600` only if the service's user owns it: on the shipped `root:port49d 0440` file it leaves the key readable by root alone. A group such as Debian's `ssl-cert` is refused |
| A secret file's POSIX ACL names someone else | `...carries the ACL entry user:N:r--, a user that is neither this process's (uid M) nor root; it could read the secret too - remove it with setfacl -x u:N on the file (setfacl -b clears every extended entry)` | same | run the `setfacl` the line prints (`-x u:N` or `g:N` for a named entry; `-m g::-` or `-m o::-` for a base one) on the file it names, or `setfacl -b` it. port49d reads the ACL, not the mode's group bits (which are the ACL mask): a file with `group::---` and only port49d named is accepted |
| The issuing CA differs from the store's | `issuance: this broker's issuing CA (...) is not the one the store records (...)` | `journalctl -u port49-broker -b` | copy `issuing-ca.pem` and `.key` from a broker that holds it |
| etcd below the floor | `etcd at <url> is version <v>, below the floor port49 needs (3.4.24, 3.5.8 or 3.6): ...` | `journalctl -u port49d -b` | upgrade the member |
| etcd unreachable at boot | a store refusal after `start_timeout` (30 s unless you set it), then the unit restarts | `journalctl -u port49d -b` | nothing: it retries every ten seconds; start etcd |

<!-- --8<-- [end:will_not_start] -->
## The smoke test

`make systemd-smoke` installs the package under systemd in a container and drives it. The smokes run in CI
(`.github/workflows/systemd.yml`). Locally they refuse to start on a host with a TPM or a security key
(`/dev/tpm0`, `/dev/tpmrm0`, a Yubico device on the USB bus), because the container holds
`CAP_SYS_ADMIN` with no AppArmor profile and is not an isolation boundary; the refusal is one line that
names the device it found.
