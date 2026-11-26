# port49 on systemd

port49 runs as two systemd units, `port49d` and `port49-broker`, on your own etcd. The `port49-server`
package installs them.

<!-- --8<-- [start:install] -->
The package installs two units. Neither is enabled or started until you do it.

| Unit | Runs as | Does |
|---|---|---|
| `port49d.service` | `port49d` | TACACS+ on 49 (and, if you turn it on, TACACS+ over TLS on 300) |
| `port49-broker.service` | `port49-broker` | the login broker on 8443, the issuing CA, the directory |

The [Install overview](https://blanketfish.github.io/port49/latest/operate/deploy/) lists what to have
ready.

## 1. Install the package

```sh
sudo apt install ./port49-server_<version>_amd64.deb      # or the .rpm, with your rpm tool
```

The package creates the two users and the directories under `/etc/port49`. To check, run:

```sh
systemctl list-unit-files 'port49*'
id port49d && id port49-broker
```

Both units show `disabled`, and `id` prints both users.

## 2. Install etcd

port49 needs its own etcd cluster of three members, version 3.6.15 or later at `/usr/local/bin/etcd`.
Do this on each etcd host, from `/usr/share/doc/port49-server/examples/systemd/` (`deploy/systemd/examples/`
in a checkout):

```sh
sudo install -m 0644 sysusers-etcd.conf /usr/lib/sysusers.d/etcd.conf
sudo install -m 0644 tmpfiles-etcd.conf /usr/lib/tmpfiles.d/port49-etcd.conf
sudo systemd-sysusers etcd.conf && sudo systemd-tmpfiles --create port49-etcd.conf
sudo install -m 0644 etcd@.service /etc/systemd/system/
sudo install -m 0644 etcd-1.yaml /etc/etcd/          # etcd-2.yaml on the second host, and so on
```

Edit each member file for your names and put its certificates in `/etc/etcd/pki/`. The examples turn on
TLS and client-certificate auth, periodic compaction every 10 minutes and an 8 GiB quota. Then start each
member:

```sh
sudo systemctl enable --now etcd@etcd-1       # etcd-2, etcd-3 on the others
```

!!! info "etcd's disk"
    etcd needs sustained WAL fsync p99 under 10 ms: datacenter NVMe or a cloud SSD volume. See
    [Requirements](https://blanketfish.github.io/port49/latest/reference/requirements/#etcd-disk).

To check, run this with etcd's root client certificate:

```sh
export ETCDCTL_ENDPOINTS=https://etcd-1.example.com:2379 ETCDCTL_CACERT=/etc/etcd/pki/ca.pem \
       ETCDCTL_CERT=<root-client.pem> ETCDCTL_KEY=<root-client-key.pem>
etcdctl endpoint health --cluster
```

Success prints three lines, each saying `is healthy`.

## 3. Put the secrets in place

Every secret is a file. No secret goes into a config file, an environment variable or a unit.

| File | Owner and mode | Holds |
|---|---|---|
| `/etc/port49/keys/<name>-v<N>` | `root:port49d` 0440 | one version of a device's shared secret |
| `/etc/port49/secrets/encryption.key` | `port49d:port49d` 0400 | port49d's 32-byte sealing key |
| `/etc/port49/secrets/broker-encryption.key` | `port49-broker:port49-broker` 0400 | the broker's copy, the same 32 bytes |
| `/etc/port49/etcd/*-key.pem` | each process's own, 0400 | its etcd client key |
| `/etc/port49/broker/broker-key.pem` | `port49-broker:port49-broker` 0400 | the broker's TLS key |

The two encryption files hold one value and sit outside `/etc/port49/keys`, which a policy may name files from.

Make the sealing key once, on one host:

```sh
sudo port49d key sealing
```

On every other host, copy one of the two files over a private channel and import it. A second
`key sealing` would make a different key, and the hosts could not open each other's records:

```sh
sudo cat /etc/port49/secrets/encryption.key | ssh host 'umask 077; cat > encryption.key'   # on the first host
ssh host 'sudo port49d key sealing --import encryption.key && shred -u encryption.key'
```

Then make a key for each device, one new name per version:

```sh
sudo port49d key device example-v1     # the name the example policy's secret_ref uses
```

It prints where the key is, never the key. Read it from the file to type into the device. To check, run:

```sh
sudo ls -l /etc/port49/secrets /etc/port49/keys
```

The listing shows the owners and modes of the table.

## 4. Configure

Copy the examples from `/usr/share/doc/port49-server/examples/config/` to `/etc/port49/` and edit them.
Name every etcd member's URL in each store block, never a load balancer or a VIP. Complete store blocks
are in `examples/stores/single-site/` and `multi-region/`. Then pick the sign-in backend.

=== "OIDC"

    In `port49-broker.yaml`, replace `client_ca_file` with an `identity:` block that has an `oidc` human
    verifier and `issuance:`. Register port49 at the provider first.
    [OIDC sign-in](https://blanketfish.github.io/port49/latest/admin/sign-in/oidc/) has the block.

=== "Client certificate (x509)"

    The shipped `client_ca_file` trusts your client CA. If the CA has no OCSP responder (AD CS and step-ca
    often have none), set `certificate_status` to `crls:` before the first sign-in: the shipped setting
    refuses every certificate whose CA names no responder. Never set `disabled: true` outside a trial.
    [Client certificates](https://blanketfish.github.io/port49/latest/admin/sign-in/x509/) has the block.

=== "Directory password"

    Turn on `broker.directory` and add a `directory_password` verifier. A directory with a Kerberos bind
    needs its keytab at `/etc/port49/directory/svc-port49.keytab` (0600, owned by `port49-broker`) and
    `krb5.conf` beside it. Set the broker's site with `sudo systemctl edit port49-broker`:

    ```ini
    [Service]
    Environment=PORT49_SITE=hq
    ```

    [Directory password](https://blanketfish.github.io/port49/latest/admin/sign-in/directory-password/) and
    [The directory](https://blanketfish.github.io/port49/latest/admin/directory/) have the blocks.

`store-roles` in step 5 reads both files first and refuses a missing etcd identity, naming the key.

## 5. Apply port49's roles to etcd

`store-roles` reads the two configs and prints the `etcdctl` commands that create port49's two roles.
Run them once per cluster as etcd's root (a directory with its own store prints two sections):

```sh
port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml > roles.sh
sh roles.sh        # with the ETCDCTL_* variables of step 2 set
```

To check, run `etcdctl role list`. It lists `port49_broker` and `port49_daemon`.

## 6. Make the issuing CA

Only when the broker issues certificates (OIDC and directory password do; x509 may). On one broker:

```sh
sudo -u port49-broker port49-broker init-issuer
```

Every other broker on the same etcd must hold the same CA, or it refuses to start. Copy
`issuing-ca.pem` and `issuing-ca.key` from `/var/lib/port49-broker/` to each, keeping them private:

```sh
install -o port49-broker -g port49-broker -m 0600 issuing-ca.pem issuing-ca.key /var/lib/port49-broker/
```

To check, run `sudo journalctl -u port49-broker -b` after step 8. The `issuing as ... (sha256:...)` line
has the same fingerprint on every broker.

## 7. Create the enrollment store

Only for directory password sign-in. Run it once, before the first start:

```sh
sudo -u port49-broker port49-broker init-enrollments
```

Success prints `created the enrollment store; password sign-in is on`. A broker that is already running
finds the store within 30 seconds, and until then its sign-ins answer `enrollment_store_lost`. Never put
this in `ExecStartPre=`: it refuses when anything is already there, and a unit must never initialize.

## 8. Start

```sh
sudo systemctl enable --now port49d port49-broker
```

To check, run:

```sh
port49d healthcheck --ready && port49-broker healthcheck --ready
journalctl -u port49d -b | grep 'at or above the floor'
```

Both healthchecks exit 0. The port49d line names every etcd member and the floor (3.4.24, 3.5.8 or 3.6).
If a unit does not start, see [Troubleshoot systemd](https://blanketfish.github.io/port49/latest/operate/systemd/troubleshoot/).

## 9. Enable the backups

Copy the units from `examples/systemd/`. On an etcd host, `port49-etcd-snapshot.{service,timer}` take an
hourly snapshot into `/var/backups/port49`. On a broker host, `port49-enrollments-export.{service,timer}`
export the enrollment store daily. Set `ETCDCTL_ENDPOINTS`, `ETCDCTL_CACERT`, `ETCDCTL_CERT` and
`ETCDCTL_KEY` for the snapshot unit with `systemctl edit`. Run each service once by hand, then enable its
timer. To check, run:

```sh
systemctl list-timers 'port49-*'
```

Each timer shows a next run. [Backup and restore](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/)
says what else to keep.

## 10. First device and first login

Add the device to the [inventory](https://blanketfish.github.io/port49/latest/admin/inventory/) and log
in as a person ([Log in](https://blanketfish.github.io/port49/latest/use/login/)). To check, run:

```sh
port49 ssh <device> -- show version
```

The command prints the device's output, and the decision log holds a `redeem` record with
`verdict: permit`.

## Optional steps

- [TACACS+ over TLS on port 300](https://blanketfish.github.io/port49/latest/operate/tls/)
- [`LoadCredential=` for the sealing key](https://blanketfish.github.io/port49/latest/operate/secrets/)

## Manual install

Without the package, do step 1 by hand:

1. Put the four binaries in `/usr/bin` and the two `.service` files in `/usr/lib/systemd/system/`.
2. Put `sysusers.d/port49.conf` in `/usr/lib/sysusers.d/` and `tmpfiles.d/port49.conf` in
   `/usr/lib/tmpfiles.d/`.
3. Run `systemd-sysusers port49.conf`, `systemd-tmpfiles --create port49.conf` and
   `systemctl daemon-reload`. To check, run the commands of step 1.
4. Copy `config/` to `/etc/port49/` and carry on from step 2.
<!-- --8<-- [end:install] -->

Adding a device key version, and the order that avoids a crash-loop: [Key rotation](https://blanketfish.github.io/port49/latest/admin/key-rotation/#device-keys).

Rotating the `encryption:` key: [Key rotation](https://blanketfish.github.io/port49/latest/admin/key-rotation/).

Break-glass revoke with every broker down: [Revoking access](https://blanketfish.github.io/port49/latest/admin/revocation/).

What the backup units do: [Backup and restore](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/).

TACACS+ over TLS on port 300: [TLS](https://blanketfish.github.io/port49/latest/operate/tls/).

`LoadCredential=` for the encryption key: [Secrets](https://blanketfish.github.io/port49/latest/operate/secrets/).

<!-- --8<-- [start:upgrade] -->
Read the [release notes](https://github.com/blanketfish/port49/releases) and
[Versions and upgrades](https://blanketfish.github.io/port49/latest/operate/versions/) first. They say whether
the release changes the roles, the config or the sealing key.

## 1. Upgrade the package on one host

```sh
sudo apt install ./port49-server_<version>_amd64.deb      # or the .rpm
sudo systemctl restart port49d port49-broker
```

The package reloads systemd's unit files and never restarts a unit, so the restart is yours. A restart
closes the sessions in flight on that host. To check, run:

```sh
port49d --version
port49d healthcheck --ready && port49-broker healthcheck --ready
```

The version is the new one, and both healthchecks exit 0.

## 2. Re-apply the roles when the release notes say so

Run `port49d store-roles` as in the install and run its output as etcd's root. port49d does not apply
roles for you. It refuses to start for some missing grants and names `port49d store-roles` in the line, for
example `the daemon's role cannot read meta/witness`. It does not check every grant, so do not wait for a
refusal.

## 3. Replace one group of servers at a time

Two groups that upgrade independently are two hosts, each with its own `listen`, `metrics_listen` and spool
directory. A second unit beside the first on one host needs its own three. Start the new group beside the
old, check it as in step 1, then stop the old one. Upgrade one host at a time within a group.
<!-- --8<-- [end:upgrade] -->

<!-- --8<-- [start:troubleshoot] -->
`journalctl -u port49d -b` (or `-u port49-broker`) holds the line. Each refusal names the file, the setting
or the key. Fix the cause and the next try starts.

The units set no start limit, so a start that fails is tried again every ten seconds. A port49d whose
etcd is down at boot comes back on its own when etcd does. journald rate-limits a repeated line.

## When it will not start

| Refusal | The line | Where | Fix |
|---|---|---|---|
| A secret file missing or unreadable | `config: encryption.current.secret_ref (id "e1") file:/etc/port49/secrets/encryption.key: open ...` naming the file; a key file: `config: keys.k version 1 secret_ref file:...: ...` | `journalctl -u port49d -b` | create it, owned and moded as the table in the install steps |
| The fence refuses a directory | `...is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it ...` | same | `chmod go-w` the directory the line names, or an ancestor of it |
| A key readable by a group the service is not in | `...is group-readable by gid N, which this process is not in (gid M); members of that group could read the secret too - chgrp it to the service's group ...` | same | `chgrp port49d` (or `port49-broker`) the file the line names. `chmod 0600` only if the service's user owns it: on the shipped `root:port49d 0440` file it leaves the key readable by root alone. A group such as Debian's `ssl-cert` is refused |
| A secret file's POSIX ACL names someone else | `...carries the ACL entry user:N:r--, a user that is neither this process's (uid M) nor root; it could read the secret too - remove it with setfacl -x u:N on the file (setfacl -b clears every extended entry)` | same | run the `setfacl` the line prints (`-x u:N` or `g:N` for a named entry; `-m g::-` or `-m o::-` for a base one) on the file it names, or `setfacl -b` it. port49d reads the ACL, not the mode's group bits (which are the ACL mask): a file with `group::---` and only port49d named is accepted |
| The issuing CA differs from the store's | `issuance: this broker's issuing CA (...) is not the one the store records (...)` | `journalctl -u port49-broker -b` | copy `issuing-ca.pem` and `.key` from a broker that holds it |
| etcd below the floor | `etcd at <url> is version <v>, below the floor port49 needs (3.4.24, 3.5.8 or 3.6): ...` | `journalctl -u port49d -b` | upgrade the member |
| etcd unreachable at boot | a store refusal after `start_timeout` (30 s unless you set it), then the unit restarts | `journalctl -u port49d -b` | nothing: it retries every ten seconds; start etcd |
| A key file is missing after a restart | `lstat ...: no such file` | `journalctl -u port49d -b` | restore the file under `/etc/port49/keys`, or take the policy line that names it out |

## When an admin command is refused

| You see | Cause | Fix |
|---|---|---|
| `port49: admin operations need a security key press, and your session key is in the TPM: ...`; exit 1, nothing sent | The session key is not on a security key (TPM, Secure Enclave, file) | log in with a session key on the security key |
| `401 admin_touch_refused: the touch slot's attestation does not verify: ...` | The attestation does not chain | add the root or intermediate to `attestation_roots_file`, then `sudo systemctl reload port49-broker` |
| `503 admin_touch_unavailable: no attestation roots are configured ...` | No attestation roots | set `attestation_roots_file` and reload |
| `hwkey: no touch within 15s; touch the key when it blinks and try again` | No touch in time | run it again |
| `port49 login --oidc` cannot sign in | Your certificate expired and the identity provider is down | another on-call admin revokes; break-glass only if none can |
| `503 store_unavailable` | The store is down | `revoke --offline` once the store is back but the brokers are not |

A provider outage alone changes nothing: your port49 certificate is still valid, so revoke as usual. The
words every refusal prints are in the [3am index](https://blanketfish.github.io/port49/latest/operate/troubleshooting/).
<!-- --8<-- [end:troubleshoot] -->

## More

- [Install overview](https://blanketfish.github.io/port49/latest/operate/deploy/)
- [Admin access](https://blanketfish.github.io/port49/latest/admin/admin-access/)
- [Deployment design](https://blanketfish.github.io/port49/latest/contributing/deployment-design/): why the
  units are hardened the way they are, and the smoke test
