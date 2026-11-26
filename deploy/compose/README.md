# port49 on etcd, as containers

The stack is `port49d`, `port49-broker` and a three-member etcd with client-certificate auth, run with
Docker Compose.

<!-- --8<-- [start:trial] -->
The trial runs the whole stack on one host with a PKI that protects nothing real.

## 1. Start it

From the repository root:

```sh
go run ./tests/compose/cmd/compose-pki        # writes deploy/compose/local/ (valid 24h, git-ignored)
docker compose -f deploy/compose/compose.yaml up -d --build
```

Bring the whole stack up the first time, or run `docker compose build` first: only `setup` and
`port49-broker` build, and `etcd-init` and `port49d` reuse their tags. TACACS+ is published on
`127.0.0.1:49`, the broker on `127.0.0.1:8443`, and the metrics on `127.0.0.1:9049` (port49d) and
`127.0.0.1:9050` (the broker).

To check, run:

```sh
docker compose -f deploy/compose/compose.yaml ps
curl 127.0.0.1:9049/readyz
```

`port49d` and the broker show `healthy`, and `/readyz` answers `200`. `running` alone says only that the
process started. Each healthcheck runs `healthcheck --ready` every ten seconds, after a thirty-second
grace period.

## 2. Log in

Mint a token with the trial's client certificate (`alice@example.com`):

```sh
port49 login --broker https://127.0.0.1:8443 \
  --cert deploy/compose/local/broker/client.pem --key deploy/compose/local/broker/client-key.pem \
  --broker-ca deploy/compose/local/broker/broker-ca.pem
```

Success prints `port49: logged in to <broker>; the session ends at <time>`.

Five environment variables set the inputs, each with a default: `PORT49_COMPOSE_LOCAL` (`./local`),
`PORT49_COMPOSE_CONFIG` (`./config`), `PORT49_COMPOSE_SUBNET` (`172.30.49.0/24`),
`PORT49_TACACS_PUBLISH` (`127.0.0.1:49`) and `PORT49_BROKER_PUBLISH` (`127.0.0.1:8443`).
<!-- --8<-- [end:trial] -->

<!-- --8<-- [start:install] -->
Run the commands from `deploy/compose/`. `setup` runs as root at every `up` and copies each component's
files into a volume of its own, so no volume holds both etcd identities:

| Volume | Holds | Mounted in |
|---|---|---|
| `port49d-etc` | `port49d.yaml`, policy, inventory, etcd CA, port49d's etcd certificate and key, `secrets/encryption.key` | port49d, read-only |
| `port49d-keys` | the device keys, one file per version; the directory `root:65532` 0750, each file `root:65532` 0440 | port49d, read-only at `/run/port49/keys` |
| `broker-etc` | `port49-broker.yaml`, policy, inventory, etcd CA, the broker's etcd and TLS files, `secrets/broker-encryption.key` | port49-broker, read-only |
| `etcd-pki` | the CA and the three members' certificates and keys | etcd-1..3, read-only |
| `etcd-root` | etcd's root certificate and key, and `store-roles`' output | etcd-init only |
| `etcd-N-data` | each member's data | that member |
| `broker-state` | `broker.state_dir` | port49-broker |
| `port49d-spool` | the accounting spool | port49d |

No secret is in any container's environment, so `docker inspect` shows none. Each secret is a file.

!!! warning "Docker API access is root-equivalent"
    `docker run` with a volume reads every file in it. Guard the Docker socket as you would the host.

## 1. Build the images

```sh
docker compose build
```

To check, run `docker image ls --filter 'reference=port49*:dev'`. It lists `port49-setup:dev` and
`port49:dev`.

## 2. Bring your own PKI and secrets

Put them under `PORT49_COMPOSE_LOCAL`, in the layout `compose-pki` writes: `etcd/`, `broker/`,
`keys/tacacs_v1` and `secrets/encryption.key` with `secrets/broker-encryption.key`. A device key is the
shared secret you type into the device. The two sealing keys hold the same 32 bytes: make them once, with
the setup image, and the command writes both files under those names:

```sh
docker run --rm -v "$PWD/local/secrets:/s" --entrypoint port49d port49-setup:dev \
  key sealing --dir /s --daemon-user 0 --broker-user 0
```

To check, run `ls -l local/keys local/secrets`. The listing shows the device key and both sealing keys.

## 3. Edit the config

Edit `config/policy.yaml` and `config/inventory.yaml`. List each device by the address port49d sees. The
example sets `certificate_status.disabled`, which a deployment must not. Then pick the sign-in backend.

=== "OIDC"

    In `config/port49-broker.yaml`, replace `broker.client_ca_file` with the `broker.identity` block shown
    commented there. The broker must reach the provider's discovery and JWKS URLs; behind a proxy, set
    `HTTPS_PROXY` in the service's `environment:`. The rest is on
    [OIDC sign-in](https://blanketfish.github.io/port49/latest/admin/sign-in/oidc/).

=== "Client certificate (x509)"

    Replace the example's `certificate_status` with `ocsp:` or `crls:`. If your CA has no OCSP responder,
    use `crls:` before the first sign-in. See
    [Client certificates](https://blanketfish.github.io/port49/latest/admin/sign-in/x509/).

=== "Directory password"

    Uncomment the `broker.directory:` block in `config/port49-broker.yaml` and add a `directory_password`
    verifier. Put the keytab and `krb5.conf`, if the bind uses Kerberos, in the broker's configuration
    volume (`broker-etc`, under `/etc/port49/`), the keytab mode 0600 and owned by uid 65532. Set
    `PORT49_SITE` in the broker service's `environment:`. See
    [Directory password](https://blanketfish.github.io/port49/latest/admin/sign-in/directory-password/) and
    [The directory](https://blanketfish.github.io/port49/latest/admin/directory/).

!!! info "etcd's disk"
    etcd needs sustained WAL fsync p99 under 10 ms. See
    [Requirements](https://blanketfish.github.io/port49/latest/reference/requirements/#etcd-disk).

## 4. Start

```sh
docker compose up -d
```

`etcd-init` applies `port49d store-roles`' output once and enables auth. A later `up` changes nothing.
To check, run:

```sh
docker compose ps
curl 127.0.0.1:9049/readyz
curl 127.0.0.1:9050/readyz
```

`port49d` and `port49-broker` show `healthy`, and both `/readyz` calls answer `200` `serving`. The port49d
start line names all three etcd members at or above the floor (3.4.24, 3.5.8 or 3.6): see
`docker compose logs port49d`.

!!! warning "The shipped healthcheck probes with `--ready`"
    That is right for `docker compose`. Docker Swarm restarts a container that turns unhealthy, so adapt
    both `healthcheck` blocks first. See
    [Health checks](https://blanketfish.github.io/port49/latest/reference/health-checks/).

A published port may change the device's source address. Measured in
[L39](https://blanketfish.github.io/port49/latest/reference/lab-register/#l39): it is kept for an off-host
device, and masqueraded to the compose gateway for a device on another Docker network on the same host.

!!! warning "Unmeasured"
    A connection that docker-proxy itself relays has not been measured.

## 5. Keep broker.state_dir

`broker.state_dir` holds the revocation marks, the witness and the issuing CA. Give each broker one named
volume. Never use `--scale`, `deploy.replicas` or an anonymous volume. A second broker is a second service
with a volume of its own. A fresh named volume copies uid 65532, mode 0700 from the image. A volume
filled by hand and owned by root is not refused at start, but the first write fails. To fix it, run:

```sh
docker run --rm -v <volume>:/s alpine:3.22 sh -c 'chown 65532:65532 /s && chmod 0700 /s'
```

## 6. Make the issuing CA

Only when the broker issues certificates. On one broker:

```sh
docker compose exec port49-broker port49-broker init-issuer
docker compose restart port49-broker
```

The broker loads the CA at start, so it needs the restart. A second broker must hold the same CA, or it
refuses to start. Copy both files into its volume, then restart it:

```sh
docker run --rm -v port49_broker-state:/a -v port49_broker2-state:/b alpine:3.22 sh -c \
  'install -o 65532 -g 65532 -m 0600 /a/issuing-ca.key /b/ && install -o 65532 -g 65532 -m 0644 /a/issuing-ca.pem /b/'
```

To check, run `docker compose logs port49-broker`. The `issuing as ... (sha256:...)` line has the same
fingerprint on every broker.

## 7. Create the enrollment store

Only for directory password sign-in:

```sh
docker compose run --rm port49-broker init-enrollments
```

Success prints `created the enrollment store; password sign-in is on`. A broker that is already running
finds the store within 30 seconds, and until then its sign-ins answer `enrollment_store_lost`.

## 8. First device and first login

Add the device to the [inventory](https://blanketfish.github.io/port49/latest/admin/inventory/) and log in
as a person ([Log in](https://blanketfish.github.io/port49/latest/use/login/)). To check, run
`port49 ssh <device> -- show version`. It prints the device's output, and the decision log holds a
`redeem` record with `verdict: permit`.

## More

[Backup and restore](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/) covers each
etcd data volume and `broker-state`. For several regions, see
[Stores](https://blanketfish.github.io/port49/latest/operate/stores/#several-regions). Admin operations
are on [Admin access](https://blanketfish.github.io/port49/latest/admin/admin-access/).
<!-- --8<-- [end:install] -->

<!-- moved: docs/site/operate/secrets.md (Compose secrets) -->
Compose's own `secrets:` is not used for device keys: [Secrets](https://blanketfish.github.io/port49/latest/operate/secrets/).

<!-- moved: docs/site/admin/revocation.md (Break-glass) -->
Break-glass revoke with the broker unreachable: [Revoking access](https://blanketfish.github.io/port49/latest/admin/revocation/).

<!-- moved: docs/site/admin/key-rotation.md (Adding a key version) -->
Adding a device key version, and the order that avoids a crash-loop: [Key rotation](https://blanketfish.github.io/port49/latest/admin/key-rotation/#device-keys).

<!-- moved: docs/site/admin/key-rotation.md (Rotating the `encryption:` key) -->
Rotating the `encryption:` key: [Key rotation](https://blanketfish.github.io/port49/latest/admin/key-rotation/#the-encryption-key).

<!-- --8<-- [start:upgrade] -->
Read the [release notes](https://github.com/blanketfish/port49/releases) and
[Versions and upgrades](https://blanketfish.github.io/port49/latest/operate/versions/) first. They say whether
the release changes the roles, the config or the sealing key.

## 1. Rebuild and recreate

```sh
git pull
docker compose build
docker compose up -d
```

An `up -d` after the image was rebuilt recreates port49d and the broker, so a policy edit in the same
change arrives by a restart, not a reload. Rebuild and `up -d` as one change, then make policy edits
with a plain `up -d`.

To check, run:

```sh
docker compose ps
docker compose exec port49d port49d --version
curl 127.0.0.1:9049/readyz
```

Both containers are `healthy`, the version is the new one, and `/readyz` answers `200`.

## 2. Edit the policy separately

Edit `config/policy.yaml` on the host, then run `docker compose up -d`. `setup` copies it over the
volumes' copies at every `up`, and port49d reads it at `policy.watch_interval` with no restart. A policy
edited inside a volume is reverted at the next `up`.

## 3. Re-apply the roles when the release notes say so

`etcd-init` applies `port49d store-roles`' output once and finds auth enabled on every later `up`. When a
release changes the roles, apply the new output by hand as etcd's root. port49d does not apply it for you.
It refuses to start for some missing grants and names `port49d store-roles` in the line, but it does not
check every grant.
<!-- --8<-- [end:upgrade] -->

<!-- --8<-- [start:troubleshoot] -->
`docker compose logs port49d` (or `port49-broker`) holds the line.

`restart: unless-stopped` has no limit. A start that fails is tried again, with a restart delay that
grows to a minute, until you fix the cause or `docker compose stop` it. So `docker compose ps` shows a
restarting container, and the log repeats the line.

A port49d whose etcd is down at boot comes back on its own when etcd does.

## When it will not start

| Refusal | The line | Where | Fix |
|---|---|---|---|
| A secret file missing or unreadable | `config: encryption.current.secret_ref (id "c1") file:/etc/port49/secrets/encryption.key: open ...: permission denied` (or the file it names); a key file: `config: keys.k version 1 secret_ref file:/run/port49/keys/tacacs_v1: ...` | `docker compose logs port49d` | write the file as the volume table says (`setup` installs a key that is absent, and refuses one that differs; it never rewrites one) |
| The fence refuses a directory | `...is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it ...` | same | fix the mode the line names in the volume (`docker run --rm -v <volume>:/v alpine:3.22 chmod go-w /v/<dir>`) |
| A key readable by a group the container is not in | `...is group-readable by gid N, which this process is not in (gid M); ...` | same | the container's group is 65532: `chgrp 65532` the file in the volume (`chmod 0600` only if the container's user owns the file: on a `root:65532` file it makes the key unreadable) |
| The issuing CA differs from the store's | `issuance: this broker's issuing CA (...) is not the one the store records (...)` | `docker compose logs port49-broker` | copy `issuing-ca.pem` and `.key` from a broker that holds it |
| etcd below the floor | `etcd at <url> is version <v>, below the floor port49 needs (3.4.24, 3.5.8 or 3.6): ...` | `docker compose logs port49d` | upgrade the member |
| etcd unreachable at boot | a store refusal after `start_timeout` (30 s unless you set it), then the container restarts | `docker compose logs port49d` | nothing: it retries; start etcd |
| `setup` stops the stack naming a key file | `keys are never replaced in place` | `docker compose logs setup` | the file in `local/` differs from the one in the volume: restore the original, or add a new version file |
| The broker's first write fails on a root-owned volume | the broker cannot write `marks.json` or the witness | `docker compose logs port49-broker` | run the `chown` of install step 5 |

## When an admin command is refused

| You see | Cause | Fix |
|---|---|---|
| `port49: admin operations need a security key press, and your session key is in the TPM: ...`; exit 1, nothing sent | The session key is not on a security key (TPM, Secure Enclave, file) | log in with a session key on the security key |
| `401 admin_touch_refused: the touch slot's attestation does not verify: ...` | The attestation does not chain | add the root or intermediate to `attestation-roots.pem`, then `docker compose up -d` and `docker compose kill -s HUP port49-broker` |
| `503 admin_touch_unavailable: no attestation roots are configured ...` | No attestation roots | put the file at `PORT49_COMPOSE_LOCAL/broker/attestation-roots.pem` and run the same two commands |
| `hwkey: no touch within 15s; touch the key when it blinks and try again` | No touch in time | run it again |
| `port49 login --oidc` cannot sign in | Your certificate expired and the identity provider is down | another on-call admin revokes; break-glass only if none can |
| `503 store_unavailable` | The store is down | break-glass once the store is back but the broker is not |

A provider outage alone changes nothing: your port49 certificate is still valid, so revoke as usual. The
words every refusal prints are in the [3am index](https://blanketfish.github.io/port49/latest/operate/troubleshooting/).
<!-- --8<-- [end:troubleshoot] -->
