# port49 on etcd, as containers

One peer shape beside systemd and Kubernetes; nothing in port49 requires it. The stack is
`port49d`, `port49-broker` and a three-member etcd with client-certificate auth. `make
compose-smoke` brings it up on a fresh PKI, logs a device in, recreates every container with
its volumes kept, and checks the session, a token minted before the recreate, and the broker's
`broker.state_dir` all survived. It also checks that port49d names all three etcd members at or
above the version floor, that a device key version added by writing a file takes effect with no
restart, that an admin revoke with no key press is refused, that the break-glass revoke and lift
work, and that no secret is in any container's environment. CI runs it on every pull request.

## Trial

From the repository root:

```sh
go run ./tests/compose/cmd/compose-pki        # writes deploy/compose/local/ (valid 24h, git-ignored)
docker compose -f deploy/compose/compose.yaml up -d --build
```

Mint a token with the trial's client certificate (`alice@example.com`):

```sh
port49 login --broker https://127.0.0.1:8443 \
  --cert deploy/compose/local/broker/client.pem --key deploy/compose/local/broker/client-key.pem \
  --broker-ca deploy/compose/local/broker/broker-ca.pem
```

Bring the whole stack up the first time, or run `docker compose build` first: only `setup` and
`port49-broker` build, and `etcd-init` and `port49d` reuse their tags.

The trial PKI protects nothing real. TACACS+ is published on `127.0.0.1:49`, the broker on
`127.0.0.1:8443`, and each component's metrics on `127.0.0.1:9049` and `127.0.0.1:9050`.

**Ready is not "running".** The stack has no healthchecks (planned with plan 13), so
`docker compose ps` showing `running` says only that the process started. Check readiness from
the host with `curl 127.0.0.1:9049/readyz` (port49d) and `curl 127.0.0.1:9050/readyz` (the
broker), on the metrics ports; a `200` is ready, anything else or no answer is not.

Inputs, each an environment variable with a default: `PORT49_COMPOSE_LOCAL` (`./local`),
`PORT49_COMPOSE_CONFIG` (`./config`), `PORT49_COMPOSE_SUBNET` (`172.30.49.0/24`),
`PORT49_TACACS_PUBLISH` (`127.0.0.1:49`), `PORT49_BROKER_PUBLISH` (`127.0.0.1:8443`).

## The files

`setup` runs as root at every `up` and copies each component's files into a volume of its own,
so no volume holds both etcd identities (plan 7e, Ruling 1):

| Volume | Holds | Mounted in |
|---|---|---|
| `port49d-etc` | `port49d.yaml`, policy, inventory, etcd CA, port49d's etcd certificate and key, `secrets/encryption.key` | port49d, read-only |
| `port49d-keys` | the device keys, one file per version (`tacacs_v1`, ...); the directory `root:65532` 0750, each file `root:65532` 0440 | port49d, read-only at `/run/port49/keys` |
| `broker-etc` | `port49-broker.yaml`, policy, inventory, etcd CA, the broker's etcd and TLS files, `secrets/encryption.key` | port49-broker, read-only |
| `etcd-pki` | the CA and the three members' certificates and keys | etcd-1..3, read-only |
| `etcd-root` | etcd's root certificate and key, and `store-roles`' output | etcd-init only |
| `etcd-N-data` | each member's data | that member |
| `broker-state` | `broker.state_dir` | port49-broker |
| `port49d-spool` | the accounting spool | port49d |

No secret is in any container's environment, so `docker inspect` shows none. Each is a file:

- A device key is a file in `port49d-keys`, named by the policy as
  `{version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}`. A new version is a new file and a line in
  the policy, with no restart (below; `make compose-smoke` runs that cell).
- Each component's sealing key is `secrets/encryption.key` in its own `-etc` volume (`root` 0755
  directory, the file `65532` 0400), the same 32 bytes in both. It is not under `/run/port49/keys`:
  a policy may name any file there.

`setup` places a key once. At every `up`, per key file: absent in the volume, it is installed; the
same bytes, it is left alone; different bytes, `setup` stops the stack with one line naming the file
(`keys are never replaced in place`) and the volume is untouched; gone from `local/`, the installed
file is kept and a line says so. To change a key, add a new version (below, and "Rotating the
`encryption:` key"), never edit `local/keys/` or `local/secrets/` under a running stack. The policy
is the opposite: `setup` copies `config/policy.yaml` over the volumes' at every `up`, so
**edit `config/policy.yaml` on the host, then `docker compose up -d`**. port49d reads it at
`policy.watch_interval` with no restart. A policy edited inside a volume is reverted at the next `up`.

Docker API access is root-equivalent, so guard it as you would the host: `docker run` with a volume
reads every file in it.

Compose's own `secrets:` is measured (lab L84, `tests/lab/results/L84-systemd-docker.md`) and is **not used
for device keys**. A file-backed secret starts port49d only if the host file is `root:65532` mode 0440:
Compose bind-mounts it as it is and does not apply the long syntax's `uid`, `gid` or `mode`, and the file
fence refuses `0444` (the short syntax's documented mode) and a file the operator owns. And adding a second
secret means `docker compose up -d`, which recreates port49d: a key version cannot be added with no restart.
The `port49d-keys` volume below is the way for device keys. `secrets:` may carry the encryption key, which is
read at start and goes through the same file fence (the cell measured a device key's file; the encryption key
was not measured on its own).

## Adding a key version

A device key is a file named in the policy. Add a version by writing a new file and a new line;
never rewrite a file in place (port49d reads each file once, and says so if one changes). Run this
from the repository root, with `PORT49_COMPOSE_LOCAL` as for `up` if you set it, and the project
name `port49` (`docker compose -p` changes the volume prefix):

```sh
docker run --rm -i -v port49_port49d-keys:/k --entrypoint sh port49-setup:dev -c '
  DEVICE_KEY=$1   # a new name for every version: never an existing one
  umask 077 && cd /k || exit 1
  [ ! -e "$DEVICE_KEY" ] && [ ! -L "$DEVICE_KEY" ] || { echo "port49: $DEVICE_KEY exists; pick a new key id" >&2; exit 1; }
  t=; trap "rm -f \"\$t\"" EXIT; trap "exit 1" INT TERM HUP
  t=$(mktemp ./.key.XXXXXX) || exit 1
  head -c 16 /dev/urandom | od -An -tx1 | tr -d " \n" > "$t" && [ "$(wc -c < "$t")" -eq 32 ] &&
    chown 0:65532 "$t" && chmod 0440 "$t" || { echo "port49: the device key was not made" >&2; exit 1; }
  ln "$t" "$DEVICE_KEY" || { echo "port49: $DEVICE_KEY exists; pick a new key id" >&2; exit 1; }
' sh tacacs_v2
```

It is the recipe of `deploy/systemd/README.md` ("Adding a key version"), in the volume: a temporary
file made in the destination, a no-clobber hard link, nothing left behind on a failure. Type the
key into the device from the volume, and keep the new file's name for the policy. Then add
`{version: 2, secret_ref: "file:/run/port49/keys/tacacs_v2"}` to the key set in `config/policy.yaml`, under `accept:` (moving the
old version out of `current:` once each device carries the new key), and run `docker compose up -d`:
`setup` copies the policy into both `-etc` volumes. port49d reads the policy at `policy.watch_interval` (5 s
here) and the new version takes effect with no restart: `port49_key_secret_files_changed` stays 0.

## A deployment

- Bring your own PKI under `PORT49_COMPOSE_LOCAL`, in the layout `compose-pki` writes
  (`etcd/`, `broker/`, `keys/tacacs_v1`, `secrets/port49d-encryption.key` and
  `secrets/broker-encryption.key`; the two sealing keys hold the same 32 bytes). A device key is the shared secret
  you type into the device; a sealing key is 32 random bytes, made once (the recipe in
  `deploy/systemd/README.md`, "Where the secrets live", with the destination changed). Edit `config/` for your policy and CRL or OCSP
  (the example sets `certificate_status.disabled`, which a deployment must not).
- List devices in `inventory.yaml` by the address port49d sees (design §13). A published port
  may change that address; what it does is policy engine spec §15 L39 (a). Measured: kept for an off-host device
  (modelled; `tests/lab/results/L39-docker-proxy-on-arista_eos.md` and `-off-`), masqueraded to
  the compose gateway for a device on another Docker network on the same host. A connection
  docker-proxy itself relays is unmeasured.
- `etcd-init` applies `port49d store-roles`' output once and enables auth. After a port49
  upgrade that changes the roles, re-apply `store-roles`' output by hand; it is never done
  silently.
- **One store or two.** The example runs one etcd cluster, so `stores.session` is omitted: the session
  store is the directory store. A deployment in several regions gives `stores.directory` an etcd
  stretched one member per region and each region's `stores.session` an etcd of its own;
  `port49d store-roles` then prints a section per store: run the directory's once against the stretched cluster, and each region's session section against that region's etcd. `port49 store status --metrics 127.0.0.1:9049` (the metrics
  port the stack publishes) shows each store as port49d sees it. Name every member's URL in `endpoints:`, as
  the example does, never a load balancer or a VIP: port49d prints the version of each at its start and
  refuses a member below the floor.
  Complete single-site and multi-region store blocks are in `deploy/examples/stores/` (written at the
  systemd paths: change the `/etc/port49` prefix only if your volumes differ).
- `context_cache` is off here, as everywhere by default, and so is `broker.directory` (see
  Directory below).

## Directory

The trial has no directory: a subject names its username, and a group subject mints for no
one (port49-broker says so at its start). `config/port49-broker.yaml` carries a commented
`broker.directory:` block to resolve humans and their groups from LDAP instead. What each
key does:

- `servers`: the pool, each `uri` (`ldaps://`, or `ldap://` with `start_tls: true`), a `site`
  and a `priority`. The broker prefers servers in its own site, then the highest `priority`, then file order.
- `site` or `site_env` (default `PORT49_SITE`): this broker's site. Set `PORT49_SITE` per
  broker container in the service's `environment:` (it is not a secret); replicas in
  different sites set different values.
- `ca_file`: verifies the servers' certificates.
- `bind`: how the broker authenticates. `gssapi` (`principal`, `keytab_file`, `krb5_conf`),
  `external` (`tls_cert_file`, `tls_key_file`) or `simple` (`bind_dn` and `password_secret_ref`, the
  weakest: the password is named by `file:/path`, read when the directory opens, never printed; use a
  file in `broker-etc`, not `env:NAME`, which would show in `docker inspect`).
  Samba AD (lab L43): `external` is refused with LDAP result 1, which port49 counts as a server fault (every
  breaker opens, `port49_directory_server_up` drops to 0), so use `simple` or `gssapi`; `gssapi` is refused
  under `ldap server require strong auth = yes` and accepted under `allow_sasl_over_tls`. Windows Server AD: L44.
- `base_dn`, `groups_base_dn`, `principal_attribute`, `username_attribute`: where a person
  and their groups are found, and which attributes name them. Only directory administrators
  may write the two attributes: two entries holding one value are both refused.
- `certificate_mapping`: how a client certificate finds its entry. `issuer_serial` and `sid`
  are strong; the others need `allow_weak: true` and `issuers`.
- `nested_groups`: `in_chain` (Active Directory; OpenLDAP answers it empty, so use `recursive` there), `recursive` or `direct`.
- `grace`: how long a stored membership answers when no server does.
- `prewarm`: how often, and for how many principals, group members are looked up ahead of
  their first login.
- `broker.refresh_interval`: the scheduled re-verification of every live principal.

The keytab and `krb5.conf` go in the broker's configuration volume (`broker-etc`, under
`/etc/port49/`), the keytab mode 0600 and owned by uid 65532, as the image runs. A keytab
that cannot be read, or holds no key for the principal, stops the start with the key named.
A directory outage never makes `/readyz` fail: a session on a stored membership goes on
within `grace`, and past `session.staleness_ceiling` (default 4h) a command is denied
`context_stale`.

## Admin operations

You run `port49 revoke` and `port49 directory ...` on your own workstation, through your agent;
nothing is run in the stack. Each admin-level call asks for a press of your security key, once
per operation, and an exposed certificate or token alone authorizes nothing admin-level.
`port49 revoke --principal user:bob@example.com` revokes, `--lift` lifts, and `--list` shows the
marks in force.

The broker needs the attestation roots, the right in the policy, and a session key on your security
key; the three are set out in `deploy/systemd/README.md` ("Admin operations"). In this stack:

- put the PEM roots in `PORT49_COMPOSE_LOCAL/broker/attestation-roots.pem`; `setup` copies it to
  `/etc/port49/broker/attestation-roots.pem` when it is there, and the broker config's
  `broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file` names that path. A
  changed roots file is `docker compose up -d` (setup copies it) then `docker compose kill -s HUP port49-broker` (the broker re-reads the roots file at SIGHUP; a file it cannot use keeps the roots in force and logs one line saying so);
- grant `api: [revoke_others, lift_revocations]` to at least two on-call admins by `identity:` in
  `config/policy.yaml`, even if a `group:` subject also holds it: a group's rights resolve through
  the directory, which may be down when you need them.

**Break-glass**, with the stack up but no admin able to reach a running broker: stop the broker,
revoke through etcd as the broker's own user (the image), and start it again. This stops issuance
while the broker is down, so it is for when no admin can use the API.

```sh
docker compose stop port49-broker
docker compose run --rm --no-deps port49-broker revoke --offline --principal user:bob@example.com
docker compose run --rm --no-deps port49-broker revoke --offline --list
docker compose start port49-broker
```

`--lift` instead of the principal's revoke lifts it. `init-enrollments` and `export-enrollments`
are local subcommands of the same form: `docker compose run --rm port49-broker init-enrollments`.
`port49 store status --metrics 127.0.0.1:9050` reads the broker's stores on the metrics port.

### The 3am table

What the operator sees; the exact lines are the CLI's (spec §5.1.6).

| Condition | What you see | What to do |
|---|---|---|
| Session key not on a security key (TPM, Secure Enclave, file) | `port49: admin operations need a security key press, and your session key is in the TPM: ...`; exit 1, nothing sent | log in with a session key on the security key |
| Attestation does not chain | `401 admin_touch_refused: the touch slot's attestation does not verify: ...` | add the root or intermediate to `attestation-roots.pem`, then `docker compose up -d` and `docker compose kill -s HUP port49-broker` |
| No touch in time | `hwkey: no touch within 15s; touch the key when it blinks and try again` | run it again |
| The identity provider is down | nothing: your port49 certificate is still valid | revoke as usual |
| Your certificate expired and the provider is down | `port49 login --oidc` cannot sign in | another on-call admin revokes; the break-glass above only if none can |
| No attestation roots configured | `503 admin_touch_unavailable: no attestation roots are configured ...` | set the file |
| The store is down | `503 store_unavailable` | the break-glass above, once the store is back but the broker is not |

## `broker.state_dir`

- One named volume per broker. Never `--scale`, never `deploy.replicas`, never an anonymous
  volume. A second broker is a second service with a volume of its own.
- A fresh named volume copies uid 65532, mode 0700 from the image. A bind mount, or a volume
  filled by hand, owned by root is not refused at start (root is an accepted owner), but the
  first `marks.json` or witness write fails, as the 65532 process cannot write it. Fix:

  ```sh
  docker run --rm -v <volume>:/s alpine:3.22 sh -c 'chown 65532:65532 /s && chmod 0700 /s'
  ```

## OIDC

The trial is certificate-only. To accept identity-provider tokens, replace `broker.client_ca_file`
with the `broker.identity` block shown commented in `config/port49-broker.yaml`; an OIDC-only
broker (no x509 verifier) is valid. The provider's signing keys are kept in `broker.state_dir`, so
a broker restarted during a provider outage still validates tokens until `jwks_max_age`; a fetch
failure never changes `/readyz`.

- The broker must reach the provider's discovery and JWKS URLs. Where the site's egress is a proxy,
  set `HTTPS_PROXY` on the broker service; the start line says how each issuer is fetched.
- Register `https://<broker>:8443/v1/logout` as the provider's back-channel logout URL, with
  "backchannel logout session required" on.
- Each machine client's `sub` is read from the provider: in Keycloak, the client's "Service account
  roles" user id; in Entra ID, the service principal's object id.

## The issuing CA, and a second broker

`port49-broker init-issuer` makes the issuing CA on one broker, as the broker's user:

```sh
docker compose exec port49-broker port49-broker init-issuer
```

A second broker is a second service with a `broker-state` volume of its own, and it must hold the
same CA, or it refuses to start. Copy both files into its volume, keeping them private:

```sh
docker run --rm -v port49_broker-state:/a -v port49_broker2-state:/b alpine:3.22 sh -c \
  'install -o 65532 -g 65532 -m 0600 /a/issuing-ca.key /b/ && install -o 65532 -g 65532 -m 0644 /a/issuing-ca.pem /b/'
```

Complete single-site and multi-region store blocks are in `deploy/examples/stores/`.

## Rotating the `encryption:` key

One key, in both components, from one secret, in three steps. A new key is a new file beside the old,
never a rewrite.

1. Make the new sealing key once, as `secrets/encryption-e2.key` in both `-etc` volumes
   (`65532` 0400), the same 32 bytes in each, with this one command from any directory (project
   `port49`; `docker compose -p` changes the volume prefix). It draws until the last byte is not a
   newline, makes both temporary files in the destination directories, links them no-clobber, and
   leaves nothing behind on a failure. It never overwrites: an existing `encryption-e2.key` is refused.

   ```sh
   docker run --rm -i -v port49_port49d-etc:/e -v port49_broker-etc:/b --entrypoint sh port49-setup:dev -c '
     KEY_ID=$1   # a new id for every key: never an existing one
     : "${KEY_ID:?set KEY_ID to the new key id}"
     umask 077 && cd /e/secrets && cd /b/secrets || exit 1
     n=encryption-$KEY_ID.key
     for f in /e/secrets/$n /b/secrets/$n; do
       [ ! -e "$f" ] && [ ! -L "$f" ] || { echo "port49: $f exists; pick a new key id" >&2; exit 1; }
     done
     t=; u=; trap "rm -f \"\$t\" \"\$u\"" EXIT; trap "exit 1" INT TERM HUP
     t=$(mktemp /e/secrets/.key.XXXXXX) && u=$(mktemp /b/secrets/.key.XXXXXX) || exit 1
     ok=
     for i in 1 2 3 4 5 6 7 8 9 10; do
       head -c 32 /dev/urandom > "$t" && [ "$(wc -c < "$t")" -eq 32 ] &&
         [ "$(tail -c1 "$t" | od -An -tx1 | tr -d " ")" != 0a ] && ok=1 && break
     done
     [ -n "$ok" ] || { echo "port49: no usable 32-byte key in 10 draws" >&2; exit 1; }
     cat "$t" > "$u" && chown 65532:65532 "$t" "$u" && chmod 0400 "$t" "$u" ||
       { echo "port49: the sealing key was not made" >&2; exit 1; }
     ln "$t" "/e/secrets/$n" || { echo "port49: /e/secrets/$n exists; pick a new key id" >&2; exit 1; }
     ln "$u" "/b/secrets/$n" || { rm -f "/e/secrets/$n"; echo "port49: /b/secrets/$n exists; pick a new key id" >&2; exit 1; }
   ' sh e2
   ```

   Add it to `config/port49d.yaml` and `config/port49-broker.yaml` under `encryption:` as `previous: {id: c2, secret_ref:
   file:/etc/port49/secrets/encryption-e2.key}`, run `docker compose up -d` (setup copies the config
   files) and `docker compose restart port49d port49-broker`. Both open what either key sealed.
2. Swap: make `c2` `current:` and `c1` `previous:` in both files, and restart both.
3. Remove `previous:` and the old file only after the scheduled directory pass (every `refresh_interval`)
   has re-sealed the second-factor records under `c2`. A record that opens under neither key is never
   "not enrolled": that sign-in is `503 store_unavailable`, and the broker's line names
   `port49 directory reset-second-factor`. Remove the old key from `local/secrets/` **first**
   (`port49d-encryption.key` and `broker-encryption.key` are the old key's), so an `up` in between cannot install it
   again, and then from the volumes
   (`docker run --rm -v port49_port49d-etc:/e -v port49_broker-etc:/b alpine:3.22 rm /e/secrets/encryption.key /b/secrets/encryption.key`,
   with the old file's name). Setup skips a sealing key that is in neither place; once the config no longer names the
   old file, every later `up` starts clean and the old key stays gone.

A process whose window lacks the directory's current key id refuses to start, naming the directory
store and the id. Two store blocks reaching one etcd cluster at one prefix are refused too.

## When it will not start

`docker compose logs port49d` (or `port49-broker`) holds the line. `restart: unless-stopped` has no
limit: a start that fails is tried again, with a restart delay that grows to a minute, until you fix the cause or `docker
compose stop` it, so `docker compose ps` shows a restarting container and the log repeats the line.
A port49d whose etcd is down at boot comes back on its own when etcd does.

| Refusal | The line | Where | Fix |
|---|---|---|---|
| A secret file missing or unreadable | `config: encryption.current.secret_ref (id "c1") file:/etc/port49/secrets/encryption.key: open ...: permission denied` (or the file it names); a key file: `config: keys.k version 1 secret_ref file:/run/port49/keys/tacacs_v1: ...` | `docker compose logs port49d` | write the file as the table above says (`setup` installs a key that is absent, and refuses one that differs; it never rewrites one) |
| The fence refuses a directory | `...is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it ...` | same | fix the mode the line names in the volume (`docker run --rm -v <volume>:/v alpine:3.22 chmod go-w /v/<dir>`) |
| The issuing CA differs from the store's | `issuance: this broker's issuing CA (...) is not the one the store records (...)` | `docker compose logs port49-broker` | copy `issuing-ca.pem` and `.key` from a broker that holds it (above) |
| etcd below the floor | `etcd at <url> is version <v>, below the floor port49 needs (3.4.24, 3.5.8 or 3.6): ...` | `docker compose logs port49d` | upgrade the member |
| etcd unreachable at boot | a store refusal after `start_timeout` (30 s unless you set it), then the container restarts | `docker compose logs port49d` | nothing: it retries; start etcd |

## Backups

Each etcd data volume and `broker-state` (design §13's runbook).

## Not here yet

Plan 12's install page, compaction quota sizing, and etcd alarms.
