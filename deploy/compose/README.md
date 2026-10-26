# port49 on etcd, as containers

One peer shape beside systemd and Kubernetes; nothing in port49 requires it. The stack is
`port49d`, `port49-broker` and a three-member etcd with client-certificate auth. `make
compose-smoke` brings it up on a fresh PKI, logs a device in, recreates every container with
its volumes kept, and checks the session, a token minted before the recreate, and the broker's
`broker.state_dir` all survived. CI runs it on every pull request.

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

Inputs, each an environment variable with a default: `PORT49_COMPOSE_LOCAL` (`./local`),
`PORT49_COMPOSE_CONFIG` (`./config`), `PORT49_COMPOSE_SUBNET` (`172.30.49.0/24`),
`PORT49_TACACS_PUBLISH` (`127.0.0.1:49`), `PORT49_BROKER_PUBLISH` (`127.0.0.1:8443`).

## The files

`setup` runs as root at every `up` and copies each component's files into a volume of its own,
so no volume holds both etcd identities (plan 7e, Ruling 1):

| Volume | Holds | Mounted in |
|---|---|---|
| `port49d-etc` | `port49d.yaml`, policy, inventory, etcd CA, port49d's etcd certificate and key | port49d, read-only |
| `broker-etc` | `port49-broker.yaml`, policy, inventory, etcd CA, the broker's etcd and TLS files | port49-broker, read-only |
| `etcd-pki` | the CA and the three members' certificates and keys | etcd-1..3, read-only |
| `etcd-root` | etcd's root certificate and key, and `store-roles`' output | etcd-init only |
| `etcd-N-data` | each member's data | that member |
| `broker-state` | `broker.state_dir` | port49-broker |
| `port49d-spool` | the accounting spool | port49d |

The device key and the encryption key come from env files: `port49d.env` holds both,
`port49-broker.env` only the encryption key. Both values show in `docker inspect` of the
running and exited containers; Docker API access is root-equivalent, so guard it as you would
the env files. A `secret_file` source is plan 12's to weigh.

## A deployment

- Bring your own PKI under `PORT49_COMPOSE_LOCAL`, in the layout `compose-pki` writes
  (`etcd/`, `broker/`, the two env files). Edit `config/` for your policy and CRL or OCSP
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
  `port49d store-roles` then prints a section per store: run the directory's once against the stretched cluster, and each region's session section against that region's etcd. `port49 store status` (inside the
  port49d container: `docker compose exec port49d port49 store status`) shows each store as port49d
  sees it.
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
  broker container, in `port49-broker.env` or the service's `environment:`; replicas in
  different sites set different values.
- `ca_file`: verifies the servers' certificates.
- `bind`: how the broker authenticates. `gssapi` (`principal`, `keytab_file`, `krb5_conf`),
  `external` (`tls_cert_file`, `tls_key_file`) or `simple` (`bind_dn` and `password_secret_ref`, the
  weakest: the password is named by `env:NAME` or `file:/path`, read when the directory opens, never printed).
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

## Revoking

```sh
docker compose exec port49-broker port49 revoke --socket /run/port49/port49-broker.sock --principal user:bob@example.com
```

With every broker down, as the broker's own user (which the image is; plan 7e, Ruling 13):

```sh
docker compose run --rm --entrypoint port49-broker port49-broker revoke --offline --principal user:bob@example.com
```

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

## Backups

Each etcd data volume and `broker-state` (design §13's runbook).

## Not here yet

Plan 12's install page, compaction quota sizing, and etcd alarms.
