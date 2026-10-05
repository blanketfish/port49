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
`port49-broker.env` only the encryption key.

## A deployment

- Bring your own PKI under `PORT49_COMPOSE_LOCAL`, in the layout `compose-pki` writes
  (`etcd/`, `broker/`, the two env files). Edit `config/` for your policy and CRL or OCSP
  (the example sets `certificate_status.disabled`, which a deployment must not).
- List devices in `inventory.yaml` by the address port49d sees (design §13). A published port
  may change that address; what it does is policy engine spec §15 L39 (a), not yet measured.
- `etcd-init` applies `port49d store-roles`' output once and enables auth. After a port49
  upgrade that changes the roles, re-apply `store-roles`' output by hand; it is never done
  silently.
- `context_cache` is off here, as everywhere by default.

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

## Backups

Each etcd data volume and `broker-state` (design §13's runbook).

## Not here yet

Plan 12's install page, compaction quota sizing, and etcd alarms.
