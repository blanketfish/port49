# L32 — Nautobot

- **Date measured:** 2026-10-01, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from each read's said line):** `Nautobot 1.6.32, profile nautobot_1_6`, `Nautobot 2.4.43, profile nautobot_2` and `Nautobot 3.2.6, profile nautobot_2`, each over GraphQL and over REST
- **Images:**
  - `docker.io/networktocode/nautobot:1.6.32@sha256:cc1c31b17b263d5b715a1e177ea5f0e16252ce357297ae9e8700a92bf82035b7`
  - `docker.io/networktocode/nautobot:2.4.43@sha256:7d61a4b0980d07e9fa6416a90345af1e2ef7d92b274a313769c85eea0a13d79d`
  - `docker.io/networktocode/nautobot:3.2.6@sha256:37c315740a8242de6c0afbbdbd6f4ffa4f421949a16542a2dae61405d2dbd535`
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
    (both TLS proxies; the compose logs name `nginx/1.27.5`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/nautobot-1.6.yml`, `tests/lab/sot/compose/nautobot-2.yml`, `tests/lab/sot/compose/nautobot-3.yml`, each with the `l32` profile's `proxy_host` (`127.0.0.1:<port+2000>`) and
  `proxy_xfh` (`127.0.0.1:<port+3000>`), both terminating TLS with a certificate from the run's lab CA
  (`tests/lab/cmd/sot-pki`)
- **Proxy configs:** `tests/lab/sot/compose/l32-proxy-host.conf` (`proxy_set_header Host $http_host`,
  `X-Forwarded-Proto https`, no `X-Forwarded-Host`) and `tests/lab/sot/compose/l32-proxy-xfh.conf`
  (`proxy_set_header Host nautobot:8080`, `X-Forwarded-Host $http_host`, `X-Forwarded-Proto https`), upstream
  `nautobot:8080`
- **Runs:** `tests/lab/sot/run.sh nautobot-1.6 l32` (with `-prefer-legacy`, as L30), `run.sh nautobot-2 l32`, `run.sh nautobot-3 l32` (procedure: `tests/lab/sot/README.md`), from a worktree pinned at `a50c993`; each
  record's `built`: port49d, port49 and port49-inventory built from `a50c993` (`make build`). The recorder seeded 120 devices (`-devices 120 -page-limit 50`) into
  `tests/lab/logs/`, not committed; `TestL32Connector` then read the stack with `sot.New`/`Fetch` as built,
  `page_size` 50, `filter: {status: [active]}`, primary addresses, and over GraphQL every interface's
  addresses too
- **Capture pointer (the records):** `tests/lab/sot/l32/nautobot-1.6/`, `tests/lab/sot/l32/nautobot-2/`, `tests/lab/sot/l32/nautobot-3/` (`connector.json`)
- **Credentials:** every password, secret key, pepper and API token was random per run, passed by
  environment, and is in no committed file; the test sends the token and records no `Authorization`
  header; the count-only audit over `tests/lab/sot/l32` with each run's `L27_ENV_DIR` printed 0 for every
  stack. The lab PKI lived in the run's temporary directory and was removed on exit.
- **Status:** measured; closed by plan 6c Task 16

## Claim

L30's remainder and the connector's own query: which header each release builds `next` from behind a
TLS-terminating proxy (`Host` or `X-Forwarded-Host`), and whether the connector as built reads every
device through both proxies, over GraphQL and REST, 50 to a page, saying a rebuilt `next` where it
rebuilt one (spec §15, L32). Also recorded, from an earlier review: whether the release's GraphQL device
list lets a query select `id`.

## Observation

`proxy_xfh` sent `Host: nautobot:8080`; a `next` naming `nautobot:8080` would mean the release builds from `Host`, one
naming the client's `127.0.0.1:<port+3000>` means `X-Forwarded-Host`.

| stack | proxy | what | result | said | leaf-01 as read |
|---|---|---|---|---|---|
| nautobot-1.6 | proxy_host | next: https://127.0.0.1:20016 | HTTP 200; `results[0].url` host `127.0.0.1:20016`; built from the client's `Host` (no `X-Forwarded-Host` sent), scheme from `X-Forwarded-Proto` |
| nautobot-1.6 | proxy_xfh | next: https://127.0.0.1:21016 | HTTP 200; `results[0].url` host `127.0.0.1:21016`; built from **`X-Forwarded-Host`** (the client's host; `Host` was the upstream's name), scheme from `X-Forwarded-Proto` |
| nautobot-1.6 | proxy_host | graphql | 120 devices, 3.051 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 1.6.32, profile nautobot_1_6, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-1.6 | proxy_host | rest | 120 devices, 1.635 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 1.6.32, profile nautobot_1_6, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-1.6 | proxy_xfh | graphql | 120 devices, 3.065 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 1.6.32, profile nautobot_1_6, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-1.6 | proxy_xfh | rest | 120 devices, 1.481 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 1.6.32, profile nautobot_1_6, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-1.6 | GraphQL id selectable | `{ devices(limit: 1, offset: 0) { id name } }` | HTTP 200, 0 error(s); `id` came back as a JSON string |
| nautobot-2 | proxy_host | next: https://127.0.0.1:20020 | HTTP 200; `results[0].url` host `127.0.0.1:20020`; built from the client's `Host` (no `X-Forwarded-Host` sent), scheme from `X-Forwarded-Proto` |
| nautobot-2 | proxy_xfh | next: https://127.0.0.1:21020 | HTTP 200; `results[0].url` host `127.0.0.1:21020`; built from **`X-Forwarded-Host`** (the client's host; `Host` was the upstream's name), scheme from `X-Forwarded-Proto` |
| nautobot-2 | proxy_host | graphql | 120 devices, 1.609 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 2.4.43, profile nautobot_2, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-2 | proxy_host | rest | 120 devices, 2.347 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 2.4.43, profile nautobot_2, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-2 | proxy_xfh | graphql | 120 devices, 1.606 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 2.4.43, profile nautobot_2, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-2 | proxy_xfh | rest | 120 devices, 2.180 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 2.4.43, profile nautobot_2, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-2 | GraphQL id selectable | `{ devices(limit: 1, offset: 0) { id name } }` | HTTP 200, 0 error(s); `id` came back as a JSON string |
| nautobot-3 | proxy_host | next: https://127.0.0.1:20030 | HTTP 200; `results[0].url` host `127.0.0.1:20030`; built from the client's `Host` (no `X-Forwarded-Host` sent), scheme from `X-Forwarded-Proto` |
| nautobot-3 | proxy_xfh | next: https://127.0.0.1:21030 | HTTP 200; `results[0].url` host `127.0.0.1:21030`; built from **`X-Forwarded-Host`** (the client's host; `Host` was the upstream's name), scheme from `X-Forwarded-Proto` |
| nautobot-3 | proxy_host | graphql | 120 devices, 2.892 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 3.2.6, profile nautobot_2, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-3 | proxy_host | rest | 120 devices, 2.290 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 3.2.6, profile nautobot_2, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-3 | proxy_xfh | graphql | 120 devices, 1.576 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 3.2.6, profile nautobot_2, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| nautobot-3 | proxy_xfh | rest | 120 devices, 2.085 s | rebuilt next said: no (`port49-inventory: source l32: Nautobot 3.2.6, profile nautobot_2, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| nautobot-3 | GraphQL id selectable | `{ devices(limit: 1, offset: 0) { id name } }` | HTTP 200, 0 error(s); `id` came back as a JSON string |

Every release built `next` from `X-Forwarded-Host` when one was sent and from `Host` otherwise, and took
its scheme from `X-Forwarded-Proto`: through both proxies `next` named the proxy's own scheme, host and
port, so no read rebuilt a `next` and none said so. Every read returned 120 devices.

### Not observed

- A rebuilt `next`: no release named another origin through either proxy, so the connector's rebuild
  path and its note were not exercised against a real release (its unit tests replay it).
- A proxy that drops `X-Forwarded-Proto`, or one that rewrites `Host` without sending
  `X-Forwarded-Host`.
- A GraphQL list above any server cap: 120 devices, 50 to a page where the release pages.
- A list changing between pages, and a removal (each read was a new source, with no prior read to
  confirm against).
