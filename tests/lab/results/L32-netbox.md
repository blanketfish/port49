# L32 — NetBox

- **Date measured:** 2026-10-01, on beehive (Docker 29.1.3, Compose v5.5.1); rerun after plan 6c
  Task 14's fix round 1 (GraphQL keyed by `id`, a third proxy), replacing the first run's records
- **Product and versions (from each read's said line):** `NetBox 3.7.8, profile netbox_3_7` and `NetBox 4.7.1, profile netbox_4`, each over GraphQL and over REST
- **Images:**
  - `docker.io/netboxcommunity/netbox:v3.7.8@sha256:9bf83b350a8956a83cccb11a6bf709fad0780f4e9ec4857adc747d547ade2134`
  - `docker.io/netboxcommunity/netbox:v4.7.1@sha256:59e3e5954d0243d8648f2fa7ba82cf7c7770aaeef392026cca8b21cd67411e74`
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
    (the three TLS proxies; the compose logs name `nginx/1.27.5`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/netbox-3.7.yml`, `tests/lab/sot/compose/netbox-4.yml`, each with the `l32` profile's `proxy_host` (`127.0.0.1:<port+2000>`),
  `proxy_xfh` (`<port+3000>`) and `proxy_plain` (`<port+4000>`), all terminating TLS with a certificate
  from the run's lab CA (`tests/lab/cmd/sot-pki`); each proxy reaches the product over plain http
- **Proxy configs:**
  - `tests/lab/sot/compose/l32-proxy-host.conf`: `proxy_set_header Host $http_host`, `X-Forwarded-Proto https`,
    no `X-Forwarded-Host`
  - `tests/lab/sot/compose/l32-proxy-xfh.conf`: `proxy_set_header Host netbox:8080`, `X-Forwarded-Host $http_host`,
    `X-Forwarded-Proto https`
  - `tests/lab/sot/compose/l32-proxy-plain.conf`: `proxy_pass` alone (nginx sends `Host: netbox:8080`, no
    `X-Forwarded-*`)
- **Runs:** `tests/lab/sot/run.sh netbox-3.7 l32`, `run.sh netbox-4 l32` (procedure: `tests/lab/sot/README.md`), from a worktree pinned at `eb862a4` (which holds
  the fix `e8bbe15`), restored to that commit after each stack; each record's `built`: internal/sot as compiled by go test at `eb862a4`. The
  recorder seeded 120 devices (`-devices 120 -page-limit 50`) into `tests/lab/logs/`, not committed;
  `TestL32Connector` then read the stack through each proxy with `sot.New`/`Fetch` as built, `page_size`
  50, `filter: {status: [active]}`, primary addresses, and over GraphQL every interface's addresses too
  (the query selecting `id`, the list's key)
- **Capture pointer (the records):** `tests/lab/sot/l32/netbox-3.7/`, `tests/lab/sot/l32/netbox-4/` (`connector.json`; each read names its `url`)
- **Credentials:** every password, secret key, pepper and API token was random per run, passed by
  environment, and is in no committed file; the test sends the token and records no `Authorization`
  header; the count-only audit over each run's record with that run's `L27_ENV_DIR` printed 0 for every
  stack. The lab PKI lived in the run's temporary directory and was removed on exit.
- **Status:** measured; closed by plan 6c Task 16

## Claim

L30's remainder and the connector's own query: which header each release builds `next` from behind a
TLS-terminating proxy (`Host` or `X-Forwarded-Host`), and where its scheme comes from; and whether the
connector as built reads every device through each proxy, over GraphQL and REST, 50 to a page,
following `next` on its `url` or rebuilding it there and saying so (spec §15, L32). Also recorded: whether
the release's GraphQL device list lets a query select `id`, which the connector keys the list by.

## Observation

| stack | proxy | what | result | said | leaf-01 as read |
|---|---|---|---|---|---|
| netbox-3.7 | proxy_host | next: https://127.0.0.1:20037 | HTTP 200; `results[0].url` host `127.0.0.1:20037`; built from the client's `Host` (no `X-Forwarded-Host` sent), scheme from `X-Forwarded-Proto` |
| netbox-3.7 | proxy_xfh | next: https://127.0.0.1:21037 | HTTP 200; `results[0].url` host `127.0.0.1:21037`; built from **`X-Forwarded-Host`** (`Host` was `netbox:8080`), scheme from `X-Forwarded-Proto` |
| netbox-3.7 | proxy_plain | next: http://netbox:8080 | HTTP 200; `results[0].url` host `netbox:8080`; built from `Host` as nginx sent it (`netbox:8080`); with no `X-Forwarded-Proto`, the scheme is the upstream hop's `http` |
| netbox-3.7 | proxy_host | graphql | 120 devices, 0.238 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-3.7 | proxy_host | rest | 120 devices, 0.350 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-3.7 | proxy_xfh | graphql | 120 devices, 0.231 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-3.7 | proxy_xfh | rest | 120 devices, 0.211 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-3.7 | proxy_plain | graphql | 120 devices, 0.253 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-3.7 | proxy_plain | rest | 120 devices, 1.678 s | rebuilt next said: yes (`port49-inventory: source l32: a page's next names another scheme, host or port than url; it is rebuilt on url, and the token is sent nowhere else: check the proxy's Host and X-Forwarded-Proto headers`; `port49-inventory: source l32: NetBox 3.7.8, profile netbox_3_7, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-3.7 | GraphQL id selectable | `{ device_list { id name } }` | HTTP 200, 0 error(s); `id` came back as a JSON string | | |
| netbox-4 | proxy_host | next: https://127.0.0.1:20080 | HTTP 200; `results[0].url` host `127.0.0.1:20080`; built from the client's `Host` (no `X-Forwarded-Host` sent), scheme from `X-Forwarded-Proto` |
| netbox-4 | proxy_xfh | next: https://127.0.0.1:21080 | HTTP 200; `results[0].url` host `127.0.0.1:21080`; built from **`X-Forwarded-Host`** (`Host` was `netbox:8080`), scheme from `X-Forwarded-Proto` |
| netbox-4 | proxy_plain | next: http://netbox:8080 | HTTP 200; `results[0].url` host `netbox:8080`; built from `Host` as nginx sent it (`netbox:8080`); with no `X-Forwarded-Proto`, the scheme is the upstream hop's `http` |
| netbox-4 | proxy_host | graphql | 120 devices, 0.732 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-4 | proxy_host | rest | 120 devices, 0.320 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-4 | proxy_xfh | graphql | 120 devices, 0.814 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-4 | proxy_xfh | rest | 120 devices, 0.456 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-4 | proxy_plain | graphql | 120 devices, 0.260 s | rebuilt next said: no (`port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over GraphQL`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5 10.0.1.6` |
| netbox-4 | proxy_plain | rest | 120 devices, 0.288 s | rebuilt next said: yes (`port49-inventory: source l32: a page's next names another scheme, host or port than url; it is rebuilt on url, and the token is sent nowhere else: check the proxy's Host and X-Forwarded-Proto headers`; `port49-inventory: source l32: NetBox 4.7.1, profile netbox_4, over REST`) | leaf-01: platform `arista_eos`, site `dc1`, role `leaf`, os_version `4.32.2F`, addresses `10.0.1.5` |
| netbox-4 | GraphQL id selectable | `{ device_list(pagination: {offset: 0, limit: 1}) { id name } }` | HTTP 200, 0 error(s); `id` came back as a JSON string | | |

Through `proxy_host`, every release named the client's host and port in `next`; through `proxy_xfh`, the
client's host from `X-Forwarded-Host`, not `Host` (`netbox:8080`); through `proxy_plain`, `http://netbox:8080`:
`Host` as received, and, with no `X-Forwarded-Proto`, the scheme of the hop it was asked on. So every
release builds `next` from `X-Forwarded-Host` when sent, from `Host` otherwise, and takes `https` only
from `X-Forwarded-Proto`. The connector followed `next` where it named `url`'s origin, and through
`proxy_plain` rebuilt every REST `next` on `url`, said so once, and read all 120: `netbox:8080` does not
resolve on the host, so a followed `next` would have failed the read. Every read returned 120 devices,
and every release's GraphQL list gave `id` as a string.

### Not observed

- A proxy that sends `X-Forwarded-Host` but no `X-Forwarded-Proto`, or a `next` naming another path.
- A GraphQL list above any server cap: 120 devices, 50 to a page where the release pages.
- A list changing between pages, and a removal (each read was a new source, with no prior read to
  confirm against); the `id` key's catch of a rename across pages is replayed in `sottest`, not measured.
