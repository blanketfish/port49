# L33 — NetBox

- **Date measured:** 2026-10-01, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from the service's source line):** `NetBox 3.7.8, profile netbox_3_7` and `NetBox 4.7.1, profile netbox_4`, each over GraphQL
- **Images:**
  - `docker.io/netboxcommunity/netbox:v3.7.8@sha256:9bf83b350a8956a83cccb11a6bf709fad0780f4e9ec4857adc747d547ade2134`
  - `docker.io/netboxcommunity/netbox:v4.7.1@sha256:59e3e5954d0243d8648f2fa7ba82cf7c7770aaeef392026cca8b21cd67411e74`
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` (the `l32` profile's proxies; the connector reads through `proxy_host`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/netbox-3.7.yml`, `tests/lab/sot/compose/netbox-4.yml`; the worker resolves
  `port49-inventory.lab` to the host (`extra_hosts: host-gateway`) and mounts the run's lab CA at `/etc/port49-lab/ca.pem`
- **Runs:** `tests/lab/sot/run.sh netbox-3.7 l33`, `run.sh netbox-4 l33` (procedure: `tests/lab/sot/README.md`), from a
  worktree pinned at `c8a63d8`; each record's `built`: port49d, port49 and port49-inventory built from `c8a63d8`. The
  recorder seeded 120 devices into `tests/lab/logs/`, not committed. `TestL33Webhooks` then started port49-inventory
  with the stack as its one source (`l33`, through `proxy_host`, `interval: 24h`, so every publication after the
  first is a webhook's) and `webhook_listen` on the docker bridge's address, port 18444, under a webhook certificate
  for `port49-inventory.lab` from the run's lab CA (`tests/lab/cmd/sot-pki`). It created a webhook to
  `https://port49-inventory.lab:18444/v1/webhook/l33` with `ssl_verification: true` and `ca_file_path:
  /etc/port49-lab/ca.pem`, its secret 48 random characters per run, and an event rule for device create, update and
  delete in the release's spelling; made three changes 35 s apart; then replaced it with two webhooks on one more
  change: one under a wrong secret, and one to a stand-in listener (`l33Unavailable`, port 18445, the same
  certificate) that answers every request `503 {"error":"shutting_down"}`, as port49-inventory's webhook listener
  does during shutdown
- **Capture pointer (the records):** `tests/lab/sot/l33/netbox-3.7/`, `tests/lab/sot/l33/netbox-4/` (`webhooks.json`)
- **Credentials:** every password, secret key, pepper, API token and webhook secret was random per run, passed by
  environment, and is in no committed file; the test fails if the service's log holds the webhook secret, and the
  record holds none; the count-only audit over each run's record and service log with that run's `L27_ENV_DIR`
  printed 0 for both stacks. The lab PKI lived in the run's temporary directory and was removed on exit.
- **Status:** measured; closed by plan 6c Task 16

## Claim

What NetBox does delivering a webhook to port49-inventory's `webhook_listen`, per release: whether it delivers to
an `https` payload URL whose certificate a private CA issued (`ca_file_path`, `ssl_verification` on); whether
port49-inventory authenticates each delivery (HMAC-SHA512 of the body, `X-Hook-Signature`) and finds its
`timestamp` inside the 5-minute window; how long a change takes from the API write to the published bundle; and
whether a delivery port49-inventory refuses (HTTP 401) is sent again (spec §15 L33). Also recorded: whether a
delivery answered 503 is sent again, and the release's retry setting.

## Observation

Seconds run from the API write's start to the service's `sync (webhook): published bundle` line, and include the
debouncer's 2 s settle (decision 31); "accepted" counts `port49_inventory_webhooks_total{source="l33",outcome="accepted"}`
across the change.

| stack | change | result | deliveries |
|---|---|---|---|
| netbox-3.7 | webhook created | webhook 201, event_rule 201 | |
| netbox-3.7 | update leaf-01's os_version | 2.44 s | 1 accepted |
| netbox-3.7 | create leaf-200 | 2.43 s | 1 accepted |
| netbox-3.7 | delete leaf-200 | 2.65 s | 1 accepted |
| netbox-3.7 | bad_signature | 1 in 120 s | the wrong secret's delivery, refused 401, counted once: not sent again within 120 s |
| netbox-3.7 | 503 | 1 in 120 s | the stand-in listener's one arrival, 0.10 s after the write: not sent again within 120 s |
| netbox-3.7 | stale | 0 | |
| netbox-4 | webhook created | webhook 201, event_rule 201 | |
| netbox-4 | update leaf-01's os_version | 2.50 s | 1 accepted |
| netbox-4 | create leaf-200 | 2.60 s | 1 accepted |
| netbox-4 | delete leaf-200 | 2.73 s | 1 accepted |
| netbox-4 | bad_signature | 1 in 120 s | the wrong secret's delivery, refused 401, counted once: not sent again within 120 s |
| netbox-4 | 503 | 1 in 120 s | the stand-in listener's one arrival, 0.19 s after the write: not sent again within 120 s |
| netbox-4 | stale | 0 | |

Both releases delivered to the `https` payload URL under the private CA with verification on, from the first
change: no TLS failure in the worker's log, and every delivery authenticated and fell inside the window
(`stale` 0). Each change published one bundle through the webhook, about 0.4–0.7 s after the debouncer's settle:
a `+0 −0, 1 changed` bundle for the update, `+1` for the create (leaf-200 admitted by the site `dc1` key group),
and `−1` for the delete. The service said `source l33's deliveries authenticate` once, at the first, and the wrong
secret's refusal once (`bad_signature`, naming the source and the worker's address).

**Sent again?** Neither the 401 nor the 503 was. The worker logged each as `Request failed; response status 401`
(`503`) and `webhook FAILED to process`, and the job ended there. NetBox's own retry is `RQ_RETRY_MAX` (default 0,
so none) with `RQ_RETRY_INTERVAL` (default 60 s), applied to every event-rule job in both releases
(`utilities/rqworker.py` `get_rq_retry()`, called from `extras/events.py` in 3.7.8 and `extras/event_rules.py` in
4.7.1); netbox-docker's configuration leaves it unset. So a NetBox delivery refused 401, or answered 503 (here by the stand-in listener), is lost unless
the operator sets `RQ_RETRY_MAX`; the scheduled sync covers the change. A retry with a backoff past 120 s would
not be seen here, but at the default the job is not retried at all.

### Not observed

- A delivery whose certificate the worker's default trust store holds (only the private CA was tried).
- A burst of changes inside the debouncer's 30 s gap (each change here was 35 s after the last).
- A release with `RQ_RETRY_MAX` set.
- A 503 from port49-inventory itself (it answers 503 only on a connection open when shutdown began), and a
  delivery while port49-inventory is down (connection refused), the common restart case.
