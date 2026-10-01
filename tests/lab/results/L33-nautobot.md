# L33 — Nautobot

- **Date measured:** 2026-10-01, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from the service's source line):** `Nautobot 1.6.32, profile nautobot_1_6`, `Nautobot 2.4.43, profile nautobot_2` and `Nautobot 3.2.6, profile nautobot_2`, each over GraphQL
- **Images:**
  - `docker.io/networktocode/nautobot:1.6.32@sha256:cc1c31b17b263d5b715a1e177ea5f0e16252ce357297ae9e8700a92bf82035b7`
  - `docker.io/networktocode/nautobot:2.4.43@sha256:7d61a4b0980d07e9fa6416a90345af1e2ef7d92b274a313769c85eea0a13d79d`
  - `docker.io/networktocode/nautobot:3.2.6@sha256:37c315740a8242de6c0afbbdbd6f4ffa4f421949a16542a2dae61405d2dbd535`
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` (the `l32` profile's proxies; the connector reads through `proxy_host`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/nautobot-1.6.yml`, `nautobot-2.yml`, `nautobot-3.yml`; the worker resolves
  `port49-inventory.lab` to the host (`extra_hosts: host-gateway`) and mounts the run's lab CA at `/etc/port49-lab/ca.pem`
- **Runs:** `tests/lab/sot/run.sh nautobot-1.6 l33`, `run.sh nautobot-2 l33`, `run.sh nautobot-3 l33` (procedure:
  `tests/lab/sot/README.md`), from a worktree pinned at `c8a63d8`; each record's `built`: port49d, port49 and
  port49-inventory built from `c8a63d8`. The recorder seeded 120 devices into `tests/lab/logs/`, not committed.
  `TestL33Webhooks` then started port49-inventory with the stack as its one source (`l33`, through `proxy_host`,
  `interval: 24h`, so every publication after the first is a webhook's) and `webhook_listen` on the docker bridge's
  address, port 18444, under a webhook certificate for `port49-inventory.lab` from the run's lab CA
  (`tests/lab/cmd/sot-pki`). It created a webhook to `https://port49-inventory.lab:18444/v1/webhook/l33` for
  `dcim.device` create, update and delete, with `ssl_verification: true` and `ca_file_path: /etc/port49-lab/ca.pem`,
  its secret 48 random characters per run; made three changes 35 s apart; then replaced it with two webhooks on one
  more change: one under a wrong secret, and one to a stand-in listener (`l33Unavailable`, port 18445, the same
  certificate) that answers every request `503 {"error":"shutting_down"}`, as port49-inventory's webhook listener
  does during shutdown
- **Capture pointer (the records):** `tests/lab/sot/l33/nautobot-1.6/`, `tests/lab/sot/l33/nautobot-2/`,
  `tests/lab/sot/l33/nautobot-3/` (`webhooks.json`)
- **Credentials:** every password, secret key, API token and webhook secret was random per run, passed by
  environment, and is in no committed file; the test fails if the service's log holds the webhook secret, and the
  record holds none; the count-only audit over each run's record and service log with that run's `L27_ENV_DIR`
  printed 0 for every stack. The lab PKI lived in the run's temporary directory and was removed on exit.
- **Status:** measured; closed by plan 6c Task 16

## Claim

What Nautobot does delivering a webhook to port49-inventory's `webhook_listen`, per release: whether it delivers to
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
| nautobot-1.6 | webhook created | webhook 201 | |
| nautobot-1.6 | update leaf-01's os_version | 3.57 s | 1 accepted |
| nautobot-1.6 | create leaf-200 | 3.70 s | 1 accepted |
| nautobot-1.6 | delete leaf-200 | 4.01 s | 1 accepted |
| nautobot-1.6 | bad_signature | 1 in 120 s | the wrong secret's delivery, refused 401, counted once: not sent again within 120 s |
| nautobot-1.6 | 503 | 1 in 120 s | the stand-in listener's one arrival, 0.11 s after the write: not sent again within 120 s |
| nautobot-1.6 | stale | 0 | |
| nautobot-2 | webhook created | webhook 201 | |
| nautobot-2 | update leaf-01's os_version | 4.07 s | 1 accepted |
| nautobot-2 | create leaf-200 | 3.81 s | 1 accepted |
| nautobot-2 | delete leaf-200 | 3.78 s | 1 accepted |
| nautobot-2 | bad_signature | 1 in 120 s | the wrong secret's delivery, refused 401, counted once: not sent again within 120 s |
| nautobot-2 | 503 | 1 in 120 s | the stand-in listener's one arrival, 0.14 s after the write: not sent again within 120 s |
| nautobot-2 | stale | 0 | |
| nautobot-3 | webhook created | webhook 201 | |
| nautobot-3 | update leaf-01's os_version | 4.04 s | 1 accepted |
| nautobot-3 | create leaf-200 | 3.76 s | 1 accepted |
| nautobot-3 | delete leaf-200 | 3.73 s | 1 accepted |
| nautobot-3 | bad_signature | 1 in 120 s | the wrong secret's delivery, refused 401, counted once: not sent again within 120 s |
| nautobot-3 | 503 | 1 in 120 s | the stand-in listener's one arrival, 0.14 s after the write: not sent again within 120 s |
| nautobot-3 | stale | 0 | |

Every release delivered to the `https` payload URL under the private CA with verification on, from the first
change: no TLS failure in the worker's log, and every delivery authenticated and fell inside the window
(`stale` 0). Each change published one bundle through the webhook, about 1.5–2 s after the debouncer's settle
(NetBox's, 0.4–0.7 s; the record does not split that between the delivery's arrival and the sync's read): a
`+0 −0, 1 changed` bundle for the
update, `+1` for the create (leaf-200 admitted by the site `dc1` key group), and `−1` for the delete. The service
said `source l33's deliveries authenticate` once, at the first, and the wrong secret's refusal once
(`bad_signature`, naming the source and the worker's address).

**Sent again?** Neither the 401 nor the 503 was. Every release's worker logged the task
`nautobot.extras.tasks.process_webhook` for each as `raised unexpected: RequestException('Status 401 returned ...
webhook FAILED to process.')` (`503`), once, and no task for it after. No release has a retry setting for webhooks: `process_webhook` is a plain
`@nautobot_task` (`nautobot/extras/tasks.py:108` in 1.6.32, `:225` in 2.4.43, `:64` in 3.2.6; `nautobot_task =
shared_task` in `nautobot/core/celery/__init__.py`) with no `autoretry_for`, `max_retries` or `retry_backoff`, and no setting names one, in 1.6.32,
2.4.43 and 3.2.6 alike (read from each image's `nautobot/extras/tasks.py` and the package). So a Nautobot delivery
refused 401, or answered 503 (here by the stand-in listener), is lost; the scheduled sync covers the change.

### Not observed

- A delivery whose certificate the worker's default trust store holds (only the private CA was tried).
- A burst of changes inside the debouncer's 30 s gap (each change here was 35 s after the last).
- A 503 from port49-inventory itself (it answers 503 only on a connection open when shutdown began), and a
  delivery while port49-inventory is down (connection refused), the common restart case.
