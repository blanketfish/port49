# L27 and L30: NetBox and Nautobot fixtures

What NetBox's and Nautobot's APIs return for one device, recorded from real stacks (spec §15 L27,
plan 6a Task 2), and how their device lists page, with Nautobot 3.x's answers to every L27 question
(spec §15 L30, plan 6b Task 2). The connector tests replay `fixtures/` and `l30/`; the notes are
`tests/lab/results/L27-netbox.md`, `L27-nautobot.md`, `L30-netbox.md` and `L30-nautobot.md`.

| path | what |
|---|---|
| `compose/<stack>.yml` | one product at one version, its Postgres and Valkey, images pinned by digest, API on `127.0.0.1`; an nginx reverse proxy in the `l30` profile on `127.0.0.1:<port+1000>` |
| `compose/l30-proxy.conf` | the proxy's config: forwards the client's `Host` and sets `X-Forwarded-Proto: https` (`run.sh` points it at the stack's product) |
| `run.sh` | records one stack end to end: credentials, up, wait, record, `down -v` |
| `../cmd/sot-record/` | the recorder: seeds leaf-01, reads it over REST and GraphQL, round-trips a webhook; with `-devices`, bulk-creates more, follows the REST list's `next` to its end, reads one page through the proxy, and lists over GraphQL |
| `fixtures/<stack>[-legacy]/` | L27: the recorded exchanges, one JSON file per read |
| `l30/<stack>/` | L30: every L27 file, plus `seed-bulk.json`, `rest-pages.json`, `rest-page-proxied.json`, `graphql-list.json` |

## Running

From the repository root, as a user in the docker group (or under `sg docker -c "…"`), one stack
at a time:

```bash
tests/lab/sot/run.sh netbox-3.7
tests/lab/sot/run.sh netbox-3.7 legacy    # fresh stack, -prefer-legacy, fixtures/netbox-3.7-legacy
tests/lab/sot/run.sh netbox-4
tests/lab/sot/run.sh nautobot-1.6
tests/lab/sot/run.sh nautobot-1.6 legacy
tests/lab/sot/run.sh nautobot-2
tests/lab/sot/run.sh netbox-3.7 l30       # L30: 120 devices, pages of 50, the proxy; l30/netbox-3.7
tests/lab/sot/run.sh netbox-4 l30
tests/lab/sot/run.sh nautobot-1.6 l30     # adds -prefer-legacy: 1.6 took only the legacy spelling (L27)
tests/lab/sot/run.sh nautobot-2 l30
tests/lab/sot/run.sh nautobot-3 l30       # also every L27 file for Nautobot 3.x
make lab-unit                              # the notes still name every recorded version and directory
```

Each run takes 2–4 minutes once the images are pulled. The script gives `/api/status/` 10 minutes and
the recorder 10 minutes, and tears the stack down with `down -v` on every exit, failure included. The
log is `tests/lab/logs/l27-<stack>.log` (`l30-<stack>.log` for an `l30` run), with the compose log beside it and every generated credential
in it replaced by `<redacted>`.

## Credentials

`run.sh` generates every value fresh per run into a 0600 env file outside the repository and never
prints one. No compose file holds a value: each reads `${L27_…:?}` and fails without it.

| variable | used by | value |
|---|---|---|
| `L27_DB_PASSWORD`, `L27_SECRET_KEY`, `L27_ADMIN_PASSWORD` | every stack | random `[A-Za-z0-9]`, 24/60/24 characters |
| `L27_TOKEN` | the recorder; NetBox 3.7 and both Nautobots' superuser token | 40 hex, sent as `Authorization: Token <L27_TOKEN>` |
| `L27_API_KEY`, `L27_API_TOKEN`, `L27_TOKEN_PEPPER` | NetBox 4 only (netbox-docker 5.1.1 provisions a v2 token, and only with a pepper) | 12, 40 and 60 random `[A-Za-z0-9]` |
| `L27_TOKEN` (NetBox 4) | the recorder, with `-auth-scheme Bearer` | `nbt_<L27_API_KEY>.<L27_API_TOKEN>`, sent as `Authorization: Bearer <L27_TOKEN>` |
| `L27_WEBHOOK_SECRET` | the recorder's webhook | `l27-lab-webhook-secret`: **public, lab only**, never use it anywhere else. It is fixed so 6b's verifier can be tested against the recorded `X-Hook-Signature`. |

Set `L27_ENV_DIR=<dir>` to keep the env file after the run, for a count-only audit that no value
reached a committed file:

```bash
for v in $(cut -d= -f2- "$L27_ENV_DIR"/*.env); do grep -rFc -- "$v" tests/lab/sot tests/lab/results/L27-*.md tests/lab/results/L30-*.md; done \
  | awk -F: '{s+=$NF} END{print s+0}'   # must print 0
```

The recorder never records a request's `Authorization` header, and replaces any credential a response
or webhook delivery echoes (including a token the product issues during the run) with `<redacted>`.

## Per-stack recorder flags

`run.sh` sets these; a version bump that adds a stack adds its line to the `case` in `run.sh`.

| stack | flags |
|---|---|
| `netbox-4` | `-auth-scheme Bearer -probe-v1-token` (also issues a v1 token over the API and tries it: `auth-v1.json`) |
| `nautobot-2`, `nautobot-3` | `-depth1-read` (also reads the device with `?depth=1`: `rest-device-depth1.json`) |
| `… legacy` | `-prefer-legacy` |
| `… l30` | `-devices 120 -page-limit 50 -proxy http://127.0.0.1:<port+1000>`, and `--profile l30` to compose; `nautobot-1.6 l30` adds `-prefer-legacy` |
