# L30 — Nautobot

- **Date measured:** 2026-09-30, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from `status.json` `nautobot-version`):** Nautobot **1.6.32**, **2.4.43** and
  **3.2.6**; 1.6.32 and 2.4.43 are the images L27 ran (`L27-nautobot.md`)
- **Images:**
  - `docker.io/networktocode/nautobot:1.6.32@sha256:cc1c31b17b263d5b715a1e177ea5f0e16252ce357297ae9e8700a92bf82035b7`
  - `docker.io/networktocode/nautobot:2.4.43@sha256:7d61a4b0980d07e9fa6416a90345af1e2ef7d92b274a313769c85eea0a13d79d`
  - `docker.io/networktocode/nautobot:3.2.6@sha256:37c315740a8242de6c0afbbdbd6f4ffa4f421949a16542a2dae61405d2dbd535`
    (the newest `3.*` on Docker Hub on 2026-09-30, pushed 2026-09-28)
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
    (the reverse proxy; responses carry `Server: nginx/1.27.5`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/nautobot-1.6.yml`, `tests/lab/sot/compose/nautobot-2.yml`,
  `tests/lab/sot/compose/nautobot-3.yml` (`nautobot-2.yml` with the 3.2.6 image and port 18030), each with the
  `l30` profile's `proxy` service; the proxy's config is `tests/lab/sot/compose/l30-proxy.conf` with
  `nautobot:8080` upstream (`proxy_set_header Host $http_host`, `X-Forwarded-Host $http_host`,
  `X-Forwarded-Proto https`)
- **Run:** `tests/lab/sot/run.sh nautobot-1.6 l30`, `run.sh nautobot-2 l30`, `run.sh nautobot-3 l30`
  (procedure and variables: `tests/lab/sot/README.md`); recorder `tests/lab/cmd/sot-record` with `-devices 120
  -page-limit 50 -proxy http://127.0.0.1:<port+1000>` (19016, 19020, 19030); 1.6.32 also with
  `-prefer-legacy` (it took only the legacy spelling, L27); 2.4.43 and 3.2.6 also with `-depth1-read`
- **Capture pointer (the fixtures):** `tests/lab/sot/l30/nautobot-1.6/`, `tests/lab/sot/l30/nautobot-2/`,
  `tests/lab/sot/l30/nautobot-3/` (also every L27 file for 3.2.6)
- **Credentials:** every password, secret key and API token was random per run, passed by environment,
  and is in no committed file; no fixture carries an `Authorization` header. The webhook secret
  `l27-lab-webhook-secret` is **public and lab only**, as in L27.
- **Status:** L30 closed — measured 2026-09-30 (spec §15, row L30, and its note under the register; plan 6b Task 21)

## Claim

For a REST device list holding more devices than its `limit`: whether `next` is an absolute URL, which
scheme and host it carries read directly and behind a reverse proxy, and whether following it to a null
returns every device exactly once; how GraphQL pages the same list, if at all; and, for Nautobot 3.x,
every L27 question (spec §15, L30).

## Observation: paging

Every version took the bulk create: `seed-bulk.json` `bulk_2` 201, 100 sent, 100 created; `bulk_102` 201,
19 sent, 19 created (1.6.32 with the legacy spelling, `device_role`/`site`/`"active"`). With leaf-01 the list
holds 120 devices.

| claim | 1.6.32 | 2.4.43 | 3.2.6 |
|---|---|---|---|
| `next` on the first page, read directly | absolute: `rest-pages.json` `pages[0].next` = `http://127.0.0.1:18016/api/dcim/devices/?limit=50&offset=50`; the dialed scheme, host and port; `previous` = `null` | absolute: `http://127.0.0.1:18020/api/dcim/devices/?limit=50&offset=50`; `previous` = `null` | absolute: `http://127.0.0.1:18030/api/dcim/devices/?limit=50&offset=50`; `previous` = `null` |
| `next` on the first page, read through the proxy | `rest-page-proxied.json` 200, `body.next` = `https://127.0.0.1:19016/api/dcim/devices/?limit=50&offset=50`: **the proxy's host and port, and the scheme from `X-Forwarded-Proto`**; `results[0].url` rewritten the same way | `body.next` = `https://127.0.0.1:19020/api/dcim/devices/?limit=50&offset=50`: the proxy's host, `https` | `body.next` = `https://127.0.0.1:19030/api/dcim/devices/?limit=50&offset=50`: the proxy's host, `https` |
| following `next` to the end | `rest-pages.json`: 3 pages, each 200, `count` 120, results 50/50/20; `ended_at` = `"null_next"`; 120 names, 120 distinct, `repeated` = `null`; `count` = 120 | the same: 3 pages, 50/50/20, `"null_next"`, 120 names, none repeated | the same: 3 pages, 50/50/20, `"null_next"`, 120 names, none repeated |
| GraphQL, unpaged (`graphql-list.json` `graphql_list_0`, `{ devices { name status { name } } }`) | 200, no errors, **120 names** | 200, no errors, 120 names | 200, no errors, 120 names |
| GraphQL, `devices(limit: 50, offset: 0)` and `offset: 50` (`graphql_list_1`, `graphql_list_2`) | 200, 50 names each; offset 0 begins at `leaf-01`, offset 50 at `leaf-051` (`first.name`) | 200, 50 each; `leaf-01`, `leaf-051` | 200, 50 each; `leaf-01`, `leaf-051` |
| the paged GraphQL shape the version takes | `limit`/`offset` on `devices` | `limit`/`offset` | `limit`/`offset` |
| GraphQL `status` in the unpaged list | `graphql_list_0` `first` = `{"name": "leaf-01", "status": {"name": "Active"}}` | `{"status": {"name": "Active"}}` | `{"status": {"name": "Active"}}` |

## Observation: Nautobot 3.2.6, the L27 questions

Read from `tests/lab/sot/l30/nautobot-3/`, with 2.4.43 from `L27-nautobot.md` for comparison. 3.2.6 answered
every L27 question as 2.4.43 did, except where the cell says otherwise.

| claim | 3.2.6 |
|---|---|
| version reported by | `status.json` body `nautobot-version` = `"3.2.6"`; `api-root.json` header `Api-Version` = `"3.2"` |
| role (REST write) | `role` + `/api/extras/roles/`: `seed.json` step `role` 201, `device` 201; step `role_v1` (`/api/dcim/device-roles/`) 404 |
| role (REST read) | `rest-device.json` `results[0].role` = `{id, object_type: "extras.role", url}`: no name, as 2.4.43 |
| REST read with `?depth=1` | `rest-device-depth1.json` 200: `role.name` = `"leaf"`, `platform` {`name: "eos"`, `network_driver: "arista_eos"`}, `location.name` = `"dc1"`, `primary_ip4` {`address: "10.0.1.5/32"`, `host: "10.0.1.5"`, `ip_version: 4`}, `tags[].name` = `"port49"`, `status.name` = `"Active"`, `custom_fields` = `{"os_version": "4.31.2F"}` |
| platform (REST) | `results[0].platform` = `{id, object_type: "dcim.platform", url}` |
| site / location (REST) | `results[0].location` = `{id, object_type: "dcim.location", url}`; no `site` key; `/api/dcim/sites/` 404 (step `site_v1`) |
| primary address (REST) | `results[0].primary_ip4` = `{id, object_type: "ipam.ipaddress", url}` |
| custom fields (REST) | `results[0].custom_fields` = `{"os_version": "4.31.2F"}` |
| tags (REST) | `results[0].tags` = `[{id, object_type: "extras.tag", url}]` |
| status (REST write and read) | write takes `"Active"`; `"active"` refused: step `mgmt_v1` 400 `{"status": ["Related object not found using the provided attributes: {'name': 'active'}"]}`; read `{id, object_type: "extras.status", url}` |
| interface address (REST write) | steps `mgmt_ip`, `loop_ip` 400 `{"__all__": ["One of parent or namespace must be provided"]}`; `mgmt_ip_parent`, `loop_ip_parent` 201; `/api/ipam/ip-address-to-interface/` binds (steps `mgmt_bind`, `loop_bind` 201) |
| device fields (REST) | `rest-device.json` `results[0]` keys are 2.4.43's less **`cluster`** and **`software_image_files`** (fields L27's seed never set) |
| GraphQL endpoint | `POST /api/graphql/` |
| GraphQL query shape taken | only `graphql_0` (`devices(name: "leaf-01") { … platform { name network_driver } location { name } role { name } … _custom_field_data tags { name } … }`), HTTP 200; `graphql_1` and `graphql_2` HTTP 400: no `slug` on `PlatformType` or `TagType`, no `site` or `device_role` on `DeviceType`, and (`graphql_1`) no `custom_fields` |
| GraphQL field names | `graphql_0` data: `platform.name`, `platform.network_driver` = `"arista_eos"`, `location.name`, `role.name`, `primary_ip4.address`, `_custom_field_data` = `{"os_version": "4.31.2F"}`, `tags[].name` |
| one GraphQL query returns every interface address | yes, `graphql_0`: `Loopback0` → `10.0.1.6/32`, `Management1` → `10.0.1.5/32` |
| REST pagination (`rest-page.json`, `?limit=1`, read before the bulk create) | body keys `count`, `next`, `previous`, `results`; `count` = 1, `next` = `null` |
| webhook configuration | `webhooks.json` call `webhook` (`content_types: ["dcim.device"]`, `type_create`/`type_update`/`type_delete`, `secret`) 201 |
| webhook deliveries | 3, **arrived `updated`, `deleted`, `created`** (`deliveries[].at`, within 3 ms); body `timestamp`s in change order (`updated`, `created`, `deleted`) |
| webhook latency (body `timestamp` to arrival `at`) | 3.2–3.4 s |
| webhook headers | `Content-Type: application/json`, `User-Agent: python-urllib3/2.8.0`, `X-Hook-Signature`, `Content-Length`, `Accept-Encoding` |
| webhook body | keys `event`, `timestamp`, `model` = `"device"`, `username` = `"admin"`, `request_id`, `data`, `snapshots` {`prechange`, `postchange`, `differences`} |
| webhook body carries the change | update: `data.custom_fields.os_version` = `"4.32.2F"`; create has `snapshots.prechange` null, delete has `postchange` null |
| webhook signature | `X-Hook-Signature` = HMAC-SHA512(body, secret), hex: `signature_is_hmac_sha512_of_body` true on all 3 |

Order and latency are one run's sample; 3.2.6 did not deliver in change order either. 6b orders by the body
`timestamp` (or refetches), never by arrival, as L27 found for 1.6 and 2.x.

### Not observed

- Following the proxied `next`: only the first page was read through the proxy. The proxy listens on plain
  http, and the `https://` `next` it produced was not dialed; in production the proxy terminates TLS.
- Which header Nautobot built the proxied host from: the proxy sent the client's `Host` as both `Host` and
  `X-Forwarded-Host`, so the two cannot be told apart in this run.
- A list changing between pages: nothing was created or deleted while `rest-pages.json` was read.
- A GraphQL list larger than any server-side cap: 120 names came back unpaged on every version.
- Whether the two GraphQL pages are disjoint: `graphql-list.json` records each page's count and first
  device, not every name.
- `celery-workers-running` in 3.2.6's `status.json` reads 0, though the worker delivered webhooks later in the
  same run, as L27 saw on 1.6 and 2.x; that it was read before the worker registered is an inference.
- A `?depth=1` read on 1.6: not asked, as L27.
