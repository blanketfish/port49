# L27 — Nautobot

- **Date measured:** 2026-09-30, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from `status.json` `nautobot-version`):** Nautobot **1.6.32** and Nautobot **2.4.43**
- **Images:**
  - `docker.io/networktocode/nautobot:1.6.32@sha256:cc1c31b17b263d5b715a1e177ea5f0e16252ce357297ae9e8700a92bf82035b7`
    (the newest `1.6.*`)
  - `docker.io/networktocode/nautobot:2.4.43@sha256:7d61a4b0980d07e9fa6416a90345af1e2ef7d92b274a313769c85eea0a13d79d`
    (the newest `2.*`; Docker Hub also carries a `3.*` line, newest `3.2.6`, which L27's row does not name
    and this run did not measure)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/nautobot-1.6.yml`, `tests/lab/sot/compose/nautobot-2.yml`
  (web: the image's `nautobot-server start --ini /opt/nautobot/uwsgi.ini`; worker: `nautobot-server celery worker`)
- **Run:** `tests/lab/sot/run.sh nautobot-1.6`, `run.sh nautobot-1.6 legacy`, `run.sh nautobot-2` (procedure
  and variables: `tests/lab/sot/README.md`); recorder `tests/lab/cmd/sot-record` (`-product nautobot`,
  `Authorization: Token <40 hex>`; 2.4.43 with `-depth1-read`)
- **Capture pointer (the fixtures):** `tests/lab/sot/fixtures/nautobot-1.6/`,
  `tests/lab/sot/fixtures/nautobot-1.6-legacy/` (the `-prefer-legacy` rerun), `tests/lab/sot/fixtures/nautobot-2/`
- **Credentials:** every password, secret key and API token was random per run, passed by environment,
  and is in no committed file; no fixture carries an `Authorization` header. The webhook secret
  `l27-lab-webhook-secret` is **public and lab only** (never use it anywhere else), kept so
  `X-Hook-Signature` in `webhooks.json` can be verified against it.
- **Status:** L27 closed 2026-09-30 by plan 6a Task 21 for the versions measured; a non-null
  pagination `next` and Nautobot 3.x are L30, open.

## Claim

What Nautobot's API returns for a device, per major version: where the version is reported; the field
names for role, platform, site or location, primary address, custom fields and tags over REST and over
one GraphQL query; which GraphQL query shape each version takes, and whether one query returns every
interface address; how REST paginates; and what a device create, update and delete webhook carries
(spec §15, L27).

## Observation

1.6.32 refused the 2.x spelling of the device (`role`, `location`), so every later step of
`nautobot-1.6/` named a device that did not exist; the 1.6 column is read from `nautobot-1.6-legacy/`
unless it says otherwise. Both directories are the record of which spelling 1.6 refused.

| claim | 1.6.32 | 2.4.43 |
|---|---|---|
| version reported by | `status.json` body `nautobot-version` = `"1.6.32"`; `api-root.json` header `Api-Version` = **`"1.2"`**, not the release (that 1.2 is 1.6's default REST API version is an inference; the run sent no `Accept: …; version=`) | `status.json` body `nautobot-version` = `"2.4.43"`; `api-root.json` header `Api-Version` = `"2.4"` |
| role (REST write) | `device_role` + `/api/dcim/device-roles/`: `nautobot-1.6/seed.json` step `role` (`/api/extras/roles/`) 404, step `device` 400 `{"device_role": ["This field is required."], "site": ["This field is required."]}`; steps `role_v1` 201, `device_v1` 201 | `role` + `/api/extras/roles/`: step `role` 201, `device` 201; step `role_v1` (`/api/dcim/device-roles/`) 404 |
| role (REST read) | `rest-device.json` `results[0].device_role` = `{display, id, url, name: "leaf", slug: "leaf"}`; no `role` key | `results[0].role` = `{id, object_type: "extras.role", url}`: **no name**; at default depth REST nests every related object as `{id, object_type, url}` |
| REST read with `?depth=1` | not asked | `rest-device-depth1.json` (`GET /api/dcim/devices/?name=leaf-01&depth=1`) 200: every related object inline. `role` = `{…, display: "leaf", name: "leaf", …}`; `platform` = `{…, name: "eos", network_driver: "arista_eos", …}`; `location` = `{…, name: "dc1", …}`; `primary_ip4` = `{…, address: "10.0.1.5/32", host: "10.0.1.5", ip_version: 4, …}`; `tags` = `[{…, name: "port49", …}]`; `status` = `{…, name: "Active", …}`; `custom_fields` = `{"os_version": "4.31.2F"}`. One REST read fills every fact but the interfaces' addresses |
| platform (REST) | `results[0].platform` = `{display, id, url, name: "eos", slug: "eos"}` | `results[0].platform` = `{id, object_type: "dcim.platform", url}` |
| site / location (REST) | `results[0].site` = `{display, id, url, name: "dc1", slug: "dc1"}`; `location` = `null`. A location type named `Site` is refused: step `location_type` 400 `{"name": ["This name is reserved for future use."]}` | `results[0].location` = `{id, object_type: "dcim.location", url}`; no `site` key; `/api/dcim/sites/` 404 (step `site_v1`) |
| primary address (REST) | `results[0].primary_ip4` = `{display, id, url, family: 4, address: "10.0.1.5/32"}` | `results[0].primary_ip4` = `{id, object_type: "ipam.ipaddress", url}` |
| custom fields (REST) | `results[0].custom_fields` = `{"os_version": "4.31.2F"}` | `results[0].custom_fields` = `{"os_version": "4.31.2F"}` |
| tags (REST) | `results[0].tags` = `[{display, id, url, name: "port49", slug: "port49", color, …}]` | `results[0].tags` = `[{id, object_type: "extras.tag", url}]` |
| status (REST write and read) | write takes `"active"` and `"Active"` (steps `site_v1`, `mgmt`, `mgmt_ip` 201); read `{"value": "active", "label": "Active"}` | write takes the name `"Active"`; `"active"` is refused: step `mgmt_v1` 400 `{"status": ["Related object not found using the provided attributes: {'name': 'active'}"]}`; read `{id, object_type: "extras.status", url}` |
| interface address (REST write) | `assigned_object_type` + `assigned_object_id` on the address (steps `mgmt_ip_v1`, `loop_ip_v1` 201); `/api/ipam/ip-address-to-interface/` 404 (steps `mgmt_bind`, `loop_bind`). 1.6 took three `10.0.1.5/32`, in step order `mgmt_ip` (unassigned), `mgmt_ip_v1` (assigned), `mgmt_ip_parent` (unassigned), each 201 with its own `id`: duplicates allowed; no `parent` key in the response | an address needs its prefix: steps `mgmt_ip`, `loop_ip` 400 `{"__all__": ["One of parent or namespace must be provided"]}`; `mgmt_ip_parent`, `loop_ip_parent` (with `parent`) 201; then `/api/ipam/ip-address-to-interface/` binds it (steps `mgmt_bind`, `loop_bind` 201) |
| GraphQL endpoint | `POST /api/graphql/` | `POST /api/graphql/` |
| GraphQL query shape taken | only `graphql_2`: `devices(name: "leaf-01") { … platform { slug network_driver } site { slug } device_role { slug } … _custom_field_data tags { slug } … }`, HTTP 200. `graphql_0` HTTP 400 `Cannot query field "role" on type "DeviceType"`; `graphql_1` HTTP 400 `Cannot query field "custom_fields" on type "DeviceType". Did you mean "_custom_field_data"?` | only `graphql_0`: `devices(name: "leaf-01") { … platform { name network_driver } location { name } role { name } … _custom_field_data tags { name } … }`, HTTP 200. `graphql_1` and `graphql_2` HTTP 400: no `slug` on `PlatformType` or `TagType`, no `site` or `device_role` on `DeviceType`, and (`graphql_1`) no `custom_fields` |
| GraphQL field names | `graphql_2` data: `platform.slug`, `platform.network_driver` = `"arista_eos"`, `site.slug`, `device_role.slug`, `primary_ip4.address`, `_custom_field_data` = `{"os_version": "4.31.2F"}`, `tags[].slug` | `graphql_0` data: `platform.name`, `platform.network_driver` = `"arista_eos"`, `location.name`, `role.name`, `primary_ip4.address`, `_custom_field_data`, `tags[].name` |
| one GraphQL query returns every interface address | yes, `nautobot-1.6-legacy/graphql.json` `graphql_2`: `Loopback0` → `10.0.1.6/32`, `Management1` → `10.0.1.5/32` (in `nautobot-1.6/`, where no interface was created, `interfaces` = `[]`) | yes, `graphql_0`: `Loopback0` → `10.0.1.6/32`, `Management1` → `10.0.1.5/32` |
| REST pagination | `rest-page.json` (`?limit=1`): body keys `count`, `next`, `previous`, `results`; `count` = 1, `next` = `null` | the same keys; `count` = 1, `next` = `null` |
| webhook configuration | `webhooks.json` call `webhook` (`content_types: ["dcim.device"]`, `type_create`/`type_update`/`type_delete`, `secret`) 201 | the same call, 201 |
| webhook deliveries | 3, **arrived `deleted`, `updated`, `created`** (`deliveries[].at`, all within 1 ms); body `timestamp`s are in the order the changes were made (`updated`, `created`, `deleted`) | 3, **arrived `deleted`, `created`, `updated`** (within 2 ms); body `timestamp`s in change order |
| webhook latency (body `timestamp` to arrival `at`) | 4.3–4.6 s | 9.2–9.4 s |
| webhook headers | `Content-Type: application/json`, `User-Agent: python-urllib3/2.2.2`, `X-Hook-Signature`, `Content-Length`, `Accept-Encoding` | the same set; `User-Agent: python-urllib3/2.8.0` |
| webhook body | keys `event` (`"created"`/`"updated"`/`"deleted"`), `timestamp`, `model` = `"device"`, `username` = `"admin"`, `request_id`, `data`, `snapshots` {`prechange`, `postchange`, `differences`} | the same keys and values |
| webhook body carries the change | update: `data.custom_fields.os_version` = `"4.32.2F"`; create has `snapshots.prechange` null, delete has `postchange` null | the same |
| webhook signature | `X-Hook-Signature` = HMAC-SHA512(body, secret), hex: `signature_is_hmac_sha512_of_body` true on all 3 | true on all 3 |

Order and latency are one run's sample each; neither version delivered in change order in this run.
6b orders by the body `timestamp` (or refetches), never by arrival.

### What the first 1.6 run recorded

`nautobot-1.6/` (no `-prefer-legacy`) is the refusal record: the 2.x `device` step 400, so the
interface, primary and `update`/`delete_2` steps named no device (400 or 404) and the one delivery is the
`created` of `create_2_v1` (signature true). `graphql_2` there returns the device with
`primary_ip4: null` and `interfaces: []`.

### Not observed

- `next` non-null: the run holds one device when `rest-page.json` is read, so pagination's `next`
  link was never populated; the body shape is what was recorded.
- `celery-workers-running` in `status.json` reads 0 on both versions, though the worker delivered
  webhooks later in the same run. That `status.json` was read before the worker registered is an
  inference, not a recorded fact.
- A `?depth=1` read on 1.6: not asked (1.6 nests names at default depth).
