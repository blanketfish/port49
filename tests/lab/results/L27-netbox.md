# L27 — NetBox

- **Date measured:** 2026-09-30, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from `status.json` `netbox-version`):** NetBox **3.7.8** and NetBox **4.7.1**
  (`netbox-full-version` = `4.7.1-Docker-5.1.1`)
- **Images:**
  - `docker.io/netboxcommunity/netbox:v3.7.8@sha256:9bf83b350a8956a83cccb11a6bf709fad0780f4e9ec4857adc747d547ade2134`
    (the newest `v3.7.*`; same digest as `v3.7.8-2.8.0`, netbox-docker 2.8.0)
  - `docker.io/netboxcommunity/netbox:v4.7.1@sha256:59e3e5954d0243d8648f2fa7ba82cf7c7770aaeef392026cca8b21cd67411e74`
    (the newest `v4.*`; same digest as `v4.7.1-5.1.1`, netbox-docker 5.1.1)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/netbox-3.7.yml`, `tests/lab/sot/compose/netbox-4.yml`
- **Run:** `tests/lab/sot/run.sh netbox-3.7`, `run.sh netbox-3.7 legacy`, `run.sh netbox-4` (procedure and
  variables: `tests/lab/sot/README.md`); recorder `tests/lab/cmd/sot-record` (`-product netbox`; 4.7.1 with
  `-auth-scheme Bearer -probe-v1-token`)
- **Capture pointer (the fixtures):** `tests/lab/sot/fixtures/netbox-3.7/`,
  `tests/lab/sot/fixtures/netbox-3.7-legacy/` (the `-prefer-legacy` rerun), `tests/lab/sot/fixtures/netbox-4/`
- **Credentials:** every password, secret key, pepper and API token was random per run, passed by
  environment, and is in no committed file; no fixture carries an `Authorization` header. The webhook
  secret `l27-lab-webhook-secret` is **public and lab only** (never use it anywhere else), kept so
  `X-Hook-Signature` in `webhooks.json` can be verified against it.
- **Status:** L27 stays open here; plan 6a Task 21 closes it for the versions measured.

## Claim

What NetBox's API returns for a device, per major version: where the version is reported; the field
names for role, platform, site, primary address, custom fields and tags over REST and over one GraphQL
query; which GraphQL query shape each version takes, and whether one query returns every interface
address; how REST paginates; and what a device create, update and delete webhook carries (spec §15, L27).

## Observation

Each cell quotes the fixture it was read from. "3.7" is `netbox-3.7/`; the `-legacy` rerun recorded the
same outcome for every step (below).

| claim | 3.7.8 | 4.7.1 |
|---|---|---|
| version reported by | `status.json` body `netbox-version` = `"3.7.8"`; `api-root.json` header `Api-Version` = `"3.7"` (also on `status.json`) | `status.json` body `netbox-version` = `"4.7.1"`, `netbox-full-version` = `"4.7.1-Docker-5.1.1"`; `api-root.json` header `Api-Version` = `"4.7"` |
| API token the stack provisions (source: the compose file and `run.sh`, not a fixture; the recorder never records a request's auth) | v1, `Authorization: Token <40 hex>`: every 3.7 fixture was read with it | v2, `Authorization: Bearer nbt_<12-char key>.<40-char token>`: netbox-docker 5.1.1's `super_user.py` creates only a v2 token, and only with `API_TOKEN_PEPPER_1` set; every other 4.7 fixture was read with it |
| v1 token on 4.x | not asked (3.7 has only v1) | **accepted**: `auth-v1.json` step `v1_token_create` (`POST /api/users/tokens/` `{"user": 1, "version": 1}`) 201, body `version` = 1, `key` = `null`, `pepper_id` = `null`, `token` issued (recorded as `<redacted>`); step `v1_token_status` (`GET /api/status/` with `Authorization: Token <that token>`) 200, `netbox-version` = `"4.7.1"` |
| role field (REST write) | `role`: `seed.json` step `device` 201; `device_role` refused: step `device_v3` 400 `{"role": ["This field is required."]}` | `role`: step `device` 201; step `device_v3` 400 `{"role": ["This field is required."]}` |
| role field (REST read) | `rest-device.json` `results[0]` has **both** `role` and `device_role`, the same object (`id`, `url`, `display`, `name`, `slug`) | `results[0].role` only (`id`, `url`, `display`, `name`, `slug`, `description`, `device_count`, `virtualmachine_count`, `_depth`); no `device_role` key |
| platform (REST) | `results[0].platform` = `{id, url, display, name, slug}` | `results[0].platform`, same keys plus `description`, counts, `_depth` |
| site / location (REST) | `results[0].site` = `{id, url, display, name, slug}`; `location` = `null` | `results[0].site` = `{id, url, display, name, slug, description}`; `location` = `null` |
| primary address (REST) | `results[0].primary_ip4` = `{id, url, display, family: 4, address: "10.0.1.5/32"}`; `primary_ip` the same | `results[0].primary_ip4` = `{…, family: {value: 4, label: "IPv4"}, address: "10.0.1.5/32", …}`; `primary_ip` the same |
| custom fields (REST) | `results[0].custom_fields` = `{"os_version": "4.31.2F"}` | `results[0].custom_fields` = `{"os_version": "4.31.2F"}` |
| custom field create | `content_types`: step `custom_field` (with `object_types`) 400 `{"content_types": ["This field is required."]}`; step `custom_field_v3` 201 | `object_types`: step `custom_field` 201; step `custom_field_v3` 400 `{"object_types": ["This field is required."], …}` |
| tags (REST) | `results[0].tags` = `[{id, url, display, name: "port49", slug: "port49", color}]` | `results[0].tags` = `[{id, url, display_url, display, name: "port49", slug: "port49", color}]` |
| status (REST) | `results[0].status` = `{"value": "active", "label": "Active"}` | `results[0].status` = `{"value": "active", "label": "Active"}` |
| GraphQL endpoint | `POST /graphql/` | `POST /graphql/` |
| GraphQL query shape taken | only `graphql_3`: `device_list(name: "leaf-01") { … role { slug } … custom_fields … }`, HTTP 200. `graphql_0`/`graphql_1` HTTP 400 `Unknown argument 'filters' on field 'Query.device_list'`; `graphql_2` HTTP 400 `Cannot query field 'device_role' on type 'DeviceType'` | only `graphql_0`: `device_list(filters: {name: {exact: "leaf-01"}}) { … role { slug } … }`, HTTP 200. `graphql_1` `Expected value of type 'StrFilterLookup', found "leaf-01"`; `graphql_2` and `graphql_3` `Unknown argument 'name' on field 'Query.device_list'`. All refusals are HTTP **200** with `"data": null` and `errors` |
| GraphQL field names | `graphql_3` data: `platform.slug`, `site.slug`, `role.slug`, `primary_ip4.address`, `custom_fields` (object), `tags[].slug` | `graphql_0` data: the same names |
| one GraphQL query returns every interface address | yes, `graphql_3`: `interfaces` = `Loopback0` → `10.0.1.6/32`, `Management1` → `10.0.1.5/32` | yes, `graphql_0`: the same two interfaces and addresses |
| REST pagination | `rest-page.json` (`?limit=1`): body keys `count`, `next`, `previous`, `results`; `count` = 1, `next` = `null` | same keys; `count` = 1, `next` = `null` |
| webhook configuration | a webhook has no event or model fields: `webhooks.json` call `webhook` 201; delivery needs an event rule, which 3.7 takes as `content_types` + `type_create`/`type_update`/`type_delete`: call `event_rule` (`object_types` + `event_types`) 400 `{"content_types": ["This field is required."]}`, call `event_rule_v3` 201 | call `webhook` 201, call `event_rule` (`object_types`, `event_types: ["object_created", "object_updated", "object_deleted"]`) 201; call `event_rule_v3` 400 `{"object_types": …, "event_types": ["This field is required."], …}` |
| webhook deliveries | 3, arrived `updated`, `created`, `deleted` (`deliveries[].at`), the order the changes were made (body `timestamp`) | 3, arrived `updated`, `created`, `deleted`, the order the changes were made |
| webhook latency (body `timestamp` to arrival `at`) | 0.03–0.04 s | 0.55–0.70 s |
| webhook headers | `Content-Type: application/json`, `User-Agent: python-urllib3/2.2.1`, `X-Hook-Signature`, `Content-Length`, `Accept-Encoding` | the same set; `User-Agent: python-urllib3/2.8.0` |
| webhook body | keys `event` (`"created"`/`"updated"`/`"deleted"`), `timestamp`, `model` = `"device"`, `username` = `"admin"`, `request_id`, `data` (the REST device), `snapshots` {`prechange`, `postchange`} | keys `event`, `timestamp`, `object_type` = `"dcim.device"`, `request` {`id`, `path`, `method`, `user`: `"admin"`, …}, `data`, `snapshots` {`prechange`, `postchange`}; no `model`, `username` or `request_id` |
| webhook body carries the change | update: `data.custom_fields.os_version` = `"4.32.2F"`; create has `prechange` null, delete has `postchange` null | the same |
| webhook signature | `X-Hook-Signature` = HMAC-SHA512(body, secret), hex: `signature_is_hmac_sha512_of_body` true on all 3 | true on all 3 |

### The legacy rerun

3.7.8 took the 4.x `role` spelling itself; the only older spelling it needed was `content_types` on the
custom field and the event rule. `netbox-3.7-legacy/` (fresh stack, `-prefer-legacy`) recorded the same
status for every step, the same `graphql_3` success and the same 3 deliveries as `netbox-3.7/`.

Order and latency are one run's sample each (three events, one worker); 6b orders by the body
`timestamp`, never by arrival.

### Not observed

- `next` non-null: the run holds one device when `rest-page.json` is read, so pagination's `next`
  link was never populated; the body shape (`count`/`next`/`previous`/`results`) is what was recorded.
- `rq-workers-running` in `status.json` reads 0 on both versions, though the worker delivered every
  webhook later in the same run. That `status.json` was read before the worker registered is an
  inference, not a recorded fact.
