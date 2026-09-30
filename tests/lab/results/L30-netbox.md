# L30 — NetBox

- **Date measured:** 2026-09-30, on beehive (Docker 29.1.3, Compose v5.5.1)
- **Product and versions (from `status.json` `netbox-version`):** NetBox **3.7.8** and NetBox **4.7.1**
  (`netbox-full-version` = `4.7.1-Docker-5.1.1`); the same images L27 ran (`L27-netbox.md`)
- **Images:**
  - `docker.io/netboxcommunity/netbox:v3.7.8@sha256:9bf83b350a8956a83cccb11a6bf709fad0780f4e9ec4857adc747d547ade2134`
  - `docker.io/netboxcommunity/netbox:v4.7.1@sha256:59e3e5954d0243d8648f2fa7ba82cf7c7770aaeef392026cca8b21cd67411e74`
  - `docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
    (the reverse proxy; responses carry `Server: nginx/1.27.5`)
  - `docker.io/library/postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
  - `docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507`
- **Compose files:** `tests/lab/sot/compose/netbox-3.7.yml`, `tests/lab/sot/compose/netbox-4.yml`, each with
  the `l30` profile's `proxy` service; the proxy's config is `tests/lab/sot/compose/l30-proxy.conf`
  (`proxy_set_header Host $http_host`, `X-Forwarded-Host $http_host`, `X-Forwarded-Proto https`)
- **Run:** `tests/lab/sot/run.sh netbox-3.7 l30`, `run.sh netbox-4 l30` (procedure and variables:
  `tests/lab/sot/README.md`); recorder `tests/lab/cmd/sot-record` with `-devices 120 -page-limit 50
  -proxy http://127.0.0.1:<port+1000>` (19037 for 3.7, 19080 for 4); 4.7.1 also with `-auth-scheme Bearer
  -probe-v1-token`
- **Capture pointer (the fixtures):** `tests/lab/sot/l30/netbox-3.7/`, `tests/lab/sot/l30/netbox-4/`
- **Credentials:** every password, secret key, pepper and API token was random per run, passed by
  environment, and is in no committed file; no fixture carries an `Authorization` header. The webhook
  secret `l27-lab-webhook-secret` is **public and lab only**, as in L27.
- **Status:** L30 open; Task 21 closes the row.

## Claim

For a REST device list holding more devices than its `limit`: whether `next` is an absolute URL, which
scheme and host it carries read directly and behind a reverse proxy, and whether following it to a null
returns every device exactly once; and how GraphQL pages the same list, if at all (spec §15, L30).

## Observation

Both versions took the bulk create: `seed-bulk.json` `bulk_2` 201, 100 sent, 100 created; `bulk_102` 201,
19 sent, 19 created. With leaf-01 the list holds 120 devices.

| claim | 3.7.8 | 4.7.1 |
|---|---|---|
| `next` on the first page, read directly | absolute: `rest-pages.json` `pages[0].next` = `http://127.0.0.1:18037/api/dcim/devices/?limit=50&offset=50`; the scheme, host and port the recorder dialed; `previous` = `null` | absolute: `pages[0].next` = `http://127.0.0.1:18080/api/dcim/devices/?limit=50&offset=50`; the dialed scheme, host and port; `previous` = `null` |
| `next` on the first page, read through the proxy | `rest-page-proxied.json` (`GET http://127.0.0.1:19037/api/dcim/devices/?limit=50`) 200, `body.next` = `https://127.0.0.1:19037/api/dcim/devices/?limit=50&offset=50`: **the proxy's host and port, and the scheme from `X-Forwarded-Proto`**, not NetBox's own `:8080` or `http`. Every `results[].url` is rewritten the same way (`https://127.0.0.1:19037/api/dcim/devices/1/`) | `body.next` = `https://127.0.0.1:19080/api/dcim/devices/?limit=50&offset=50`: the proxy's host and port, scheme `https`; `results[0].url` = `https://127.0.0.1:19080/api/dcim/devices/1/` |
| following `next` to the end | `rest-pages.json`: 3 pages (`page_0`..`page_2`, each 200, `count` 120, results 50/50/20), `next` offsets 50, 100, then `null`; `ended_at` = `"null_next"`; 120 names, 120 distinct, `repeated` = `null`; `count` = 120 | the same: 3 pages, 50/50/20, `ended_at` = `"null_next"`, 120 names, none repeated, `count` = 120 |
| GraphQL, unpaged (`graphql-list.json` `graphql_list_0`, `{ device_list { name status } }`) | 200, no errors, **120 names**: no silent cap | 200, no errors, **120 names** |
| GraphQL, `device_list(pagination: {offset, limit: 50})` (`graphql_list_1`, `graphql_list_2`) | **400**: `Unknown argument 'pagination' on field 'Query.device_list'. Did you mean 'position'?` | **200**, 50 names each; offset 0 begins at `leaf-01`, offset 50 at `leaf-051` (`first.name`) |
| GraphQL, `device_list(limit: 50, offset: 0)` (`graphql_list_3`) | 400: `Unknown argument 'limit'…`, `Unknown argument 'offset'…` | **HTTP 200 with `errors`**: `Unknown argument 'limit' on field 'Query.device_list'.`, the same for `offset`, 0 names |
| the paged GraphQL shape the version takes | none of those tried: 3.7.8 pages no list shape L30 asked; the unpaged list returned all 120 | `pagination: {offset, limit}` |
| GraphQL `status` in the unpaged list | `graphql_list_0` `first` = `{"name": "leaf-01", "status": "ACTIVE"}`: **upper-case enum name** | `first` = `{"name": "leaf-01", "status": "active"}`: the lower-case value |

The 4.7.1 `graphql_list_3` answer is a refusal carried in a 200: a client that reads the HTTP status alone
takes an empty list for an empty inventory. 6c reads `errors` before `data`.

### Not observed

- Following the proxied `next`: only the first page was read through the proxy. The proxy listens on plain
  http, and the `https://` `next` it produced was not dialed; in production the proxy terminates TLS.
- Which header NetBox built the proxied host from: the proxy sent the client's `Host` as both `Host` and
  `X-Forwarded-Host`, so the two cannot be told apart in this run.
- A list changing between pages: nothing was created or deleted while `rest-pages.json` was read, so what
  offset paging does across a concurrent insert or delete is not recorded.
- A GraphQL list larger than any server-side cap: 120 names came back unpaged on both versions; whether a
  `MAX_PAGE_SIZE` or GraphQL limit applies at larger counts is not recorded.
