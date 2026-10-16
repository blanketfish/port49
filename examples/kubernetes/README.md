# Kubernetes: a CronJob's projected token as its port49 identity

Every cluster claim below is provisional on lab entry L69 (kind) or L70 (managed clusters),
named by cell, until `tests/lab/results/L69-kind.md` closes the row. Nothing here is measured yet.

| File | What it is |
|---|---|
| `issuer-discovery.yaml` | the ClusterRoleBinding that lets the broker read the cluster's public keys |
| `backup-cronjob.yaml` | a ServiceAccount and a CronJob that mints tokens with `port49 workload token --token-file` |
| `port49d-identity.yaml` | the `broker.identity` fragment: one `k8s` verifier per cluster, two regions here |
| `policy.yaml` | the subject the CronJob's service account maps to |

`examples_test.go` parses all four, loads the identity fragment through port49d's config loader and
the policy through the policy loader, and checks they agree (audience, namespace, principal).

## 1. What it is

The pod's projected service account token is the workload's identity (design §7). No CA, no
secret at rest: the kubelet writes and rotates the token, the broker verifies its signature
against the cluster's published keys.

## 2. The cluster

- **Set `--service-account-issuer` per cluster.** kubeadm's default is the same everywhere, and
  port49 refuses one issuer twice. This is the main onboarding cost for a self-managed fleet.
  The safe sequence when changing an issuer (provisional on L69 (a), (d)):
  1. Add the new issuer as the *first* `--service-account-issuer` flag, keeping the old one as a
     second (the API server signs with the first and accepts both).
  2. In port49 list both issuers as two `k8s` verifiers on the same `jwks` (decision 49 ruling 4's
     migration case).
  3. Roll the pods.
  4. After the longest `expirationSeconds` in use has passed, remove the old flag and the old
     verifier.
- **Apply `issuer-discovery.yaml`** (provisional on L69 (c); managed clusters are unmeasured,
  L70). Issuer discovery needs `--anonymous-auth` on; a CIS-hardened cluster turns it off. On
  1.32+ use the structured authentication configuration (`AuthenticationConfiguration`'s
  `anonymous.conditions`) to allow anonymous requests to `/.well-known/openid-configuration` and
  `/openid/v1/jwks` alone.
- **`jwks` is the API server's own address, not the issuer's host.** Discovery's `jwks_uri`
  names the issuer's host, which nothing outside the cluster may resolve; that is why decision 49
  ruling 2 reads `jwks` directly:

  ```sh
  echo "$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')/openid/v1/jwks"
  ```

  It may be any https mirror of the keys (a bucket, a reverse proxy) for a cluster whose API
  server the broker must not reach.
- **The cluster CA for `ca_file`:**

  ```sh
  kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d
  ```

## 3. The broker

`port49d-identity.yaml` is a fragment for `port49-broker.yaml`. Per verifier:

| Key | Meaning |
|---|---|
| `type: k8s` | a machine verifier; a cluster's service accounts are workloads, not humans |
| `cluster` | port49's name for the cluster, in records and log lines; the cluster's manifests do not change |
| `issuer` | the cluster's `--service-account-issuer`, as its tokens carry it in `iss` |
| `jwks` | where the broker reads the keys (section 2) |
| `ca_file` | the CA the broker trusts for `jwks` |
| `audience` | what the pods' token volume asks for (`port49` here) |
| `namespaces` | the namespaces whose service accounts this cluster may name |

One verifier per cluster, each with its own `cluster` name. Several clusters may list one
namespace (decision 49 ruling 4): the same CronJob deployed to every region is one identity,
`system:serviceaccount:netops:oxidized`, and one policy subject, with no per-cluster namespace or
overlay. Each record's `auth.k8s.cluster` says which region minted, and the start's line
`identity: k8s namespaces: netops: eu_west, us_east` says which clusters vouch for each
namespace: check it after adding a cluster. Where a namespace means different tenants in
different clusters, list different namespaces per verifier. The overlap is allowed because a
compromised cluster already holds a genuine token for its own copy of the workload, so refusing
the overlap would buy nothing.

## 4. The workload

`backup-cronjob.yaml`:

- `automountServiceAccountToken: false`, on the ServiceAccount and the pod. The default API token's
  `aud` is the API server's and port49 refuses it (provisional on L69 (h)); only the projected
  volume is mounted.
- `expirationSeconds: 3600`. The kubelet refreshes a projected token at about 80% of its
  lifetime (provisional on L69 (b)), and the broker refuses a token issued longer ago than
  `broker.identity.max_token_age` (2h by default), so keep it at or under 3600.
- `--token-file` is read at every request, so a rotated token is picked up without a restart.
- The example stops at the mint. `/work/tokens.tsv` is on an `emptyDir`; the consumer (your backup
  tool) runs in the same pod after this container, sharing the work volume. It is not shown.
- The image is the repository's `Dockerfile` target `port49`:
  `docker build --target port49 -t port49:local .`. The broker address and CA in the manifest, and
  the `port49-backup` ConfigMap (`devices`, `broker-ca.pem`), are placeholders for your own.

## 5. The policy

`policy.yaml` maps the principal `system:serviceaccount:netops:oxidized` to the subject
`svc_backup`. `username:` is required: a service account has no login name of its own.
Check a policy offline with `port49 policy test --policy policy.yaml --inventory <file>`.

## 6. 3am

What the operator sees. `<cluster>` is the verifier's `cluster` name with its issuer.

| Case | The workload's stderr | The broker's log and metric |
|---|---|---|
| First start, JWKS unreachable | 503 `identity_provider_unavailable`; retries within `--deadline`, exits 75 | `identity: <cluster>: no keys fetched yet (<error>)…`; `port49_oidc_keys_fetch_failures_total{issuer}` climbs; record `deny trust_domain_unresolved` |
| JWKS unreachable later | mints go on with the keys held for `jwks_max_age` (24h); then as above | `keys not refreshed since <t>…`, hourly; alert on `time() - port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age/2` |
| Key rotated at the cluster | none: one refetch finds the new key (provisional on L69 (d)) | none; rotated wrongly: 401 "no one key of <cluster> matches its key id", exit 77 |
| Clock skew | 401 "issued at <t>, ahead of the broker's clock by more than clock_skew" | fix the broker host's clock |
| Token from an unlisted cluster | 401 "no configured verifier accepts its issuer", exit 77 | metric under `issuer="unknown"` |
| Unlisted namespace | 401 `identity_unmapped` "its namespace <ns> is not one <cluster> lists" | record `auth.method: k8s` |
| Wrong audience, or the default API token | 401 "its aud is not exactly [port49]", exit 77 | fix the volume's `audience` (L69 (g), (h)) |
| Token past `max_token_age` | 401 "issued <d> ago, past broker.identity.max_token_age" | the kubelet stopped rotating, or `expirationSeconds` is too long |
| Discovery names another issuer | each token refused until `issuer` matches | `identity: <cluster>: the cluster's discovery … names issuer <X>`, once |

A deleted service account or pod is not a refusal: see section 7.

## 7. Stopping a workload

```sh
port49 revoke --principal system:serviceaccount:netops:oxidized
```

Deleting the service account alone is not immediate. The broker does not call the cluster's
TokenReview (decision 49 ruling 11): doing so would put every cluster's API server on the mint
path, and needs a broker credential on each cluster. A token already in hand mints until its
`exp` or `iat` plus `max_token_age`, at most 2h (provisional on L69 (e)). `revoke` closes the
window at once; the mark also stands for a service account re-created under that name until
`port49 revoke --lift`.

## 8. What is not measured

- Managed clusters (EKS, GKE, AKS): L70, open.
- A CronJob run in a cluster against a broker outside it is plan 12's deployment test.
- Every cell cited above to L69 is unmeasured until Task 11 closes it.
