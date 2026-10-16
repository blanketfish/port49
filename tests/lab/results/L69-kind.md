# L69 — kind

- **Date measured:** 2026-10-16
- **Run:** commit `d7b55571045bd6d17a19f4d1eea800eb1dee5500`, `make lab-k8s` (`-run TestL69`) (the measured commit, what ran; rebased as `e5ff120d` with no change to plan 10's code: `git diff d7b55571 e5ff120d` touches only main's files)
- **Platform:** kind
- **Image version:** kind v0.29.0, node image `kindest/node:v1.33.1` (kindest/node@sha256:050072256b9a903bd914c0b2866828150cb229cea0efe5892e2b644d5dd3b34f), Kubernetes v1.33.1
- **Capture:** `tests/lab/evidence/L69-kind.json`
- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are never written; certificates are public.

## Claim

A Kubernetes cluster's service account tokens as port49's `k8s` verifier meets them (plan 10), on kind: (a) a projected token's claims for `audience: port49-lab`, `expirationSeconds: 600` (`iss`, `aud`, `exp` − `iat`, `nbf`, `sub`, `kubernetes.io` with `namespace`, `serviceaccount`, `pod`, `node`, `jti`; the header's `alg`, `kid` and `typ`); (b) when the kubelet rewrites the file, as a fraction of `expirationSeconds`; (c) the issuer discovery document and `/openid/v1/jwks` read anonymously before and after binding `system:service-account-issuer-discovery` to `system:unauthenticated`, and discovery's `issuer` and `jwks_uri` against the API server's flags; (d) a signing key rotated at the API server, and whether port49 mints with the new key's token without a restart; (e) a token after its pod, then its service account, is deleted: what TokenReview answers and what port49 does; (f) a second cluster's token at a broker that lists only the first, for a namespace only the first lists, and for a namespace both list; (g) a token for another audience, an unbound `kubectl create token`, a Secret-bound and a Node-bound `kubectl create token`, and a legacy Secret token; (h) the default `kube-api-access` token's `aud` and lifetime.

## Observation

### (a) claims

**PASS.** iss https://l69-a.port49.lab, aud [port49-lab], exp-iat 600s, sub system:serviceaccount:netops:oxidized, header alg RS256 kid true, typ ""; kubernetes.io {namespace, node, pod, serviceaccount}; recorded nbf 1792169911, jti true, node true, warnafter absent

### (c) discovery

**PASS.** anonymous discovery/jwks before the binding [403 403], after [200 200]; discovery issuer "https://l69-a.port49.lab", jwks_uri "https://172.18.0.2:6443/openid/v1/jwks"; A's broker silent true (mint exit 0); B's discovery jwks_uri "https://l69-b.invalid/openid/v1/jwks", B's broker mint exit 0, quiet true

### port49 mints

**PASS.** A's pod token minted exit 0

### (b) rotation

**PASS.** the file changed at 0.87 of expirationSeconds (measured from the old token's iat; inside [0.75, 0.97], so the docs' "about 80%" stands); the new token minted exit 0

### (d) key rotation

**PASS.** JWKS keys 1 then 2; kid "nDwCK_22ZnLlGBnBcFGiCuaoi_JuyFlag3i-NOg5bAg" then "J3J2tY5XjKwQPfQUcTcHIjch7Aob1vUDb9KmeBO-B6Y" (differs true); the new key's token minted on the running broker after 0s (first attempt exit 0, 1 attempts), last exit 0

### (e) deletion

**PASS.** after the pod was deleted TokenReview answered authenticated=false ("[invalid bearer token, service account token has been invalidated]") and port49 minted exit 0; after the service account was deleted authenticated=false ("[invalid bearer token, serviceaccounts \"oxidized\" not found]"), port49 exit 0; after port49 revoke system:serviceaccount:netops:oxidized (ran true) the same token exited 77: port49 workload token: 401 credential_revoked: this principal was revoked at 2026-10-16T17:09:25Z; nothing is minted for it until an operator lifts the revocation (port49 revoke --lift): 1 of 1 devices were not minted

### (f) another cluster

**PASS.** B's token at a broker listing A alone: exit 77; at A (netops) and B (backup): exit 77; at A and B both listing netops: the start says the overlap true, A's token exit 0, B's exit 0, mint records name clusters [l69_a l69_b]

### (g) shapes refused

**PASS.** each of the five shapes was refused with trust_domain_unresolved and its own reason: wrong_audience exit 77 (true), unbound exit 77 (true), secret_bound exit 77 (true), node_bound exit 77 (true), legacy_secret exit 77 (true)

### (h) the default token

**PASS.** the default token's aud is [https://l69-a.port49.lab], exp-iat 31536000s, warnafter 1792173518; port49 exit 77: port49 workload token: 401 trust_domain_unresolved: its aud is not exactly [port49-lab]: a token another audience accepts could be replayed here (decision 49 ruling 5): 1 of 1 devices were not minted


