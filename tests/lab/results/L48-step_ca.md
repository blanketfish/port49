# L48 — step_ca

- **Date measured:** 2026-11-07
- **Run:** commit `3d171e34f4d8fffab05c59cf05dea28208335843`, `make lab-workload` (`-run TestL48`)
- **Platform:** step_ca
- **Image version:** Smallstep CA/0.30.2 (linux/amd64); image `smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270` (smallstep/step-ca@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270)
- **Capture:** `tests/lab/evidence/L48-step_ca.json`
- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are never written; certificates are public.

## Claim

A workload CA's behaviour with port49's workload verifier (plan 8). On step-ca: whether a certificate requested for a SPIFFE ID carries it as its one URI SAN, with `clientAuth`, not a CA; whether `step ca renew` keeps the ID and the key and changes the serial, and port49 mints for the renewed certificate with no change; when `step ca renew --daemon` renews, as a fraction of the lifetime; with step-ca stopped, whether port49 mints until `NotAfter` and refuses after, and when the late-renewal line comes; whether step-ca's CRL (`crl.enabled`) is DER, issued by the intermediate, and loaded by port49's `certificate_status` over https with the broker trusting step-ca's root (`SSL_CERT_FILE`), and whether a `step ca revoke` reaches port49 within `refresh_interval` and stops a renewal of the revoked certificate; whether a provisioner's x509 name policy allowing one URI refuses a request for another SPIFFE ID.

## Observation

- **1. Issue** (`step ca certificate`, 24h, `--san spiffe://port49.lab/host/oxidized-01`):
  - URI SANs `[spiffe://port49.lab/host/oxidized-01]` (exactly the requested ID, alone: yes); DNS SANs `[]`; EKUs `[serverAuth clientAuth]`; IsCA `false`.
  - Issuer `CN=port49 lab workloads Intermediate CA,O=port49 lab workloads`; lifetime 24h1m0s (`2026-11-07T10:33:02Z` to `2026-11-08T10:34:02Z`); serial `7e16cc9c99bcb3a46958f7953257467e`.
  - The broker, anchored on the intermediate with `certificate_status` disabled: `workload identity` exit 2, prints the principal `` (the requested ID: no); `workload token` exit 2.
- **2. Renew** (`step ca renew --force`, the same broker, no change to port49):
  - Same URI SAN: yes (`[spiffe://port49.lab/host/oxidized-01]`); same public key: yes; serial `7e16cc9c99bcb3a46958f7953257467e` to `775daeae05ab037ebf1425b84edefa7c` (new serial: yes).
  - `workload token` exit 2.
- **3. Daemon timing** (`step ca renew --daemon` on a 15m certificate, polled every 5s):
  - Renewed 9m41s after the daemon started, at 0.67 of the lifetime (detected at 2026-11-07T10:43:44Z of `2026-11-07T10:33:03Z` to `2026-11-07T10:49:03Z`); the new certificate's NotBefore is at 0.60 of the old one's lifetime.
  - Detected 10m41s after NotBefore and 5m19s before NotAfter.
- **4. The CA down** (a 6m certificate: its lifetime is 7m0s, as step-ca backdates NotBefore by 1m; `NotAfter` 5m59s after the first run; step-ca stopped, `workload token` every 30s to 7m, times from the first run):
  - The local broker's `token.candidate_cap` is 64 (port49's default is 8): the 15 runs, none redeemed, stay under it, so a refusal here is the CA's absence or the certificate's expiry, never the cap.
  - `step ca renew` from a one-off container with the CA stopped: `error renewing certificate: client POST https://localhost:19000/renew failed: dial tcp 127.0.0.1:19000: connect: connection refused`.
  - The broker's "its renewal is late" line first appeared: never within 7m. The CLI's warning first appeared: never within 7m.
  - The last run that exited 0 was at never within 7m. The first exit that was not 0: 1s (5m58s before NotAfter, 0.15 of the lifetime), exit 2, stderr `port49 workload token: the certificate /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w.pem and key /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w-key.pem: keyfile: the directory /home/rwendt/git (above /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w-key.pem) is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it, or, if others share it, move the file under directories only root or uid 1000…`.
- **5. The CRL** (`crl: {enabled: true, generateOnRevoke: true}`):
  - DER: yes; issuer `CN=port49 lab workloads Intermediate CA,O=port49 lab workloads` (the intermediate: yes; signature verifies against it: yes); next update `2026-11-08T10:50:48Z`; 0 entries.
  - Its issuing distribution point names `[https://step-ca.port49.lab/1.0/crl]` by fullName (the name the template puts on leaves, `https://step-ca.port49.lab/1.0/crl`: yes).
  - Leaves: one from the provisioner's default template (CRL distribution points `[]`), and one under `examples/oxidized/step-ca-workload.tpl` (CRL distribution points `[https://step-ca.port49.lab/1.0/crl]`, URI SANs `[spiffe://port49.lab/host/oxidized-01]`).
  - The broker, trusting step-ca's root through `SSL_CERT_FILE` (`https://localhost:19000/1.0/crl`), `refresh_interval: 1m`, started with: `port49d: broker: certificate status: every certificate under CN=port49 lab slice CA (broker.identity.humans[].trust_anchor_file) will be refused (503; final at port49 workload): no crls entry is that anchor or a CA it signed, and no ocsp is set; turn the CA's CRL on and name it in crls, or sync it to a file: source | port49d: broker: certificate status from CRL step_ca (not loaded yet); a status that cannot be established is refused (503, retried) | port49d: broker: certificate status: CRL step_ca loaded (next update 2026-11-08T10:50:51Z)`. The CRL loaded: yes.
  - `workload token` with the default leaf (no CRL distribution point): exit 2, stderr `port49 workload token: the certificate /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/default.pem and key /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/default-key.pem: keyfile: the directory /home/rwendt/git (above /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/default-key.pem) is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it, or, if others share it, move the file under directories onl…`.
  - `workload token` with the templated leaf before the revocation: exit 2.
  - After `step ca revoke` (step-ca's CRL lists the serial: yes), `workload token` did not exit 77 with `credential_revoked` within 3m; the last run: exit 2, stderr `port49 workload token: the certificate /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w.pem and key /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w-key.pem: keyfile: the directory /home/rwendt/git (above /home/rwendt/git/port49/.worktrees/fix-47/tests/lab/logs/workload/host-w/w-key.pem) is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it, or, if others share it, move the file under directories only root or uid 1000…`.
  - `step ca renew` of the revoked certificate: refused, `step ca renew: exit status 1: The request lacked necessary authorization to be completed. Please see the certificate authority logs for more info. Re-run with STEPDEBUG=1 for more info.`.
- **6. Holding a provisioner to one SPIFFE ID** (`spiffe://port49.lab/host/oxidized-01`; the other request is `spiffe://elsewhere.lab/host/other`, another trust domain):
  - The provisioner's x509 `allow: {uri: [spiffe://port49.lab/host/oxidized-01]}` in ca.json (step-ca restarted on it):
    - `spiffe://port49.lab/host/oxidized-01`: ISSUED as asked (URI SANs `[spiffe://port49.lab/host/oxidized-01]`).
    - `spiffe://elsewhere.lab/host/other`: ISSUED as asked (URI SANs `[spiffe://elsewhere.lab/host/other]`).
  - The authority's x509 `allow: {uri: [spiffe://port49.lab/host/oxidized-01]}`: step-ca refused to start, `cannot parse permitted URI domain constraint "spiffe://port49.lab/host/oxidized-01": URI domain constraint "spiffe://port49.lab/host/oxidized-01" contains scheme (not supported yet)`.
  - The provisioner's x509 template with `uris: [spiffe://port49.lab/host/oxidized-01]` fixed (step-ca restarted on it):
    - `spiffe://port49.lab/host/oxidized-01`: ISSUED as asked (URI SANs `[spiffe://port49.lab/host/oxidized-01]`).
    - `spiffe://elsewhere.lab/host/other`: issued with the pinned ID instead (URI SANs `[spiffe://port49.lab/host/oxidized-01]`, subject `CN=spiffe://port49.lab/host/oxidized-01`): not refused, rewritten.

