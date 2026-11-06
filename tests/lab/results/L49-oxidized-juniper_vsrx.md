# L49 — juniper_vsrx

- **Date measured:** 2026-11-06
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL49Oxidized$`
- **Platform:** juniper_vsrx
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`), Oxidized 0.37.0-101-g65125713 (image `oxidized/oxidized:latest@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc`, oxidized/oxidized@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc)
- **Capture:** `tests/lab/evidence/L49-oxidized-juniper_vsrx.json`
- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are never written; certificates are public.

## Claim

Oxidized as the day-one consumer of minted tokens (plan 8): the commands each model (`eos`, `nxos`, `ios`, `junos`) sends at login and during a backup, as port49 receives them; whether Oxidized reads a node's username and password from its CSV source at each `/reload` and uses them at the node's next run (`/node/next/<node>`); with a token past its TTL, how many authentications one node's run costs and what Oxidized records; that no token appears in Oxidized's log at its default level; and that a backup made with a minted token holds the device's configuration, the decision log naming the workload's principal.

## Observation

- **Device capture:** `tests/lab/evidence/L49-oxidized-juniper_vsrx.pcap` — 4447 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L49-oxidized-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **A. What Oxidized sends** (role `**`, `port49-oxidized-run` with `PORT49_TTL=15m`):
  - The example's `config` sets `auth_methods` with `keyboard-interactive` (which Oxidized's default list `none`, `publickey`, `password` lacks) for the `eos` model alone, under `models: eos: vars`. This device's sshd listed, for `none`: `publickey,password,keyboard-interactive`.
  - Oxidized's own startup run (with the setup run's token, before this phase's mark) ended, status `success`; authentications at port49d: 1 (permit/token_redeemed x1).
  - The run ended with status `success`; the wrapper exited 0.
  - The device sent no per-command authorization for Oxidized's commands (no authorize_command record). This is consistent with the snippet's `unenforced_rules` on Junos.
  - Commands port49 received from `svc-oxidized`, in order, once each (0): ``.
  - Authentications (redeem records) for the run: 1 (permit/token_redeemed x1).
  - The mint record's principal: `spiffe://port49.lab/host/oxidized-01` (the workload's ID: yes).
  - The backup holds the device's own line `host-name srx1;`: yes; it is 13393 bytes (over 1 KiB: yes).
- **B. A stale token** (the example's role; `receipt_idle_ttl: 2m` in this stack's `port49d.yaml`, so a spent token's receipt lapses in minutes; the default is 15m):
  - Oxidized's own startup run (with the setup run's token, before this phase's mark) ended, status `success`; authentications at port49d: 1 (permit/token_redeemed x1).
  - A 60s token: the run ended with status `success`.
  - 3m later, `PUT /node/next/vsrx1` with no new mint: the run ended; Oxidized's status `no_connection` (a success would be `success`).
  - Authentications that one stale run cost: 1 redeem records for `svc-oxidized` between the mark taken just before the `PUT` and the settle after it (deny/token_spent x1); no other run was started in that span.
  - Oxidized's log for the stale run (class and message lines only):
    - `2026-11-06 06:10:35.474636 W [7:Job 'vsrx1'] Oxidized::Node -- 172.100.100.22 raised Net::SSH::AuthenticationFailed with msg "Authentication failed for user svc-oxidized@172.100.100.22"`
  - Node crashfiles in Oxidized's `crashes` directory: 0 written by the stale run (modified at or after the `PUT`), 0 in all; the process-crash file `crash` exists: no.
  - The wrapper again with a new 60s token (wrapper exit 0): the run ended with status `success`; Oxidized read the new credential at `/reload`: yes.
- **C. The example's role** (`examples/oxidized/policy.yaml`, the same stack):
  - The run ended with status `success`; 0 authorize_command records, 0 denied.
  - The device sent no per-command authorization for Oxidized's commands (no authorize_command record). This is consistent with the snippet's `unenforced_rules` on Junos.
- **D. No token in Oxidized's log** (`docker compose logs oxidized`, through the secrets check against every token minted in A to C and the workload's key):
  - A: Oxidized's log (994 bytes, default level) holds none of the 7 tokens minted so far and no compact JWS.
  - B and C: Oxidized's log (2049 bytes, default level) holds none of the 15 tokens minted so far and no compact JWS.

