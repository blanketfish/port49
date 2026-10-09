# L51 — juniper_vsrx

- **Date measured:** 2026-10-09
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`; the version is the image tag and `tests/lab/results/juniper_vsrx-config-verified.md`; `show version` was not run in this session)
- **Client:** `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026` (`ssh -V`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`, `tests/lab/configs/vjunos-startup.conf` unchanged
- **Capture:** `tests/lab/evidence/L51-juniper_vsrx.pcap` (all cells), redacted with `make evidence`. Raw `-v` excerpts: `tests/lab/l51/out/juniper_vsrx-cases.txt`.
- **Method:** by hand with `tests/lab/l51/` (same scripts and caveats as `L51-cisco_nxos.md`; `ADDR=172.100.100.22`, `L51_NAS=vsrx1`). **This image has no usable local account** (`juniper_vsrx-config-verified.md`), so the device-side setting was changed on the serial console (`tests/lab/l51/console.py`, telnet to 172.100.100.22:5000, `root`, no password) and deleted again afterwards. Throwaway keys and CA in a mktemp dir, deleted at the end; fingerprints only.

## Claim

What an OpenSSH client offering several public keys before the password does to a port49 login (spec §15, L51).

## Answer

**Identical to vJunos-router (`L51-juniper_vjunos.md`)**: limit 6 by default; N=5 refused keys reach the prompt, **N=6 is the first that never does** (`Received disconnect from 172.100.100.22 port 22:2: Too many authentication failures`); no TACACS+ exchange from a refused key; no lockout afterwards (token logins at 0/30/60/120/300 s succeeded); a certificate costs two attempts; `system login retry-options tries-before-disconnect` is the device-side lever and the key limit is twice its value; the client-side settings avoid it.

## Observation

### 1. Default limit, N = 1..10 (`-o IdentitiesOnly=yes -i k1 … -i kN`, garbage answer)

`show configuration system services ssh` -> `root-login allow;`; `show configuration system login retry-options` empty (defaults).

| N | keys offered | password prompts reached | end |
|---|---|---|---|
| 1, 2, 3 | N | 2 | permission denied |
| 4 | 4 | 2 | `Too many authentication failures` (4 + 2 = 6) |
| 5 | 5 | 1 | `Too many authentication failures` after that prompt (5 + 1 = 6) |
| 6..10 | 6 of N | **0** | `Received disconnect from 172.100.100.22 port 22:2: Too many authentication failures` |

### 2. Does a refused key reach port49?

No. Decision log, matrix window: `redeem token_not_found` for alice01..alice04 (typed prompts) and alice05 (one prompt); none for N=6..10 (six keys, no password); none for the lockout-test sessions that were cut at six keys.

### 3. Lockout afterwards

Six keys refused (cut), then a token login as the same user:

| wait | result |
|---|---|
| 0 s (alice11) | `Authenticated to 172.100.100.22 ([172.100.100.22]:22) using "keyboard-interactive".` |
| 30 s (alice12) | same |
| 60 s (alice13) | same |
| 120 s (alice14) | same |
| 300 s (alice15) | same |

Device log: from the console, `show log messages | match sshd | count` -> `Count: 0 lines`; `show log messages | match alice | count` -> `Count: 0 lines`. Nothing was logged for the cut sessions or the logins.

### 4. Options, each alone, agent holding the cert and 5 plain keys (7 identities)

| # | option | prompt on first try | attempts counted before the prompt | real-token login | side effect |
|---|---|---|---|---|---|
| 0 | none | **no** | 6 | refused (`T0`: offers=6, prompts=0, `Too many authentication failures`) | locks out an agent of 6+ identities |
| 1 | `-o PubkeyAuthentication=no` | **yes** | 0 | `Authenticated ... using "keyboard-interactive"` (`T1`) | no public key or cert auth for that connection |
| 2 | `-o IdentityAgent=none` | **yes** | 0 | same (`T2`) | agent keys and certs unusable; `IdentityFile`/`CertificateFile` and default `~/.ssh` keys still offered (`-o IdentityFile=none` removed them here) |
| 3 | `-o PreferredAuthentications=keyboard-interactive,password` | **yes** | 0 | same (`T3`) | client never tries publickey |
| 4 | device `system login retry-options tries-before-disconnect 10` (console; deleted afterwards) | **yes** | 7 | offers=7 prompts=1, `Authenticated ... using "keyboard-interactive"` (`O4`) | none visible; N=6 and N=14 refused keys with `10` still reached both prompts; with `2`: N=3 cut after its prompt, N=4 never got one (key limit = 2 x setting) |

With `tries-before-disconnect 2`, N=1 and N=2 end `Too many password failures for alice01` / `alice02`.

### (e), (f), (g), (h)

- (e) A cert in the agent is two identities, bare key then certificate, both offered and counted.
- (f) `IdentitiesOnly yes` + `CertificateFile` + `IdentityFile kc.pub`: cert first, bare key second, other agent keys not offered; real token (`Tf`): offers=2, prompts=1, logged in.
- (g) `conf_g1_sr`, `conf_g2_sr`, `conf_g3_sr` (`Host 172.100.100.22 / PubkeyAuthentication no`; `Match host 172.100.100.22 / IdentityAgent none`; `Host 172.100.100.22 / PreferredAuthentications keyboard-interactive,password`): full agent loaded, real token, all three offered 0 keys, prompted first try and logged in (`Tg1`, `Tg2`, `Tg3`).
- (h) Same client behaviour as NX-OS: h1 (snippet `CertificateFile` only): cert alone offered, real token logged in (`Th1`: offers=1, prompts=1); h2 cert then bare key; h3 cert alone; h3b cert then key; h3c/h3d key then cert (auto-paired). See `juniper_vsrx-cases.txt`.

## Reading

Same as vJunos-router: an agent with 6 or more identities never reaches the token prompt; port49 and the device log see nothing; raising `tries-before-disconnect` (maximum 10, key limit 20) fixes it device-side; no lockout.

*Unmeasured:* `show version` on this image in this session; `lockout-period`, `backoff-*`, `minimum-time`; settings 3..9; other releases.
