# L51 — juniper_vjunos

- **Date measured:** 2026-10-09
- **Platform:** juniper_vjunos (vJunos-router, containerlab node `srx1`, 172.100.100.21)
- **Image version:** `Junos: 23.4R2-S2.1` (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`; `show version`: `Model: vmx`)
- **Client:** `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026` (`ssh -V`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`, `tests/lab/configs/vjunos-startup.conf` unchanged
- **Capture:** `tests/lab/evidence/L51-juniper_vjunos.pcap` (N matrix, lockout, agent cases), `L51-juniper_vjunos-b.pcap` (`tries-before-disconnect 10`), `L51-juniper_vjunos-c.pcap` (`tries-before-disconnect 2`); redacted with `make evidence`. Raw `-v` excerpts: `tests/lab/l51/out/juniper_vjunos-cases.txt`.
- **Method:** by hand with `tests/lab/l51/` (same scripts and caveats as `L51-cisco_nxos.md`; `ADDR=172.100.100.21`, `L51_NAS=srx1`, `REMOTE_CMD='show version'`). Throwaway keys and CA in a mktemp dir, deleted at the end; fingerprints only.

## Claim

What an OpenSSH client offering several public keys before the password does to a port49 login (spec §15, L51).

## Answer

**Same failure, limit 6 by default; the Junos knob is `system login retry-options tries-before-disconnect`, and the key limit is twice its value.** Each refused public key counts as one failed attempt. With nothing configured the session is cut at the sixth attempt: N=5 refused keys still reach the prompt, **N=6 is the first that never does** (`Received disconnect from 172.100.100.21 port 22:2: Too many authentication failures`). Refused keys cause no TACACS+ exchange. No lockout afterwards (token logins at 0/30/60/120/300 s succeeded). A certificate costs two attempts. **Raising the device setting works and is the only platform where it carries a realistic agent**: `tries-before-disconnect 10` (the maximum) let 14 refused keys plus both prompts through, and `tries-before-disconnect 2` cut at 4. The client-side settings avoid it.

## Observation

### 1. Default limit, N = 1..10 (`-o IdentitiesOnly=yes -i k1 … -i kN`, garbage answer)

`show configuration system services ssh` -> `root-login allow;` only. `show configuration system login retry-options` is empty (defaults). `set system services ssh retry-options` is `syntax error` on 23.4R2-S2.1; the login-class one is `set system login retry-options ?` -> `backoff-factor`, `backoff-threshold`, `lockout-period`, `maximum-time`, `minimum-time`, `tries-before-disconnect`.

| N | keys offered | password prompts reached | end |
|---|---|---|---|
| 1 | 1 | 2 (keyboard-interactive, password) | permission denied |
| 2 | 2 | 2 | permission denied |
| 3 | 3 | 2 | permission denied |
| 4 | 4 | 2 | `Too many authentication failures` (4 keys + 2 prompts = 6) |
| 5 | 5 | 1 (keyboard-interactive) | `Too many authentication failures` after that prompt (5 + 1 = 6) |
| 6 | 6 | **0** | `Received disconnect from 172.100.100.21 port 22:2: Too many authentication failures` |
| 7..10 | 6 of N | 0 | same |

### 2. Does a refused key reach port49?

No. The decision log for the matrix window holds `redeem token_not_found` for alice01..alice04 (2 each) and alice05 (1), exactly the typed prompts; there is none for the N=6..10 sessions, which sent six keys and no password; the lockout-test sessions (cut at six keys) add none either.

### 3. Lockout afterwards (`tests/lab/l51/lockout.sh`; six keys, cut)

| wait | token login |
|---|---|
| 0 s (alice11) | `Authenticated to 172.100.100.21 ([172.100.100.21]:22) using "keyboard-interactive".` |
| 30 s (alice12) | same |
| 60 s (alice13) | same |
| 120 s (alice14) | same |
| 300 s (alice15) | same |

Device log: `show log messages | match sshd | count` -> `Count: 0 lines`, and `match alice0` -> `Count: 0 lines`; the file holds only the image's build-time boot lines (dated Aug 21). **vJunos-router wrote nothing about the cut sessions or the logins to `messages`.** (`show log auth` -> `error: could not resolve file: auth`; no other log file was checked.) `lockout-period` under `retry-options` is not set by default.

### 4. Options, each alone, agent holding the cert and 5 plain keys (7 identities)

| # | option | prompt on first try | attempts counted before the prompt | real-token login | side effect |
|---|---|---|---|---|---|
| 0 | none | **no** | 6 (`l51-throwaway-1..5`, `-certkey ED25519`) | refused (`T0`: offers=6, prompts=0, `Too many authentication failures`) | locks out an agent of 6+ identities |
| 1 | `-o PubkeyAuthentication=no` | **yes** | 0 | `Authenticated ... using "keyboard-interactive"` (`T1`) | no public key or cert auth at all for that connection |
| 2 | `-o IdentityAgent=none` | **yes** | 0 | same (`T2`) | agent keys and certs unusable; `IdentityFile`/`CertificateFile` and default `~/.ssh` keys still offered (`-o IdentityFile=none` removed them here) |
| 3 | `-o PreferredAuthentications=keyboard-interactive,password` | **yes** | 0 | same (`T3`) | client never tries publickey |
| 4 | device `system login retry-options tries-before-disconnect 10` (deleted afterwards) | **yes** | 7 offers (`O4`) | `Authenticated ... using "keyboard-interactive"`; offers=7 prompts=1 | none visible. Limit scales: with `10`, N=5,6,8,9,10,11 and 14 refused keys each still reached both prompts (`R10-N*`); with `2`, N=3 was cut after its prompt and N=4 never got one, so the key limit is 2 x the setting (default behaves as 3) |

Messages differ when the password tries run out first: `tries-before-disconnect 2`, N=1 and N=2: `Received disconnect from 172.100.100.21 port 22:2: Too many password failures for alice01`.

`-v` method lines for 1-3 as on NX-OS: 1 and 3 go straight to `Next authentication method: keyboard-interactive`; 2 shows `Next authentication method: publickey` with no `Offering`, then keyboard-interactive. Advertised methods: `publickey,password,keyboard-interactive`.

### (e) Agent with a user certificate

Two identities (bare key, then certificate), both offered and counted (`Cf`/`Tf`: 2 offers then the prompt). With the agent order of this run (cert last) the cert is not reached at the default limit.

### (f) `IdentitiesOnly yes` + `CertificateFile` + `IdentityFile <key>.pub`

Cert first, bare key second, other agent keys unoffered; 2 attempts; real token (`Tf`): offers=2, prompts=1, `Authenticated ... using "keyboard-interactive"`.

### (g) Per-host scoping, `ssh -F` (`tests/lab/l51/conf_g1_jn`, `_g2_jn`, `_g3_jn`)

```
Host 172.100.100.21                       Match host 172.100.100.21         Host 172.100.100.21
    PubkeyAuthentication no                   IdentityAgent none                PreferredAuthentications keyboard-interactive,password
```

Full agent loaded, real token: all three offered 0 keys, prompted on the first try and logged in (`Tg1`, `Tg2`, `Tg3`).

### (h) Broker snippet shape

Identical client behaviour to NX-OS. h1 (snippet `CertificateFile` only, `IdentitiesOnly yes`, key in agent): the cert alone is offered; real token (`Th1`): offers=1, prompts=1, logged in. h2 (`IdentityFile kc.pub` in the user's own file): cert first, bare key second, no other agent key. h3 (key on disk at the stem, agent empty, snippet only): cert alone; with `IdentityFile stem/id_l51` (h3b) cert then key; with only `-i stem/id_l51` (h3c, h3d) key then cert via auto-pairing. See `juniper_vjunos-cases.txt`.

## Reading

- On vJunos-router 23.4R2-S2.1 an agent with 6 or more identities never reaches the token prompt by default; port49 sees nothing and the device logs nothing.
- Of the four platforms measured so far, Junos is the one where the device-side remedy is practical: `set system login retry-options tries-before-disconnect 10` raises the key limit to 20.
- No lockout of user or source after the cut.

*Unmeasured:* what `lockout-period` does together with refused keys (not set; it is documented as applying after `tries-before-disconnect` password failures); the exact key limit at settings 3..9 (measured at default, 2 and 10; "twice the setting" is inferred from 2 -> 4 and default -> 6); `backoff-*` and `minimum-time`; other Junos releases; vSRX is a separate row.
