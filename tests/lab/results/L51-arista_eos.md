# L51 — arista_eos

- **Date measured:** 2026-10-09
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab, `show version`: `Software image version: 4.31.2F` (container tag `vrnetlab/arista_veos:4.32.2F`; the image running is 4.31.2F)
- **Client:** `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026` (`ssh -V`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`, `tests/lab/configs/eos-startup.cfg` unchanged (`aaa authentication login default group port49 local`)
- **Capture:** `tests/lab/evidence/L51-arista_eos.pcap` (redacted with `make evidence`); raw `-v` excerpts `tests/lab/l51/out/arista_eos-cases.txt` and `arista_eos-cases-g.txt`
- **Method:** by hand with the scripts in `tests/lab/l51/` (same as `L51-cisco_nxos.md`: `SSH_ASKPASS` answers the prompt so no credential is typed or printed; throwaway ed25519 keys and CA in a mktemp dir, deleted at the end; only fingerprints below).

## Claim

What an OpenSSH client offering several public keys before the password does to a port49 login (spec §15, L51).

## Answer

**Same failure as NX-OS, with a limit of 6.** Each refused public key counts as one failed authentication attempt against what behaves as OpenSSH's default `MaxAuthTries 6`. N=5 refused keys still reach the prompt (it is attempt 6, and a correct token typed there succeeds); **N=6 is the first that never gets the prompt** (`Received disconnect ... Too many authentication failures`). Refused keys cause no TACACS+ exchange; no lockout afterwards (token logins at 0/30/60/120/300 s all succeeded). A certificate costs two attempts. **EOS has no CLI knob for the limit**: `management ssh` offers `authentication empty-passwords|protocol` and `login timeout`, nothing for attempts, so option 4 is not available. The client-side settings avoid it exactly as on NX-OS.

## Observation

### 1. Default limit, N = 1..8 (`-o IdentitiesOnly=yes -i k1 … -i kN`, garbage answer)

`show running-config all | include retries|attempt` returns only an unrelated SNMP trap line; `management ssh` sub-commands, from the CLI: `authentication ?` -> `empty-passwords`, `protocol`; `login ?` -> `timeout`. Running config: `authentication protocol keyboard-interactive public-key`, `login timeout 120`.

| N | keys offered | password prompt reached |
|---|---|---|
| 1 | 1 | yes |
| 2 | 2 | yes |
| 3 | 3 | yes |
| 4 | 4 | yes |
| 5 | 5 | yes (attempt 6; after the failed answer: `Too many authentication failures`) |
| 6 | 6 | **no** — `Received disconnect from 172.100.100.11 port 22:2: Too many authentication failures` |
| 7 | 6 of 7 | no, same |
| 8 | 6 of 8 | no, same |

### 2. TACACS+ exchange for a refused key?

None. The decision log holds a `redeem` record for each typed answer (alice01..alice05, the N=1..5 prompts) and **none for the N=6, 7, 8 sessions**, which sent six keys and no password. The sessions of the lockout test below, all cut at six keys, add no record either.

### 3. Lockout afterwards

Six keys refused, then a login as the same user with its minted token (`-o PubkeyAuthentication=no`), `tests/lab/l51/lockout.sh`:

| wait | result |
|---|---|
| 0 s (alice09) | `Authenticated to 172.100.100.11 ([172.100.100.11]:22) using "keyboard-interactive".` |
| 30 s (alice10) | same |
| 60 s (alice11) | same |
| 120 s (alice12) | same |
| 300 s (alice13) | same |

Device log: `show logging | include sshd|ssh|SSH|authentication` shows only `%AAA-4-AUTHN_FALLBACK` lines for the break-glass logins made while port49d was stopped, and `grep -c "Too many\|maximum" /var/log/messages` (via `bash`) returned code 1, no match. **EOS logs nothing for a session cut at the attempt limit.**

### 4. Options, each alone, agent holding the cert and 5 plain keys (7 identities)

Baseline `T0` (real token, no options): 6 offers (`l51-throwaway-1..5`, `-certkey ED25519`), 0 prompts, `Too many authentication failures`.

| # | option | prompt on first try | attempts counted before the prompt | real-token login | side effect |
|---|---|---|---|---|---|
| 0 | none | **no** | 6 | refused | locks out an agent of 6+ identities |
| 1 | `-o PubkeyAuthentication=no` | **yes** | 0 | `Authenticated ... using "keyboard-interactive"` | no public key or cert auth at all for that connection |
| 2 | `-o IdentityAgent=none` | **yes** | 0 | same | agent keys and agent certs unusable; keys named by `IdentityFile`/`CertificateFile` and default `~/.ssh/id_*` still offered (not neutralised in the `Ce` run; here `-o IdentityFile=none` removed them) |
| 3 | `-o PreferredAuthentications=keyboard-interactive,password` | **yes** | 0 | same | client never tries publickey; a cert-only host cannot be reached with it |
| 4 | device `ssh login-attempts` | n/a: no such setting on EOS | | | |

`-v` method lines: 1 and 3 go straight to `Next authentication method: keyboard-interactive`; 2 shows `Next authentication method: publickey` with no `Offering` line, then keyboard-interactive. EOS advertises `publickey,keyboard-interactive` only (`Permission denied (publickey,keyboard-interactive)`), so there is no separate password method and the first prompt is keyboard-interactive.

### (e) Agent with a user certificate plus plain keys

The cert is two identities, bare key then certificate, and **both count**: with the cert added first, the offers were `kc ED25519`, `kc ED25519-CERT`, `l51-throwaway-1` .. `-4` = 6 attempts, cut with 0 prompts (the cert as one attempt would have left a prompt). Added after k1..k5 it is never reached.

### (f) `IdentitiesOnly yes` + `CertificateFile <cert>` + `IdentityFile <key>.pub`, key in the agent

Offers: `kc-cert.pub ED25519-CERT ... explicit` then `kc.pub ED25519 ... explicit agent`; no other agent key. Real token (`Tf`): offers=2 prompts=1, `Authenticated ... using "keyboard-interactive"`.

### (g) Per-host scoping, `ssh -F` (`tests/lab/l51/conf_g1_eos`, `_g2_eos`, `_g3_eos`)

```
Host 172.100.100.11                       Match host 172.100.100.11         Host 172.100.100.11
    PubkeyAuthentication no                   IdentityAgent none                PreferredAuthentications keyboard-interactive,password
```

Full agent loaded, real token: all three prompted first try and logged in (`Tg1`, `Tg2`, `Tg3`: offers=0, prompts=1).

### (h) Broker snippet (`Include $W/snip/*.conf` holding only `CertificateFile`, user config `IdentitiesOnly yes`)

Identical to NX-OS (client-side): h1 offers the cert alone (`Th1`: offers=1 prompts=1, logged in); h2 (`IdentityFile kc.pub` in the user's file) offers cert then bare key, no other agent key; h3 (key at the cert stem on disk, agent empty, snippet only) offers the cert alone, with `IdentityFile stem/id_l51` added (h3b) cert then key, with only `-i stem/id_l51` (h3c, h3d) the client auto-pairs the `-cert.pub` and offers key then cert. See `arista_eos-cases.txt`.

## Reading

- On vEOS 4.31.2F a client offering 6 or more identities before the password never reaches the token prompt; nothing reaches port49 and the device logs nothing, so the operator sees only "Too many authentication failures" on the client.
- There is no device-side remedy on EOS; scope the client (g1-g3 work).
- No lockout of user or source.

*Unmeasured:* whether the limit of 6 is `MaxAuthTries` read from a hidden sshd_config (inferred from the counts; an sshd_config edit via `bash` was not attempted); other EOS releases (the image is 4.31.2F, not the 4.32.2F of the tag); `ssh_known_hosts`/key-type specific offers beyond ed25519.
