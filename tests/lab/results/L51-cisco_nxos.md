# L51 — cisco_nxos

- **Date measured:** 2026-10-09
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`; `show version`: `NXOS: version 10.4(2) [Feature Release]`)
- **Client:** `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026` (`ssh -V`). Client behaviour here has changed across OpenSSH releases; the client rows are for this version only.
- **Topology:** `tests/lab/topologies/nxos.clab.yml`; `tests/lab/configs/nxos-startup.cfg` unchanged (`aaa authentication login default group port49 local`).
- **Capture:** `tests/lab/evidence/L51-cisco_nxos.pcap` (N=1..6 matrix), `L51-cisco_nxos-b.pcap` (lockout timings, client-option cases), `L51-cisco_nxos-c.pcap` (device `ssh login-attempts 10`), `L51-cisco_nxos-d.pcap` (real-token confirmations); redacted with `make evidence`. Raw `-v` excerpts: `tests/lab/l51/out/cisco_nxos-cases.txt` (agent cases, default `~/.ssh` identities neutralised) and `cisco_nxos-cases-with-default-identity.txt`; device log lines: `tests/lab/l51/out/cisco_nxos-device-log.txt`.
- **Method:** by hand with the scripts in `tests/lab/l51/` (`askpass.sh` feeds the prompt through `SSH_ASKPASS`, so no credential is typed, printed or logged; `probe.sh` types a garbage string, `tok.sh` the minted token). Throwaway ed25519 keys and a throwaway CA in a mktemp dir, deleted at the end; only fingerprints appear below. Credentials appear only as `credential_sha256` in the decision log.

## Claim

What an OpenSSH client offering several public keys before the password does to a port49 login on this platform (spec §15, L51).

## Answer

**It locks the password prompt out, and the limit is small.**

- The default is `ssh login-attempts 3` (range 1-10). **Every refused public key counts as one failed attempt**, and so does every refused keyboard-interactive or password try. A client that offers N keys reaches the password prompt only if N + 1 is within the limit, because the prompt is the next attempt: with the default, N=2 gets the prompt (and a correct token typed there is attempt 3 and succeeds); **N=3 is the first N that never gets a password prompt** (`Received disconnect from 172.100.100.31 port 22:2: Too many authentication failures`).
- A refused key causes **no TACACS+ exchange** and no accounting record.
- The refusals **do not lock the user or the source**: a correct token login immediately and after 30, 60, 120 and 300 s all succeeded. The session is cut; the next connection starts from zero.
- Settings that avoid it, each measured on its own with the full agent loaded: `PubkeyAuthentication no`, `IdentityAgent none`, `PreferredAuthentications keyboard-interactive,password` (client), and `ssh login-attempts` raised (device; max 10, so an agent with 10 or more identities is still cut off). `IdentitiesOnly yes` with no `-i` does **not** avoid it on a machine with default `~/.ssh` keys, because it still offers those.
- **A certificate costs two attempts**: OpenSSH offers the bare key, then the certificate, and the device counts both.

## Observation

### 1. Default limit and N = 1..6 (`-o IdentitiesOnly=yes -i k1 … -i kN`, garbage password, `NumberOfPasswordPrompts=1`)

Device before: `show running-config all | include login-attempts` -> `ssh login-attempts 3`, `telnet login-attempts 3`. `ssh login-attempts ?` -> `<1-10>  Specify max-attempt number`.

Command (`tests/lab/l51/nmatrix.sh`): `ssh -F /dev/null -v -o IdentitiesOnly=yes -i k1 … -i kN -o NumberOfPasswordPrompts=1 alice0N@172.100.100.31 'show hostname'`, `SSH_ASKPASS` answering the prompt.

| N | keys offered | password prompt reached | client reply |
|---|---|---|---|
| 1 | 1 | yes (keyboard-interactive, then password) | after the second failed prompt: `Received disconnect ... Too many authentication failures` (1 key + 2 prompts = 3) |
| 2 | 2 | yes (keyboard-interactive only) | disconnect after that prompt fails (2 + 1 = 3) |
| 3 | 3 | **no** | `Received disconnect from 172.100.100.31 port 22:2: Too many authentication failures` |
| 4 | 3 of 4 | no | same; the 4th key is never offered |
| 5 | 3 of 5 | no | same |
| 6 | 3 of 6 | no | same |

Exact auth lines for N=3 (fingerprints only):

```
Offering public key: $W/k1 ED25519 SHA256:ZjJeZAA3tvlmpOJr7nRUQuk74PnJd/uhx2IqLuCWCe4 explicit
Offering public key: $W/k2 ED25519 SHA256:leLzsX1CXCZheLhKpRMD3UBtXfi8bsWRYRqhnIBPDJ0 explicit
Offering public key: $W/k3 ED25519 SHA256:Z8cGPHtNoMscjm+EFTHhgHgJIy7ld6xOUZ9VPrFt0MA explicit
Received disconnect from 172.100.100.31 port 22:2: Too many authentication failures
```

Device log, one line per cut session, e.g. `%DAEMON-3-SYSTEM_MSG: error: maximum authentication attempts exceeded for invalid user alice03 from 172.100.100.1 port 59004 ssh2 [preauth] - dcos_sshd[1291]` (full list in the device-log file; "invalid user" because the TACACS+-only name has no local account).

### 2. Does a refused key reach port49?

No. In the decision log for the matrix window, `redeem` records exist only for `alice01` (the prompt that was reached, N=1) and `alice02` (N=2): one `token_not_found` per typed garbage string, `credential_sha256` `844be5f8…0ee4`. **There is none for alice03, alice04, alice05 or alice06**, whose sessions were cut after three refused keys; and none for `alice04` in the real-token run `T0` below (agent offered 3 keys, 0 prompts). The capture holds `authen_start` packets only for the typed strings. A failed password does make NX-OS send an unattributed accounting stop (`cmd=PAM: Authentication …`, redacted by the daemon); a refused key does not.

### 3. Lockout afterwards (`tests/lab/l51/lockout.sh`)

Six keys refused as `aliceNN` (session cut, no prompt), then a login as the same user with that user's minted token, `-o PubkeyAuthentication=no`:

| wait after the refusals | token login |
|---|---|
| 0 s | `Authenticated to 172.100.100.31 ([172.100.100.31]:22) using "keyboard-interactive".` |
| 30 s | same |
| 60 s | same |
| 120 s | same |
| 300 s | same |

Device log: the only lines are the `maximum authentication attempts exceeded ... [preauth]` ones; `show logging logfile | include "lock|locked|Too many|refused"` returns nothing else (one unrelated `EXT4-fs ... unable to read superblock` kernel line matches `lock` as a substring of `superblock`).

### 4. Options, each on its own, agent holding the cert and 5 plain keys

Agent (dedicated `ssh-agent`), 7 identities: `k1`..`k5`, `kc` (ED25519) and `kc` with certificate (ED25519-CERT, `SHA256:m6BdMMc8+y6BzpG6dFmy3vucJ0rS9jCXPhPjG7Fp3e8`). Baseline, no options, real token, default limit 3 (`T0`): offers 3 (`l51-throwaway-1..3`), 0 prompts, `Too many authentication failures`; port49 saw nothing.

Real-token results (`tok.sh`, `ssh -F /dev/null -o IdentityFile=none` so only the agent supplies keys):

| # | option | prompt on first try | offers = attempts counted before the prompt | login with the real token | side effect |
|---|---|---|---|---|---|
| 0 | none (baseline) | **no** | 3 | refused, session cut | locks out any user whose agent holds 3+ identities |
| 1 | `-o PubkeyAuthentication=no` | **yes** | 0 | `Authenticated ... using "keyboard-interactive"` | turns public-key and certificate auth off for that connection, on any host it applies to |
| 2 | `-o IdentityAgent=none` | **yes** | 0 | same | agent-held keys and certs unusable; keys named by `IdentityFile` or `CertificateFile` on disk are still offered (and default `~/.ssh/id_*`, see below) |
| 3 | `-o PreferredAuthentications=keyboard-interactive,password` | **yes** | 0 | same | the client never tries publickey, so a host that accepts only a certificate cannot be reached with it |
| 4 | device `ssh login-attempts 10` (restored to 3 afterwards) | **yes** with the 7-identity agent | 7 (5 plain keys, the cert key bare, and its certificate) | prompt was attempt 8; `Authenticated ... using "keyboard-interactive"` | none visible; 12 identities (+`k6`, rsa, ecdsa, 2 more) are still cut at 10 offers: `Offering` x10 then `Too many authentication failures`, 0 prompts |

`ssh -v` method lines for 1-3: `Next authentication method: keyboard-interactive` is the first and only method tried before the prompt (1, 3); for 2 it is `Next authentication method: publickey` with no `Offering` line, then `keyboard-interactive`. For 4: seven `Offering public key: ... agent` lines (`l51-throwaway-1` .. `-5`, `-certkey ED25519`, `-certkey ED25519-CERT`), then `Next authentication method: keyboard-interactive`.

**`IdentitiesOnly yes` with no `-i`** (`Ce`): not an avoidance on a normal machine. With the user's default `~/.ssh/id_ed25519` present, it offered that key (1 attempt) and the prompt then failed within the limit (with a garbage answer and two methods the session was cut after 3 attempts). With default identities neutralised (`-o IdentityFile=none`) it offered nothing and reached the prompt. See `cisco_nxos-cases-with-default-identity.txt`; the same default key was offered under `IdentityAgent none` in that run.

### (e) Agent with one OpenSSH user certificate plus plain keys

- A certificate in the agent is **two identities**: ssh-add lists `kc (ED25519)` and `kc (ED25519-CERT)`, and the client offers both, bare key first. Both are counted by the device. With the cert added first the offers were `kc ED25519`, `kc ED25519-CERT`, `l51-throwaway-1`, then the cut: three attempts, the cert itself was the second.
- Added after k1..k5 (our baseline agent) the cert is never reached: the client is cut after k1..k3. Whether the broker's cert is reached depends on the agent order, which the client does not control.

### (f) `IdentitiesOnly yes`, `CertificateFile <cert>`, `IdentityFile <key>.pub`, private key only in the agent

`ssh -o IdentitiesOnly=yes -o CertificateFile=$W/kc-cert.pub -i $W/kc.pub` with the full agent:

```
Will attempt key: kc-cert.pub ED25519-CERT SHA256:m6BdMMc8+y6BzpG6dFmy3vucJ0rS9jCXPhPjG7Fp3e8 explicit
Will attempt key: kc.pub ED25519 SHA256:m6BdMMc8+y6BzpG6dFmy3vucJ0rS9jCXPhPjG7Fp3e8 explicit agent
Offering public key: kc-cert.pub ED25519-CERT SHA256:m6BdMMc8+y6BzpG6dFmy3vucJ0rS9jCXPhPjG7Fp3e8 explicit
Offering public key: kc.pub ED25519 SHA256:m6BdMMc8+y6BzpG6dFmy3vucJ0rS9jCXPhPjG7Fp3e8 explicit agent
Next authentication method: keyboard-interactive
```

The cert **is** offered, first, and the **bare key is offered too** (two attempts); the other agent keys are not. The prompt came on the first try with the real token (`Tf`: offers=2 prompts=1, `Authenticated ... using "keyboard-interactive"`) and it was attempt 3 of 3. One attempt of headroom, none to spare.

### (g) Per-host scoping, `ssh -F <config>` (configs in `tests/lab/l51/conf_g*`)

```
# conf_g1                           # conf_g2                         # conf_g3
Host nx1 172.100.100.31             Match host 172.100.100.31         Host 172.100.100.31
    PubkeyAuthentication no             IdentityAgent none                PreferredAuthentications keyboard-interactive,password
```

Full agent loaded, real token each: all three reached the prompt on the first try and logged in (`Tg1`, `Tg2`, `Tg3`: offers=0, prompts=1, `Authenticated ... using "keyboard-interactive"`). `-v`: g1 and g3 go straight to `Next authentication method: keyboard-interactive`; g2 shows `Next authentication method: publickey` with no offer, then keyboard-interactive.

### (h1)-(h3) the broker snippet shape (`Include $W/snip/*.conf` holding only `CertificateFile $W/kc-cert.pub`; user config `IdentitiesOnly yes`)

- **h1**, key in the agent only, no IdentityFile: the cert **is offered** (`Will attempt key: kc-cert.pub ED25519-CERT ... explicit`, `Offering public key: kc-cert.pub ED25519-CERT ... explicit`), as a single offer; no bare key, no other agent key. Token login `Th1`: offers=1, prompts=1, logged in. (On this OpenSSH, `CertificateFile` alone is an identity; the agent signs it.)
- **h2**, the same plus `IdentityFile $W/kc.pub` in the user's own config: cert offered **first**, bare key second (`explicit agent`), no other agent key; 2 attempts, the prompt reached on the first try (garbage run: `prompts reached: 1`, then the third failure). Accumulation across blocks works as the brief states.
- **h3**, key on disk at the cert's stem (`stem/id_l51` beside `stem/id_l51-cert.pub`), agent empty, snippet `CertificateFile` only: the cert alone is offered (1 attempt, prompt reached on the next); the on-disk key is **not** offered because nothing names it. With `IdentityFile stem/id_l51` added (h3b), cert then bare key (2 attempts). With only `-i stem/id_l51` and no `CertificateFile` (h3c), the client **auto-pairs** the `-cert.pub` and offers key then cert, also 2 attempts (and likewise with the agent loaded, h3d). So a private key on disk costs the same two attempts as one in the agent.

## Reading

- On NX-OS 10.4(2)F, any client that can offer 3 or more identities before the password is cut off by default, before port49 sees anything; a minted token cannot be typed. The failure is silent to port49: its log shows no record, so the operator sees "Too many authentication failures" on the client and a `maximum authentication attempts exceeded ... [preauth]` line on the device only.
- Nothing is locked out afterwards; the same user may retry at once.
- Advice that is now measured here: scope `PubkeyAuthentication no` or `IdentityAgent none` or `PreferredAuthentications keyboard-interactive,password` to the device with a `Host`/`Match host` block (g1-g3 all work); raising `ssh login-attempts` helps only up to a maximum of 10 and needs the offers + 1 within it. A certificate-based broker needs the cert offered, which costs two attempts; keep the agent's other identities out (`IdentitiesOnly yes` plus `CertificateFile`, h1) and the default `~/.ssh` keys out as well (`IdentityFile none`, or a dedicated host block).

*Unmeasured:* RSA/ECDSA key-type offers on NX-OS beyond the two throwaways in the 12-identity run (they were offered and counted the same); `ssh login-attempts` between 4 and 9 (the rule offers + 1 <= limit follows from 3 and 10 and was not swept); a user that exists locally on the device (the lab users are TACACS-only, "invalid user"); whether the break-glass local account is counted differently; other NX-OS releases and OpenSSH releases.

## Addendum: the login ban (`aaa authentication rejected`), measured 2026-10-09 on a second deploy of the same image

- **Capture:** `tests/lab/evidence/L51-cisco_nxos-ban.pcap`; scripts `tests/lab/l51/ban_nxos.sh`, `ban2_nxos.sh`, `ban3_nxos.sh`.
- **The command exists.** Exact `?` output at the config prompt:

```
nx1(config)# aaa authentication ?
  login     Configure methods for login
  rejected  Set max number of fail attempts

nx1(config)# aaa authentication rejected ?
  <1-65535>  Fail attempts max value

nx1(config)# aaa authentication rejected 3 ?
  in  Watch period for fail attempts
```

  Set: `aaa authentication rejected 3 in 60 ban 120`; `show running-config all | include "aaa authentication rejected"` -> `aaa authentication rejected 3 in 60 ban 120`. `login ?` offers only `on-failure` and `on-success` (no `block-for`). Removing it: `no aaa authentication rejected` printed `All Blocked / Watched user statistics will be cleared.` and `Note: Per User Login block feature is completely disabled.` Restored; the line is gone from the running config.
- **Refused public keys do not count.** One connection with 3 refused keys (cut with `Too many authentication failures`), then a correct token login as the same user at +0 s, and as another user: both `Authenticated ... using "keyboard-interactive"`. Then 3 such connections (9 refused keys) within 60 s, as one user: the token login straight after, as that user and as another, succeeded. Two keys with no password offered, then a login: succeeded (control).
- **Failed password sessions do count, and the ban is per user, not per source.** Three sessions with a wrong answer as `alice11` (each `Permission denied`, three `redeem token_not_found` in the decision log), then at +0 s: `alice11` with its correct token `Permission denied` after two prompts, `alice12` from the same source address `Authenticated`. The device sends **no TACACS+ request** for a banned user (no `redeem` record for the refused attempts).
- **Timing** (user `alice15`, three failed sessions at 03:34:35-03:34:37, correct token tried every 30 s): refused at +0, +30, +60, +90, +120 s (`Permission denied`, `prompts=2`, no TACACS+ packet); `Authenticated ... using "keyboard-interactive"` at +150 s and +180 s. The 120 s ban lapsed between +120 and +150 s after the third failure.
- **Device log:** `show logging logfile | include "ban|reject|lock|too many"` shows nothing for the ban (only an unrelated `EXT4-fs ... superblock` kernel line). The operator sees only a refused login.
- **Reading for L51:** a refused public key is not an AAA rejection on NX-OS, so a login ban of this kind is not triggered by an agent's key offers; a typed wrong token is, and bans that username for the ban period while port49 is never asked. A user who mistypes a token three times in the window cannot log in even with a fresh token until the ban lapses.
