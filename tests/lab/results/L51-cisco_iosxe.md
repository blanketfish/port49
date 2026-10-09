# L51 — cisco_iosxe

- **Date measured:** 2026-10-09
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V autonomous, `show version`: `Cisco IOS XE Software, Version 17.13.01a` (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Client:** `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026` (`ssh -V`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`, `tests/lab/configs/iosxe-startup.cfg` unchanged (`aaa authentication login default group port49 local`)
- **Capture:** `tests/lab/evidence/L51-cisco_iosxe.pcap` (N matrix, lockout 0-120 s, agent cases), `L51-cisco_iosxe-b.pcap` (login sequence, lockout 300 s), `L51-cisco_iosxe-c.pcap` (device `ip ssh authentication-retries 5`); redacted with `make evidence`. Raw `-v` excerpts: `tests/lab/l51/out/cisco_iosxe-cases.txt`; device log: `tests/lab/l51/out/cisco_iosxe-device-log.txt`.
- **Method:** by hand with `tests/lab/l51/` (same scripts and caveats as `L51-cisco_nxos.md`; `REMOTE_CMD='show privilege'`, `ADDR=172.100.100.41`, `L51_NAS=xe1`). Throwaway keys and CA in a mktemp dir, deleted at the end; fingerprints only.

## Claim

What an OpenSSH client offering several public keys before the password does to a port49 login (spec §15, L51).

## Answer

**Same failure, with a limit of `ip ssh authentication-retries` (default 3): the offer that exceeds it is cut.** Each refused public key counts. With the default 3, N=3 still reaches the password prompt and **N=4 is the first that never does** (`Connection closed by 172.100.100.41 port 22`, no disconnect message). Refused keys cause no TACACS+ exchange. No lockout afterwards (token logins at 0/30/60/120/300 s succeeded). A certificate costs two attempts. The device-side setting exists, `ip ssh authentication-retries <0-5>`, and its **maximum of 5 does not cover a 7-identity agent** (cut at the sixth offer). The client-side settings avoid it.

**Separate finding, not caused by keys:** on this image a login with a valid single-use token and no public keys at all failed without any TACACS+ packet being sent in 3 of 8 consecutive attempts (see "Unexplained" below). It limits what the "token login" cells below prove.

## Observation

### 1. Default limit, N = 1..6 (`-o IdentitiesOnly=yes -i k1 … -i kN`, garbage answer)

`show ip ssh`: `Authentication timeout: 120 secs; Authentication retries: 3`; running config `ip ssh authentication-retries 3`; `ip ssh authentication-retries ?` -> `<0-5>  Number of authentication retries`. `show ip ssh` also lists `Authentication methods:publickey,keyboard-interactive,password`.

| N | keys offered | password prompts reached | end of session |
|---|---|---|---|
| 1 | 1 | 2 (keyboard-interactive, then password) | `Permission denied (publickey,keyboard-interactive,password)` |
| 2 | 2 | 2 | `Connection closed by 172.100.100.41 port 22` after the second prompt |
| 3 | 3 | 1 (keyboard-interactive) | `Connection closed ...` after that prompt fails |
| 4 | 4 | **0** | `Connection closed by 172.100.100.41 port 22` after the 4th offer |
| 5 | 4 of 5 | 0 | same |
| 6 | 4 of 6 | 0 | same |

N=3 sent `kbd int inst: port49: authentication failed, mint a new token with 'port49 token'` to the client, so that prompt reached port49. The prompt is the attempt after the third refusal, so a correct token typed there would succeed.

Device log for a cut session (`show logging`): `%SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) ... Succeeded` then `%SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session ... Failed` and `%SSH-5-SSH2_CLOSE: ... for user '' closed`. The user is empty and there is **no line naming the retry limit**; a grep of the whole log for `exceed|too many|quiet|block|retr` matches nothing relevant.

### 2. Does a refused key reach port49?

No. In the matrix window the capture holds TACACS+ connections at 02:09:21 (the N=2 prompt) and 02:09:35 (the N=3 prompt) and nothing during the N=4, 5, 6 sessions, which sent four keys and no password; the decision log has `redeem token_not_found` for exactly those two (alice02, alice03). The N=1 sessions (alice01, twice) show the unexplained no-TACACS behaviour below, so only N=2..6 carry weight. The sessions of the lockout test (cut at four keys) also produced no `redeem` record.

### 3. Lockout afterwards (`tests/lab/l51/lockout.sh`; six keys offered, cut at four)

| wait | token login |
|---|---|
| 0 s (alice07) | `Authenticated to 172.100.100.41 ([172.100.100.41]:22) using "keyboard-interactive".` |
| 30 s (alice08) | same |
| 60 s (alice09) | same |
| 120 s (alice10) | same |
| 300 s (alice12) | same |

No device log line beyond the `SSH2_USERAUTH ... Failed` of the cut sessions; `%SEC_LOGIN-5-LOGIN_SUCCESS` lines for the later logins. No quiet mode or block (`login block-for` is not configured).

### 4. Options, each alone, agent holding the cert and 5 plain keys (7 identities)

| # | option | prompt on first try | attempts counted before the prompt | real-token login | side effect |
|---|---|---|---|---|---|
| 0 | none | **no** | 4 offers (`l51-throwaway-1..4`), cut | refused (`T0`: offers=4, prompts=0) | locks out an agent of 4+ identities |
| 1 | `-o PubkeyAuthentication=no` | **yes** | 0 | `Authenticated ... using "keyboard-interactive"` (`T1`) | no public key or cert auth at all for that connection |
| 2 | `-o IdentityAgent=none` | **yes** | 0 | same (`T2`) | agent keys and certs unusable; `IdentityFile`/`CertificateFile` and default `~/.ssh` keys still offered (`-o IdentityFile=none` removed them in this run) |
| 3 | `-o PreferredAuthentications=keyboard-interactive,password` | **yes** | 0 | same (`T3`) | client never tries publickey |
| 4 | device `ip ssh authentication-retries 5` (restored to 3 afterwards) | **no** with the 7-identity agent: 6 offers, then `Connection closed` (`O4a`) | 6 | refused | **the maximum, 5, still cannot carry a 7-identity agent**; with a 5-identity agent (`k1`..`k5`): offers=5, prompts=1, `Authenticated ... using "keyboard-interactive"` on the first try (`O4b`); later tries of the same cell hit the flake below |

`-v` method lines for 1-3 as on NX-OS: 1 and 3 go straight to `Next authentication method: keyboard-interactive`; 2 shows `Next authentication method: publickey` with no `Offering`, then keyboard-interactive. For 4: `Offering public key: l51-throwaway-1 .. -5, -certkey ED25519` then `Connection closed`.

### (e) Agent with a certificate

A cert in the agent is two identities, the bare key then the certificate, both offered and counted: in the garbage run `Cf` (`-o IdentitiesOnly=yes -o CertificateFile=… -i kc.pub`) the client offered `kc-cert.pub ED25519-CERT` then `kc.pub ED25519` (2 attempts), then both prompts, then the device closed the connection (2 + 2 = 4 failures). Added after `k1..k5` the cert is never reached.

### (f) `IdentitiesOnly yes` + `CertificateFile` + `IdentityFile <key>.pub`

Cert offered first, then the bare key (both `explicit`), other agent keys not offered. Prompt on the first try (garbage run: `prompts reached: 2`). The real-token run `Tf` did not log in on its first attempt (no TACACS packet, see below); a rerun `Tf2` (offers=2, prompts=1) authenticated with `keyboard-interactive`.

### (g) Per-host scoping, `ssh -F` (`tests/lab/l51/conf_g1_xe`, `_g2_xe`, `_g3_xe`)

```
Host 172.100.100.41                       Match host 172.100.100.41         Host 172.100.100.41
    PubkeyAuthentication no                   IdentityAgent none                PreferredAuthentications keyboard-interactive,password
```

Full agent loaded: all three offered **0** keys and reached the prompt on the first try (`Tg1`, `Tg2`, `Tg3`: offers=0, prompts reached). **The token login in those three runs failed without a TACACS+ packet** (the flake); a successful login with the same options and no config file is cell 1, 2, 3 of the table above. So the scoping works at the SSH layer; the end-to-end login on IOS-XE was not re-confirmed for g.

### (h) Broker snippet shape (`Include` of a `CertificateFile`-only snippet, `IdentitiesOnly yes`)

Client behaviour is identical to NX-OS (`cisco_iosxe-cases.txt`): h1 offers the cert alone (`Th1` offers=1, prompt reached; the token login again hit the flake); h2 offers cert then bare key; h3 (key on disk at the stem, snippet only) offers the cert alone; with `IdentityFile stem/id_l51` (h3b) cert then key; with only `-i stem/id_l51` (h3c, h3d) the client auto-pairs the `-cert.pub` and offers key then cert. Each offer counts: h2/h3b/h3c/h3d use two attempts, and the device then cut the session after both prompts failed.

### Unexplained: valid-token logins that never reach port49

Eight consecutive logins as the same user with the real token, no keys, `-o PubkeyAuthentication=no`, 12 s apart (`tests/lab/l51/seq.sh`): five authenticated (`redeem token_redeemed` once, then `receipt_replayed`), three failed with `Permission denied (publickey,keyboard-interactive,password)` after two prompts and **no TACACS+ packet in the capture and no decision-log record**. Device log for the failed ones: `SSH2 Session request ... Succeeded`, about four seconds later `User '' authentication ... Failed`. The same happened to garbage-password logins (alice01 four times, alice11 once) and to the token logins `Tf`, `Tg1`..`Tg3`, `Th1` (five in a row). It did not depend on public keys, and the cut sessions (which end before any TACACS+ request) are unaffected in meaning. It was not diagnosed (no `show tacacs`/debug capture while it happened). Treat any single failed token login on this image as unproven until repeated; tell the lead if this matters for plan 13's operator notes.

## Reading

- IOS-XE 17.13.01a: an agent with more identities than `ip ssh authentication-retries` (default 3, max 5) never reaches the token prompt; nothing reaches port49 and the log names no limit.
- The device-side remedy is bounded at 5, so the client must be scoped (cells 1-3 and g work at the SSH layer).
- No lockout of user or source after the cut.

*Unmeasured:* the cause of the no-TACACS failures; whether `retries 0`, `1`, `2`, `4` follow "cut when the offer count exceeds the setting" (measured at 3 and 5); other IOS-XE releases; `login block-for` / `aaa local authentication attempts max-fail` interplay (neither configured).

## Addendum A: `login block-for` and refused public keys (measured 2026-10-09, same image, 17.13.01a)

- **Capture:** `tests/lab/evidence/L51-cisco_iosxe-flake.pcap` (port 49 only; refused keys produce no TACACS+ traffic). Device lines: `tests/lab/l51/out/cisco_iosxe-quiet-mode-log.txt`, `cisco_iosxe-login-block-config.txt`. Scripts: `tests/lab/l51/ban_xe.sh`, `showlogin.sh`.
- **Command and `?` output** (config prompt): `login ?` lists `block-for`, `delay`, `on-failure`, `on-success`, `password-reuse-interval`, `password-warning-interval`, `quiet-mode`. `login block-for ?` -> `<1-65535> Time period in seconds`; `... 120 ?` -> `attempts  Set max number of fail attempts`; `... attempts 3 ?` -> `within  Watch period for fail attempts`; `... within ?` -> `<1-65535> Time period in seconds`. Set: `login block-for 120 attempts 3 within 60`. `show login` then reports: `A default login delay of 1 seconds is applied. ... If more than 3 login failures occur in 60 seconds or less, logins will be disabled for 120 seconds. Router presently in Normal-Mode.`
- **Each refused public key counts as one login failure.** Port 49 stopped, so only the device counts. `show login` after one connection offering one refused key: `Present login failure count 1`; `show login failures`: `alice09 172.100.100.1 22 Count 4 04:16:36` (cumulative per user). One more connection with two refused keys (alice10): quiet mode on at the third failure (`%SEC_LOGIN-1-QUIET_MODE_ON: ... [user: alice10] [Source: 172.100.100.1] [localport: 22] [Reason: Login Authentication Failed]`, 04:16:53), `QUIET_MODE_OFF` at 04:18:53, exactly 120 s later.
- **The block is on the source address, and covers every user.** Timing, port 49 running, one connection with 3 refused keys (04:21:32, quiet mode on 04:21:35), then a correct token login for a different user each time:

  | after the trigger | result |
  |---|---|
  | +0 s | `kex_exchange_identification: read: Connection reset by peer` |
  | +30 s | Connection reset by peer |
  | +60 s | Connection reset by peer |
  | +120 s | `Authenticated ... using "keyboard-interactive"` (QUIET_MODE_OFF 04:23:35) |
  | +180 s | Authenticated |

  Connections from the source are reset at the TCP/SSH banner, before any user is named, so the device sends nothing to port 49 and a break-glass SSH login from that address is also refused for the 120 s. No other source was tried.
- **Positive control:** two wrong-answer password sessions (each fails both `keyboard-interactive` and `password`, so each counts twice) -> quiet mode on 04:25:15 and the same reset/reset/reset/ok/ok sequence at +0/+30/+60/+120/+180 s.
- **Reading for L51:** on IOS-XE with `login block-for N attempts A`, an agent that offers more refused keys than `ip ssh authentication-retries` allows, or two or three login attempts over the limit, takes the whole source address offline for N seconds, which for a bastion is every user behind it. The earlier "no lockout" finding in this note was measured without `login block-for`. Restored: `no login block-for`; `show running-config | include login block` is empty.

## Addendum B: why valid-token logins sometimes fail with no TACACS+ packet (measured 2026-10-09)

- **Capture:** `tests/lab/evidence/L51-cisco_iosxe-flake.pcap`. Device debug: `tests/lab/l51/out/cisco_iosxe-flake-device-debug.txt`, `cisco_iosxe-flake-timeline-device.txt`. port49d's decision logs and stderr were kept per run in `tests/lab/logs/` (not committed).
- **Reproduced with no keys:** `PubkeyAuthentication=no`, one token login per user, ~6 s apart. Run 1: `OOOOO FFF OOO F` (12 logins, 4 failed). Run D: `F OOO F`. Run E (`single-connection`): `FF OOOO FFFF OOOO FF`. Run F (7 s cadence, 24 logins): `OOOO FFFFFFF OOOO FFFFFFF O F`. Same pattern with `single-connection` removed and `ip tacacs source-interface` removed from the group (G: `OOOFFFFFFFOOOOFFFFFFFOOO`), and with all `aaa accounting` lines removed (H: `OFFFFFFFOOOOFFFFFFFOOFFF`). Healthy stretches are about four logins; failing stretches 40-55 s.
- **port49 is not involved.** For every failing login there is no SYN from 172.100.100.41 to port 49 in the capture (checked for 03:45:26, :40, :54 and 03:46:45; the SYNs at 03:44:25, :37, :50, 03:45:02, :14, 03:46:09, :21, :33 are exactly the eight successes). port49d logged no `redeem` for those users and nothing on stderr: it never saw a connection. The device's `show tacacs` throughout: `Server Status: Alive`, `Socket Timeouts: 0`, `Socket Errors: 0`, `Continous Authc fail count: 0`; no `DEAD`/`ALIVE` log line for the server.
- **What the device does instead.** With `debug aaa authentication`, `debug tacacs events`, `debug ip ssh` in the log buffer:
  - Success: `AAA/AUTHEN/LOGIN: Pick method list 'default'`, then `TPLUS: Source IP selected is: 10.0.0.15`, `TPLUS(...)/0/None: Started 120 sec timeout`, a reply, `%SEC_LOGIN-5-LOGIN_SUCCESS`.
  - Failure: `Pick method list 'default'`, then `TPLUS(...) login timer stopped` with **no** `Source IP selected` and no `TAC+:` line, then within 16 ms `SSH0: password authentication failed for aliceNN`; the same again for the `password` method two seconds later; `SSH2_USERAUTH: User '' ... Failed` about 4 s after the session began. The device skipped the `group port49` method and ended in the method list's `local` (which has no such user), so it answered "failed" without asking anyone. The client sees a second prompt and `Permission denied (publickey,keyboard-interactive,password)`.
  - Per-session lines: `cisco_iosxe-flake-device-debug.txt`.
- **Not caused by** (each tested above): `single-connection`, the group's `ip tacacs source-interface`, accounting, TACACS+ socket state or counters, a refused-key offer (no keys involved), a login block (not configured in these runs). A periodic `%AAA-6-METHOD_LIST_STATE: authen mlist pvt_authen_0 of DOT1X service ... DEAD` line appears while the topology is up; it names a DOT1X list, not `default`, and its stamps do not line up with the failure windows consistently (two of four ok windows start just after one).
- **Verdict:** a device-side fault in this C8000V image's AAA method-list evaluation (the TACACS+ group is skipped for tens of seconds at a time, then used again). Not a port49 bug; port49d was healthy and idle during every failure. Root cause on the device is not identified. For the operator it looks like intermittent "Permission denied" with a valid token and nothing in port49's log; the discriminator is `show logging | include SSH2_USERAUTH` showing `User ''` four seconds after `SSH2_SESSION` with no `SEC_LOGIN-5-LOGIN_SUCCESS`, and no `redeem` in the decision log.
- **Effect on every other measurement here:** any "valid token failed" row in this note's lockout and case tables is as likely this fault as a real refusal; rows were judged by the port49 `redeem` record, not the client result alone. A login block would also count each such failure.
- **Unmeasured:** why the group is skipped; whether other IOS-XE releases do it; whether `deadtime`/`test aaa` settings change the window. Config changed for these runs and restored: `single-connection`, `ip tacacs source-interface`, the `aaa accounting` lines and `logging buffered` (back to the default size); debug flags were turned off by `no debug all`.
