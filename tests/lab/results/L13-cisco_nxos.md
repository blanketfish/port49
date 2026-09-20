# L13 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L13-cisco_nxos.pcap` — 214 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L13-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Each device's TACACS+ reply timeout, and what the device does when a FAIL reply arrives after it — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server.

## Observation

### The device's own timeout

`show tacacs-server`:

```
timeout value:5
deadtime value:0
source interface:any available
Global Test Username:test
Global Test Password <redacted by the harness>
total number of servers:1

following TACACS+ servers are configured:
        172.100.100.1:
                available on port:49
                TACACS+ shared secret <redacted by the harness>
```

`show tacacs-server groups`:

```
total number of groups:1

following TACACS+ server groups are configured:
        group port49:
                server 172.100.100.1 on port 49
                deadtime is 0
                vrf is management
                Source interface mgmt0
```

`show running-config | include tacacs`:

```
feature tacacs+
tacacs-server host 172.100.100.1 key <redacted by the harness>
aaa group server tacacs+ port49
```

### Late FAIL replies

port49d was restarted before each row with `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` both set to the delay in the first column, so the **first** failure for this account already carried the full delay and no failures had to be driven first. The login is the local account `breakglass` presenting its own local password; port49 holds no token for it, so the reply is FAIL (`token_not_found`), sent that long after the request arrived.

| FAIL delayed by | SSH login | elapsed | redeem records for the account | reasons |
|---|---|---|---|---|
| 2s | refused | 5.01s | 2 | deny/token_not_found, deny/token_not_found |
| 6s | **logged in** | 5.86s | 1 | deny/token_not_found |
| 12s | **logged in** | 5.86s | 1 | deny/token_not_found |

**Measured reply timeout: about 5.9s.** A FAIL delayed by 2s was acted on — the login was refused, 5.01s elapsed. One delayed by 6s was not: that login **succeeded on the local password** after 5.86s. So the timeout lies between 2s and 5.9s.

When the FAIL arrived after that, the device **accepted the local password**, exactly as it does when the server is unreachable (L4). A denial delayed past the timeout is therefore not a denial: it is indistinguishable from an outage, and the device takes the fall-through branch. 

**This device retransmits**: 1 of 3 rows produced more than one redeem record for a single login attempt. So the elapsed column measures the retransmission schedule as much as the reply timeout, and the figure above is read off which logins the device acted on rather than off the clock. **port49's own default `limits.auth_failure_delay_max` is 5s** (internal/config), reached after five consecutive failures for one `(nas, username)` pair. Compare that with the figure above before treating a repeated-failure delay as a way to slow an attacker down: past the device's timeout it stops slowing anything down and starts changing the answer the device acts on.


**How to read the elapsed column.** An elapsed time at or just above the delay means the device waited for the reply. An elapsed time well below it means the device stopped waiting, and what it did next — refuse, or fall through to the local password — is the outcome column. More than one redeem record for a single login attempt means the device gave up and asked again, which is the retransmission half of the same behavior.

What SSH said when the login was refused:

- 2s delay: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`

### Not measured

- The method list in force is whatever `tests/lab/configs` deploys; this row does not sweep the authentication order (that is L4).
- A second TACACS+ server, so "tries the next server" is untested — the lab has one.
- The device's retransmission and `deadtime` timers as configured values, beyond what the quoted output above shows.
- Every transport but SSH, and every platform but Nexus 9300v 10.4(2)F.
- Delays above 12s, and whether the connection is torn down by the device or by port49d.

