# L13 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L13-arista_eos.pcap` — 276 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L13-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Each device's TACACS+ reply timeout, and what the device does when a FAIL reply arrives after it — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server.

## Observation

### The device's own timeout

`show tacacs`:

```
TACACS+ server            : 172.100.100.1/49
          Connection opens:         40
         Connection closes:          8
    Connection disconnects:          0
       Connection failures:         32
       Connection timeouts:          0
             Messages sent:         10
         Messages received:         10
            Receive errors:          0
          Receive timeouts:          0
             Send timeouts:          0
                DNS errors:          0
 Unknown attribute ignored:          0
Unknown attribute failures:          0

TACACS+ server-group: port49
     0: 172.100.100.1/49 

Last time counters were cleared: never
```

`show running-config | include tacacs`:

```
tacacs-server host 172.100.100.1 key <redacted by the harness>
aaa group server tacacs+ port49
```

### Late FAIL replies

port49d was restarted before each row with `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` both set to the delay in the first column, so the **first** failure for this account already carried the full delay and no failures had to be driven first. The login is the local account `breakglass` presenting its own local password; port49 holds no token for it, so the reply is FAIL (`token_not_found`), sent that long after the request arrived.

| FAIL delayed by | SSH login | elapsed | redeem records for the account | reasons |
|---|---|---|---|---|
| 2s | refused | 2.03s | 1 | deny/token_not_found |
| 6s | **logged in** | 5.04s | 1 | deny/token_not_found |
| 12s | **logged in** | 5.04s | 1 | deny/token_not_found |

**Measured reply timeout: about 5s.** A FAIL delayed by 2s was acted on — the login was refused, 2.03s elapsed. One delayed by 6s was not: that login **succeeded on the local password** after 5.04s. So the timeout lies between 2s and 5s.

When the FAIL arrived after that, the device **accepted the local password**, exactly as it does when the server is unreachable (L4). A denial delayed past the timeout is therefore not a denial: it is indistinguishable from an outage, and the device takes the fall-through branch. **port49's own default `limits.auth_failure_delay_max` is 2s** (internal/config), reached after three consecutive failures for one `(nas, username)` pair. It was 5s until this row was measured, and was lowered on 2026-09-21 to sit under every reply timeout measured here. Compare it with the figure above before raising it: past the device's timeout a delay stops slowing an attacker down and starts changing the answer the device acts on.


**How to read the elapsed column.** An elapsed time at or just above the delay means the device waited for the reply. An elapsed time well below it means the device stopped waiting, and what it did next — refuse, or fall through to the local password — is the outcome column. More than one redeem record for a single login attempt means the device gave up and asked again, which is the retransmission half of the same behavior.

What SSH said when the login was refused:

- 2s delay: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain`

### Not measured

- The method list in force is whatever `tests/lab/configs` deploys; this row does not sweep the authentication order (that is L4).
- A second TACACS+ server, so "tries the next server" is untested — the lab has one.
- The device's retransmission and `deadtime` timers as configured values, beyond what the quoted output above shows.
- Every transport but SSH, and every platform but vEOS-lab 4.32.2F.
- Delays above 12s, and whether the connection is torn down by the device or by port49d.

