# L13 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L13-juniper_vsrx.pcap` — 390 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L13-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Each device's TACACS+ reply timeout, and what the device does when a FAIL reply arrives after it — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server.

## Observation

### The device's own timeout

`show configuration system tacplus-server | display inheritance defaults`:

```
set system tacplus-server 172.100.100.1 routing-instance mgmt_junos
set system tacplus-server 172.100.100.1 secret <redacted by the harness>
```

What the device's own reference says about `timeout` (`help reference system tacplus-server`):

```
single-connection;
           source-address source-address;
           timeout seconds;

   }

    Hierarchy Level

   [edit system]

    Release Information

   Statement introduced before JUNOS Release 7.4.
```

### Late FAIL replies

port49d was restarted before each row with `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` both set to the delay in the first column, so the **first** failure for this account already carried the full delay and no failures had to be driven first. The login is the local account `breakglass` presenting its own local password; port49 holds no token for it, so the reply is FAIL (`token_not_found`), sent that long after the request arrived.

| FAIL delayed by | SSH login | elapsed | redeem records for the account | reasons |
|---|---|---|---|---|
| 2s | **logged in** | 2.06s | 1 | deny/token_not_found |
| 6s | **logged in** | 3.51s | 1 | deny/token_not_found |
| 12s | **logged in** | 3.02s | 1 | deny/token_not_found |

**Measured reply timeout: about 3.5s.** A FAIL delayed by 2s was waited out (2.06s elapsed); one delayed by 6s was not, and the login resolved after 3.51s. So the timeout lies between 2s and 3.5s.

When the FAIL arrived after that, the device **accepted the local password**, exactly as it does when the server is unreachable (L4). A denial delayed past the timeout is therefore not a denial: it is indistinguishable from an outage, and the device takes the fall-through branch. **port49's own default `limits.auth_failure_delay_max` is 5s** (internal/config), reached after five consecutive failures for one `(nas, username)` pair. Compare that with the figure above before treating a repeated-failure delay as a way to slow an attacker down: past the device's timeout it stops slowing anything down and starts changing the answer the device acts on.


**How to read the elapsed column.** An elapsed time at or just above the delay means the device waited for the reply. An elapsed time well below it means the device stopped waiting, and what it did next — refuse, or fall through to the local password — is the outcome column. More than one redeem record for a single login attempt means the device gave up and asked again, which is the retransmission half of the same behavior.

### Not measured

- The method list in force is whatever `tests/lab/configs` deploys; this row does not sweep the authentication order (that is L4).
- A second TACACS+ server, so "tries the next server" is untested — the lab has one.
- The device's retransmission and `deadtime` timers as configured values, beyond what the quoted output above shows.
- Every transport but SSH, and every platform but vSRX3 21.4R3.15.
- Delays above 12s, and whether the connection is torn down by the device or by port49d.

