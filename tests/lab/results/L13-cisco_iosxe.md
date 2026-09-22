# L13 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L13-cisco_iosxe.pcap` — 272 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L13-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Each device's TACACS+ reply timeout, and what the device does when a FAIL reply arrives after it — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server.

## Observation

### The device's own timeout

`show tacacs`:

```
Tacacs+ Server -  public  :
               Server name: port49-host
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:         13
             Socket closes:         13
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:          2
        Total Packets Sent:         11
        Total Packets Recv:         11
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0
```

`show aaa servers`:

```

```

`show running-config | include tacacs`:

```
aaa group server tacacs+ port49
 ip tacacs source-interface GigabitEthernet1
tacacs server port49-host
```

### Late FAIL replies

port49d was restarted before each row with `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` both set to the delay in the first column, so the **first** failure for this account already carried the full delay and no failures had to be driven first. The login is the local account `breakglass` presenting its own local password; port49 holds no token for it, so the reply is FAIL (`token_not_found`), sent that long after the request arrived.

| FAIL delayed by | SSH login | elapsed | redeem records for the account | reasons |
|---|---|---|---|---|
| 2s | refused | 8.02s | 2 | deny/token_not_found, deny/token_not_found |
| 6s | refused | 14.02s | 2 | deny/token_not_found, deny/token_not_found |
| 12s | refused | 14.02s | 1 | deny/token_not_found |

**The device acted on the denial every time.** No delay up to 12s made it stop waiting and take the local password, so its reply timeout is above that and this run does not bound it from above.


**How to read the elapsed column.** An elapsed time at or just above the delay means the device waited for the reply. An elapsed time well below it means the device stopped waiting, and what it did next — refuse, or fall through to the local password — is the outcome column. More than one redeem record for a single login attempt means the device gave up and asked again, which is the retransmission half of the same behavior.

What SSH said when the login was refused:

- 2s delay: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`
- 6s delay: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`
- 12s delay: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`

### Not measured

- The method list in force is whatever `tests/lab/configs` deploys; this row does not sweep the authentication order (that is L4).
- A second TACACS+ server, so "tries the next server" is untested — the lab has one.
- The device's retransmission and `deadtime` timers as configured values, beyond what the quoted output above shows.
- Every transport but SSH, and every platform but Catalyst 8000V 17.13.01a.
- Delays above 12s, and whether the connection is torn down by the device or by port49d.

