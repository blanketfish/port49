# L4 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L4-juniper_vsrx.pcap` — 590 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L4-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior.

## Observation

The local account `breakglass` presented its own LOCAL password over SSH, under each method list and each server condition. Under `port49d answering FAIL` that account has no token in port49's store, so port49 answers the device FAIL; the decision log column is the proof that it did, for that attempt.

The time column is the device's, not port49's: for this test both `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` were pinned to 100ms, rather than the product defaults of 500ms doubling to 5s, so nothing in these figures is the daemon sleeping.

| method list | port49d | local login | time | decision log |
|---|---|---|---|---|
| `authentication-order [ tacplus password ]` | port49d not listening | **logged in** | 10ms | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `authentication-order [ tacplus password ]` | port49d answering FAIL | **logged in** | 120ms | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |
| `authentication-order tacplus` | port49d not listening | **logged in** | 520ms | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `authentication-order tacplus` | port49d answering FAIL | refused | 5.23s | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |

### What the device said when it refused

- `authentication-order tacplus` / port49d answering FAIL: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`

### Does fall-through happen on a denial?

- `authentication-order [ tacplus password ]`: **yes.** port49 replied FAIL and the device then accepted the local password. A denial is not treated as final.
- `authentication-order tacplus`: **no.** port49 replied FAIL and the device refused the login rather than trying the local password.


### The local account

`show configuration system login user breakglass` carries an **`encrypted-password` line** (the value is not reproduced here). The startup config's hash survived the commit on this image.

The order in force when this was read, per `show configuration system authentication-order`:

```
set system authentication-order tacplus
set system authentication-order password
```

CLI channel used: SSH CLI as breakglass. The order was switched in place over the device's own CLI and restored afterwards.

### Not measured

- `deadtime` — this lab has one TACACS+ server and no dead-server timer was exercised.
- Every transport but SSH: console, eAPI, NX-API and NETCONF.
- A second TACACS+ server, so nothing here says what a device does with one server rejecting and another reachable.
- NX-OS and IOS-XE, and any Junos or EOS release but the one named above.
- Authorization fall-through. This measures the authentication method list only; whether command authorization falls back to local on a deny is a separate question spec §5.6 also leans on.

