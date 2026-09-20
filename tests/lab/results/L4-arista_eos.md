# L4 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L4-arista_eos.pcap` — 394 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L4-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior.

## Observation

The local account `breakglass` presented its own LOCAL password over SSH, under each method list and each server condition. Under `port49d answering FAIL` that account has no token in port49's store, so port49 answers the device FAIL; the decision log column is the proof that it did, for that attempt.

The time column is the device's, not port49's: for this test both `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` were pinned to 100ms, rather than the product defaults of 500ms doubling to 5s, so nothing in these figures is the daemon sleeping.

| method list | port49d | local login | time | decision log |
|---|---|---|---|---|
| `aaa authentication login default group port49 local` | port49d not listening | **logged in** | 40ms | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `aaa authentication login default group port49 local` | port49d answering FAIL | refused | 140ms | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |
| `aaa authentication login default group tacacs+ local` | port49d not listening | **logged in** | 40ms | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `aaa authentication login default group tacacs+ local` | port49d answering FAIL | refused | 140ms | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |

### What the device said when it refused

- `aaa authentication login default group port49 local` / port49d answering FAIL: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain`
- `aaa authentication login default group tacacs+ local` / port49d answering FAIL: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain`

### Does fall-through happen on a denial?

- `aaa authentication login default group port49 local`: **no.** port49 replied FAIL and the device refused the login rather than trying the local password.
- `aaa authentication login default group tacacs+ local`: **no.** port49 replied FAIL and the device refused the login rather than trying the local password.


### The local account

EOS has no equivalent of the Junos password-materialisation defect: the `username breakglass` line in `tests/lab/configs/eos-startup.cfg` produces a usable local password, and every cell above that logged in proves it.

That line now also carries `role network-admin`, and the reason belongs in this note. With `privilege 15` alone, this account logged in while port49d was unreachable and was then refused its first configuration command: `% Authorization denied for command 'configure'`. EOS command authorization under `... group port49 local` falls back to the local **role**, and a role is not a privilege level — an account with no role gets the default one, which authorizes `show` and `enable` and stops there. A break-glass account that can log in during an outage and cannot change anything is worth knowing about before the outage.

CLI channel used: SSH CLI as breakglass. The method list was switched in place over the device's own CLI and restored afterwards.

### Not measured

- `deadtime` — this lab has one TACACS+ server and no dead-server timer was exercised.
- Every transport but SSH: console, eAPI, NX-API and NETCONF.
- A second TACACS+ server, so nothing here says what a device does with one server rejecting and another reachable.
- NX-OS and IOS-XE, and any Junos or EOS release but the one named above.
- Authorization fall-through. This measures the authentication method list only; whether command authorization falls back to local on a deny is a separate question spec §5.6 also leans on.

