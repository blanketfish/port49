# L4 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L4-cisco_iosxe.pcap` — 570 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L4-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior.

## Observation

The local account `breakglass` presented its own LOCAL password over SSH, under each method list and each server condition. Under `port49d answering FAIL` that account has no token in port49's store, so port49 answers the device FAIL; the decision log column is the proof that it did, for that attempt.

The time column is the device's, not port49's: for this test both `limits.auth_failure_delay_base` and `limits.auth_failure_delay_max` were pinned to 100ms, rather than the product defaults of 500ms doubling to 2s, so nothing in these figures is the daemon sleeping.

| method list | port49d | local login | time | decision log |
|---|---|---|---|---|
| `aaa authentication login default group port49 local` | port49d not listening | **logged in** | 20ms | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `aaa authentication login default group port49 local` | port49d answering FAIL | refused | 4.22s | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |
| `aaa authentication login default group port49` | port49d not listening | refused | 4.02s | port49d was not listening, so no decision record could exist for this attempt. The capture holds the device's refused connection attempts to port 49. |
| `aaa authentication login default group port49` | port49d answering FAIL | refused | 4.22s | `event=redeem verdict=deny reason=token_not_found`, so port49 replied FAIL for this attempt. |

### What the device said when it refused

- `aaa authentication login default group port49 local` / port49d answering FAIL: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`
- `aaa authentication login default group port49` / port49d not listening: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`
- `aaa authentication login default group port49` / port49d answering FAIL: `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain`

### Does fall-through happen on a denial?

- `aaa authentication login default group port49 local`: **no.** port49 replied FAIL and the device refused the login rather than trying the local password.
- `aaa authentication login default group port49`: **no.** port49 replied FAIL and the device refused the login rather than trying the local password.


### The local account

The local account is the `username breakglass privilege 15 secret ...` line in `tests/lab/configs/iosxe-startup.cfg`. Every cell above that logged in is the proof it exists, and `privilege 15` is what lets it configure anything once it is in: IOS-XE command authorization under `... group port49 local` authorizes a command only if the user's level is at or above the command's, which is the privilege-level form of the role lesson EOS taught in `tests/lab/results/L4-arista_eos.md`.

The second method list is NX-OS's contrast, not EOS's: the lab line already names a group and ends in `local`, so the shape worth trying is the one Junos answered -- a list with **no local method at all**.

Setting that list on IOS-XE costs something no other platform here charges, and it is why `configs/iosxe-startup.cfg` carries an `aaa authentication login CONSOLE local` list pinned to `line con 0`. NX-OS keeps a console method list of its own that defaults to `local`; IOS-XE runs the console through the same `default` list as every vty, so `group port49` with the daemon stopped would shut out SSH and the console together and the restore below could not happen at all. The named list changes nothing this test measures -- every login here is over SSH, on a vty using the `default` list under test.

CLI channel used: SSH CLI as alice05. The method list was switched in place over the device's own CLI and restored afterwards.

### Not measured

- `deadtime` — this lab has one TACACS+ server and no dead-server timer was exercised.
- Every transport but SSH: console, eAPI, NX-API and NETCONF.
- A second TACACS+ server, so nothing here says what a device does with one server rejecting and another reachable.
- Any cisco_iosxe release but the one named above, and every platform family this lab does not deploy. The families it does are `arista_eos`, `juniper_vjunos-router`, `juniper_vsrx`, `cisco_nxos`, each in its own L4 note.
- Authorization fall-through. This measures the authentication method list only; whether command authorization falls back to local on a deny is a separate question spec §5.6 also leans on.

