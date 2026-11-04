# Reference AAA configurations

One file per platform and transport. Replace each placeholder, create the break-glass
account by hand (with a password only you know: no file here holds one), and paste.

| Platform | TCP (RFC 8907) | TLS (RFC 9887) |
|---|---|---|
| Arista EOS | `arista_eos.cfg` | `arista_eos-tls.cfg` |
| Cisco IOS XE | `cisco_iosxe.cfg` | `cisco_iosxe-tls.cfg` |
| Cisco NX-OS | `cisco_nxos.cfg` | `cisco_nxos-tls.cfg` |
| Juniper Junos | `juniper_junos.set` | `juniper_junos-tls.set` |
| Cisco IOS XR | `cisco_iosxr.cfg` | `cisco_iosxr-tls.cfg` |
| Nokia SR Linux | `nokia_srlinux.cli` | none |

`policy-platforms.yaml` is the `platforms:` block XR and SR Linux need in the policy file.

## Placeholders

| Placeholder | What it is |
|---|---|
| `<PORT49_1>`, `<PORT49_2>` | The two port49 servers' addresses. Always two, and distinct. |
| `<KEY>` | The device's shared key (TCP only; an RFC 9887 server carries none). |
| `<SOURCE_INTERFACE>` | EOS, IOS XE, NX-OS and XR: the interface TACACS+ is sourced from. |
| `<SOURCE_ADDRESS>` | Junos and SR Linux: the source address. |
| `<MGMT_VRF>` | The management VRF or routing instance (`management`, `mgmt_junos`, `Mgmt-intf`...). |
| `<BREAKGLASS_USER>` | The local account that works when port49 does not. |
| `<TLS_PORT>` | port49d's RFC 9887 listener port. Always set it: the defaults differ (below). |
| `<SERVER_NAME>` | This device's own name (hostname or FQDN), which its certificate carries. Not port49's hostname. |
| `<CERT_ID>` | The device certificate's trustpoint or certificate id. |

Pin the source (spec section 10): port49 keys a device by its source address, so it must not
change with the route.

## Lines the lab never ran

L88 loaded these files on every lab image, plain TCP and RFC 9887, and they worked (the notes
below cite them). Still unshown: the Junos TLS enrolment through the PKI store, which the lab
did through a root shell.

Two device facts the lab found: the Junos `source-address` must be fxp0's own address
(10.0.0.15 on the lab's VMs), because vrnetlab NATs it to the container's; an address the box
does not hold never leaves it. On XR the group `vrf` clause is for a named VRF only: XR reserves
the name `default`, so the default-VRF form omits it (the file ships both, and L88 measured both). In the L73 run the lab
placed Junos's trust files and client key through a lab-only root shell, so the PKI-store method
is documented but not shown to work. The IOS XE and XR revocation settings are left to you: the
lab used `revocation-check none` and `crl optional` because its CAs publish no CRL.

## What is measured

Cells cite the note that measured them. "Unmeasured (L88)" means the lab register's L88 has not
measured it under these files; treat the cell as unknown, not as a promise.

**How long a device keeps answering locally after its servers failed** (measured by the
retries in L88 cells a, f, e, f2, f3): vJunos, vSRX, vEOS, cEOS and NX-OS: none beyond the
go-dark bound; XR 26.1.1: about 24 to 46 s; IOS XE: 30 to 65 s, the device's own dead-time
(it has no configurable `deadtime`: `deadtime 1` is "Invalid input" and `aaa dead-criteria` is
"Unrecognized", L4-error-cisco_iosxe.md). Inside that window a token login is refused with nothing
sent to port49, and break-glass works. After port49d returns from a stop expect it.

### Junos

Order is `authentication-order tacplus` alone. With `password` listed a port49 deny falls
through to the local password (L4, both Junos images).

**The cost, at 3am:** while port49 answers ERROR (its store is failing), an ERROR is final.
Break-glass waits until go-dark closes the listener, about 5.5 s at the defaults, bounded at 10.5 s (L41), then
logs in. Under the restore guard, it waits until port49d is stopped.

Login classes are not in the file. Run
`port49 platform export --classes --config port49d.yaml juniper_junos` and load its output;
each class's `idle-timeout` is the least ceiling of the sessions landing in it.

| What | Measured | Note |
|---|---|---|
| A deny | Falls through only when `password` is listed, so final under `tacplus` alone | `tests/lab/results/L4-juniper_vjunos-router.md`; under the reference: refused, no fall-through (L88 a; `tests/lab/results/L88-juniper_vjunos-router.md`, `L88-juniper_vsrx.md`, `L88-juniper_vjunos-router-vjunos26.md`) |
| port49 stopped | Break-glass logs in | `tests/lab/results/L4-juniper_vjunos-router.md`, under the reference: break-glass in 20 to 40 ms (L88 b) |
| ERROR | Final until go-dark, then break-glass. Under the reference the first break-glass login succeeded at +7 s on 23.4 and vSRX (port49d closed its listener at +5.5 s); on 26.2R1.7 at once (L88 c) | `tests/lab/results/L4-error-juniper_vjunos-router.md`; bound from L41; L88 notes |
| Dark | Break-glass logs in | L4, L17; under the reference: break-glass logs in and runs a command, 160 to 190 ms (L88 d) |
| Second server | The first server resetting at Accept, the second answering: token login succeeded in 160 to 180 ms (L88 f) | L88 notes |
| Key retire / reload | Session survives; next login break-glass | `tests/lab/results/L29-reload-juniper_vjunos-router.md` (23.4). On 26.2R1.7 the device held no connection open across the reload; on vSRX the in-flight and second command printed, and the next token login was refused for about 5 s with break-glass working (L88 g) |
| Largest `idle-timeout` | 4294967295 minutes; the next value fails the commit (L88 i). `platform export --classes` caps there | `tests/lab/results/L88-juniper_vsrx.md` |
| TLS | Enrolment through the PKI store: not shown (L73 and L88 h placed the trust files and client key through a lab-only root shell). Port, `trusted-ca-group`, `mutual-authentication certificate-id`, `single-connection`. No port: dials 49. SNI: the literal server address. | `tests/lab/results/L73-juniper_vjunos-router.md` (26.2R1.7; not SRX) |
| Reference over TLS | vJunos 26.2R1.7: a, b, d, e, f passed. Break-glass 40 ms stopped, 200 ms dark; token login through the second server in 190 ms (L88 h). The lab placed the trust files and client key through its root shell, so the PKI-store enrolment above is still unshown | `tests/lab/results/L88-juniper_vjunos-router-vjunos26-tls.md` |

### Cisco IOS XE

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-cisco_iosxe.md` |
| port49 stopped | Break-glass in 20 to 30 ms under the reference (L88 b) | `tests/lab/results/L88-cisco_iosxe.md` |
| ERROR | Final: the login is refused, not tried locally. Keep a console path. During a store hang the local account works once port49d closes its listener: +6 s (L88 c) | `tests/lab/results/L4-error-cisco_iosxe.md`. Over TLS it was final too (L73 cell i) |
| Dark | Break-glass logs in, 780 ms (L88 d) | L88 notes |
| Second server | Token login through the second in under 3 s on a fresh device (L88 f). After a break-glass session with port49d stopped, the next token login took 39 s to reach the second (L88 f3, the device's dead window) | `tests/lab/results/L88-cisco_iosxe.md` (f, f3) |
| After port49d returns from a stop | The device answers locally for 30 s measured in f2, 55 s in cell e: a token login in that window is refused with nothing sent to port49, break-glass works (L88 f2) | `tests/lab/results/L88-cisco_iosxe.md` (f2) |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-cisco_iosxe.md` (17.13). On 17.18.02 the device held no connection open across the reload (L88 g, `L88-cisco_iosxe-iosxe1718.md`) |
| TLS | `tls trustpoint server` names the root (L73 ran it). Port 6049 with none set. Two server objects need two distinct addresses (17.18.02 drops a shared one). After a refused handshake the client marks the server dead and answers locally for 57 to 67 s. SNI: none. Sends leaf and intermediate | `tests/lab/results/L73-cisco_iosxe.md` (17.18.02) |
| Reference over TLS | IOS XE 17.18.02: a, b, d, e, f passed. Break-glass 20 ms stopped, 780 ms dark; token login through the second server in 790 ms (L88 h) | `tests/lab/results/L88-cisco_iosxe-iosxe1718-tls.md` |

### Cisco NX-OS

No `deadtime`: `deadtime 1` locks token logins out for its minute after the server returns (L4).

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-cisco_nxos.md` |
| port49 stopped | Break-glass in 140 to 210 ms under the reference (L88 b) | `tests/lab/results/L88-cisco_nxos.md` |
| ERROR | The break-glass login lands (5.2 s over TLS), then port49's authorization FAIL `store_unavailable` refuses its commands. Under the reference the login landed at once, in 2.3 s (L88 c) | `tests/lab/results/L4-error-cisco_nxos.md`, `tests/lab/results/L73-cisco_nxos.md` |
| Dark | Break-glass logs in, about 1.1 to 1.3 s (L88 d) | L88 notes |
| Second server | Token login through the second in about 1.3 s (L88 f) | L88 notes |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-cisco_nxos.md` (10.4). On 10.6(2)F the commands after the reload printed, the next token login was refused for 30 s, and break-glass logged in (L88 g, `L88-cisco_nxos-nxos106.md`) |
| TLS | `tacacs-server secure tls` is required (L73 typed it). 10.6(2)F offered no server-trustpoint keyword, so none is set. No port: dials 49. RSA key. SNI: none. Sends leaf and intermediate. With `single-connection` the login reused the probe's connection | `tests/lab/results/L73-cisco_nxos.md` (10.6(2)F); per-request commands `tests/lab/results/L80-cisco_nxos.md` |
| Reference over TLS | NX-OS 10.6(2)F: a, b, d, e, f passed. Break-glass 220 ms stopped, 1.2 s dark; token login through the second server in 6.2 s, after five connection attempts to the first (L88 h). | `tests/lab/results/L88-cisco_nxos-nxos106-tls.md` |

### Arista EOS

The EOS reference adds `ip tacacs vrf <MGMT_VRF> source-interface <SOURCE_INTERFACE>`; the lab's
startup config pinned none. L88 loaded the clause as shipped (default VRF) on vEOS and cEOS.

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-arista_eos.md` |
| port49 stopped | Break-glass in 40 ms under the reference (L88 b) | `tests/lab/results/L88-arista_eos.md` |
| ERROR | The login falls to local, then exec authorization goes to port49, gets FAIL `store_unavailable`, and does not go on to local. Under the reference the login landed at once (1.1 s) (L88 c) | `tests/lab/results/L4-error-arista_eos.md` |
| Dark | Break-glass logs in, 140 ms (L88 d) | L88 notes |
| Second server | Token login through the second in 290 ms (L88 f) | L88 notes |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-arista_eos.md` (4.31). cEOS 4.36.3M: the commands after the reload were refused, the next token login was refused for 6 s, break-glass logged in (L88 g, `L88-arista_ceos.md`) |
| TLS | Dials 300 with none set. SNI: none. EOS sends its leaf alone, so set `intermediates_file` under `tls_listener` in `port49d.yaml`. Refuses a server certificate that does not name the configured address | `tests/lab/results/L73-arista_ceos.md` (4.36.3M) |
| Reference over TLS | cEOS 4.36.3M: a, b, d, e, f passed. Break-glass 1.8 s stopped, 2 s dark; token login through the second server in 2.4 s (L88 h). EOS shows a TLS host without `port 300`, the default | `tests/lab/results/L88-arista_ceos-tls.md` |

### Cisco IOS XR

Needs the `policy-platforms.yaml` block. XR enrols nothing until a `domain name` is configured.

| What | Measured | Note |
|---|---|---|
| A deny | Refused, no fall-through (L88 a). The device may answer locally for about 24 s after earlier failures, with nothing sent to port49 | `tests/lab/results/L88-cisco_xrd.md`, `L88-cisco_xrd-named-vrf.md` |
| port49 stopped | Break-glass in 110 ms (L88 b) | L88 notes |
| ERROR | Over TLS (L73) final: no fall to local, and break-glass fails; keep a console or second path. Under the reference over plain TCP the break-glass login landed at once during a store hang (L88 c) | `tests/qual/profiles/cisco_iosxr/XRd-control-plane-26.1.1.yaml`, `tests/lab/results/L73-cisco_xrd.md` |
| Dark | Break-glass logs in, 5.6 s (L88 d) | L88 notes |
| Second server | Token login through the second after 31 s of local answers (L88 f; XR's dead window runs 24 to 46 s) | L88 notes |
| Key retire / reload | The command in flight was refused (the reset hit an authorization packet), the second after 5 s, the next token login was refused and break-glass logged in (16 s for three commands) (L88 g) | `tests/lab/results/L88-cisco_xrd.md` |
| Named VRF | The `vrf mgmt` form of the group, with the management interface and SSH server moved into vrf mgmt: a, b, d, e, f passed (L88) | `tests/lab/results/L88-cisco_xrd-named-vrf.md` |
| TLS | No port: dials 49. RSA key. SNI: none. Sends leaf and intermediate. `single-connection` opens its connection at commit. Refused handshake then ERROR: no local fall | `tests/lab/results/L73-cisco_xrd.md` (26.1.1) |
| Reference over TLS | XRd 26.1.1, the reference applied unchanged over a lab enrolment: a, b, d, e, f passed. Break-glass 120 ms stopped and 470 ms dark. A token login reached the second server after 26 s (the device's dead window, as over plain TCP) (L88 h). The group `vrf` line is for a named VRF only, as over plain TCP | `tests/lab/results/L88-cisco_xrd-tls.md` |

### Nokia SR Linux

`exit-on-reject true` makes a port49 deny final. Without it a deny falls through to local
(L76 cell d). `priv-lvl-authorization true` and `services [ cli ]` on each mapped role are
required (L76): with the default, port49 is never asked. The operator level maps to priv-lvl 1,
so an operator is read-only here.

**Provisional on L87:** whether break-glass logs in on ERROR and once port49d is dark under
`exit-on-reject true` is open. This file may change when L87 closes.

| What | Measured | Note |
|---|---|---|
| A deny | Final with `exit-on-reject true`; break-glass is refused while port49 is up and denies it | `tests/lab/results/L76-nokia_srlinux.md` (cells d, l) |
| port49 stopped | With `exit-on-reject true`, break-glass logged in (53 ms). Under the reference over a pty SSH login: 60 to 70 ms (L88 b) | `tests/lab/results/L76-nokia_srlinux.md` (cell l), `L88-nokia_srlinux.md` |
| ERROR | Under the reference the break-glass login landed at once during a store hang, in 3.3 s (L88 c, observed; L87 a stays open) | `tests/lab/results/L88-nokia_srlinux.md` |
| Dark | Break-glass logs in and runs a command, 2.1 to 2.4 s (L88 d; L87 b stays open) | L88 notes |
| Commands | SR Linux asks port49 for no command, so port49 cannot deny one: the command port49's policy denies elsewhere ran, and accounting recorded START and STOP (L88 e). The roles decide what a user may run | L88 notes |
| Second server | The first server resetting at Accept, the second answering: token login in 2.0 to 2.3 s (L88 f) | L88 notes |
| Key retire / reload | No single-connection setting exists in the device's schema (`tree flat system aaa server-group`), so a reload has no shared connection to reset (L88 g, observed) | L88 notes |
| Source address | `source-address` must be configured on an interface of the network instance; the commit refused the DHCP-learned management address and took it once configured statically (L88) | L88 notes |
| TLS | No RFC 9887 reference | |
