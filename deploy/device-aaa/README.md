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
| `<SERVER_NAME>` | The name the device's certificate carries. |
| `<CERT_ID>` | The device certificate's trustpoint or certificate id. |

Pin the source (spec section 10): port49 keys a device by its source address, so it must not
change with the route.

## What is measured

Cells cite the note that measured them. "Unmeasured (L88)" means the lab register's L88 will
measure it under these files; until it does, treat the cell as unknown, not as a promise.

### Junos

Order is `authentication-order tacplus` alone. With `password` listed a port49 deny falls
through to the local password (L4, both Junos images).

**The cost, at 3am:** while port49 answers ERROR (its store is failing), an ERROR is final.
Break-glass waits until go-dark closes the listener, at most 5.5 s at the defaults (L41), then
logs in. Under the restore guard, it waits until port49d is stopped.

Login classes are not in the file. Run
`port49 platform export --classes --config port49d.yaml juniper_junos` and load its output;
each class's `idle-timeout` is the least ceiling of the sessions landing in it.

| What | Measured | Note |
|---|---|---|
| A deny | Falls through only when `password` is listed, so final under `tacplus` alone | `tests/lab/results/L4-juniper_vjunos-router.md`; under the reference: unmeasured (L88 a) |
| port49 stopped | Break-glass logs in | `tests/lab/results/L4-juniper_vjunos-router.md`, under the reference: unmeasured (L88 b) |
| ERROR | Final until go-dark, then break-glass | `tests/lab/results/L4-error-juniper_vjunos-router.md`; bound from L41 |
| Dark | Break-glass logs in | L4, L17; under the reference: unmeasured (L88 d) |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Session survives; next login break-glass | `tests/lab/results/L29-reload-juniper_vjunos-router.md` (23.4); unmeasured on 26.2 (L88 g) |
| TLS | Port, `trusted-ca-group`, `mutual-authentication certificate-id`, `single-connection`. No port: dials 49. SNI: the literal server address. | `tests/lab/results/L73-juniper_vjunos-router.md` (26.2R1.7; not SRX) |

### Cisco IOS XE

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-cisco_iosxe.md` |
| port49 stopped | Unmeasured under the reference (L88 b) | |
| ERROR | Final: the login is refused, not tried locally. Keep a console path | `tests/lab/results/L4-error-cisco_iosxe.md`. Over TLS it was final too (L73 cell i) |
| Dark | Unmeasured (L88 d) | |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-cisco_iosxe.md` (17.13) |
| TLS | Port 6049 with none set. Two server objects need two distinct addresses (17.18.02 drops a shared one). After a refused handshake the client marks the server dead and answers locally for 57 to 67 s. SNI: none. Sends leaf and intermediate | `tests/lab/results/L73-cisco_iosxe.md` (17.18.02) |

### Cisco NX-OS

No `deadtime`: `deadtime 1` locks token logins out for its minute after the server returns (L4).

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-cisco_nxos.md` |
| port49 stopped | Unmeasured under the reference (L88 b) | |
| ERROR | The break-glass login lands (5.2 s over TLS), then port49's authorization FAIL `store_unavailable` refuses its commands | `tests/lab/results/L4-error-cisco_nxos.md`, `tests/lab/results/L73-cisco_nxos.md` |
| Dark | Unmeasured (L88 d) | |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-cisco_nxos.md` (10.4) |
| TLS | No port: dials 49. RSA key. SNI: none. Sends leaf and intermediate. With `single-connection` the login reused the probe's connection | `tests/lab/results/L73-cisco_nxos.md` (10.6(2)F); per-request commands `tests/lab/results/L80-cisco_nxos.md` |

### Arista EOS

The EOS reference adds `ip tacacs vrf <MGMT_VRF> source-interface <SOURCE_INTERFACE>`; the lab's
startup config pinned none. Its VRF clauses are unmeasured (L88).

| What | Measured | Note |
|---|---|---|
| A deny | Never falls through | `tests/lab/results/L4-arista_eos.md` |
| port49 stopped | Unmeasured under the reference (L88 b) | |
| ERROR | The login falls to local, then exec authorization goes to port49, gets FAIL `store_unavailable`, and does not go on to local | `tests/lab/results/L4-error-arista_eos.md` |
| Dark | Unmeasured (L88 d) | |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Session survives; a served device's FAIL is final | `tests/lab/results/L29-reload-arista_eos.md` (4.31) |
| TLS | Dials 300 with none set. SNI: none. EOS sends its leaf alone, so set `intermediates_file` under `tls_listener` in `port49d.yaml`. Refuses a server certificate that does not name the configured address | `tests/lab/results/L73-arista_ceos.md` (4.36.3M) |

### Cisco IOS XR

Needs the `policy-platforms.yaml` block. XR enrols nothing until a `domain name` is configured.

| What | Measured | Note |
|---|---|---|
| A deny | Unmeasured (L88 a) | |
| port49 stopped | Unmeasured (L88 b) | |
| ERROR | Final: no fall to local, and break-glass fails. Keep a console or second path | `tests/qual/profiles/cisco_iosxr/XRd-control-plane-26.1.1.yaml`, `tests/lab/results/L73-cisco_xrd.md` |
| Dark | Unmeasured (L88 d) | |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Unmeasured (L88 g) | |
| TLS | No port: dials 49. RSA key. SNI: none. Sends leaf and intermediate. `single-connection` opens its connection at commit. Refused handshake then ERROR: no local fall | `tests/lab/results/L73-cisco_xrd.md` (26.1.1) |

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
| port49 stopped | Unmeasured (L87, L88 b) | |
| ERROR | Unmeasured (L87 a) | |
| Dark | Unmeasured (L87 b) | |
| Second server | Unmeasured (L88 f) | |
| Key retire / reload | Unmeasured (L88 g) | |
| TLS | No RFC 9887 reference | |
