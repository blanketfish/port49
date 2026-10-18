# L71 — juniper_vjunos-router

- **Date measured:** 2026-10-17
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L71-juniper_vjunos-router/probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `7631fe1679233017c4467e990e23c04184553b75`, `PORT49_LAB_PLATFORMS=eos,iosxe,nxos,vjunos,vsrx`, `-run TestL71TLSClientSupport`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

Measured: the help for `set system tacplus-server 192.0.2.71 ?` is a real option list (it lists one of the control options [secret port timeout]) and lists none of [tls], so this image offers no RFC 9887 client there

Sent:

```
set system tacplus-server 192.0.2.71 ?
```

The device replied:

```
set system tacplus-server 192.0.2.71 ?
Possible completions:
  <[Enter]>            Execute this command
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  port                 TACACS+ authentication server port number
  routing-instance     Routing instance
  secret               Shared secret with the authentication server
  single-connection    Optimize TCP connection attempts
  source-address       Use specified address as source address
  timeout              Request timeout period (1..90 seconds)
  |                    Pipe through a command
[edit]
breakglass@srx1# set system tacplus-server 192.0.2.71    
```



## Addendum 2026-10-18: vJunos-router 26.2R1.7 (`vrnetlab/juniper_vjunos-router:26.2R1.7`)

Probed by TestL73 (commit `d1614baa70cddaff861c0c171bb82ad9a3360522`, `PORT49_LAB_PLATFORMS=vjunos26`, `-run ^TestL73$`); the exchange is `tests/lab/evidence/L73-juniper_vjunos-router/l71-probe.txt`.

**Has a client.** Typed `set system tacplus-server 192.0.2.71 ?`; the help lists:

```
> tls                  TACACS+ over TLS
```

Full help:

```
set system tacplus-server 192.0.2.71 ?
Possible completions:
  <[Enter]>            Execute this command
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  port                 TACACS+ authentication server port number
  routing-instance     Routing instance
  secret               Shared secret with the authentication server
  single-connection    Optimize TCP connection attempts
  source-address       Use specified address as source address
  timeout              Request timeout period (1..90 seconds)
> tls                  TACACS+ over TLS
  |                    Pipe through a command
[edit]
breakglass@srx1# set system tacplus-server 192.0.2.71    
```

