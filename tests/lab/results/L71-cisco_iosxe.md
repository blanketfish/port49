# L71 — cisco_iosxe

- **Date measured:** 2026-10-17
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L71-cisco_iosxe/probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `7631fe1679233017c4467e990e23c04184553b75`, `PORT49_LAB_PLATFORMS=eos,iosxe,nxos,vjunos,vsrx`, `-run TestL71TLSClientSupport`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

Measured: the help for `?` is a real option list (it lists one of the control options [address key port timeout]) and lists none of [tls], so this image offers no RFC 9887 client there

Sent:

```
?
```

The device replied:

```
?
TACACS server sub-mode commands:
  address            Specify ip address for tacacs server
  exit               Exit from TACACS server configuration mode
  key                per-server encryption key (overrides default)
  no                 Negate a command or set its defaults
  port               TCP port for TACACS+ server (default is 49)
  send-nat-address   To send client's post NAT address to tacacs+ server
  single-connection  Multiplex all packets over a single tcp connection to server (for CiscoSecure)
  timeout            Time to wait for this TACACS server to reply (overrides default)

xe1(config-server-tacacs)#
```



## Addendum 2026-10-18: Catalyst 8000V 17.18.02 (`vrnetlab/cisco_c8000v:17.18.02`)

Probed by TestL73 (commit `d9275748b9332d095549d52020d9f866bd330c12`, `PORT49_LAB_PLATFORMS=iosxe1718`, `-run ^TestL73$`); the exchange is `tests/lab/evidence/L73-cisco_iosxe/l71-probe.txt`.

**Has a client.** Typed `?`; the help lists:

```
tls                Configure tls for tacacs server
```

Full help:

```
?
TACACS server sub-mode commands:
  address            Specify ip address for tacacs server
  exit               Exit from TACACS server configuration mode
  key                per-server encryption key (overrides default)
  no                 Negate a command or set its defaults
  port               TCP port for TACACS+ server (default is 49)
  send-nat-address   To send client's post NAT address to tacacs+ server
  single-connection  Multiplex all packets over a single tcp connection to server (for CiscoSecure)
  timeout            Time to wait for this TACACS server to reply (overrides default)
  tls                Configure tls for tacacs server

xe1(config-server-tacacs)#
```

