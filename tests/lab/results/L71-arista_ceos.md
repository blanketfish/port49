# L71 — arista_ceos

- **Date measured:** 2026-10-18
- **Platform:** arista_ceos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Capture:** `tests/lab/evidence/L73-arista_ceos/l71-probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `4736fc05fb12c48b73dba7629851169d776f3b10`, `PORT49_LAB_PLATFORMS=ceos436`, `-run ^TestL73$`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

**Has a client.** Typed `tacacs-server host 192.0.2.71 ?`; the help lists:

```
tls                Enable TLS for TACACS+ server
```

Full help:

```
tacacs-server host 192.0.2.71 ?
  key                Encryption key for this TACACS+ server (overrides default)
  port               TCP port of TACACS+ server ( default is 49 )
  single-connection  Use one TCP connection for multiple sessions
  timeout            Time to wait for this TACACS+ server to respond ( overrides default)
  tls                Enable TLS for TACACS+ server
  vrf                VRF for this TACACS+ server
  <cr>               

leaf1(config)#tacacs-server host 192.0.2.71 
```

