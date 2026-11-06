# L71 — cisco_nxos

- **Date measured:** 2026-10-17
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L71-cisco_nxos/probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `7631fe1679233017c4467e990e23c04184553b75`, `PORT49_LAB_PLATFORMS=nxos`, `-run TestL71TLSClientSupport`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

Measured: the help for `tacacs-server host 192.0.2.71 ?` is a real option list (it lists one of the control options [key port timeout]) and lists none of [tls secure], so this image offers no RFC 9887 client there

Sent:

```
tacacs-server host 192.0.2.71 ?
```

The device replied:

```
tacacs-server host 192.0.2.71 ?
  <CR>               
  key                TACACS+ shared secret
  port               TACACS+ server port
  single-connection  Use single connection for this Tacacs+ server
  test               Parameters to send test packets
  timeout            TACACS+ server timeout period in seconds

[43D[Jnx1(config)# tacacs-server host 192.0.2.71 
```

Measured: the help for `tacacs-server ?` is a real option list (it lists one of the control options [key port timeout]) and lists none of [tls secure], so this image offers no RFC 9887 client there

Sent:

```
tacacs-server ?
```

The device replied:

```
tacacs-server ?
  deadtime          Duration for which non-reachable server is skipped
  directed-request  Enable direct authentication requests to server
  host              TACACS+ server's DNS name or its IP address
  key               Global TACACS+ server shared secret
  test              Parameters to send test packets
  timeout           Global TACACS+ server timeout period in seconds

[27D[Jnx1(config)# tacacs-server 
```



## Addendum 2026-10-18: Nexus 9300v 10.6(2)F (`vrnetlab/cisco_n9kv:9300v64-10.6.2.F`)

Probed by TestL73 (commit `7ff5249f69423fddcccfc5122264c8c1ba9a6082`, `PORT49_LAB_PLATFORMS=nxos106`, `-run ^TestL73$`); the exchange is `tests/lab/evidence/L73-cisco_nxos/l71-probe.txt`.

**Has a client.** Typed `tacacs-server host 192.0.2.71 ?`; the help lists:

```
tls                TLS secure connection parameters
```

Full help:

```
tacacs-server host 192.0.2.71 ?
  <CR>               
  key                TACACS+ shared secret
  port               TACACS+ server port
  single-connection  Use single connection for this Tacacs+ server
  test               Parameters to send test packets
  timeout            TACACS+ server timeout period in seconds
  tls                TLS secure connection parameters

[43D[Jnx1(config)# tacacs-server host 192.0.2.71 
```

