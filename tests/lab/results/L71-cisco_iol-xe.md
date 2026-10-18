# L71 — cisco_iol-xe

- **Date measured:** 2026-10-18
- **Platform:** cisco_iol-xe (containerlab node `iol1`, 172.100.100.51)
- **Image version:** IOL-XE 17.18.02 (`vrnetlab/cisco_iol:17.18.02`)
- **Topology:** `tests/lab/topologies/iolxe1718.clab.yml`
- **Capture:** `tests/lab/evidence/L73-cisco_iol-xe/l71-probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `e2cbb76ee353b12d792293acc19d68f92666a9a3`, `PORT49_LAB_PLATFORMS=iolxe1718`, `-run ^TestL73$`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (the IOL-XE probe creates no object: it reads config-mode help only) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

Measured: IOL-XE 17.18.02 offers no RFC 9887 client in its configuration help: config mode lists `aaa`, `tacacs-server` among the words beginning aaa or tacacs and no `tacacs` object; `tacacs-server host <addr>` lists `<cr>` only.

Sent:

```
tacacs-server host 192.0.2.71 ?
```

The device replied:

```
tacacs-server host 192.0.2.71 ?
  <cr>  <cr>

iol1(config)#tacacs-server host 192.0.2.71 
```

The asks, in the order the dialect lists them (the L71 ask first; the evidence-only asks next, recorded and graded on nothing; the `tls` level only if the first ask listed `tls`). The first ask is above.

2. typed `tacacs-server ?`, kept the whole help:

```
  administration      Start tacacs+ deamon handling administrative messages
  attribute           Customize selected tacacs attributes
  cache               AAA auth cache default server group
  directed-request    Allow user to specify tacacs server to use with `@server'
  dns-alias-lookup    Enable IP Domain Name System Alias lookup for TACACS servers
  domain-stripping    Strip the domain from the username
  extended            Enable extended TACACS
  host                Specify a TACACS server
  key                 Set TACACS+ encryption key.
  last-resort         Define TACACS action if no server responds
  optional-passwords  The first TACACS request can be made without password verification
  packet              Modify TACACS+ packet options
  retransmit          Search iterations of the TACACS server list
  timeout             Time to wait for a TACACS server to reply
```

3. typed `?`, kept the lines beginning aaa or tacacs:

```
aaa                         Authentication, Authorization and Accounting.
tacacs-server               Modify TACACS query parameters
```

