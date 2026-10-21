# L71 — cisco_xrd

- **Date measured:** 2026-10-18
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/L73-cisco_xrd/l71-probe.txt` — the CLI exchange from the help request to the empty-line check, credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.
- **Transport:** SSH
- **Run:** commit `1a4ac229ea0f5696b381aafb5621e1516766b565`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestL73$`

## Claim

Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own help with nothing left configured (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos 26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved 23.4R2-S2.1 and vSRX 23.4R1.9 are not probed.

## Observation

**Has a client.** Typed `tacacs-server host 192.0.2.71 ?`; the help lists:

```
tls                             TLS support for TACACS+
```

Full help:

```
tacacs-server host 192.0.2.71 ?
  apply-group                     Apply configuration from a group
  exclude-group                   Exclude apply-group configuration from a group
  holddown-time                   Time for which this TACACS server is marked as dead
  key                             per-server encryption key (overrides default)
  port                            TCP port for TACACS+ server (default is 49)
  single-connection               Reuse connection to this server for all requests
  single-connection-idle-timeout  Idle timeout for a single-connection to the server
  timeout                         Time to wait for this TACACS server to reply (overrides default)
  tls                             TLS support for TACACS+
  <cr>                            
RP/0/RP0/CPU0:xrd1(config)#tacacs-server host 192.0.2.71 
```

The asks, in the order the dialect lists them (the L71 ask first; the evidence-only asks next, recorded and graded on nothing; the `tls` level only if the first ask listed `tls`). The first ask is above.

2. typed `ssh server ?`, kept the whole help:

```
  algorithms                 server algorithms
  backup                     Cisco sshd backup server
  capability                 Turn on Capability
  certificate                certificate related parameters
  disable                    Disable sshd algorithms
  dscp                       Cisco ssh server DSCP
  enable                     Enable AES-CBC and 3DES-CBC algorithms
  ipv4                       IPv4 access list for ssh server
  ipv6                       IPv6 access list for ssh server
  logging                    Enable ssh server logging
  max-auth-limit             User Configurable max authentication attempts
  netconf                    start ssh service for netconf subsystem
  openssh                    OpenSSH certificates
  packet-flow-netio          Configure to make packets go via NetIO. Applicable only to Mgmt Traffic
  port                       User Configurable ssh port (Default 22)
  port-forwarding            Enable port forwarding for ssh server
  rate-limit                 Cisco sshd rate-limit of service requests
  rekey-time                 Configures time-based rekey (default 60 minutes)
  rekey-volume               Configures volume-based rekey (default 1024MB)
  session-limit              Cisco sshd session-limit of service requests
  set-dscp-connection-phase  Mark packets with dscp value from ssh connection phase
  tcp-window-scale           Set tcp window-scale factor for High Latency links
  timeout                    Server timeouts for incoming ssh sessions
  trustpoint                 trustpoints for server certificates
  username                   ssh user
  v1                         Cisco sshd protocol version 1. This is deprecated in 25.3.1.
  v2                         Cisco sshd force protocol version 2 only
  vrf                        Cisco sshd VRF name
  <cr>
```

3. typed `ssh server rate-limit ?`, kept the whole help:

```
  <1-6000>  Limit in term of number of request per minute (default 60)
```

## Operator fact: XRd's sshd rate-limits incoming sessions

Measured in the two XRd runs of 2026-10-18 before this one (not part of this run's help-only exchange): the harness's login probes and its first CLI open arrived close together, and the container log, read through the lab's filter, shows `sshd[...]: Incoming SSH session rate limit exceeded` (06:58:07 and 06:58:12 UTC in the second run, 06:28:47 and 06:28:52 in the first), each time with the new session's SSH handshake ended by `connection reset by peer`. A retry 10 s later connected. The image's own help (above) offers `ssh server rate-limit` with a range of `<1-6000>` requests per minute and says "default 60"; `ssh server session-limit` is a separate option. Nothing was configured: the harness retries the open (up to 6 tries, 10 s apart, only on a reset or closed handshake). For anyone scripting logins into XRd: expect resets above the rate limit, and retry rather than treat a reset as a refusal.

## Addendum: TestL73 probe

Measured 2026-10-21 on XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`). Probed by TestL73 (commit `67fd821d38f8fa70ad28f2ec4ea215ef6ddddc80`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestL73$`); the exchange is `tests/lab/evidence/L73-cisco_xrd/l71-probe.txt`.

**Has a client.** Typed `tacacs-server host 192.0.2.71 ?`; the help lists:

```
tls                             TLS support for TACACS+
```

Full help:

```
tacacs-server host 192.0.2.71 ?
  apply-group                     Apply configuration from a group
  exclude-group                   Exclude apply-group configuration from a group
  holddown-time                   Time for which this TACACS server is marked as dead
  key                             per-server encryption key (overrides default)
  port                            TCP port for TACACS+ server (default is 49)
  single-connection               Reuse connection to this server for all requests
  single-connection-idle-timeout  Idle timeout for a single-connection to the server
  timeout                         Time to wait for this TACACS server to reply (overrides default)
  tls                             TLS support for TACACS+
  <cr>                            
RP/0/RP0/CPU0:xrd1(config)#tacacs-server host 192.0.2.71 
```

The asks, in the order the dialect lists them (the L71 ask first; the evidence-only asks next, recorded and graded on nothing; the `tls` level only if the first ask listed `tls`). The first ask is above.

10. typed `ssh server ?`, kept the whole help:

```
  algorithms                 server algorithms
  backup                     Cisco sshd backup server
  capability                 Turn on Capability
  certificate                certificate related parameters
  disable                    Disable sshd algorithms
  dscp                       Cisco ssh server DSCP
  enable                     Enable AES-CBC and 3DES-CBC algorithms
  ipv4                       IPv4 access list for ssh server
  ipv6                       IPv6 access list for ssh server
  logging                    Enable ssh server logging
  max-auth-limit             User Configurable max authentication attempts
  netconf                    start ssh service for netconf subsystem
  openssh                    OpenSSH certificates
  packet-flow-netio          Configure to make packets go via NetIO. Applicable only to Mgmt Traffic
  port                       User Configurable ssh port (Default 22)
  port-forwarding            Enable port forwarding for ssh server
  rate-limit                 Cisco sshd rate-limit of service requests
  rekey-time                 Configures time-based rekey (default 60 minutes)
  rekey-volume               Configures volume-based rekey (default 1024MB)
  session-limit              Cisco sshd session-limit of service requests
  set-dscp-connection-phase  Mark packets with dscp value from ssh connection phase
  tcp-window-scale           Set tcp window-scale factor for High Latency links
  timeout                    Server timeouts for incoming ssh sessions
  trustpoint                 trustpoints for server certificates
  username                   ssh user
  v1                         Cisco sshd protocol version 1. This is deprecated in 25.3.1.
  v2                         Cisco sshd force protocol version 2 only
  vrf                        Cisco sshd VRF name
  <cr>
```

11. typed `ssh server rate-limit ?`, kept the whole help:

```
  <1-6000>  Limit in term of number of request per minute (default 60)
```
