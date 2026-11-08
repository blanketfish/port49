---
title: Cisco NX-OS
description: Configuring Cisco NX-OS to authenticate and authorize logins through port49, and what the lab measured on Nexus 9300v.
platforms:
  - cisco_nxos
---

# Cisco NX-OS

NX-OS 10.6(2)F over TLS honors the single-connect port49 offers it: with the offer the device keeps one connection and asks about every command, where before it asked about some commands only and in one run `show users`, a command port49 denies, ran ([L80-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)). Measured on Nexus 9300v 10.4(2)F (TCP only) and 10.6(2)F (TCP and RFC 9887).

## Reference configuration

Load [`cisco_nxos.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_nxos.cfg) (TACACS+ on port 49) or [`cisco_nxos-tls.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_nxos-tls.cfg) (RFC 9887, NX-OS 10.6(1)F or later). The [placeholders table](index.md#placeholders) says what each placeholder is. Create the break-glass account by hand. The lines that matter, quoted from the files:

```text
feature tacacs+
aaa group server tacacs+ port49
  server <PORT49_1>
  server <PORT49_2>
  use-vrf <MGMT_VRF>
  source-interface <SOURCE_INTERFACE>
aaa authentication login default group port49 local
aaa authorization commands default group port49 local
aaa authorization config-commands default group port49 local
aaa accounting default group port49
```

Over TLS, the lines that differ:

```text
tacacs-server secure tls
tacacs-server host <PORT49_1> port <TLS_PORT> single-connection
tacacs-server host <PORT49_1> tls client-trustpoint <CERT_ID>
```

There is no `deadtime` line, on purpose: see the traps below.

## What the lab measured

Over per-request TLS, the device's default, a command port49 denies ran before the fix and the device asked about some commands only. With port49 offering single-connect the device keeps one connection and asks about every command, `show users` was denied by port49, three concurrent sessions shared one connection, and a session idle for 35 s reconnected cleanly after port49 closed the idle connection ([L80-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)).

The RFC 9887 client was measured on Nexus 9300v 10.6(2)F on 2026-10-18 ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)):

- With no port configured the device dials 49, not 300, and it sends no server name ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cells a and c).
- Every packet has the unencrypted flag set: port49d recorded no `obfuscated_over_tls` records ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cell b).
- It sends its leaf and its intermediate certificate, and negotiates TLS 1.3 with TLS_AES_128_GCM_SHA256. It offered no session ticket ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cells e, f and g).
- Given a server certificate naming only a DNS name, the login failed with the cause unproven; the device's next data came 5 s after the server's first. It refuses an expired certificate and one from an unknown CA with an alert ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cell d).
- With `single-connection` the login reused the readiness probe's connection and opened no new one; without it one login opened 5 ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cell h).
- After an alert at the handshake, break-glass logged in in 5.2 s, and the device never opened a connection to port 49 for the same host (RFC 9887 forbids a fall to plain TACACS+). After an ERROR reply it also landed, in 5.2 s ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md), cells i and j).

!!! note "Regression rerun pending"
    The 2026-11 regression rerun of this measurement did not reproduce it, and the rerun is pending (#46). The results above stand as the lab register records them until a rerun says otherwise.

### Other measured behavior

- A deny is never tried locally ([L4-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-cisco_nxos.md)).
- With port49d stopped, break-glass logs in in 160 ms; with port49d dark, in 1.1 s; and with the first server resetting at accept, a token login reached the second in 1.1 s over TCP ([L88-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_nxos.md), cells b, d and f). Over TLS on 10.6(2)F the same cells took 6.7 s, 1.2 s and 6.2 s, the latter after five connection attempts to the first server ([L88-cisco_nxos-nxos106-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_nxos-nxos106-tls.md)).
- While port49 is dark, commands in sessions that were already open ran under local authorization, so a command port49 would deny is then decided locally ([L41-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-cisco_nxos.md), cell 3).
- An ERROR does not make break-glass a way around port49's commands: the break-glass login lands and then every command is refused `Error: AAA authorization failed` ([L4-error-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_nxos.md)). [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) says what to do.
- Break-glass with `single-connection` on, after port49d reset a de-admitted device's connection, was closed with the fix: on every declined path it logged in within 0.5 s of the key miss ([L31-breakglass-cisco-singleconnection.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L31-breakglass-cisco-singleconnection.md)).
- A port49d restart in mid-session on a real etcd cost nothing: the device reconnected by itself and every permitted command ran. On the memory store every command typed after the restart was denied `context_missing` until the person logged in again ([L80-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)).

## Traps

- Set no `deadtime`: `deadtime 1` locks token logins out for its minute after the server returns ([L4-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-cisco_nxos.md)).
- Over TLS you need `tacacs-server secure tls`: without it NX-OS speaks plain TACACS+ to the TLS port ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)).
- Set the TLS `port`: with none the device dials 49, not port49d's listener ([L73-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)).
- The first TLS open on a new connection can take about 5 s: NX-OS 10.6's open retry, with or without a restart. A login or break-glass over TLS can take that long ([L80-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)).
- Run port49d on etcd, not the memory store, if a restart must not cost a fresh login: the memory store loses the login context in the stopped process ([L80-cisco_nxos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)).

## Unmeasured

!!! warning "Unmeasured: whether NX-OS checks port49's certificate status"
    Whether NX-OS checks port49's revocation status, and SCEP, CMPv2, EST and ACME enrolment, were not measured: the lab used terminal enrolment and `revocation-check none` ([the TLS note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)).

!!! warning "Unmeasured: why the first TLS open fails"
    Why the device's first `nxos_ssl_open` on a new connection fails before its retry succeeds about 5 s later is unknown, and so is one counter that read 3 in seven of eight fixed-arm cells with no fallback line beside it ([the per-request TLS note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L80-cisco_nxos.md)).

!!! warning "Unmeasured: other NX-OS releases"
    The lab ran 10.4(2)F over TCP and 10.6(2)F over TCP and RFC 9887. What other releases do is unknown.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/cisco-nx-os.md"
