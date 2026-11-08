---
title: Cisco IOS XE
description: Configuring Cisco IOS XE to authenticate and authorize logins through port49, and what the lab measured on it.
platforms:
  - cisco_iosxe
  - cisco_iol
---

# Cisco IOS XE

IOS XE does not fall to its local method when port49 answers ERROR: the login is refused, and break-glass fails too, so keep a path that does not depend on port49 answering (the console, or a second reachable server) for the time port49's store is down ([L4-error-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_iosxe.md); over TLS it was final too, [L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell i). Measured on Catalyst 8000V 17.13.01a (TCP) and 17.18.02 (TCP and RFC 9887); the page also names IOL-XE 17.18.02, which has no TLS client.

## Reference configuration

Load [`cisco_iosxe.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_iosxe.cfg) (TACACS+ on port 49) or [`cisco_iosxe-tls.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_iosxe-tls.cfg) (RFC 9887, IOS XE 17.18.1 or later). The [placeholders table](index.md#placeholders) says what each placeholder is. Create the break-glass account by hand, with a password only you know. The lines that matter, quoted from the files:

```text
aaa group server tacacs+ port49
 server name port49-1
 server name port49-2
 ip vrf forwarding <MGMT_VRF>
 ip tacacs source-interface <SOURCE_INTERFACE>
aaa authentication login default group port49 local
aaa authorization exec default group port49 local
aaa authorization commands 15 default group port49 local
aaa authorization config-commands
```

Over TLS each server object carries these instead of a key:

```text
tacacs server port49-1
 address ipv4 <PORT49_1>
 tls port <TLS_PORT>
 tls trustpoint client <CERT_ID>
 tls trustpoint server port49-root
 single-connection
```

## What the lab measured

- A deny port49 answers is never tried locally: break-glass is not a way around it ([L4-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-cisco_iosxe.md)).
- With port49d stopped, break-glass logs in in 20 to 30 ms, and with port49d dark in 780 ms. Commands in sessions that were already open are refused with `% Authorization failed.` ([L88-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md), cells b and d; [L41-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-cisco_iosxe.md); [L35-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L35-cisco_iosxe.md)).
- While port49 answers ERROR, break-glass is refused; with port49d's listener closed it logs in in 60 ms ([L4-error-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_iosxe.md), cells a and c). [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) says what to do while you wait.
- Over TCP the device answers locally for 30 to 39 s after port49d returns from a stop, or after the first server fails: a token login in that window is refused with nothing sent to port49, and break-glass works ([L88-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md), cells f2 and f3). The device has no configurable dead time: the lab's image offered no setting ([L4-error-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_iosxe.md)).
- Over TLS on 17.18.02, after port49d declined or reset the handshakes, the client sent port49d nothing and answered locally for 57 to 67 s. This was measured once ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell i).
- With the first server resetting at accept, a token login reached the second in under 3 s on a fresh device, and in 790 ms over TLS ([L88-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md), cell f; [L88-cisco_iosxe-iosxe1718-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe-iosxe1718-tls.md)).
- Over TLS with no port set the device dials 6049, it sends no server name, and it sends its leaf and its intermediate ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cells a, c, e).
- IOS XE accepts a server certificate that names only a DNS name, and one that names another IP address, though it was configured by address. It refuses an expired certificate and one from an unknown CA with a `bad_certificate` alert ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell d).
- With `single-connection` on, break-glass after port49d reset a de-admitted device's connection was analysed from earlier runs and closed with the fix: on every declined path it logged in within 0.5 s of the key miss ([L31-breakglass-cisco-singleconnection.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L31-breakglass-cisco-singleconnection.md)).
- IOL-XE 17.18.02 offers no RFC 9887 client in its configuration help: `tacacs-server host <address>` lists `<cr>` only ([L71-cisco_iol-xe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L71-cisco_iol-xe.md)).

## Traps

- Keep a console path. An ERROR gives no break-glass over TCP until port49d closes its listener ([L4-error-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_iosxe.md)), and gave none over TLS in the one measured run ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell i).
- A refused token login right after port49d returns is the device's own dead window, not port49: wait it out, or use break-glass ([L88-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md), cell f2).
- Set the TLS `port`: with none the device dials 6049, not port49d's listener ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell a).
- The device accepts a server certificate naming another address, so it does not check what port49d's certificate names: keep the trust to your own CA ([L73-cisco_iosxe.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md), cell d).
- The revocation settings are left to you: the lab used `revocation-check none` because its CAs publish no CRL ([L88-cisco_iosxe-iosxe1718-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe-iosxe1718-tls.md)).

## Unmeasured

!!! warning "Unmeasured: why the second-server login once failed"
    One earlier full reference run failed the second-server cell without an explanation and did not repeat in the three runs after it. The cause is unknown (L52, open; [the evidence run](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe-f-evidence-run.md) is its history).

!!! warning "Unmeasured: the IOS XE SSH condition after refusals"
    A run of refusals to an unrecognised reply attribute stopped the device answering SSH for about a minute without sending port49 a packet. Whether that is the vty pool is unknown (L18, open; [the reply-attribute note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L18-cisco_iosxe.md)).

!!! warning "Unmeasured: two server objects at one address, and the hang timing"
    The reference file says that 17.18.02 drops a second TLS server object that shares an address, so give the two servers distinct addresses; this comes from the file's own comment, and no results note shows the device doing it. How long after a store hang starts the local account first works on IOS XE is also not confirmed here: a report of about 6 s rests on the reference README, not on a note line this page can cite.

!!! warning "Unmeasured: other IOS XE releases and hardware"
    The lab ran Catalyst 8000V 17.13.01a and 17.18.02 and IOL-XE 17.18.02. What other releases and hardware do is unknown.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/cisco-ios-xe.md"
