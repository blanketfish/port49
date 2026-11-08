---
title: Juniper Junos
description: Configuring Juniper Junos to authenticate and authorize logins through port49, and what the lab did and did not measure on it.
platforms:
  - juniper_vjunos-router
  - juniper_vjunos
  - juniper_vsrx
  - juniper_srx
---

# Juniper Junos

Set `authentication-order tacplus` alone, as the reference file does, so that no local password sits behind port49 (what listing `password` after it does is boxed under Unmeasured). The cost is paid at 3am: while port49 answers ERROR, the ERROR is final and break-glass waits until port49d closes its listener ([L4-error-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-juniper_vjunos-router.md)). This page covers vJunos-router, vSRX and SRX hardware. The lab measured nothing on hardware: what is unmeasured on SRX and on hardware is boxed under Unmeasured.

## Reference configuration

Load [`juniper_junos.set`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/juniper_junos.set) (TACACS+ on port 49) or [`juniper_junos-tls.set`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/juniper_junos-tls.set) (RFC 9887, Junos 26.2R1 or later on routing and switching platforms) with `load set terminal`. The [placeholders table](index.md#placeholders) says what each placeholder is. Create the break-glass account's password by hand: no file holds one. The lines that matter, quoted from the files:

```text
delete system authentication-order
set system authentication-order tacplus
set system tacplus-server <PORT49_1> secret "<KEY>"
set system tacplus-server <PORT49_1> routing-instance <MGMT_VRF>
set system tacplus-server <PORT49_1> source-address <SOURCE_ADDRESS>
set system login user <BREAKGLASS_USER> class super-user
```

Over TLS the server carries no secret, the port is always set, and the certificate lines are:

```text
set system tacplus-server <PORT49_1> port <TLS_PORT>
set system tacplus-server <PORT49_1> tls trusted-ca-group port49
set system tacplus-server <PORT49_1> tls mutual-authentication certificate-id <CERT_ID>
set system tacplus-server <PORT49_1> single-connection
```

The login classes and the remote template user are not in the files. They come from your policy: run `port49 platform export --classes --config port49d.yaml juniper_junos` and load its output after the reference file. Each class's `idle-timeout` is the least ceiling of the sessions landing in it.

## What the lab measured

- With port49d stopped, break-glass logs in in 20 to 40 ms; with port49d dark it logs in and runs a command in 160 to 190 ms. Junos asks port49 for no command authorization either way ([L88-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vjunos-router.md), cells b and d; [L41-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-juniper_vjunos-router.md), [L41-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-juniper_vsrx.md)).
- An ERROR is final. Break-glass waits until port49d closes its listener (about 5.5 s at the defaults, bounded at 10.5 s) and then logs in; on 26.2R1.7 the first break-glass login landed at once ([L4-error-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-juniper_vsrx.md), [L88-juniper_vjunos-router-vjunos26.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vjunos-router-vjunos26.md), cell c, [L41-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-juniper_vjunos-router.md)). [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) and the [failure matrix](../../operate/troubleshooting/failure-matrix.md#at-3am) say what to do while you wait.
- The first server resetting at accept, the second answering: a token login succeeded in 160 to 180 ms ([L88-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vjunos-router.md), cell f).
- `idle-timeout` per login class: the largest value the device accepts is 4294967295 minutes, and the next value fails the commit. `port49 platform export --classes` stops there ([L88-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vsrx.md), cell i).
- A live shell keeps its access until logout. Junos asks port49 only at login unless `authorization-time-interval` is set; with it set, Junos asked again once, a revoked principal was denied there, and the denial did not end the session ([L36-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vjunos-router.md), [L36-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vsrx.md)). [Revocation](../../concepts/revocation.md#what-revocation-cannot-do) has the consequence.
- Platform set 1.2.0 adds `junoscript **` and `op **` denies to a reply where a deny is the only guard beneath a sent bit; set 1.3.0 adds `view-configuration` to the bits a reply may send with its reach denied. Over an SSH exec channel, `xml-mode netconf need-trailer` was refused with set 1.2.0's reply and reached NETCONF with a deny of `show configuration` alone and with no deny ([L26c-entries-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L26c-entries-juniper_vjunos-router.md); [L26c-junoscript-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L26c-junoscript-juniper_vjunos-router.md)). [Policy](../policy.md#platform-sets) says how to pin a set and `port49 platform upgrade` how to move one.
- Over RFC 9887 on vJunos-router 26.2R1.7: with no port set the device dials 49, it sends the literal server address as the SNI name, and it sends its leaf and its intermediate certificate ([L73-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md), cells a, c, e).
- The reference over TLS on vJunos-router 26.2R1.7, loaded unchanged: break-glass in 40 ms with port49d stopped and 190 ms dark, and a token login through the second server in 190 ms ([L88-juniper_vjunos-router-vjunos26-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vjunos-router-vjunos26-tls.md)).
- A permit reply of up to 375 bytes, every attribute at most 255, logged in with no lockout on vJunos-router 23.4R2-S2.1 and 26.2R1.7, and break-glass logged in before and after every step. That is a VM; hardware is below ([L78-vJunos-router-26.2R1.7-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L78-vJunos-router-26.2R1.7-juniper_vjunos-router.md)).

## Traps

- The device sends the server's IP address as the SNI name over TLS. If you set `server_names` in port49d's `tls_listener`, list every address the device may dial, or leave it unset: otherwise the device sees an `internal_error` alert and port49d logs `tls_refused` with `sni_mismatch` ([L73-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md), cell c). See [TLS](../../operate/tls.md).
- Mutual TLS is `tls mutual-authentication certificate-id` on the server and on the accounting destination. Vendor documentation puts the TLS client at Junos 26.2R1 on routing and switching platforms ([L71-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L71-juniper_vjunos-router.md)).
- `idle-timeout` is per login class, so it comes from `port49 platform export --classes`, not from the reference file ([L88-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vsrx.md), cell i).
- `source-address` must be an address the box holds on the routing instance; an address it does not hold never leaves it. Accounting destinations need the routing instance too, or the records never leave ([L88-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-juniper_vjunos-router.md)).
- A `junoscript` deny closes the CLI's `xml-mode` route and that session's NETCONF on the images the lab ran; it is set 1.2.0 or later that sends it ([L26c-junoscript-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L26c-junoscript-juniper_vjunos-router.md)).
- An ERROR is final: keep a console path for the seconds break-glass waits ([L4-error-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-juniper_vjunos-router.md)).

## Unmeasured

!!! warning "Unmeasured: a reply over 255 bytes on hardware"
    Whether Junos on hardware locks a user out when a permit session reply totals more than 255 bytes is unknown (L78, open). The lab ran two VM images only ([the 26.2R1.7 run](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L78-vJunos-router-26.2R1.7-juniper_vjunos-router.md)). The only evidence for hardware is a production prior, not a measurement: the operator's experience on hardware Junos is that a reply over 255 bytes locked the user out. port49 keeps its replies inside a budget for that reason; test any long policy on the hardware you run before you rely on it.

!!! warning "Unmeasured: the Junos TLS certificate enrolment and SRX"
    The documented enrolment through the PKI store (generate-key-pair, generate-certificate-request, local-certificate load, a trusted-ca-group) is not shown to work: the lab placed the trust files and the client key through a lab-only root shell, and the note does not record which of two issued certificates the device sent. Whether SRX speaks RFC 9887 at all, and on which releases, is unknown: the lab has not run it, and the vendor documentation quoted in [the lab's client check](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L71-juniper_vjunos-router.md) puts the TLS client on routing and switching platforms, not SRX.

!!! warning "Unmeasured: the local-password fall-through under tacplus alone, and list handling"
    That a login port49 denies falls through to a local password when `password` is listed after `tacplus`, that `authentication-order tacplus` alone refuses a denied login with no fall-through, that `set` on the list adds to it so a device already holding `[ tacplus password ]` keeps `password` (the reference file deletes the list first), and that on 23.4 and on vSRX break-glass lands about 7 s into a store hang, are reported in the reference README and the file's comments. None of these is confirmed here against a note line, and no device debug was captured. Treat them as expectations and check the order with `show configuration system authentication-order` after you load the file.

!!! warning "Unmeasured: how far the junoscript deny reaches"
    Whether the `junoscript` deny also closes REST, the XML API, `outbound-ssh` and `scp` is unknown (L59, open), and so is what these replies do on a Junos release or hardware family the lab did not run.

!!! warning "Unmeasured: SRX hardware command denies"
    An operator reported, from SRX hardware running Junos 23.4R2-S8.7, that a deny naming a hierarchy such as `show configuration security` was not enforced and that regex denies of `xml-mode` did not stop `xml-mode netconf` ([operator-reported note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L26c-operator-juniper_srx.md)). The lab did not run those commands on hardware.

!!! warning "Unmeasured: a second re-authorization"
    Whether Junos re-authorizes an open session more than once, so whether a revocation made after the first ever reaches it, is unknown (L40, open). Do not rely on a revocation reaching a Junos session before the device ends it.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/juniper-junos.md"
