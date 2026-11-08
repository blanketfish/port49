---
title: Cisco IOS XR
description: Configuring Cisco IOS XR to authenticate and authorize logins through port49, and what the lab measured on XRd.
platforms:
  - cisco_xrd
---

# Cisco IOS XR

With no `port` set, XR's TLS client dials 49, not the RFC's 300, so you always set the TLS server's `port` to match port49d's RFC 9887 listener ([L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md), cell a). XR also needs a `platforms:` block in the port49 policy file, or every login is refused. Measured on XRd control plane 26.1.1, over TACACS+ on port 49 and over RFC 9887.

## Reference configuration

Load [`cisco_iosxr.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_iosxr.cfg) (TACACS+ on port 49) or [`cisco_iosxr-tls.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/cisco_iosxr-tls.cfg) (RFC 9887). The [placeholders table](index.md#placeholders) says what each placeholder is. Create the break-glass account first, by hand, with a secret only you know.

Add the [`policy-platforms.yaml`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/policy-platforms.yaml) block to your policy file. Without it, platform set 1.3.0 has no `cisco_iosxr` adapter, the generic adapter sends no priv-lvl, and XR refuses every command locally with `% This command is not authorized` while asking port49 about none; it fails safe, but nothing works ([QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.md)). The block:

```yaml
platforms:
  cisco_iosxr:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
```

Only `priv-lvl=15` was measured. Level 1 for `readonly` and `operator` can only grant less than the role says, and on XR that holds only with command authorization configured on the device. [Policy](../policy.md#platform-sets) says how platform sets work. The lines that matter, quoted from the files:

```text
tacacs source-interface <SOURCE_INTERFACE> vrf <MGMT_VRF>
tacacs-server host <PORT49_1> key 0 <KEY>
aaa group server tacacs+ port49
 server <PORT49_1>
 server <PORT49_2>
aaa authentication login default group port49 local
aaa authorization exec default group port49 local
aaa authorization commands default group port49 local
```

Over TLS each host carries its port and options, one option per line:

```text
tacacs-server host <PORT49_1> port <TLS_PORT> tls trustpoint <CERT_ID>
tacacs-server host <PORT49_1> port <TLS_PORT> single-connection
```

## What the lab measured

- A deny port49 answers is refused ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cell a).
- After earlier failures XR answers locally and asks port49 nothing for a while: a login at +12 s succeeded on a local account while port49d was up and saw no request. In that window a local account logs in even where port49 would deny its user, so keep local accounts to break-glass only ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cell a).
- With port49d stopped, break-glass logs in in 120 ms; with port49d dark in 5.6 s ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cells b and d). [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) has what to do when break-glass does not work.
- During a store hang the first break-glass login landed at once (500 ms) ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cell c). That cell ran inside the device's dead window and did not exercise an ERROR reply, so it shows nothing about one.
- With the first server resetting at accept, a token login reached the second server only after 36 s of local answers: the named-VRF run took 31 s ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cell f; [L88-cisco_xrd-named-vrf.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd-named-vrf.md), cell f).
- XR sends command authorization: one command port49 permitted ran and one it denied was refused, over TLS ([L88-cisco_xrd-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd-tls.md), cell e; [L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md), cell a).
- The named-VRF form of the group (`vrf <MGMT_VRF>`, with the management interface and the SSH server moved into that VRF) passed cells a, b, d, e and f ([L88-cisco_xrd-named-vrf.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd-named-vrf.md)).
- Over RFC 9887 XR dials 49 with no port, sends no server name, uses an RSA key, and sends its leaf and its intermediate, so no `intermediates_file` is needed. `single-connection` opens its connection when the configuration is committed. It refuses a server certificate naming only a DNS name (no alert, cause unproven), and refuses one naming another address, an expired one and one from a CA it was never given, the last three with `certificate_unknown` ([L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md), cells a, c, d, e, h).
- After a refused handshake and then an ERROR reply, XR did not fall to its local method: the login was refused and break-glass failed (797 ms, the SSH session closed). Keep a console or a second path ([L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md), cell i).
- The reference over TLS, applied unchanged over a lab enrolment: break-glass in 120 ms stopped and 470 ms dark, and a token login through the second server after 26 s, the device's dead window as over plain TCP ([L88-cisco_xrd-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd-tls.md)).

## Traps

- The group's `vrf` line is for a named management VRF only. XR reserves the name `default` and refuses `vrf default` under the group (the whole commit reverts), so a device managing in the default VRF leaves the line out. The file ships both forms and both were measured ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md); [L88-cisco_xrd-named-vrf.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd-named-vrf.md)).
- Keep `aaa authorization commands default group port49 local` in the configuration: with it XRd sent a permitted command authorization to port49 ([L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md), cell a).
- Every TLS option after the port ends its line, so give each option as a line of its own for the same host ([L73-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)).
- A refused token login after port49d returns is XR's dead window, not port49: break-glass logged in while the token login waited ([L88-cisco_xrd.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md), cell f).

## Unmeasured

!!! warning "Unmeasured: a domain name before enrolment"
    XR is reported to enrol nothing until a `domain name` is configured: `crypto ca enroll` failed with "Domain name is not configured" during development, so the reference enrolment sets one under your own domain. A committed lab run did not measure it, and the device's own debug was not captured ([the XRd qualification note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/QUAL-XRd-control-plane-26.1.1-cisco_xrd.md)). Treat it as an expected step, not a measured limit.

!!! warning "Unmeasured: the group member and the host in separate commits"
    XR is reported to refuse a commit that removes a group member and re-adds its host with a moved port ("Cannot delete this server as it is still referenced in one of the server groups"), so the lab removed the member in its own commit first. This was seen during development and not measured by a committed run ([the XRd TLS note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)). When you move a host's port, expect to do the same.

!!! warning "Unmeasured: an ERROR over plain TCP"
    Whether XR falls to its local method when port49 answers ERROR over TACACS+ on port 49 is unknown (L93, open). The qualification run saw break-glass refused after the ERROR ([the qualification note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/QUAL-XRd-control-plane-26.1.1-cisco_xrd.md)), and no register row measured it. Plan as if it is refused.

!!! warning "Unmeasured: commands in sessions already open"
    What XR does with a session that is already open when port49 stops or goes dark is unknown: the lab did not run it.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/cisco-ios-xr.md"
