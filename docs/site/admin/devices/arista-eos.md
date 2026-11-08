---
title: Arista EOS
description: Configuring Arista EOS to authenticate and authorize logins through port49, and what the lab measured on vEOS and cEOS.
platforms:
  - arista_eos
  - arista_ceos
---

# Arista EOS

EOS sends its leaf certificate alone over RFC 9887, so set `intermediates_file` under `tls_listener` in `port49d.yaml` to give port49 the intermediate it needs to verify that leaf. EOS also dials 300, the RFC's port, when none is set, and refuses a server certificate that does not name the address it was configured with ([L73-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md), cells a, d and e). Measured on vEOS-lab 4.31.2F (TCP) and cEOS-lab 4.36.3M (TCP and RFC 9887).

## Reference configuration

Load [`arista_eos.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/arista_eos.cfg) (TACACS+ on port 49) or [`arista_eos-tls.cfg`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/arista_eos-tls.cfg) (RFC 9887, EOS 4.36.1F or later). The [placeholders table](index.md#placeholders) says what each placeholder is. Create the break-glass account by hand. The lines that matter, quoted from the files:

```text
ip tacacs vrf <MGMT_VRF> source-interface <SOURCE_INTERFACE>
tacacs-server host <PORT49_1> vrf <MGMT_VRF> key 0 <KEY>
aaa group server tacacs+ port49
   server <PORT49_1> vrf <MGMT_VRF>
   server <PORT49_2> vrf <MGMT_VRF>
aaa authentication login default group port49 local
aaa authorization exec default group port49 local
aaa authorization commands all default group port49 local
```

Over TLS the host lines carry the profile and the port:

```text
tacacs-server tls ssl-profile port49-tacacs
tacacs-server host <PORT49_1> tls vrf <MGMT_VRF> single-connection port <TLS_PORT>
```

## What the lab measured

- A deny port49 answers is never tried locally ([L4-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-arista_eos.md)).
- An ERROR does not make break-glass a way around port49: the login falls to the local account, then the exec authorization goes to port49, gets FAIL `store_unavailable`, and does not go on to local, so the person is thrown out ([L4-error-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-arista_eos.md)). [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) says what to do.
- With port49d stopped, break-glass logs in in 60 ms on vEOS and 2.4 s on cEOS; with port49d dark, in 150 ms and 2.5 s ([L88-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_eos.md); [L88-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_ceos.md), cells b and d).
- While port49 is dark, commands in sessions that were already open ran under local authorization, so a command port49 would deny is then decided locally ([L41-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L41-arista_eos.md), cell 3).
- With the first server resetting at accept, a token login reached the second in 300 ms on vEOS and 2.1 s on cEOS ([L88-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_eos.md); [L88-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_ceos.md), cell f).
- Over RFC 9887 on cEOS 4.36.3M: break-glass in 2.3 s with port49d stopped and 2.4 s dark, and a token login through the second server in 2.9 s ([L88-arista_ceos-tls.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_ceos-tls.md)).
- Over RFC 9887 EOS sends no server name and offers a session ticket, which port49 accepted 11 of 11 times ([L73-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md), cells c and g).
- Break-glass with single-connection on, after port49d reset a de-admitted device's connection, was closed with the fix: on every declined path it logged in within 0.5 s of the key miss ([L31-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L31-arista_eos.md)).

## Traps

- Set `intermediates_file` for EOS: it sends its leaf alone, and without the intermediate the chain does not verify ([L73-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md), cell e).
- Set the TLS port explicitly. With none set EOS dials 300, so the `port` you set must match port49d's RFC 9887 listener ([L73-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md), cell a).
- Configure the host by the address its certificate names: EOS refuses a server certificate that does not name the configured address, with a `bad_certificate` alert ([L73-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md), cell d).
- The EOS reference adds `ip tacacs vrf <MGMT_VRF> source-interface <SOURCE_INTERFACE>`; the lab's own startup config pinned none, and the clause loaded as shipped, in the default VRF, on vEOS and cEOS ([L88-arista_ceos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-arista_ceos.md)).
- Keep a path that does not need port49 for an ERROR: the local account is thrown out by the exec authorization ([L4-error-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-arista_eos.md)).

## Unmeasured

!!! warning "Unmeasured: other EOS releases and hardware"
    The lab ran vEOS-lab 4.31.2F over TCP and cEOS-lab 4.36.3M over TCP and RFC 9887. What other releases and hardware do is unknown.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/arista-eos.md"
