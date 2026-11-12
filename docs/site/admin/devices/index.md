---
title: Devices
description: What every device needs to talk to port49, how to read a device page, and the page for each qualified platform.
---

# Devices

port49 serves unmodified network devices, so what a device does when port49 answers, refuses, errors or goes dark is the device's own behavior, and the lab is where it was measured. One page per platform says what the lab measured, what bites, and what nobody measured. The reference configurations here are the starting point for every one of them.

| Platform | Page |
|---|---|
| Arista EOS | [Arista EOS](arista-eos.md) |
| Cisco IOS XE (and IOL-XE) | [Cisco IOS XE](cisco-ios-xe.md) |
| Cisco IOS XR | [Cisco IOS XR](cisco-ios-xr.md) |
| Cisco NX-OS | [Cisco NX-OS](cisco-nx-os.md) |
| Juniper Junos | [Juniper Junos](juniper-junos.md) |
| Nokia SR Linux | [Nokia SR Linux](nokia-sr-linux.md) |
| Anything else | [Other platforms](other-platforms.md) |

## How to read a device page

Every device page has the same sections, in this order:

1. **The lead** is the one thing that bites on that platform, with the lab note that measured it linked.
2. **Reference configuration** links the files under `deploy/device-aaa/` for the platform and quotes the lines that matter. Replace the placeholders (the table below) and load the file.
3. **What the lab measured** lists what a lab run observed, each item linked to the results note that records it, with the image and the date in the note.
4. **Traps** are the things an operator gets wrong, each linked the same way.
5. **Unmeasured** holds everything that is not measured, one yellow box per item. A claim is *measured* when a linked note shows it, and *unmeasured* when it appears only in a yellow "Unmeasured" box. Where a box says a device is "reported" to do something, a person saw it and the lab did not measure it: treat it as an expectation, not a limit.
6. **Lab evidence** is the table of every results note for the platform, with its image and date, generated from the notes. Each row names the lab register entry the note belongs to and its status: *(closed)* means the register row is measured and closed, and *(open)* means that row is still open, so the note is evidence for part of it and a claim that rests on the row alone is unmeasured.

A result written for one image is not a result for a release or a hardware family the page does not name. A platform that is not here was not tested.

## Qualified platforms

--8<-- "docs/qualified-platforms.md:3"

## What the status column means

- **qualified**: every cell that applies to the row read yes in the lab's golden run. A dash is a cell that does not apply, such as TLS on a device with no RFC 9887 client, and a dash that names a register entry says why (for example, the device sends no per-command authorization). A register entry written "open" is not yet measured on every platform: the dash records what the golden run saw, and the matching device page says what is unknown.
- **partial**: at least one cell that applies read no, or the device's per-request TLS login does not carry command authorization (a bypass never reads as a pass). The command authorization over TLS column says which.
- **re-vet pending**: the row's golden is marked as waiting for a new lab run, so the cells are not current. Read the device page for the last measurement.

A row says only what its golden shows port49 answering. Everything else is on the device's page.

## Single-connection: one device's sessions share a connection

Every TLS reference configuration turns `single-connection` on, and port49 offers it to NX-OS over TLS whether or not the device asks. The device's sessions can then share one connection (NX-OS shares it; EOS and Junos open one per login, below). port49d answers them at once: a login that fails and waits out its failure delay (up to `limits.auth_failure_delay_max`, 2 s by default), or a request waiting on a slow store, holds only its own session. A command authorization from another operator on the same device is answered at once, not behind it. The packets of one session are still answered in order.

At most 16 packets on one connection are in progress at a time. A 17th waits, unread, until one of them is answered, and its reply comes that much later: the connection is not closed. There is no setting for this.

If a device's packet breaks the protocol (a CONTINUE for a session it never started, more than 64 unfinished logins, a `seq_no` of 255), port49d closes the connection at once, with the record and backoff it always has. Replies still owed to the device's other sessions on that connection are not sent, so those sessions time out on the device as they would after any close.

With sessions answered at once, a reply can leave before the reply to a request the device sent earlier, on another session. RFC 8907 lets a device share one connection among sessions and says nothing about the order of replies. What the lab measured ([L94](../../reference/lab-register.md#l94)):

- **NX-OS 10.6(2)F** takes replies out of request order, offered and with `single-connection`. With three failing logins on one connection, a command answered in under 1 s; before, it waited up to 7.3 s and the device marked port49 dead.
- **EOS 4.36.3M and vJunos-router 26.2R1.7** open a new connection for each login even with `single-connection` set, and never have two requests outstanding on one, so a failing login there never held up another session's command on either build. Their out-of-order handling is not exercised.

!!! warning "Unmeasured: replies out of order on other platforms"
    IOS-XE and IOS XR were run and not measured (no request reached port49 in the lab), and vSRX cannot be run in the harness. On those, and on any platform not listed above, whether the device takes replies out of request order is unknown ([L94](../../reference/lab-register.md#l94), open).

## Reference configurations

--8<-- "deploy/device-aaa/README.md:reference"

The files are in [`deploy/device-aaa/`](https://github.com/blanketfish/port49/tree/main/deploy/device-aaa) in the repository.
