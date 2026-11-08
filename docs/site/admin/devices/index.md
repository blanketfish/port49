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
6. **Lab evidence** is the table of every results note for the platform, with its image and date, generated from the notes.

A result written for one image is not a result for a release or a hardware family the page does not name. A platform that is not here was not tested.

## Qualified platforms

--8<-- "docs/qualified-platforms.md:3:26"

### What the status column means

- **qualified**: every cell that applies to the row read yes in the lab's golden run. A dash is a cell that does not apply, such as TLS on a device with no RFC 9887 client, and a dash that names a register entry says why (for example, the device sends no per-command authorization). A register entry written "open" is not yet measured on every platform: the dash records what the golden run saw, and the matching device page says what is unknown.
- **partial**: at least one cell that applies read no, or the device's per-request TLS login does not carry command authorization (a bypass never reads as a pass). The command authorization over TLS column says which.
- **re-vet pending**: the row's golden is marked as waiting for a new lab run, so the cells are not current. Read the device page for the last measurement.

A row says only what its golden shows port49 answering. Everything else is on the device's page.

## Reference configurations

--8<-- "deploy/device-aaa/README.md:3:32"

The files are in [`deploy/device-aaa/`](https://github.com/blanketfish/port49/tree/main/deploy/device-aaa) in the repository.
