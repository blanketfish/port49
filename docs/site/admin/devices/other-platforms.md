---
title: Other platforms
description: What to expect from a TACACS+ client port49 has not been qualified against, and how the generic adapter serves it.
---

# Other platforms

A device whose platform port49 has no adapter for is still admitted: it is in your inventory, so its source address is known. port49 serves it with the platform set's **generic adapter**, which sends `priv-lvl` only and supports the session service only. The lab measured nothing on such a device, so what follows is what port49 does, not what the device does.

## What the generic adapter does

- It carries one privilege attribute, `priv-lvl`, and asks for no per-command authorization: a platform with no adapter is held to `supports: [session]`, with a service list of `[shell]`, so a missing dialect never takes a login down (spec section 8, "Unknown platforms").
- It does not know the device's dialect: whether commands end in `<cr>`, whether a denial's message is displayed, which attributes the device treats as privilege. Those defaults come from the generic adapter and are unmeasured for your device.
- It raises an alarm that does not go away until you fix the inventory.

## What you see

| Where | What |
|---|---|
| The decision log | One `generic_platform` record per such device per bundle, at start and at each bundle swap, with the reason `platform_unknown`. It carries no verdict ([decision log](../../reference/decision-log.md)). |
| The start and reload lines | Each names the platforms and their counts. |
| A metric | `port49_devices_generic_platform` (devices the bundle in force serves with the generic adapter), and `port49_inventory_generic_platform_devices` from the inventory service ([metrics](../../reference/metrics.md)). |
| An alert | [`port49_devices_generic_platform`](../../reference/alerts.md#port49_devices_generic_platform), severity ticket, after 5 minutes. |

Treat a nonzero count as a mapping to fix, not a state to live in: [Inventory](../inventory.md) says how a platform slug is translated, and `platform_aliases:` maps the slugs your source reports onto the ones port49 knows.

## What to do

1. Check whether the device is one of the [qualified platforms](index.md#qualified-platforms) under another name. If it is, map its slug in the inventory and the count falls to zero.
2. If it is not, define its adapter in your policy file's `platforms:` block, as [Nokia SR Linux](nokia-sr-linux.md) and [Cisco IOS XR](cisco-ios-xr.md) do for `priv-lvl` ([Policy](../policy.md#platform-sets) says how platform sets and blocks work).
3. Test a login and a denied command on the device before you rely on the policy, and read the device's own AAA debug if a login is refused.
4. If you can measure the device, [qualification](../../contributing/qualification.md) says how to add it to the list.

!!! warning "Unmeasured: an unqualified device"
    What port49 does for a device that is not on the qualified list is unknown until someone runs it. In particular, whether its TACACS+ client honors single-connect, falls to its local method when port49 answers ERROR, or sends command authorization at all is not something the generic adapter can tell you. Keep a console path.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/other-platforms.md"
