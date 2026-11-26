---
title: Platform sets
description: Pin a platform set in the policy and move the pin to a newer set as a reviewed change.
---

# Platform sets

The shipped adapters say what each platform's reply looks like, which commands it sends and how its privilege is
rendered. They come in numbered platform sets, and your policy pins one with `platform_set:`. A policy that pins none
renders with `1.0.0` on every later binary, so upgrading port49 never changes what a policy renders. `port49 platform list`
and `show` print the newest set unless you pass `--set` or the policy. Only `juniper_junos` differs between the sets.

| Set | What it adds |
|---|---|
| `1.0.0` | The first set. Junos is session-only and no level is rendered. |
| `1.1.0` | Junos renders your command rules into the session reply (`command_projection: junos_regex`): permission bits with their reach, carve-outs and the smallest bits a grant needs. |
| `1.2.0` | `rpc_entry_denies: ["junoscript **", "op **"]` on Junos: where a deny is the only guard beneath a sent bit, the reply adds them, closing the CLI's `xml-mode` and `op url` routes into a native RPC and that session's NETCONF. |
| `1.3.0` | `deny_reach_bits: [view-configuration]` on Junos: a reply may send that bit where the grant permits a carve-out of it, with the rest of its reach denied on the wire. Read only where `rpc_entry_denies` is kept. |

The [Junos page](devices/juniper-junos.md) lists the two images these were measured on and links each note.

!!! warning "Unmeasured"
    Whether the `junoscript` deny also closes REST, the XML API, `outbound-ssh` and `scp` is unknown ([L59](../reference/lab-register.md#l59), open),
    and so is what these replies do on a Junos release or hardware family the lab did not run. Test a policy on
    the device before you rely on it there.

## Move to a newer set

A moved pin changes what the policy renders, so moving it is a reviewed change. Do not edit `platform_set` by hand. Run:

```sh
port49 platform upgrade --policy policy.yaml --inventory inventory.yaml --to 1.3.0
```

It prints what the move changes: each adapter key that differs on a platform your inventory has and how many devices and
subjects it reaches, the `acknowledge:` entry each gated key needs, each key a `platforms:` block keeps its own value
for, and what the move would quarantine or fail closed. For a policy pinned to `1.1.0` with one Junos device:

```text
platform_set 1.1.0 -> 1.3.0
  platforms.juniper_junos.rpc_entry_denies
    null -> ["junoscript **","op **"]
    affects 1 devices, 0 subjects
    gated: add {platform: juniper_junos, field: rpc_entry_denies, sha256: <sha256>, reason: "..."} under acknowledge:
  platforms.juniper_junos.deny_reach_bits
    null -> ["view-configuration"]
    affects 1 devices, 0 subjects
    gated: add {platform: juniper_junos, field: deny_reach_bits, sha256: <sha256>, reason: "..."} under acknowledge:
  port49 policy diff fails on the move until every gated entry above is under acknowledge: (spec §12); it also shows the replies the move changes
```

The `<sha256>` placeholders stand for the 64-character digests the tool prints. The command writes nothing unless you
add `--write`, which rewrites the pin and nothing else. Then commit the policy, run `port49 policy diff`, and add the
[`acknowledge:`](policy-review.md#acknowledge) entries it asks for, each with a reason a reviewer can read. The diff fails
on the move until each gated key is acknowledged.
