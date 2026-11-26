---
title: Administer
description: The order to set up sign-in, the directory, the inventory and policy, with a link to each page.
---

# Administer

Administering port49 means deciding who can sign in, which devices exist, and who may do what on them. Set these up in
order. Each row links the page that does it.

| Step | Decide | Page |
|---|---|---|
| 1 | How people sign in | [OIDC](sign-in/oidc.md), [client certificates](sign-in/x509.md) or [directory password](sign-in/directory-password.md) |
| 2 | Where groups come from | [The directory](directory.md), if a policy names a `group:` |
| 3 | Which devices exist and their attributes | [Inventory](inventory.md) |
| 4 | Who may do what | [Policy](policy.md), [roles and grants](roles-and-grants.md) |
| 5 | What each platform needs | [Devices](devices/index.md) |
| 6 | Who may run admin commands | [Admin access](admin-access.md), [revoking access](revocation.md) |

Workloads such as Oxidized or a CI job sign in with their own identity: see [Workloads](workloads.md). Rotating a key is
on [Key rotation](key-rotation.md).

## The parts you configure

| Part | Holds | Config |
|---|---|---|
| Broker | The sign-in backends, the directory, the issuing CA | `port49-broker.yaml`, [reference](../reference/config/port49d.md) |
| port49d | The policy and inventory sources, the device keys | `port49d.yaml`, [reference](../reference/config/port49d.md) |
| Policy file | Subjects, scopes, roles, grants, tests | [reference](../reference/config/policy.md) |
| Inventory | The devices and their attributes | [reference](../reference/config/inventory.md) |

## Before you start

- A working install of [port49](../operate/deploy/index.md), with a client that can [sign in](../use/index.md).
- A hardware security key for each admin who will revoke or reset
  ([Admin access](admin-access.md)).
- The policy and the inventory in a repository, so a change is reviewed before it ships.

## First commands

The policy tools run offline against the policy and inventory files, so nothing needs a broker. Check that the
policy loads and passes its tests, then ask why one subject gets what it gets on one device:

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml
port49 explain --policy policy.yaml --inventory inventory.yaml --subject netops --device leaf1
```

`policy test` ends with a count of tests and failures. `explain` prints the subject, the grants that matched, the roles,
the level and the session age.
