---
title: Inventory
description: Telling port49 which devices exist, from a file or from an inventory connector, and the bounds that stop a bad source from taking the fleet off the air.
---

# Inventory

port49 admits a TACACS+ connection by its **source address**. The inventory says which devices exist, what
platform each is, which addresses it connects from and what attributes policy scopes can match. A device that is
not in it gets no answer at all (`device_unknown`), so the inventory is as much an access control as the policy
is. This page covers the two ways to supply it, what the service's connectors do, and the three mechanisms that
protect you from a bad source: the removal bound, quarantine, and the refusal to serve an empty list.

The policy is a separate file ([Policy](policy.md)); the keys a device is admitted under are in the policy's
`key_groups:` ([Key rotation](key-rotation.md#device-keys)).

## Two ways to supply it

| | `inventory_file` | `inventory.service` |
|---|---|---|
| What it is | one YAML file read by port49d | `port49-inventory`, a service that syncs sources and publishes a signed bundle |
| Sources | the file | files, NetBox, Nautobot, each at its own `interval` |
| Use it for | a lab, a small fleet, CI, `port49 explain` against a device that does not exist | a fleet whose source of truth is a NetBox or a Nautobot |
| A bad source | the previous inventory keeps serving | the service keeps publishing the last good bundle, and port49d keeps the one it holds |

port49d takes exactly one: `inventory_file`, or `inventory.service` with no `inventory_file`. Naming both is refused
at start. Both need a policy: the bundle port49d serves is built from the inventory and the policy together.

## The inventory file

```yaml
devices:
  - {name: leaf1, platform: arista_eos, addresses: [192.0.2.1], attributes: {site: east}}
  - {name: edge1, platform: cisco_iosxe, addresses: [192.0.2.21], attributes: {site: west}}
```

Every key is in the [inventory file reference](../reference/config/inventory.md). An unknown key, a second YAML
document, a device named twice, a device with no name, or one address given to two devices refuses the whole file.

**List every address a device may connect from.** TACACS+ is often sourced from a loopback or a management
interface, not the primary address. A device that connects from an address the file does not list is
`device_unknown`, and nothing in the message points back at the inventory. Pin the source interface in the device's
AAA configuration (`ip tacacs source-interface` or the platform's equivalent) so the address cannot change under
you.

`attributes:` are the free keys that policy scopes match on, such as `site` and `role`. A scope that matches on an
attribute the device does not have is decided by the scope's `on_missing:` ([Policy](policy.md)), which is why a
connector's `map` is worth checking before the first sync.

port49d watches the file on the policy watch ticker (`broker.policy_watch_interval`, or `policy.watch_interval` on a port49d with no `broker:` block; 5s by default) and re-reads it at
SIGHUP. A change loads once two reads in a row agree, so an edit takes effect within two intervals: write the file
atomically (to a new name, then rename), so a half-written file is never read. A file that does not load, or is
refused by the removal bound below, leaves the previous inventory serving and sets `port49_inventory_file_refused`.
The inventory service is different: it re-reads its own configuration only at a restart, and a SIGHUP to it starts a
sync.

## The inventory service

`port49-inventory` reads one or more sources, checks the result against the policy, and publishes a bundle signed
with an Ed25519 key. port49d polls it (`inventory.service.poll_interval`, 30 seconds by default), verifies every
bundle against `inventory.service.verify_key_files`, and applies one only when it is newer than the one in force.
The service speaks mutual TLS: `readers` may fetch the bundle, `syncers` may also start a sync
(`port49 inventory sync`). Their names are exact: `user:<email>` in lower case, or a certificate's URI SAN such as
`spiffe://...`. `*` is not a wildcard.

A source is synced:

- at its `interval` (default `10m`, `1m` to `24h`, set on the service or on one source);
- at the service's start, which refuses to serve with no snapshot at all;
- when NetBox or Nautobot sends a webhook, if the source names a `webhook_secret_ref`;
- on demand, with `port49 inventory sync --service URL --ca FILE --cert FILE --key FILE` (it waits as long as a
  sync may take, up to `sync_timeout`), or by SIGHUP to the service.

**Size `interval` to how long a change may wait.** The webhook is the fast path, but no measured NetBox or Nautobot
release sends a refused delivery again at its defaults
([NetBox](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L33-netbox.md),
[Nautobot](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L33-nautobot.md)). The scheduled sync is the
backstop: a newly racked device is un-admittable for up to one `interval` when a webhook is lost, and a webhook that
arrives while the service is shutting down triggers nothing (the startup sync covers it).

### A NetBox source

```yaml
listen: ":8443"
tls_cert_file: /etc/port49-inventory/server.pem
tls_key_file: /etc/port49-inventory/server-key.pem
client_ca_file: /etc/port49-inventory/clients-ca.pem
readers: ["spiffe://example.com/port49d"]
syncers: ["user:alice@example.com"]
signing_key_file: /etc/port49-inventory/signing.key
policy_file: /etc/port49-inventory/policy.yaml
state_dir: /var/lib/port49-inventory
interval: 10m
safety: {max_removed_percent: 10}
sync:
  - name: netbox_prod
    type: netbox
    url: https://netbox.example.com
    ca_file: /etc/ssl/certs/ca-certificates.crt
    token_secret_ref: env:PORT49_NETBOX_TOKEN
    filter: {status: [active]}
    map: {site: site.slug, role: role.slug}
```

Started with `PORT49_NETBOX_TOKEN` set to a placeholder, the service says what is wrong with that file before a
listener opens:

```text
port49-inventory: sync[0] (netbox_prod): map must name platform: the path the device's platform is read from
```

Add `platform: platform.slug` to the `map`. With the token variable unset the service says
`port49-inventory: sync[0].token_secret_ref the environment variable it names is not set`, and every fault of this
kind is a refusal at start, never a half-started service. The key list is in the
[service reference](../reference/config/port49-inventory.md); the token and the webhook secret are
[secret references](../operate/secrets.md), read at start and never printed.

What the connector does that a hand-written file would not:

- **It reads the release first** (`/api/status/`) and picks a mapping profile for it. The accepted releases are
  **NetBox 3.7, NetBox 4.x, Nautobot 1.6, and Nautobot 2.x and 3.x**; the lab measured NetBox 3.7 and 4.7 and
  Nautobot 1.6, 2.4 and 3.2, and another minor of an accepted major is read with that profile and noted as
  unmeasured. **A release outside that list refuses every
  sync** until the source sets `profile:`, with
  `<product> <version> is a release no lab run measured (spec §15 L27, L30: <measured list>); set profile to read it with a measured release's fields, at your own risk`.
  The last good bundle keeps serving meanwhile, but new devices are not admitted until you act. After a NetBox
  or Nautobot major upgrade, check that the next sync succeeds. The notes
  ([NetBox](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L30-netbox.md),
  [Nautobot](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L30-nautobot.md))
  record what each release was measured to do.
- **Removals are confirmed.** A device the last read kept and this read lacks is asked for by name before it counts
  as removed (up to 256 of them; past that the whole list is read a second time and both reads must agree). One that
  is still there makes the sync fail, so a list that shifts under paging, a rename or a delete at a page boundary,
  never reads as a removal.
- **GraphQL first, REST as the fallback** (`api: auto`). A GraphQL list is taken only when its length equals REST's
  `count` before and after it and no device appears twice, so a server cap or a page lost to a concurrent delete
  fails the sync instead of looking like devices removed.
- **`filter:`** keeps `status: [active]` unless you say otherwise, and `tags:` or `has_primary_ip:` narrow it. It is
  applied by the service, to what was read.
- **`map:`** names, per attribute, the path in the product's record it comes from. It must name `platform`. An
  attribute a device does not give (a null custom field, or one that is an object or a list) is left unset, never
  invented; `on_missing:` in the policy then decides what that means.
- **Addresses** are the primary IPs (`addresses.primary`, default true), plus the interfaces you name
  (`addresses.interfaces`) or every interface (`all_interfaces`). Interface addresses are opt-in because every
  address listed admits its source, and an address on two devices refuses the sync. A loopback, link-local,
  multicast or unspecified interface address is left out.
- **Platforms** are translated through a built-in alias table (`eos`, `arista-eos`, `veos`, `cisco_xe` and the
  netutils drivers Nautobot reports), plus your `platform_aliases:`. A slug neither knows is kept as the device's
  platform, and the device is **admitted and served by the generic adapter**, which has no platform-specific
  handling. Each publication that changes that set says so, and `port49_inventory_generic_platform_devices` holds
  the count. Treat a nonzero count as a mapping to fix, not as a state to live in.

### Behind an egress proxy

The service honours `HTTPS_PROXY` and `NO_PROXY` for each NetBox and Nautobot source (the plan 6c note that it dials
directly "until plan 12" no longer holds). At start it says, per source, how it will fetch:

```text
port49-inventory: source netbox_prod is fetched directly (no HTTPS_PROXY)
port49-inventory: source netbox_prod is fetched through the proxy <scheme>://<host> (with credentials) (HTTPS_PROXY)
```

The second form is the shape the line takes with a proxy set. It names the proxy's scheme and host and whether it
carries credentials, never the credentials. Two faults are worth knowing: an `HTTPS_PROXY` that does not parse as
a proxy URL (percent-encode `#`, `/`, `?` and `%` in its password) fails every sync of that source until it is fixed,
and a proxy that answers 407 fails the sync with `the egress proxy refused HTTPS_PROXY's credentials; the token was
not sent`. The source's API token is never sent to a proxy that refused. Set the variable on the service's unit or
container; a Compose broker's note says the same for identity providers
([the compose README](https://github.com/blanketfish/port49/blob/main/deploy/compose/README.md)).

### Pointing port49d at the service

```yaml
inventory:
  service:
    url: https://port49-inventory.example.com:8443
    ca_file: /etc/port49/inventory-ca.pem
    tls_cert_file: /etc/port49/port49d.pem
    tls_key_file: /etc/port49/port49d-key.pem
    verify_key_files: [/etc/port49/inventory-signing.pub]
    state_dir: /var/lib/port49/inventory
```

`state_dir` holds the last bundle port49d applied, so a restart starts from it with no service reachable;
`mirror_dir` is an optional second copy the service writes, read at a cold start when `state_dir` has none. List two
`verify_key_files` while the service's signing key rotates ([Key rotation](key-rotation.md#the-inventory-services-signing-key)).
Every path under `inventory.service` is absolute, and `state_dir` and `mirror_dir` may not overlap.

If the service is down, **nothing fails closed**: the fleet keeps authenticating on the bundle in force. The alerts
([Troubleshooting](../operate/troubleshooting/index.md#inventory)) tell you the service is failing, its bundle is
refused or its snapshot is stale.

## The removal bound: `max_removed_percent`

A partly available source of truth, a mistyped filter or a NetBox that returns a short page would otherwise
silently deauthorize the fleet. So every sync, and every inventory reload in port49d, is **refused** when it takes
more than `max_removed_percent` of the devices in force out of service. Out of service means a device that was
removed, one that stays but is newly refused admission, and one that stays but lost every address it had. The
default is **10**, on the service (`safety.max_removed_percent`, or a source's own `safety:`) and in port49d
(`inventory.max_removed_percent`). `0` refuses every removal and `100` turns the bound off.

A refused change keeps the last good snapshot serving and raises an alarm
(`port49_inventory_sync_refused` on the service, `port49_inventory_file_refused` or
`port49_inventory_bundle_refused` in port49d). An empty inventory, and one the policy admits no device of, are
refused whatever the bound says.

`port49 inventory diff` runs the same check offline, so you can see a refusal before you make one. For a ten-device
inventory (`old.yaml`) and the same file with the last two devices removed (`new.yaml`), against the policy in
force:

```sh
port49 inventory diff --policy policy.yaml old.yaml new.yaml
```

```text
bundle sha256:<digest> → sha256:<digest>: +0 device(s), -2, 0 changed
  device removed edge1 (cisco_iosxe)
  device removed edge2 (cisco_iosxe)
  scope all_devices: edge1 left
  scope all_devices: edge2 left
refused: the new inventory removes 2 of 10 devices and refuses 0 more (20%), more than inventory.max_removed_percent (10%); fix the file, or, if the change is meant, raise inventory.max_removed_percent in port49d.yaml and send SIGHUP, which re-reads it with the reload
```

The command exits 1 on a refusal. The `<digest>` placeholders stand for the two bundle hashes, which differ with
every input; everything else is the command's output as it was run. With `--max-removed-percent 20` the same two
files end with `ok: port49d would take the new inventory (inventory.max_removed_percent 20%)` and exit 0.

### A deliberate large removal

Decommissioning more than a tenth of the fleet is a planned change, and you raise **both** bounds, in this order:

1. If the devices come from the service, raise `safety.max_removed_percent` (or the source's own) in
   `port49-inventory.yaml` and restart the service (a SIGHUP to it starts a sync; it does not re-read the file).
2. In `port49d.yaml`, raise `inventory.max_removed_percent` and send SIGHUP to port49d, which re-reads this key
   with the reload. The same bound is the only check on the effect of port49d's own policy file on admission, so
   it applies to a policy edit that newly refuses or quarantines devices as well.
3. Make the change, watch it apply, and **lower both back**.

**Why the default stays at 10, and why 100 is not the answer.** A service's first sync after its state is lost is
bounded by nothing, because there is no earlier bundle to compare to. port49d's bound is then the only thing between
a partial NetBox page and most of the fleet leaving admission, and those devices then get no answer from port49.
Ten percent is large enough that a normal week of racking and decommissioning passes, and small enough that a
source failure does not. Do a deliberate removal in daytime, with the source's owner reachable.

## Quarantine

Some checks are joint over the policy and the inventory: a privilege level a platform cannot number, a session reply
above the grant's ceiling, a role landing above the ceiling, `enable: auto` on a platform whose enable exchange
carries no principal. A device racked tomorrow with a new platform can fail them against a policy that was valid
today. Refusing the whole bundle would block every inventory change fleet-wide, so port49 **quarantines the
device**: it is published with `admission: quarantined` and the reason, and the rest of the fleet moves.

What the operator sees:

- port49d's reload line counts them: `inventory reloaded (...): ...; N device(s) quarantined now, M before; ...`,
  and each quarantined device is logged with its cause at start and at every reload that loads.
- `port49_devices_quarantined` is the count in force now. `port49 policy test` ends with
  `... 0 quarantined, 0 projection refusals`.
- A mint for the device is refused `device_quarantined`, and its connection is **closed without a reply**, as for
  `device_unknown`.

**Silence, not FAIL, on purpose.** The device sees a dead server and falls to its local method, which is the
posture every platform documents for an outage and the one the reference AAA configuration covers. An answer of
FAIL would tell the device that AAA is healthy and refuses everyone. Break-glass therefore works on a quarantined
device. The close was measured on Arista, Cisco IOS XE, Cisco NX-OS and Juniper images
(spec §10; spec §14 for a quarantine through a sync), and how long break-glass takes with `single-connection` on is
per platform, in the [device pages](devices/index.md).

**Quarantine means port49 cannot compute a correct policy for the device, not that the device is suspect.**
The way out is the change the cause names: a policy edit that the next reload applies, an adapter or platform-set
change, or a corrected attribute in the source. The service's next sync reports the device no longer quarantined.
Do not clear one by weakening a ceiling to make the check pass; read the cause first.

## Verifying a change before it lands

- `port49 policy test --policy FILE --inventory FILE` reports quarantines, admission refusals and projection
  refusals for the inventory you give it.
- `port49 inventory diff --policy FILE OLD NEW` shows the devices a change removes or re-admits, and the bound.
- `port49 inventory export --service URL ... --verify-key FILE` writes a verified copy of the bundle the service
  publishes. Without `--from` it accepts an older genuine bundle, and its header names the sequence, so read the
  header before you compare.
- `port49 explain --policy FILE --inventory FILE --subject NAME --device NAME` answers what a subject can do on a
  device, including a device that is only in your candidate inventory.
