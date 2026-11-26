---
title: Inventory
description: Telling port49 which devices exist, from a file or from an inventory connector, and the bounds that stop a bad source from taking the fleet off the air.
---

# Inventory

port49d names a device from the connection's source address, looked up in the inventory, and never from anything the
device sends. The inventory says which devices exist, what platform each is, which addresses it connects from and what
attributes policy scopes can match. A device that is not in it gets no answer at all (`device_unknown`), so the
inventory is as much an access control as the policy is. The policy is a separate file ([Policy](policy.md)); the keys
a device is admitted under are in the policy's `key_groups:` ([Key rotation](key-rotation.md#device-keys)).

## Who may write the inventory

Write access to the inventory, or to the source of truth behind it, is privilege-granting. Scopes match on device
attributes and names, the mint hands a device's addresses to SSH clients, and a record can pin a key. Whoever can edit
those moves a device into or out of a scope with no policy change.

- On an RFC 8907 device whose key comes from a shared CIDR or attribute key group, port49d names the connection by its
  source address alone. So a shared key plus inventory write access lets anyone who can add or move an address use any
  in-range device's grants from other hardware.
- For crown-jewel devices, use `transport: tls` ([TLS](../operate/tls.md)), or pin the device to its own key with a
  policy key group that matches its name (`match: {name: leaf1}`). A name pin outranks every CIDR and attribute group,
  and no attribute or address edit lifts it. Set it in the policy, not in the inventory record's `key_ref`, which the
  same writers can change.
- Give a connector's token read access to devices and nothing more. A webhook's secret lets its holder trigger a sync
  and nothing else.
- Review `port49 inventory diff` for every change: it shows scope changes and added addresses, and an address that
  moves between devices pages as `port49_inventory_address_moved`.
- port49d refuses `inventory_file`, at start and at every reload, if anyone but its own user or root could have written
  the file or its directory.

## Two ways to supply it

| | `inventory_file` | `inventory.service` |
|---|---|---|
| What it is | one YAML file read by port49d | `port49-inventory`, a service that syncs sources and publishes a signed bundle |
| Sources | the file | files, NetBox, Nautobot, each at its own `interval` |
| Use it for | a lab, a small fleet, CI, `port49 explain` against a device that does not exist | a fleet whose source of truth is a NetBox or a Nautobot |
| A bad source | the previous inventory keeps serving | the service keeps publishing the last good bundle, and port49d keeps the one it holds |

port49d takes exactly one: `inventory_file`, or `inventory.service` with no `inventory_file`. Naming both is refused at
start. Both need a policy: the bundle port49d serves is built from the inventory and the policy together.

## The inventory file

```yaml
devices:
  - {name: leaf1, platform: arista_eos, addresses: [192.0.2.1], attributes: {site: east}}
  - {name: edge1, platform: cisco_iosxe, addresses: [192.0.2.21], attributes: {site: west}}
```

Every key is in the [inventory file reference](../reference/config/inventory.md). An unknown key, a second YAML
document, a device named twice or without a name, or one address given to two devices refuses the whole file.

**List every address a device may connect from.** TACACS+ is often sourced from a loopback or a management interface.
A device that connects from an address the file does not list is `device_unknown`, and nothing in the message points
back at the inventory. Pin the source interface in the device's AAA configuration (`ip tacacs source-interface` or the
platform's equivalent). An address written as IPv4-mapped IPv6 (`::ffff:10.1.1.1`) is read as the IPv4 address, so
listing both forms on two devices is the usual one-address-on-two-devices refusal, and a key group `cidr` in the mapped
form is refused at load.

`attributes:` are the free keys that policy scopes match on, such as `site` and `role`. A scope that matches an
attribute the device lacks is decided by the scope's `on_missing:` ([Policy](policy.md)).

port49d re-reads the file at SIGHUP and on the policy watch ticker (`broker.policy_watch_interval`, or
`policy.watch_interval` with no `broker:` block; 5s by default). A change loads once two reads in a row agree, so an
edit takes effect within two intervals. Write the file to a new name, then rename it. A file that does not load, or is
refused by the removal bound below, leaves the previous inventory serving and sets `port49_inventory_file_refused`.

## The inventory service

`port49-inventory` reads one or more sources, checks the result against the policy and publishes a bundle signed with an
Ed25519 key. port49d polls it (`inventory.service.poll_interval`, 30 seconds by default), verifies every bundle against
`inventory.service.verify_key_files` and applies one only when it is newer than the one in force. The service speaks
mutual TLS. `readers` may fetch the bundle and `syncers` may also start a sync. Their names are exact: `user:<email>` in
lower case, or a certificate's URI SAN such as `spiffe://...`. `*` is not a wildcard. It re-reads its configuration only
at a restart; a SIGHUP starts a sync.

A source is synced at its `interval` (default `10m`, `1m` to `24h`, on the service or on one source), at the service's
start (which refuses to serve with no snapshot at all), when NetBox or Nautobot sends a webhook for a source that names
a `webhook_secret_ref`, and on demand with `port49 inventory sync --service URL --ca FILE --cert FILE --key FILE`.

**Size `interval` to how long a change may wait.** No measured NetBox or Nautobot release sends a refused delivery again
at its defaults ([NetBox](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L33-netbox.md),
[Nautobot](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L33-nautobot.md)). When a webhook is lost,
a newly racked device cannot be admitted for up to one `interval`.

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

Every fault in this file is a refusal at start, before a listener opens. With a placeholder token set, the service says:

```text
port49-inventory: sync[0] (netbox_prod): map must name platform: the path the device's platform is read from
```

Add `platform: platform.slug` to the `map`. The keys are in the [service reference](../reference/config/port49-inventory.md);
the token and the webhook secret are [secret references](../operate/secrets.md), read at start and never printed.

The connector reads the release first and picks a mapping profile: NetBox 3.7 and 4.x, Nautobot 1.6, 2.x and 3.x
(the lab measured [NetBox](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L30-netbox.md) and
[Nautobot](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L30-nautobot.md)). **A release outside
that list refuses every sync** until the source sets `profile:`, and new devices are not admitted meanwhile, so check
the next sync after a NetBox or Nautobot major upgrade. Addresses are the primary IPs plus any interfaces you opt in,
since every address listed admits its source. The service honors `HTTPS_PROXY` and `NO_PROXY` for each source. The
refusal lines, paging, `filter`, `map` and the proxy's start lines are on the keys of the
[service reference](../reference/config/port49-inventory.md).

A platform slug the alias table and your `platform_aliases:` do not know is admitted and served by the generic
adapter. `port49_inventory_generic_platform_devices` holds the count: treat a nonzero count as a mapping to fix.

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

`state_dir` holds the last bundle port49d applied, so a restart needs no service
([the other keys](../reference/config/port49d.md)). List two `verify_key_files` while the service's signing key
rotates ([Key rotation](key-rotation.md#the-inventory-services-signing-key)).

If the service is down, **nothing fails closed**: the fleet keeps authenticating on the bundle in force. The alerts
([Troubleshooting](../operate/troubleshooting/index.md#inventory)) say the service is failing, its bundle is refused or
its snapshot is stale.

## The removal bound: `max_removed_percent`

A partly available source, a mistyped filter or a short NetBox page would otherwise silently deauthorize the fleet. So
every sync, and every inventory reload in port49d, is **refused** when it takes more than `max_removed_percent` of the
devices in force out of service: removed, newly refused admission, or left with no address. The default is **10**, on
the service (`safety.max_removed_percent`, or a source's own `safety:`) and in port49d (`inventory.max_removed_percent`).
`0` refuses every removal and `100` turns the bound off.

A refused change keeps the last good snapshot serving and raises `port49_inventory_sync_refused` on the service, or
`port49_inventory_file_refused` or `port49_inventory_bundle_refused` in port49d. An empty inventory, and one the policy
admits no device of, are refused whatever the bound says.

`port49 inventory diff` runs the same check offline. For a ten-device `old.yaml` and a `new.yaml` without the last two
devices:

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

It exits 1 on a refusal. With `--max-removed-percent 20` the same files end with `ok: port49d would take the new
inventory (inventory.max_removed_percent 20%)` and exit 0.

### A deliberate large removal

Decommissioning more than a tenth of the fleet is a planned change. Raise **both** bounds, in this order:

1. If the devices come from the service, raise `safety.max_removed_percent` (or the source's own) in
   `port49-inventory.yaml` and restart the service.
2. In `port49d.yaml`, raise `inventory.max_removed_percent` and send SIGHUP to port49d. This bound is also the only
   check on what port49d's own policy edit does to admission, so it applies to a policy edit that newly refuses or
   quarantines devices.
3. Make the change, watch it apply, and **lower both back**.

Keep the default at 10, not 100. A service's first sync after its state is lost has no earlier bundle to compare to, so
port49d's bound is then the only thing between a partial NetBox page and most of the fleet leaving admission. Do a
deliberate removal in daytime, with the source's owner reachable.

## Quarantine

Some checks need both the policy and the inventory: a privilege level a platform cannot number, a session reply or role
above the grant's ceiling, and `enable: auto` on a platform whose enable exchange carries no principal. A device racked
tomorrow with a new platform can fail them against a policy that was valid today. Refusing the whole bundle would block
every inventory change fleet-wide, so port49 **quarantines the device**: it is published with
`admission: quarantined` and the reason, and the rest of the fleet moves on.

- port49d's reload line counts them (`inventory reloaded (...): ...; N device(s) quarantined now, M before; ...`), and
  each is logged with its cause at start and at every reload that loads. `port49_devices_quarantined` is the count in
  force. `port49 policy test` ends with `... 0 quarantined, 0 projection refusals`.
- A mint for the device is refused `device_quarantined`, and its connection is **closed without a reply**, as for
  `device_unknown`.

The silence is deliberate: the device falls to its local method, so break-glass works on a quarantined device
([device pages](devices/index.md)). Quarantine means port49 cannot compute a correct policy for the device, not that
the device is suspect. The way out is the change the cause names: a policy edit, an adapter or platform-set change,
or a corrected attribute in the source. Do not weaken a ceiling to make the check pass.

## Verifying a change before it lands

`port49 policy test --policy FILE --inventory FILE` reports quarantines and refusals; the rest is in
[Policy review](policy-review.md). `port49 inventory export --service URL ... --verify-key FILE` writes a verified
copy of the published bundle; without `--from` it accepts an older genuine bundle, so read the header's sequence
first.
