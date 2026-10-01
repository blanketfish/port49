# L33-e2e-nautobot — arista_eos

- **Date measured:** 2026-10-01
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L33-e2e-nautobot-arista_eos.pcap` — 366 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L33-e2e-nautobot-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

A change in a source of truth reaches a device's admission through the webhook, the inventory service and port49d (spec §15 L33, the device run): the device in NetBox or Nautobot, synced by the connector, admits a token login; an attribute change, a status change that the default filter removes, and the status restored each publish through the webhook and reload in port49d, and break-glass logs in while the device is removed.

## Observation

port49d, port49 and port49-inventory built from `1c0b8d1` (`make build`).

Source of truth: nautobot-3 (`run.sh nautobot-3 e2e`), beside the 120 devices the run seeded.

Token login, the device synced at start: logged in in 190ms.

| change | to the service's publication | to port49d's reload | token login after | break-glass after |
|---|---|---|---|---|
| os_version 4.99.0F | 3.78 s | 4.49 s | logged in in 30ms | not tried |
| status offline (the default filter removes it) | 3.74 s | 4.92 s | no token: port49 token: leaf1: deny no_grants_matched (exit: exit status 1) | logged in |
| status active again | 3.74 s | 6.98 s | logged in in 30ms | not tried |

Controller's reading: the "no token" cell for status offline is the removal working, not a failure of the
login. With the device out of the bundle, the mint answers `no_grants_matched`, since a subject with no grant
on a device is answered that before anything else (spec §5.7). The device is not in inventory, so the grant's
scope `all_devices` matches nothing. Break-glass logged in while it was removed, and the token login worked
again once the status was restored. The refusal was measured at the mint: no token was presented to the
device while it was removed; a device's behavior on a connection after removal is L29's
(`tests/lab/results/L29-reload-arista_eos.md`, Phase: removed).
