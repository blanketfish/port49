# quarantine-sync — arista_eos

- **Date measured:** 2026-09-30
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/quarantine-sync-arista_eos.pcap` — 330 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §14: a sync introducing a device whose platform fails joint validation publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the device is closed without a reply and logged device_quarantined, the device falls to its local method, and the next sync after the named fix admits it.

## Observation

port49d, port49 and port49-inventory built from `adc5746` (`make build`).

Single-connection: not configured by this test; the device keeps whatever an earlier test in this deploy set (TestL29Reload turns it on where the image offers it).

Sync introducing the device, and changing dummy-xe's `site` beside it:

```
published bundle 2 (sha256:5a1c58fdb26a1c2426fab895cd55bed2c740bdeee01b3d651a816df75cfdb1d9): bundle sha256:9cebf95a4658356a50af8fbbc0ca0c23ca2de7f6873a9be5b3458f48178c6323 → sha256:5a1c58fdb26a1c2426fab895cd55bed2c740bdeee01b3d651a816df75cfdb1d9: +1 device(s), -0, 1 changed; 1 quarantined
  attributes_changed dummy-xe: {site: dc1} → {site: dc2}
  device added leaf1 (arista_eos): quarantined
  scope all_devices: leaf1 joined
  scope lab_eos: leaf1 joined
  device leaf1 (arista_eos) is quarantined against the service's policy: subject "eos_probe": level unmapped has no rendering on arista_eos and no parent that has one (spec §6)
```

port49d reloaded bundle 2 by 20:36:13.581Z and named leaf1 quarantined by 20:36:13.581Z (host UTC).

The device earned no unadmitted-source strike before its introduction; nothing was waited out.

Quarantine probe: probe attempt 1's connection was closed as `device_quarantined` (2s).

After the fix (`quarantine-sync/fixed.yaml` written at 20:36:27.549Z to port49d's policy_file and the service's):

```
published bundle 3 (sha256:5c05f94b8d7d190782db85accb3105311fb6bd535ffd32a85e572979c167669c): bundle sha256:5c05f94b8d7d190782db85accb3105311fb6bd535ffd32a85e572979c167669c → sha256:5c05f94b8d7d190782db85accb3105311fb6bd535ffd32a85e572979c167669c: +0 device(s), -0, 0 changed; 0 quarantined
```

port49d said `policy reloaded` by 20:36:28.572Z. port49d took the fix from its own policy_file (spec §13, decision 29): the service's bundle 3 carries the same devices, so it changes nothing at port49d, and the sync's part in the fix is the service's own report of 0 quarantined. port49d said the service's policy and the policy in force agree again by 20:36:28.572Z: the policy-mismatch alarm cleared with bundle 3.

| step | while quarantined | after the fix |
|---|---|---|
| `port49 token leaf1` over a held `port49 login` | `port49 token: leaf1: deny device_quarantined (exit: exit status 1)` | a token (not printed) |
| `slice01` logs in with the minted token | not tried: nothing minted | logged in in 180ms |

While quarantined:

| step | outcome |
|---|---|
| next token login (`alice12`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 1.39s |
| break-glass login plus three `show version` | logged in and ran them in 320ms |

Records: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=acct` ×10; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=authen` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=author` ×6

After the fix: probe attempt 1 reached port49 (1s).

| step | outcome |
|---|---|
| next token login (`alice13`) | logged in in 190ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 530ms |

Records: `event=account` ×4; `event=blob` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×2

Capture: `tests/lab/evidence/quarantine-sync-arista_eos.pcap` — 330 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

