# quarantine-sync — cisco_iosxe

- **Date measured:** 2026-09-30
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/quarantine-sync-cisco_iosxe.pcap` — 1440 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §14: a sync introducing a device whose platform fails joint validation publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the device is closed without a reply and logged device_quarantined, the device falls to its local method, and the next sync after the named fix admits it.

## Observation

port49d, port49 and port49-inventory built from `adc5746` (`make build`).

Single-connection: not configured by this test; the device keeps whatever an earlier test in this deploy set (TestL29Reload turns it on where the image offers it).

Sync introducing the device, and changing dummy-xe's `site` beside it:

```
published bundle 2 (sha256:d2588a57145e253aa4c0a050f19ab9d8ee1b9eaec1fde40d4cf182540ae30337): bundle sha256:9cebf95a4658356a50af8fbbc0ca0c23ca2de7f6873a9be5b3458f48178c6323 → sha256:d2588a57145e253aa4c0a050f19ab9d8ee1b9eaec1fde40d4cf182540ae30337: +1 device(s), -0, 1 changed; 1 quarantined
  attributes_changed dummy-xe: {site: dc1} → {site: dc2}
  device added xe1 (cisco_iosxe): quarantined
  scope all_devices: xe1 joined
  scope lab_devices: xe1 joined
  device xe1 (cisco_iosxe) is quarantined against the service's policy: subject "quarantine_probe": role "eos_class_only" names @loopback, which cisco_iosxe does not define
```

port49d reloaded bundle 2 by 20:46:01.712Z and named xe1 quarantined by 20:46:01.712Z (host UTC).

The device earned no unadmitted-source strike before its introduction; nothing was waited out.

Quarantine probe: probe attempt 1's connection was closed as `device_quarantined` (4s).

After the fix (`quarantine-sync/fixed.yaml` written at 20:46:40.194Z to port49d's policy_file and the service's):

```
published bundle 3 (sha256:e90d4174e3f2be8949fbd9a34ff69ee2adaa0c571a27910d2a3e02b78051a001): bundle sha256:e90d4174e3f2be8949fbd9a34ff69ee2adaa0c571a27910d2a3e02b78051a001 → sha256:e90d4174e3f2be8949fbd9a34ff69ee2adaa0c571a27910d2a3e02b78051a001: +0 device(s), -0, 0 changed; 0 quarantined
```

port49d said `policy reloaded` by 20:46:41.718Z. port49d took the fix from its own policy_file (spec §13, decision 29): the service's bundle 3 carries the same devices, so it changes nothing at port49d, and the sync's part in the fix is the service's own report of 0 quarantined. port49d said the service's policy and the policy in force agree again by 20:46:41.718Z: the policy-mismatch alarm cleared with bundle 3.

| step | while quarantined | after the fix |
|---|---|---|
| `port49 token xe1` over a held `port49 login` | `port49 token: xe1: deny device_quarantined (exit: exit status 1)` | a token (not printed) |
| `slice01` logs in with the minted token | not tried: nothing minted | logged in in 10ms |

While quarantined:

| step | outcome |
|---|---|
| next token login (`alice12`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s |
| break-glass login plus three `show version` | logged in and ran them in 20.31s |

Records: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=acct` ×6; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=authen` ×3; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=author` ×99

After the fix: probe attempt 1 reached port49 (6s).

| step | outcome |
|---|---|
| next token login (`alice13`) | logged in in 10ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.52s |

Records: `event=blob` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_not_found` ×2; `event=redeem reason=token_redeemed` ×2

Capture: `tests/lab/evidence/quarantine-sync-cisco_iosxe.pcap` — 1440 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

