# quarantine-sync — cisco_nxos

- **Date measured:** 2026-09-30
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/quarantine-sync-cisco_nxos.pcap` — 502 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §14: a sync introducing a device whose platform fails joint validation publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the device is closed without a reply and logged device_quarantined, the device falls to its local method, and the next sync after the named fix admits it.

## Observation

port49d, port49 and port49-inventory built from `c441c95` (`make build`).

Single-connection: not configured by this test; the device keeps whatever an earlier test in this deploy set (TestL29Reload turns it on where the image offers it).

Sync introducing the device, and changing dummy-xe's `site` beside it:

```
published bundle 2 (sha256:1ff017a69785b712b819df724246403d19cbd42ffc08fd934f9abd6659e49766): bundle sha256:9cebf95a4658356a50af8fbbc0ca0c23ca2de7f6873a9be5b3458f48178c6323 → sha256:1ff017a69785b712b819df724246403d19cbd42ffc08fd934f9abd6659e49766: +1 device(s), -0, 1 changed; 1 quarantined
  attributes_changed dummy-xe: {site: dc1} → {site: dc2}
  device added nx1 (cisco_nxos): quarantined
  scope all_devices: nx1 joined
  scope lab_devices: nx1 joined
  device nx1 (cisco_nxos) is quarantined against the service's policy: subject "quarantine_probe": role "eos_class_only" names @loopback, which cisco_nxos does not define
```

port49d reloaded bundle 2 by 20:58:45.514Z and named nx1 quarantined by 20:58:45.514Z (host UTC).

The device earned no unadmitted-source strike before its introduction; nothing was waited out.

Quarantine probe: probe attempt 1's connection was closed as `device_quarantined` (6s).

After the fix (`quarantine-sync/fixed.yaml` written at 20:59:08.998Z to port49d's policy_file and the service's):

```
published bundle 3 (sha256:10c060d8f52fac13a2f125e59dc14f2a97fc9d2ef46bc44f26060a68a621e3f4): bundle sha256:10c060d8f52fac13a2f125e59dc14f2a97fc9d2ef46bc44f26060a68a621e3f4 → sha256:10c060d8f52fac13a2f125e59dc14f2a97fc9d2ef46bc44f26060a68a621e3f4: +0 device(s), -0, 0 changed; 0 quarantined
```

port49d said `policy reloaded` by 20:59:10.526Z. port49d took the fix from its own policy_file (spec §13, decision 29): the service's bundle 3 carries the same devices, so it changes nothing at port49d, and the sync's part in the fix is the service's own report of 0 quarantined. port49d said the service's policy and the policy in force agree again by 20:59:10.526Z: the policy-mismatch alarm cleared with bundle 3.

| step | while quarantined | after the fix |
|---|---|---|
| `port49 token nx1` over a held `port49 login` | `port49 token: nx1: deny device_quarantined (exit: exit status 1)` | a token (not printed) |
| `slice01` logs in with the minted token | not tried: nothing minted | logged in in 220ms |

While quarantined:

| step | outcome |
|---|---|
| next token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.51s |
| break-glass login plus three `show version` | logged in and ran them in 2.68s |

Records: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=acct` ×8; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=authen` ×3; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=author` ×6

After the fix: probe attempt 1 reached port49 (2s).

| step | outcome |
|---|---|
| next token login (`alice03`) | logged in in 230ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 1.98s |

Records: `event=account` ×3; `event=authorize_session reason=context_matched` ×2; `event=blob` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_not_found` ×2; `event=redeem reason=token_redeemed` ×2

Capture: `tests/lab/evidence/quarantine-sync-cisco_nxos.pcap` — 502 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

