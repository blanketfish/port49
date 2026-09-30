# quarantine-sync — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/quarantine-sync-juniper_vjunos-router.pcap` — 360 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §14: a sync introducing a device whose platform fails joint validation publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the device is closed without a reply and logged device_quarantined, the device falls to its local method, and the next sync after the named fix admits it.

## Observation

port49d, port49 and port49-inventory built from `6fcce47` (`make build`).

Single-connection: not configured by this test; the device keeps whatever an earlier test in this deploy set (TestL29Reload turns it on where the image offers it).

Sync introducing the device, and changing dummy-xe's `site` beside it:

```
published bundle 2 (sha256:21a358bc6553f9f1f3f10f58780282c85a89ba9e662acbea48ec337ddce4ba17): bundle sha256:9cebf95a4658356a50af8fbbc0ca0c23ca2de7f6873a9be5b3458f48178c6323 → sha256:21a358bc6553f9f1f3f10f58780282c85a89ba9e662acbea48ec337ddce4ba17: +1 device(s), -0, 1 changed; 1 quarantined
  attributes_changed dummy-xe: {site: dc1} → {site: dc2}
  device added srx1 (juniper_junos): quarantined
  scope all_devices: srx1 joined
  scope lab_devices: srx1 joined
  device srx1 (juniper_junos) is quarantined against the service's policy: subject "quarantine_probe": role "eos_class_only" names @loopback, which juniper_junos does not define
```

port49d reloaded bundle 2 by 21:48:55.499Z and named srx1 quarantined by 21:48:55.499Z (host UTC).

The device earned no unadmitted-source strike before its introduction; nothing was waited out.

Quarantine probe: probe attempt 1's connection was closed as `device_quarantined` (5s).

After the fix (`quarantine-sync/fixed.yaml` written at 21:49:16.236Z to port49d's policy_file and the service's):

```
published bundle 3 (sha256:58b8a7ae44c5c9188c611ee110ccd98329e3337133944147e579b376ef89ef36): bundle sha256:58b8a7ae44c5c9188c611ee110ccd98329e3337133944147e579b376ef89ef36 → sha256:58b8a7ae44c5c9188c611ee110ccd98329e3337133944147e579b376ef89ef36: +0 device(s), -0, 0 changed; 0 quarantined
```

port49d said `policy reloaded` by 21:49:17.473Z. port49d took the fix from its own policy_file (spec §13, decision 29): the service's bundle 3 carries the same devices, so it changes nothing at port49d, and the sync's part in the fix is the service's own report of 0 quarantined. port49d said the service's policy and the policy in force agree again by 21:49:20.479Z: the policy-mismatch alarm cleared with bundle 3.

| step | while quarantined | after the fix |
|---|---|---|
| `port49 token srx1` over a held `port49 login` | `port49 token: srx1: deny device_quarantined (exit: exit status 1)` | a token (not printed) |
| `slice01` logs in with the minted token | not tried: nothing minted | logged in in 20ms (recorded, not asserted: on Junos it depends on the projection) |

While quarantined:

| step | outcome |
|---|---|
| next token login (`alice12`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.06s |
| break-glass login plus three `show version` | logged in and ran them in 470ms |

Records: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=srx1 type=acct` ×9; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=srx1 type=authen` ×3

After the fix: probe attempt 1 reached port49 (7s).

| step | outcome |
|---|---|
| next token login (`alice13`) | logged in in 20ms |
| break-glass login plus three `show version` | logged in and ran them in 960ms |

Records: `event=account` ×9; `event=authorize_session reason=context_matched` ×2; `event=blob` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×2

Capture: `tests/lab/evidence/quarantine-sync-juniper_vjunos-router.pcap` — 360 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/quarantine-sync-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

