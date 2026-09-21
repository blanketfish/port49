# L2 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L2-cisco_iosxe.pcap` — 572 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L2-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Command `show clock` was denied by the lab authorizer with a 61-character `server_msg`:

```
port49: denied by lab_deny (show clock); see 'port49 explain'
```

**The operator saw it: displayed.**

This took **4 login attempts**: the earlier one(s) returned an empty transcript even though the decision log showed the command reaching port49 and being denied. An empty transcript cannot be told from a device that printed nothing, which is the very thing this test reports, so the attempt is retried rather than recorded.

Read over the **interactive SSH CLI**. What the device printed for the denied command (login as `alice09`):

```
port49: denied by lab_deny (show clock); see 'port49 explain'
```

### Truncation length

Not measured, and the reason is itself an observation. The operator typed a 171-character line, but the device did not send that line for authorization, so port49 never built a long `server_msg` to truncate. What the device actually asked port49 to authorize:

```
"show clock"
```

The device printed:

```

```

