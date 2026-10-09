# L53 — juniper_vjunos-router

- **Date measured:** 2026-10-09
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vjunos-router.pcap` — 2025 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=vjunos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan read a `ssh-rsa` key, SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`file show /etc/ssh/ssh_host_ed25519_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ed25519_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLRhgIe6UG+rzdWxFm6dcQpiQpqKNSVUPuBA+kqK9UN root@

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_ecdsa_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEiDZX5Kli9u/lanRgYMTZ459v5JHvAFj+9OmldXE4Qzo0th190598GBHfELc3zARJhH9sOyy4TjRA7+AIQF79A= root@

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_rsa_key.pub`: base64 key.

```
file show /etc/ssh/ssh_host_rsa_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3nLeVczFB9EGrQxKfWEyG933vaI5P2jPwSo+BUFGKQz68bklBTgnae+9Sxei6Cewyt9xalNC1o0fICXyjIl5Wz7bTbPRV8Gw2TRiUF4EtPPhAHUA06UZp5gCTeWZirbRWldWPVYFL/hwXYgyjpLfq2S9UGNI3GpIOFfr3QlfDdnjdhhrwWLgWeDIDuV/fpAuPL5aYi8LB5VIgn6132CgjyNTJCmnH75sOvfoVywM8VJNKOE5ZnBFAZeX47kripcAOQLehc8NZidhutu2Ej4N5tF4BJH4512Ft9nQhR9e7ftEgQz07czHC79E9E+0o+JheISQoZf1RP1kHFngMnODx root@

breakglass@srx1> 
```

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 17:56:28 UTC (00:01:33 ago)\r"].

`show log messages`: 0 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```

```

The reload command was sent at 17:58:25; the device was seen down (no SSH banner on two connections in a row) at 17:58:29, and serving SSH authentication again 1m28s later.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 17:58:56 UTC (00:01:00 ago)\r"].

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4).
