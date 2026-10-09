# L53 — cisco_nxos

- **Date measured:** 2026-10-09
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_nxos.pcap` — 804 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=nxos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan read a `ssh-rsa` key, SHA256:0vWobTM5g4Io5o25u1H0xM3ofLH5+IxkO2HSoh4qvG4.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show ssh key`: base64 key.

```
show ssh key
**************************************
rsa Keys generated:Fri Oct  9 18:06:05 2026

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsC0rbsyDOs6TqXw0eZeo/0j6uhtZuminpHVu50nTreSlGOR167OmYUjQOPJ8SdCN8BBljLcvhXrSCjzJ+4wuQcTS51vDNVg18vxYAahA92zg1WL+8EjD7+fPfGPlmyJG1t9Dx4bEQN8GPQ2parfv69dP/p4EcS+NLvnnCQut64kXZ2cCIsm8LZpcCSYYuwh0KKz1TqtuVj8OssyG43rB8NiHhvLIjMkFsBVyOpI4/6mreFUR1eleeJANOOZK6S2B3jj+CQdimFT6b0MxpEUCVRfQNRIJBKpB0j907PUSxA7wLRUM0Xo3SDxW4CPohUoOA2Mtrzn8cfieA8PaRQr5r

bitcount:2048
fingerprint:
SHA256:0vWobTM5g4Io5o25u1H0xM3ofLH5+IxkO2HSoh4qvG4
**************************************
could not retrieve dsa key information
**************************************
could not retrieve ecdsa key information
**************************************
nx1# 
```

Before the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 23 second(s)\r"].

`show logging logfile`: 0 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```

```

With `aaa authentication rejected 2 in 60 ban 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain).

The reload command was sent at 18:10:21; the device was seen down (no SSH banner on two connections in a row) at 18:10:38, and serving SSH authentication again 58s later.

After the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 0 minute(s), 56 second(s)\r"].

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:0vWobTM5g4Io5o25u1H0xM3ofLH5+IxkO2HSoh4qvG4).
