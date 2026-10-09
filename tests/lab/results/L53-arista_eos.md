# L53 — arista_eos

- **Date measured:** 2026-10-09
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-arista_eos.pcap` — 498 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=eos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan read a `ssh-rsa` key, SHA256:Ag1Oarr/0IHLSA7IVeVQ5JfkWLc97D5ljnutqNOZxvQ.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show management ssh hostkey ed25519 public`: not this key.

```
show management ssh hostkey ed25519 public
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICHKu3HhPLvWhJLjp0X8iKVPJqAXtW4mVhWnyN0IU9x0 chassisAddr=0c:00:5c:14:c2:ac
leaf1#
```

`show management ssh hostkey ecdsa-nistp256 public`: not this key.

```
show management ssh hostkey ecdsa-nistp256 public
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu9gOL+cbd6T4iIClCfHUXIRNRTSrML1T8EwAie3HjH7t14zCFz4q4rp3ENk4mqCuTJmrxmp9zx4G/hM8d6cQ= chassisAddr=0c:00:5c:14:c2:ac
leaf1#
```

`show management ssh hostkey rsa public`: base64 key.

```
show management ssh hostkey rsa public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrot+TCOIZmx/iHknlexKYsWBsJOY8vVUsb6HT2f07Ak8pJnv7iroia3BvDFEgXYrMbwSXumFXe7pU1ma7oUMntUdBwYuYoYzbVNDPwe1KJbbpP8jQeqyDxaa96vgFlr3KkYUocMKSUDyw1W26XwUMht3a9F5tZihykvgNb0y4FruQOVC7UiHESQjlCs8XiZKpznQ3h6ogDK0hBiKv1z0Oz5rb+8NPJKwJtC4z8jNT/Pd5ZKvnI3yF0pPFW1X7liAR1dbml6c3eAMNIenFt4KYCO6U3HgcaXiqCHTjMEHOlfkiyfTDpMMcJjwQJraNo9GDyfwCu7m09wv/1ZMJrWzB chassisAddr=0c:00:5c:14:c2:ac keySize=2048
leaf1#
```

Before the reload, `show version` says: ["Uptime: 1 minute\r"].

`show logging`: 19 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```
Oct  9 17:42:56 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
Oct  9 17:43:08 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-AUTHN_FALLBACK: Authentication method 'group port49' is currently unavailable; falling back to next method for service 'sshd' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:17 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
Oct  9 17:43:18 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
```

The reload command was sent at 17:43:41; the device was seen down (no SSH banner on two connections in a row) at 17:43:45, and serving SSH authentication again 59s later.

After the reload, `show version` says: ["Uptime: 0 minutes\r"].

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:Ag1Oarr/0IHLSA7IVeVQ5JfkWLc97D5ljnutqNOZxvQ).
