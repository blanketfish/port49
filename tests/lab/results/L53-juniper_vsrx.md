# L53 — juniper_vsrx

- **Date measured:** 2026-10-09
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vsrx.pcap` — 765 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=vsrx`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan read a `ssh-rsa` key, SHA256:8J9m+oDu0/xouhsn5pTHvQ8IyKpJjmxrJYg15PwnKHc.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`file show /etc/ssh/ssh_host_ed25519_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ed25519_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASEyNIfOYcIa+IPyKSu6zxXd55QsrO5U8m0niNJ1T1X root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_ecdsa_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ/iyH9prJtJg/n/JEHY5eYZ8/cYHNrAWX1Lwzh7OVfwH0HVYo4mS65JiGC4C463AFyEtPmq6EjqZYe7NBahjdk= root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_rsa_key.pub`: base64 key.

```
file show /etc/ssh/ssh_host_rsa_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjAQQzrJqclK6w/E1QlK9V0R2P8vBrp+oPEsy3DTVqtAzP3SJcEs3MQ7JpagzkTlCb9gR3vblE+jsQvJ5BBJF82lZ9oouImNfp0EIBFrUeaCNQMzmQVYyLtI037lemcDYzi3qmPIkmRARzH6r23XEpDnuQTlkU4mfua4HtFntYAQm9NsPRhGUWda+0AJElPBBn8BApZ7k8deyF30UmzZprQKKBGJ6g2nESmE/3YK6d+kRsFCrARvXit962rFQ9gQdVXbhG8SvuCAs8T0e1/RAYzY41CwRWK3UZBt877oUxUVX+73O+5IVPHlmFL4eG1tGO71C0AIU3Dw4JTDmgPOkd root@srx1

breakglass@srx1> 
```

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 18:00:31 UTC (00:01:27 ago)\r"].

`show log messages`: 0 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```

```

`file list /var/log/`: 1 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```
fpc_poweron_seq.log
```

The reload command was sent at 18:02:21; the device was seen down (no SSH banner on two connections in a row) at 18:02:25, and serving SSH authentication again 1m6s later.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 18:02:52 UTC (00:00:39 ago)\r"].

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:8J9m+oDu0/xouhsn5pTHvQ8IyKpJjmxrJYg15PwnKHc).
