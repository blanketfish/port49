# L54 — juniper_vsrx

- **Date measured:** 2026-10-09
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vsrx.pcap` — 672 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=vsrx`, `-run TestL53L54PortSSH`

## Claim

port49 ssh against the device: the method, the askpass, the command, and a wrong pin (policy engine spec §15, L54).

## Observation

`port49 ssh vsrx1 -- show version` exited 0; methods ssh tried: [keyboard-interactive]; askpass asked 1 times; `show version` output present.

Redeem records for the login: 1.

The good login's own window, from its start to 10s after it ended: 270 TACACS+ packets to or from the device in the capture. The counter counts: the wrong-pin zero below is a zero of the same count.

Against a wrong pin: 0 TACACS+ packets to or from the device in the capture; records other than mint and blob: []. port49 ssh said:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:miuRj2m7MwyCKEhn7Vy1lX5tyBVGquu45eS/imL51m0.
Please contact your system administrator.
Add correct host key in /tmp/TestL53L54PortSSHjuniper_vsrx2419604372/001/port49/known_hosts to get rid of this message.
Offending ED25519 key in /tmp/TestL53L54PortSSHjuniper_vsrx2419604372/001/port49/known_hosts:1
  remove with:
  ssh-keygen -f '/tmp/TestL53L54PortSSHjuniper_vsrx2419604372/001/port49/known_hosts' -R 'vsrx1'
Host key for vsrx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before vsrx1 asked for the token, so it was never sent (ssh exit 255, its message is above); if ssh's message above says Host key verification failed, the address inventory gives for vsrx1 may not be the device: verify the key on its console, then run 'port49 devices trust --replace vsrx1'
```
