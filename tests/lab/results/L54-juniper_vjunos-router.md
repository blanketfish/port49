# L54 — juniper_vjunos-router

- **Date measured:** 2026-10-09
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vjunos-router.pcap` — 2025 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=vjunos`, `-run TestL53L54PortSSH`

## Claim

port49 ssh against the device: the method, the askpass, the command, and a wrong pin (policy engine spec §15, L54).

## Observation

`port49 ssh srx1 -- show version` exited 0; methods ssh tried: [keyboard-interactive]; askpass asked 1 times; `show version` output present.

Redeem records for the login: 1.

Against a wrong pin: 0 TACACS+ packets to or from the device in the capture; records other than mint and blob: []. port49 ssh said:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:oTX03x0nCqeEVfqfcylh7EXonXbva8jCsEL0sfYsb9E.
Please contact your system administrator.
Add correct host key in /tmp/TestL53L54PortSSHjuniper_vjunos-router406041843/001/port49/known_hosts to get rid of this message.
Offending ED25519 key in /tmp/TestL53L54PortSSHjuniper_vjunos-router406041843/001/port49/known_hosts:1
  remove with:
  ssh-keygen -f '/tmp/TestL53L54PortSSHjuniper_vjunos-router406041843/001/port49/known_hosts' -R 'srx1'
Host key for srx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before srx1 asked for the token, so it was never sent (ssh exit 255, its message is above); if ssh's message above says Host key verification failed, the address inventory gives for srx1 may not be the device: verify the key on its console, then run 'port49 devices trust --replace srx1'
```
