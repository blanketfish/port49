# L54 — cisco_iosxe

- **Date measured:** 2026-10-09
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_iosxe.pcap` — 998 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=iosxe`, `-run TestL53L54PortSSH`

## Claim

port49 ssh against the device: the method, the askpass, the command, and a wrong pin (policy engine spec §15, L54).

## Observation

`port49 ssh xe1 -- show version` exited 0; methods ssh tried: [keyboard-interactive]; askpass asked 1 times; `show version` output present.

Redeem records for the login: 1.

Against a wrong pin: 0 TACACS+ packets to or from the device in the capture; records other than mint and blob: []. port49 ssh said:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
SHA256:fSKEhew9YpJnJjhYP3tXXcfe9VOplfXVGiJX4JE1BRY.
Please contact your system administrator.
Add correct host key in /tmp/TestL53L54PortSSHcisco_iosxe1555335386/001/port49/known_hosts to get rid of this message.
Offending ED25519 key in /tmp/TestL53L54PortSSHcisco_iosxe1555335386/001/port49/known_hosts:1
  remove with:
  ssh-keygen -f '/tmp/TestL53L54PortSSHcisco_iosxe1555335386/001/port49/known_hosts' -R 'xe1'
Host key for xe1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before xe1 asked for the token, so it was never sent (ssh exit 255, its message is above); if ssh's message above says Host key verification failed, the address inventory gives for xe1 may not be the device: verify the key on its console, then run 'port49 devices trust --replace xe1'
```
