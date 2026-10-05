# L39-docker-proxy-on — arista_eos

- **Date measured:** 2026-10-05
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L39-docker-proxy-on-arista_eos.pcap` — 26 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L39-docker-proxy-on-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the compose deployment (plan 7f; deploy/compose), with port49d's TACACS+ port published on the clab bridge's address (172.100.100.1:49), port49d sees the device's own address as the TCP source, so the device-binding check passes for the known device: the redeem record's device.nas is the device's management address, not the compose network's gateway (172.30.49.1, listed as l39_gateway so a rewritten source is recorded rather than refused). Measured with Docker's userland proxy as the run found it (policy engine spec §15 L39 (a); design §13).

## Observation

| cell | observed |
|---|---|
| Docker's userland proxy | on (a docker-proxy process serves 172.100.100.1:49) |
| the redeem record's device | nas "172.30.49.1", name "l39_gateway" (the device's address: 172.100.100.11) |
| the login | err ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain; redeem "device_mismatch" |

**Not as the claim says:** port49d saw "172.30.49.1", not the device's 172.100.100.11.

