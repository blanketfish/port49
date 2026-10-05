# L39-docker-proxy-on — arista_eos

- **Date measured:** 2026-10-05
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L39-docker-proxy-on-arista_eos.pcap` — 243 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L39-docker-proxy-on-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the compose deployment (plan 7f; deploy/compose), with port49d's TACACS+ port published on the clab bridge's address (172.100.100.1:49), port49d sees the device's own address as the TCP source, so the device-binding check passes for the known device: the redeem record's device.nas is the device's management address, not the compose network's gateway (172.30.49.1, listed as l39_gateway so a rewritten source is recorded rather than refused). Measured with Docker's userland proxy as the run found it (policy engine spec §15 L39 (a); design §13).

## Observation

| cell | observed |
|---|---|
| Docker's userland proxy | on (a docker-proxy process serves 172.100.100.1:49) |
| Docker engine | 29.1.3 |
| the redeem record's device | nas "172.100.100.11", name "leaf1" (the device's address: 172.100.100.11) |
| the login | err <nil>; redeem "token_redeemed" |

In both modes the kernel's DNAT carried the device's connection: the capture shows the SYN forwarded to the container 14 microseconds after it arrived, with the same sequence number and source port. docker-proxy, running with the proxy on, carried none. A connection docker-proxy relays (Docker's iptables management off) is unmeasured. This run was made at commit 438f364 with an `iptables -t nat -I POSTROUTING 1 -s 172.100.100.0/24 -d 172.30.49.0/24 -j RETURN` in place (the clab network's own masquerade kept off the device's traffic, which models a device off the Docker host).

## Earlier run (5ee1137) — INVALID

The first run, 2026-10-05 at commit 5ee1137, with the userland proxy on, saw nas `172.30.49.1` (`l39_gateway`) and refused the login `device_mismatch`. It is not a measurement of the published port: its precondition, device traffic routed as an off-host device's is, did not hold. The clab management network `port49-lab` (172.100.100.0/24) is itself a Docker bridge network, so Docker installs `-t nat -A POSTROUTING -s 172.100.100.0/24 ! -o br-<clab> -j MASQUERADE`. The device's packet, DNAT'd to the compose bridge, left by another interface, matched that rule and was masqueraded to the compose gateway 172.30.49.1 with its source port kept (the first run's capture showed exactly that). A device off the host has a source that is no Docker network's, and never matches the rule. The run above, at the fix commit 438f364, inserts `iptables -t nat -I POSTROUTING 1 -s 172.100.100.0/24 -d 172.30.49.0/24 -j RETURN` for the run (`startCompose`; recorded in compose.log with the rules in force) and removes it after.

