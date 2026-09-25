# L25 — cisco_nxos

- **Date measured:** 2026-09-25
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L25-cisco_nxos.pcap` — 190 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L25-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the N9Kv, whether a network-operator's bare `show interface` prompts for sudo, whether cancelling it writes an accounting record under `admin` with task_id `vsh.bin.<port>`, and whether a person's NX-API request can carry such a task_id (spec §5.8, §15 L25).

## Observation

Reply `["shell:roles*network-operator"]`; the session was alice01; typed: show interface, then q at the --More-- pager.

Measured: a network-operator's bare `show interface` asked for no sudo password on this image, so there was no prompt to cancel, and no accounting record under `admin` followed in 30s

Sent:

```
show interface, then q at the --More-- pager
```

The device replied:

```
show interface
mgmt0 is up
admin state is up,
  Hardware: Ethernet, address: 0c00.ba08.9900 (bia 0c00.ba08.9900)
  Internet Address is 10.0.0.15/24
  MTU 1500 bytes, BW 65535000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  unknown enum:<0>-duplex, unknown enum:<65535>
  Auto-Negotiation is turned on
  Auto-mdix is turned off
  EtherType is 0x0000 
  1 minute input rate 0 bits/sec, 0 packets/sec
  1 minute output rate 0 bits/sec, 0 packets/sec
  Rx
    184 input packets 147 unicast packets 0 multicast packets
    37 broadcast packets 17104 bytes
  Tx
    142 output packets 125 unicast packets 14 multicast packets
    3 broadcast packets 21479 bytes
  Management transceiver: Absent
  Active connector: RJ45
  Configured Media-type: RJ45 
Ethernet1/1 is down (Link not connected)
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000 Ethernet, address: 0c08.9900.0101 (bia 0c08.9900.0101)
  MTU 1500 bytes, BW 10000000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  Port mode is access
  auto-duplex, auto-speed
  Beacon is turned off
  Auto-Negotiation is turned on  FEC mode is Auto
  Input flow-control is off, output flow-control is off
  Auto-mdix is turned off
  Switchport monitor is off 
  EtherType is 0x8100 
  EEE (efficient-ethernet) : n/a
    admin fec state is auto, oper fec state is off
  Last link flapped never
  Last clearing of "show interface" counters never
  0 interface resets
  Load-Interval #1: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  Load-Interval #2: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  RX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 input packets  0 bytes
    0 jumbo packets  0 storm suppression packets
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
    0 Stomped CRC
  TX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 output packets  0 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause

Ethernet1/2 is down (Link not connected)
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000 Ethernet, address: 0c08.9900.0102 (bia 0c08.9900.0102)
  MTU 1500 bytes, BW 10000000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  Port mode is access
  auto-duplex, auto-speed
  Beacon is turned off
  Auto-Negotiation is turned on  FEC mode is Auto
  Input flow-control is off, output flow-control is off
  Auto-mdix is turned off
  Switchport monitor is off 
  EtherType is 0x8100 
  EEE (efficient-ethernet) : n/a
    admin fec state is auto, oper fec state is off
  Last link flapped never
  Last clearing of "show interface" counters never
  0 interface resets
  Load-Interval #1: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  Load-Interval #2: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  RX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 input packets  0 bytes
    0 jumbo packets  0 storm suppression packets
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
    0 Stomped CRC
  TX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 output packets  0 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause

Ethernet1/3 is down (Link not connected)
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000 Ethernet, address: 0c08.9900.0103 (bia 0c08.9900.0103)
  MTU 1500 bytes, BW 10000000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  Port mode is access
  auto-duplex, auto-speed
  Beacon is turned off
  Auto-Negotiation is turned on  FEC mode is Auto
  Input flow-control is off, output flow-control is off
  Auto-mdix is turned off
  Switchport monitor is off 
  EtherType is 0x8100 
  EEE (efficient-ethernet) : n/a
    admin fec state is auto, oper fec state is off
  Last link flapped never
  Last clearing of "show interface" counters never
  0 interface resets
  Load-Interval #1: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  Load-Interval #2: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  RX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 input packets  0 bytes
    0 jumbo packets  0 storm suppression packets
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
    0 Stomped CRC
  TX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 output packets  0 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause

Ethernet1/4 is down (Link not connected)
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000 Ethernet, address: 0c08.9900.0104 (bia 0c08.9900.0104)
  MTU 1500 bytes, BW 10000000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  Port mode is access
  auto-duplex, auto-speed
  Beacon is turned off
  Auto-Negotiation is turned on  FEC mode is Auto
  Input flow-control is off, output flow-control is off
  Auto-mdix is turned off
  Switchport monitor is off 
  EtherType is 0x8100 
  EEE (efficient-ethernet) : n/a
    admin fec state is auto, oper fec state is off
  Last link flapped never
  Last clearing of "show interface" counters never
  0 interface resets
  Load-Interval #1: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  Load-Interval #2: 0 seconds
    0 seconds input rate 0 bits/sec, 0 packets/sec
    0 seconds output rate 0 bits/sec, 0 packets/sec
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  RX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 input packets  0 bytes
    0 jumbo packets  0 storm suppression packets
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
    0 Stomped CRC
  TX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 output packets  0 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
[7m--More--[m[Knx1# 
nx1# 
```

A person's NX-API `cli_show` as nxapi01 wrote accounting with task_id `nginx`: a `vsh.bin.` task_id on a person's record: false.

