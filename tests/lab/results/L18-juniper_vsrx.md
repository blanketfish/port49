# L18 — juniper_vsrx

- **Date measured:** 2026-09-22
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L18-juniper_vsrx.pcap` — 2440 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How each platform treats a reply attribute it did not ask for -- one it does not understand, one belonging to another vendor, one that does not exist, and a known attribute carrying a value the device cannot use -- in both the OPTIONAL and the MANDATORY spelling. For each: does the session open, what role or privilege does it end up with, and does the device still send per-command authorization. RFC 8907 §8.2 says an optional argument a device does not understand SHOULD be ignored; this row is the measurement of whether that holds, because an operator writing one server definition for a mixed fleet is relying on it.

## Observation

- **Date measured:** 2026-09-22
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Capture:** `tests/lab/evidence/L18-juniper_vsrx.pcap` — 2440 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

Each variant below is one set of reply attributes on the session authorization, one daemon restart and one token login. Per variant: whether the session opened and what the device said if it did not; `show cli authorization` for what the session was given; and one `show version`, typed only to see whether the device sends per-command authorization under this reply at all.

**How the summary table's cell is derived.** It is not written by hand and it is not a reading of the attribute's name. A variant whose session never opened is `session refused`. Otherwise the variant is compared with the one named in its `read against` column, on a single value: class and permissions, as `show cli authorization` reports them. Identical is `ignored`, different is `applied`. So `ignored` means the session came out indistinguishable from the one that differs only by the attribute under test, which is the only thing a lab can observe about an attribute a device chose to drop.

**Which baseline, and why it is not one fixed row.** Variants 3 to 6 send the known attribute AND the attribute under test, so that the session has something to be given and the bad attribute is the only variable; they are read against the control, which is the known attribute alone. Variants that REPLACE the whole reply -- the bad value, and on Junos the decision-22 attributes -- are read against variant 8. no attributes at all (the control for `ignored`). Reading everything against that instead would mark every row carrying the known attribute `applied`, because the known attribute was applied, and the table would then contradict the transcripts printed above it.

The device carries one login template for the length of this run, removed afterwards:

```
set system login class p49-l18-ops permissions [ view view-configuration configure ]
set system login user p49l18 uid 2099 class p49-l18-ops
```

It exists because this image already maps every TACACS+ user with no local account onto `user remote { class p49-readonly }`, so an attribute pointing at `remote` would leave the session identical to one carrying no attribute -- and the table could not tell `applied` from `ignored`. This template's class is deliberately different from the default's.

**What is not measured here.** The same question asked on a per-command authorization REPLY. The lab authorizer returns no attributes on that path (`Lab.Command` in `internal/daemon/author/lab.go`) and the `lab:` config block has no key for them, so there is no reply to put a bad attribute in. The wire side is not the obstacle -- `author.Handler` copies a decision's attributes onto the response for commands and sessions alike -- so this is a missing configuration key, and adding one is a daemon change this measurement was not scoped to make. Every variant below still records whether per-command authorization happened, which answers the neighbouring question of whether a device under this reply reaches that path at all.

### 1. mandatory KNOWN attribute (the control)

the control. One attribute, MANDATORY, that this platform is already measured to understand, and nothing else. Variants 3 to 6 are read against this one, so its own cell is read against the empty variant -- if the known attribute does not change the session either, this platform's signal is not sensitive enough to say anything about the others, and every cell below it says `not comparable` rather than `ignored`.

Reply attributes: `["local-user-name=p49l18"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice01' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice01@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 2. OPTIONAL known attribute

the same attribute sent OPTIONAL. RFC 8907 §8.2's flag decides what a device MAY ignore, not what it may apply, so a platform that drops a known attribute merely because it is optional would be its own finding -- and would mean an adapter cannot use the flag to be polite. It REPLACES the known attribute rather than sitting beside it, so it is read against the empty reply -- `applied` here means the optional form delivered something, which is the question. Whether the flag changed WHAT it delivered is a comparison with the control, and finding 3 below makes it directly.

Reply attributes: `["local-user-name*p49l18"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice02' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice02@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice02@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 3. OPTIONAL foreign-vendor attribute

another vendor's attribute, OPTIONAL: `shell:roles`. NX-OS reads this one and applies the role named in it (results/L16-cisco_nxos.md), and vEOS does not (results/L16-arista_eos.md). This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["local-user-name=p49l18", "shell:roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice03' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice03@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice03@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 4. MANDATORY foreign-vendor attribute

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["local-user-name=p49l18", "shell:roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice04' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice04@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice04@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 3b. OPTIONAL foreign-vendor attribute, the other vendor's spelling

another vendor's attribute, OPTIONAL: `roles`. vEOS reads this one and applies the role named in it (results/L16-arista_eos.md), and NX-OS reads `shell:roles` instead. This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["local-user-name=p49l18", "roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice05' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice05@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 4b. MANDATORY foreign-vendor attribute, the other vendor's spelling

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["local-user-name=p49l18", "roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice06' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice06@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice06@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 5. OPTIONAL invented attribute

an attribute no vendor has, OPTIONAL. The foreign-vendor variants above cannot tell "this device dislikes that particular name" from "this device refuses anything it does not recognise"; this one can, and on IOS-XE it is the variant that settled it in 2026-09-20's run (results/L10-cisco_iosxe.md).

Reply attributes: `["local-user-name=p49l18", "p49-nonsense*1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice07' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice07@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice07@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 6. MANDATORY invented attribute

the invented attribute MANDATORY: the one cell in this table where every platform is SUPPOSED to refuse the session. A platform that opens it here is ignoring a mandatory argument, which means an adapter cannot use the mandatory flag to make a device tell it that an attribute did not land.

Reply attributes: `["local-user-name=p49l18", "p49-nonsense=1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice08' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice08@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice08@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 7. known attribute, a value the device cannot use

a known attribute carrying a value the device cannot use: `local-user-name=p49-nosuchtemplate`. This is the typo case rather than the mixed-fleet case, and it is a different question -- the device parses the attribute and then has to decide what to do with the value. Does it clamp, ignore the attribute, or refuse the session? It REPLACES the known attribute rather than sitting beside it, so it is read against the empty variant.

Reply attributes: `["local-user-name=p49-nosuchtemplate"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice09' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice09@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice09@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 8. no attributes at all (the control for `ignored`)

no attributes at all on a permit. It is the floor of the table: what a session looks like when port49 delivers nothing. The control is read against it, and so is every variant that replaces the whole reply rather than adding to it. Without this row the table could report "ignored" only as an opinion.

Reply attributes: `[]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice10' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice10@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice10@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 9. Junos `user-permissions`, MANDATORY

the second attribute decision 22 projects into, MANDATORY. `view` alone is narrower than the default class `p49-readonly`, which carries `view view-configuration`, so a permissions list that SHRINKS is proof the attribute was applied -- no ignored attribute can take a permission away.

Reply attributes: `["user-permissions=view"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice11' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice11@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice11@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 10. Junos `user-permissions`, OPTIONAL

the same attribute OPTIONAL. If Junos applies it under both flags, decision 22 may choose the flag for its own reasons; if only the mandatory form lands, the projection has to send mandatory and accept what §8.2 says that costs on a device that does not understand it.

Reply attributes: `["user-permissions*view"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice12' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice12@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice12@srx1> 
```

**No command authorization reached port49 in this session at all.**


### 11. Junos `local-user-name` and `user-permissions` together, MANDATORY

both decision-22 attributes in one reply, which is the shape the projection would actually send. `user-permissions` is documented to REPLACE the class's permissions rather than merge with them (§15 L12); this is the variant that says whether the template's class survives beside it. Read against the empty variant, and then by hand against each attribute alone -- the three together are what say whether they compose.

Reply attributes: `["local-user-name=p49l18", "user-permissions=view"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show cli authorization`:

```
 
Current user: 'p49l18' login: 'alice13' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice13@srx1> 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice13@srx1> 
```

**No command authorization reached port49 in this session at all.**


## Every variant side by side

| variant | reply attributes | outcome | what the session got | read against | per-command authorization |
|---|---|---|---|---|---|
| 1. mandatory KNOWN attribute (the control) | `["local-user-name=p49l18"]` | **applied** | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | no attributes at all | **none** |
| 2. OPTIONAL known attribute | `["local-user-name*p49l18"]` | **applied** | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | no attributes at all | **none** |
| 3. OPTIONAL foreign-vendor attribute | `["local-user-name=p49l18", "shell:roles*network-operator"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 4. MANDATORY foreign-vendor attribute | `["local-user-name=p49l18", "shell:roles=network-operator"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 3b. OPTIONAL foreign-vendor attribute, the other vendor's spelling | `["local-user-name=p49l18", "roles*network-operator"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 4b. MANDATORY foreign-vendor attribute, the other vendor's spelling | `["local-user-name=p49l18", "roles=network-operator"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 5. OPTIONAL invented attribute | `["local-user-name=p49l18", "p49-nonsense*1"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 6. MANDATORY invented attribute | `["local-user-name=p49l18", "p49-nonsense=1"]` | ignored | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | the control (same reply, minus this attribute) | **none** |
| 7. known attribute, a value the device cannot use | `["local-user-name=p49-nosuchtemplate"]` | ignored | class=p49-readonly permissions=[view view-configuration] regexes=all none | no attributes at all | **none** |
| 8. no attributes at all (the control for `ignored`) | `[]` | opened (this is the baseline) | class=p49-readonly permissions=[view view-configuration] regexes=all none | — | **none** |
| 9. Junos `user-permissions`, MANDATORY | `["user-permissions=view"]` | ignored | class=p49-readonly permissions=[view view-configuration] regexes=all none | no attributes at all | **none** |
| 10. Junos `user-permissions`, OPTIONAL | `["user-permissions*view"]` | ignored | class=p49-readonly permissions=[view view-configuration] regexes=all none | no attributes at all | **none** |
| 11. Junos `local-user-name` and `user-permissions` together, MANDATORY | `["local-user-name=p49l18", "user-permissions=view"]` | **applied** | class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none | no attributes at all | **none** |

The `what the session got` column is the verbatim `show` output above reduced to the one value the cell is derived from, and `read against` names the row it was compared with. The transcripts both come from are in each variant's section, and a cell that disagrees with the transcript above it is a defect in this generator rather than a finding about the device.

## What this answers

**0. The measurement can see an attribute land.** The control (`["local-user-name=p49l18"]`) left the session `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none` and the empty reply (`[]`) left it `class=p49-readonly permissions=[view view-configuration] regexes=all none`, on the same device minutes apart. So when a row below reads `ignored` it means the device produced the same session as the control despite being sent something extra -- a comparison, not an assumption.

**1. This platform does what RFC 8907 §8.2 says: an optional attribute it does not understand is ignored.** All 3 of them -- `["local-user-name=p49l18", "shell:roles*network-operator"]`, `["local-user-name=p49l18", "roles*network-operator"]`, `["local-user-name=p49l18", "p49-nonsense*1"]` -- opened a session that matched the control's on class and permissions, as `show cli authorization` reports them. The control carries the same reply without the extra attribute, so the attribute is what changed, and nothing changed. An adapter may send another vendor's attributes here marked optional without ending anyone's session.

**2. It does NOT do what §8.2 makes a MUST.** Measured: a MANDATORY argument this device does not understand does NOT fail the authorization on vSRX3 21.4R3.15: the session opened and came out indistinguishable from the control, which is the same reply with the mandatory argument taken out. So the mandatory flag buys an adapter nothing here -- there is no way to make this device say that an attribute did not land.

Sent:

```
reply attributes ["local-user-name=p49l18", "p49-nonsense=1"]
then, in the session:
show cli authorization
```

The device replied:

```
show cli authorization
 
Current user: 'p49l18' login: 'alice08' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice08@srx1> 
```

**3. A KNOWN attribute is applied under either flag.** `["local-user-name=p49l18"]` and `["local-user-name*p49l18"]` both left the session on `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none`, so an adapter may mark this platform's own attributes optional -- the politeness §8.2 invites -- without losing what they deliver.

**4. A known attribute with an unusable value is dropped, not clamped.** `["local-user-name=p49-nosuchtemplate"]` left the session on `class=p49-readonly permissions=[view view-configuration] regexes=all none` -- the same as sending nothing. The operator gets a working login with none of the privilege the policy named, and port49's log records the attribute as sent.

**5. This platform sends no per-command authorization at all.** All 13 sessions that opened ran the probe command and not one produced an `authorize_command` record. So the per-command reply is not a place this platform could be handed a bad attribute even if port49 had one to send -- which is the shape decision 21 already records for Junos.

**6. Every login in this run reached the device's AAA.** No SSH connection was refused before the device asked port49, so nothing here says a run of refused authorizations costs anything beyond the sessions refused.


## The two attributes decision 22 will use

Spec §8's session-only projection sends `local-user-name` and `user-permissions` over `junos-exec`, and §15 L12 records both as unmeasured over TACACS+. This run asks each of them the same way the variants above ask about foreign attributes: does the session change, and what does `show cli authorization` say.

**`local-user-name` takes effect over `junos-exec`.** Measured: the session does NOT stay on the device's own `user remote` template when the reply names another one. With `["local-user-name=p49l18"]` the session came out `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none`, against `class=p49-readonly permissions=[view view-configuration] regexes=all none` for a reply carrying no attributes at all, minutes apart on the same device.

Sent:

```
reply attributes ["local-user-name=p49l18"]
then, in the session:
show cli authorization
```

The device replied:

```
 
Current user: 'p49l18' login: 'alice01' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

**The flag does not change `local-user-name`.** Sent optional (`["local-user-name*p49l18"]`) it left the session `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none`, the same as the mandatory form, so decision 22 may mark it optional -- which on a device that does not understand it is the difference between a degraded session and no session.

**`user-permissions` MANDATORY did not change the session**: `["user-permissions=view"]` came out `class=p49-readonly permissions=[view view-configuration] regexes=all none`, the same as the empty control. `show cli authorization` in full:

```
 
Current user: 'remote' login: 'alice11' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice11@srx1> 
```

**`user-permissions` OPTIONAL did not change the session**: `["user-permissions*view"]` came out `class=p49-readonly permissions=[view view-configuration] regexes=all none`, the same as the empty control. `show cli authorization` in full:

```
 
Current user: 'remote' login: 'alice12' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice12@srx1> 
```

**Both together** -- the shape the projection would actually send -- left the session `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none`, against `class=p49-l18-ops permissions=[configure view view-configuration] regexes=all none` for `local-user-name` alone and `class=p49-readonly permissions=[view view-configuration] regexes=all none` for `user-permissions` alone. **So `user-permissions` contributes nothing, beside `local-user-name` or on its own.** The pair is indistinguishable from `local-user-name` alone, and `user-permissions` alone is indistinguishable from an empty reply. On this image the projection's second attribute is inert: whatever decision 22 puts in it, the operator gets the template's class and nothing else, and port49's log records an attribute that did nothing. `show cli authorization` in full:

```
 
Current user: 'p49l18' login: 'alice13' class 'p49-l18-ops'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice13@srx1> 
```

None of this closes §15 L12. That row asks four more questions this run does not touch -- whether `user-permissions` replaces or merges across a bitless template, what each bit reaches, the wire `deny-commands` precedence, and whether numbered attribute names are distinct -- and a row closes on all of its clauses or none.

