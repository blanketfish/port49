# L18 — arista_eos

- **Date measured:** 2026-09-22
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L18-arista_eos.pcap` — 1642 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How each platform treats a reply attribute it did not ask for -- one it does not understand, one belonging to another vendor, one that does not exist, and a known attribute carrying a value the device cannot use -- in both the OPTIONAL and the MANDATORY spelling. For each: does the session open, what role or privilege does it end up with, and does the device still send per-command authorization. RFC 8907 §8.2 says an optional argument a device does not understand SHOULD be ignored; this row is the measurement of whether that holds, because an operator writing one server definition for a mixed fleet is relying on it.

## Observation

- **Date measured:** 2026-09-22
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Capture:** `tests/lab/evidence/L18-arista_eos.pcap` — 1642 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

Each variant below is one set of reply attributes on the session authorization, one daemon restart and one token login. Per variant: whether the session opened and what the device said if it did not; `show privilege`, `show users detail` for what the session was given; and one `show version`, typed only to see whether the device sends per-command authorization under this reply at all.

**How the summary table's cell is derived.** It is not written by hand and it is not a reading of the attribute's name. A variant whose session never opened is `session refused`. Otherwise the variant is compared with the one named in its `read against` column, on a single value: privilege level and role, as `show privilege` and `show users detail` report them. Identical is `ignored`, different is `applied`. So `ignored` means the session came out indistinguishable from the one that differs only by the attribute under test, which is the only thing a lab can observe about an attribute a device chose to drop.

**Which baseline, and why it is not one fixed row.** Variants 3 to 6 send the known attribute AND the attribute under test, so that the session has something to be given and the bad attribute is the only variable; they are read against the control, which is the known attribute alone. Variants that REPLACE the whole reply -- the bad value, and on Junos the decision-22 attributes -- are read against `8. no attributes at all (the control for `ignored`)`. Reading everything against `8. no attributes at all (the control for `ignored`)` instead would mark every row carrying the known attribute `applied`, because the known attribute was applied, and the table would then contradict the transcripts printed above it.

**What is not measured here.** The same question asked on a per-command authorization REPLY. The lab authorizer returns no attributes on that path (`Lab.Command` in `internal/daemon/author/lab.go`) and the `lab:` config block has no key for them, so there is no reply to put a bad attribute in. The wire side is not the obstacle -- `author.Handler` copies a decision's attributes onto the response for commands and sessions alike -- so this is a missing configuration key, and adding one is a daemon change this measurement was not scoped to make. Every variant below still records whether per-command authorization happened, which answers the neighbouring question of whether a device under this reply reaches that path at all.

### 1. mandatory KNOWN attribute (the control)

the control. One attribute, MANDATORY, that this platform is already measured to understand, and nothing else. Variants 3 to 6 are read against this one, so its own cell is read against the empty variant -- if the known attribute does not change the session either, this platform's signal is not sensitive enough to say anything about the others, and every cell below it says `not comparable` rather than `ignored`.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 15
leaf1#
```

`show users detail`:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:08        local                           
4             alice01        <unknown>           vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 0 minutes
Total memory: 1979668 kB
Free memory: 621336 kB

leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show users detail -> permit permit_dominates
show version -> permit permit_dominates
```


### 2. OPTIONAL known attribute

the same attribute sent OPTIONAL. RFC 8907 §8.2's flag decides what a device MAY ignore, not what it may apply, so a platform that drops a known attribute merely because it is optional would be its own finding -- and would mean an adapter cannot use the flag to be polite. It REPLACES the known attribute rather than sitting beside it, so it is read against the empty reply -- `applied` here means the optional form delivered something, which is the question. Whether the flag changed WHAT it delivered is a comparison with the control, and finding 3 below makes it directly.

Reply attributes: `["priv-lvl*15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 15
leaf1#
```

`show users detail`:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:20        local                           
5             alice02        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 0 minutes
Total memory: 1979668 kB
Free memory: 623264 kB

leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show users detail -> permit permit_dominates
show version -> permit permit_dominates
```


### 3. OPTIONAL foreign-vendor attribute

another vendor's attribute, OPTIONAL: `shell:roles`. NX-OS reads this one and applies the role named in it (results/L16-cisco_nxos.md), and vEOS does not (results/L16-arista_eos.md). This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["priv-lvl=15", "shell:roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 15
leaf1#
```

`show users detail`:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:32        local                           
6             alice03        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 1 minute
Total memory: 1979668 kB
Free memory: 628460 kB

leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show users detail -> permit permit_dominates
show version -> permit permit_dominates
```


### 4. MANDATORY foreign-vendor attribute

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["priv-lvl=15", "shell:roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
Authorization denied: 
```

What the harness reported:

```
the device refused the session after authenticating it; it said: Authorization denied:
```


### 5. OPTIONAL invented attribute

an attribute no vendor has, OPTIONAL. The foreign-vendor variants above cannot tell "this device dislikes that particular name" from "this device refuses anything it does not recognise"; this one can, and on IOS-XE it is the variant that settled it in 2026-09-20's run (results/L10-cisco_iosxe.md).

Reply attributes: `["priv-lvl=15", "p49-nonsense*1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 15
leaf1#
```

`show users detail`:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:54        local                           
8             alice05        <unknown>           vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 1 minute
Total memory: 1979668 kB
Free memory: 626104 kB

leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show users detail -> permit permit_dominates
show version -> permit permit_dominates
```


### 6. MANDATORY invented attribute

the invented attribute MANDATORY: the one cell in this table where every platform is SUPPOSED to refuse the session. A platform that opens it here is ignoring a mandatory argument, which means an adapter cannot use the mandatory flag to make a device tell it that an attribute did not land.

Reply attributes: `["priv-lvl=15", "p49-nonsense=1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
Authorization denied: 
```

What the harness reported:

```
the device refused the session after authenticating it; it said: Authorization denied:
```


### 7. known attribute, a value the device cannot use

a known attribute carrying a value the device cannot use: `priv-lvl=99`. This is the typo case rather than the mixed-fleet case, and it is a different question -- the device parses the attribute and then has to decide what to do with the value. Does it clamp, ignore the attribute, or refuse the session? It REPLACES the known attribute rather than sitting beside it, so it is read against the empty variant.

Reply attributes: `["priv-lvl=99"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 1
leaf1>
```

`show users detail`:

```
% Invalid input (privileged mode required)
leaf1>
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 1 minute
Total memory: 1979668 kB
Free memory: 665848 kB

leaf1>
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


### 8. no attributes at all (the control for `ignored`)

no attributes at all on a permit. It is the floor of the table: what a session looks like when port49 delivers nothing. The control is read against it, and so is every variant that replaces the whole reply rather than adding to it. Without this row the table could report "ignored" only as an opinion.

Reply attributes: `[]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 1
leaf1>
```

`show users detail`:

```
% Invalid input (privileged mode required)
leaf1>
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.aa15.c2d1
System MAC address: 0c00.aa15.c2d1

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 2 minutes
Total memory: 1979668 kB
Free memory: 667412 kB

leaf1>
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


## Every variant side by side

| variant | reply attributes | outcome | what the session got | read against | per-command authorization |
|---|---|---|---|---|---|
| 1. mandatory KNOWN attribute (the control) | `["priv-lvl=15"]` | **applied** | priv=15 role=<unknown> | no attributes at all | 4 request(s) |
| 2. OPTIONAL known attribute | `["priv-lvl*15"]` | **applied** | priv=15 role=<unknown> | no attributes at all | 4 request(s) |
| 3. OPTIONAL foreign-vendor attribute | `["priv-lvl=15", "shell:roles*network-operator"]` | ignored | priv=15 role=<unknown> | the control (same reply, minus this attribute) | 4 request(s) |
| 4. MANDATORY foreign-vendor attribute | `["priv-lvl=15", "shell:roles=network-operator"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 5. OPTIONAL invented attribute | `["priv-lvl=15", "p49-nonsense*1"]` | ignored | priv=15 role=<unknown> | the control (same reply, minus this attribute) | 4 request(s) |
| 6. MANDATORY invented attribute | `["priv-lvl=15", "p49-nonsense=1"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 7. known attribute, a value the device cannot use | `["priv-lvl=99"]` | ignored | priv=1 role=— | no attributes at all | 3 request(s) |
| 8. no attributes at all (the control for `ignored`) | `[]` | opened (this is the baseline) | priv=1 role=— | — | 3 request(s) |

The `what the session got` column is the verbatim `show` output above reduced to the one value the cell is derived from, and `read against` names the row it was compared with. The transcripts both come from are in each variant's section, and a cell that disagrees with the transcript above it is a defect in this generator rather than a finding about the device.

## What this answers

**0. The measurement can see an attribute land.** The control (`["priv-lvl=15"]`) left the session `priv=15 role=<unknown>` and the empty reply (`[]`) left it `priv=1 role=—`, on the same device minutes apart. So when a row below reads `ignored` it means the device produced the same session as the control despite being sent something extra -- a comparison, not an assumption.

**1. This platform does what RFC 8907 §8.2 says: an optional attribute it does not understand is ignored.** All 2 of them -- `["priv-lvl=15", "shell:roles*network-operator"]`, `["priv-lvl=15", "p49-nonsense*1"]` -- opened a session that matched the control's on privilege level and role, as `show privilege` and `show users detail` report them. The control carries the same reply without the extra attribute, so the attribute is what changed, and nothing changed. An adapter may send another vendor's attributes here marked optional without ending anyone's session.

**2. And it does what §8.2 makes a MUST: every MANDATORY attribute it does not understand ended the session.** All 2 of them -- `["priv-lvl=15", "shell:roles=network-operator"]`, `["priv-lvl=15", "p49-nonsense=1"]`. So on this platform the argument flag is a working switch: an adapter that wants to be told when an attribute did not land can send it mandatory and find out by losing the session.

**3. A KNOWN attribute is applied under either flag.** `["priv-lvl=15"]` and `["priv-lvl*15"]` both left the session on `priv=15 role=<unknown>`, so an adapter may mark this platform's own attributes optional -- the politeness §8.2 invites -- without losing what they deliver.

**4. A known attribute with an unusable value is dropped, not clamped.** `["priv-lvl=99"]` left the session on `priv=1 role=—` -- the same as sending nothing. The operator gets a working login with none of the privilege the policy named, and port49's log records the attribute as sent.

**5. Every session that opened went on to per-command authorization**, 6 of 6, whatever the reply carried. So a bad attribute on this platform either ends the session outright or leaves the command path exactly as it was: there is no middle state where the session survives and the device stops asking.


