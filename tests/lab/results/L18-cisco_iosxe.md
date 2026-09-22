# L18 — cisco_iosxe

- **Date measured:** 2026-09-22
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L18-cisco_iosxe.pcap` — 1549 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How each platform treats a reply attribute it did not ask for -- one it does not understand, one belonging to another vendor, one that does not exist, and a known attribute carrying a value the device cannot use -- in both the OPTIONAL and the MANDATORY spelling. For each: does the session open, what role or privilege does it end up with, and does the device still send per-command authorization. RFC 8907 §8.2 says an optional argument a device does not understand SHOULD be ignored; this row is the measurement of whether that holds, because an operator writing one server definition for a mixed fleet is relying on it.

## Observation

- **Date measured:** 2026-09-22
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Capture:** `tests/lab/evidence/L18-cisco_iosxe.pcap` — 1549 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

Each variant below is one set of reply attributes on the session authorization, one daemon restart and one token login. Per variant: whether the session opened and what the device said if it did not; `show privilege` for what the session was given; and one `show version`, typed only to see whether the device sends per-command authorization under this reply at all.

**How the summary table's cell is derived.** It is not written by hand and it is not a reading of the attribute's name. A variant whose session never opened is `session refused`. Otherwise the variant is compared with the one named in its `read against` column, on a single value: privilege level, as `show privilege` reports it. Identical is `ignored`, different is `applied`. So `ignored` means the session came out indistinguishable from the one that differs only by the attribute under test, which is the only thing a lab can observe about an attribute a device chose to drop.

**Which baseline, and why it is not one fixed row.** Variants 3 to 6 send the known attribute AND the attribute under test, so that the session has something to be given and the bad attribute is the only variable; they are read against the control, which is the known attribute alone. Variants that REPLACE the whole reply -- the bad value, and on Junos the decision-22 attributes -- are read against variant 8. no attributes at all (the control for `ignored`). Reading everything against that instead would mark every row carrying the known attribute `applied`, because the known attribute was applied, and the table would then contradict the transcripts printed above it.

**The per-command reply is asked too, in three shapes.** `lab.command_attributes` puts attributes on a PERMITTED per-command authorization the way `lab.session_attributes` does on a session one, so variants 9. OPTIONAL invented attribute on a PER-COMMAND reply, 10. MANDATORY invented attribute on a PER-COMMAND reply and 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply hold the session reply constant at the control's and vary only what the command reply carries.

**Their cells are derived differently from the rest, and have to be.** Their sessions are the control's by construction, so comparing sessions would read `ignored` however the device reacted to the command reply. The cell is read off the COMMANDS instead, in this order: the session lost after a prompt was reached, or the device asking for no command authorization at all, or a command whose reply is one of this platform's refusal markers (`% Authorization failed`, `Authorization failed`, `% Authorization`, `Command authorization failed`, `authorization failed`), or -- the only way to `ran` -- a reply whose first line is the one the control's `show version` produced on the same device. A command that neither matched a refusal marker nor came back looking like the control's output is reported as neither, with its words printed, rather than being counted as having run.

### 1. mandatory KNOWN attribute (the control)

the control. One attribute, MANDATORY, that this platform is already measured to understand, and nothing else. Variants 3 to 6 are read against this one, so its own cell is read against the empty variant -- if the known attribute does not change the session either, this platform's signal is not sensitive enough to say anything about the others, and every cell below it says `not comparable` rather than `ignored`.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 15
xe1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco IOS XE Software, Version 17.13.01a
Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 13-Dec-23 21:43 by mcpre


Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.  The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.  You can redistribute and/or modify such
GPL code under the terms of GPL Version 2.0.  For more details, see the
documentation or "License Notice" file accompanying the IOS-XE software,
or the applicable URL provided on the flyer accompanying the IOS-XE
software.


ROM: IOS-XE ROMMON
xe1 uptime is 0 minutes
Uptime for this control processor is 1 minute
System returned to ROM by reload
System image file is "bootflash:packages.conf"
Last reload reason: Reload Command



This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.

A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html

If you require further assistance please contact us by sending email to
export@cisco.com.

License Level: network-premier
License Type: Perpetual
Next reload license Level: network-premier

Addon License Level: dna-premier
Addon License Type: Subscription
Next reload addon license Level: dna-premier

The current throughput level is 20000 kbps 


Smart Licensing Status: Smart Licensing Using Policy

cisco C8000V (VXE) processor (revision VXE) with 2017252K/3075K bytes of memory.
Processor board ID 94EHBYZD7PG
Router operating mode: Autonomous
1 Gigabit Ethernet interface
32768K bytes of non-volatile configuration memory.
3960696K bytes of physical memory.
5234688K bytes of virtual hard disk at bootflash:.

Configuration register is 0x2102

xe1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
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
xe1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco IOS XE Software, Version 17.13.01a
Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 13-Dec-23 21:43 by mcpre


Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.  The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.  You can redistribute and/or modify such
GPL code under the terms of GPL Version 2.0.  For more details, see the
documentation or "License Notice" file accompanying the IOS-XE software,
or the applicable URL provided on the flyer accompanying the IOS-XE
software.


ROM: IOS-XE ROMMON
xe1 uptime is 0 minutes
Uptime for this control processor is 1 minute
System returned to ROM by reload
System image file is "bootflash:packages.conf"
Last reload reason: Reload Command



This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.

A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html

If you require further assistance please contact us by sending email to
export@cisco.com.

License Level: network-premier
License Type: Perpetual
Next reload license Level: network-premier

Addon License Level: dna-premier
Addon License Type: Subscription
Next reload addon license Level: dna-premier

The current throughput level is 20000 kbps 


Smart Licensing Status: Smart Licensing Using Policy

cisco C8000V (VXE) processor (revision VXE) with 2017252K/3075K bytes of memory.
Processor board ID 94EHBYZD7PG
Router operating mode: Autonomous
1 Gigabit Ethernet interface
32768K bytes of non-volatile configuration memory.
3960696K bytes of physical memory.
5234688K bytes of virtual hard disk at bootflash:.

Configuration register is 0x2102

xe1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


### 3. OPTIONAL foreign-vendor attribute

another vendor's attribute, OPTIONAL: `shell:roles`. NX-OS reads this one and applies the role named in it (results/L16-cisco_nxos.md), and vEOS does not (results/L16-arista_eos.md). This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["priv-lvl=15", "shell:roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 4. MANDATORY foreign-vendor attribute

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["priv-lvl=15", "shell:roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 3b. OPTIONAL foreign-vendor attribute, the other vendor's spelling

another vendor's attribute, OPTIONAL: `roles`. vEOS reads this one and applies the role named in it (results/L16-arista_eos.md), and NX-OS reads `shell:roles` instead. This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["priv-lvl=15", "roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 4b. MANDATORY foreign-vendor attribute, the other vendor's spelling

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["priv-lvl=15", "roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 5. OPTIONAL invented attribute

an attribute no vendor has, OPTIONAL. The foreign-vendor variants above cannot tell "this device dislikes that particular name" from "this device refuses anything it does not recognise"; this one can, and on IOS-XE it is the variant that settled it in 2026-09-20's run (results/L10-cisco_iosxe.md).

Reply attributes: `["priv-lvl=15", "p49-nonsense*1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 6. MANDATORY invented attribute

the invented attribute MANDATORY: the one cell in this table where every platform is SUPPOSED to refuse the session. A platform that opens it here is ignoring a mandatory argument, which means an adapter cannot use the mandatory flag to make a device tell it that an attribute did not land.

Reply attributes: `["priv-lvl=15", "p49-nonsense=1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

This variant took 3 SSH connection(s); the earlier ones were refused before the device ran AAA:

```
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 7. known attribute, a value the device cannot use

a known attribute carrying a value the device cannot use: `priv-lvl=99`. This is the typo case rather than the mixed-fleet case, and it is a different question -- the device parses the attribute and then has to decide what to do with the value. Does it clamp, ignore the attribute, or refuse the session? It REPLACES the known attribute rather than sitting beside it, so it is read against the empty variant.

Reply attributes: `["priv-lvl=99"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session did not open.** What the device said on the channel, verbatim:

```
% Authorization failed.
```

What the harness reported:

```
the device refused the session after authenticating it; it said: % Authorization failed.
```


### 8. no attributes at all (the control for `ignored`)

no attributes at all on a permit. It is the floor of the table: what a session looks like when port49 delivers nothing. The control is read against it, and so is every variant that replaces the whole reply rather than adding to it. Without this row the table could report "ignored" only as an opinion.

Reply attributes: `[]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show privilege`:

```
Current privilege level is 1
xe1>
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco IOS XE Software, Version 17.13.01a
Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 13-Dec-23 21:43 by mcpre


Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.  The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.  You can redistribute and/or modify such
GPL code under the terms of GPL Version 2.0.  For more details, see the
documentation or "License Notice" file accompanying the IOS-XE software,
or the applicable URL provided on the flyer accompanying the IOS-XE
software.


ROM: IOS-XE ROMMON
xe1 uptime is 2 minutes
Uptime for this control processor is 3 minutes
System returned to ROM by reload
System image file is "bootflash:packages.conf"
Last reload reason: Reload Command



This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.

A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html

If you require further assistance please contact us by sending email to
export@cisco.com.

License Level: network-premier
License Type: Perpetual
Next reload license Level: network-premier

Addon License Level: dna-premier
Addon License Type: Subscription
Next reload addon license Level: dna-premier

The current throughput level is 20000 kbps 


Smart Licensing Status: Smart Licensing Using Policy

cisco C8000V (VXE) processor (revision VXE) with 2017252K/3075K bytes of memory.
Processor board ID 94EHBYZD7PG
Router operating mode: Autonomous
1 Gigabit Ethernet interface
32768K bytes of non-volatile configuration memory.
3960696K bytes of physical memory.
5234688K bytes of virtual hard disk at bootflash:.

Configuration register is 0x2102

xe1>
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


### 9. OPTIONAL invented attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is an OPTIONAL attribute no vendor has -- the shape RFC 8907 §8.2 says a device SHOULD ignore, and the mildest thing that can be wrong in a reply.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["p49-nonsense*1"]`. The device said:

```
Command authorization failed.

xe1#
```

`show privilege`:

```
Command authorization failed.

xe1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Command authorization failed.

xe1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


### 10. MANDATORY invented attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is the same invented attribute sent MANDATORY, which is where §8.2 stops being a SHOULD: a device that does not understand it MUST fail the authorization. It is also the only shape that could tell an adapter its attribute did not land, so what this platform does with it decides whether the flag is worth anything on the command path.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["p49-nonsense=1"]`. The device said:

```
Command authorization failed.

xe1#
```

`show privilege`:

```
Command authorization failed.

xe1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Command authorization failed.

xe1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show version -> permit permit_dominates
```


### 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is another vendor's attribute, OPTIONAL: `shell:roles`. NX-OS reads this one and applies the role named in it (results/L16-cisco_nxos.md), and vEOS does not (results/L16-arista_eos.md). This is the reply an operator gets when one server definition serves a mixed fleet, and it separates "this device dislikes anything unfamiliar" from "this device dislikes that particular name" without leaning on the invented one alone.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["shell:roles*network-operator"]`. The device said:

```
Command authorization failed.

xe1#
```

`show privilege`:

```
Command authorization failed.

xe1#
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Command authorization failed.

xe1#
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
| 1. mandatory KNOWN attribute (the control) | `["priv-lvl=15"]` | **applied** | 15 | no attributes at all | 3 request(s) |
| 2. OPTIONAL known attribute | `["priv-lvl*15"]` | **applied** | 15 | no attributes at all | 3 request(s) |
| 3. OPTIONAL foreign-vendor attribute | `["priv-lvl=15", "shell:roles*network-operator"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 4. MANDATORY foreign-vendor attribute | `["priv-lvl=15", "shell:roles=network-operator"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 3b. OPTIONAL foreign-vendor attribute, the other vendor's spelling | `["priv-lvl=15", "roles*network-operator"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 4b. MANDATORY foreign-vendor attribute, the other vendor's spelling | `["priv-lvl=15", "roles=network-operator"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 5. OPTIONAL invented attribute | `["priv-lvl=15", "p49-nonsense*1"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 6. MANDATORY invented attribute | `["priv-lvl=15", "p49-nonsense=1"]` | **session refused** | — | the control (same reply, minus this attribute) | **none** |
| 7. known attribute, a value the device cannot use | `["priv-lvl=99"]` | **session refused** | — | no attributes at all | **none** |
| 8. no attributes at all (the control for `ignored`) | `[]` | opened (this is the baseline) | 1 | — | 3 request(s) |
| 9. OPTIONAL invented attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["p49-nonsense*1"]`** | **command refused** | — | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |
| 10. MANDATORY invented attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["p49-nonsense=1"]`** | **command refused** | — | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |
| 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["shell:roles*network-operator"]`** | **command refused** | — | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |

The `what the session got` column is the verbatim `show` output above reduced to the one value the cell is derived from, and `read against` names the row it was compared with. The transcripts both come from are in each variant's section, and a cell that disagrees with the transcript above it is a defect in this generator rather than a finding about the device. The rows whose `reply attributes` name a **command** list send the control's session reply and differ from it only there, so their `what the session got` column is the control's by construction and their outcome is read off the commands.

## What this answers

**0. The measurement can see an attribute land.** The control (`["priv-lvl=15"]`) left the session `15` and the empty reply (`[]`) left it `1`, on the same device minutes apart. So when a row below reads `ignored` it means the device produced the same session as the control despite being sent something extra -- a comparison, not an assumption.

**1. This platform does NOT ignore an optional attribute it does not understand: it refuses the session.** Measured: RFC 8907 §8.2 says a device SHOULD ignore an OPTIONAL argument it does not understand. On Catalyst 8000V 17.13.01a it does not: 3 of the 3 optional unknown attributes tried here produced no session at all, on a session authorization port49 answered `permit context_matched`.

Sent:

```
reply attributes ["priv-lvl=15", "shell:roles*network-operator"]
(then one SSH login as a token operator)
```

The device replied:

```
% Authorization failed.
```

The variants that did this: `["priv-lvl=15", "shell:roles*network-operator"]`, `["priv-lvl=15", "roles*network-operator"]`, `["priv-lvl=15", "p49-nonsense*1"]`. An operator whose server definition carries another vendor's attributes for a mixed fleet is locked out of this platform, and port49's own log says `permit`.

**2. And it does what §8.2 makes a MUST: every MANDATORY attribute it does not understand ended the session.** All 3 of them -- `["priv-lvl=15", "shell:roles=network-operator"]`, `["priv-lvl=15", "roles=network-operator"]`, `["priv-lvl=15", "p49-nonsense=1"]`. So on this platform the argument flag is a working switch: an adapter that wants to be told when an attribute did not land can send it mandatory and find out by losing the session.

**3. A KNOWN attribute is applied under either flag.** `["priv-lvl=15"]` and `["priv-lvl*15"]` both left the session on `15`, so an adapter may mark this platform's own attributes optional -- the politeness §8.2 invites -- without losing what they deliver.

**4. A known attribute with a value the device cannot use ends the session.** Measured: `["priv-lvl=99"]` is an attribute this platform reads, carrying a value it cannot use. It does not clamp the value and it does not ignore the attribute: there is no session.

Sent:

```
reply attributes ["priv-lvl=99"]
(then one SSH login as a token operator)
```

The device replied:

```
% Authorization failed.
```

**5. Every session that opened went on to per-command authorization**, 3 of 3, whatever the SESSION reply carried. So an attribute on the session reply either ends the session outright or leaves the device still asking about commands: there is no middle state where the session survives and the device stops asking. Whether the commands then RUN is a different question, and it is 5b -- these 3 variants put nothing on the command reply.

**5b. The same question asked of a PER-COMMAND reply, in 3 shapes.** Each one sends the control's session attributes (`["priv-lvl=15"]`) and differs from the control only in what a PERMITTED command authorization carries, so whatever the device does below it is doing about the command reply. The control itself answered 3 command authorization(s) and ran every command typed in it.

`["p49-nonsense*1"]` on every permitted command — **a permit became a refusal.** Measured: port49 PERMITTED `terminal length 0` -- 3 command authorization(s) reached it in this session and its log records what it answered -- and the device refused the command anyway. The same command under the control reply, which differs only in that the command reply carries nothing, ran.

Sent:

```
lab.command_attributes ["p49-nonsense*1"]
then, in the session:
terminal length 0
```

The device replied:

```
Command authorization failed.

xe1#
```

So on Catalyst 8000V 17.13.01a a per-command reply may carry nothing the device does not read: the decision log records a permit for a command that never ran, and an operator reading it sees an authorization that succeeded.

`["p49-nonsense=1"]` on every permitted command — **a permit became a refusal.** Measured: port49 PERMITTED `terminal length 0` -- 3 command authorization(s) reached it in this session and its log records what it answered -- and the device refused the command anyway. The same command under the control reply, which differs only in that the command reply carries nothing, ran.

Sent:

```
lab.command_attributes ["p49-nonsense=1"]
then, in the session:
terminal length 0
```

The device replied:

```
Command authorization failed.

xe1#
```

So on Catalyst 8000V 17.13.01a a per-command reply may carry nothing the device does not read: the decision log records a permit for a command that never ran, and an operator reading it sees an authorization that succeeded.

`["shell:roles*network-operator"]` on every permitted command — **a permit became a refusal.** Measured: port49 PERMITTED `terminal length 0` -- 3 command authorization(s) reached it in this session and its log records what it answered -- and the device refused the command anyway. The same command under the control reply, which differs only in that the command reply carries nothing, ran.

Sent:

```
lab.command_attributes ["shell:roles*network-operator"]
then, in the session:
terminal length 0
```

The device replied:

```
Command authorization failed.

xe1#
```

So on Catalyst 8000V 17.13.01a a per-command reply may carry nothing the device does not read: the decision log records a permit for a command that never ran, and an operator reading it sees an authorization that succeeded.

**The two paths, attribute by attribute.** The same attribute in the same spelling, once on the session reply and once on a command reply. Both columns are the cells from the table above, with one word changed so they can be compared: a command reply whose commands ran is written `ignored` here, which is what the session column already calls a reply that changed nothing.

| attribute | on the SESSION reply | on a COMMAND reply |
|---|---|---|
| `["p49-nonsense*1"]` | **the session was refused** | **command refused** |
| `["p49-nonsense=1"]` | **the session was refused** | **command refused** |
| `["shell:roles*network-operator"]` | **the session was refused** | **command refused** |

**The two paths agree on all 3, and on 3 of them the cost is not the same size.** The device objects to the same attributes in both replies -- so one rule predicts both -- but objecting on the session reply costs the operator the login, and objecting on a command reply leaves them logged in and unable to run anything. Same rule, different blast radius, and the second is the one an operator will call in about.

**6. A refused authorization costs the NEXT connection too, and the device recovers on its own.** `["priv-lvl=15", "p49-nonsense=1"]` took 3 SSH connections: the first 2 were refused at the authentication layer, before the device ran AAA at all, and the last one got through to the device's own answer. What the refused connections returned:

```
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

Nothing was lost to it here -- every variant was measured -- so this run does not show an outage, it shows the mechanism that produces one. An earlier run of this same test on this same image did lose one: three connections over 50 seconds, every one refused this way, with no TACACS+ packet for any of them, and the variant after them connected normally.

**What that means at 3am, and it is the operational half of this row.** These refusals do not reach port49, so its log says nothing about them: the last thing in it is a `permit`. The operator sees an SSH server refusing their password, which looks like a credential problem and is not one. Break-glass reaches the same SSH server, so for as long as the condition lasts it is refused too. The trigger is a reply attribute -- one line in a server definition -- and the blast radius is the device rather than the session.


