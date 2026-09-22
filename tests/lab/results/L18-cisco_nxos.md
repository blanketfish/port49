# L18 — cisco_nxos

- **Date measured:** 2026-09-22
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L18-cisco_nxos.pcap` — 1880 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How each platform treats a reply attribute it did not ask for -- one it does not understand, one belonging to another vendor, one that does not exist, and a known attribute carrying a value the device cannot use -- in both the OPTIONAL and the MANDATORY spelling. For each: does the session open, what role or privilege does it end up with, and does the device still send per-command authorization. RFC 8907 §8.2 says an optional argument a device does not understand SHOULD be ignored; this row is the measurement of whether that holds, because an operator writing one server definition for a mixed fleet is relying on it.

## Observation

- **Date measured:** 2026-09-22
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Capture:** `tests/lab/evidence/L18-cisco_nxos.pcap` — 1880 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L18-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

Each variant below is one set of reply attributes on the session authorization, one daemon restart and one token login. Per variant: whether the session opened and what the device said if it did not; `show user-account %s` for what the session was given; and one `show version`, typed only to see whether the device sends per-command authorization under this reply at all.

**How the summary table's cell is derived.** It is not written by hand and it is not a reading of the attribute's name. A variant whose session never opened is `session refused`. Otherwise the variant is compared with the one named in its `read against` column, on a single value: role or roles, as `show user-account <user>` names them. Identical is `ignored`, different is `applied`. So `ignored` means the session came out indistinguishable from the one that differs only by the attribute under test, which is the only thing a lab can observe about an attribute a device chose to drop.

**Which baseline, and why it is not one fixed row.** Variants 3 to 6 send the known attribute AND the attribute under test, so that the session has something to be given and the bad attribute is the only variable; they are read against the control, which is the known attribute alone. Variants that REPLACE the whole reply -- the bad value, and on Junos the decision-22 attributes -- are read against variant 8. no attributes at all (the control for `ignored`). Reading everything against that instead would mark every row carrying the known attribute `applied`, because the known attribute was applied, and the table would then contradict the transcripts printed above it.

**The per-command reply is asked too, in three shapes.** `lab.command_attributes` puts attributes on a PERMITTED per-command authorization the way `lab.session_attributes` does on a session one, so variants 9. OPTIONAL invented attribute on a PER-COMMAND reply, 10. MANDATORY invented attribute on a PER-COMMAND reply and 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply hold the session reply constant at the control's and vary only what the command reply carries.

**Their cells are derived differently from the rest, and have to be.** Their sessions are the control's by construction, so comparing sessions would read `ignored` however the device reacted to the command reply. The cell is read off the COMMANDS instead, in this order: the session lost after a prompt was reached, or the device asking for no command authorization at all, or a command whose reply is one of this platform's refusal markers (`Authorization denied`, `AAA authorization failed`, `Cmd exec error`, `Permission denied`, `Error: AAA`), or -- the only way to `ran` -- a reply whose first line is the one the control's `show version` produced on the same device. A command that neither matched a refusal marker nor came back looking like the control's output is reported as neither, with its words printed, rather than being counted as having run.

### 1. mandatory KNOWN attribute (the control)

the control. One attribute, MANDATORY, that this platform is already measured to understand, and nothing else. Variants 3 to 6 are read against this one, so its own cell is read against the empty variant -- if the known attribute does not change the session either, this platform's signal is not sensitive enough to say anything about the others, and every cell below it says `not comparable` rather than `ignored`.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice01`:

```
user:alice01
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 2 minute(s), 56 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice01 -> permit permit_dominates
show version -> permit permit_dominates
```


### 2. OPTIONAL known attribute

the same attribute sent OPTIONAL. RFC 8907 §8.2's flag decides what a device MAY ignore, not what it may apply, so a platform that drops a known attribute merely because it is optional would be its own finding -- and would mean an adapter cannot use the flag to be polite. It REPLACES the known attribute rather than sitting beside it, so it is read against the empty reply -- `applied` here means the optional form delivered something, which is the question. Whether the flag changed WHAT it delivered is a comparison with the control, and finding 3 below makes it directly.

Reply attributes: `["priv-lvl*15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice02`:

```
user:alice02
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 8 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice02 -> permit permit_dominates
show version -> permit permit_dominates
```


### 3. OPTIONAL foreign-vendor attribute

another vendor's attribute, OPTIONAL: `roles`. vEOS reads this one and applies the role named in it (results/L16-arista_eos.md), and NX-OS reads `shell:roles` instead. This is the reply an operator gets when one server definition serves a mixed fleet and the other vendor's attributes are marked optional -- which is exactly what RFC 8907 §8.2 invites them to do. The known attribute is in the reply too, so the foreign one is the only thing separating this variant from the control.

Reply attributes: `["priv-lvl=15", "roles*network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice03`:

```
user:alice03
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 20 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice03 -> permit permit_dominates
show version -> permit permit_dominates
```


### 4. MANDATORY foreign-vendor attribute

the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that does not understand it must fail the authorization. A platform that opens the session anyway is not following §8.2, and one that opens it AND applies nothing is the worst case for an operator, who sees a working login and no privilege.

Reply attributes: `["priv-lvl=15", "roles=network-operator"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice04`:

```
user:alice04
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 32 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice04 -> permit permit_dominates
show version -> permit permit_dominates
```


### 5. OPTIONAL invented attribute

an attribute no vendor has, OPTIONAL. The foreign-vendor variants above cannot tell "this device dislikes that particular name" from "this device refuses anything it does not recognise"; this one can, and on IOS-XE it is the variant that settled it in 2026-09-20's run (results/L10-cisco_iosxe.md).

Reply attributes: `["priv-lvl=15", "p49-nonsense*1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice05`:

```
user:alice05
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 44 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice05 -> permit permit_dominates
show version -> permit permit_dominates
```


### 6. MANDATORY invented attribute

the invented attribute MANDATORY: the one cell in this table where every platform is SUPPOSED to refuse the session. A platform that opens it here is ignoring a mandatory argument, which means an adapter cannot use the mandatory flag to make a device tell it that an attribute did not land.

Reply attributes: `["priv-lvl=15", "p49-nonsense=1"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice06`:

```
user:alice06
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 56 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice06 -> permit permit_dominates
show version -> permit permit_dominates
```


### 7. known attribute, a value the device cannot use

a known attribute carrying a value the device cannot use: `priv-lvl=99`. This is the typo case rather than the mixed-fleet case, and it is a different question -- the device parses the attribute and then has to decide what to do with the value. Does it clamp, ignore the attribute, or refuse the session? It REPLACES the known attribute rather than sitting beside it, so it is read against the empty variant.

Reply attributes: `["priv-lvl=99"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice07`:

```
user:alice07
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 8 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice07 -> permit permit_dominates
show version -> permit permit_dominates
```


### 8. no attributes at all (the control for `ignored`)

no attributes at all on a permit. It is the floor of the table: what a session looks like when port49 delivers nothing. The control is read against it, and so is every variant that replaces the whole reply rather than adding to it. Without this row the table could report "ignored" only as an opinion.

Reply attributes: `[]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`show user-account alice08`:

```
user:alice08
        roles:vdc-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 20 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice08 -> permit permit_dominates
show version -> permit permit_dominates
```


### 9. OPTIONAL invented attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is an OPTIONAL attribute no vendor has -- the shape RFC 8907 §8.2 says a device SHOULD ignore, and the mildest thing that can be wrong in a reply.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["p49-nonsense*1"]`. The device said:

```
nx1# 
```

`show user-account alice09`:

```
user:alice09
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 32 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice09 -> permit permit_dominates
show version -> permit permit_dominates
```


### 10. MANDATORY invented attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is the same invented attribute sent MANDATORY, which is where §8.2 stops being a SHOULD: a device that does not understand it MUST fail the authorization. It is also the only shape that could tell an adapter its attribute did not land, so what this platform does with it decides whether the flag is worth anything on the command path.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["p49-nonsense=1"]`. The device said:

```
nx1# 
```

`show user-account alice10`:

```
user:alice10
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 44 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice10 -> permit permit_dominates
show version -> permit permit_dominates
```


### 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply

the same question asked of a PER-COMMAND authorization reply instead of a session one. The session reply is the control's, so the only difference from the control is what the command reply carries. Three of the five platforms in this row end the SESSION over an attribute like this; what it costs on the command path is a separate question, and it decides whether a per-command adapter may carry anything at all. The commands typed below are the measurement: if they run, the device tolerated the attribute; if the device refuses one, a policy permit became a refusal; if the session goes away, one attribute cost the operator every command and not just this one. Here it is another vendor's attribute, OPTIONAL: `roles`. vEOS reads this one and applies the role named in it (results/L16-arista_eos.md), and NX-OS reads `shell:roles` instead. This is the reply an operator gets when one server definition serves a mixed fleet, and it separates "this device dislikes anything unfamiliar" from "this device dislikes that particular name" without leaning on the invented one alone.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**, so everything below is the DEVICE's answer to a session port49 permitted.

**The session opened.**

`terminal length 0` — the FIRST command in the session, and so the first authorization reply to carry `["roles*network-operator"]`. The device said:

```
nx1# 
```

`show user-account alice11`:

```
user:alice11
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` — typed to see whether per-command authorization follows. The device said:

```
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.

Nexus 9000v is a demo version of the Nexus Operating System

Software
  BIOS: version 
  NXOS: version 10.4(2) [Feature Release]
  BIOS compile time:  
  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin
  NXOS compile time:  11/30/2023 12:00:00 [12/14/2023 05:25:50]

Hardware
  cisco Nexus9000 C9300v Chassis 
   with 10187692 kB of memory.
  Processor Board ID 92HBGN1962V
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 56 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice11 -> permit permit_dominates
show version -> permit permit_dominates
```


## Every variant side by side

| variant | reply attributes | outcome | what the session got | read against | per-command authorization |
|---|---|---|---|---|---|
| 1. mandatory KNOWN attribute (the control) | `["priv-lvl=15"]` | **applied** | network-admin | no attributes at all | 3 request(s) |
| 2. OPTIONAL known attribute | `["priv-lvl*15"]` | **applied** | network-admin | no attributes at all | 3 request(s) |
| 3. OPTIONAL foreign-vendor attribute | `["priv-lvl=15", "roles*network-operator"]` | ignored | network-admin | the control (same reply, minus this attribute) | 3 request(s) |
| 4. MANDATORY foreign-vendor attribute | `["priv-lvl=15", "roles=network-operator"]` | ignored | network-admin | the control (same reply, minus this attribute) | 3 request(s) |
| 5. OPTIONAL invented attribute | `["priv-lvl=15", "p49-nonsense*1"]` | ignored | network-admin | the control (same reply, minus this attribute) | 3 request(s) |
| 6. MANDATORY invented attribute | `["priv-lvl=15", "p49-nonsense=1"]` | ignored | network-admin | the control (same reply, minus this attribute) | 3 request(s) |
| 7. known attribute, a value the device cannot use | `["priv-lvl=99"]` | **applied** | network-operator | no attributes at all | 3 request(s) |
| 8. no attributes at all (the control for `ignored`) | `[]` | opened (this is the baseline) | vdc-operator | — | 3 request(s) |
| 9. OPTIONAL invented attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["p49-nonsense*1"]`** | the command ran | network-admin | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |
| 10. MANDATORY invented attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["p49-nonsense=1"]`** | the command ran | network-admin | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |
| 11. OPTIONAL foreign-vendor attribute on a PER-COMMAND reply | session `["priv-lvl=15"]`<br>**command `["roles*network-operator"]`** | the command ran | network-admin | the control's `["priv-lvl=15"]` session; the cell reads the commands | 3 request(s) |

The `what the session got` column is the verbatim `show` output above reduced to the one value the cell is derived from, and `read against` names the row it was compared with. The transcripts both come from are in each variant's section, and a cell that disagrees with the transcript above it is a defect in this generator rather than a finding about the device. The rows whose `reply attributes` name a **command** list send the control's session reply and differ from it only there, so their `what the session got` column is the control's by construction and their outcome is read off the commands.

## What this answers

**0. The measurement can see an attribute land.** The control (`["priv-lvl=15"]`) left the session `network-admin` and the empty reply (`[]`) left it `vdc-operator`, on the same device minutes apart. So when a row below reads `ignored` it means the device produced the same session as the control despite being sent something extra -- a comparison, not an assumption.

**1. This platform does what RFC 8907 §8.2 says: an optional attribute it does not understand is ignored.** All 2 of them -- `["priv-lvl=15", "roles*network-operator"]`, `["priv-lvl=15", "p49-nonsense*1"]` -- opened a session that matched the control's on role or roles, as `show user-account <user>` names them. The control carries the same reply without the extra attribute, so the attribute is what changed, and nothing changed. An adapter may send another vendor's attributes here marked optional without ending anyone's session.

**2. It does NOT do what §8.2 makes a MUST.** Measured: a MANDATORY argument this device does not understand does NOT fail the authorization on Nexus 9300v 10.4(2)F: the session opened and came out indistinguishable from the control, which is the same reply with the mandatory argument taken out. So the mandatory flag buys an adapter nothing here -- there is no way to make this device say that an attribute did not land.

Sent:

```
reply attributes ["priv-lvl=15", "p49-nonsense=1"]
then, in the session:
show user-account alice06
```

The device replied:

```
show user-account alice06
user:alice06
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

**3. A KNOWN attribute is applied under either flag.** `["priv-lvl=15"]` and `["priv-lvl*15"]` both left the session on `network-admin`, so an adapter may mark this platform's own attributes optional -- the politeness §8.2 invites -- without losing what they deliver.

**4. A known attribute with an unusable value is taken somehow.** `["priv-lvl=99"]` left the session on `network-operator`, against `vdc-operator` for the empty control. What the device did with the value is in the transcript above; this run does not name a rule for it.

**5. Every session that opened went on to per-command authorization**, 11 of 11, whatever the reply carried. So a bad attribute on this platform either ends the session outright or leaves the command path exactly as it was: there is no middle state where the session survives and the device stops asking.

**5b. The same question asked of a PER-COMMAND reply, in 3 shapes.** Each one sends the control's session attributes (`["priv-lvl=15"]`) and differs from the control only in what a PERMITTED command authorization carries, so whatever the device does below it is doing about the command reply. The control itself answered 3 command authorization(s) and ran every command typed in it.

`["p49-nonsense*1"]` on every permitted command — **ignored: the commands ran.** `show version` came back with the same first line as the control's (`Cisco Nexus Operating System (NX-OS) Software`), over 3 authorization request(s), and `terminal length 0` before it was answered normally. So this platform reads a per-command reply the way §8.2 asks: what it does not understand there costs nothing.

`["p49-nonsense=1"]` on every permitted command — **ignored: the commands ran.** `show version` came back with the same first line as the control's (`Cisco Nexus Operating System (NX-OS) Software`), over 3 authorization request(s), and `terminal length 0` before it was answered normally. So this platform reads a per-command reply the way §8.2 asks: what it does not understand there costs nothing.

`["roles*network-operator"]` on every permitted command — **ignored: the commands ran.** `show version` came back with the same first line as the control's (`Cisco Nexus Operating System (NX-OS) Software`), over 3 authorization request(s), and `terminal length 0` before it was answered normally. So this platform reads a per-command reply the way §8.2 asks: what it does not understand there costs nothing.

**The two paths, attribute by attribute.** The same attribute in the same spelling, once on the session reply and once on a command reply. Both columns are the cells from the table above, with one word changed so they can be compared: a command reply whose commands ran is written `ignored` here, which is what the session column already calls a reply that changed nothing.

| attribute | on the SESSION reply | on a COMMAND reply |
|---|---|---|
| `["p49-nonsense*1"]` | ignored | ignored |
| `["p49-nonsense=1"]` | ignored | ignored |
| `["roles*network-operator"]` | ignored | ignored |

**The two paths agree on all 3.** An adapter that knows what an attribute does to a session here knows what it does to a command, and one rule covers both replies on this platform.

**6. Every login in this run reached the device's AAA.** No SSH connection was refused before the device asked port49, so nothing here says a run of refused authorizations costs anything beyond the sessions refused.


