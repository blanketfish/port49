# L16 — cisco_nxos

- **Date measured:** 2026-09-21
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L16-cisco_nxos.pcap` — 1549 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L16-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a custom role delivered by name over TACACS+ takes effect on EOS and NX-OS; whether a command that role forbids is refused locally and whether the device still sends a per-command authorization request for it; which wins when the device's role and port49 disagree, in both directions; two roles at once; a role the device does not have; no role attribute at all; the accepted spellings of the attribute; and the `priv-lvl=N` to role mapping.

## Observation

The device holds one custom role, defined for this test and removed afterwards:

```
role name p49-noc
rule 10 deny command show version
rule 5 permit command *
exit
```

It permits everything and denies exactly one command, so one variable separates the two probes that matter. The three probes are `show version` (the role denies it, port49 permits it), `show clock` (the role permits it, port49 denies it — it is the last entry of `lab.deny_prefixes`), and `show hostname` (both permit it, the control). Each variant below is one set of reply attributes, one daemon restart and one token login.

### no role attribute at all

the control. Whatever the device does here is what a role delivery has to be measured against, and it is also what port49 sends today on every platform but NX-OS.

Reply attributes: `["priv-lvl=15"]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:admin
        this user account has no expiry date
        roles:network-admin 
user:breakglass
        this user account has no expiry date
        roles:network-admin 
user:alice01
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 2 minute(s), 58 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### `shell:roles*<role>` — bare, OPTIONAL

the spelling `tests/lab/port49d-lab.yaml` has been sending since the N9Kv asked for it, with the custom role in place of `network-admin`. Nothing has ever checked that the device applies it.

Reply attributes: `["priv-lvl=15", "shell:roles*p49-noc"]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 11 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### `shell:roles=<role>` — bare, MANDATORY

the same attribute sent as mandatory. RFC 8907 §8.2 says a device that does not understand a mandatory argument must fail the authorization, so this variant also asks whether the device understands it at all.

Reply attributes: `["priv-lvl=15", "shell:roles=p49-noc"]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 23 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### inside `cisco-av-pair`

the spelling Cisco documentation uses for NX-OS. If both work the adapter has a choice; if only one does, plan 5 has no choice at all.

Reply attributes: `["priv-lvl=15", "cisco-av-pair*shell:roles=\"p49-noc\""]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice04
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 36 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### two roles at once

NX-OS documents a union with permit winning. If that holds, a role delivered alongside a permissive one is not a restriction, which is the whole point of delivering it.

Reply attributes: `["priv-lvl=15", "shell:roles*\"p49-noc network-operator\""]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:admin
        this user account has no expiry date
        roles:network-admin 
user:breakglass
        this user account has no expiry date
        roles:network-admin 
user:alice01
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice04
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice05
        roles:p49-noc network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 48 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### a role the device does not have

the 3am case: a policy names a role that was renamed or never created on this device. Does the operator get no privileges, all of them, or no session?

Reply attributes: `["priv-lvl=15", "shell:roles*p49-nosuchrole"]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:admin
        this user account has no expiry date
        roles:network-admin 
user:breakglass
        this user account has no expiry date
        roles:network-admin 
user:alice01
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice04
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice05
        roles:p49-noc network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice06
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 1 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


### `priv-lvl=1` alone

the privilege-level path rather than the role path, for the mapping half of this row. On NX-OS this is only meaningful with `feature privilege`, and this lab does not configure it, so what the device does with it here is itself the finding.

Reply attributes: `["priv-lvl=1"]`

`show user-account` — the `roles:` line names the roles NX-OS believes this session holds:

```
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice04
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice05
        roles:p49-noc network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice07
        roles:vdc-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 4 minute(s), 13 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# 
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
nx1 
nx1# 
```


## Every variant side by side

| reply attributes | session | role reported | `show version` (role denies) | `show clock` (port49 denies) | `show hostname` (control) |
|---|---|---|---|---|---|
| no role attribute at all | opened | `network-admin` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `shell:roles*<role>` — bare, OPTIONAL | opened | `p49-noc` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `shell:roles=<role>` — bare, MANDATORY | opened | `p49-noc` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| inside `cisco-av-pair` | opened | `p49-noc` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| two roles at once | opened | `p49-noc network-operator` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| a role the device does not have | opened | `network-operator` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `priv-lvl=1` alone | opened | `vdc-operator` | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |

## What this answers

**1. The role IS delivered, and its own command rules do NOT bind.** The device reports `p49-noc` for this session, against `network-admin` with no attribute sent, so the name reached it and was applied to the account. But `show version` -- which the role denies with an explicit rule -- **ran anyway**, and port49 had answered `permit permit_dominates` for it with 1 authorization request(s).

That is the shape to take away: on this platform a delivered role is an **identity label**, not a second command-authorization policy, while `aaa authorization commands` points at TACACS+. port49 decides the command; the role decides what the account is. The two do not compete, which is the good news -- and it means a role cannot be used to constrain a session that port49 has permitted.

The device's own words for this session:

```
user:alice02
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

and for `show version`:

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
   with 10187700 kB of memory.
  Processor Board ID 9BFJBM9IYXH
  Device name: nx1
  bootflash:    4495360 kB

Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 11 second(s)

Last reset 
  Reason: Unknown
  System version: 
  Service: 

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):
        
nx1# 
```

**3. port49's deny wins over the role's permit.** `show clock` is permitted by the role and denied by port49 (`deny no_permit_dominates_deny`), and the device refused it. So a per-command deny is real on this platform whatever the role says.

Every other question — the spellings, two roles at once, an absent role, `priv-lvl=1` — is answered by the table above, cell by cell, and each cell is what that variant's session did.

