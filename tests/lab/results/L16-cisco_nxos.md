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

## Precedence: `priv-lvl` and `shell:roles` in the same reply
- **Date measured:** 2026-09-22
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Capture:** `tests/lab/evidence/L16-prec-cisco_nxos.pcap` — 2543 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L16-prec-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

L16 above sent `priv-lvl` and `shell:roles` one at a time. Each works: `priv-lvl=15` alone lands the session on `network-admin`, and a named role alone is delivered. **This section sends both at once**, which is the only shape that decides what an NX-OS adapter may put in a reply -- and the shape a read-only server definition on a production Nexus 9000 has been sending for years, with the roles attribute misnamed so that only the privilege level took effect.

Each variant below is one set of reply attributes, one daemon restart and one token login. Three probes per session: `show user-account <user>` for the role the device says it holds, `configure terminal` for whether the session reaches configuration mode, and `hostname nx1` -- a configuration command that writes the value the device already has -- for whether it can actually change anything. The last two are separate because on this image they answer differently: a `network-operator` session is admitted to configuration mode and refused the command inside it, so reaching `(config)#` is not evidence of privilege here. The custom role from the section above is defined for the run and removed after it:

```
role name p49-noc
rule 10 deny command show version
rule 5 permit command *
exit
```

### `priv-lvl=15` + `shell:roles*network-operator`

the question. The privilege level says administrator and the role says read-only, in the OPTIONAL spelling an adapter would use. Whichever the session turns out to hold is the one the device believes.

Reply attributes: `["priv-lvl=15", "shell:roles*network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice01` — the device's own word for the role this session holds:

```
user:alice01
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice01 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `priv-lvl=15` + `shell:roles=network-operator`

the same conflict with the role sent MANDATORY. If a device resolves a conflict by argument flag rather than by attribute, this is where it shows: the mandatory one is the one RFC 8907 §8.2 says the device must honour or fail.

Reply attributes: `["priv-lvl=15", "shell:roles=network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice02` — the device's own word for the role this session holds:

```
user:alice02
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice02 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `priv-lvl=1` + `shell:roles*network-admin`

the conflict inverted: the privilege level says near-nothing and the role says administrator. Without this, an answer of "the restrictive one wins" cannot be told apart from "the role wins", and they imply opposite adapter rules.

Reply attributes: `["priv-lvl=1", "shell:roles*network-admin"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice03` — the device's own word for the role this session holds:

```
user:alice03
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice03 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `priv-lvl=0` + `shell:roles=network-admin`

the inverted conflict with the role mandatory, and `priv-lvl=0` rather than 1 -- the lowest privilege the protocol can express, against the highest role the device has.

Reply attributes: `["priv-lvl=0", "shell:roles=network-admin"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice04` — the device's own word for the role this session holds:

```
user:alice04
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice04 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `shell:roles=network-operator` alone

the control for the role half: the role with NO privilege level in the reply at all. This is the reply an adapter would send under the rule "roles only", so it is also the variant that says whether that rule is safe to ship.

Reply attributes: `["shell:roles=network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice05` — the device's own word for the role this session holds:

```
user:alice05
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice05 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `priv-lvl=15` alone

the control for the privilege half, and the reply `tests/lab/port49d-lab.yaml` sends today once its `shell:roles*network-admin` is taken out. L16 measured this as `network-admin`; it is repeated here so both halves of every conflict are measured on the same deploy.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice06` — the device's own word for the role this session holds:

```
user:alice06
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice06 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `shell:roles=p49-noc` + `priv-lvl=15`

a CUSTOM role against the administrative privilege level. A built-in role might be resolved by a table the custom ones are not in, and the custom role is what plan 5 would actually deliver.

Reply attributes: `["priv-lvl=15", "shell:roles=p49-noc"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice07` — the device's own word for the role this session holds:

```
user:alice07
        roles:p49-noc 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice07 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `shell:roles=nonexistent-role` + `priv-lvl=15`

the 3am case crossed with the question. L16 measured that an unknown role name alone degrades the session to `network-operator`. With `priv-lvl=15` beside it, does the degradation still happen, or does the privilege level fill the gap and make the operator an administrator?

Reply attributes: `["priv-lvl=15", "shell:roles=nonexistent-role"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice08` — the device's own word for the role this session holds:

```
user:alice08
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice08 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


### `priv-lvl=6` alone

the owner saw `priv-lvl=6` map to `vdc-operator` on a production Nexus 9000 running NX-OS 10.3(5). This asks whether 10.4(2)F on the N9Kv agrees, which is the only part of the production reading this lab can check.

Reply attributes: `["priv-lvl=6"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice09` — the device's own word for the role this session holds:

```
user:alice09
        roles:vdc-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
nx1(config)# 
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show user-account alice09 -> permit permit_dominates
configure terminal -> permit permit_dominates
hostname nx1 -> permit permit_dominates
end -> permit permit_dominates
```


#### Every variant side by side

| reply attributes | session | role the device reports | config mode | `hostname` accepted | port49 asked about |
|---|---|---|---|---|---|
| `priv-lvl=15` + `shell:roles*network-operator` | opened | `network-operator` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `priv-lvl=15` + `shell:roles=network-operator` | opened | `network-operator` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `priv-lvl=1` + `shell:roles*network-admin` | opened | `network-admin` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `priv-lvl=0` + `shell:roles=network-admin` | opened | `network-admin` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `shell:roles=network-operator` alone | opened | `network-operator` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `priv-lvl=15` alone | opened | `network-admin` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `shell:roles=p49-noc` + `priv-lvl=15` | opened | `p49-noc` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `shell:roles=nonexistent-role` + `priv-lvl=15` | opened | `network-operator` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |
| `priv-lvl=6` alone | opened | `vdc-operator` | entered | yes | `configure terminal` 1 req (permit permit_dominates); `hostname` 1 req (permit permit_dominates) |

#### Phase B — the same question with port49 out of the command path

9 of the 9 sessions above configured the device, whatever role the device named for them. That is not the role failing to arrive -- `show user-account` names it in every row -- it is `aaa authorization commands default group port49 local` sending each command to a lab authorizer that permits everything, so the role is never consulted. Phase B points both command-authorization method lists at the device's own role database and asks the two decisive variants again:

```
aaa authorization commands default local
aaa authorization config-commands default local
```

and puts them back afterwards.


### `priv-lvl=15` + `shell:roles*network-operator`, command authorization LOCAL

the conflict again, with the device authorizing commands against the role it was handed instead of asking port49. If `network-operator` is refused configuration mode here and was allowed it above, the role is real privilege and port49's permit was what made it look like a label.

Reply attributes: `["priv-lvl=15", "shell:roles*network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice10` — the device's own word for the role this session holds:

```
user:alice10
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Permission denied for the role
nx1(config)# 
```

**No command authorization reached port49 in this session at all.**


### `priv-lvl=15` alone, command authorization LOCAL

the same control as above, under the same changed method lists: the reply that carries no role at all. It is what the `network-operator` row has to be read against, because a refusal that happens to every session under local authorization says nothing about roles.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

`show user-account alice11` — the device's own word for the role this session holds:

```
user:alice11
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

`configure terminal` (does the session reach configuration mode at all) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

`hostname nx1` (the configuration command itself, writing the value the device already holds -- this is where NX-OS enforces a role, not at the mode change) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
nx1(config)# 
```

**No command authorization reached port49 in this session at all.**


#### Every variant side by side

| reply attributes | session | role the device reports | config mode | `hostname` accepted | port49 asked about |
|---|---|---|---|---|---|
| `priv-lvl=15` + `shell:roles*network-operator`, command authorization LOCAL | opened | `network-operator` | entered | **refused** | `configure terminal` 0 req (nothing (no authorization request reached port49)); `hostname` 0 req (nothing (no authorization request reached port49)) |
| `priv-lvl=15` alone, command authorization LOCAL | opened | `network-admin` | entered | yes | `configure terminal` 0 req (nothing (no authorization request reached port49)); `hostname` 0 req (nothing (no authorization request reached port49)) |

#### What this answers

**1. `shell:roles` wins. The privilege level beside it changes nothing.** Measured: `priv-lvl=15` does NOT put the session on `network-admin` when `shell:roles*network-operator` is in the same reply. The device names the session `network-operator`, against `network-admin` for `priv-lvl=15` alone on this same deploy and the same image.

Sent:

```
reply attributes ["priv-lvl=15", "shell:roles*network-operator"]
then, in the session:
show user-account alice01
```

The device replied:

```
user:alice01
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

The same question with the role taken out of the reply, minutes later on the same device:

```
user:alice06
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

One attribute separates them.

**1b. And in this lab's configuration the role is a label and nothing more.** Measured: Holding `network-operator` did NOT stop the session configuring the device. It entered configuration mode and `hostname nx1` was accepted, because `aaa authorization commands default group port49 local` sends every command to port49, which permitted it. The role the device named is not consulted while port49 is in the command path -- the same shape L16 found with `p49-noc` and `show version`.

Sent:

```
reply attributes ["priv-lvl=15", "shell:roles*network-operator"]
then, in the session:
hostname nx1
```

The device replied:

```
nx1(config)# 
```

So the configuration probe does not separate the roles in phase A, and a reading that took it for a privilege measurement would have reported the opposite of question 1. Phase B is where the role gets asked.

**2. The argument flag does not change it.** `shell:roles=network-operator` sent MANDATORY names the same role as the optional spelling, `network-operator`, and the session opened either way. RFC 8907 §8.2's mandatory/optional distinction decides whether a device may ignore an attribute; this device ignores it under neither flag.

**3. Inverted, the answer is the same one.** `priv-lvl=1` with `shell:roles*network-admin` names `network-admin`, and `priv-lvl=0` with the same role mandatory names `network-admin`. A reply whose privilege level says 0 or 1 still puts the session on the administrative role, so this is not "the more restrictive of the two wins": it is the role, in both directions, whatever the privilege level says.

**4. The role alone is enough, and that is what makes the rule shippable.** With NO `priv-lvl` in the reply at all, port49 answered the session authorization `permit context_matched`, the session opened, and the device named it `network-operator` -- the same role as when `priv-lvl=15` was sent beside it. Dropping `priv-lvl` from an NX-OS reply costs nothing this run can see.

**5. An unknown role name still degrades the session, with `priv-lvl=15` beside it.** `shell:roles=nonexistent-role` names `network-operator`. The privilege level does not fill the gap, so a policy naming a role this device does not have leaves the operator where L16 found them -- and port49 cannot tell: the reply it sent and the record it wrote are byte-identical to the case where the role exists.

**6. `priv-lvl=6` alone gives `vdc-operator`** on Nexus 9300v 10.4(2)F. The owner's production Nexus 9000 on NX-OS 10.3(5) maps 0 and 6 to `vdc-operator` and 15 to `network-admin`; this image agrees on 6. Read with question 1, that is the whole danger of `priv-lvl` here: with no role in the reply the device picks a role nobody named, and which one it picks is a per-release mapping.

**7. With port49 out of the command path, the delivered role is real privilege.** Measured: Under `aaa authorization commands default local`, a session delivered `shell:roles*network-operator` beside `priv-lvl=15` CANNOT change the device: `hostname nx1` is refused. The same reply with `priv-lvl=15` and no role runs it. So the role the reply names is what the device enforces once the device is the one enforcing, and `priv-lvl=15` does not override it.

Sent:

```
reply attributes ["priv-lvl=15", "shell:roles*network-operator"]
then, in the session:
hostname nx1
```

The device replied:

```
% Permission denied for the role
nx1(config)# 
```

The control, same method lists, same minute, no role in the reply, the same command:

```
nx1(config)# 
```

That is the pair phase A could not produce: same device, same port49, one attribute apart, opposite outcomes.

**Where the device enforces it is worth knowing for its own sake.** The `network-operator` session was allowed INTO configuration mode and refused the command inside it. `configure terminal` answered:

```
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
```

so a probe that only checked for the `(config)#` prompt would have concluded the role does not bind. Reaching configuration mode is not evidence of privilege on this platform.

**The adapter rule this supports: on NX-OS send `shell:roles` and never `priv-lvl`.** Whenever both are in the reply the device takes the role and ignores the privilege level, in both directions -- `priv-lvl=15` with `network-operator` is a read-only account, `priv-lvl=0` with `network-admin` is an administrator. The role alone opens a session and is delivered, so nothing is lost by leaving `priv-lvl` out. Leaving it IN costs something real: it is inert here and it is the attribute that governs the session on every other platform in this lab, so an adapter that computes one and sends it to NX-OS is writing a privilege into the log that the device did not apply -- and `priv-lvl` with no role is how a reply silently picks a role nobody named (`15` to `network-admin`, `6` to `vdc-operator`, per-release). **Phase B is what makes this a privilege claim rather than a labelling one:** with the device authorizing its own commands, the same reply that names `network-operator` is refused `hostname nx1` and the one carrying `priv-lvl=15` alone runs it. The role port49 sends is the operator's real privilege on a device that enforces it, which is the state a fleet is in before port49 owns command authorization.

Every other cell -- the custom role beside `priv-lvl=15`, the `privilege` the device asserted on each request, how many authorization requests each command cost -- is in the tables above, and each one is what that variant's session did on Nexus 9300v 10.4(2)F.
