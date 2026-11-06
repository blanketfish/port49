# L7 — cisco_nxos

- **Date measured:** 2026-11-06
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L7-nxapi-cisco_nxos.pcap` — 320 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L7-nxapi-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** NX-API over HTTPS `ins_api`

## Claim

Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests.

## Observation

Transport measured: **NX-API (HTTPS `ins_api`, `cli_show` and `cli_conf`)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| cli_show `show version` | `nxapi01` | yes | 1 | 1 | 2 | start=1 | 6.73s |
| cli_show again, same token | `nxapi01` | yes | 1 | 1 | 2 | none | 1.02s |
| cli_conf `snmp-server location` | `nxapi02` | yes | 1 | 1 | 3 | start=1, stop=1 | 5.88s |

### Does a second request with the same token re-authenticate?

**Yes, for a client shaped like this one.** The first request as `nxapi01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. **This client sends HTTP Basic credentials on a fresh TCP connection every call** (`DisableKeepAlives`, no cookie jar), so what is measured here is that the device runs AAA for each such request — not that the transport cannot do better. The `/login` session-cookie flow and HTTP keep-alive are the obvious ways a real client avoids this, and both are separately measured (L7).

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, username, credential_sha256)` rather than out of the store — the same credential hashes to the same key, so a repeat finds its own receipt. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **the receipt's two bounds**: the sliding `receipt_idle_ttl`, which every answered call pushes out, and `receipt_max_age`, which is measured from the first redemption and never moves. Past either, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: (empty string), `0`
- `rem_addr`: (empty string), `172.100.100.1`
- `auth.method`: `pap`

These are the values this transport produced. Compare them with the SSH figures in `L1-cisco_nxos.md`. Nothing keys on `port` any more (spec §13, decision 15), so a transport reporting the same constant as SSH no longer costs anything; what these values are still for is accounting annotation and the record an operator reads at 3am.

### How many TCP connections the device opened to port49d

**32** TCP connection(s) were opened toward port49d during this test, from source port(s) 33700, 33712, 33716, 33726, 47276, 47288, 48120, 48128, 48134, 51788, 51800, 51814, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/evidence/L7-nxapi-cisco_nxos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**cli_show `show version`** (as `nxapi01`)

```
2026-11-06T09:24:06.606Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-11-06T09:24:06.624Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-11-06T09:24:06.781Z event=account verdict= reason= flags=start port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1793957045
    accounting AV: timezone=UTC
    accounting AV: service=none
2026-11-06T09:24:12.393Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-11-06T09:24:13.317Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"type":	"cli_show",
		"version":	"1.0",
		"sid":	"eoc",
		"outputs":	{
			"output":	{
				"input":	"show version",
				"msg":	"Success",
				"code":	"200",
				"body":	{
					"header_str":	"Cisco Nexus Operating System (NX-OS) Software\nTAC support: http://www.cisco.com/tac\nDocuments: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html\nCopyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.\nThe copyrights to certain works contained herein are owned by\nother third parties and are used and distributed under license.\nSome parts of this software are covered under the GNU Public\nLicense. A copy of the license is available at\nhttp://www.gnu.org/licenses/gpl.html.\n\nNexus 9000v is a demo version of the Nexus Operating System\n",
					"bios_ver_str":	"",
					"nxos_ver_str":	"10.4(2)",
					"release_type":	"Feature Release",
					"bios_cmpl_time":	"",
					"nxos_file_name":	"bootflash:///nxos64-cs.10.4.2.F.bin",
					"nxos_cmpl_time":	"11/30/2023 12:00:00",
					"nxos_tmstmp":	"12/14/2023 05:25:50",
					"chassis_id":	"cisco Nexus9000 C9300v Chassis",
					"cpu_name":	"",
					"memory":	10187692,
					"mem_type":	"kB",
					"proc_board_id":	"95MH2CAI14U",
					"host_name":	"nx1",
					"bootflash_size":	4495360,
					"kern_uptm_days":	0,
					"kern_uptm_hrs":	0,
					"kern_uptm_mins":	3,
					"kern_uptm_secs":	0,
					"rr_reason":	"Unknown",
					"rr_sys_ver":	"",
					"rr_service":	"",
					"plugins":	"Core Plugin, Ethernet Plugin",
					"manufacturer":	"Cisco Systems, Inc.",
					"TABLE_package_list":	{
						"ROW_package_list":	{
							"package_id":	""
						}
					}
				}
			}
		}
	}
}
```

**cli_show again, same token** (as `nxapi01`)

```
2026-11-06T09:24:23.367Z event=redeem verdict=permit reason=receipt_replayed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-11-06T09:24:23.386Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-11-06T09:24:23.423Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-11-06T09:24:24.370Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"type":	"cli_show",
		"version":	"1.0",
		"sid":	"eoc",
		"outputs":	{
			"output":	{
				"input":	"show version",
				"msg":	"Success",
				"code":	"200",
				"body":	{
					"header_str":	"Cisco Nexus Operating System (NX-OS) Software\nTAC support: http://www.cisco.com/tac\nDocuments: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html\nCopyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved.\nThe copyrights to certain works contained herein are owned by\nother third parties and are used and distributed under license.\nSome parts of this software are covered under the GNU Public\nLicense. A copy of the license is available at\nhttp://www.gnu.org/licenses/gpl.html.\n\nNexus 9000v is a demo version of the Nexus Operating System\n",
					"bios_ver_str":	"",
					"nxos_ver_str":	"10.4(2)",
					"release_type":	"Feature Release",
					"bios_cmpl_time":	"",
					"nxos_file_name":	"bootflash:///nxos64-cs.10.4.2.F.bin",
					"nxos_cmpl_time":	"11/30/2023 12:00:00",
					"nxos_tmstmp":	"12/14/2023 05:25:50",
					"chassis_id":	"cisco Nexus9000 C9300v Chassis",
					"cpu_name":	"",
					"memory":	10187692,
					"mem_type":	"kB",
					"proc_board_id":	"95MH2CAI14U",
					"host_name":	"nx1",
					"bootflash_size":	4495360,
					"kern_uptm_days":	0,
					"kern_uptm_hrs":	0,
					"kern_uptm_mins":	3,
					"kern_uptm_secs":	11,
					"rr_reason":	"Unknown",
					"rr_sys_ver":	"",
					"rr_service":	"",
					"plugins":	"Core Plugin, Ethernet Plugin",
					"manufacturer":	"Cisco Systems, Inc.",
					"TABLE_package_list":	{
						"ROW_package_list":	{
							"package_id":	""
						}
					}
				}
			}
		}
	}
}
```

**cli_conf `snmp-server location`** (as `nxapi02`)

```
2026-11-06T09:24:34.422Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-11-06T09:24:34.440Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-11-06T09:24:34.595Z event=account verdict= reason= flags=start port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1793957073
    accounting AV: timezone=UTC
    accounting AV: service=none
2026-11-06T09:24:40.205Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=terminal
    request AV: cmd-arg=<cr>
2026-11-06T09:24:40.220Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=snmp-server
    request AV: cmd-arg=location
    request AV: cmd-arg=port49-lab-nxapi
    request AV: cmd-arg=<cr>
2026-11-06T09:24:40.282Z event=authorize_command verdict=permit reason=permit_dominates port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
2026-11-06T09:24:40.282Z event=account verdict= reason= flags=stop port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1793957079
    accounting AV: timezone=UTC
    accounting AV: cmd=configure terminal ; snmp-server location port49-lab-nxapi (SUCCESS)
    accounting AV: service=none
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"version":	"1.0",
		"sid":	"eoc",
		"type":	"cli_conf",
		"outputs":	{
			"output":	{
				"code":	"200",
				"msg":	"Success",
				"body":	{
			}
			}
		}
	}
}
```

### The requests that were sent

Read (steps 1 and 2), POSTed to `https://172.100.100.31/ins` with HTTP Basic authentication, the token as the password:

```json
{
  "ins_api": {
    "chunk": "0",
    "input": "show version",
    "output_format": "json",
    "sid": "1",
    "type": "cli_show",
    "version": "1.0"
  }
}
```

Configuration (step 3):

```json
{
  "ins_api": {
    "chunk": "0",
    "input": "snmp-server location port49-lab-nxapi",
    "output_format": "json",
    "sid": "1",
    "type": "cli_conf",
    "version": "1.0"
  }
}
```


### Not measured

- The NX-API JSON-RPC dialect (`Content-Type: application/json-rpc`, `"method": "cli"`). Only the `ins_api` envelope is measured here, and the two are different code paths on the device.
- The NX-API sandbox and any cookie or session id the device may hand back in `sid`; every request here sends `sid: "1"` and carries HTTP Basic credentials.
- HTTP keep-alive: each step opens its own TCP connection.
- `aaa authentication login ascii-authentication` is left at the NX-OS default, so the `auth.method` reported above is whatever that default produces. The other setting is unmeasured.
- Whether `aaa authorization config-commands` changes what step 3 sends; this run has it configured and nothing to compare it against.

