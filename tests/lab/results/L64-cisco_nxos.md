# L64 — cisco_nxos

- **Date measured:** 2026-10-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-cisco_nxos.pcap` — 1290 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `2c680dbfad8fed41de8176383c9e67e2f871d2eb`, `PORT49_LAB_PLATFORMS=nxos`, `-run ^TestL64L65$`

## Claim

`port49 ssh` under OpenSSH's accept-new against cisco_nxos (policy engine spec §15, L64): (a) a first contact, (b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 2c680dbfad8fed41de8176383c9e67e2f871d2eb into the shared lab venv.

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 7.4s |
| L64b | PASS | 1m57.6s |
| L64c | PASS | 16.6s |
| L64d | PASS | 37.1s |

### L64a: PASS

`port49 ssh -v nx1 -- show version` with an empty known_hosts: exit 0; 30 lines of output; ssh tried [keyboard-interactive], authenticated by `keyboard-interactive`; 1 askpass asks (the keyboard-interactive and password methods tried); 1 redeem records; 120 TACACS+ packets in the window (the positive control: it must be above 0); records: blob x1, mint x1, redeem x1, authorize_session x1, account x2, authorize_command x2. ssh: accepted. After the login `ssh-keygen -F nx1` finds 1 line(s), of key types [ssh-rsa] (a read error: <nil>); the file holds 1 line(s).

```
Warning: Permanently added 'nx1' (RSA) to the list of known hosts.
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.31 ([172.100.100.31]:22) using "keyboard-interactive".
```

### L64b: PASS

The device rebooted: true (uptime 3m47s, then 1m11s after 1m48s). The scan's key is the same after the reload (SHA256:pSpQxcWVmKr0kGjjBd/MuKYu4S6p8uD3v6w0RnlS8ng).

The filed lines (type and key, compared with the host field left out) before the reload: 1; after: 1; added by the login: none; gone after it: none.

```
reload step "configure terminal": err <nil>; the device said:
configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
reload step "boot nxos bootflash:/nxos64-cs.10.4.2.F.bin": err <nil>; the device said:
boot nxos bootflash:/nxos64-cs.10.4.2.F.bin
Performing image verification and compatibility check, please wait....
nx1(config)# 
reload step "end": err <nil>; the device said:
end
nx1# 
reload step "copy running-config startup-config": err <nil>; the device said:
copy running-config startup-config
[#                                       ]   0%[#                                       ]   1%[#                                       ]   2%[##                                      ]   3%[##                                      ]   4%[###                                     ]   5%[###                                     ]   6%[###                                     ]   7%[####                                    ]   8%[####                                    ]   9%[#####                                   ]  10%[#####                                   ]  11%[#####                                   ]  12%[######                                  ]  13%[######                                  ]  14%[######                                  ]  14%[#######                                 ]  15%[#######                                 ]  16%[#######                                 ]  17%[########                                ]  18%
reload step "reload": err <nil>; the device said:
reload
[########                                ]  19%[#########                               ]  20%[#########                               ]  21%[#########                               ]  22%[##########                              ]  23%[##########                              ]  24%[###########                             ]  25%[###########                             ]  26%[###########                             ]  27%[############                            ]  28%[############                            ]  28%[############                            ]  29%[#############                           ]  30%[#############                           ]  31%[#############                           ]  32%[##############                          ]  33%[##############                          ]  34%[###############                         ]  35%[###############                         ]  36%[###############                         ]  37%[################                        ]  38%[################                        ]  39%[#################                       ]  40%[#################                       ]  41%[#################                       ]  42%[#################                       ]  42%[##################                      ]  43%[##################                      ]  44%[###################                     ]  45%[###################                     ]  46%[###################                     ]  47%[####################                    ]  48%[####################                    ]  49%[#####################                   ]  50%[#####################                   ]  51%[#####################                   ]  52%[######################                  ]  53%[######################                  ]  54%[#######################                 ]  55%[#######################                 ]  56%[#######################                 ]  57%[#######################                 ]  57%[########################                ]  58%[########################                ]  59%[#########################               ]  60%[#########################               ]  61%[#########################               ]  62%[##########################              ]  63%[##########################              ]  64%[###########################             ]  65%[########################
... (truncated for this note; the full answer is in the test log)
```

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

After it, `port49 ssh -v nx1 -- show version`: exit 0; 30 lines of output; 120 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command authorize_command account]; ssh: clean; the warning banner is present: false.

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.31 ([172.100.100.31]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home2525898629/.ssh/known_hosts for nx1 / (none)
debug1: client_input_hostkeys: no new or deprecated keys from server
```

### L64c: PASS

`port49 ssh` against an entry replaced by a fresh `ssh-rsa` key: exit 255; ssh: changed (filed type "RSA", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending RSA key in /tmp/p49l64home2525898629/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home2525898629/.ssh/known_hosts' -R 'nx1'
Host key for nx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before nx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under nx1 is not the one 172.100.100.31 presents: either the device's key changed, or the address inventory gives for nx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home2525898629/.ssh/known_hosts -R nx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

### L64d: PASS

`port49 ssh` against an entry replaced by a `ssh-ed25519` key, a type other than the filed `ssh-rsa`: exit 255; ssh: other_type (filed type "ED25519", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending ED25519 key in /tmp/p49l64home2525898629/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home2525898629/.ssh/known_hosts' -R 'nx1'
Host key for nx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before nx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under nx1 is not the one 172.100.100.31 presents: either the device's key changed, or the address inventory gives for nx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home2525898629/.ssh/known_hosts -R nx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

