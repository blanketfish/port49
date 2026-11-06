# L26c-scripts — juniper_vjunos-router

- **Date measured:** 2026-11-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L26c-scripts-juniper_vjunos-router.pcap` — 1935 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L26c-scripts-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL26cEntryScripts$`

## Claim

Whether `deny-commands "junoscript"` beside a deny of `show configuration` also refuses an `op url` script's `jcs:invoke` RPCs and REST's `/rpc`, and what `scp` of `/config/juniper.conf.gz` reads under each class; against the same reply less the junoscript deny and a control with the same bits and no deny (spec §15 L26c; plan 9b1 Task 3, cells b and e).

## Observation

The classes were committed: commit complete. REST: commit complete, with the forwarding knob `system services ssh allow-tcp-forwarding`.

The op script, at `/var/tmp/p49-entry-op.slax`:

```
version 1.0;
ns junos = "http://xml.juniper.net/junos/*/junos";
ns xnm = "http://xml.juniper.net/xnm/1.1/xnm";
ns jcs = "http://xml.juniper.net/junos/commit-scripts/1.0";
match / {
    <op-script-results> {
        var $v = jcs:invoke("get-software-information");
        <output> "P49OP-VERSION " _ $v//host-name;
        var $rpc = <get-configuration> { <configuration> { <system>; } }
        var $g = jcs:invoke($rpc);
        <output> "P49OP-CONFIG " _ count($g//host-name);
    }
}
```

| class | reply | why |
|---|---|---|
| W | `["local-user-name=p49-ent-vc", "deny-commands=^( *show +configuration( .*)? *(\\\|.*)?\| *junoscript( .*)? *(\\\|.*)?)$"]` | view view-configuration; deny show configuration and junoscript (set 1.2.0's reply) |
| V | `["local-user-name=p49-ent-vc", "deny-commands=^ *show +configuration( .*)? *(\\\|.*)?$"]` | view view-configuration; deny show configuration only (the hole) |
| C | `["local-user-name=p49-ent-vc"]` | view view-configuration; no deny (the control) |
| Vw | `["local-user-name=p49-ent-v"]` | view alone; no deny (scp only) |

| probe | W | V | C | Vw |
|---|---|---|---|---|
| op url: script | version and configuration | version and configuration | version and configuration | — |
| rest: get-configuration | not observed | not observed | not observed | — |
| scp /config/juniper.conf.gz | refused | refused | refused | refused |

### Verdict against the control

| probe | W | V |
|---|---|---|
| op url: script | reached | reached |
| rest: get-configuration | not observed | not observed |
| scp /config/juniper.conf.gz | runs nowhere | runs nowhere |

### W

`op url: script`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 1

alice01@srx1> 
```

`rest: get-configuration`:

```
tunnel: Post "http://127.0.0.1:3000/rpc": ssh: rejected: connect failed ("open failed")
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

### V

`op url: script`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 1

alice04@srx1> 
```

`rest: get-configuration`:

```
tunnel: Post "http://127.0.0.1:3000/rpc": ssh: rejected: connect failed ("open failed")
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

### C

`op url: script`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 1

alice07@srx1> 
```

`rest: get-configuration`:

```
tunnel: Post "http://127.0.0.1:3000/rpc": ssh: rejected: connect failed ("open failed")
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

### Vw

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

### Gates (plan 9b1)

- G1, `op`: under W the script printed version and configuration: reached past the junoscript deny; `op` goes on set 1.2.0's list.
- G2, `rest`: under W not observed: not measured; `rest` is handled as reached (fails closed).

