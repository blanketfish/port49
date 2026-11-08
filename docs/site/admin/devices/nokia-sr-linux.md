---
title: Nokia SR Linux
description: Configuring Nokia SR Linux to authenticate logins through port49, and what it does not send.
platforms:
  - nokia_srlinux
---

# Nokia SR Linux

SR Linux sends no command authorization to port49, so port49's command policy does not apply on it: a command the policy would deny still runs, and the roles configured on the device decide what a user may run. Accounting start and stop records still reach port49 ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md), cell e; [L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md)). Measured on SR Linux 26.7.2-519, over TACACS+ on port 49 only: there is no TLS reference file for this platform.

## Reference configuration

Load [`nokia_srlinux.cli`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/nokia_srlinux.cli) and replace each placeholder (the [placeholders table](index.md#placeholders) says what each is). Set the break-glass account's password by hand: no file holds one.

SR Linux needs a `platforms:` block in the port49 policy file, or every login is refused, because platform set 1.3.0 has no `nokia_srlinux` adapter and the generic adapter sends no priv-lvl ([QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.md)). The block is [`policy-platforms.yaml`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/policy-platforms.yaml); [Policy](../policy.md#platform-sets) says how platform sets work. The lines that matter most, quoted from the file:

```text
authentication {
    exit-on-reject true
    authentication-method [
        port49
        local
    ]
}
authorization {
    role p49-read {
        services [ cli ]
        tacacs {
            priv-lvl 1
        }
    }
    role p49-admin {
        services [ cli ]
        tacacs {
            priv-lvl 15
        }
    }
}
server-group port49 {
    type tacacs
    tacacs {
        priv-lvl-authorization true
    }
}
```

## What the lab measured

- With `priv-lvl-authorization true` the device asks port49 for the session's privilege level and for nothing per command, whatever the user types ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md), cell b).
- With `exit-on-reject true` a port49 deny is final. With the default, false, a person port49 denies still gets in if the device has a local account for them ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md), cell d).
- Break-glass logs in with port49d stopped (50 ms), with port49d dark (2.4 s, and a command ran), and during a store hang (first login at once, 2.9 s). All three held with `exit-on-reject true` ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md), cells b, c, d; [L87-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L87-nokia_srlinux.md), cell b).
- With the first server resetting every connection at accept, a token login reached the second server in 2.3 s ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md), cell f).
- A command port49's policy denies on other platforms ran and printed output; port49 received no command authorization ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md), cell e).
- The operator level maps to priv-lvl 1, so an operator is read-only here: only levels 1 and 15 were measured ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md)).

- At 3am break-glass logs in at once whether port49d is stopped, dark or hung ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md)); the one case it is refused is while port49 is up and denies it, as above. [Troubleshooting](../../operate/troubleshooting/index.md#break-glass-does-not-work) has the rest.

## Traps

- `priv-lvl-authorization` defaults to false, and then the device sends port49 no authorization at all (0 requests): every user port49 authenticates gets whatever the device grants without it. Set it `true` ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md), section i).
- A local role grants no service unless `services` lists one, and a user whose roles grant none is refused and the session closed. List `services [ cli ]` on every role you map ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md)).
- `source-address` must be an address configured on an interface of the network instance. The management address is DHCP-learned and the commit refused it; the lab deleted the dhcp-client and set a static address in one commit ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md)).
- `exit-on-reject true` makes a port49 deny final, and costs one thing: the break-glass account is refused while port49 is up and denies it ([L76-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md), cell l).
- SR Linux has no single-connection setting in its schema, so a reload has no shared connection to reset ([L88-nokia_srlinux.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux.md), cell g, observed).

## Unmeasured

!!! warning "Unmeasured: TLS on SR Linux"
    Whether SR Linux speaks RFC 9887 is unknown (L92, open). The schema has `server tls-profile`. One observation on 26.7.2: with a profile set and port 300 the client sent plain TACACS+ (first byte `0xc0`, not `0x16`) with no error and no TLS line in its aaa log ([the TLS observation](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-nokia_srlinux-tls.md)). That is not a finding that the device cannot do TLS, and it is not a promise that it can. Keep SR Linux on port 49 with the shared key, and do not count on a profile for confidentiality.

!!! warning "Unmeasured: commands in sessions already open"
    What SR Linux does with a session that is already open when port49 stops is unknown: the lab did not run it.

!!! warning "Unmeasured: the default is full admin"
    That `priv-lvl-authorization false` grants full admin comes from the image's own YANG, not from a run: the lab measured only reads as that user ([the SR Linux privilege note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L76-nokia_srlinux.md), section i). Treat it as true and set the option.

## Lab evidence

--8<-- "docs/site/_snippets/evidence/nokia-sr-linux.md"
