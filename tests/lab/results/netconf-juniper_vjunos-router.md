# netconf — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/netconf-juniper_vjunos-router.pcap` — 1712 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/netconf-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** NETCONF over SSH (port 830)

## Claim

Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does, whether any authorization request is sent for the session or for an `<edit-config>` and with what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and whether a second session with the same token re-authenticates.

## Observation

Transport measured: **NETCONF over SSH (port 830)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 0 | start=2, stop=4 | 130ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 0 | start=2, stop=4 | 460ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 1 | 0 | start=2, stop=3 | 160ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: (empty string), `non-tty`
- `rem_addr`: (empty string), `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-juniper_vjunos-router.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**170** TCP connection(s) were opened toward port49d during this test, from source port(s) 35858, 35872, 35878, 35888, 35896, 35902, 35916, 35918, 35928, 35944, 35960, 35962, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/evidence/netconf-juniper_vjunos-router.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T17:36:33.413Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="" rem_addr="172.100.100.1"
2026-09-20T17:36:33.413Z event=authorize_session verdict=deny reason=service_unsupported port="" rem_addr="172.100.100.1"
    request AV: service=junos-exec
2026-09-20T17:36:35.870Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14362
    accounting AV: cmd=login
2026-09-20T17:36:35.871Z event=account verdict= reason= flags=stop port="non-tty" rem_addr=""
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: session_pid = 14362
    accounting AV: cmd=xml-mode netconf need-trailer <cr>
2026-09-20T17:36:35.876Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14362
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
2026-09-20T17:36:35.878Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14361
    accounting AV: cmd=login
2026-09-20T17:36:35.878Z event=account verdict= reason= flags=stop port="non-tty" rem_addr=""
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: session_pid = 14361
    accounting AV: cmd=get-config<cr>
2026-09-20T17:36:35.879Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14361
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
```

What the device answered:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<data>
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:commit-seconds="1789925773" junos:commit-localtime="2026-09-20 17:36:13 UTC" junos:commit-user="root">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
            <user>
                <name>breakglass</name>
                <uid>2002</uid>
                <class>super-user</class>
                <authentication>
                <junos:comment>/* This is a SHA-512 crypt hash of breakglassPassword in
                   tests/lab/harness_test.go -- that constant is the source of
                   truth for the plaintext, and this line is only its hash.
                   Regenerate with `openssl passwd -6 -salt p49labsalt` over
                   that same constant if it ever changes. Neither is a secret:
                   both are published lab constants in a public repository, and
                   the account exists only inside this containerlab topology.

                   It is a hash rather than plain-text-password-value because
                   that form does not produce a usable password on vSRX
                   21.4R3.15. Junos normally converts it to an
                   encrypted-password at commit; on that image it does not, and
                   the account ended up with a disabled password field in
                   /etc/master.passwd -- cannot authenticate with one -- so every
                   refused breakglass login there said nothing about
                   authentication-order, because there was nothing to fall
                   through TO. Measured 2026-09-20 off the console, in
                   tests/lab/results/juniper_vsrx-config-verified.md.

                   Verified after this change on BOTH images: breakglass logs
                   in over SSH with port49d not running. Do not go back to
                   plain-text-password-value. */</junos:comment>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
            <user>
                <name>remote</name>
                <uid>2001</uid>
                <class>p49-readonly</class>
            </user>
        </login>
        <junos:comment>/* NETCONF over SSH, for the transport tests in tests/lab/transport_test.go.
       Junos serves NETCONF on TCP 830 once this statement is committed and on
       nothing at all until then, so without this line the NETCONF tests fail on
       a connection refused that reads like a device fault rather than a missing
       statement. It is the only thing in this file that is not about TACACS+.

       On comment syntax, once more: never write a closing slash-star pair
       inside comment prose. The long note above authentication-order explains
       what that cost the first time. */</junos:comment>
        <services>
            <netconf>
                <ssh>
                </ssh>
            </netconf>
            <ssh>
                <root-login>allow</root-login>
            </ssh>
        </services>
        <management-instance/>
        <junos:comment>/* `password` is listed so that a local account can still log in while
       port49 is not an
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T17:36:43.574Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="" rem_addr="172.100.100.1"
2026-09-20T17:36:43.575Z event=authorize_session verdict=deny reason=service_unsupported port="" rem_addr="172.100.100.1"
    request AV: service=junos-exec
2026-09-20T17:36:45.928Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14473
    accounting AV: cmd=login
2026-09-20T17:36:45.929Z event=account verdict= reason= flags=stop port="non-tty" rem_addr=""
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: session_pid = 14473
    accounting AV: cmd=xml-mode netconf need-trailer <cr>
2026-09-20T17:36:45.930Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14473
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
2026-09-20T17:36:45.931Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14472
    accounting AV: cmd=login
2026-09-20T17:36:45.932Z event=account verdict= reason= flags=stop port="non-tty" rem_addr=""
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: session_pid = 14472
    accounting AV: cmd=get-config<cr>
2026-09-20T17:36:45.933Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14472
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
```

What the device answered:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<data>
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:commit-seconds="1789925773" junos:commit-localtime="2026-09-20 17:36:13 UTC" junos:commit-user="root">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
            <user>
                <name>breakglass</name>
                <uid>2002</uid>
                <class>super-user</class>
                <authentication>
                <junos:comment>/* This is a SHA-512 crypt hash of breakglassPassword in
                   tests/lab/harness_test.go -- that constant is the source of
                   truth for the plaintext, and this line is only its hash.
                   Regenerate with `openssl passwd -6 -salt p49labsalt` over
                   that same constant if it ever changes. Neither is a secret:
                   both are published lab constants in a public repository, and
                   the account exists only inside this containerlab topology.

                   It is a hash rather than plain-text-password-value because
                   that form does not produce a usable password on vSRX
                   21.4R3.15. Junos normally converts it to an
                   encrypted-password at commit; on that image it does not, and
                   the account ended up with a disabled password field in
                   /etc/master.passwd -- cannot authenticate with one -- so every
                   refused breakglass login there said nothing about
                   authentication-order, because there was nothing to fall
                   through TO. Measured 2026-09-20 off the console, in
                   tests/lab/results/juniper_vsrx-config-verified.md.

                   Verified after this change on BOTH images: breakglass logs
                   in over SSH with port49d not running. Do not go back to
                   plain-text-password-value. */</junos:comment>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
            <user>
                <name>remote</name>
                <uid>2001</uid>
                <class>p49-readonly</class>
            </user>
        </login>
        <junos:comment>/* NETCONF over SSH, for the transport tests in tests/lab/transport_test.go.
       Junos serves NETCONF on TCP 830 once this statement is committed and on
       nothing at all until then, so without this line the NETCONF tests fail on
       a connection refused that reads like a device fault rather than a missing
       statement. It is the only thing in this file that is not about TACACS+.

       On comment syntax, once more: never write a closing slash-star pair
       inside comment prose. The long note above authentication-order explains
       what that cost the first time. */</junos:comment>
        <services>
            <netconf>
                <ssh>
                </ssh>
            </netconf>
            <ssh>
                <root-login>allow</root-login>
            </ssh>
        </services>
        <management-instance/>
        <junos:comment>/* `password` is listed so that a local account can still log in while
       port49 is not an
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T17:36:54.053Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="" rem_addr="172.100.100.1"
2026-09-20T17:36:54.054Z event=authorize_session verdict=deny reason=service_unsupported port="" rem_addr="172.100.100.1"
    request AV: service=junos-exec
2026-09-20T17:36:55.935Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14509
    accounting AV: cmd=login
2026-09-20T17:36:55.937Z event=account verdict= reason= flags=stop port="non-tty" rem_addr=""
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: session_pid = 14509
    accounting AV: cmd=xml-mode netconf need-trailer <cr>
2026-09-20T17:36:55.938Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14509
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
2026-09-20T17:36:55.938Z event=account verdict= reason= flags=start port="non-tty" rem_addr=""
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14508
    accounting AV: cmd=login
2026-09-20T17:36:55.939Z event=account verdict= reason= flags=stop port="non-tty" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: session_pid = 14508
    accounting AV: elapsed_time=0
    accounting AV: cmd=logout
```

What the device answered:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>permission denied</error-message>
<error-info>
<bad-element>edit-config</bad-element>
</error-info>
</rpc-error>
</rpc-reply>

--- commit ---
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>permission denied</error-message>
<error-info>
<bad-element>commit</bad-element>
</error-info>
</rpc-error>
</rpc-reply>
```

### The requests that were sent

NETCONF over the SSH `netconf` subsystem on **port 830**, the token presented as the SSH password exactly as the interactive tests present one.

Read (sessions 1 and 2):

```xml
<get-config><source><running/></source></get-config>
```

Write (session 3), target `candidate`:

```xml
<configuration><snmp><location>port49-lab-netconf</location></snmp></configuration>
```

**The write payload above is unverified.** It was written from model documentation and has never been sent to this image. If the reply is an `<rpc-error>`, that error — not the documentation — is what the payload should be rewritten from.

The device's NETCONF hello:

```xml
<!-- No zombies were killed during the creation of this user interface -->
<!-- user remote, class j-p49-readonly -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file</capability>
    <capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:url:1.0?scheme=http,ftp,file</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
    <capability>http://xml.juniper.net/dmi/system/1.0</capability>
    <capability>http://yang.juniper.net/junos/jcmd?module=junos-configuration-metadata&amp;revision=2021-09-01</capability>
  </capabilities>
  <session-id>14361</session-id>
</hello>
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

