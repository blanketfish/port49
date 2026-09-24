# L20 — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`; `show version`: `Cisco IOS XE Software, Version 17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L20-cisco_iosxe.pcap` — 4336 packets, every one of them to or from the lab subnet (`tcpdump -r tests/lab/evidence/L20-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`); `-i any` records each packet twice, on the bridge and the veth. Taken by hand, so there are no loopback bracketing probes; tcpdump ran 2s before the first request and was stopped 2s after the last.
- **Transport:** RESTCONF over HTTPS, HTTP Basic, seeded tokens
- **Method:** by hand, following `tests/lab/README.md` "By hand"

## Claim

Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys
that answer on (the credential, the username, the client); whether a **wrong password** for the
same user inside that window is also accepted; and whether a credential port49 would now refuse is
re-checked inside it (spec §15, L20).

## Answer

**A wrong password is not accepted inside the window.** IOS-XE keeps a per-credential cache of a
successful RESTCONF authentication for **about 10 seconds, fixed from the authentication that
filled it** — a repeat 9s after it was answered from the cache, a repeat 10s after it went to
TACACS+ again, and requests every 2.5s did not extend it. The cache is keyed on the username and
the password together: a different password for the same user, inside the window, went to port49
and was refused `401`. It is **not** keyed on the client address, and a cached credential is
**not** re-checked: with port49 answering every authentication ERROR and every authorization FAIL,
a credential cached 2s earlier still got `200` with no TACACS+ packet sent.

So the RESTCONF repeat does not weaken who can get in — only the holder of the exact credential
does — but for up to 10s after any successful request it is out of port49's reach: a revocation,
a spent token or a store outage does not stop that credential until the entry ages out.

## Setup

port49d ran `tests/lab/port49d-lab.yaml` with `session_attributes: ["priv-lvl=15"]`, 80 extra
seeds for `xe1` (`u001`..`u080`) and `lab.fault_file` added — a config derived for the run
(`tests/lab/logs/port49d-byhand.yaml`, git-ignored). The device configuration, applied as
`breakglass` before port49d started, is the one `tests/lab/results/L1-restconf-cisco_iosxe.md`
records (`ip http authentication aaa login-authentication default`, `... exec-authorization
default`, `restconf`), on top of `tests/lab/configs/iosxe-startup.cfg`:
`aaa authentication login default group port49 local`.

Every request was

```
printf 'user = "%s:%s"\n' "$USER" "$PASSWORD" |
  curl -sk -i -K - -H 'Accept: application/yang-data+json' \
  https://172.100.100.41/restconf/data/Cisco-IOS-XE-native:native/hostname
```

with the credential on stdin, never on a command line. A "wrong password" is 30 random
alphanumerics. The second client address is `172.100.100.2`, added to the host's clab bridge for
the run and selected with `curl --interface 172.100.100.2`. After each request the decision log
was read for 1.5s; "no record" means port49d logged nothing for that request and the capture shows
no TCP connection from the device in that interval.

## Observation

### Replies, verbatim

Every `200` in this note is this reply (the `Date:` differs):

```
HTTP/1.1 200 OK
Server: openresty
Date: Thu, 24 Sep 2026 01:17:05 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "Cisco-IOS-XE-native:hostname": "xe1"
}
```

and every `401` is this one:

```
HTTP/1.1 401 Unauthorized
Server: openresty
Date: Thu, 24 Sep 2026 01:17:09 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
WWW-Authenticate: Basic realm="restconf"
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "ietf-restconf:errors": {
    "error": [
      {
        "error-type": "protocol",
        "error-tag": "access-denied"
      }
    ]
  }
}
```

### 1. A wrong password inside the window

One user, `u001`, one seeded token, requests about 3s apart (the second column is the time the
request was sent):

| # | sent | request | reply | decision log |
|---|---|---|---|---|
| 1 | 01:17:02.425Z | `u001`, its token | `200` | `redeem permit token_redeemed`; `authorize_session permit context_matched` |
| 2 | 01:17:05.988Z | `u001`, the same (now spent) token | `200` | none |
| 3 | 01:17:08.503Z | `u001`, **wrong password** | `401` | `redeem deny device_mismatch` |
| 4 | 01:17:11.533Z | `u001`, another wrong password | `401` | `redeem deny device_mismatch` |
| 5 | 01:17:15.053Z | `u002` (holds an unspent token), wrong password | `401` | `redeem deny device_mismatch` |
| 6 | 01:17:18.075Z | `nobody` (unknown to port49), wrong password | `401` | `redeem deny device_mismatch` |
| 7 | 01:17:21.098Z | `u001`, **empty** password | `401` in 0.01s | none: the device refused it without asking |
| 8 | 01:17:23.609Z | `u001`, its token, from `172.100.100.2` | `200` | `redeem permit receipt_replayed`; `authorize_session permit context_matched` |
| 9 | 01:17:26.134Z | `u001`, wrong password, from `172.100.100.2` | `401` | `redeem deny device_mismatch` |
| 10 | 01:17:30.656Z | `u001`, its token, from the first address | `200` | none |

(`device_mismatch` is what port49 answers a 30-character string that is not a token minted for
this device. The refused requests took 0.5s to 2.0s: port49's failure delay, doubling per
`(nas, username)` — `u001`'s took 0.53s, 1.02s and 2.02s.)

Rows 3–6 are the answer: inside the window, a wrong password — for the cached user, for another
user, for a user port49 has never heard of — is sent to port49 and refused. The device did not
key on the username.

### 2. What the cache is keyed on

Each experiment with fresh users and 15s between experiments:

| experiment | request | reply | decision log |
|---|---|---|---|
| two users cached at once | redeem `u021`, redeem `u022`, then `u021` again, `u022` again (1.5s apart) | all `200` | the two redeems only; both repeats none |
| client address | redeem `u023` from `.1`, then again from `.2`, then again from `.1` | all `200` | the redeem only; both repeats none |
| own failure | redeem `u024`, repeat, **wrong password** for `u024`, then the right credential again | `200`, `200`, `401`, `200` | redeem; none; `redeem deny device_mismatch`; none |
| another user's failure | redeem `u025`, wrong password for `u026`, `u025` again | `200`, `401`, `200` | redeem; `redeem deny device_mismatch`; none |

So the entry is per credential (username and password together), several are held at once, the
client address is not part of the key, and a failed attempt — the user's own or another's —
neither clears nor refreshes it. Row 8 of table 1 is not a counterexample: it was 21s after the
entry was filled, past the window.

### 3. Whether port49 is asked again inside the window

`u027` redeemed at 01:30:36.949Z; the fault switch was set to `store_unavailable` at 01:30:38.475Z,
under which port49 answers every authentication ERROR and every authorization FAIL:

| sent | request | reply | decision log |
|---|---|---|---|
| 01:30:38.475Z | `u027`, its token | `200` | none |
| 01:30:39.992Z | `u027`, its token | `200` | none |
| 01:30:41.507Z | `u028`, an **unspent** token | `401` in 0.02s | `redeem deny store_unavailable` |
| 01:30:43.028Z | `u027`, its token | `200` | none |

A credential port49 would now refuse was not re-checked: the cached one kept working, while a
fresh one was refused (the device took port49's ERROR as a failure; it did not fall through to
`local`, which would have refused `u028` too).

### 4. How long

Each row is a fresh user, redeemed, then the same credential **once** after the delay with no
other request in between (a hit could otherwise refresh the entry):

| delay after the redeem | reply | decision log on the repeat |
|---|---|---|
| 5s | `200` | none |
| 6s | `200` | none |
| 7s | `200` | none |
| 8s | `200` | none |
| 9s | `200` | none |
| 10s | `200` | `redeem permit receipt_replayed` |
| 20s, 30s, 60s, 120s, 300s | `200` | `redeem permit receipt_replayed` |

Sliding or fixed: `u040` redeemed at 01:42:04.541Z and repeated every ~2.5s for 30s. The device
went back to port49 at 01:42:14.612Z, 01:42:24.683Z and 01:42:34.756Z — every 10.07s — and
answered every request between them from the cache. The window is **fixed from the authentication
that filled it**; hits do not extend it. The earlier multi-user sweep in the same capture (users
`u003`–`u013`, repeats at 10s to 600s and every 15s) agrees: every repeat at 10s or later went to
port49.

After the window the repeat reached port49 as `receipt_replayed`: it is the receipt's
`receipt_idle_ttl` (default 15m) that bounds the spent token from there, as decision 15 intends.

## Reading

- The open question L20 was added for is answered **no**: a wrong password inside the window is
  refused, so RESTCONF on IOS-XE does not hand authentication to whoever knows a username.
- Revocation does not reach a cached credential for up to 10s after the device last asked. port49
  cannot shorten that and nothing in its log shows it happening. Measured as a ceiling, 10s is
  small beside `receipt_idle_ttl`, but it is also a floor on how long a store outage or a
  revocation takes to bite on this transport.
- The cache also answers a spent token's repeats during a store outage (§3), which is the one case
  where the device's behaviour is kinder to the operator than port49's.

*Unmeasured:* the same questions on eAPI and NX-API with Basic credentials; NETCONF-YANG on IOS-XE;
whether any IOS-XE configuration changes the 10s (none was found: `aaa group server tacacs+`
offers no timer on this image, see `L4-error-cisco_iosxe.md`); whether a cached credential still
passes after `clear aaa cache` or an `ip http` restart.
