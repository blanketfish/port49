---
title: TLS
description: Running TACACS+ over TLS (RFC 9887) on port 300, the certificates it needs, and what an operator sees when one is wrong.
---

# TLS

RFC 9887 puts TACACS+ inside a TLS 1.3 connection with mutual authentication. A device proves who it is
with a certificate, not a shared key, so there is no key to rotate on the fleet. port49 serves it on a
second listener beside the RFC 8907 one. A device speaks one or the other, as its inventory record says.

## The two listeners

| Listener | Config key | Default | Device record |
|---|---|---|---|
| RFC 8907 (obfuscated under a shared key) | `listen` | `:49` | `transport: tcp` (the default) |
| RFC 9887 (TLS 1.3, mutual) | `tls_listener.listen` | `:300` | `transport: tls` |

Run both at once while you migrate, or only one. To serve TLS alone, set `listen: none` and add a
`tls_listener:` block; a file with neither listener is refused. They may not bind the same address.

```yaml
listen: none
tls_listener:
  listen: ":300"
  cert_file: /etc/port49/tls/server.pem
  key_file: /etc/port49/tls/server-key.pem
  client_ca_file: /etc/port49/tls/device-ca.pem
  intermediates_file: /etc/port49/tls/device-intermediates.pem
  state_dir: /var/lib/port49
  certificate_status:
    crls:
      - name: device_ca
        url: https://pki.example.net/device-ca.crl
        issuer_file: /etc/port49/tls/device-ca.pem
```

| Key | What it is for |
|---|---|
| `cert_file`, `key_file` | The server certificate chain (leaf first) and its key. The key must be owned by port49's user or root, with no group or other mode bit. |
| `client_ca_file` | The device CA certificates: the anchors a device certificate must chain to. |
| `intermediates_file` | Optional. Issuing CAs held here, so a device that sends only its leaf still verifies. |
| `device_identity` | Which certificate names identify a device (below). |
| `server_names` | When set, the SNI names a ClientHello may ask for. |
| `state_dir` | Absolute directory where the verified CRLs are kept so a restart keeps them. Required when `certificate_status.crls` names any. |
| `certificate_status` | Required. Revocation: CRLs, OCSP, or `disabled: true`, always a written choice. |
| `handshake_timeout`, `session_ticket_lifetime`, `reload_interval`, `expiry_warning_fraction` | Timing. Defaults and limits are in the [reference](../reference/config/port49d.md#tls_listener). |

A device that connects to the wrong listener is reset: a `tcp` device on 300 before any TLS byte, a `tls`
device on 49 after its first header (`transport_mismatch`).

## How a device is identified

A device is the inventory record its source address belongs to. Its certificate must then name that
device, by one of two rules (`tls_listener.device_identity.match`, both on by default):

- **By name.** A `dns_name` in the certificate equal to the device's inventory `name`, or to the name under
  a suffix in `device_identity.dns_suffixes`, ignoring case and a trailing dot. A wildcard never names a
  device, and neither does a name with non-ASCII characters.
- **By address.** An `ip_address` in the certificate that is one of the device's `addresses`.

The common name is never read. A certificate that names another device is refused `identity_mismatch`,
and the detail says what the certificate named and what was wanted. The values of the reason are in
the [`tls_outcome` table](../reference/decision-log.md#tls_outcome).

### Two names that cannot be told apart

- **`tls_name_clash`.** Two `tls` devices whose names are equal under ASCII case folding are both refused
  admission, and the start names them (`inventory: device "<name>" is refused (tls_name_clash): ...`).
  The rest of the fleet loads. Rename one of them.
- **Unidentifiable devices.** A `dns_suffixes` clash, or a non-ASCII name with no `ip_address` match,
  means a certificate cannot be told from another's. Such a device is declined at Accept as
  `identity_mismatch`, with no handshake and no strike, and named once at start or reload:
  `tls_listener: device <name> cannot be identified: ...`. Rename it, or give it an `ip_address` the
  certificate carries.

## The server certificate's names

A device configured with a DNS name or an address may or may not check that port49's certificate carries
it. In the lab, IOS XE 17.18.02 accepted a server certificate that named only a DNS name, and one that
named another address, though it was configured by address
([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md)).
EOS and XRd 26.1.1 refused the one naming another address
([EOS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md),
[XRd](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)), and EOS
refused the DNS-only one too. So do not count on the device to check the names: the server certificate must come from
a CA the device trusts for nothing else. A certificate from a CA your devices also trust for web sites is
a certificate anyone who can get one issued can use against them.

If you want a wildcard in the server certificate, confine it to a subdomain only TACACS+ servers use
(RFC 9887 section 5.1.6).

!!! warning "Unmeasured"
    Whether Junos, NX-OS and XRd check the server certificate's DNS name or address is unknown. In the lab
    Junos and NX-OS failed the logins with a certificate naming only a DNS name and one naming another
    address, and XRd failed the DNS-only one, but the cause was not proven. Give them a certificate that carries every name and address the device might be
    configured with, and do not rely on either result.

## Junos

Junos makes the client certificate optional for TLS, and port49 requires it. Without it a login is refused
`no_client_certificate` (port49's own refusal, measured with the lab's reference client in
[L72](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L72-reference.md)). Tell the
device to send its certificate on each server and on accounting:

```text
set system tacplus-server <server-address> tls mutual-authentication certificate-id <id>
set system accounting destination tacplus server <server-address> tls mutual-authentication certificate-id <id>
```

The lab configured exactly this on vJunos-router 26.2R1.7
([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md)),
beside a `tls trusted-ca-group` line. The whole stanza is in
[`deploy/device-aaa/juniper_junos-tls.set`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/juniper_junos-tls.set).
Junos also sends the server's IP address as the SNI name, so if you set `server_names`, list every address
the device may dial, or leave it unset. The device sees an `internal_error` alert and port49d logs
`tls_refused` with `sni_mismatch`.

!!! warning "Unmeasured"
    Which Junos releases accept this line, and whether SRX does, is unknown; the line was run on one image
    only. Whether a Junos device whose `authentication-order` lists `tacplus` alone falls to anything over
    TLS when port49 answers ERROR was not measured. The lab placed the client certificate through a lab-only root shell, so the documented enrolment
    on Junos is also unmeasured, and which of two certificates the device sent is not recorded.

## Revocation

`certificate_status` is required, so skipping the check is a choice you wrote down. With CRLs, port49d
fetches or re-reads each list every `refresh_interval` (10 minutes by default), keeps what it verified in
`state_dir` so a restart does not lose them, and checks OCSP if you configure it. A revoked certificate
completes the handshake and is then reset with no alert, `certificate_revoked`.

When the status of a certificate cannot be established (a CRL source down past the list's `nextUpdate`),
`on_unavailable: refuse` (the default) completes the handshake and resets the connection, recorded
`status_unavailable`. This is a decline, not a strike: the next connection inside the decline window is
reset at Accept with no new record, and a device falls to its local method at once. `on_unavailable:
allow` admits the connection and says so; it is the reviewed escape, not the default.

## Migrating a device from `tcp` to `tls`

1. Issue the device a client certificate (`clientAuth`) from a CA in `client_ca_file`, naming the device
   by its inventory name or address. If the device sends only its leaf, put the issuing CA in
   `intermediates_file`. In the lab, EOS sent its leaf alone
   ([EOS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md));
   Junos, IOS XE, NX-OS and XRd sent the leaf and the intermediate
   ([Junos](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md),
   [IOS XE](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md),
   [NX-OS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md),
   [XRd](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)).
2. Start the TLS listener beside the RFC 8907 one, and check `port49_tls_server_certificate_lifetime_left_ratio`.
3. On the device, add the TLS server at port 300. With no port configured the lab found Junos and
   NX-OS dial 49, IOS XE dials 6049, XRd dials 49 and EOS dials 300, so configure the port explicitly
   (the same five notes).
4. Change the device's inventory `transport` to `tls`. From then on the device is declined on 49 and
   served on 300.
5. Remove the shared-key server from the device.

Keep the window in which the device lists both the TLS server and a plain one as short as you can
(RFC 9887 section 6.1). In the lab, XRd sent plain TACACS+ headers to the plain server in a mixed list
([XRd](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)). IOS XE,
Junos and EOS opened a connection to it that was reset before any header, and NX-OS opened none
([IOS XE](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md),
[Junos](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md),
[EOS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md),
[NX-OS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)). Whether
those three would have sent a header had the server stayed up is not measured. port49 refuses a `tls` device's packet on the RFC 8907 listener (`transport_mismatch`),
so a device that does fall back is not served, but it is a header on the wire.

A sync that flips a device from `tls` to `tcp` is recorded `transport_changed`, and port49 does not block
it. The alert is [port49_inventory_transport_changed](../reference/alerts.md#port49_inventory_transport_changed).

## What you see at 3am

| What happened | What port49d says | Fix |
|---|---|---|
| A device's certificate expired | Record `tls_refused` with `certificate_expired`, naming the device and the certificate's `NotAfter`; the counter `port49_tls_handshakes_total{outcome="certificate_expired"}`. Before it expired, the `expiry_warning_fraction` line and `port49_tls_device_certificate_lifetime_left_ratio` below 0.33. | Renew it on the device. |
| A device stopped renewing a short-lived certificate | One line a day naming it, once it is in the last third of its own life. | Fix its enrolment before the certificate expires. |
| The device CA rotated | `unknown_ca` per device once `client_ca_file` lost the old CA; a reload line names the anchors in force. Open connections close at their next packet. | Keep both CAs in `client_ca_file` until every device has re-enrolled; read `outcome="unknown_ca"` at zero before you remove the old one. |
| The CRL is unreachable | After `nextUpdate`: `tls_listener: certificate status: CRL ...` lines and `status_unavailable` records, and then one line every 10 minutes counting the declined devices. `port49_cert_status_unavailable_total{component="tls_listener"}`. | Restore the CRL source. A failed source is retried from 30 seconds, doubling up to `refresh_interval`, so a `file:` source copied in by hand is read at the next retry, at most `refresh_interval` later. |
| A device speaks TLS 1.2 only | Record `version_refused`: "offered 303; RFC 9887 requires TLS 1.3". | Upgrade the device, or set it back to `transport: tcp`. |
| A device on the wrong port or transport | Record `transport_mismatch` naming the device and its record's transport. | Correct the device's server port, or the record's `transport`. |
| SNI mismatch | Record `sni_mismatch`, "asked for server name X". A decline, no strike. | Correct the device's server name, or `server_names`. |
| The certificate names another device | Record `identity_mismatch`, e.g. "the certificate names dns_name [leaf-02.example.net]; device leaf-01 is dns_name leaf-01 or leaf-01.example.net, or ip_address 10.0.1.5". | Reissue the certificate, or fix the inventory name or address. |
| port49d's own certificate expired | The start or reload line "server certificate ... expired"; `port49_tls_server_certificate_lifetime_left_ratio` below 0. Every device's handshake is recorded `handshake_failed` and struck, with a detail that begins "the device aborted the handshake (it may refuse port49's certificate)". | Replace `cert_file`; it is picked up within `reload_interval`. The strikes lapse on their own. |

The alerts for these are [port49_tls_handshake_failures](../reference/alerts.md#port49_tls_handshake_failures),
[port49_tls_device_certificate_renewal_late](../reference/alerts.md#port49_tls_device_certificate_renewal_late),
[port49_tls_server_certificate_renewal_late](../reference/alerts.md#port49_tls_server_certificate_renewal_late),
[port49_tls_server_certificate_expired](../reference/alerts.md#port49_tls_server_certificate_expired),
[port49_tls_cert_status_unavailable](../reference/alerts.md#port49_tls_cert_status_unavailable) and
[port49_crl_next_update_passed](../reference/alerts.md#port49_crl_next_update_passed).

### IOS XE and a down store

When port49's store is down and port49 answers ERROR (`store_unavailable`), IOS XE 17.18.02 over TLS does
not fall to its local method, so break-glass fails: the lab login failed in 4.1 seconds
([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_iosxe.md)).
XRd 26.1.1 behaved the same way
([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)).
Junos (with `password` after `tacplus` in `authentication-order`, as the lab configured it), EOS and NX-OS
fell to local in the same test
([Junos](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-juniper_vjunos-router.md),
[EOS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-arista_ceos.md),
[NX-OS](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_nxos.md)).

!!! warning "A down store and IOS XE"
    On IOS XE and XRd over TLS, a store outage that makes port49 answer ERROR locks out the local
    break-glass account too. Keep an out-of-band way in (the console), and read
    [stores](stores.md#when-the-session-store-is-the-one-that-is-down) for when port49d closes its
    listeners instead, which is what lets a device use its local method.

## The `component` label

`port49_cert_status_checks_total`, `port49_crl_loads_total`, `port49_crl_next_update_timestamp_seconds`
and `port49_cert_status_unavailable_total` carry `component`: `tls_listener` for this listener and
`broker` for the broker's own CRLs. A CRL of the same name in both has a series in each. A rule that
divides or compares two of them one-to-one fails to match across components, so aggregate first or ignore
the label:

```promql
sum by (component) (rate(port49_cert_status_unavailable_total[5m]))
  / sum by (component) (rate(port49_cert_status_checks_total[5m]))
```

Or match with `ignoring(component)` where only that label differs. The shipped rules each name
their component (`component="tls_listener"`), so they need neither; see the
[alerts notes](../reference/alerts.md#notes).

## Which edits need a restart

An edit to any `tls_listener:` key needs a restart. port49d says this once, at the first SIGHUP:
`tls_listener: config changes take effect at restart; files reload now`. Only the first SIGHUP says
it; a later SIGHUP of an edited restart-only key says nothing and changes nothing, so do not read
silence as applied.

The files reload by themselves. `cert_file`, `key_file`, `client_ca_file` and `intermediates_file` are
re-read every `reload_interval` (1 minute by default, 10 seconds to 1 hour) and at SIGHUP. A CA rotation
needs no restart: the anchors in force are named in the reload line, and a connection whose chain no
longer verifies ends at its next packet. A file that does not load leaves the set in force serving, and
the failure is said once.

A change to the inventory or the policy (a device's `transport`, its addresses) is picked up by the
watch and SIGHUP, with no restart. Everything else in `port49d.yaml`, `listen` included, is read at
start; the [reference](../reference/config/port49d.md) marks the few other keys that SIGHUP re-reads.
