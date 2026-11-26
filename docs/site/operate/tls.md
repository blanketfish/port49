---
title: TLS
description: Running TACACS+ over TLS (RFC 9887) on port 300, the certificates it needs, and what an operator sees when one is wrong.
---

# TLS

RFC 9887 puts TACACS+ inside a TLS 1.3 connection with mutual authentication. A device proves who it is
with its certificate, so there is no shared key to rotate on the fleet. port49 serves it on a
second listener beside the RFC 8907 one, and each device speaks one or the other, as its inventory record
says.

| Listener | Config key | Default | Device record |
|---|---|---|---|
| RFC 8907 (obfuscated under a shared key) | `listen` | `:49` | `transport: tcp` (the default) |
| RFC 9887 (TLS 1.3, mutual) | `tls_listener.listen` | `:300` | `transport: tls` |

## Turn the listener on

Run both listeners while you migrate, or only one: `listen: none` serves TLS alone. A file with neither
listener is refused, and the two may not bind one address.

=== "systemd"

    Uncomment `tls_listener:` in `/etc/port49/port49d.yaml`. Put the server certificate chain, its key and
    the device CA in `/etc/port49/tls/`, the key mode 0400 and owned by `port49d`, and open TCP 300 from
    your devices.

=== "Containers"

    The stack ships with port 49 only. Add the `tls_listener:` block to port49d's configuration, put the
    same files where port49d can read them, and publish 300 beside 49 on the port49d service.

=== "Helm"

    Set `tlsListener.enabled: true` and `tlsListener.existingSecret` to a Secret holding `tls.crt`,
    `tls.key` and `ca.crt` (the devices' CA). The chart adds port 300 (`tlsListener.port`).

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

`cert_file` holds the server chain, leaf first, and its key must be owned by port49's user or root with no
group or other bit. `client_ca_file` holds the anchors a device certificate chains to, and
`intermediates_file` the issuing CAs, so a device that sends only its leaf still verifies.
`certificate_status` is required: CRLs, OCSP, or `disabled: true`, always a written choice. The other keys
are in the [reference](../reference/config/port49d.md#tls_listener).

To check, read `port49_tls_server_certificate_lifetime_left_ratio` on port49d's metrics port: it is above 0
while the server certificate is in date.

## How a device is identified

A device is the inventory record its source address belongs to, and its certificate must name it, by name
or by address (`tls_listener.device_identity.match`, both on by default):

- A `dns_name` equal to the device's inventory `name`, or to the name under a suffix in
  `device_identity.dns_suffixes`, ignoring case and a trailing dot. A wildcard never names a device.
- An `ip_address` that is one of the device's `addresses`.

The common name is never read. A certificate that names another device is refused `identity_mismatch`, and
the detail says what it named and what was wanted. The reason values are in the
[`tls_outcome` table](../reference/decision-log.md#tls_outcome).

Two `tls` devices whose names are equal under ASCII case folding are both refused admission
(`tls_name_clash`, named at start): rename one. A `dns_suffixes` clash, or a non-ASCII name with no
`ip_address` match, cannot be told apart either. That device is declined at Accept as `identity_mismatch`
with no handshake and no strike, and named once at start: rename it, or give it an `ip_address` its
certificate carries.

## The server certificate

The server certificate must come from a CA the device trusts for nothing else. Devices differ in whether they
check the names in it ([L73](../reference/lab-register.md#l73)), so do not count on it. If you want a wildcard in
it, confine it to a subdomain only TACACS+ servers use (RFC 9887 section 5.1.6).

!!! warning "Unmeasured"
    Whether Junos, NX-OS and XRd check the server certificate's DNS name or address is unknown. Junos and
    NX-OS failed the logins with a certificate naming only a DNS name and one naming another address, and
    XRd failed the DNS-only one, but the cause was not proven. Give them a certificate that carries every
    name and address the device might be configured with.

## Junos

Junos makes the client certificate optional, and port49 requires it, so without
`tls mutual-authentication certificate-id` on each server and on accounting a login is refused
`no_client_certificate`. The lines, the SNI behavior and what is unmeasured are on [Juniper Junos](../admin/devices/juniper-junos.md).

## Revocation

`certificate_status` is required, so skipping the check is a choice you wrote down. With CRLs, port49d
fetches each list every `refresh_interval` (10 minutes by default), keeps what it verified in `state_dir`,
and checks OCSP if you configure it. A revoked certificate completes the handshake and is then reset with
no alert, recorded `certificate_revoked`.

When a certificate's status cannot be established (a CRL source down past the list's `nextUpdate`),
`on_unavailable: refuse` (the default) resets the connection after the handshake, recorded
`status_unavailable`. That is a decline, not a strike, so a device falls to its local method at once.
`on_unavailable: allow` admits the connection and says so.

## Migrating a device from `tcp` to `tls`

1. Issue the device a client certificate (`clientAuth`) from a CA in `client_ca_file`, naming the device by
   its inventory name or address. If the device sends only its leaf, put the issuing CA in
   `intermediates_file`.
2. Start the TLS listener beside the RFC 8907 one.
3. On the device, add the TLS server with its port set explicitly: the platforms differ with none set
   (table below).
4. Change the device's inventory `transport` to `tls`. The device is then declined on 49 and served on 300.
5. Remove the shared-key server from the device.

Keep the window in which a device lists both a TLS server and a plain one short (RFC 9887 section 6.1).
A sync that flips a device from `tls` to `tcp` is recorded `transport_changed`; port49 does not block it
([alert](../reference/alerts.md#port49_inventory_transport_changed)).

What the [L73](../reference/lab-register.md#l73) runs saw:

| Platform | Port with none set | Sends | Mixed list, plain server | Falls to local on an ERROR answer |
|---|---|---|---|---|
| IOS XE | 6049 | leaf and intermediate | connection reset before any header | No |
| EOS | 300 | leaf only | connection reset before any header | Yes |
| Junos | 49 | leaf and intermediate | connection reset before any header | Yes, with `password` after `tacplus` |
| NX-OS | 49 | leaf and intermediate | no connection | Yes |
| XRd | 49 | leaf and intermediate | sends plain TACACS+ headers | No |

!!! warning "Unmeasured"
    Whether the three that reset would have sent a header had the server stayed up is not measured. port49
    refuses a `tls` device's packet on the RFC 8907 listener, so a device that falls back is not served, but it
    is a header on the wire.

## What you see at 3am

| What happened | What port49d says | Fix |
|---|---|---|
| A device's certificate expired | `tls_refused` with `certificate_expired`, naming the device; `port49_tls_handshakes_total{outcome="certificate_expired"}`. Before it expired, `port49_tls_device_certificate_lifetime_left_ratio` below 0.33. | Renew it on the device. |
| A device stopped renewing a short-lived certificate | One line a day naming it, in the last third of its life. | Fix its enrolment. |
| The device CA rotated | `unknown_ca` per device once `client_ca_file` lost the old CA. Open connections close at their next packet. | Keep both CAs in `client_ca_file` until every device has re-enrolled and `outcome="unknown_ca"` is at zero. |
| The CRL is unreachable | After `nextUpdate`: `tls_listener: certificate status: CRL ...` lines and `status_unavailable` records. `port49_cert_status_unavailable_total{component="tls_listener"}`. | Restore the CRL source. A failed source is retried from 30 seconds, doubling up to `refresh_interval`. |
| A device speaks TLS 1.2 only | `version_refused`: "offered 303; RFC 9887 requires TLS 1.3". | Upgrade it, or set it back to `transport: tcp`. |
| A device on the wrong port or transport | `transport_mismatch` naming the device and its record's transport. | Correct the server port or the record's `transport`. |
| SNI mismatch | `sni_mismatch`, "asked for server name X". A decline, no strike. | Correct the device's server name, or `server_names`. |
| The certificate names another device | `identity_mismatch`, naming what the certificate carried and what was wanted. | Reissue it, or fix the inventory name or address. |
| port49d's own certificate expired | "server certificate ... expired"; `port49_tls_server_certificate_lifetime_left_ratio` below 0. Every handshake is recorded `handshake_failed` and struck. | Replace `cert_file`; it is picked up within `reload_interval`. The strikes lapse on their own. |

### IOS XE and a down store

On IOS XE and XRd over TLS, a store outage that makes port49 answer ERROR also locks out the local break-glass
account. Keep a console way in. When port49d closes its listeners instead, the device uses its local method
([Stores](stores.md#when-the-session-store-is-the-one-that-is-down)).

## Reloads

An edit to any `tls_listener:` key needs a restart. The certificate, key, CA and intermediates files are
re-read every `reload_interval` (1 minute by default) and at SIGHUP, so a CA rotation needs no restart. Metrics
that carry a `component` label need `sum by (component)` or `ignoring(component)` before a division
([alerts notes](../reference/alerts.md#notes)).
