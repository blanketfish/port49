# The RFC 9887 TLS listener: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** port49d serves TACACS+ over TLS 1.3 with mutual certificate authentication on its own
listener (RFC 9887, port 300), beside or instead of the RFC 8907 listener on 49. A device record
says which it speaks (`transport: tcp | tls`), and a TLS device's credential is its certificate:
no shared key (design §11; spec §10; design §19 step 11).

**Architecture:** The TLS listener is the existing accept loop (`internal/daemon/server`) with a
`TLS` part in its `Deps`. Every decision that does not need a TLS byte (unadmitted source, refused
device, quarantine, wrong transport) is made at Accept, before a handshake costs anything. The
handshake is `crypto/tls`, TLS 1.3 only, with `RequireAnyClientCert`. port49 verifies the chain
itself in `VerifyConnection`, on a full handshake and on a resumption alike, through one new
package, `internal/devicecert`. That package does the path to the configured anchors (plus
stored intermediates), the device's identity in the subjectAltName, and revocation through a
second `certstatus.Checker`. After the handshake the packet loop is the one port 49 uses. Three
things differ: no key is tried, the unencrypted flag is required, and every reply sets it. The
listener's files are loaded into one `server.Material` and swapped whole on change, so a CA
rotation reaches the next handshake and the next packet of an open connection.

**Tech Stack:** Go 1.26 (module `github.com/rhwendt/port49`), the standard library's
`crypto/tls` and `crypto/x509` only, no new module; `internal/tacacs/wire`, `internal/admission`,
`internal/policy`, `internal/bundle`, `internal/config`, `internal/certstatus`, `internal/decision`,
`internal/keyring`, `internal/daemon/{server,metrics,authen}`, `internal/port49d`, `cmd/port49`;
the lab on beehive (the SER8), build tag `lab`, `openssl` 3.x as a reference client.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md`:
- §10 "Admission and keys" (:4876, the `transport` paragraph at :4937), "Device records" (:5310),
  the diagnosis buckets (:5098–5160) and the decline window (:5183–5220);
- §5.7, the record fields (`device`, :2183; `device.key_ref`, :2230) and `inventory_change`
  (:2281);
- "Key rotation", "Per-device keys are not supported" (:5287) and the three-key table (:5301);
- §13 decisions 20 (quarantine silence), 32 and 33 (certificate status), and 49 (the last);
- §15, the register's rules (:10715) and its last row, L70 (:10817).

Design `docs/design/2026-08-21-port49-design.md` §2 (:33, "no mainstream network OS ships a
TLS-capable TACACS+ client"), §11 (:1270), §15 (:1853), §19 step 11 (:2401). RFC 9887
(December 2025), every section this plan cites by number. The roadmap's "Plan 11" section
(`docs/superpowers/plans/README.md:6954`).

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo, no new module. Before any "done": `make test &&
  make vet`, and report the real output.
- Data is snake_case: the config block `tls_listener` and its keys `listen`, `cert_file`,
  `key_file`, `client_ca_file`, `intermediates_file`, `device_identity.match`,
  `device_identity.dns_suffixes`, `server_names`, `handshake_timeout`,
  `session_ticket_lifetime`, `expiry_warning`, `reload_interval`, `state_dir`,
  `certificate_status`; `listen: none`; the record fields `device.transport`, `device.cert_sha256`,
  `unvalidated.transport`, `unvalidated.tls_outcome`, `unvalidated.detail`,
  `unvalidated.cert_sha256`; the diagnoses `transport_mismatch`, `tls_refused`,
  `obfuscated_over_tls`; the change kind `transport_changed`; the metrics
  `port49_tls_handshakes_total{outcome}`, `port49_tls_device_certificate_expiry_seconds`,
  `port49_tls_server_certificate_expiry_seconds`, `port49_devices_by_transport{transport}`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds
  none. A TLS refusal is an `unvalidated` record with a diagnosis, as a key miss is. A quarantined
  device keeps `device_quarantined`, and an admission a reload withdrew keeps `device_unknown`.
  §12's warning codes are policy-tooling codes; this plan adds none.
- The log never contains a token, password, challenge, response, private key or ticket. A device
  certificate is not a credential secret: its SHA-256 (`cert_sha256`) and, in `detail`, its
  subjectAltName entries and subject are recorded, each through `printsafe.Line` with a bound.
  An unvalidated body is never logged or hashed on the TLS listener: there it is the cleartext of
  a peer that holds a certificate, and may carry a credential.
- No device identity in a metric label. `outcome` and `transport` are closed vocabularies.
- The lab register is the source of truth. No lab image today carries an RFC 9887 client
  (vendor documentation, Rulings R19). Every device-behaviour claim cites L73 and reads
  "unmeasured (L73)" until a row cell closes. L71 (which lab images carry a client) and L72 (port49
  against reference clients) are measured by this plan. If a result contradicts a doc, the doc is
  wrong: fix it, cite the note, and say so in the commit.
- Lab runs: single occupant; the STOP sentinel `/tmp/port49-STOP-LAB` checked before every cell
  (`labGuardAt`); a background stall watchdog, re-armed on every wake; a detached run worktree
  pinned at the commit. An INVALID run writes no note. The harness never prints a token. Every
  token it reads is held in memory, read only from a seed file under `t.TempDir()`, and
  registered with the note's leak check (`labcreds.Contains`). Never read
  `/tmp/port49-lab-tokens.jsonl` or any credential or env file. Never run `ykman`,
  `pkcs11-tool` or `tpm2_*` (a real YubiKey and TPM are attached to the lab host).
- Commits: Conventional Commits, one per step that says Commit, on `feature/tls-listener`. Each
  message ends with only `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`. No
  `Claude-Session:` line and no claude.ai link.

## Rulings (planner, 2026-10-16, security-first where the spec and RFC 9887 are silent)

Recorded as spec §13 decision 50 by Task 1. Each rests on reasoning unless it says data. Ryan may
override any.

- **R1. Two listeners, independently configured and separable** (design §11; RFC 9887 §3.1, §5.2).
  `tls_listener:` is a new port49d.yaml block; `tls_listener.listen` defaults to `:300` (RFC 9887
  §7, IANA `tacacss`). `listen: none` turns the RFC 8907 listener off: this is RFC 9887 §5.2's
  "single option to disable all non-TLS operations". A port49d with neither listener is refused
  at load. Two listeners on one bind (same port, and the same host or either a wildcard) are
  refused at load; port `0` never conflicts. One port49d may run both. RFC 9887 §5.1.1 does
  not recommend TLS and non-TLS servers on one host. So the start says, in a notice, that the
  two run on one host, and why it is still downgrade-safe here: each device record names one
  transport, and the other listener refuses that device (R4). The notice is said at every start
  and asks nothing. Q2 asks whether to require an opt-in instead. Cisco's documents for IOS XE
  17.18 and NX-OS 10.6 configure port 6049, Cisco ISE's default. The default here stays 300 (RFC),
  and the operator notes name 6049 as the vendor default to override on the device or listen on.
  What a device defaults to is L73 (a).
- **R2. TLS 1.3 only, Go's cipher suites.** `MinVersion: tls.VersionTLS13`, no `MaxVersion`
  (RFC 9887 §3.2 says "a minimum of TLS 1.3"). A ClientHello without 1.3 is refused by
  `crypto/tls` with `protocol_version`, and recorded `version_refused`. `crypto/tls` does not let
  TLS 1.3 suites be configured. It offers `TLS_AES_128_GCM_SHA256` (RFC 8446 §9.1's mandatory
  suite), `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`. RFC 9887 §3.4.3's SHOULD
  (configurable suites) is therefore not met, and the docs say so. FIPS 140-3 deployments run
  `GODEBUG=fips140=on`, which narrows the suites. The TLS Cached Information Extension (RFC 7924;
  RFC 9887 §3.4.1, SHOULD) is not in `crypto/tls`, and no cgo means no other library: not
  implemented, and said.
- **R3. Certificates only; no shared key on a TLS device.** RFC 9887 §3.3 requires
  certificate-based mutual authentication and makes PSKs and raw public keys a MAY. Neither is
  built: design §11 names mutual TLS, and a PSK is a shared secret again, which is what the
  transport replaces. A `transport: tls` device takes no key. Key groups do not apply to it, a
  `key_ref` pin on its record and a policy name group naming it are ignored, and `port49 keys
  show` says "transport tls (RFC 9887): no shared key; its credential is its certificate".
  `port49 keys status` leaves it out. Obfuscation never runs on the TLS listener (RFC 9887 §4).
- **R4. Admission: a TLS device is admitted, and served only by the TLS listener.** Spec §10's
  "until plan 11, `transport: tls` is refused admission" is replaced. `tls` is admitted with no
  `key_ref`, and an unknown transport is still refused (`refused_transport`). Which listener a
  device may use is decided per connection, not at admission. A connection on the listener its
  device does not speak is declined: diagnosis `transport_mismatch`, recorded, no strike, and a
  decline window, as an admission refusal is (spec §10). Admission takes no account of which
  listeners this port49d runs. This keeps one policy meaning one thing on every replica, so a
  split deployment (a TLS-only port49d beside a TCP-only one, RFC 9887 §5.1.1's recommendation)
  never refuses, mints nothing different, and raises no `admission_refused` alarm for the other
  host's devices. A port49d holding devices of a transport it does not serve says so at start and
  at every reload that changes the count: "N devices have transport tls and port49d serves no
  tls_listener; their connections here are declined transport_mismatch: leaf-01, ...". It also
  exports `port49_devices_by_transport{transport}`. A swap that changes a device's transport is
  a security change, `transport_changed` (inventory_change, `port49 inventory diff`), and its
  `key_ref_changed` is not also reported. An open connection whose device's transport a reload
  changed is withdrawn at its next packet (`admission_withdrawn`), as a re-key is.
- **R5. Everything that needs no TLS byte is decided at Accept.** On the TLS listener an
  unadmitted source is struck and reset. A refused device, a quarantined one and one of the
  other transport are recorded, declined and reset. Each happens before the handshake, so
  none of them costs a key exchange or a signature: the listener is unauthenticated until the
  handshake ends, and a handshake is the CPU amplifier spec §10 forbids. Their records carry no
  header fields (none was read), `transport: tls`, and the device block where one is known. The
  RFC 8907 listener is unchanged, except that a `tls` device's first header there is recorded
  `transport_mismatch` and declined, as `admission_refused` is today.
- **R6. A device is found by its source address and must be named by its certificate** (RFC 9887
  §3.4.2). The source address still finds the device (spec §10's binding, unchanged). The
  verified leaf must also name that device, by `device_identity.match` (default both, either
  suffices):
  - `dns_name`: a subjectAltName dNSName equal, case-insensitively and with a trailing dot
    dropped, to the inventory name, or to the name plus `.` plus one of
    `device_identity.dns_suffixes`.
  - `ip_address`: a subjectAltName iPAddress that is one of the device's inventory addresses.

  RFC 9887 requires both match kinds to be supported. A wildcard dNSName never names a device.
  The common name is never read (RFC 9525). The mapping comes from the inventory alone, with no
  per-device configuration, so a fleet enrolled by SCEP, ACME or EST under one naming rule needs
  nothing from the operator per device. A certificate naming another device is
  `identity_mismatch`, and the record says what it named and what was wanted.
- **R7. The chain** (RFC 9887 §3.4, §3.4.1). It is verified by `x509.Certificate.Verify` against
  `client_ca_file` (each a CA certificate), with the peer's own intermediates plus
  `intermediates_file`'s. A device sending only its leaf therefore verifies, as RFC 9887
  §3.4.1's stored chain requires. The leaf must carry the clientAuth extended key usage or none
  (RFC 5280): a serverAuth-only certificate is `certificate_invalid`, and what devices'
  enrolments issue is L73 (e). An unknown anchor is `unknown_ca`. A leaf expired or not yet
  valid is `certificate_expired`. Every other path error is `certificate_invalid`.
- **R8. Revocation is required, refuse by default** (RFC 9887 §3.4: "MUST validate the
  certificate path ... including revocation checking"). `tls_listener.certificate_status` is
  required and has the broker's shape exactly (decision 33): `crls`, `ocsp`,
  `refresh_interval`, `on_unavailable` (refuse, the default, or allow), or `disabled: true`
  explicitly. A second `certstatus.Checker` serves it, its lines begun `tls_listener:
  certificate status:`, and its kept lists in `tls_listener.state_dir` (required with `crls`).
  A revoked chain is `certificate_revoked`. A status that cannot be established is
  `status_unavailable` under refuse. That is port49's fault, not the device's, so it is a
  decline (no strike). Under allow the device is admitted and the checker's own lines and
  `port49_cert_status_unavailable_total` say so. At 3am a CRL server down past the list's
  `nextUpdate` declines every TLS device to its local method. The operator sees the checker's
  line, the `status_unavailable` records and outcome counter, and the start line naming the
  CRL's next update. The escape is a `file:` CRL source the operator copies in, or
  `on_unavailable: allow`, a reviewed change.
- **R9. An open connection is judged at every packet.** Holding a connection open never extends a
  certificate's life (as spec §10 says of a key version). Each packet re-checks every chain
  certificate's `NotAfter` and the chain's status (the checker's lists are cached, so this is a
  map lookup). When the listener's files have been reloaded since the handshake, the chain is
  verified again in full. A failure is recorded (`tls_refused`, with the packet's header fields)
  and the connection reset, with no strike: the device did nothing on this connection. Its next
  handshake is judged, and struck, as any other.
- **R10. SNI** (RFC 9887 §3.4.2, §5.1.5). `server_names`, when set, are the names a
  ClientHello's SNI may carry. Any other is refused at the ClientHello (`sni_mismatch`;
  `crypto/tls` sends `internal_error`). An absent SNI is accepted, because a device configured with
  the server's address sends none (RFC 6066 forbids an IP literal there). SNI is not identity, and it
  travels in clear. The check is there to catch a device pointed at the wrong port49 (a lab device
  at production).
- **R11. Resumption: off by default; single-use and age-bounded when on** (RFC 9887 §3.6).
  `session_ticket_lifetime` is `0s` by default (no ticket issued: every connection a full
  handshake), and at most `1h`. With tickets on, each ticket carries its issue time. One
  older than the lifetime, or presented twice, is ignored and the connection does a full
  handshake (RFC 9887 §3.6, "SHOULD allow resumption if the ticket ... has not expired and has
  not been used before"). The ticket keys are random per load of the listener's files, so a
  reload invalidates every ticket outstanding, and they are never written anywhere. A resumption
  runs `VerifyConnection` again: the chain is verified against the anchors in force and its
  status checked (RFC 9887 §3.6, "certificates must be verified to check for revocation"). The
  lifetime a ticket advertises is `crypto/tls`'s fixed seven days; port49 enforces its own. Off
  is the default because every full handshake re-verifies everything, and how often devices
  resume is unmeasured (L73 (g)).
- **R12. 0-RTT is refused.** `crypto/tls` aborts a ClientHello carrying `early_data` with
  `unsupported_extension`, the abrupt disconnect RFC 9887 §5.1.2 requires. It is recorded
  `early_data_refused` and struck. A port49 ticket never permits early data (measured, L72 (k)).
- **R13. An obfuscated packet over TLS gets an ERROR and a close** (RFC 9887 §4). A header whose
  unencrypted flag is clear is answered with the ERROR status of its type
  (`TAC_PLUS_AUTHEN_STATUS_ERROR`, `_AUTHOR_`, `_ACCT_`), with the flag set and `seq_no + 1`, and
  then the connection closes. Its body is never read. It is recorded `obfuscated_over_tls` with
  no strike, because the peer holds a valid certificate and is misconfigured, not hostile. Every
  reply on the TLS listener sets the unencrypted flag. A packet that fails another header check
  is `not_tacacs` and struck, as on 49.
- **R14. The handshake has a deadline**: `handshake_timeout`, default 5s, 1s to 30s. That bounds
  the slot a stalled peer holds under the per-NAS cap. A timeout is `handshake_timeout`, struck.
  The default sits above the shortest measured reply timeout (3s, L13) only because a
  handshake that takes longer is already lost to that device, and the deadline exists to free
  the slot.
- **R15. The listener's files reload without a restart.** `cert_file`, `key_file`,
  `client_ca_file` and `intermediates_file` are read again every `reload_interval` (default 1m,
  10s to 1h) and at every SIGHUP. A set whose bytes changed and that loads is swapped in whole
  and said: the anchors by subject and SHA-256, and the server certificate's expiry. A set
  that does not load is refused and said once per distinct failure, and the set in force stays.
  A server certificate already expired at load is loaded and said loudly, because refusing it
  would also take down nothing the device can use. With a short-lived certificate issued by
  automation, rotation needs no step from the operator.
- **R16. What is recorded and counted.**
  - A record of an exchange on the TLS listener carries `device.transport: "tls"` and
    `device.cert_sha256`, and no `key_ref`. A TCP record is byte-for-byte unchanged.
  - A refusal is `unvalidated` with diagnosis `tls_refused`, `transport: "tls"`, `tls_outcome`,
    `detail` (bounded, printable) and `cert_sha256` where a certificate was sent.
  - `port49_tls_handshakes_total{outcome}` counts `ok`, `resumed`, and every refusal outcome.
  - `port49_tls_device_certificate_expiry_seconds` is the least time to expiry among device
    certificates verified in the last 24h, `+Inf` with none.
  - `port49_tls_server_certificate_expiry_seconds` is the server certificate's time to
    expiry.
  - `port49_devices_by_transport{transport}` counts admitted devices.
  - A device whose verified certificate expires within `expiry_warning` (default 336h; `0s` is
    off) is named in one line at most every 24h.
  - A refusal is also said on stderr, at most once per device and outcome every 10 minutes:
    the decision log is the audit trail, and stderr is where the 3am reader looks first.
  - `port49_connection_events_total` gains `tls_refused`, `transport_mismatch` and
    `obfuscated_over_tls`.
- **R17. One device, one set of limits.** The per-NAS cap, strikes, backoff and decline windows
  are per source address, shared by both listeners. A device struck on 300 is held on 49 too, so
  it cannot double its slots or reset its backoff by changing port.
- **R18. plan 1's mode serves TLS too.** port49d with no `broker:` block reads the inventory
  file's key groups. A `tls` device needs none, and "a device that matches no key group refuses
  the start" exempts it.
- **R19. The lab.** Vendor documentation (read 2026-10-16) puts RFC 9887 clients in Arista EOS
  4.36.1F (Arista TOI "TACACS+ over TLS", EOS-4.36.1F), Cisco IOS XE 17.18.1 (Cisco document
  225097), Cisco NX-OS 10.6(1)F on Nexus 9000 (Cisco document 224882) and Junos (Juniper
  "TACACS+ over TLS overview", release not stated). Every lab image predates these:
  - vEOS-lab 4.31.2F (tagged 4.32.2F);
  - Catalyst 8000V 17.13.01a;
  - Nexus 9300v 10.4(2)F;
  - vJunos-router 23.4R2-S2.1;
  - vSRX3 21.4R3.15.

  So:
  - **L71** measures, on each image, whether its CLI offers a TLS TACACS+ client at all,
    expected none.
  - **L72** measures port49 itself against reference clients (`openssl s_client` 3.x and a Go
    client in `tests/lab/cmd/tacacs-tls-client`), and closes in this plan.
  - **L73** holds every claim about a device's RFC 9887 behaviour and stays open until Q1's
    images arrive. Device configuration and reference AAA configs for TLS are plan 12's, on L73.

## Questions for Ryan

- **Q1. Images that carry an RFC 9887 client.** L73 cannot close without one. The floors are
  vendor-documented and unmeasured. Each needs your vendor account:
  - cEOS-lab or vEOS-lab 4.36.1F or later (arista.com);
  - Catalyst 8000V 17.18.1 or later (CCO);
  - Nexus 9300v at 10.6(1)F or later. Cisco's document tests a C9364D-GX2A and does not say
    the 9300v carries it.
  - a vJunos-router or vSRX release whose CLI has `set system tacplus-server <ip> tls`. Juniper's
    page names no release.

  Recommendation: fetch C8000V 17.18 first. Cisco's document is the most specific, and the
  C8000V is the lab's fastest boot. Until then the device column is open, and the reference
  harness (L72) is the only measurement.
- **Q2. One host serving both listeners.** RFC 9887 §5.1.1 says it is NOT RECOMMENDED (a SHOULD
  NOT). Ruled (R1) as allowed with a start notice. The design requires separable, not
  separated, and per-device transport (R4) already refuses the downgrade. The stricter
  alternative is to refuse both on one port49d unless `tls_listener.share_host: true`. That
  costs every migrating deployment one more key, and buys no protection R4 does not already
  give. Recommendation: keep the notice.

## The operator at 3am

What each case looks like, and what fixes it. "Record" is the decision log; "line" is stderr.

| Case | The device sees | port49d says | Fix |
|---|---|---|---|
| A device's certificate expired | `bad_certificate` alert, falls to its next server or local method; retries inside the backoff are reset at Accept | record `tls_refused`/`certificate_expired` naming the device, the subject and `NotAfter`; line once per 10m; `port49_tls_handshakes_total{outcome="certificate_expired"}`; before it happened, the `expiry_warning` line and `port49_tls_device_certificate_expiry_seconds` | renew it on the device; nothing at port49 |
| The device CA rotated | old certificates: `unknown_ca` per device once `client_ca_file` lost the old CA; open connections close at their next packet | reload line naming the anchors in force by SHA-256; records `unknown_ca` | keep both CAs in `client_ca_file` until every device re-enrolled; `port49_tls_handshakes_total{outcome="unknown_ca"}` reads zero before removing the old one |
| The CRL is unreachable | until the list's `nextUpdate`, nothing; after it, every TLS device is declined (local method at once, decline window) | `tls_listener: certificate status: CRL x: ...` lines; records `status_unavailable`; `port49_cert_status_unavailable_total` | restore the CRL source; a `file:` source copied in by hand works at once; `on_unavailable: allow` is the reviewed escape |
| A device speaks TLS 1.2 only | `protocol_version` alert | record `version_refused`, "offered 303; RFC 9887 requires TLS 1.3" | upgrade the device, or set it back to `transport: tcp` and the RFC 8907 server |
| A device on the wrong port or transport | a reset before any TLS byte (TCP device on 300), or a reset after its first header (TLS device on 49) | record `transport_mismatch` naming the device and its record's transport; line | correct the device's server port, or the record's `transport` |
| SNI mismatch | `internal_error` alert at ClientHello | record `sni_mismatch`, "asked for server name X" | correct the device's configured server name, or `server_names` |
| Mixed fleet | each device on its own listener; nothing | start line counts each transport; `port49_devices_by_transport` | none |
| Certificate names another device | `bad_certificate` | record `identity_mismatch`: "the certificate names dns_name [leaf-02.example.net]; device leaf-01 is dns_name leaf-01 or leaf-01.example.net, or ip_address 10.0.1.5" | reissue the certificate, or fix the inventory name or address |
| port49d's own certificate expired | the device refuses port49 (its side; L73 (d)) | start or reload line "server certificate ... expired"; `port49_tls_server_certificate_expiry_seconds` < 0 | replace `cert_file`; picked up within `reload_interval` |

## Review Focus

- **A device certificate naming the device in another spelling** (`LEAF-01.Example.NET.`, or the
  name under a suffix not configured): a person expects case and a trailing dot not to matter, and
  an unlisted suffix to refuse with a detail saying which names were wanted. Task 4's identity
  table pins each.
- **A CA rotated while a single-connect session is open**: a person expects the session to end at
  its next packet when its chain no longer verifies, not to run until idle. Task 8's
  `TestTLSReloadedAnchorsEndAnOpenConnection` pins it.
- **A device's `transport` flipped by a sync while it holds a connection**: a person expects the
  open connection to end at its next packet and the next one to be declined on the listener it no
  longer speaks. Task 8's `TestTLSTransportChangeWithdrawsAnOpenConnection` pins it.
- **A CRL outage under `on_unavailable: refuse`**: a person expects the device to fall to its local
  method at once (decline, no strike). They do not expect it to be struck into a backoff that
  outlives the outage. Task 7's `TestTLSStatusUnavailableIsDeclinedNotStruck` pins it.
- **A ticket presented twice, or after a reload**: a person expects a full handshake, never an
  error or a refusal. Task 9's `TestTicketsAreSingleUse` and `TestAReloadInvalidatesTickets` pin
  them.

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md` | the spec and design first | 1 |
| `internal/tacacs/wire/header.go`, `errors.go`, `tlserror.go` (new) | `ValidateTLS`, `ErrObfuscatedOverTLS`, `ErrorReply` | 2 |
| `internal/admission/admission.go` | `tls` admitted without a key; `Device.EffectiveTransport` | 3 |
| `internal/policy/admit.go`, `internal/config/config.go` (no-broker check), `internal/bundle/diff.go`, `cmd/port49/keys.go` | key checks skip TLS devices; `transport_changed`; `keys show`/`status` | 3 |
| `internal/devicecert/{outcome,identity,verify,expiry}.go` (new) | the device certificate's verdict | 4 |
| `internal/certstatus/certstatus.go`, `crl.go` | `Config.Component` for the line prefix | 5 |
| `internal/config/config.go`, `internal/config/tlslistener.go` (new) | `tls_listener:`, `listen: none` | 5 |
| `internal/decision/log.go`, `internal/keyring/keyring.go`, `internal/daemon/metrics/metrics.go`, `internal/daemon/authen/authen.go` | record fields, diagnoses, metrics, the peer | 6 |
| `internal/daemon/server/tls.go` (new), `server.go`, `conn.go` | Accept decisions, the handshake, the packet path | 7, 8 |
| `internal/daemon/server/tickets.go` (new) | single-use, age-bounded tickets | 9 |
| `internal/port49d/tlslistener.go` (new), `certstatus.go`, `main.go`, `reload.go` | loading, reloading, wiring, start lines | 10 |
| `tests/lab/cmd/tacacs-tls-client/main.go` (new), `tests/lab/l72_test.go` (new), `tests/lab/README.md` | the reference harness | 11 |
| `tests/lab/l71_test.go` (new) | the image probe | 12 |
| `tests/lab/results/L71-*.md`, `L72-reference.md`, spec §15 | the runs | 13 |
| `docs/superpowers/plans/README.md` | the roadmap's record and operator notes | 14 |

---

### Task 1: The spec and the design first

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the vocabulary every later task cites. Diagnoses `transport_mismatch`, `tls_refused`
  and `obfuscated_over_tls`. The `tls_outcome` values `version_refused`,
  `no_client_certificate`, `unknown_ca`, `certificate_expired`, `certificate_invalid`,
  `certificate_revoked`, `status_unavailable`, `identity_mismatch`, `sni_mismatch`,
  `early_data_refused`, `handshake_timeout` and `handshake_failed`. The record fields of R16, the
  change kind `transport_changed`, decision 50, and L71–L73.

- [ ] **Step 1: §10, "Admission and keys"**

Replace the paragraph at :4937 ("RFC 9887 replaces the shared key with mutual TLS, so a device
record MUST be able to express both: ... Until plan 11 serves RFC 9887, a device with `transport:
tls` is refused admission, as is one whose `transport` is neither; the file and the rest of the
fleet load (above).") with:

```markdown
RFC 9887 replaces the shared key with mutual TLS, so a device record MUST be able to express
both: `transport: tcp` (the default, RFC 8907 under a shared key, served on `listen`) or
`transport: tls` (RFC 9887, TLS 1.3 with mutual certificates, served on `tls_listener`; §13
decision 50). A `tls` device is admitted with no `key_ref`: key groups do not apply to it, and a
pin on its record or a policy name group naming it is ignored. Its credential is its certificate.
A device whose `transport` is neither is refused admission (`refused_transport`); the file and the
rest of the fleet load (above). Which listener serves a device is decided per connection, never at
admission. A connection on the listener the device does not speak is declined as a refused
device's is, and recorded `transport_mismatch`. So one policy admits the same devices on every
replica, whichever listeners each runs (decision 50 ruling 4).
```

In the same section's refusal paragraph (:4917, "A device is refused on its own, never the
daemon"), change "and one whose `transport` port49d does not serve (below)" to "and one whose
`transport` is neither `tcp` nor `tls` (below)".

- [ ] **Step 2: §10, "Device records"**

After the paragraph ending "`transport` is above." (:5326), add:

```markdown
A `tls` device's certificate must name it: by a subjectAltName dNSName equal to its `name`, or to
`name` under one of `tls_listener.device_identity.dns_suffixes`, or by a subjectAltName iPAddress
among its `addresses` (decision 50 ruling 6). Nothing per device is configured at port49: the
inventory's name and addresses are the mapping, so a fleet enrolled under one naming rule needs no
step per device.
```

- [ ] **Step 3: §10, the diagnosis buckets**

After the paragraph ending "with no strike either way." (:5142, the `admission_withdrawn`
paragraph), add:

```markdown
An eighth, `transport_mismatch`, is a connection from an admitted device on the listener it does
not speak: a `tls` device's first header on the RFC 8907 listener, or a `tcp` device at Accept on
the RFC 9887 listener. It is declined as `admission_refused` is, with no strike (decision 50
ruling 4).

A ninth, `tls_refused`, is a connection the RFC 9887 listener refused at its handshake, or an open
one it ended because the certificate stopped verifying. The record carries `transport: "tls"`, a
`tls_outcome`, a bounded printable `detail` and, where a certificate was sent, its `cert_sha256`
(decision 50 rulings 7–14):

| `tls_outcome` | Means | Strike |
|---|---|---|
| `version_refused` | the ClientHello offered no TLS 1.3 | yes |
| `no_client_certificate` | the device sent no certificate | yes |
| `unknown_ca` | its chain reaches no `client_ca_file` anchor | yes |
| `certificate_expired` | a certificate in its chain is expired or not yet valid | yes |
| `certificate_invalid` | any other path error, a serverAuth-only leaf included | yes |
| `certificate_revoked` | a certificate in its chain is revoked | yes |
| `status_unavailable` | its status could not be established under `on_unavailable: refuse` | no: declined |
| `identity_mismatch` | the leaf does not name the device its source address is | yes |
| `sni_mismatch` | the ClientHello asked for a server name not in `server_names` | yes |
| `early_data_refused` | the ClientHello carried `early_data` (RFC 9887 §5.1.2) | yes |
| `handshake_timeout` | no handshake within `handshake_timeout` | yes |
| `handshake_failed` | anything else: a bad signature, a client abort | yes |

At a later packet an open connection is ended as `tls_refused` with the packet's header fields,
and with no strike.

A tenth, `obfuscated_over_tls`, is a packet on the RFC 9887 listener whose unencrypted flag is
clear. It is answered with its type's ERROR status, the flag set, and the connection closed
(RFC 9887 §4). Its body is not read, and it is no strike: the peer's certificate verified.

On the RFC 9887 listener no body is hashed into any record: there a body is the cleartext of a
peer that holds a certificate, and may carry a credential.
```

In "**The unencrypted flag is refused.**" (:5115), prefix the first sentence with "On the RFC
8907 listener, " and append at the paragraph's end: "On the RFC 9887 listener the opposite holds:
TLS is the boundary, and the flag MUST be set on every packet in both directions (RFC 9887 §4;
`obfuscated_over_tls` above)."

- [ ] **Step 4: §5.7, the record fields and `inventory_change`**

After the `device.key_ref` paragraph (:2230), add:

```markdown
`device.transport` is `"tls"` on every record of an exchange on the RFC 9887 listener, and absent
on the RFC 8907 listener's, which are unchanged. With it, `device.cert_sha256` is the SHA-256 of
the device's verified leaf certificate, lower-case hex. Such a record has no `key_ref`: no key
validated it (§13 decision 50 ruling 16). An `unvalidated` record from that listener carries
`transport`, and a `tls_refused` one `tls_outcome`, `detail` and `cert_sha256` (§10).
```

In the `inventory_change` paragraph (:2281), after "`key_ref_changed` with `"from"` and `"to"` for
a device's key assignment changing," insert "`transport_changed` with `"from"` and `"to"` for a
device's `transport` changing (its `key_ref_changed` is then not also written),".

- [ ] **Step 5: "Per-device keys are not supported" and the three-key table**

At :5293–5297, replace "That is a reason to prefer the TLS transport as clients appear, and it is
recorded rather than acted on because no mainstream network OS ships a TLS-capable TACACS+ client
(design document §2)." with "That is a reason to prefer the TLS transport where a device has a
client. Plan 11 serves it (`transport: tls`, §13 decision 50). Vendor documentation puts clients in
recent releases; no lab image has one, and what devices do is unmeasured (§15 L71, L73)."

- [ ] **Step 6: §13, decision 50**

After decision 49's last bullet (`- **16. The lab.** L69 on kind; L70 (managed clusters) open.`),
add:

```markdown
**50. RFC 9887: a second listener, a certificate in place of the key, decided at Accept where it
can be.** *Plan 11, 2026-10-16.* Rulings rest on reasoning unless they say data. The planner ruled
each where this document and RFC 9887 were silent; Ryan may override any.
```

followed by one bullet per ruling R1 to R19 of this plan's "Rulings" section, numbered 1 to 19,
each `- **N. <its bold title without "RN.">** <its text>`, copied word for word. Then append to
the "Deferred, with reasons" list (:8000) one bullet:

```markdown
- **RFC 9887's PSK and raw-public-key authentication, configurable TLS 1.3 cipher suites, and the
  TLS Cached Information Extension** (decision 50 rulings 2 and 3): PSKs and raw public keys are a
  MAY, and a PSK is the shared secret mutual TLS replaces; `crypto/tls` offers neither a TLS 1.3
  suite setting nor RFC 7924, and port49 takes no cgo.
```

- [ ] **Step 7: §15, three rows**

After the L70 row, add:

```markdown
| **L71** | Which lab images carry an RFC 9887 (TACACS+ over TLS) client at all, read from each image's own CLI help with no configuration committed: EOS `tacacs-server host <ip> ?` (an `ssl-profile` or `tls` option), IOS-XE `tacacs server <name>` then `tls ?`, NX-OS `tacacs-server host <ip> ?` and `tacacs-server secure ?`, Junos `set system tacplus-server <ip> ?` (a `tls` option). Vendor documentation puts the floors at EOS 4.36.1F, IOS XE 17.18.1, NX-OS 10.6(1)F and an unnamed Junos release, all after every lab image. | §13 decision 50 ruling 19; whether L73 can be measured on an image in hand | vEOS-lab 4.31.2F, C8000V 17.13.01a, N9300v 10.4(2)F, vJunos-router 23.4R2-S2.1, vSRX3 21.4R3.15 | open |
| **L72** | port49's RFC 9887 listener against reference clients (`openssl s_client` 3.x and `tests/lab/cmd/tacacs-tls-client`, Go `crypto/tls`), on the lab host with no device: (a) a TLS 1.3 PAP login with a seed token passes, every reply has the unencrypted flag, and the record carries `device.transport` and `device.cert_sha256` and no `key_ref`; (b) a TLS 1.2-only client: the alert the client reports and `version_refused`; (c) no client certificate: the alert and `no_client_certificate`; (d) an unknown CA, (e) an expired leaf, (f) a leaf naming another device, (g) a leaf a CRL file lists: each one's alert and outcome; (h) a CRL source past its `nextUpdate` and unreachable: `status_unavailable`, and the next connection reset at Accept with no strike; (i) a server name not in `server_names`: the alert and `sni_mismatch`; (j) with `session_ticket_lifetime: 10m`, a second connection resumes, and one ticket presented twice resumes once; (k) `openssl s_client -early_data` with a port49 session: whether any early data is sent; (l) a packet with the unencrypted flag clear: the reply's status and flags and the close; (m) a `tcp` device's address and an address not in the inventory on the TLS listener: whether any TLS byte comes back before the reset, and the records; (n) a `tls` device's address on the RFC 8907 listener: the reset after its header and `transport_mismatch`; (o) a TCP connection that sends nothing: when it is closed and `handshake_timeout`. | §13 decision 50 rulings 2, 5, 8, 10–14 | reference clients on the lab host | open |
| **L73** | Each device's RFC 9887 client against port49, per platform, once an image carries one (L71): (a) the port it uses with none configured (RFC 9887 says 300; Cisco's documents use 6049); (b) whether every packet has the unencrypted flag set; (c) whether it sends SNI, and what; (d) whether it checks port49's certificate's dNSName or iPAddress against what it was configured with, and what it does on a mismatch and on an expired server certificate; (e) the client certificate its documented enrolment issues: subjectAltName entries, extended key usage, chain sent; (f) TLS 1.3 negotiated, and the suite; (g) whether it resumes with a port49 ticket; (h) single-connection over TLS; (i) what it does on each port49 refusal (an alert at the handshake, a reset at Accept, a decline window, an ERROR for an obfuscated packet), and how fast it falls to its next server or local method, as L28 and L31 measured on 49; (j) whether it ever falls back to a non-TLS server for the same host (RFC 9887 §5.1.1 forbids it). | §13 decision 50 rulings 1, 6, 7, 10, 11; plan 12's reference device configurations for `transport: tls` | Arista EOS ≥ 4.36.1F, Cisco IOS XE ≥ 17.18.1, Cisco NX-OS ≥ 10.6(1)F, Junos (release unknown) | open — no lab image carries a client (L71); needs images (plan 11 Q1) |
```

- [ ] **Step 8: Design §2 and §11**

In design §2 (:33–36), replace "but no mainstream network OS ships a TLS-capable TACACS+
*client*. Server-side support exists; there is nothing to talk to. Any design that depends on RFC
9887 for identity has its ship date set by hardware vendors." with "and vendors document TLS
clients only in their newest releases (Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS
10.6(1)F, Junos; unmeasured, policy engine spec §15 L71, L73), so most deployed devices cannot
speak it. Any design that depends on RFC 9887 for identity has its ship date set by hardware
vendors and by every operator's upgrade cycle."

In design §11, after "Both listeners MUST be independently configurable and MUST be separable,
per RFC 9887's requirement that TLS and non-TLS services be distinct to prevent downgrade
attacks.", add:

```markdown
port49d's `listen` is the RFC 8907 listener (`none` turns it off) and `tls_listener.listen` the
RFC 9887 one (default `:300`). Either may run alone, or both on one host. A device record's
`transport` names the one listener that serves it, and the other declines it, so a device cannot be
downgraded by blocking 300. A TLS device carries no shared key: its certificate must chain to
`tls_listener.client_ca_file`, name the device the source address finds, and not be revoked
(policy engine spec §13 decision 50). Every listener limit below applies per source across both
listeners.
```

In design §15's "The daemon exports, at minimum:" sentence, after "unvalidated packets by
diagnosis;" insert "TLS handshakes by outcome, and the soonest device and server certificate
expiry;".

- [ ] **Step 9: Check and commit**

Run: `grep -n "until plan 11\|does not serve until" docs/design/*.md internal/admission/admission.go`
Expected: only `internal/admission/admission.go` lines (Task 3 changes them); no design hit.

Run: `grep -c "^| \*\*L7[123]\*\*" docs/design/2026-08-23-policy-engine-spec.md`
Expected: `3`

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 50, the RFC 9887 listener, and lab register rows L71-L73

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: The wire: TLS header checks and the ERROR reply

**Files:**
- Modify: `internal/tacacs/wire/header.go`
- Modify: `internal/tacacs/wire/errors.go`
- Create: `internal/tacacs/wire/tlserror.go`
- Test: `internal/tacacs/wire/header_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func (h Header) ValidateTLS() error`;
  - `var ErrObfuscatedOverTLS = errors.New("wire: unencrypted flag clear over TLS; refused")`;
  - `func ErrorReply(h Header) (Header, []byte)`: the ERROR reply to request `h`, flag set, `seq_no + 1`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/tacacs/wire/header_test.go` (add `"errors"` to its imports if absent):

```go
func TestValidateTLSRequiresTheUnencryptedFlag(t *testing.T) {
	ok := Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted, Length: 10}
	if err := ok.ValidateTLS(); err != nil {
		t.Fatalf("a flagged packet over TLS: %v", err)
	}
	single := ok
	single.Flags |= FlagSingleConnect
	if err := single.ValidateTLS(); err != nil {
		t.Fatalf("single-connect beside the flag: %v", err)
	}
	for name, c := range map[string]struct {
		h    Header
		want error
	}{
		"flag clear":    {Header{MajorVersion: MajorVersion, Type: TypeAuthor, SeqNo: 1, Length: 10}, ErrObfuscatedOverTLS},
		"bad version":   {Header{MajorVersion: 0xb, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted}, ErrBadVersion},
		"bad type":      {Header{MajorVersion: MajorVersion, Type: 4, SeqNo: 1, Flags: FlagUnencrypted}, ErrBadType},
		"even seq_no":   {Header{MajorVersion: MajorVersion, Type: TypeAcct, SeqNo: 2, Flags: FlagUnencrypted}, ErrSeqNotOdd},
		// Length before the flag: a packet that is too long is noise, not a
		// misconfigured device, whatever its flag says.
		"too long, flag clear": {Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Length: MaxBodyLen + 1}, ErrTooLong},
	} {
		if err := c.h.ValidateTLS(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestValidateStillRefusesTheFlagOnTCP(t *testing.T) {
	h := Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted, Length: 10}
	if err := h.Validate(); !errors.Is(err, ErrUnencrypted) {
		t.Fatalf("RFC 8907 listener: %v, want ErrUnencrypted", err)
	}
}

func TestErrorReplyIsTheTypesErrorWithTheFlagSet(t *testing.T) {
	for typ, want := range map[Type]uint8{TypeAuthen: AuthenStatusError, TypeAuthor: AuthorStatusError, TypeAcct: AcctStatusError} {
		h := Header{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne, Type: typ, SeqNo: 3,
			Flags: FlagSingleConnect, SessionID: 7, Length: 99}
		rh, body := ErrorReply(h)
		if rh.MajorVersion != MajorVersion || rh.MinorVersion != MinorVersionOne || rh.Type != typ || rh.SeqNo != 4 ||
			rh.Flags != FlagUnencrypted || rh.SessionID != 7 || rh.Length != uint32(len(body)) {
			t.Fatalf("type %d: header %+v", typ, rh)
		}
		var got uint8
		switch typ {
		case TypeAuthen:
			r, err := DecodeAuthenReply(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		case TypeAuthor:
			r, err := DecodeAuthorResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		case TypeAcct:
			r, err := DecodeAcctReply(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		}
		if got != want {
			t.Errorf("type %d: status %#x, want %#x", typ, got, want)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/tacacs/wire/ -run 'TestValidateTLS|TestValidateStill|TestErrorReply' -v`
Expected: FAIL to build: `h.ValidateTLS undefined`, `undefined: ErrObfuscatedOverTLS`,
`undefined: ErrorReply`.

- [ ] **Step 3: Implement**

In `internal/tacacs/wire/errors.go`, add to the `var` block after `ErrUnencrypted`:

```go
	// ErrObfuscatedOverTLS is a packet on the RFC 9887 listener whose
	// unencrypted flag is clear: RFC 9887 §4 requires the flag on every packet
	// over TLS, and an ERROR reply to one without it.
	ErrObfuscatedOverTLS = errors.New("wire: unencrypted flag clear over TLS; refused")
```

In `internal/tacacs/wire/header.go`, after `Validate`, add:

```go
// ValidateTLS is Validate for a packet on the RFC 9887 listener (spec §10;
// §13 decision 50 ruling 13): the same checks, but the unencrypted flag MUST
// be set, since TLS is the boundary and obfuscation never runs over it (RFC
// 9887 §4). Length comes before the flag, so a packet too long to be TACACS+
// is noise whatever its flag says.
func (h Header) ValidateTLS() error {
	switch {
	case h.MajorVersion != MajorVersion:
		return ErrBadVersion
	case h.Type < TypeAuthen || h.Type > TypeAcct:
		return ErrBadType
	case h.SeqNo%2 == 0:
		return ErrSeqNotOdd
	case h.Length > MaxBodyLen:
		return ErrTooLong
	case h.Flags&FlagUnencrypted == 0:
		return ErrObfuscatedOverTLS
	}
	return nil
}
```

Create `internal/tacacs/wire/tlserror.go`:

```go
package wire

// ErrorReply is the reply RFC 9887 §4 requires to a packet whose unencrypted
// flag is clear on a TLS connection: the ERROR status of the request's type,
// with the unencrypted flag set, seq_no one past the request's. h has passed
// every ValidateTLS check but the flag, so its type is one of the three.
func ErrorReply(h Header) (Header, []byte) {
	var body []byte
	switch h.Type {
	case TypeAuthen:
		body = AuthenReply{Status: AuthenStatusError}.Encode()
	case TypeAuthor:
		body = AuthorResponse{Status: AuthorStatusError}.Encode()
	default:
		body = AcctReply{Status: AcctStatusError}.Encode()
	}
	return Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type, SeqNo: h.SeqNo + 1,
		Flags: FlagUnencrypted, SessionID: h.SessionID, Length: uint32(len(body))}, body
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/tacacs/wire/ -v -run 'TestValidateTLS|TestValidateStill|TestErrorReply' && go test ./internal/tacacs/wire/`
Expected: PASS, and the package's other tests and fuzz seeds still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/tacacs/wire/
git commit -m "feat: wire header checks for TLS and the RFC 9887 ERROR reply

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 3: Admission admits a TLS device with no key

**Files:**
- Modify: `internal/admission/admission.go` (`TransportTLS` comment :24, `transportRefusal` :241,
  `Resolve` :268, `Build` :312)
- Modify: `internal/policy/admit.go` (`admit` :124)
- Modify: `internal/config/config.go` (the no-broker check :1137)
- Modify: `internal/bundle/diff.go` (kinds :19, the per-device diff :133)
- Modify: `cmd/port49/keys.go` (`keysStatus` :122, `keysShow` :172)
- Modify: `internal/daemon/server/server_test.go:1314` (its refusal text only)
- Test: `internal/admission/admission_test.go`, `internal/policy/admit_test.go`,
  `internal/bundle/diff_test.go`, `cmd/port49/keys_test.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func (d Device) EffectiveTransport() string`, which is `TransportTCP` for `""`;
  - `Resolve` and `Build` admitting a `tls` device with `KeyRef ""`;
  - `bundle.TransportChanged = "transport_changed"`.

- [ ] **Step 1: Write the failing tests**

In `internal/admission/admission_test.go`, replace the loop at :303–308 (the `tls-1`/`udp-1`
refusal) and the trie expectations below it with:

```go
	if r := Resolve(byName["tls-1"], inv.KeyGroups); r.Refused != "" || r.KeyRef != "" {
		t.Errorf("tls-1: a TLS device is admitted with no key_ref (decision 50 ruling 4), got %+v", r)
	}
	r := Resolve(byName["udp-1"], inv.KeyGroups)
	if r.Refusal != RefusedTransport || r.KeyRef != "" || !strings.Contains(r.Refused, `transport "udp"`) {
		t.Errorf("udp-1: want refused_transport, got %+v", r)
	}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	for addr, admitted := range map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": false} {
		if _, ok := tr.Lookup(netip.MustParseAddr(addr)); ok != admitted {
			t.Errorf("%s: admitted %v, want %v", addr, ok, admitted)
		}
	}
```

(The fixture above that loop gives `tls-1` the address 10.0.0.3 and `udp-1` 10.0.0.4; check
before editing, and adjust the addresses in the map to the fixture's if they differ.) Then add:

```go
func TestATLSDeviceIgnoresKeyGroupsAndItsPin(t *testing.T) {
	d := Device{Name: "tls-9", Platform: "arista_eos", Transport: TransportTLS, KeyRef: "pinned_key",
		Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.1")}}
	groups := []KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"},
		{Name: "tls-9", KeyRef: "other_key"}}
	r := Resolve(d, groups)
	if r.Refused != "" || r.KeyRef != "" {
		t.Fatalf("a TLS device takes no key, pinned or grouped: %+v", r)
	}
	if got := d.EffectiveTransport(); got != TransportTLS {
		t.Fatalf("EffectiveTransport: %q", got)
	}
	if got := (Device{}).EffectiveTransport(); got != TransportTCP {
		t.Fatalf("an absent transport is tcp: %q", got)
	}
	// Build, plan 1's no-broker mode: a TLS device none of the groups is
	// needed for is indexed, admitted.
	tr, err := Build(Inventory{Devices: []Device{d}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := tr.Lookup(netip.MustParseAddr("10.9.0.1")); !ok || got.Refused != "" || got.KeyRef != "" {
		t.Fatalf("Build: %+v %v", got, ok)
	}
}
```

In `internal/policy/admit_test.go`, add (using the file's existing helper that loads a policy
against an inventory with `Env.KeyRefs`; it is the one the `RefusedUnknownKey` test uses, find
it with `grep -n "RefusedUnknownKey" internal/policy/admit_test.go`):

```go
func TestATLSDeviceIsNotRefusedForAKeyPort49dLacks(t *testing.T) {
	inv := []admission.Device{
		{Name: "tls-1", Platform: "arista_eos", Transport: admission.TransportTLS,
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}},
	}
	p, err := Parse([]byte(minimalPolicyForAdmit), Env{Devices: inv, KeyRefs: []string{"prod_key"}})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Admitted("tls-1")
	if !ok || r.Refused != "" || r.KeyRef != "" {
		t.Fatalf("tls-1: %+v %v", r, ok)
	}
	if _, has := p.KeyAssignment("tls-1"); has {
		t.Fatal("a TLS device has no key assignment for keys show to print")
	}
	if n := len(p.AdmissionRefusals()); n != 0 {
		t.Fatalf("refusals: %d", n)
	}
}
```

If the file has no `minimalPolicyForAdmit`, use the smallest policy body another test in that
file parses with key groups `[{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]`, copied as a
`const` above the test.

In `internal/bundle/diff_test.go`, add a case beside the existing `KeyRefChanged` test (find it
with `grep -n KeyRefChanged internal/bundle/diff_test.go`), building `old` with `leaf-01`
`transport: tcp` under a group's key and `new` with `leaf-01` `transport: tls`:

```go
func TestATransportFlipIsOneSecurityChange(t *testing.T) {
	old := loadDiffBundle(t, diffPolicy, "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}\n")
	new := loadDiffBundle(t, diffPolicy,
		"devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], transport: tls}\n")
	var kinds []string
	for _, c := range Diff(old, new, time.Now()) {
		if c.Device == "leaf-01" {
			kinds = append(kinds, c.Kind)
			if c.Kind == TransportChanged && (c.From != "tcp" || c.To != "tls" || !c.Security) {
				t.Errorf("transport_changed: %+v", c)
			}
		}
	}
	if !slices.Equal(kinds, []string{TransportChanged}) {
		t.Fatalf("changes for leaf-01: %v, want only transport_changed", kinds)
	}
}
```

`loadDiffBundle`, `diffPolicy` and `Diff`'s exact name and signature are the file's own. Read
`internal/bundle/diff_test.go`'s first `KeyRefChanged` test and use its helpers and call form,
renaming here to match; `diffPolicy` must carry `key_groups: [{match: {cidr: 10.0.0.0/8},
key_ref: prod_key}]`.

In `cmd/port49/keys_test.go`, add (using the file's fixture writer for `--policy`/`--inventory`,
as the `leaf-19` tests do):

```go
func TestKeysShowSaysATLSDeviceHasNoKey(t *testing.T) {
	pol, inv := writeKeysFixture(t, "devices:\n  - {name: tls-7, platform: arista_eos, addresses: [10.20.0.7], transport: tls}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "tls-7"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if want := "tls-7: transport tls (RFC 9887): no shared key; its credential is its certificate"; !strings.Contains(out.String(), want) {
		t.Fatalf("got %q", out.String())
	}
}
```

`writeKeysFixture` is whatever the file's existing `keys show` tests use to write `pol` and `inv`;
reuse it with this inventory.

In `internal/config/config_test.go`, add a no-broker load whose inventory file holds one `tls`
device and no key group matching it, and which loads (the start is not refused):

```go
func TestNoBrokerModeAdmitsATLSDeviceWithNoKeyGroup(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	writeFile(t, inv, "devices:\n"+
		"  - {name: tls-1, platform: arista_eos, addresses: [10.0.0.9], transport: tls}\n"+
		"  - {name: tcp-1, platform: arista_eos, addresses: [10.0.0.1]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.1/32}, key_ref: k}\n")
	t.Setenv("T_K", "secret")
	cfg := filepath.Join(dir, "port49d.yaml")
	writeFile(t, cfg, "listen: 127.0.0.1:0\ninventory_file: "+inv+"\nkeys:\n  k:\n    current: {version: 1, secret_env: T_K}\n")
	c, err := Load(cfg)
	if err != nil {
		t.Fatalf("a TLS device with no key group refused the start: %v", err)
	}
	if r, ok := c.Admission.Lookup(netip.MustParseAddr("10.0.0.9")); !ok || r.Refused != "" || r.KeyRef != "" {
		t.Fatalf("tls-1: %+v %v", r, ok)
	}
}
```

The config needs whatever else this file's other no-broker `Load` tests write (an
`encryption:` block, an `accounting.spool_path` in `t.TempDir()`). Copy the smallest such fixture
from `internal/config/config_test.go` and add only the inventory above. `writeFile` is the file's
own helper; if it has none, use `os.WriteFile(path, []byte(body), 0o600)` with a `t.Fatal` on
error.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/admission/ ./internal/policy/ ./internal/bundle/ ./cmd/port49/ ./internal/config/ -run 'TLS|Transport' -v`
Expected: FAIL. `Resolve` refuses `tls-1` (`refused_transport`), `EffectiveTransport` is
undefined, `TransportChanged` is undefined, `keys show` prints "refused admission", and the
config load fails "matches no key group".

- [ ] **Step 3: Implement admission**

In `internal/admission/admission.go`:

Change the constant's comment at :24 to `TransportTLS = "tls" // RFC 9887, mutual TLS; no shared
key (spec §13 decision 50)`.

After the `Device` struct, add:

```go
// EffectiveTransport is the device's transport with the default applied:
// "" is TransportTCP (spec §10).
func (d Device) EffectiveTransport() string {
	if d.Transport == "" {
		return TransportTCP
	}
	return d.Transport
}
```

Replace `transportRefusal` with:

```go
// transportRefusal is why a device's transport is no transport at all, or ""
// for tcp and tls. Which listener serves a device is decided per connection,
// never here (spec §13 decision 50 ruling 4). It refuses the device, never
// the file: a sync can write one, and refusing the file would stop every
// inventory change fleet-wide (spec §10).
func transportRefusal(d Device) string {
	switch d.Transport {
	case "", TransportTCP, TransportTLS:
		return ""
	default:
		return fmt.Sprintf("has transport %q, which is not tcp or tls", d.Transport)
	}
}
```

In `Resolve`, after the `transportRefusal` check and before `pinRefusal`, add:

```go
	if d.EffectiveTransport() == TransportTLS {
		// Mutual TLS replaces the shared key: no group, tie or pin applies,
		// and the record's key_ref, if any, is ignored (decision 50 ruling 3).
		return r
	}
```

In `Build`, replace the loop body with:

```go
	for _, d := range inv.Devices {
		if transportRefusal(d) != "" {
			continue // refused alone (spec §10)
		}
		if d.EffectiveTransport() == TransportTLS {
			entries = append(entries, Resolved{Device: d}) // admitted, no key (decision 50 ruling 18)
			continue
		}
		if pinRefusal(d) != "" {
			continue
		}
		as, err := Assign(d, inv.KeyGroups)
		if err != nil {
			return nil, err
		}
		if as.KeyRef == "" {
			continue // in inventory, but no group admits it: refused (spec §10)
		}
		entries = append(entries, Resolved{Device: d, KeyRef: as.KeyRef})
	}
```

and in `Build`'s doc comment change "or whose transport port49d does not serve" to "or whose
transport is neither tcp nor tls", and add "A tls device is indexed with no key_ref." Update the
`Resolved.Refused` comment's "its transport is one port49d does not serve" to "its transport is
neither tcp nor tls".

- [ ] **Step 4: Implement the policy, config, diff and keys changes**

In `internal/policy/admit.go`'s `admit`, change the `KeyRefs` check's condition to:

```go
		if r.Refused == "" && d.EffectiveTransport() != admission.TransportTLS && p.env.KeyRefs != nil &&
			!slices.Contains(p.env.KeyRefs, r.KeyRef) {
```

and guard the assignment record:

```go
		// How the key_ref was chosen, for `port49 keys show`; a tie has none,
		// and a TLS device takes no key (decision 50 ruling 3).
		if d.EffectiveTransport() != admission.TransportTLS {
			if as, err := admission.Assign(d, p.keyGroups); err == nil {
				p.assigned[d.Name] = as
			}
		}
```

In `internal/config/config.go`, change the no-broker check's condition (:1142) to:

```go
			if r, ok := trie.Lookup(a); ok && r.Refused == "" &&
				(r.KeyRef != "" || r.Device.EffectiveTransport() == admission.TransportTLS) {
```

and the comment above the loop to begin "A tcp device that matches no key group ...".

In `internal/bundle/diff.go`, add `TransportChanged = "transport_changed"` to the kinds after
`KeyRefChanged`, and in the per-device diff replace the `KeyRefChanged` block with:

```go
			// A transport change swaps the device's credential, a shared key
			// for a certificate or back (decision 50 ruling 4): a security
			// change, and the key_ref change it implies is not said twice.
			if ot, nt := o.EffectiveTransport(), n.EffectiveTransport(); ot != nt {
				add(Change{Kind: TransportChanged, Device: name, Platform: n.Platform, From: ot, To: nt, Security: true})
			} else if ro.Refused == "" && rn.Refused == "" && ro.KeyRef != rn.KeyRef {
				add(Change{Kind: KeyRefChanged, Device: name, Platform: n.Platform, From: ro.KeyRef, To: rn.KeyRef,
					Security: true})
			}
```

(`o` and `n` are the old and new `admission.Device`, as the `PlatformChanged` line above uses
them.) Add `TransportChanged` wherever the file lists the security kinds an `inventory_change`
record names (`grep -n KeyRefChanged internal/bundle/*.go internal/port49d/*.go
internal/inventory/*.go` and add it beside each non-test use; a `port49_inventory_changes_total`
pre-registration list, if one exists, gets it too).

In `cmd/port49/keys.go`, in `keysShow` after the `r.Refused` check, add:

```go
	if r.Device.EffectiveTransport() == admission.TransportTLS {
		fmt.Fprintf(stdout, "%s: transport tls (RFC 9887): no shared key; its credential is its certificate\n", name)
		return 0
	}
```

and in `keysStatus` skip TLS devices when building `devices`:

```go
	for _, d := range p.Devices() {
		if d.EffectiveTransport() == admission.TransportTLS {
			continue // no key to phase out (decision 50 ruling 3)
		}
```

Add the `admission` import to `cmd/port49/keys.go` if absent.

In `internal/daemon/server/server_test.go:1314`, change the refusal text to `Refused: "has
transport \"udp\", which is not tcp or tls"`. The test's point (a refused entry is never
validated) is unchanged.

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./internal/admission/ ./internal/policy/ ./internal/bundle/ ./cmd/port49/ ./internal/config/ ./internal/daemon/server/ ./internal/inventory/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/admission internal/policy internal/config internal/bundle cmd/port49 internal/daemon/server/server_test.go internal/inventory internal/port49d
git commit -m "feat: admit a transport tls device with no shared key

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: `internal/devicecert`, the device certificate's verdict

**Files:**
- Create: `internal/devicecert/outcome.go`, `identity.go`, `verify.go`, `expiry.go`
- Test: `internal/devicecert/identity_test.go`, `verify_test.go`, `outcome_test.go`, `expiry_test.go`

**Interfaces:**
- Consumes: `admission.Device`, `admission.Device.EffectiveTransport` (Task 3); `printsafe.Line`;
  `testpki` in tests.
- Produces (package `devicecert`, imports only the standard library, `internal/admission` and
  `internal/printsafe`):
  - `type Outcome string` and its constants `OK`, `Resumed`, `VersionRefused`,
    `NoClientCertificate`, `UnknownCA`, `CertificateExpired`, `CertificateInvalid`,
    `CertificateRevoked`, `StatusUnavailable`, `IdentityMismatch`, `SNIMismatch`,
    `EarlyDataRefused`, `HandshakeTimeout` and `HandshakeFailed`; `var Outcomes []Outcome` (the
    refusals); `func (o Outcome) Struck() bool`.
  - `type Verdict struct{ Outcome Outcome; Detail string; Leaf *x509.Certificate; Chain
    []*x509.Certificate; StatusUnknown bool }`.
  - `type Refusal struct{ Verdict Verdict }`, implementing `error`.
  - `func Classify(err error, timedOut bool) Outcome`.
  - `type Rule struct{ DNSName, IPAddress bool; DNSSuffixes []string }`; `func (r Rule)
    Match(leaf *x509.Certificate, dev admission.Device) error`.
  - `type Status int`, with `StatusGood`, `StatusRevoked` and `StatusUnknown`; `type StatusFunc
    func(ctx context.Context, chain []*x509.Certificate) (Status, string)`.
  - `type Verifier struct{ Anchors *x509.CertPool; Intermediates []*x509.Certificate; Rule Rule;
    Status StatusFunc; AllowUnknown bool; Now func() time.Time }`, with `func (v *Verifier)
    Verify(ctx context.Context, certs []*x509.Certificate, dev admission.Device) Verdict` and
    `func (v *Verifier) Recheck(ctx context.Context, was Verdict) Verdict`.
  - `func Fingerprint(leaf *x509.Certificate) string`.
  - `type Expiry struct{ Warn time.Duration; Say func(string, ...any) }`, with `func (e *Expiry)
    Seen(device string, leaf *x509.Certificate, now time.Time)` and `func (e *Expiry)
    Soonest(now time.Time) (time.Duration, bool)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/devicecert/identity_test.go`:

```go
package devicecert

import (
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

func leafNaming(dns []string, ips ...string) *x509.Certificate {
	c := &x509.Certificate{DNSNames: dns}
	for _, s := range ips {
		c.IPAddresses = append(c.IPAddresses, net.ParseIP(s))
	}
	return c
}

func TestRuleMatch(t *testing.T) {
	dev := admission.Device{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.5"),
		netip.MustParseAddr("2001:db8::5")}}
	both := Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"net.example.com"}}
	for name, c := range map[string]struct {
		rule Rule
		leaf *x509.Certificate
		ok   bool
	}{
		"exact name":                 {both, leafNaming([]string{"leaf-01"}), true},
		"name under a suffix":        {both, leafNaming([]string{"leaf-01.net.example.com"}), true},
		"case and trailing dot":      {both, leafNaming([]string{"LEAF-01.Net.Example.COM."}), true},
		"an unlisted suffix":         {both, leafNaming([]string{"leaf-01.other.example.com"}), false},
		"another device":             {both, leafNaming([]string{"leaf-02.net.example.com"}), false},
		"a wildcard never":           {both, leafNaming([]string{"*.net.example.com"}), false},
		"a name only as a prefix":    {both, leafNaming([]string{"leaf-01x"}), false},
		"one of its addresses":       {both, leafNaming(nil, "10.0.1.5"), true},
		"its v6 address":             {both, leafNaming(nil, "2001:db8::5"), true},
		"an address not its own":     {both, leafNaming(nil, "10.0.1.6"), false},
		"dns only ignores addresses": {Rule{DNSName: true}, leafNaming(nil, "10.0.1.5"), false},
		"ip only ignores names":      {Rule{IPAddress: true}, leafNaming([]string{"leaf-01"}), false},
	} {
		err := c.rule.Match(c.leaf, dev)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestRuleMatchNeverReadsTheCommonName(t *testing.T) {
	leaf := leafNaming(nil)
	leaf.Subject.CommonName = "leaf-01"
	if err := (Rule{DNSName: true, IPAddress: true}).Match(leaf, admission.Device{Name: "leaf-01"}); err == nil {
		t.Fatal("the common name named the device (RFC 9525: it is never read)")
	}
}

func TestAMismatchSaysWhatWasNamedAndWanted(t *testing.T) {
	dev := admission.Device{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.5")}}
	err := Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"example.net"}}.Match(
		leafNaming([]string{"leaf-02.example.net"}, "10.9.9.9"), dev)
	if err == nil {
		t.Fatal("matched")
	}
	for _, want := range []string{"leaf-02.example.net", "10.9.9.9", "leaf-01 or leaf-01.example.net", "10.0.1.5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err, want)
		}
	}
}
```

Create `internal/devicecert/verify_test.go`:

```go
package devicecert

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/testpki"
)

var dev01 = admission.Device{Name: "leaf-01", Transport: admission.TransportTLS,
	Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}

type pki struct {
	root, issuing *testpki.CA
	now           time.Time
}

func newPKI(t *testing.T) pki {
	t.Helper()
	now := time.Now()
	root, err := testpki.NewCA("Device Root", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := root.IssueCA("Device Issuing", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return pki{root: root, issuing: issuing, now: now}
}

func (p pki) leaf(t *testing.T, l testpki.Leaf) *x509.Certificate {
	t.Helper()
	if l.NotBefore.IsZero() {
		l.NotBefore, l.NotAfter = p.now.Add(-time.Minute), p.now.Add(time.Hour)
	}
	c, err := p.issuing.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

func (p pki) verifier(status StatusFunc, allow bool) *Verifier {
	return &Verifier{Anchors: p.root.Pool(), Intermediates: []*x509.Certificate{p.issuing.Cert},
		Rule: Rule{DNSName: true, IPAddress: true}, Status: status, AllowUnknown: allow,
		Now: func() time.Time { return p.now }}
}

func good(context.Context, []*x509.Certificate) (Status, string) { return StatusGood, "" }

func TestVerify(t *testing.T) {
	p := newPKI(t)
	other, err := testpki.NewCA("Other", p.now.Add(-time.Hour), p.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	strange, err := other.Issue(testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
		NotBefore: p.now.Add(-time.Minute), NotAfter: p.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		certs []*x509.Certificate
		want  Outcome
	}{
		"a client leaf naming the device": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})}, OK},
		"no extended key usage is any purpose": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, NoExtKeyUsage: true})}, OK},
		"by address": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{IPs: []net.IP{net.ParseIP("127.0.0.1")}, Client: true})}, OK},
		"no certificate": {nil, NoClientCertificate},
		"another CA":     {[]*x509.Certificate{strange.Leaf}, UnknownCA},
		"expired": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
			NotBefore: p.now.Add(-2 * time.Hour), NotAfter: p.now.Add(-time.Hour)})}, CertificateExpired},
		"not yet valid": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
			NotBefore: p.now.Add(time.Hour), NotAfter: p.now.Add(2 * time.Hour)})}, CertificateExpired},
		"serverAuth only": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}})}, CertificateInvalid},
		"another device":  {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-02"}, Client: true})}, IdentityMismatch},
	} {
		v := p.verifier(good, false).Verify(context.Background(), c.certs, dev01)
		if v.Outcome != c.want {
			t.Errorf("%s: %s (%s), want %s", name, v.Outcome, v.Detail, c.want)
		}
		if c.want == OK && (len(v.Chain) != 3 || v.Chain[2] != p.root.Cert) {
			t.Errorf("%s: chain %d long, want leaf, issuing, root", name, len(v.Chain))
		}
	}
}

func TestVerifyUsesStoredIntermediates(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	v := p.verifier(good, false)
	v.Intermediates = nil
	if got := v.Verify(context.Background(), []*x509.Certificate{leaf}, dev01); got.Outcome != UnknownCA {
		t.Fatalf("leaf alone, no stored intermediate: %s", got.Outcome)
	}
	if got := v.Verify(context.Background(), []*x509.Certificate{leaf, p.issuing.Cert}, dev01); got.Outcome != OK {
		t.Fatalf("leaf with its intermediate sent: %s %s", got.Outcome, got.Detail)
	}
	v.Intermediates = []*x509.Certificate{p.issuing.Cert}
	if got := v.Verify(context.Background(), []*x509.Certificate{leaf}, dev01); got.Outcome != OK {
		t.Fatalf("leaf alone, intermediate stored (RFC 9887 §3.4.1): %s %s", got.Outcome, got.Detail)
	}
}

func TestVerifyStatus(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	revoked := func(context.Context, []*x509.Certificate) (Status, string) { return StatusRevoked, "crl issuing: revoked" }
	unknown := func(context.Context, []*x509.Certificate) (Status, string) { return StatusUnknown, "crl issuing: stale" }
	if v := p.verifier(revoked, false).Verify(context.Background(), []*x509.Certificate{leaf}, dev01); v.Outcome != CertificateRevoked {
		t.Fatalf("revoked: %s", v.Outcome)
	}
	if v := p.verifier(unknown, false).Verify(context.Background(), []*x509.Certificate{leaf}, dev01); v.Outcome != StatusUnavailable {
		t.Fatalf("unknown under refuse: %s", v.Outcome)
	}
	v := p.verifier(unknown, true).Verify(context.Background(), []*x509.Certificate{leaf}, dev01)
	if v.Outcome != OK || !v.StatusUnknown || v.Detail != "crl issuing: stale" {
		t.Fatalf("unknown under allow: %+v", v)
	}
	if v := p.verifier(nil, false).Verify(context.Background(), []*x509.Certificate{leaf}, dev01); v.Outcome != OK {
		t.Fatalf("certificate_status disabled: %s", v.Outcome)
	}
}

func TestRecheck(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	st := StatusGood
	ver := p.verifier(func(context.Context, []*x509.Certificate) (Status, string) { return st, "per crl" }, false)
	was := ver.Verify(context.Background(), []*x509.Certificate{leaf}, dev01)
	if got := ver.Recheck(context.Background(), was); got.Outcome != OK {
		t.Fatalf("unchanged: %s", got.Outcome)
	}
	st = StatusRevoked
	if got := ver.Recheck(context.Background(), was); got.Outcome != CertificateRevoked {
		t.Fatalf("revoked since: %s", got.Outcome)
	}
	st = StatusGood
	ver.Now = func() time.Time { return leaf.NotAfter.Add(time.Second) }
	if got := ver.Recheck(context.Background(), was); got.Outcome != CertificateExpired {
		t.Fatalf("expired since: %s", got.Outcome)
	}
}

func TestFingerprint(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	if f := Fingerprint(leaf); len(f) != 64 || Fingerprint(nil) != "" {
		t.Fatalf("%q", f)
	}
}

func TestRefusalUnwrapsToItsVerdict(t *testing.T) {
	err := error(&Refusal{Verdict: Verdict{Outcome: IdentityMismatch, Detail: "x"}})
	var r *Refusal
	if !errors.As(err, &r) || Classify(err, false) != IdentityMismatch {
		t.Fatal(err)
	}
}
```

Create `internal/devicecert/outcome_test.go`:

```go
package devicecert

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassify(t *testing.T) {
	for msg, want := range map[string]Outcome{
		"tls: client sent unexpected early data":               EarlyDataRefused,
		"tls: client didn't provide a certificate":             NoClientCertificate,
		"tls: client offered only unsupported versions: [303]": VersionRefused,
		"tls: invalid signature by the client certificate":     HandshakeFailed,
		"EOF": HandshakeFailed,
	} {
		if got := Classify(errors.New(msg), false); got != want {
			t.Errorf("%q: %s, want %s", msg, got, want)
		}
	}
	if got := Classify(fmt.Errorf("x: %w", context.DeadlineExceeded), false); got != HandshakeTimeout {
		t.Errorf("deadline: %s", got)
	}
	if got := Classify(errors.New("read: connection reset"), true); got != HandshakeTimeout {
		t.Errorf("timed out: %s", got)
	}
}

func TestOnlyStatusUnavailableIsNotStruck(t *testing.T) {
	for _, o := range Outcomes {
		if o.Struck() == (o == StatusUnavailable) {
			t.Errorf("%s: Struck %v", o, o.Struck())
		}
	}
	if OK.Struck() || Resumed.Struck() {
		t.Error("a success is struck")
	}
	if len(Outcomes) != 12 {
		t.Fatalf("%d refusal outcomes, want spec §10's 12", len(Outcomes))
	}
}
```

Create `internal/devicecert/expiry_test.go`:

```go
package devicecert

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestExpiryWarnsOncePerDayAndKnowsTheSoonest(t *testing.T) {
	var lines []string
	e := &Expiry{Warn: 14 * 24 * time.Hour, Say: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	now := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	soon := &x509.Certificate{NotAfter: now.Add(9 * 24 * time.Hour), SerialNumber: big.NewInt(0xbeef)}
	late := &x509.Certificate{NotAfter: now.Add(90 * 24 * time.Hour), SerialNumber: big.NewInt(1)}
	e.Seen("leaf-07", soon, now)
	e.Seen("leaf-07", soon, now.Add(time.Hour))
	e.Seen("leaf-08", late, now)
	if len(lines) != 1 || !strings.Contains(lines[0], "leaf-07") || !strings.Contains(lines[0], "beef") {
		t.Fatalf("lines: %q", lines)
	}
	e.Seen("leaf-07", soon, now.Add(25*time.Hour))
	if len(lines) != 2 {
		t.Fatalf("a day later it is said again: %q", lines)
	}
	if d, ok := e.Soonest(now.Add(25 * time.Hour)); !ok || d != soon.NotAfter.Sub(now.Add(25*time.Hour)) {
		t.Fatalf("soonest: %v %v", d, ok)
	}
	// At +50h leaf-07 was last seen 25h before and leaf-08 50h before: both
	// are outside the 24h window, so nothing counts.
	if _, ok := e.Soonest(now.Add(50 * time.Hour)); ok {
		t.Fatal("nothing was seen in the last 24h")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/devicecert/`
Expected: FAIL to build: the package has no non-test files.

- [ ] **Step 3: Implement**

Create `internal/devicecert/outcome.go`:

```go
// Package devicecert decides whether a device's TLS client certificate
// admits it on the RFC 9887 listener (spec §10; §13 decision 50): a path to
// a configured anchor, the device's own identity in its subjectAltName, and
// its revocation status. It decides nothing about policy.
package devicecert

import (
	"context"
	"errors"
	"os"
	"strings"
)

// Outcome is a handshake's result: the record's tls_outcome and
// port49_tls_handshakes_total's outcome, one closed vocabulary (spec §10).
type Outcome string

const (
	OK                  Outcome = "ok"
	Resumed             Outcome = "resumed"
	VersionRefused      Outcome = "version_refused"
	NoClientCertificate Outcome = "no_client_certificate"
	UnknownCA           Outcome = "unknown_ca"
	CertificateExpired  Outcome = "certificate_expired"
	CertificateInvalid  Outcome = "certificate_invalid"
	CertificateRevoked  Outcome = "certificate_revoked"
	StatusUnavailable   Outcome = "status_unavailable"
	IdentityMismatch    Outcome = "identity_mismatch"
	SNIMismatch         Outcome = "sni_mismatch"
	EarlyDataRefused    Outcome = "early_data_refused"
	HandshakeTimeout    Outcome = "handshake_timeout"
	HandshakeFailed     Outcome = "handshake_failed"
)

// Outcomes is every refusal, in spec §10's order.
var Outcomes = []Outcome{VersionRefused, NoClientCertificate, UnknownCA, CertificateExpired, CertificateInvalid,
	CertificateRevoked, StatusUnavailable, IdentityMismatch, SNIMismatch, EarlyDataRefused, HandshakeTimeout,
	HandshakeFailed}

// Struck reports whether a refusal counts against its source, as a key
// miss does. Only status_unavailable does not: the status could not be
// established, which is port49's fault, so it is a decline (decision 50
// ruling 8).
func (o Outcome) Struck() bool {
	switch o {
	case OK, Resumed, StatusUnavailable:
		return false
	}
	return true
}

// Refusal is the error a handshake fails with when port49 refused it; its
// Verdict says why.
type Refusal struct{ Verdict Verdict }

func (r *Refusal) Error() string {
	return "devicecert: " + string(r.Verdict.Outcome) + ": " + r.Verdict.Detail
}

// Classify names a failed handshake from crypto/tls's error when no Verdict
// did. timedOut is whether the handshake's own deadline passed. The three
// texts are crypto/tls's (handshake_server.go, handshake_server_tls13.go,
// Go 1.26); TestClassify pins them, and L72 measures them.
func Classify(err error, timedOut bool) Outcome {
	var r *Refusal
	switch {
	case errors.As(err, &r):
		return r.Verdict.Outcome
	case timedOut, errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return HandshakeTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unexpected early data"):
		return EarlyDataRefused
	case strings.Contains(msg, "didn't provide a certificate"):
		return NoClientCertificate
	case strings.Contains(msg, "unsupported versions"):
		return VersionRefused
	}
	return HandshakeFailed
}
```

Create `internal/devicecert/identity.go`:

```go
package devicecert

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"crypto/x509"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Rule is tls_listener.device_identity (decision 50 ruling 6): which
// subjectAltName kinds name a device, and the DNS suffixes its inventory
// name may carry. Suffixes are lower case with no leading or trailing dot
// (config refuses any other). The common name is never read (RFC 9525).
type Rule struct {
	DNSName     bool
	IPAddress   bool
	DNSSuffixes []string
}

// Match is nil when leaf names dev: a dNSName equal to its name, or its
// name under a suffix, case-insensitively and with a trailing dot dropped;
// or an iPAddress among its inventory addresses. A wildcard never names a
// device. The error says what the certificate named and what was wanted.
func (r Rule) Match(leaf *x509.Certificate, dev admission.Device) error {
	if r.DNSName {
		for _, san := range leaf.DNSNames {
			if r.namesDevice(san, dev.Name) {
				return nil
			}
		}
	}
	if r.IPAddress {
		for _, ip := range leaf.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && slices.Contains(dev.Addresses, a.Unmap()) {
				return nil
			}
		}
	}
	return errors.New(r.describe(leaf, dev))
}

func (r Rule) namesDevice(san, name string) bool {
	san = strings.TrimSuffix(strings.ToLower(san), ".")
	name = strings.ToLower(name)
	if san == "" || strings.Contains(san, "*") {
		return false
	}
	if san == name {
		return true
	}
	for _, s := range r.DNSSuffixes {
		if san == name+"."+s {
			return true
		}
	}
	return false
}

func (r Rule) describe(leaf *x509.Certificate, dev admission.Device) string {
	var has, want []string
	if r.DNSName {
		has = append(has, "dns_name "+bounded(leaf.DNSNames))
		names := []string{dev.Name}
		for _, s := range r.DNSSuffixes {
			names = append(names, dev.Name+"."+s)
		}
		want = append(want, "dns_name "+strings.Join(names, " or "))
	}
	if r.IPAddress {
		ips := make([]string, 0, len(leaf.IPAddresses))
		for _, ip := range leaf.IPAddresses {
			ips = append(ips, ip.String())
		}
		has = append(has, "ip_address "+bounded(ips))
		addrs := make([]string, 0, len(dev.Addresses))
		for _, a := range dev.Addresses {
			addrs = append(addrs, a.String())
		}
		want = append(want, "ip_address "+strings.Join(addrs, " or "))
	}
	return printsafe.Line(fmt.Sprintf("the certificate names %s; device %s is %s", strings.Join(has, " and "),
		dev.Name, strings.Join(want, ", or ")), 400)
}

// bounded lists at most eight entries, "[none]" for none.
func bounded(s []string) string {
	if len(s) == 0 {
		return "[none]"
	}
	if len(s) > 8 {
		return "[" + strings.Join(s[:8], " ") + fmt.Sprintf(" and %d more]", len(s)-8)
	}
	return "[" + strings.Join(s, " ") + "]"
}
```

(Put `"crypto/x509"` in the standard-library import group; `gofmt` sorts it.)

Create `internal/devicecert/verify.go`:

```go
package devicecert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Status is a verified chain's revocation status.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnknown
)

// StatusFunc is a verified chain's status, leaf first and anchor last, and a
// line saying which source decided and, when unknown, why. port49d adapts
// certstatus.Checker.Check to it.
type StatusFunc func(ctx context.Context, chain []*x509.Certificate) (Status, string)

// Verdict is one judgement of a device's certificate.
type Verdict struct {
	Outcome Outcome
	// Detail is a bounded, printable line for the record and stderr.
	Detail string
	// Leaf is the device's certificate, when it sent one; Chain the verified
	// path, leaf first and anchor last, on OK.
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	// StatusUnknown is an OK under on_unavailable: allow whose status could
	// not be established; Detail says why.
	StatusUnknown bool
}

// Verifier is one load of tls_listener's anchors and rules (decision 50
// rulings 6–8). It is immutable once built: a reload builds another.
type Verifier struct {
	Anchors       *x509.CertPool
	Intermediates []*x509.Certificate // intermediates_file's (RFC 9887 §3.4.1)
	Rule          Rule
	Status        StatusFunc // nil when certificate_status is disabled
	AllowUnknown  bool       // on_unavailable: allow
	Now           func() time.Time
}

// Verify judges certs, as the device sent them, leaf first, for dev: a path
// to an anchor through the sent and stored intermediates, with the
// clientAuth usage (or none); the device's identity; then the chain's
// status. It runs at a full handshake and at a resumption alike.
func (v *Verifier) Verify(ctx context.Context, certs []*x509.Certificate, dev admission.Device) Verdict {
	if len(certs) == 0 {
		return Verdict{Outcome: NoClientCertificate, Detail: "the device sent no certificate"}
	}
	leaf := certs[0]
	pool := x509.NewCertPool()
	for _, c := range certs[1:] {
		pool.AddCert(c)
	}
	for _, c := range v.Intermediates {
		pool.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.Anchors, Intermediates: pool, CurrentTime: v.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return Verdict{Outcome: chainOutcome(err), Detail: printsafe.Line(err.Error(), 300), Leaf: leaf}
	}
	if err := v.Rule.Match(leaf, dev); err != nil {
		return Verdict{Outcome: IdentityMismatch, Detail: err.Error(), Leaf: leaf}
	}
	return v.status(ctx, Verdict{Outcome: OK, Leaf: leaf, Chain: chains[0]})
}

// Recheck judges an open connection's chain again at a later packet:
// expiry of every certificate in it, then its status (decision 50 ruling 9).
// The path itself is verified again only by Verify, when the anchors changed.
func (v *Verifier) Recheck(ctx context.Context, was Verdict) Verdict {
	now := v.Now()
	for _, c := range was.Chain {
		if now.After(c.NotAfter) {
			return Verdict{Outcome: CertificateExpired, Leaf: was.Leaf, Detail: printsafe.Line(fmt.Sprintf(
				"%s expired at %s", c.Subject, c.NotAfter.UTC().Format(time.RFC3339)), 300)}
		}
	}
	return v.status(ctx, Verdict{Outcome: OK, Leaf: was.Leaf, Chain: was.Chain})
}

func (v *Verifier) status(ctx context.Context, ok Verdict) Verdict {
	if v.Status == nil {
		return ok
	}
	st, detail := v.Status(ctx, ok.Chain)
	switch st {
	case StatusRevoked:
		return Verdict{Outcome: CertificateRevoked, Detail: printsafe.Line(detail, 300), Leaf: ok.Leaf}
	case StatusUnknown:
		if v.AllowUnknown {
			ok.StatusUnknown, ok.Detail = true, printsafe.Line(detail, 300)
			return ok
		}
		return Verdict{Outcome: StatusUnavailable, Detail: printsafe.Line(detail, 300), Leaf: ok.Leaf}
	}
	return ok
}

func chainOutcome(err error) Outcome {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return UnknownCA
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return CertificateExpired
	}
	return CertificateInvalid
}

// Fingerprint is leaf's SHA-256, lower-case hex, as records carry it: ""
// when there is no leaf.
func Fingerprint(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}
```

Create `internal/devicecert/expiry.go`:

```go
package devicecert

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// seenWindow is how long a device's last verified certificate counts
// toward the soonest expiry: a device not seen for a day may be gone.
const seenWindow = 24 * time.Hour

// Expiry remembers when each device's last verified certificate expires,
// for tls_listener.expiry_warning's line and
// port49_tls_device_certificate_expiry_seconds (decision 50 ruling 16).
type Expiry struct {
	Warn time.Duration // 0 is off
	Say  func(format string, args ...any)

	mu   sync.Mutex
	seen map[string]seenCert
}

type seenCert struct{ notAfter, at, warned time.Time }

// Seen notes leaf as device's at now, and says once a day when it expires
// within Warn.
func (e *Expiry) Seen(device string, leaf *x509.Certificate, now time.Time) {
	e.mu.Lock()
	if e.seen == nil {
		e.seen = map[string]seenCert{}
	}
	s := e.seen[device]
	s.notAfter, s.at = leaf.NotAfter, now
	warn := e.Warn > 0 && leaf.NotAfter.Sub(now) < e.Warn && now.Sub(s.warned) >= seenWindow
	if warn {
		s.warned = now
	}
	e.seen[device] = s
	e.mu.Unlock()
	if warn && e.Say != nil {
		e.Say("tls_listener: %s's certificate (serial %s, issuer %s) expires %s, in %s; renew it before then",
			device, leaf.SerialNumber.Text(16), printsafe.Line(leaf.Issuer.String(), 200),
			leaf.NotAfter.UTC().Format(time.RFC3339), leaf.NotAfter.Sub(now).Round(time.Hour))
	}
}

// Soonest is the least time to expiry among certificates seen in the last
// 24h, and whether there was one. Older entries are dropped.
func (e *Expiry) Soonest(now time.Time) (time.Duration, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var least time.Duration
	found := false
	for name, s := range e.seen {
		if now.Sub(s.at) > seenWindow {
			delete(e.seen, name)
			continue
		}
		if d := s.notAfter.Sub(now); !found || d < least {
			least, found = d, true
		}
	}
	return least, found
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/devicecert/ -v && go vet ./internal/devicecert/`
Expected: PASS. `x509.Verify` reports a serverAuth-only leaf asked for clientAuth as
`CertificateInvalidError{Reason: IncompatibleUsage}`, hence `certificate_invalid`.

- [ ] **Step 5: Commit**

```bash
git add internal/devicecert/
git commit -m "feat: devicecert, the verdict on a device's TLS client certificate

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: `tls_listener:` and `listen: none` in the config

**Files:**
- Create: `internal/config/tlslistener.go`
- Modify: `internal/config/config.go` (`fileConfig` :514, `Config` :577, `daemonDefaults`
  :1166, `checkCertificateStatus` :1778, `brokerRefusals` :1408, `load`)
- Modify: `internal/certstatus/certstatus.go` (`Config`, `New`), `internal/certstatus/crl.go` (the
  four `"broker: certificate status: "` literals)
- Test: `internal/config/tlslistener_test.go`, `internal/certstatus/crl_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `type TLSListenerConfig struct` (fields below) and `type DeviceIdentityConfig struct{ Match
    []string; DNSSuffixes []string }`;
  - `Config.TLSListener *TLSListenerConfig`, nil without the block;
  - `Config.Listen == ""` meaning `listen: none`;
  - `const ListenNone = "none"`;
  - `func checkStatusBlock(cs *CertificateStatusConfig, key, stateDir string, others []namedPath) error`;
  - `certstatus.Config.Component string`: the line prefix, `"broker"` when empty.

- [ ] **Step 1: Write the failing tests**

Create `internal/config/tlslistener_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsBase writes a no-broker port49d.yaml with one TLS device, the files a
// tls_listener names (contents unread by Load), and block appended.
func tlsBase(t *testing.T, top, block string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"srv.crt", "srv.key", "ca.pem", "inter.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: tls-1, platform: arista_eos, addresses: [10.0.0.9], transport: tls}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("T_ENC", "33333333333333333333333333333333")
	body := top + "metrics_listen: 127.0.0.1:0\ninventory_file: " + inv + "\n" +
		"encryption:\n  current: {id: v1, secret_env: T_ENC}\naccounting: {spool_path: " + filepath.Join(dir, "acct.jsonl") + "}\n" +
		strings.ReplaceAll(block, "DIR", dir)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const tlsMinimal = `tls_listener:
  cert_file: DIR/srv.crt
  key_file: DIR/srv.key
  client_ca_file: DIR/ca.pem
  certificate_status: {disabled: true}
`

func TestTLSListenerDefaults(t *testing.T) {
	c, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal))
	if err != nil {
		t.Fatal(err)
	}
	tl := c.TLSListener
	if tl == nil || tl.Listen != ":300" || tl.HandshakeTimeout != 5*time.Second || tl.SessionTicketLifetime != 0 ||
		tl.ExpiryWarning != 336*time.Hour || tl.ReloadInterval != time.Minute {
		t.Fatalf("defaults: %+v", tl)
	}
	if got := tl.DeviceIdentity.Match; len(got) != 2 || got[0] != "dns_name" || got[1] != "ip_address" {
		t.Fatalf("match default: %v", got)
	}
}

func TestListenNone(t *testing.T) {
	c, err := Load(tlsBase(t, "listen: none\n", tlsMinimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "" {
		t.Fatalf("listen: none is the empty Listen, got %q", c.Listen)
	}
	if _, err := Load(tlsBase(t, "listen: none\n", "")); err == nil ||
		!strings.Contains(err.Error(), "serves no TACACS+ listener") {
		t.Fatalf("neither listener: %v", err)
	}
}

func TestTLSListenerRefusals(t *testing.T) {
	for name, c := range map[string]struct{ top, block, want string }{
		"same bind": {"listen: 0.0.0.0:300\n", tlsMinimal, "same address as listen"},
		"wildcard against a host": {"listen: \":300\"\n",
			strings.Replace(tlsMinimal, "tls_listener:\n", "tls_listener:\n  listen: 10.0.0.1:300\n", 1), "same address as listen"},
		"no cert_file": {"", strings.Replace(tlsMinimal, "  cert_file: DIR/srv.crt\n", "", 1), "tls_listener.cert_file is required"},
		"no client_ca_file": {"", strings.Replace(tlsMinimal, "  client_ca_file: DIR/ca.pem\n", "", 1),
			"tls_listener.client_ca_file is required"},
		"no certificate_status": {"", strings.Replace(tlsMinimal, "  certificate_status: {disabled: true}\n", "", 1),
			"tls_listener.certificate_status is required"},
		"unknown match": {"", tlsMinimal + "  device_identity: {match: [common_name]}\n", "dns_name or ip_address"},
		"empty match":   {"", tlsMinimal + "  device_identity: {match: []}\n", "dns_name or ip_address"},
		"suffix without dns_name": {"", tlsMinimal + "  device_identity: {match: [ip_address], dns_suffixes: [example.net]}\n",
			"dns_suffixes needs dns_name"},
		"wildcard suffix":      {"", tlsMinimal + "  device_identity: {dns_suffixes: [\"*.example.net\"]}\n", "not a DNS suffix"},
		"wildcard server name": {"", tlsMinimal + "  server_names: [\"*.example.net\"]\n", "not a server name"},
		"handshake too long":   {"", tlsMinimal + "  handshake_timeout: 1m\n", "between 1s and 30s"},
		"tickets too long":     {"", tlsMinimal + "  session_ticket_lifetime: 2h\n", "between 0s and 1h"},
		"reload too fast":      {"", tlsMinimal + "  reload_interval: 1s\n", "between 10s and 1h"},
		"crls without state_dir": {"", strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
			"certificate_status: {crls: [{name: issuing, file: DIR/ca.pem, issuer_file: DIR/ca.pem}]}", 1),
			"tls_listener.state_dir is required"},
	} {
		top := c.top
		if top == "" {
			top = "listen: 127.0.0.1:0\n"
		}
		if _, err := Load(tlsBase(t, top, c.block)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestTLSListenerStatusIsTheBrokersShape(t *testing.T) {
	block := strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
		"certificate_status: {crls: [{name: issuing, url: \"http://crl.example.net/i.crl\", issuer_file: DIR/ca.pem}]}", 1) +
		"  state_dir: DIR\n"
	c, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", block))
	if err != nil {
		t.Fatal(err)
	}
	cs := c.TLSListener.CertificateStatus
	if cs.OnUnavailable != "refuse" || cs.RefreshInterval != 10*time.Minute {
		t.Fatalf("the broker's defaults apply: %+v", cs)
	}
	bad := strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
		"certificate_status: {crls: [{name: issuing, url: \"http://crl.example.net/i.crl\", issuer_file: DIR/ca.pem}], "+
			"on_unavailable: maybe}", 1) + "  state_dir: DIR\n"
	if _, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", bad)); err == nil ||
		!strings.Contains(err.Error(), "tls_listener.certificate_status.on_unavailable must be refuse or allow") {
		t.Fatalf("on_unavailable: %v", err)
	}
}

func TestTheBrokerRefusesATLSListener(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49-broker.yaml")
	if err := os.WriteFile(p, []byte("tls_listener:\n  cert_file: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// brokerRefusals runs right after the decode, before any required key
	// is asked for.
	_, err := LoadBroker(p)
	if err == nil || !strings.Contains(err.Error(), "tls_listener is not port49-broker.yaml's") {
		t.Fatalf("port49-broker.yaml with tls_listener: %v", err)
	}
}
```

In `internal/certstatus/crl_test.go`, beside the test at :665 that checks the `"broker:
certificate status: CRL issuing loaded (next update "` line, add a copy that builds the checker
with `Config{..., Component: "tls_listener"}` and expects `"tls_listener: certificate status: CRL
issuing loaded (next update "`. Copy that test's setup exactly; only the `Component` and the
expected prefix differ.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/config/ ./internal/certstatus/ -run 'TLS|Listen|Component|loaded' -v`
Expected: FAIL. `tls_listener` is an unknown field (`KnownFields`), `listen: none` is taken as an
address, and `certstatus.Config` has no `Component`.

- [ ] **Step 3: Implement certstatus's prefix**

In `internal/certstatus/certstatus.go`, add to `Config`:

```go
	// Component begins each line, "<component>: certificate status: ":
	// "broker" when empty, "tls_listener" for the RFC 9887 listener's
	// device checker (spec §13 decision 50 ruling 8).
	Component string
```

and after `New`:

```go
// prefix begins every line this checker says.
func (c *Checker) prefix() string {
	if c.cfg.Component == "" {
		return "broker: certificate status: "
	}
	return c.cfg.Component + ": certificate status: "
}
```

In `internal/certstatus/crl.go`, replace each of the four `"broker: certificate status: ` string
literal prefixes (:340, :417, :421, :484) with `c.prefix()+"`, so that `c.say(key, "broker:
certificate status: CRL %s ...", ...)` becomes `c.say(key, c.prefix()+"CRL %s ...", ...)`. Change
the `New` doc comment's "each begun \"broker: certificate status: \"" to "each begun with
Config.Component's prefix". Run `grep -rn '"broker: certificate status' internal/certstatus/ |
grep -v _test`; expect no output.

- [ ] **Step 4: Implement the config**

Create `internal/config/tlslistener.go`:

```go
package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ListenNone is listen's value that turns the RFC 8907 listener off (spec
// §13 decision 50 ruling 1; RFC 9887 §5.2).
const ListenNone = "none"

// TLSListenerConfig is tls_listener: (spec §13 decision 50): TACACS+ over
// TLS 1.3 with mutual certificates (RFC 9887), on a listener of its own.
type TLSListenerConfig struct {
	Listen string `yaml:"listen"` // default ":300"
	// CertFile is the server certificate chain, PEM, leaf first; KeyFile its
	// key. Both re-read every ReloadInterval and at SIGHUP (ruling 15).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ClientCAFile is the device CA certificates, PEM: the anchors a device
	// certificate must chain to. IntermediatesFile, optional, is issuing CAs
	// held here so a device that sends only its leaf verifies (RFC 9887
	// §3.4.1).
	ClientCAFile      string               `yaml:"client_ca_file"`
	IntermediatesFile string               `yaml:"intermediates_file"`
	DeviceIdentity    DeviceIdentityConfig `yaml:"device_identity"`
	// ServerNames, when set, are the SNI names a ClientHello may ask for
	// (ruling 10). Lower-cased at load.
	ServerNames           []string      `yaml:"server_names"`
	HandshakeTimeout      time.Duration `yaml:"handshake_timeout"`       // default 5s; 1s to 30s
	SessionTicketLifetime time.Duration `yaml:"session_ticket_lifetime"` // default 0s (off); up to 1h
	// ExpiryWarning is expiry_warning, read through tlsListenerYAML so an
	// absent key (336h) is told from 0s (off).
	ExpiryWarning  time.Duration `yaml:"-"`
	ReloadInterval time.Duration `yaml:"reload_interval"` // default 1m; 10s to 1h
	// StateDir keeps certificate_status's verified CRLs across a restart,
	// crl-<name>.der; required with crls.
	StateDir          string                   `yaml:"state_dir"`
	CertificateStatus *CertificateStatusConfig `yaml:"certificate_status"`
}

// DeviceIdentityConfig is tls_listener.device_identity (ruling 6).
type DeviceIdentityConfig struct {
	Match       []string `yaml:"match"`        // dns_name, ip_address; default both
	DNSSuffixes []string `yaml:"dns_suffixes"` // lower-cased, dots trimmed at load
}

// tlsListenerYAML tells an absent expiry_warning (the default) from an
// explicit 0s (off).
type tlsListenerYAML struct {
	TLSListenerConfig `yaml:",inline"`
	ExpiryWarningSet  *time.Duration `yaml:"expiry_warning"`
}

// namedPath is a config key and the file it names, for the kept-list
// collision check.
type namedPath struct{ key, path string }

// checkTLSListener checks tls_listener: and applies its defaults. listen is
// the resolved RFC 8907 listen ("" is none).
func checkTLSListener(y *tlsListenerYAML, listen string) (*TLSListenerConfig, error) {
	t := y.TLSListenerConfig
	const key = "tls_listener"
	t.Listen = or(t.Listen, ":300")
	if listen != "" && sameBind(listen, t.Listen) {
		return nil, fmt.Errorf("config: %s.listen %s is the same address as listen %s; RFC 9887 §3.1 requires its "+
			"own port", key, t.Listen, listen)
	}
	for _, f := range []struct{ name, path string }{{"cert_file", t.CertFile}, {"key_file", t.KeyFile},
		{"client_ca_file", t.ClientCAFile}} {
		if f.path == "" {
			return nil, fmt.Errorf("config: %s.%s is required", key, f.name)
		}
	}
	for _, f := range []struct{ name, path string }{{"cert_file", t.CertFile}, {"key_file", t.KeyFile},
		{"client_ca_file", t.ClientCAFile}, {"intermediates_file", t.IntermediatesFile}} {
		if f.path == "" {
			continue
		}
		if err := readableFile(key+"."+f.name, f.path); err != nil {
			return nil, err
		}
	}
	id := &t.DeviceIdentity
	if id.Match == nil {
		id.Match = []string{"dns_name", "ip_address"}
	}
	if len(id.Match) == 0 {
		return nil, fmt.Errorf("config: %s.device_identity.match must list dns_name or ip_address, or both", key)
	}
	for i, m := range id.Match {
		if (m != "dns_name" && m != "ip_address") || slices.Index(id.Match, m) != i {
			return nil, fmt.Errorf("config: %s.device_identity.match lists each of dns_name or ip_address at "+
				"most once; got %q", key, m)
		}
	}
	if len(id.DNSSuffixes) > 0 && !slices.Contains(id.Match, "dns_name") {
		return nil, fmt.Errorf("config: %s.device_identity.dns_suffixes needs dns_name in match", key)
	}
	for i, s := range id.DNSSuffixes {
		s = strings.ToLower(strings.Trim(s, "."))
		if !dnsShape(s) {
			return nil, fmt.Errorf("config: %s.device_identity.dns_suffixes[%d] is not a DNS suffix (letters, "+
				"digits, - and ., no wildcard)", key, i)
		}
		id.DNSSuffixes[i] = s
	}
	for i, n := range t.ServerNames {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !dnsShape(n) {
			return nil, fmt.Errorf("config: %s.server_names[%d] is not a server name (letters, digits, - and ., "+
				"no wildcard)", key, i)
		}
		t.ServerNames[i] = n
	}
	t.HandshakeTimeout = orD(t.HandshakeTimeout, 5*time.Second)
	if t.HandshakeTimeout < time.Second || t.HandshakeTimeout > 30*time.Second {
		return nil, fmt.Errorf("config: %s.handshake_timeout must be between 1s and 30s; got %s", key, t.HandshakeTimeout)
	}
	if t.SessionTicketLifetime < 0 || t.SessionTicketLifetime > time.Hour {
		return nil, fmt.Errorf("config: %s.session_ticket_lifetime must be between 0s and 1h; got %s", key,
			t.SessionTicketLifetime)
	}
	t.ExpiryWarning = 336 * time.Hour
	if y.ExpiryWarningSet != nil {
		t.ExpiryWarning = *y.ExpiryWarningSet
	}
	if t.ExpiryWarning < 0 || t.ExpiryWarning > 2160*time.Hour {
		return nil, fmt.Errorf("config: %s.expiry_warning must be between 0s (off) and 2160h; got %s", key, t.ExpiryWarning)
	}
	t.ReloadInterval = orD(t.ReloadInterval, time.Minute)
	if t.ReloadInterval < 10*time.Second || t.ReloadInterval > time.Hour {
		return nil, fmt.Errorf("config: %s.reload_interval must be between 10s and 1h; got %s", key, t.ReloadInterval)
	}
	if t.CertificateStatus == nil {
		return nil, fmt.Errorf("config: %s.certificate_status is required (RFC 9887 §3.4 requires revocation "+
			"checking): name crls or an ocsp block, or set disabled: true", key)
	}
	if len(t.CertificateStatus.CRLs) > 0 {
		if t.StateDir == "" || !filepath.IsAbs(t.StateDir) {
			return nil, fmt.Errorf("config: %s.state_dir is required with certificate_status.crls, an absolute "+
				"directory: each verified list is kept there across a restart", key)
		}
	}
	others := []namedPath{{key + ".cert_file", t.CertFile}, {key + ".key_file", t.KeyFile},
		{key + ".client_ca_file", t.ClientCAFile}, {key + ".intermediates_file", t.IntermediatesFile}}
	if err := checkStatusBlock(t.CertificateStatus, key+".certificate_status", t.StateDir, others); err != nil {
		return nil, err
	}
	return &t, nil
}

// sameBind reports whether two listen addresses would bind the same socket:
// one port, and one host or either a wildcard. Port 0 never conflicts.
func sameBind(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || ap != bp || ap == "0" {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ah == bh || wild(ah) || wild(bh)
}

// dnsShape is letters, digits, - and ., between 1 and 253 bytes, no empty
// label and no wildcard.
func dnsShape(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

var errNoListener = errors.New("config: port49d serves no TACACS+ listener: listen is none and there is no " +
	"tls_listener; set one or both")
```

In `internal/config/config.go`:

1. In `fileConfig`, after `Listen`, add `TLSListener *tlsListenerYAML `yaml:"tls_listener"``.
2. In `Config`, after `Listen`, add:

```go
	// TLSListener is tls_listener:, nil without it (spec §13 decision 50).
	// Listen is "" under listen: none.
	TLSListener *TLSListenerConfig
```

3. In `daemonDefaults`, replace `c.Listen = or(f.Listen, ":49")` with:

```go
	c.Listen = or(f.Listen, ":49")
	if f.Listen == ListenNone {
		c.Listen = ""
	}
	if f.TLSListener != nil {
		tl, err := checkTLSListener(f.TLSListener, c.Listen)
		if err != nil {
			return err
		}
		c.TLSListener = tl
	}
	if c.Listen == "" && c.TLSListener == nil {
		return errNoListener
	}
```

4. In `brokerRefusals`, beside the `{"listen", f.Listen != "", "port49-broker never speaks
   TACACS+; that is port49d's"}` entry, add `{"tls_listener", f.TLSListener != nil,
   "port49-broker never speaks TACACS+; that is port49d's"}`.

5. Split `checkCertificateStatus`. Rename its body to `checkStatusBlock(cs *CertificateStatusConfig,
   key, stateDir string, others []namedPath) error`. Every use of `key` stays, and the kept-list
   collision loop iterates `others` plus `{at + ".file", src.File}` and `{at + ".issuer_file",
   src.IssuerFile}`. Then `checkCertificateStatus(cs, b)` becomes:

```go
func checkCertificateStatus(cs *CertificateStatusConfig, b BrokerConfig) error {
	// The kept lists sit in broker.state_dir under the broker's role, and
	// beside broker.revocations_file under the daemon's (plan 7e, Ruling 12).
	stateDir := b.StateDir
	if stateDir == "" {
		revAbs, err := filepath.Abs(b.RevocationsFile)
		if err != nil {
			return fmt.Errorf("config: broker.revocations_file: %w", err)
		}
		stateDir = filepath.Dir(revAbs)
	}
	marker := ""
	if b.RevocationsFile != "" {
		marker = b.RevocationsFile + ".created"
	}
	others := []namedPath{
		{"broker.revocations_file", b.RevocationsFile}, {"broker.revocations_file's marker", marker},
		{"broker.policy_file", b.PolicyFile}, {"broker.tls_cert_file", b.TLSCertFile},
		{"broker.tls_key_file", b.TLSKeyFile}, {"broker.client_ca_file", b.ClientCAFile},
		{"broker.identity.machines[].trust_anchor_file", b.WorkloadCAFile},
	}
	for _, iss := range identityIssuers(&b) {
		others = append(others, namedPath{"broker.identity's kept keys for " + iss,
			filepath.Join(BrokerStateDir(&b), oidc.KeyFileName(iss))})
	}
	others = append(others, namedPath{"broker.directory.enrollment_store's file",
		filepath.Join(BrokerStateDir(&b), "enrollments.json")})
	return checkStatusBlock(cs, "broker.certificate_status", stateDir, others)
}
```

   with `checkStatusBlock` computing `kept := filepath.Join(stateDir, "crl-"+src.Name+".der")`
   as before, and skipping the collision loop when `stateDir == ""` (a TLS listener with only
   OCSP keeps no list). Every existing broker error text is unchanged, so the broker's tests
   pass untouched.

6. In `load`, before the strict decode's `fileConfig` use is finished, nothing else changes. The
   `tls_listener` block reaches `daemonDefaults` through `f`.

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./internal/config/ ./internal/certstatus/ ./internal/port49d/`
Expected: PASS: the new tests, every broker `certificate_status` test unchanged, and port49d's
tests (whose configs carry no `tls_listener`).

- [ ] **Step 6: Commit**

```bash
git add internal/config internal/certstatus
git commit -m "feat: tls_listener and listen: none in port49d.yaml

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 6: Records, diagnoses, metrics and the peer

**Files:**
- Modify: `internal/decision/log.go` (`Device` :216, `Unvalidated` :480)
- Modify: `internal/keyring/keyring.go` (the diagnoses :32–42)
- Modify: `internal/daemon/metrics/metrics.go`
- Modify: `internal/daemon/authen/authen.go` (`Peer` :30, `Device` :53)
- Test: `internal/decision/log_test.go`, `internal/daemon/metrics/metrics_test.go`,
  `internal/daemon/authen/authen_test.go`

**Interfaces:**
- Consumes: `devicecert.Outcomes` (Task 4).
- Produces:
  - `decision.Device.Transport`, `.CertSHA256`; `decision.Unvalidated.Transport`, `.TLSOutcome`,
    `.Detail`, `.CertSHA256`;
  - `keyring.DiagTransportMismatch`, `DiagTLSRefused`, `DiagObfuscatedOverTLS`;
  - `metrics.Metrics.TLSHandshakes *prometheus.CounterVec`;
  - `func (m *Metrics) WatchTLSExpiry(device func() (time.Duration, bool), server func() time.Duration)`;
  - `func (m *Metrics) CountDevicesByTransport(count func() map[string]int)`;
  - `authen.Peer.Transport`, `authen.Peer.CertSHA256`.

- [ ] **Step 1: Write the failing tests**

In `internal/decision/log_test.go`, add:

```go
func TestATCPRecordIsUnchangedAndATLSOneSaysSo(t *testing.T) {
	var b bytes.Buffer
	em := NewJSONLines(&b)
	em.Emit(Record{TS: time.Unix(0, 0).UTC(), Event: EventRedeem,
		Device: &Device{NAS: "10.0.0.1", Name: "leaf-01", Platform: "arista_eos", KeyRef: "k", KeyVersion: 1}})
	if strings.Contains(b.String(), "transport") || strings.Contains(b.String(), "cert_sha256") {
		t.Fatalf("a TCP record gained a field: %s", b.String())
	}
	b.Reset()
	em.Emit(Record{TS: time.Unix(0, 0).UTC(), Event: EventUnvalidated,
		Device: &Device{NAS: "10.0.0.9", Name: "tls-1", Platform: "arista_eos", Transport: "tls", CertSHA256: "ab"},
		Unvalidated: &Unvalidated{Source: "10.0.0.9", Diagnosis: "tls_refused", Transport: "tls",
			TLSOutcome: "certificate_expired", Detail: "x509: certificate has expired", CertSHA256: "ab"}})
	for _, want := range []string{`"transport":"tls"`, `"cert_sha256":"ab"`, `"tls_outcome":"certificate_expired"`,
		`"detail":"x509: certificate has expired"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s lacks %s", b.String(), want)
		}
	}
	if strings.Contains(b.String(), "key_ref") {
		t.Errorf("a TLS record named a key: %s", b.String())
	}
}
```

(Use the file's existing imports; add `bytes`, `strings` and `time` if absent. If
`NewJSONLines`'s output needs a flush, follow the file's other tests.)

In `internal/daemon/metrics/metrics_test.go`, add:

```go
func TestTLSMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	for _, o := range append([]devicecert.Outcome{devicecert.OK, devicecert.Resumed}, devicecert.Outcomes...) {
		m.TLSHandshakes.WithLabelValues(string(o)).Inc()
	}
	m.WatchTLSExpiry(func() (time.Duration, bool) { return 90 * time.Second, true }, func() time.Duration { return time.Hour })
	m.CountDevicesByTransport(func() map[string]int { return map[string]int{"tcp": 3, "tls": 2} })
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		for _, mm := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range mm.GetLabel() {
				key += "{" + l.GetName() + "=" + l.GetValue() + "}"
			}
			if g := mm.GetGauge(); g != nil {
				got[key] = g.GetValue()
			}
		}
	}
	if got["port49_tls_device_certificate_expiry_seconds"] != 90 || got["port49_tls_server_certificate_expiry_seconds"] != 3600 ||
		got["port49_devices_by_transport{transport=tcp}"] != 3 || got["port49_devices_by_transport{transport=tls}"] != 2 {
		t.Fatalf("gauges: %v", got)
	}
	if n := testutil.CollectAndCount(m.TLSHandshakes); n != 14 {
		t.Fatalf("%d outcome series, want 14", n)
	}
}

func TestTLSExpiryWithNoneSeenIsInfinite(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.WatchTLSExpiry(func() (time.Duration, bool) { return 0, false }, nil)
	if v := testutil.ToFloat64(m.TLSDeviceCertExpiry); !math.IsInf(v, 1) {
		t.Fatalf("none seen: %v, want +Inf so an expiry alarm never fires on nothing", v)
	}
}
```

(Imports: `math`, `time`, `prometheus`, `testutil`, and `devicecert`. `devicecert` imports
nothing from `metrics`, so there is no cycle.)

In `internal/daemon/authen/authen_test.go`, add:

```go
func TestATLSPeersDeviceBlock(t *testing.T) {
	d := Peer{NAS: "tls-1", NASAddr: "10.0.0.9", Platform: "arista_eos", Transport: "tls", CertSHA256: "ab"}.Device()
	if d.Transport != "tls" || d.CertSHA256 != "ab" || d.KeyRef != "" {
		t.Fatalf("%+v", d)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/decision/ ./internal/daemon/metrics/ ./internal/daemon/authen/ -run 'TLS' -v`
Expected: FAIL to build: unknown fields `Transport`, `CertSHA256`, `TLSOutcome`, `Detail`;
`m.TLSHandshakes`, `WatchTLSExpiry`, `CountDevicesByTransport` and `TLSDeviceCertExpiry`
undefined.

- [ ] **Step 3: Implement**

In `internal/decision/log.go`, add to `Device` after `KeyVersion`:

```go
	// Transport is "tls" on a record of an exchange on the RFC 9887
	// listener, absent on the RFC 8907 listener's; CertSHA256 is then the
	// device's verified leaf certificate (spec §5.7; §13 decision 50 ruling
	// 16). Such a record has no KeyRef.
	Transport  string `json:"transport,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
```

and to `Unvalidated` after `BodySHA256`:

```go
	// Transport is "tls" on a record from the RFC 9887 listener. TLSOutcome,
	// Detail and CertSHA256 are a tls_refused record's (spec §10): Detail is
	// bounded and printable, never a body.
	Transport  string `json:"transport,omitempty"`
	TLSOutcome string `json:"tls_outcome,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
```

In `internal/keyring/keyring.go`, after `DiagAdmissionWithdrawn`, add:

```go
	DiagTransportMismatch Diagnosis = "transport_mismatch"  // an admitted device on the listener it does not speak (spec §10)
	DiagTLSRefused        Diagnosis = "tls_refused"         // the RFC 9887 listener refused or ended it; tls_outcome says why
	DiagObfuscatedOverTLS Diagnosis = "obfuscated_over_tls" // a packet over TLS with the unencrypted flag clear (RFC 9887 §4)
```

In `internal/daemon/metrics/metrics.go`:

1. Add the fields to `Metrics`, after `ConnectionEvents`:

```go
	// port49_tls_handshakes_total{outcome}: the RFC 9887 listener's
	// handshakes by devicecert.Outcome, ok and resumed included (spec §13
	// decision 50 ruling 16). No device label.
	TLSHandshakes *prometheus.CounterVec
	// port49_tls_device_certificate_expiry_seconds: the least time to
	// expiry among device certificates verified in the last 24h, +Inf with
	// none; port49_tls_server_certificate_expiry_seconds: the listener's own.
	TLSDeviceCertExpiry prometheus.GaugeFunc
	TLSServerCertExpiry prometheus.GaugeFunc
	// port49_devices_by_transport{transport}: admitted devices, one gauge
	// each for tcp and tls.
	DevicesByTransport []prometheus.GaugeFunc
```

   and the unexported holders beside `admissionRefused`:

```go
	tlsDeviceExpiry  atomic.Pointer[func() (time.Duration, bool)]
	tlsServerExpiry  atomic.Pointer[func() time.Duration]
	devicesTransport atomic.Pointer[func() map[string]int]
```

2. Extend the `ConnectionEvents` comment's list with: `"tls_refused" (the RFC 9887 listener
   refused a handshake and struck the source), "transport_mismatch" (an admitted device on the
   listener it does not speak: declined, no strike), and "obfuscated_over_tls" (a packet over
   TLS with the unencrypted flag clear: an ERROR, then closed)`.

3. In `New`, construct them:

```go
	m.TLSHandshakes = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_tls_handshakes_total",
		Help: "RFC 9887 listener handshakes by outcome."}, []string{"outcome"})
	m.TLSDeviceCertExpiry = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_tls_device_certificate_expiry_seconds",
		Help: "Seconds until the soonest-expiring device certificate verified in the last 24h; +Inf with none."},
		func() float64 {
			if f := m.tlsDeviceExpiry.Load(); f != nil {
				if d, ok := (*f)(); ok {
					return d.Seconds()
				}
			}
			return math.Inf(1)
		})
	m.TLSServerCertExpiry = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_tls_server_certificate_expiry_seconds",
		Help: "Seconds until the RFC 9887 listener's own certificate expires; +Inf with no listener."},
		func() float64 {
			if f := m.tlsServerExpiry.Load(); f != nil && *f != nil {
				return (*f)().Seconds()
			}
			return math.Inf(1)
		})
	for _, tr := range []string{"tcp", "tls"} {
		m.DevicesByTransport = append(m.DevicesByTransport, prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "port49_devices_by_transport", Help: "Admitted devices by transport.",
			ConstLabels: prometheus.Labels{"transport": tr}}, func() float64 {
			if f := m.devicesTransport.Load(); f != nil {
				return float64((*f)()[tr])
			}
			return 0
		}))
	}
```

   and add `m.TLSHandshakes, m.TLSDeviceCertExpiry, m.TLSServerCertExpiry` and
   `m.DevicesByTransport...` to the `reg.MustRegister` calls (the last as its own
   `for _, g := range m.DevicesByTransport { reg.MustRegister(g) }`).

4. Add the setters:

```go
// WatchTLSExpiry sets what the two certificate expiry gauges report.
func (m *Metrics) WatchTLSExpiry(device func() (time.Duration, bool), server func() time.Duration) {
	m.tlsDeviceExpiry.Store(&device)
	m.tlsServerExpiry.Store(&server)
}

// CountDevicesByTransport sets what port49_devices_by_transport reports.
func (m *Metrics) CountDevicesByTransport(count func() map[string]int) { m.devicesTransport.Store(&count) }
```

5. At the end of `New`, pre-create every outcome series so a rate alarm has a zero to start
   from: `for _, o := range append([]devicecert.Outcome{devicecert.OK, devicecert.Resumed},
   devicecert.Outcomes...) { m.TLSHandshakes.WithLabelValues(string(o)) }`. Import
   `internal/devicecert` and `math`.

In `internal/daemon/authen/authen.go`, add to `Peer` after `KeyVersion`:

```go
	// Transport and CertSHA256 are "tls" and the device's verified leaf on
	// the RFC 9887 listener, which every record of the connection names
	// (spec §5.7; decision 50 ruling 16); empty on the RFC 8907 listener.
	Transport  string
	CertSHA256 string
```

and make `Device()` return `&decision.Device{NAS: p.NASAddr, Name: p.NAS, Platform: p.Platform,
KeyRef: p.KeyRef, KeyVersion: p.KeyVersion, Transport: p.Transport, CertSHA256: p.CertSHA256}`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/decision/ ./internal/keyring/ ./internal/daemon/... ./internal/replay/`
Expected: PASS (the replay package reads records; omitempty fields change none it reads).

- [ ] **Step 5: Commit**

```bash
git add internal/decision internal/keyring internal/daemon/metrics internal/daemon/authen
git commit -m "feat: TLS record fields, diagnoses and metrics

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 7: The RFC 9887 listener: Accept, handshake and packets

**Files:**
- Create: `internal/daemon/server/tls.go`
- Modify: `internal/daemon/server/server.go` (`Deps` :40, the Accept loop :117–175, `declining`
  :218)
- Modify: `internal/daemon/server/conn.go` (`conn` :41, `unvalidated` :61, `quarantine` :76,
  `refusedAdmission` :90, `admissionWithdrawn` :129, every `reset(s.c)`, `serve` :237, `write`
  :412, `dispatch` :441)
- Test: `internal/daemon/server/tls_test.go`

**Interfaces:**
- Consumes:
  - `wire.Header.ValidateTLS`, `wire.ErrObfuscatedOverTLS`, `wire.ErrorReply` (Task 2);
  - `admission.Device.EffectiveTransport`, `admission.TransportTLS` (Task 3);
  - `devicecert.*` (Task 4);
  - the record fields, `keyring.DiagTLSRefused`, `DiagTransportMismatch`,
    `DiagObfuscatedOverTLS`, `metrics.TLSHandshakes`, `authen.Peer.Transport` and `.CertSHA256`
    (Task 6).
- Produces:
  - `server.Deps.TLS *server.TLS`;
  - `type TLS struct{ Material func() *Material; ServerNames []string; HandshakeTimeout
    time.Duration; Seen func(device string, leaf *x509.Certificate, now time.Time); Said
    func(device, source string, v devicecert.Verdict) }`;
  - `type Material struct{ Config *tls.Config; Verifier *devicecert.Verifier }`;
  - `Serve` serving RFC 9887 when `Deps.TLS != nil`;
  - the test fixture `newTLSFixture` (in `tls_test.go`), which Tasks 8 and 9 use.

- [ ] **Step 1: Write the failing tests**

Create `internal/daemon/server/tls_test.go`:

```go
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// tlsFixture is a server on the RFC 9887 listener: leaf-01 at 127.0.0.1
// with transport tls, a device CA, a server certificate for
// tacacs.example.net, and a status the test sets.
type tlsFixture struct {
	ts     *testServer
	ca     *testpki.CA
	server tls.Certificate
	status atomic.Int32 // a devicecert.Status
	allow  bool
	mat    atomic.Pointer[Material]
	admit  *swapAdmitter
}

// swapAdmitter is an Admitter a test can change under a running server, as
// a reload does.
type swapAdmitter struct{ cur atomic.Pointer[admission.Trie] }

func (a *swapAdmitter) Lookup(addr netip.Addr) (admission.Resolved, bool) { return a.cur.Load().Lookup(addr) }

func (a *swapAdmitter) set(t *testing.T, rs ...admission.Resolved) {
	t.Helper()
	tr, err := admission.NewTrie(rs)
	if err != nil {
		t.Fatal(err)
	}
	a.cur.Store(tr)
}

var leaf01TLS = admission.Device{Name: "leaf-01", Platform: "arista_eos", Transport: admission.TransportTLS,
	Addresses: []netip.Addr{loopback}}

func seededStore(t *testing.T) store.Store {
	t.Helper()
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return st
}

func newTLSFixture(t *testing.T, log *syncBuffer, adjust func(*Deps, *tlsFixture)) *tlsFixture {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Issue(testpki.Leaf{CommonName: "port49", DNSNames: []string{"tacacs.example.net"},
		IPs: testpki.Loopback(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	f := &tlsFixture{ca: ca, server: srv, admit: &swapAdmitter{}}
	f.admit.set(t, admission.Resolved{Device: leaf01TLS})
	f.mat.Store(f.material(ca, true))
	f.ts = newTestServerWith(t, log, seededStore(t), nil, func(d *Deps) {
		d.Admission = f.admit
		d.TLS = &TLS{Material: f.mat.Load, ServerNames: []string{"tacacs.example.net"}, HandshakeTimeout: 2 * time.Second}
		if adjust != nil {
			adjust(d, f)
		}
	})
	return f
}

// material is a load of the listener's files with anchor as the device CA;
// ticketsOff is session_ticket_lifetime: 0s.
func (f *tlsFixture) material(anchor *testpki.CA, ticketsOff bool) *Material {
	return &Material{
		Config: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.server},
			ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: ticketsOff},
		Verifier: &devicecert.Verifier{Anchors: anchor.Pool(), Rule: devicecert.Rule{DNSName: true, IPAddress: true},
			AllowUnknown: f.allow, Now: time.Now,
			Status: func(context.Context, []*x509.Certificate) (devicecert.Status, string) {
				return devicecert.Status(f.status.Load()), "test status source"
			}}}
}

// deviceCert is a client certificate from ca: by default leaf-01's, valid
// for an hour.
func (f *tlsFixture) deviceCert(t *testing.T, ca *testpki.CA, l testpki.Leaf) tls.Certificate {
	t.Helper()
	if ca == nil {
		ca = f.ca
	}
	if l.DNSNames == nil && l.IPs == nil {
		l.DNSNames = []string{"leaf-01"}
	}
	if l.NotAfter.IsZero() {
		l.NotBefore, l.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	}
	if !l.NoExtKeyUsage {
		l.Client = true
	}
	c, err := ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tlsClient is a device on the RFC 9887 listener: no obfuscation, and the
// flags each send names.
type tlsClient struct {
	conn *tls.Conn
	sid  uint32
	seq  uint8
}

// dialTLS opens a TLS connection as a device presenting cert (nil: none).
// In TLS 1.3 the server's verdict on the client certificate arrives after
// the client's Finished, so a refusal shows at the first read.
func (f *tlsFixture) dialTLS(t *testing.T, cert *tls.Certificate, adjust func(*tls.Config)) (*tlsClient, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: f.ca.Pool(), ServerName: "tacacs.example.net", MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if adjust != nil {
		adjust(cfg)
	}
	raw, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	tc := tls.Client(raw, cfg)
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return &tlsClient{conn: tc, sid: 0xabcd1234, seq: 1}, nil
}

func (c *tlsClient) send(typ wire.Type, body []byte, flags uint8) error {
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: c.seq, Flags: flags, SessionID: c.sid, Length: uint32(len(body))}
	c.seq += 2
	_, err := c.conn.Write(append(h.Encode(), body...))
	return err
}

func (c *tlsClient) recv() (wire.Header, []byte, error) {
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c.conn, hb); err != nil {
		return wire.Header{}, nil, err
	}
	h, _ := wire.DecodeHeader(hb)
	body := make([]byte, h.Length)
	_, err := io.ReadFull(c.conn, body)
	return h, body, err
}

var aliceLogin = wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
	Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()

// login dials as cert and logs alice in; any refusal is the error.
func (f *tlsFixture) login(t *testing.T, cert *tls.Certificate, adjust func(*tls.Config)) (wire.Header, wire.AuthenReply, error) {
	t.Helper()
	c, err := f.dialTLS(t, cert, adjust)
	if err != nil {
		return wire.Header{}, wire.AuthenReply{}, err
	}
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		return wire.Header{}, wire.AuthenReply{}, err
	}
	h, body, err := c.recv()
	if err != nil {
		return h, wire.AuthenReply{}, err
	}
	r, err := wire.DecodeAuthenReply(body)
	return h, r, err
}

func TestTLSLoginPassesAndRecordsTheCertificate(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	h, r, err := f.login(t, &cert, nil)
	if err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("login: %v status %d; log %s", err, r.Status, log.String())
	}
	if h.Flags&wire.FlagUnencrypted == 0 {
		t.Fatalf("a reply over TLS without the unencrypted flag (RFC 9887 §4): %#x", h.Flags)
	}
	if !waitFor(t, func() bool { return log.contains(`"event":"redeem"`) }) {
		t.Fatalf("no redeem: %s", log.String())
	}
	for _, rec := range log.records(t) {
		if rec["event"] != "redeem" {
			continue
		}
		dev, _ := rec["device"].(map[string]any)
		if dev["transport"] != "tls" || dev["cert_sha256"] != devicecert.Fingerprint(cert.Leaf) || dev["key_ref"] != nil {
			t.Fatalf("redeem device block: %v", dev)
		}
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues("ok")); n != 1 {
		t.Fatalf("handshakes{ok} = %v", n)
	}
}

func TestTLSSingleConnectCarriesTwoExchanges(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.seq, c.sid = 1, uint32(0x100+i)
		if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted|wire.FlagSingleConnect); err != nil {
			t.Fatal(err)
		}
		h, _, err := c.recv()
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if h.Flags != wire.FlagUnencrypted|wire.FlagSingleConnect {
			t.Fatalf("exchange %d: reply flags %#x", i, h.Flags)
		}
	}
}

// refusedAtHandshake dials and logs in; it wants the attempt to fail, the
// record to say outcome, and the source struck or declined as struck says.
func refusedAtHandshake(t *testing.T, f *tlsFixture, log *syncBuffer, cert *tls.Certificate, adjust func(*tls.Config),
	outcome devicecert.Outcome, struck bool) {
	t.Helper()
	if _, _, err := f.login(t, cert, adjust); err == nil {
		t.Fatalf("%s: the login was answered", outcome)
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"` + string(outcome) + `"`) }) {
		t.Fatalf("%s: no record: %s", outcome, log.String())
	}
	if !log.contains(`"diagnosis":"tls_refused"`) || !log.contains(`"transport":"tls"`) {
		t.Fatalf("%s: record: %s", outcome, log.String())
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(outcome))); n != 1 {
		t.Fatalf("%s: handshakes = %v", outcome, n)
	}
	if got := f.ts.limits.Holding(loopback); got != struck {
		t.Fatalf("%s: struck %v, want %v", outcome, got, struck)
	}
	if !struck && !f.ts.limits.Declined(loopback) {
		t.Fatalf("%s: not struck, so declined", outcome)
	}
}

func TestTLSRefusesAtTheHandshake(t *testing.T) {
	otherCA, err := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		cert    func(*tlsFixture) *tls.Certificate
		adjust  func(*tls.Config)
		outcome devicecert.Outcome
	}{
		"TLS 1.2 only": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, nil, testpki.Leaf{}); return &c },
			func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, devicecert.VersionRefused},
		"no certificate": {func(*tlsFixture) *tls.Certificate { return nil }, nil, devicecert.NoClientCertificate},
		"another CA": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, otherCA, testpki.Leaf{}); return &c },
			nil, devicecert.UnknownCA},
		"expired": {func(f *tlsFixture) *tls.Certificate {
			c := f.deviceCert(t, nil, testpki.Leaf{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
			return &c
		}, nil, devicecert.CertificateExpired},
		"another device": {func(f *tlsFixture) *tls.Certificate {
			c := f.deviceCert(t, nil, testpki.Leaf{DNSNames: []string{"leaf-02"}})
			return &c
		}, nil, devicecert.IdentityMismatch},
		"a server name not configured": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, nil, testpki.Leaf{}); return &c },
			func(c *tls.Config) { c.ServerName = "other.example.net"; c.InsecureSkipVerify = true }, devicecert.SNIMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
			refusedAtHandshake(t, f, log, c.cert(f), c.adjust, c.outcome, true)
		})
	}
}

func TestTLSRevokedIsStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	f.status.Store(int32(devicecert.StatusRevoked))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	refusedAtHandshake(t, f, log, &cert, nil, devicecert.CertificateRevoked, true)
}

func TestTLSStatusUnavailableIsDeclinedNotStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	f.status.Store(int32(devicecert.StatusUnknown))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	refusedAtHandshake(t, f, log, &cert, nil, devicecert.StatusUnavailable, false)
}

func TestTLSAllowUnknownAdmits(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(_ *Deps, f *tlsFixture) { f.allow = true; f.mat.Store(f.material(f.ca, true)) })
	f.status.Store(int32(devicecert.StatusUnknown))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	if _, r, err := f.login(t, &cert, nil); err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("on_unavailable: allow: %v %d", err, r.Status)
	}
}

// acceptRefused dials raw TCP and wants the connection ended with no byte
// from the server: nothing TLS was exchanged.
func acceptRefused(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("read %d bytes, %v: want the connection ended with nothing sent", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the server held the connection instead of ending it at Accept")
	}
}

func TestTLSDecidesAtAcceptBeforeAnyTLSByte(t *testing.T) {
	tcpDev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Transport: admission.TransportTCP,
		Addresses: []netip.Addr{loopback}}
	for name, c := range map[string]struct {
		set    func(*testing.T, *tlsFixture)
		quar   bool
		diag   string
		struck bool
	}{
		"not in the inventory": {func(t *testing.T, f *tlsFixture) { f.admit.set(t) }, false, "unadmitted_source", true},
		"refused admission": {func(t *testing.T, f *tlsFixture) {
			f.admit.set(t, admission.Resolved{Device: admission.Device{Name: "leaf-01", Transport: "udp",
				Addresses: []netip.Addr{loopback}}, Refused: `has transport "udp"`, Refusal: admission.RefusedTransport})
		}, false, "admission_refused", false},
		"a tcp device": {func(t *testing.T, f *tlsFixture) { f.admit.set(t, admission.Resolved{Device: tcpDev, KeyRef: "prod_key"}) },
			false, "transport_mismatch", false},
		"quarantined": {func(*testing.T, *tlsFixture) {}, true, "device_quarantined", false},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) {
				d.Limits = slowBackoff()
				if c.quar {
					d.Quarantined = func(string, time.Time) (string, bool) { return "a grant expired", true }
				}
			})
			c.set(t, f)
			acceptRefused(t, f.ts.addr)
			if !waitFor(t, func() bool { return log.contains(`"diagnosis":"` + c.diag + `"`) }) {
				t.Fatalf("no %s record: %s", c.diag, log.String())
			}
			if !log.contains(`"transport":"tls"`) || log.contains(`"seq_no":1`) {
				t.Fatalf("an Accept record has transport tls and no header: %s", log.String())
			}
			var total float64
			for _, o := range append([]devicecert.Outcome{devicecert.OK}, devicecert.Outcomes...) {
				total += testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(o)))
			}
			if total != 0 {
				t.Fatalf("%v handshakes counted: a refusal at Accept runs none", total)
			}
			if got := f.ts.limits.Holding(loopback); got != c.struck {
				t.Fatalf("struck %v, want %v", got, c.struck)
			}
		})
	}
}

func TestTLSObfuscatedPacketGetsAnErrorAndAClose(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.send(wire.TypeAuthor, []byte("anything at all"), 0); err != nil {
		t.Fatal(err)
	}
	h, body, err := c.recv()
	if err != nil {
		t.Fatalf("no ERROR reply: %v", err)
	}
	r, err := wire.DecodeAuthorResponse(body)
	if err != nil || r.Status != wire.AuthorStatusError || h.Flags != wire.FlagUnencrypted || h.SeqNo != 2 {
		t.Fatalf("reply %+v %+v %v", h, r, err)
	}
	if _, _, err := c.recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the ERROR the connection closes: %v", err)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"obfuscated_over_tls"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if log.contains("body_sha256") || f.ts.limits.Holding(loopback) {
		t.Fatalf("a body hash, or a strike: %s", log.String())
	}
}

func TestTLSHandshakeTimeoutIsStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) {
		d.Limits = slowBackoff()
		d.TLS.HandshakeTimeout = time.Second
	})
	conn, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server sent something to a silent peer")
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("closed after %v, want about handshake_timeout (1s)", d)
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"handshake_timeout"`) }) || !f.ts.limits.Holding(loopback) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestTLSRecordsNeverHoldABody(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	// seq_no 255 is a protocol error after the header passed.
	c.seq = 255
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	c.recv()
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"malformed_after_validation"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if log.contains("body_sha256") || strings.Contains(log.String(), "p49_e2e") {
		t.Fatalf("a TLS record held a body or a credential: %s", log.String())
	}
}
```

`slowBackoff()` is `server_test.go`'s existing helper, a limiter whose strike backoff lasts long
enough for `Holding` to read true. Check it with `grep -n "func slowBackoff" -A 8
internal/daemon/server/server_test.go`. If its decline window is too short for `Declined` to
read true at once, give the TLS tests their own helper with a minute's decline window, built
the same way.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/server/ -run TestTLS -v`
Expected: FAIL to build: `d.TLS undefined`, `undefined: TLS`, `undefined: Material`.

- [ ] **Step 3: Write `tls.go`**

Create `internal/daemon/server/tls.go`:

```go
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/printsafe"
)

// TLS is the RFC 9887 listener's part of Deps (spec §13 decision 50). Serve
// runs the RFC 8907 listener when Deps.TLS is nil and the RFC 9887 one when
// it is set: one accept loop, one per-source limiter for both (ruling 17).
type TLS struct {
	// Material is the listener's files as loaded now, read at each Accept and
	// at each packet: a reload reaches the next handshake, and ends an open
	// connection whose chain no longer verifies (rulings 9, 15).
	Material func() *Material
	// ServerNames, when not empty, are the SNI names a ClientHello may ask
	// for, lower case; an absent SNI is accepted (ruling 10).
	ServerNames      []string
	HandshakeTimeout time.Duration
	// Seen notes a device certificate that verified (devicecert.Expiry.Seen);
	// Said is told each refusal, for port49d's throttled line. Nil is
	// nothing.
	Seen func(device string, leaf *x509.Certificate, now time.Time)
	Said func(device, source string, v devicecert.Verdict)
}

// Material is one load of the listener's files (ruling 15). Config is the
// base each connection's is cloned from: TLS 1.3 only, the server
// certificate, RequireAnyClientCert (port49 verifies the chain itself, at a
// full handshake and a resumption alike), and the ticket settings.
type Material struct {
	Config   *tls.Config
	Verifier *devicecert.Verifier
}

// tlsSession is what a connection on the RFC 9887 listener holds once its
// handshake ends.
type tlsSession struct {
	mat     *Material
	verdict devicecert.Verdict
	peer    []*x509.Certificate // as the device sent them, for a full re-verify
	certSHA string
	started bool // the first packet was read; its single-connect flag decides
}

// startTLS decides a connection on the RFC 9887 listener before any TLS
// byte is read (ruling 5): nothing it refuses here costs a key exchange.
// Then it runs the handshake. It reports whether the connection goes on to
// its packets.
func (s *conn) startTLS(ctx context.Context) bool {
	switch {
	case s.refused:
		s.acceptRecord(keyring.DiagAdmissionRefused, "", "")
		s.decline()
	case !s.admitted:
		s.acceptRecord(keyring.DiagUnadmittedSource, "", "")
		s.d.Limits.Malformed(s.src)
		reset(s.raw)
		s.d.Metrics.ConnectionEvents.WithLabelValues("unadmitted_source").Inc()
	case s.mismatch:
		s.acceptRecord(keyring.DiagTransportMismatch, "", "the device record says transport "+
			s.dev.Device.EffectiveTransport()+"; this is the RFC 9887 listener")
		s.d.Metrics.ConnectionEvents.WithLabelValues("transport_mismatch").Inc()
		s.decline()
	case s.quarantined():
		s.acceptRecord(keyring.DiagDeviceQuarantined, decision.DeviceQuarantined, "")
		s.decline()
	default:
		return s.handshake(ctx)
	}
	return false
}

// acceptRecord records a connection the RFC 9887 listener ended at Accept.
// No header was read, so the record carries none.
func (s *conn) acceptRecord(diag keyring.Diagnosis, reason decision.Reason, detail string) {
	rec := decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Reason: reason,
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(diag), Transport: admission.TransportTLS,
			Detail: detail}}
	if s.admitted || s.refused {
		rec.Device = s.deviceBlock()
	}
	s.d.Log.Emit(rec)
	s.d.Metrics.Unvalidated.WithLabelValues(string(diag)).Inc()
}

// handshake runs TLS 1.3 with the material in force. The ClientHello is
// read first for its versions and its SNI; the device's chain is judged in
// VerifyConnection, which crypto/tls runs on a full handshake and a
// resumption alike, with its status checked inside the handshake's
// deadline.
func (s *conn) handshake(ctx context.Context) bool {
	mat := s.d.TLS.Material()
	hctx, cancel := context.WithTimeout(ctx, s.d.TLS.HandshakeTimeout)
	defer cancel()
	var v devicecert.Verdict
	cfg := mat.Config.Clone()
	cfg.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(hi.SupportedVersions, tls.VersionTLS13) {
			// crypto/tls refuses it next with protocol_version; this only
			// names why.
			v = devicecert.Verdict{Outcome: devicecert.VersionRefused,
				Detail: fmt.Sprintf("offered TLS versions %x; RFC 9887 requires TLS 1.3", hi.SupportedVersions)}
			return nil, nil
		}
		if name := hi.ServerName; name != "" && len(s.d.TLS.ServerNames) > 0 &&
			!slices.Contains(s.d.TLS.ServerNames, strings.ToLower(name)) {
			v = devicecert.Verdict{Outcome: devicecert.SNIMismatch,
				Detail: "asked for server name " + printsafe.Line(name, 253)}
			return nil, &devicecert.Refusal{Verdict: v}
		}
		return nil, nil
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		v = mat.Verifier.Verify(hctx, cs.PeerCertificates, s.dev.Device)
		if v.Outcome != devicecert.OK {
			return &devicecert.Refusal{Verdict: v}
		}
		return nil
	}
	tc := tls.Server(s.raw, cfg)
	err := tc.HandshakeContext(hctx)
	if err == nil && (v.Outcome != devicecert.OK || v.Leaf == nil) {
		err = fmt.Errorf("the handshake ended with no verdict on the device's certificate")
		v = devicecert.Verdict{}
	}
	if err != nil {
		if ctx.Err() != nil {
			return false // shutdown, not the device
		}
		if v.Outcome == "" || v.Outcome == devicecert.OK {
			v = devicecert.Verdict{Outcome: devicecert.Classify(err, hctx.Err() != nil),
				Detail: printsafe.Line(err.Error(), 300), Leaf: v.Leaf}
		}
		s.tlsRefused(v)
		return false
	}
	cs := tc.ConnectionState()
	outcome := devicecert.OK
	if cs.DidResume {
		outcome = devicecert.Resumed
	}
	s.d.Metrics.TLSHandshakes.WithLabelValues(string(outcome)).Inc()
	s.c = tc
	s.tls = &tlsSession{mat: mat, verdict: v, peer: cs.PeerCertificates, certSHA: devicecert.Fingerprint(v.Leaf)}
	if s.d.TLS.Seen != nil {
		s.d.TLS.Seen(s.dev.Device.Name, v.Leaf, s.d.Now())
	}
	return true
}

// tlsRefused records a refused handshake and ends the connection: struck
// and reset, as a key miss is, or for status_unavailable, which is port49's
// fault, declined (ruling 8).
func (s *conn) tlsRefused(v devicecert.Verdict) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
			Transport: admission.TransportTLS, TLSOutcome: string(v.Outcome), Detail: v.Detail,
			CertSHA256: devicecert.Fingerprint(v.Leaf)}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
	s.d.Metrics.TLSHandshakes.WithLabelValues(string(v.Outcome)).Inc()
	if s.d.TLS.Said != nil {
		s.d.TLS.Said(s.dev.Device.Name, s.src.String(), v)
	}
	if !v.Outcome.Struck() {
		s.decline()
		return
	}
	s.d.Limits.Malformed(s.src)
	reset(s.raw)
	s.d.Metrics.ConnectionEvents.WithLabelValues("tls_refused").Inc()
}

// obfuscatedOverTLS answers a packet whose unencrypted flag is clear on the
// RFC 9887 listener as RFC 9887 §4 requires: its type's ERROR with the flag
// set, then the connection closes (serve's deferred Close sends
// close_notify). The body is never read. The peer's certificate verified,
// so it is no strike (ruling 13).
func (s *conn) obfuscatedOverTLS(h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagObfuscatedOverTLS, 0)
	rh, body := wire.ErrorReply(h)
	if err := s.c.SetWriteDeadline(time.Now().Add(s.d.IdleTimeout)); err == nil {
		_, _ = s.c.Write(append(rh.Encode(), body...))
	}
	s.d.Metrics.ConnectionEvents.WithLabelValues("obfuscated_over_tls").Inc()
}

// deviceBlock names the device this connection's source is; on the RFC
// 9887 listener it says so.
func (s *conn) deviceBlock() *decision.Device {
	d := &decision.Device{NAS: s.src.String(), Name: s.dev.Device.Name, Platform: s.dev.Device.Platform}
	if s.d.TLS != nil {
		d.Transport = admission.TransportTLS
	}
	return d
}

// transportName is "tls" on the RFC 9887 listener and "" on the RFC 8907
// one, whose records are unchanged.
func (s *conn) transportName() string {
	if s.d.TLS != nil {
		return admission.TransportTLS
	}
	return ""
}
```

Add `"github.com/rhwendt/port49/internal/tacacs/wire"` to its imports.

- [ ] **Step 4: Wire it into `server.go` and `conn.go`**

In `server.go`, add to `Deps` after `Abort`:

```go
	// TLS, when set, makes this the RFC 9887 listener (spec §13 decision 50);
	// nil is the RFC 8907 listener.
	TLS *TLS
```

In the Accept loop, after `admitted := found && dev.Refused == ""`, add:

```go
		listener := admission.TransportTCP
		if d.TLS != nil {
			listener = admission.TransportTLS
		}
		// A device speaks one transport, and the other listener declines it
		// (spec §13 decision 50 ruling 4).
		mismatch := admitted && dev.Device.EffectiveTransport() != listener
```

change `if declining(d, dev, admitted) {` to `if declining(d, dev, admitted, listener) {`, and
change the `conn` construction and key choice to:

```go
		cc := &conn{d: d, c: c, raw: c, src: src, dev: dev, admitted: admitted, mismatch: mismatch,
			refused: found && dev.Refused != "", sessions: map[uint32]*authen.Session{}}
		if cc.admitted && !mismatch && d.TLS == nil {
			cc.keys = d.Keys[dev.KeyRef]
		}
```

Replace `declining` with:

```go
// declining reports whether port49d would decline a connection from dev on
// this listener as admission and the policy stand now: a source the
// inventory does not name, a device admission refuses, one of the other
// transport, or a quarantined one. It is asked only at an Accept inside a
// decline window.
func declining(d Deps, dev admission.Resolved, admitted bool, listener string) bool {
	if !admitted || dev.Device.EffectiveTransport() != listener {
		return true
	}
	if d.Quarantined == nil {
		return false
	}
	_, q := d.Quarantined(dev.Device.Name, d.Now())
	return q
}
```

Update the package comment's first line to "Package server owns the TACACS+ listeners, RFC 8907
and RFC 9887, and the per-connection loop: ...".

In `conn.go`:

1. Add to `conn` after `c net.Conn`:

```go
	// raw is the TCP connection: c itself on the RFC 8907 listener, and
	// beneath the TLS connection on the RFC 9887 one. A reset is made on it.
	raw      net.Conn
	mismatch bool        // admitted, on the listener its transport is not (spec §10)
	tls      *tlsSession // set once a TLS handshake ends
```

2. Replace every `reset(s.c)` in `conn.go` with `reset(s.raw)` (`admissionWithdrawn`, `keyMiss`,
   `unadmitted`, `decline`; `grep -n "reset(s.c)" internal/daemon/server/conn.go` should then print
   nothing).

3. In `unvalidated`, `quarantine`, `refusedAdmission` and `admissionWithdrawn`, add `Transport:
   s.transportName()` to the `decision.Unvalidated` literal. In the three that build a
   `&decision.Device{NAS: ..., Name: ..., Platform: ...}`, use `s.deviceBlock()` instead.

4. Replace `serve`'s opening and its header-to-body section. The full new function, with the
   parts after `body` unchanged, is:

```go
func (s *conn) serve(ctx context.Context) {
	// s.c becomes the TLS connection after a handshake: Close it as it is
	// then, so a TLS peer gets close_notify.
	defer func() { s.c.Close() }()
	if s.d.TLS != nil && !s.startTLS(ctx) {
		return
	}
	for {
		// The deadline is wall-clock I/O, so it uses the real clock even when a
		// test injects Deps.Now for record timestamps.
		deadline := s.d.IdleTimeout
		if !s.admitted && deadline > unadmittedHeaderDeadline {
			deadline = unadmittedHeaderDeadline
		}
		if err := s.c.SetReadDeadline(time.Now().Add(deadline)); err != nil {
			return
		}
		hb := make([]byte, wire.HeaderLen)
		if _, err := io.ReadFull(s.c, hb); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.d.Metrics.ConnectionEvents.WithLabelValues("idle_closed").Inc()
			}
			return
		}
		h, err := wire.DecodeHeader(hb)
		if err != nil {
			return // unreachable: ReadFull delivered exactly HeaderLen bytes
		}

		// (the unadmitted block, unchanged; on the RFC 9887 listener startTLS
		// has already ended such a connection)
		if !s.admitted {
			if s.refused {
				s.refusedAdmission(h)
				s.decline()
				return
			}
			s.unadmitted(h)
			return
		}

		if diag := s.readmitted(); diag != "" {
			s.admissionWithdrawn(h, diag)
			return
		}

		// (the quarantine block and its comment, unchanged)
		if s.quarantined() {
			s.quarantine(h)
			s.decline()
			return
		}

		// Header checks come before anything that would touch the body. On
		// the RFC 8907 listener an unencrypted packet is refused without its
		// cleartext ever being read; on the RFC 9887 listener the flag is
		// required, and one without it is answered ERROR (RFC 9887 §4).
		if s.tls != nil {
			if err := h.ValidateTLS(); err != nil {
				if errors.Is(err, wire.ErrObfuscatedOverTLS) {
					s.obfuscatedOverTLS(h)
					return
				}
				s.unvalidated(h, nil, keyring.DiagNotTACACS, 0)
				s.backoff(ctx, "malformed_backoff")
				return
			}
		} else if err := h.Validate(); err != nil {
			diag := keyring.DiagNotTACACS
			if errors.Is(err, wire.ErrUnencrypted) {
				diag = keyring.DiagUnencrypted
			}
			s.unvalidated(h, nil, diag, 0)
			s.backoff(ctx, "malformed_backoff")
			return
		}

		raw := make([]byte, h.Length) // a Validate has already bounded Length at wire.MaxBodyLen
		if _, err := io.ReadFull(s.c, raw); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.d.Metrics.ConnectionEvents.WithLabelValues("idle_closed").Inc()
			}
			return
		}

		body := raw
		if s.tls != nil {
			// No key over TLS (RFC 9887 §4): the first packet's
			// single-connect flag decides, as the first validated one does on 49.
			if !s.tls.started {
				s.tls.started = true
				s.single = h.Flags&wire.FlagSingleConnect != 0
			}
		} else {
			var ok bool
			if body, ok = s.deobfuscate(ctx, h, raw); !ok {
				return
			}
		}

		// (from `if h.SeqNo == 255 {` to the end of the loop, unchanged)
	}
}
```

Keep each "unchanged" block's existing comments verbatim; the placeholders above stand only for
blocks this step does not touch.

5. In `write`, after `flags = wire.FlagSingleConnect`'s block, add:

```go
	out := body
	if s.tls != nil {
		flags |= wire.FlagUnencrypted // every reply over TLS (RFC 9887 §4)
	}
```

   build `rh` with `Flags: flags`, and send `append(rh.Encode(), out...)`, where `out` is
   `wire.Obfuscate(rh, s.keys.Secret(s.version), body)` only when `s.tls == nil`:

```go
	if s.tls == nil {
		out = wire.Obfuscate(rh, s.keys.Secret(s.version), body)
	}
	_, err := s.c.Write(append(rh.Encode(), out...))
	return err == nil
```

6. In `dispatch`, after building `peer`, add:

```go
	if s.tls != nil {
		peer.Transport, peer.CertSHA256 = admission.TransportTLS, s.tls.certSHA
	}
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./internal/daemon/server/ -run TestTLS -v -count=1`
Expected: PASS. Then run the whole package with the race detector: `go test -race
./internal/daemon/server/`. Expected: PASS, with every RFC 8907 test unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/server/
git commit -m "feat: the RFC 9887 listener: decide at Accept, then TLS 1.3 with mutual certificates

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 8: The other transport on 49, and open connections judged again

**Files:**
- Modify: `internal/daemon/server/conn.go` (`readmitted` :107, `serve`)
- Modify: `internal/daemon/server/tls.go`
- Test: `internal/daemon/server/tls_test.go`, `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: Task 7's fixture, `swapAdmitter`, `tlsSession`; `devicecert.Verifier.Recheck`.
- Produces: `func (s *conn) transportMismatch(h wire.Header)`, `func (s *conn) recheckTLS(ctx
  context.Context) devicecert.Verdict`, `func (s *conn) tlsWithdrawn(h wire.Header, v
  devicecert.Verdict)`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/daemon/server/server_test.go`:

```go
// A tls device's first header on the RFC 8907 listener is recorded
// transport_mismatch and declined: no key is tried, and no strike (spec §10;
// decision 50 ruling 4).
func TestATLSDeviceOnTheTCPListenerIsDeclined(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		dev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Transport: admission.TransportTLS,
			Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		trie, err := admission.NewTrie([]admission.Resolved{{Device: dev}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"transport_mismatch"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`the device record says transport tls; this is the RFC 8907 listener`) {
		t.Fatalf("the record says why: %s", log.String())
	}
	addr := netip.MustParseAddr("127.0.0.1")
	if ts.limits.Holding(addr) || !ts.limits.Declined(addr) {
		t.Fatal("declined, not struck")
	}
	if n := testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues("", "0", "no_known_key_matches")); n != 0 {
		t.Fatalf("a key was tried: %v", n)
	}
}
```

Append to `internal/daemon/server/tls_test.go`:

```go
// openSession dials leaf-01 single-connect and completes one exchange.
func openSession(t *testing.T, f *tlsFixture) *tlsClient {
	t.Helper()
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted|wire.FlagSingleConnect); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.recv(); err != nil {
		t.Fatal(err)
	}
	return c
}

// nextPacketEnds sends one more exchange and wants the connection ended
// with no reply.
func nextPacketEnds(t *testing.T, c *tlsClient) {
	t.Helper()
	c.seq, c.sid = 1, c.sid+1
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted|wire.FlagSingleConnect); err != nil {
		return // already gone
	}
	if _, _, err := c.recv(); err == nil {
		t.Fatal("the packet was answered")
	}
}

func TestTLSRecheckEndsAConnectionWhenItsCertificateIsRevoked(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	c := openSession(t, f)
	f.status.Store(int32(devicecert.StatusRevoked))
	nextPacketEnds(t, c)
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"certificate_revoked"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"seq_no":1`) || f.ts.limits.Holding(loopback) {
		t.Fatalf("the record carries the packet's header, and there is no strike: %s", log.String())
	}
}

func TestTLSReloadedAnchorsEndAnOpenConnection(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	c := openSession(t, f)
	rotated, err := testpki.NewCA("Device CA 2", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.mat.Store(f.material(rotated, true))
	nextPacketEnds(t, c)
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"unknown_ca"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestTLSTransportChangeWithdrawsAnOpenConnection(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	c := openSession(t, f)
	tcpDev := leaf01TLS
	tcpDev.Transport = admission.TransportTCP
	f.admit.set(t, admission.Resolved{Device: tcpDev, KeyRef: "prod_key"})
	nextPacketEnds(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_withdrawn"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	acceptRefused(t, f.ts.addr) // and the next connection is declined: transport_mismatch
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"transport_mismatch"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/server/ -run 'TestATLSDeviceOnTheTCPListener|TestTLSRecheck|TestTLSReloaded|TestTLSTransportChange' -v -count=1`
Expected: FAIL. On 49 the TLS device's packet is tried under an empty key set and recorded
`no_known_key_matches`, struck. On the TLS listener the revoked, re-anchored and re-transported
sessions are answered.

- [ ] **Step 3: Implement**

In `conn.go`'s `readmitted`, change the withdrawn case to:

```go
	case now.Device.Name != s.dev.Device.Name || now.KeyRef != s.dev.KeyRef ||
		now.Device.Platform != s.dev.Device.Platform || now.WirePlatform != s.dev.WirePlatform ||
		now.Device.EffectiveTransport() != s.dev.Device.EffectiveTransport():
		return keyring.DiagAdmissionWithdrawn
```

and add "or re-transports" to its doc comment's list of what a reload can do.

In `serve`, after the `if !s.admitted { ... }` block and before `readmitted`, add:

```go
		if s.mismatch {
			// A tls device on the RFC 8907 listener (spec §13 decision 50
			// ruling 4); on the RFC 9887 listener startTLS has ended it.
			s.transportMismatch(h)
			s.decline()
			return
		}
```

and after the quarantine block, before the header checks:

```go
		// An open TLS connection is judged again at every packet: holding it
		// open never extends a certificate's life (ruling 9).
		if s.tls != nil {
			if v := s.recheckTLS(ctx); v.Outcome != devicecert.OK {
				s.tlsWithdrawn(h, v)
				return
			}
		}
```

Add to `conn.go` (import `devicecert`):

```go
// transportMismatch records an admitted device's first header on the RFC
// 8907 listener when its record says another transport (spec §10): nothing
// past the header is read, no key is tried, and decline closes it with no
// strike.
func (s *conn) transportMismatch(h wire.Header) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTransportMismatch),
			Detail: "the device record says transport " + s.dev.Device.EffectiveTransport() +
				"; this is the RFC 8907 listener",
			Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTransportMismatch)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("transport_mismatch").Inc()
}
```

Add to `tls.go`:

```go
// recheckTLS judges an open connection's certificate at this packet: in
// full against the material in force when a reload replaced the one its
// handshake used, else its chain's expiry and status (ruling 9).
func (s *conn) recheckTLS(ctx context.Context) devicecert.Verdict {
	mat := s.d.TLS.Material()
	if mat != s.tls.mat {
		v := mat.Verifier.Verify(ctx, s.tls.peer, s.dev.Device)
		if v.Outcome == devicecert.OK {
			s.tls.mat, s.tls.verdict = mat, v
		}
		return v
	}
	return mat.Verifier.Recheck(ctx, s.tls.verdict)
}

// tlsWithdrawn ends an open connection whose certificate no longer admits
// it: recorded with the packet's header, and reset with no strike, since
// the device did nothing on this connection. A status that cannot be
// established is port49's, and declines (ruling 8).
func (s *conn) tlsWithdrawn(h wire.Header, v devicecert.Verdict) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
			Transport: admission.TransportTLS, TLSOutcome: string(v.Outcome), Detail: v.Detail, CertSHA256: s.tls.certSHA,
			Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("admission_closed").Inc()
	if s.d.TLS.Said != nil {
		s.d.TLS.Said(s.dev.Device.Name, s.src.String(), v)
	}
	if !v.Outcome.Struck() {
		s.decline()
		return
	}
	reset(s.raw)
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test -race ./internal/daemon/server/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/server/
git commit -m "feat: decline the other transport on 49, and judge open TLS connections at every packet

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 9: Session tickets, single-use and age-bounded

**Files:**
- Create: `internal/daemon/server/tickets.go`
- Test: `internal/daemon/server/tickets_test.go`

**Interfaces:**
- Consumes: Task 7's fixture.
- Produces: `func NewTicketGuard(lifetime time.Duration, now func() time.Time) *TicketGuard`,
  `func (g *TicketGuard) Apply(c *tls.Config) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/daemon/server/tickets_test.go`:

```go
package server

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// firstTicket is a client session cache that keeps the first ticket it is
// given and offers it at every connection: a client replaying one ticket.
type firstTicket struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *firstTicket) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *firstTicket) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cs == nil && cs != nil {
		c.cs = cs
	}
}

// ticketed sets the fixture's material to issue tickets for lifetime,
// under clock now.
func ticketed(t *testing.T, f *tlsFixture, lifetime time.Duration, now func() time.Time) {
	t.Helper()
	m := f.material(f.ca, false)
	if err := NewTicketGuard(lifetime, now).Apply(m.Config); err != nil {
		t.Fatal(err)
	}
	f.mat.Store(m)
}

// resumed logs in with cache and reports whether the connection resumed.
func resumed(t *testing.T, f *tlsFixture, cert tls.Certificate, cache tls.ClientSessionCache) bool {
	t.Helper()
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.recv(); err != nil { // the reply; the ticket arrived with it
		t.Fatal(err)
	}
	return c.conn.ConnectionState().DidResume
}

func TestNoTicketsWhenTheLifetimeIsZero(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := tls.NewLRUClientSessionCache(4)
	for i := 0; i < 2; i++ {
		if resumed(t, f, cert, cache) {
			t.Fatal("resumed with session_ticket_lifetime 0s")
		}
	}
}

func TestTicketsAreSingleUse(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	if resumed(t, f, cert, cache) {
		t.Fatal("the first connection resumed")
	}
	if !resumed(t, f, cert, cache) {
		t.Fatal("an unused ticket did not resume (RFC 9887 §3.6: SHOULD allow)")
	}
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket resumed twice")
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(devicecert.Resumed))); n != 1 {
		t.Fatalf("handshakes{resumed} = %v", n)
	}
}

func TestTicketsExpire(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	var skew atomic.Int64
	ticketed(t, f, time.Minute, func() time.Time { return time.Now().Add(time.Duration(skew.Load())) })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	skew.Store(int64(2 * time.Minute))
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket older than session_ticket_lifetime resumed")
	}
}

func TestAReloadInvalidatesTickets(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	ticketed(t, f, 10*time.Minute, time.Now) // a reload: new material, new keys
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket from before the reload resumed")
	}
}

func TestAResumptionIsVerifiedAgain(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	f.status.Store(int32(devicecert.StatusRevoked))
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err == nil {
		err = c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted)
		if err == nil {
			_, _, err = c.recv()
		}
	}
	if err == nil {
		t.Fatal("a resumption with a revoked certificate was answered (RFC 9887 §3.6)")
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"certificate_revoked"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/server/ -run 'Ticket|Resumption' -v -count=1`
Expected: FAIL to build: `undefined: NewTicketGuard`.

- [ ] **Step 3: Implement**

Create `internal/daemon/server/tickets.go`:

```go
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"sync"
	"time"
)

// TicketGuard makes the RFC 9887 listener's session tickets single-use and
// bounds their age at session_ticket_lifetime (RFC 9887 §3.6; spec §13
// decision 50 ruling 11). A ticket it will not resume is ignored, never an
// error: the device gets a full handshake, which verifies everything again.
type TicketGuard struct {
	lifetime time.Duration
	now      func() time.Time

	mu   sync.Mutex
	used map[[32]byte]time.Time // a resumed ticket's hash, and when it was used
}

// NewTicketGuard is a guard for tickets lifetime long.
func NewTicketGuard(lifetime time.Duration, now func() time.Time) *TicketGuard {
	return &TicketGuard{lifetime: lifetime, now: now, used: map[[32]byte]time.Time{}}
}

// Apply sets c, the base config every connection's is cloned from, to issue
// tickets under a fresh random key held only in memory, each stamped with
// its issue time, and to resume a ticket only once and only within the
// lifetime. A new load of the listener's files applies a new guard, so a
// reload invalidates every ticket outstanding.
func (g *TicketGuard) Apply(c *tls.Config) error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	c.SessionTicketsDisabled = false
	c.SetSessionTicketKeys([][32]byte{key})
	c.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		var at [8]byte
		binary.BigEndian.PutUint64(at[:], uint64(g.now().Unix()))
		ss.Extra = append(ss.Extra, at[:])
		return c.EncryptTicket(cs, ss)
	}
	c.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := c.DecryptTicket(identity, cs)
		if err != nil || ss == nil || !g.fresh(ss) || !g.firstUse(identity) {
			return nil, nil
		}
		return ss, nil
	}
	return nil
}

// fresh is whether ss carries an issue time within the lifetime.
func (g *TicketGuard) fresh(ss *tls.SessionState) bool {
	if len(ss.Extra) == 0 || len(ss.Extra[len(ss.Extra)-1]) != 8 {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(ss.Extra[len(ss.Extra)-1])), 0)
	age := g.now().Sub(issued)
	return age >= -time.Minute && age <= g.lifetime
}

// firstUse records identity as used and reports whether it was not before.
// Entries older than the lifetime are dropped: such a ticket is refused as
// stale anyway.
func (g *TicketGuard) firstUse(identity []byte) bool {
	sum := sha256.Sum256(identity)
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, at := range g.used {
		if now.Sub(at) > g.lifetime {
			delete(g.used, k)
		}
	}
	if _, seen := g.used[sum]; seen {
		return false
	}
	g.used[sum] = now
	return true
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test -race ./internal/daemon/server/ -run 'Ticket|Resumption' -v -count=1 && go test -race ./internal/daemon/server/`
Expected: PASS. If `TestTicketsAreSingleUse`'s second connection does not resume, check that
`resumed` reads the reply before closing: a TLS 1.3 client takes the NewSessionTicket only while
reading.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/server/tickets.go internal/daemon/server/tickets_test.go
git commit -m "feat: single-use, age-bounded session tickets on the RFC 9887 listener

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 10: port49d: load, reload and serve the TLS listener

**Files:**
- Create: `internal/port49d/tlslistener.go`
- Modify: `internal/port49d/certstatus.go` (`certStatusConfig` :35)
- Modify: `internal/port49d/brokerd.go:506`, `internal/port49d/main.go` (:1091 the broker's
  checker; :1174 `deps`; :1220 the binds; the "listening on" line; the reloader goroutine
  :1375–1412; :1415 `Serve`; the shutdown joins)
- Modify: `internal/port49d/reload.go` (`run` :337)
- Test: `internal/port49d/tlslistener_test.go`, `internal/port49d/broker_test.go`
  (`writeRunConfig` :441)

**Interfaces:**
- Consumes:
  - `config.TLSListenerConfig` and `config.Config.Listen == ""` (Task 5);
  - `server.TLS`, `server.Material`, `server.NewTicketGuard` (Tasks 7, 9);
  - `devicecert.*` (Task 4);
  - `certstatus.Config.Component` (Task 5);
  - `metrics.WatchTLSExpiry`, `CountDevicesByTransport` (Task 6).
- Produces:
  - `type tlsListener` with `Material() *server.Material`, `ServerExpiry() time.Duration`,
    `reload(why string)` and `watch(ctx context.Context)`;
  - `func tlsListenerOf(cfg config.Config, m *metrics.Metrics, say func(string, ...any))
    (*tlsListener, *certstatus.Checker, error)`;
  - `certStatusConfig(cs, anchors, stateDir, trusted, who string)`;
  - `func writeRunConfigWith(t *testing.T, b *config.BrokerConfig, inventory, extra string)
    string` (a test helper).

- [ ] **Step 1: Write the failing tests**

In `internal/port49d/broker_test.go`, turn `writeRunConfig` into a wrapper:

```go
func writeRunConfig(t *testing.T, b *config.BrokerConfig) string {
	t.Helper()
	return writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`, "")
}

// writeRunConfigWith is writeRunConfig with the inventory's body and extra
// top-level YAML appended to port49d.yaml (a tls_listener block, say).
func writeRunConfigWith(t *testing.T, b *config.BrokerConfig, inventory, extra string) string {
	t.Helper()
	t.Setenv("T_RUN_SECRET", "run-test-secret")
	t.Setenv("T_RUN_ENC", "33333333333333333333333333333333")
	// safeDir: the inventory is read behind the policy file's fence.
	dir := safeDir(t)
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
keys:
  k:
    current: {version: 1, secret_env: T_RUN_SECRET}
encryption:
  current: {id: v1, secret_env: T_RUN_ENC}
accounting: {spool_path: %s}
broker:
  listen: %q
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
  revocations_file: %s
  policy_watch_interval: 1s
  certificate_status:
%s`, inv, filepath.Join(dir, "acct.jsonl"), b.Listen, b.TLSCertFile, b.TLSKeyFile, b.ClientCAFile,
		b.PolicyFile, b.RevocationsFile, certStatusYAML(t, b.CertificateStatus))+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}
```

This is the old body with the inventory and `extra` as parameters. Every existing caller is
unchanged. `certStatusYAML`'s output ends with a newline; if it does not, add one before
`extra`.

Create `internal/port49d/tlslistener_test.go`:

```go
package port49d

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// devicePKI is a device CA, port49's TLS server certificate under it, and
// leaf1's client certificate, written to files.
type devicePKI struct {
	ca                         *testpki.CA
	caFile, certFile, keyFile  string
	client                     tls.Certificate
}

func writeDevicePKI(t *testing.T) devicePKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := testpki.NewCA("Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Issue(testpki.Leaf{DNSNames: []string{"tacacs.example.net"}, IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.Issue(testpki.Leaf{DNSNames: []string{"leaf1"}, Client: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	p := devicePKI{ca: ca, caFile: filepath.Join(dir, "device-ca.pem"), certFile: filepath.Join(dir, "srv.crt"),
		keyFile: filepath.Join(dir, "srv.key"), client: cli}
	for path, body := range map[string][]byte{p.caFile: ca.PEM(), p.certFile: certPEM, p.keyFile: keyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func (p devicePKI) block(listen string) string {
	return "tls_listener:\n  listen: \"" + listen + "\"\n  cert_file: " + p.certFile + "\n  key_file: " + p.keyFile +
		"\n  client_ca_file: " + p.caFile + "\n  server_names: [tacacs.example.net]\n" +
		"  certificate_status: {disabled: true}\n"
}

// tlsLogin logs user in over the RFC 9887 listener as leaf1.
func tlsLogin(t *testing.T, addr string, p devicePKI, user, password string) uint8 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.ca.Pool(), ServerName: "tacacs.example.net",
		Certificates: []tls.Certificate{p.client}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(password)}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: wire.FlagUnencrypted, SessionID: 0x5eed,
		Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), body...)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		t.Fatalf("no reply over TLS: %v", err)
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		t.Fatal(err)
	}
	r, err := wire.DecodeAuthenReply(rb)
	if err != nil {
		t.Fatal(err)
	}
	return r.Status
}

func TestRunServesBothListenersApart(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}
`, p.block("127.0.0.1:0"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	find := func(re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(out.String())
		if m == nil {
			t.Fatalf("no %q in stderr: %q", re, out.String())
		}
		return m[1]
	}
	tcpAddr := find(`port49d: listening on (127\.0\.0\.1:\d+)`)
	tlsAddr := find(`port49d: RFC 9887 listener on (127\.0\.0\.1:\d+)`)
	brokerAddr := find(`broker listening on (127\.0\.0\.1:\d+)`)
	for _, want := range []string{"RFC 9887 §5.1.1", "1 devices transport tls", "tls_listener: anchors CN=Device CA"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, out.String())
		}
	}

	if st := tlsLogin(t, tlsAddr, p, "alice", mint(t, brokerAddr, pkiDir, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("login over TLS: %d; log %s", st, log.String())
	}
	if !strings.Contains(log.String(), `"transport":"tls"`) || !strings.Contains(log.String(), `"cert_sha256":"`) {
		t.Fatalf("the redeem record names the transport and the certificate: %s", log.String())
	}

	// The same device on the RFC 8907 listener: one header, then a reset.
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
	conn.Write(append(h.Encode(), 0, 0, 0, 0))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("a tls device on 49 was answered: %d %v", n, err)
	}
	waitFor(t, &log, `"diagnosis":"transport_mismatch"`)
}

func TestListenNoneSaysTheRFC8907ListenerIsOff(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	b := brokerConfig(t, minimalPolicy).Broker
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n",
		p.block("127.0.0.1:0"))
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(string(raw), `listen: "127.0.0.1:0"`+"\nmetrics_listen",
		"listen: none\nmetrics_listen", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: RFC 8907 listener off (listen: none)")
	if strings.Contains(out.String(), "RFC 9887 §5.1.1") {
		t.Fatal("a TLS-only port49d said the same-host notice")
	}
}

func TestTLSMaterialReloadKeepsTheOldOnABadFile(t *testing.T) {
	p := writeDevicePKI(t)
	var lines []string
	say := func(f string, a ...any) { lines = append(lines, strings.TrimSpace(fmt.Sprintf(f, a...))) }
	cfg := config.TLSListenerConfig{Listen: ":0", CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.caFile,
		DeviceIdentity: config.DeviceIdentityConfig{Match: []string{"dns_name", "ip_address"}}}
	l, err := newTLSListener(cfg, nil, false, time.Now, say)
	if err != nil {
		t.Fatal(err)
	}
	first := l.Material()
	l.reload("SIGHUP")
	if l.Material() != first {
		t.Fatal("unchanged files swapped the material")
	}
	if err := os.WriteFile(p.certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.reload("reload_interval")
	l.reload("reload_interval")
	if l.Material() != first {
		t.Fatal("a bad file replaced the material in force")
	}
	refusals := 0
	for _, line := range lines {
		if strings.Contains(line, "not reloaded, the files in force stay") {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("a refusal is said once: %q", lines)
	}
	p2 := writeDevicePKI(t)
	certPEM, err := os.ReadFile(p2.certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(p2.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.certFile, certPEM, 0o600)
	os.WriteFile(p.keyFile, keyPEM, 0o600)
	l.reload("SIGHUP")
	if l.Material() == first || !strings.Contains(strings.Join(lines, "\n"), "SIGHUP: reloaded") {
		t.Fatalf("a good set was not swapped in: %q", lines)
	}
}

func TestTLSMaterialRefusesANonCAAnchor(t *testing.T) {
	p := writeDevicePKI(t)
	certPEM, _, err := testpki.PEMs(p.client)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.caFile, certPEM, 0o600)
	cfg := config.TLSListenerConfig{CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.caFile,
		DeviceIdentity: config.DeviceIdentityConfig{Match: []string{"dns_name"}}}
	if _, err := newTLSListener(cfg, nil, false, time.Now, func(string, ...any) {}); err == nil ||
		!strings.Contains(err.Error(), "is not a CA certificate") {
		t.Fatalf("a leaf as an anchor: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/port49d/ -run 'TestRunServesBoth|TestListenNone|TestTLSMaterial' -v -count=1`
Expected: FAIL to build: `undefined: newTLSListener`. Once that builds, `run` ignores
`tls_listener` and prints no "RFC 9887 listener on" line.

- [ ] **Step 3: Write `tlslistener.go`**

Create `internal/port49d/tlslistener.go`:

```go
package port49d

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/printsafe"
)

// tlsFileMax bounds each of the listener's files: a chain or a CA bundle is
// kilobytes.
const tlsFileMax = 1 << 20

// tlsListener holds the RFC 9887 listener's files as loaded, and swaps them
// whole when their bytes change and they load (spec §13 decision 50 ruling
// 15). The key file's bytes are hashed to tell a change and never kept,
// said or logged.
type tlsListener struct {
	cfg          config.TLSListenerConfig
	status       devicecert.StatusFunc
	allowUnknown bool
	now          func() time.Time
	say          func(format string, args ...any)

	cur        atomic.Pointer[server.Material]
	serverLeaf atomic.Pointer[x509.Certificate]

	mu     sync.Mutex
	sum    [32]byte
	failed string
}

func newTLSListener(cfg config.TLSListenerConfig, status devicecert.StatusFunc, allowUnknown bool,
	now func() time.Time, say func(string, ...any)) (*tlsListener, error) {
	l := &tlsListener{cfg: cfg, status: status, allowUnknown: allowUnknown, now: now, say: say}
	files, sum, err := l.read()
	if err != nil {
		return nil, err
	}
	m, leaf, desc, err := l.build(files)
	if err != nil {
		return nil, err
	}
	l.cur.Store(m)
	l.serverLeaf.Store(leaf)
	l.sum = sum
	say("tls_listener: %s", desc)
	l.sayExpired(leaf)
	return l, nil
}

// Material is the set in force, for server.TLS.
func (l *tlsListener) Material() *server.Material { return l.cur.Load() }

// ServerExpiry is the time until the server certificate in force expires.
func (l *tlsListener) ServerExpiry() time.Duration { return l.serverLeaf.Load().NotAfter.Sub(l.now()) }

// reload reads the files again. Unchanged bytes do nothing; a set that loads
// replaces the one in force and is said; one that does not is said once per
// distinct failure, and the set in force stays.
func (l *tlsListener) reload(why string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	files, sum, err := l.read()
	if err == nil && sum == l.sum {
		l.failed = ""
		return
	}
	var m *server.Material
	var leaf *x509.Certificate
	var desc string
	if err == nil {
		m, leaf, desc, err = l.build(files)
	}
	if err != nil {
		if msg := err.Error(); msg != l.failed {
			l.failed = msg
			l.say("tls_listener: %s: not reloaded, the files in force stay: %s", why, msg)
		}
		return
	}
	l.failed = ""
	l.cur.Store(m)
	l.serverLeaf.Store(leaf)
	l.sum = sum
	l.say("tls_listener: %s: reloaded: %s", why, desc)
	l.sayExpired(leaf)
}

// watch reloads every reload_interval until ctx ends.
func (l *tlsListener) watch(ctx context.Context) {
	t := time.NewTicker(l.cfg.ReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.reload("reload_interval")
		}
	}
}

type tlsFiles struct{ cert, key, ca, inter []byte }

// read reads the four files, each a regular file within tlsFileMax, and
// their joint hash.
func (l *tlsListener) read() (tlsFiles, [32]byte, error) {
	var f tlsFiles
	h := sha256.New()
	for _, x := range []struct {
		key, path string
		into      *[]byte
	}{{"cert_file", l.cfg.CertFile, &f.cert}, {"key_file", l.cfg.KeyFile, &f.key},
		{"client_ca_file", l.cfg.ClientCAFile, &f.ca}, {"intermediates_file", l.cfg.IntermediatesFile, &f.inter}} {
		if x.path == "" {
			continue
		}
		b, err := config.ReadRegular(x.path, tlsFileMax)
		if err != nil {
			return tlsFiles{}, [32]byte{}, fmt.Errorf("tls_listener.%s %s: %w", x.key, x.path, err)
		}
		*x.into = b
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return f, sum, nil
}

// build makes one Material from the files' bytes and describes it.
func (l *tlsListener) build(f tlsFiles) (*server.Material, *x509.Certificate, string, error) {
	cert, err := tls.X509KeyPair(f.cert, f.key)
	if err != nil {
		// crypto/tls's text names the fault, never the key's bytes.
		return nil, nil, "", fmt.Errorf("tls_listener.cert_file and key_file do not load as a pair (%s)",
			printsafe.Line(err.Error(), 200))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("tls_listener.cert_file: %w", err)
	}
	anchors, err := caCerts("client_ca_file", f.ca)
	if err != nil {
		return nil, nil, "", err
	}
	if len(anchors) == 0 {
		return nil, nil, "", errors.New("tls_listener.client_ca_file holds no certificate")
	}
	inters, err := caCerts("intermediates_file", f.inter)
	if err != nil {
		return nil, nil, "", err
	}
	pool := x509.NewCertPool()
	for _, a := range anchors {
		pool.AddCert(a)
	}
	base := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true}
	tickets := "off"
	if l.cfg.SessionTicketLifetime > 0 {
		if err := server.NewTicketGuard(l.cfg.SessionTicketLifetime, l.now).Apply(base); err != nil {
			return nil, nil, "", fmt.Errorf("tls_listener: session ticket keys: %w", err)
		}
		tickets = "single-use, " + l.cfg.SessionTicketLifetime.String()
	}
	id := l.cfg.DeviceIdentity
	ver := &devicecert.Verifier{Anchors: pool, Intermediates: inters, Status: l.status, AllowUnknown: l.allowUnknown,
		Now: l.now, Rule: devicecert.Rule{DNSName: slices.Contains(id.Match, "dns_name"),
			IPAddress: slices.Contains(id.Match, "ip_address"), DNSSuffixes: id.DNSSuffixes}}
	names := make([]string, 0, len(anchors))
	for _, a := range anchors {
		names = append(names, describeCert(a))
	}
	desc := fmt.Sprintf("anchors %s; %d stored intermediates; server certificate %s expires %s; session tickets %s",
		strings.Join(names, ", "), len(inters), describeCert(leaf), leaf.NotAfter.UTC().Format(time.RFC3339), tickets)
	return &server.Material{Config: base, Verifier: ver}, leaf, desc, nil
}

func (l *tlsListener) sayExpired(leaf *x509.Certificate) {
	if now := l.now(); now.After(leaf.NotAfter) {
		l.say("tls_listener: the server certificate expired at %s: devices that check it refuse this listener "+
			"until cert_file is replaced", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}

// caCerts parses every CERTIFICATE block in b and refuses one that is not a
// CA certificate: an anchor or an intermediate signs, and a leaf there would
// admit only itself while reading as a CA.
func caCerts(key string, b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tls_listener.%s: certificate %d: %w", key, len(out)+1, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("tls_listener.%s: %s is not a CA certificate", key, printsafe.Line(c.Subject.String(), 200))
		}
		out = append(out, c)
	}
}

// describeCert is a certificate's subject and the first 16 hex digits of
// its SHA-256, as the start and reload lines name it.
func describeCert(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return printsafe.Line(c.Subject.String(), 120) + " (sha256 " + hex.EncodeToString(sum[:8]) + ")"
}

// deviceStatus adapts the TLS listener's certstatus.Checker to devicecert.
func deviceStatus(c *certstatus.Checker) devicecert.StatusFunc {
	return func(ctx context.Context, chain []*x509.Certificate) (devicecert.Status, string) {
		r := c.Check(ctx, chain)
		switch r.Verdict {
		case certstatus.Revoked:
			return devicecert.StatusRevoked, fmt.Sprintf("%s %s: the certificate at depth %d was revoked at %s",
				r.Source, r.Name, r.Depth, r.RevokedAt.UTC().Format(time.RFC3339))
		case certstatus.Unknown:
			return devicecert.StatusUnknown, r.Detail
		}
		return devicecert.StatusGood, ""
	}
}

// tlsListenerOf builds the RFC 9887 listener's material and its status
// checker from cfg.TLSListener: nil, nil without one.
func tlsListenerOf(cfg config.Config, m *metrics.Metrics, say func(string, ...any)) (*tlsListener, *certstatus.Checker, error) {
	tc := cfg.TLSListener
	if tc == nil {
		return nil, nil, nil
	}
	var checker *certstatus.Checker
	var status devicecert.StatusFunc
	if cs := tc.CertificateStatus; !cs.Disabled {
		var trusted []*x509.Certificate
		for _, p := range []string{tc.ClientCAFile, tc.IntermediatesFile} {
			if p == "" {
				continue
			}
			b, err := config.ReadRegular(p, tlsFileMax)
			if err != nil {
				return nil, nil, err
			}
			cs, err := caCerts("client_ca_file", b)
			if err != nil {
				return nil, nil, err
			}
			trusted = append(trusted, cs...)
		}
		ccfg, err := certStatusConfig(*cs, trusted, tc.StateDir, "tls_listener.client_ca_file or intermediates_file",
			"the TLS listener")
		if err != nil {
			return nil, nil, fmt.Errorf("tls_listener.certificate_status.%w", err)
		}
		ccfg.Component = "tls_listener"
		checker = certstatus.New(ccfg, time.Now, m, say)
		for _, err := range checker.LoadPersisted() {
			say("tls_listener: certificate status: %s", printsafe.Line(err.Error(), 300))
		}
		status = deviceStatus(checker)
	}
	l, err := newTLSListener(*tc, status, tc.CertificateStatus.OnUnavailable == "allow", time.Now, say)
	if err != nil {
		return nil, nil, err
	}
	return l, checker, nil
}

// refusalSayer says each device's TLS refusal on stderr at most once per
// device and outcome every ten minutes (ruling 16): the decision log has
// every one.
type refusalSayer struct {
	now  func() time.Time
	say  func(string, ...any)
	mu   sync.Mutex
	last map[string]time.Time
}

func (r *refusalSayer) said(device, source string, v devicecert.Verdict) {
	key := device + "\x00" + source + "\x00" + string(v.Outcome)
	now := r.now()
	r.mu.Lock()
	if r.last == nil {
		r.last = map[string]time.Time{}
	}
	if at, ok := r.last[key]; ok && now.Sub(at) < 10*time.Minute {
		r.mu.Unlock()
		return
	}
	r.last[key] = now
	r.mu.Unlock()
	name := device
	if name == "" {
		name = "an unknown device"
	}
	r.say("tls_listener: %s (%s) refused: %s: %s (said once per 10m)", name, source, v.Outcome, v.Detail)
}
```

In `internal/port49d/certstatus.go`, change `certStatusConfig`'s signature to
`certStatusConfig(cs config.CertificateStatusConfig, anchors []*x509.Certificate, stateDir,
trusted, who string)`. Its refusal becomes:

```go
			return certstatus.Config{}, fmt.Errorf("%s: %s is neither a trust anchor's certificate nor signed by "+
				"one (%s); CRL %s would vouch for certificates %s does not trust", key,
				printsafe.Line(issuer.Subject.String(), 200), trusted, src.Name, who)
```

Update its two callers (`main.go:1091`, `brokerd.go:506`) to pass `"broker.client_ca_file, or a
broker.identity x509 trust_anchor_file", "the broker"`. The broker's text is then unchanged.

- [ ] **Step 4: Wire it into `run`**

In `internal/port49d/main.go`:

1. Right after the `deps := server.Deps{...}` statement, build the listener (a refusal stops the
   start before anything binds):

```go
	sayf := func(format string, args ...any) { fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...) }
	tl, tlsChecker, err := tlsListenerOf(cfg, m, sayf)
	if err != nil {
		mln.Close()
		stopSpool()
		<-spoolDone
		return err
	}
	var tlsDeps *server.TLS
	if tl != nil {
		expiry := &devicecert.Expiry{Warn: cfg.TLSListener.ExpiryWarning, Say: sayf}
		said := &refusalSayer{now: time.Now, say: sayf}
		m.WatchTLSExpiry(func() (time.Duration, bool) { return expiry.Soonest(time.Now()) }, tl.ServerExpiry)
		tlsDeps = &server.TLS{Material: tl.Material, ServerNames: cfg.TLSListener.ServerNames,
			HandshakeTimeout: cfg.TLSListener.HandshakeTimeout, Seen: expiry.Seen, Said: said.said}
	}
	m.CountDevicesByTransport(func() map[string]int { n, _ := transportCount(cfg, live); return n })
```

   (If a `sayf` already exists in `run`'s scope, reuse it.)

2. Replace the single bind `ln, err := net.Listen("tcp", cfg.Listen)` and its error block with:

```go
	var ln, tln net.Listener
	closeListeners := func() {
		if ln != nil {
			ln.Close()
		}
		if tln != nil {
			tln.Close()
		}
	}
	if cfg.Listen != "" {
		if ln, err = net.Listen("tcp", cfg.Listen); err != nil {
			mln.Close()
			stopSpool()
			<-spoolDone
			return err
		}
	}
	if tl != nil {
		if tln, err = net.Listen("tcp", cfg.TLSListener.Listen); err != nil {
			closeListeners()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("tls_listener.listen %s: %w", cfg.TLSListener.Listen, err)
		}
	}
```

   and in the broker-bind and admin-socket failure paths below it, replace `ln.Close()` with
   `closeListeners()`.

3. Replace the "listening on" `Fprintf` with:

```go
	if ln != nil {
		fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
			ln.Addr(), mln.Addr(), admitted)
	} else {
		fmt.Fprintf(stderr, "port49d: RFC 8907 listener off (listen: none), metrics on %s, %d devices admitted\n",
			mln.Addr(), admitted)
	}
	announceTransports(stderr, cfg, live, ln, tln, tlsChecker)
```

   and add to `tlslistener.go`:

```go
// announceTransports is the start's lines about the RFC 9887 listener and
// the devices each transport counts (decision 50 rulings 1 and 4).
func announceTransports(w io.Writer, cfg config.Config, live *policy.Live, ln, tln net.Listener, chk *certstatus.Checker) {
	n, names := transportCount(cfg, live)
	if tln != nil {
		tc := cfg.TLSListener
		status := "disabled (tls_listener.certificate_status.disabled)"
		if chk != nil {
			status = "from " + chk.Describe() + "; a status that cannot be established is " +
				map[string]string{"refuse": "refused (declined)", "allow": "allowed, alarmed"}[tc.CertificateStatus.OnUnavailable]
		}
		fmt.Fprintf(w, "port49d: RFC 9887 listener on %s (TLS 1.3, mutual certificates; device identity by %s; "+
			"certificate status %s), %d devices transport tls\n", tln.Addr(), strings.Join(tc.DeviceIdentity.Match, " or "),
			status, n["tls"])
	}
	if ln != nil && tln != nil {
		fmt.Fprintf(w, "port49d: notice: RFC 9887 §5.1.1 does not recommend TLS and non-TLS TACACS+ on one host; "+
			"here each device's record names one transport and the other listener declines it "+
			"(transport_mismatch), so no device can be downgraded from %s to %s\n", tln.Addr(), ln.Addr())
	}
	if !servesTLS(cfg) && n["tls"] > 0 {
		fmt.Fprintf(w, "port49d: %d devices have transport tls and port49d serves no tls_listener; their "+
			"connections here are declined transport_mismatch: %s\n", n["tls"], strings.Join(names["tls"], ", "))
	}
	if cfg.Listen == "" && n["tcp"] > 0 {
		fmt.Fprintf(w, "port49d: %d devices have transport tcp and port49d serves no RFC 8907 listener "+
			"(listen: none); their connections here are declined transport_mismatch: %s\n", n["tcp"],
			strings.Join(names["tcp"], ", "))
	}
}

func servesTLS(cfg config.Config) bool { return cfg.TLSListener != nil }

// transportCount is the admitted devices by transport, with up to five
// names of each, from the policy in force or, with no broker, the
// inventory port49d admits from.
func transportCount(cfg config.Config, live *policy.Live) (map[string]int, map[string][]string) {
	n, names := map[string]int{}, map[string][]string{}
	add := func(d admission.Device) {
		t := d.EffectiveTransport()
		n[t]++
		if len(names[t]) < 5 {
			names[t] = append(names[t], d.Name)
		}
	}
	if live != nil {
		pol := live.Load()
		for _, d := range pol.Devices() {
			if r, ok := pol.Admitted(d.Name); ok && r.Refused == "" {
				add(d)
			}
		}
		return n, names
	}
	for _, d := range cfg.Inventory.Devices {
		if len(d.Addresses) == 0 || cfg.Admission == nil {
			continue
		}
		if r, ok := cfg.Admission.Lookup(d.Addresses[0]); ok && r.Refused == "" {
			add(d)
		}
	}
	return n, names
}
```

   Add the imports `io`, `net`, `internal/admission` and `internal/policy`. The test's `"1
   devices transport tls"` matches the TLS line's tail.

4. In the reloader goroutine, after `r := newReloader(...)`, add:

```go
		if tl != nil {
			r.onHUP = func() { tl.reload("SIGHUP") }
		}
		// A swap that changes how many devices have a transport this
		// port49d does not serve says so (decision 50 ruling 4).
		lastUnserved := unservedOf(cfg, live)
		r.onSwap = func(*policy.Policy) {
			if u := unservedOf(cfg, live); u != lastUnserved {
				lastUnserved = u
				announceTransports(stderr, cfg, live, nil, nil, nil)
			}
		}
```

   With both listeners passed as nil, `announceTransports` prints only the unserved lines: the
   notice needs both, and the TLS line needs `tln`. Define `unservedOf` beside
   `transportCount`:

```go
// unservedOf is how many admitted devices have a transport this port49d
// runs no listener for.
func unservedOf(cfg config.Config, live *policy.Live) int {
	n, _ := transportCount(cfg, live)
	u := 0
	if !servesTLS(cfg) {
		u += n["tls"]
	}
	if cfg.Listen == "" {
		u += n["tcp"]
	}
	return u
}
```

   In the no-broker loop (`if live == nil { for { select { ... case <-hup:` ), call
   `tl.reload("SIGHUP")` when `tl != nil` before its existing line.

   In `internal/port49d/reload.go`, add to `reloader` beside `onSwap`:

```go
	// onHUP is told each SIGHUP before the reload: the TLS listener's files
	// are re-read then too (decision 50 ruling 15). Nil is nothing.
	onHUP func()
```

   and in `run`'s `case <-hup:` call `if r.onHUP != nil { r.onHUP() }` before
   `r.reload(ctx, "SIGHUP")`.

5. Start the watch and the checker after the "listening" lines, joined with the others at
   shutdown:

```go
	if tl != nil {
		statusDone.Add(1)
		go func() { defer statusDone.Done(); tl.watch(ctx) }()
		if tlsChecker != nil {
			statusDone.Add(1)
			go func() { defer statusDone.Done(); tlsChecker.Run(ctx) }()
		}
	}
```

   (Put this after `var statusDone sync.WaitGroup` is declared.)

6. Replace `go func() { serveErr <- server.Serve(ctx, ln, deps) }()` with:

```go
	go func() { serveErr <- serveListeners(ctx, cancel, ln, deps, tln, tlsDeps) }()
```

   and add to `tlslistener.go`:

```go
// serveListeners runs the RFC 8907 listener, the RFC 9887 one, or both,
// and returns once each has: the first to fail ends the run (cancel), so
// the spool is never stopped while either still serves.
func serveListeners(ctx context.Context, cancel context.CancelFunc, ln net.Listener, deps server.Deps,
	tln net.Listener, tlsDeps *server.TLS) error {
	errs := make(chan error, 2)
	n := 0
	if ln != nil {
		n++
		go func() { errs <- server.Serve(ctx, ln, deps) }()
	}
	if tln != nil {
		n++
		td := deps
		td.TLS = tlsDeps
		go func() { errs <- server.Serve(ctx, tln, td) }()
	}
	var first error
	for range n {
		if err := <-errs; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}
```

   `deps` is read here, after the admin socket set `deps.Held`, so both copies carry it. The
   existing `select` on `serveErr` is unchanged.

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test -race ./internal/port49d/ -count=1 -timeout 30m`
Expected: PASS: the new tests, and every existing run test (no `tls_listener`, same lines).

- [ ] **Step 6: Commit**

```bash
git add internal/port49d/
git commit -m "feat: port49d loads, reloads and serves the RFC 9887 listener

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 11: The reference harness (L72)

**Files:**
- Create: `tests/lab/cmd/tacacs-tls-client/main.go`
- Create: `tests/lab/l72_test.go` (build tag `lab`)
- Create: `tests/lab/l72_unit_test.go` (no tag: the client's output parser and the cell table)
- Modify: `tests/lab/README.md` (a section "L72: the RFC 9887 listener against reference clients")

**Interfaces:**
- Consumes: port49d with `tls_listener` (Task 10); `testpki`; `labcreds.SeedTokens`,
  `labcreds.Contains`, `labcreds.RedactNote`; `labGuardAt`.
- Produces: the client binary's JSON line `{"conn":N,"handshake":"ok"|"error","error":"...",
  "resumed":bool,"status":"pass"|"fail"|"error"|"none","flags":N,"after":"eof"|"reset"|"open"|"timeout","closed_ms":N}`,
  and `tests/lab/results/L72-reference.md` plus `tests/lab/evidence/L72-reference/`.

- [ ] **Step 1: Write the client**

Create `tests/lab/cmd/tacacs-tls-client/main.go`:

```go
// Command tacacs-tls-client is L72's reference RFC 9887 client: TACACS+
// over TLS with Go's crypto/tls, one PAP login per connection, and a JSON
// line per connection saying what the server did. It never prints the token
// it reads.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type result struct {
	Conn      int    `json:"conn"`
	Handshake string `json:"handshake"`
	Error     string `json:"error,omitempty"`
	Resumed   bool   `json:"resumed"`
	Status    string `json:"status"`
	Flags     int    `json:"flags"`
	After     string `json:"after"`
	ClosedMS  int64  `json:"closed_ms"`
}

// firstTicket offers the first ticket it was given at every connection.
type firstTicket struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *firstTicket) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *firstTicket) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cs == nil && cs != nil {
		c.cs = cs
	}
}

func main() {
	addr := flag.String("addr", "", "host:port")
	source := flag.String("source", "", "local address to connect from")
	certFile := flag.String("cert", "", "client certificate (PEM); none sends no certificate")
	keyFile := flag.String("key", "", "client key (PEM)")
	caFile := flag.String("ca", "", "CA that signs the server's certificate")
	serverName := flag.String("server-name", "", "SNI and the name the server's certificate is checked against")
	user := flag.String("user", "alice", "username")
	tokenFile := flag.String("token-file", "", "file holding the password; read, never printed")
	tls12 := flag.Bool("max-tls12", false, "offer TLS 1.2 only")
	obfuscated := flag.Bool("obfuscated", false, "send the login with the unencrypted flag clear")
	plain := flag.Bool("plain", false, "no TLS: send one RFC 8907 header and four body bytes")
	silent := flag.Bool("silent", false, "connect over TCP and send nothing; report when the server closes")
	count := flag.Int("count", 1, "connections, one after another")
	replay := flag.Bool("replay", false, "offer the first session ticket at every connection")
	flag.Parse()

	var password []byte
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "token-file:", err) // the path's error, never its contents
			os.Exit(2)
		}
		password = []byte(strings.TrimSpace(string(b)))
	}
	cfg := &tls.Config{ServerName: *serverName, MinVersion: tls.VersionTLS12}
	if *tls12 {
		cfg.MaxVersion = tls.VersionTLS12
	}
	if *caFile != "" {
		b, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ca:", err)
			os.Exit(2)
		}
		cfg.RootCAs = x509.NewCertPool()
		cfg.RootCAs.AppendCertsFromPEM(b)
	}
	if *certFile != "" {
		c, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cert:", err)
			os.Exit(2)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	if *replay {
		cfg.ClientSessionCache = &firstTicket{}
	} else {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if *source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(*source)}
	}
	enc := json.NewEncoder(os.Stdout)
	for i := 1; i <= *count; i++ {
		enc.Encode(one(i, dialer, *addr, cfg, *user, password, *obfuscated, *plain, *silent))
	}
}

func one(i int, d *net.Dialer, addr string, cfg *tls.Config, user string, password []byte,
	obfuscated, plain, silent bool) result {
	r := result{Conn: i, Status: "none"}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		r.Handshake, r.Error = "error", err.Error()
		return r
	}
	defer raw.Close()
	start := time.Now()
	raw.SetDeadline(start.Add(10 * time.Second))
	if silent || plain {
		r.Handshake = "none"
		if plain {
			h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
			raw.Write(append(h.Encode(), 0, 0, 0, 0))
		}
		r.After = after(raw)
		r.ClosedMS = time.Since(start).Milliseconds()
		return r
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		r.Handshake, r.Error = "error", err.Error()
		return r
	}
	r.Handshake, r.Resumed = "ok", tc.ConnectionState().DidResume
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("tty0"), RemAddr: []byte("192.0.2.72"),
		Data: password}.Encode()
	flags := uint8(wire.FlagUnencrypted)
	if obfuscated {
		flags = 0
	}
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: flags, SessionID: 0x72, Length: uint32(len(body))}
	if _, err := tc.Write(append(h.Encode(), body...)); err != nil {
		r.Error = err.Error()
		r.After = "reset"
		return r
	}
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(tc, hb); err != nil {
		r.Error = err.Error() // a TLS alert arrives here in TLS 1.3
		r.After = classify(err)
		r.ClosedMS = time.Since(start).Milliseconds()
		return r
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	io.ReadFull(tc, rb)
	r.Flags = int(rh.Flags)
	if rep, err := wire.DecodeAuthenReply(rb); err == nil {
		r.Status = map[uint8]string{wire.AuthenStatusPass: "pass", wire.AuthenStatusFail: "fail",
			wire.AuthenStatusError: "error"}[rep.Status]
	}
	r.After = after(tc)
	r.ClosedMS = time.Since(start).Milliseconds()
	return r
}

// after reads once more and says how the server left the connection.
func after(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return classify(err)
}

func classify(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "open"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error: " + err.Error()
}
```

- [ ] **Step 2: Write the unit test of the cell table**

Create `tests/lab/l72_unit_test.go`:

```go
package lab

import "testing"

// Every L72 cell named in spec §15 has a runner, and none is run twice.
func TestL72CellsAreTheRegistersCells(t *testing.T) {
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o"}
	got := map[string]bool{}
	for _, c := range l72Cells {
		if got[c.id] {
			t.Fatalf("cell %s twice", c.id)
		}
		got[c.id] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("cell %s has no runner", id)
		}
	}
}

func TestL72ParsesTheClientsLine(t *testing.T) {
	r, err := parseL72Result([]byte(`{"conn":1,"handshake":"error","error":"remote error: tls: bad certificate","resumed":false,"status":"none","flags":0,"after":"","closed_ms":0}` + "\n"))
	if err != nil || len(r) != 1 || r[0].Error != "remote error: tls: bad certificate" {
		t.Fatalf("%+v %v", r, err)
	}
}
```

Put `l72Cells`, `l72Cell` and `parseL72Result` in a file with no build tag,
`tests/lab/l72_cells.go`, so the unit test builds without `-tags lab`:

```go
package lab

import (
	"bufio"
	"bytes"
	"encoding/json"
)

// l72Result is one line of tacacs-tls-client's output.
type l72Result struct {
	Conn      int    `json:"conn"`
	Handshake string `json:"handshake"`
	Error     string `json:"error"`
	Resumed   bool   `json:"resumed"`
	Status    string `json:"status"`
	Flags     int    `json:"flags"`
	After     string `json:"after"`
	ClosedMS  int64  `json:"closed_ms"`
}

func parseL72Result(out []byte) ([]l72Result, error) {
	var rs []l72Result
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var r l72Result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return rs, sc.Err()
}

// l72Cell is one register cell: its letter, what it measures, and its run.
// run is set in l72_test.go (build tag lab); here it is only named.
type l72Cell struct {
	id, claim string
}

// l72Cells are spec §15 L72's cells, in its order.
var l72Cells = []l72Cell{
	{"a", "a TLS 1.3 PAP login with a seed token passes; every reply has the unencrypted flag; the record has device.transport and device.cert_sha256 and no key_ref"},
	{"b", "a TLS 1.2-only client: the alert and version_refused"},
	{"c", "no client certificate: the alert and no_client_certificate"},
	{"d", "a leaf from another CA: the alert and unknown_ca"},
	{"e", "an expired leaf: the alert and certificate_expired"},
	{"f", "a leaf naming another device: the alert and identity_mismatch"},
	{"g", "a leaf the CRL lists: the alert and certificate_revoked"},
	{"h", "a CRL source past nextUpdate and unreachable: status_unavailable, then a reset at Accept with no strike"},
	{"i", "a server name not in server_names: the alert and sni_mismatch"},
	{"j", "tickets on: the second connection resumes; one ticket presented twice resumes once"},
	{"k", "openssl -early_data with a port49 session: whether early data is sent"},
	{"l", "a packet with the unencrypted flag clear: an ERROR with the flag, then the close"},
	{"m", "a tcp device's address and an address not in the inventory on the TLS listener: no TLS byte before the reset; the records"},
	{"n", "a tls device's address on the RFC 8907 listener: a reset after its header; transport_mismatch"},
	{"o", "a TCP connection that sends nothing: closed at handshake_timeout; handshake_timeout"},
}
```

- [ ] **Step 3: Write the lab test**

Create `tests/lab/l72_test.go`:

```go
//go:build lab

package lab

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// l72Env is one port49d with both listeners, its PKI and its files, all
// under one temporary directory. Every secret it makes is random, held in
// memory, and registered for the leak check.
type l72Env struct {
	t        *testing.T
	dir      string
	bin       string // port49d
	clientBin string // tacacs-tls-client
	tcpPort  int
	tlsPort  int
	secrets  []string
	daemon   *exec.Cmd
	log      *bytes.Buffer // the decision log (port49d's stdout)
	stderr   *bytes.Buffer
	caFile   string
	certs    map[string][2]string // name -> cert file, key file
	seedFile string
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newL72Env(t *testing.T, crl string) *l72Env {
	t.Helper()
	e := &l72Env{t: t, dir: t.TempDir(), certs: map[string][2]string{}, log: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	e.bin = filepath.Join(e.dir, "port49d")
	e.clientBin = filepath.Join(e.dir, "tacacs-tls-client")
	for out, pkg := range map[string]string{e.bin: "./cmd/port49d", e.clientBin: "./tests/lab/cmd/tacacs-tls-client"} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("INVALID: build %s: %v\n%s", pkg, err, b)
		}
	}
	now := time.Now()
	ca, err := testpki.NewCA("L72 Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.NewCA("L72 Other CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.caFile = e.write("ca.pem", ca.PEM())
	issue := func(name string, from *testpki.CA, l testpki.Leaf) {
		if l.NotAfter.IsZero() {
			l.NotBefore, l.NotAfter = now.Add(-time.Minute), now.Add(time.Hour)
		}
		c, err := from.Issue(l)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		e.certs[name] = [2]string{e.write(name+".crt", cp), e.write(name+".key", kp)}
	}
	issue("server", ca, testpki.Leaf{DNSNames: []string{"tacacs.l72.example"}, IPs: testpki.Loopback()})
	issue("good", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true})
	issue("other_ca", other, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true})
	issue("expired", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true,
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)})
	issue("other_device", ca, testpki.Leaf{DNSNames: []string{"tls-other"}, Client: true})
	revokedSerial := big.NewInt(0x72)
	issue("revoked", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true, Serial: revokedSerial})
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: revokedSerial, RevocationTime: now.Add(-time.Minute)}}},
		ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	crlFile := e.write("l72.crl", crlDER)
	inv := e.write("inventory.yaml", []byte("devices:\n"+
		"  - {name: tls-dev, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n"+
		"  - {name: tcp-dev, platform: arista_eos, addresses: [127.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.2/32}, key_ref: l72}\n"))
	e.tcpPort, e.tlsPort = freePort(t), freePort(t)
	keyEnv, encEnv := randomHex(t, 16), randomHex(t, 16)
	e.secrets = append(e.secrets, keyEnv, encEnv)
	e.seedFile = filepath.Join(e.dir, "seeds.jsonl")
	status := "{crls: [{name: l72, file: " + crlFile + ", issuer_file: " + e.caFile + "}]}"
	if crl == "unreachable" {
		status = fmt.Sprintf("{crls: [{name: l72, url: \"http://127.0.0.1:%d/l72.crl\", issuer_file: %s}]}",
			freePort(t), e.caFile)
	}
	cfg := fmt.Sprintf(`listen: "127.0.0.1:%d"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
keys:
  l72:
    current: {version: 1, secret_env: L72_KEY}
encryption:
  current: {id: v1, secret_env: L72_ENC}
accounting: {spool_path: %s}
limits:
  # A strike's backoff and a decline's window start at 2s, so a cell's
  # second connection is inside it, and settle's 6s is past the 5s cap.
  malformed_backoff_base: 2s
lab:
  session_attributes: ["priv-lvl=15"]
  seed_token_file: %s
  seed_tokens: [{nas: tls-dev, username: alice}]
tls_listener:
  listen: "127.0.0.1:%d"
  cert_file: %s
  key_file: %s
  client_ca_file: %s
  server_names: [tacacs.l72.example]
  handshake_timeout: 2s
  session_ticket_lifetime: 10m
  state_dir: %s
  certificate_status: %s
`, e.tcpPort, inv, filepath.Join(e.dir, "acct.jsonl"), e.seedFile, e.tlsPort, e.certs["server"][0],
		e.certs["server"][1], e.caFile, e.mkdir("state"), status)
	cfgPath := e.write("port49d.yaml", []byte(cfg))
	e.daemon = exec.Command(e.bin, "-config", cfgPath)
	e.daemon.Env = append(os.Environ(), "L72_KEY="+keyEnv, "L72_ENC="+encEnv)
	e.daemon.Stdout, e.daemon.Stderr = e.log, e.stderr
	if err := e.daemon.Start(); err != nil {
		t.Fatalf("INVALID: start port49d: %v", err)
	}
	t.Cleanup(func() { e.daemon.Process.Kill(); e.daemon.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(e.stderr.String(), "RFC 9887 listener on") {
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: port49d did not start: %s", e.stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	seeds, err := labcreds.SeedTokens(e.seedFile)
	if err != nil {
		t.Fatalf("INVALID: seeds: %v", err)
	}
	secrets, err := labcreds.SecretsOf(seeds)
	if err != nil {
		t.Fatal(err)
	}
	e.secrets = append(e.secrets, secrets...)
	// The token goes to a 0600 file the client reads; it is never printed.
	e.write("token", []byte(secrets[0]))
	return e
}
```

Before writing `newL72Env`, check the shapes this code assumes against the real code. Then
match them:
- `labcreds.SeedToken` and `SecretsOf` (`tests/lab/labcreds/labcreds.go:89, :182`);
- port49d's config-path flag (`grep -n 'flag.String("config"' cmd/port49d/main.go`; use the
  flag the lab's `startDaemonWith` passes);
- whether a lab seed needs a policy. Plan 1's no-broker mode with `lab:` seeds is what
  `tests/lab/port49d-lab.yaml` runs, so copy its `lab:` block's other required keys.

Then add the helpers and the cells:

```go
func (e *l72Env) write(name string, b []byte) string {
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *l72Env) mkdir(name string) string {
	p := filepath.Join(e.dir, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// client runs tacacs-tls-client against port with args, as cert (a name in
// e.certs, or "" for none).
func (e *l72Env) client(port int, cert string, args ...string) []l72Result {
	e.t.Helper()
	base := []string{"-addr", fmt.Sprintf("127.0.0.1:%d", port), "-ca", e.caFile, "-server-name", "tacacs.l72.example",
		"-token-file", filepath.Join(e.dir, "token")}
	if cert != "" {
		base = append(base, "-cert", e.certs[cert][0], "-key", e.certs[cert][1])
	}
	out, err := exec.Command(e.clientBin, append(base, args...)...).Output()
	if err != nil {
		e.t.Fatalf("INVALID: tacacs-tls-client %v: %v", args, err)
	}
	rs, err := parseL72Result(out)
	if err != nil {
		e.t.Fatal(err)
	}
	return rs
}

// openssl runs openssl s_client against the TLS listener; stdin is sleep
// seconds of nothing, so the client reads what the server sends (a
// NewSessionTicket, an alert) before it quits.
func (e *l72Env) openssl(sleep int, args ...string) string {
	e.t.Helper()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("sleep %d | openssl s_client -connect 127.0.0.1:%d %s 2>&1",
		sleep, e.tlsPort, strings.Join(args, " ")))
	out, _ := cmd.CombinedOutput() // s_client exits non-zero on a refused handshake: the transcript is the result
	return string(out)
}

// records is the decision log so far, one line each, matching sub.
func (e *l72Env) records(sub string) []string {
	var out []string
	for _, l := range strings.Split(e.log.String(), "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}
```

Then `TestL72ReferenceClients`. It runs each cell in order. For each, it gathers an observation
string, checks it against the cell's expectation, and keeps `(id, claim, observation, ok)`. The
runs:

```go
func TestL72ReferenceClients(t *testing.T) {
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("INVALID: no openssl on PATH")
	}
	osslVersion, _ := exec.Command("openssl", "version").Output()
	e := newL72Env(t, "file")
	var got []l72Obs
	cell := func(id string, ok bool, format string, args ...any) {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatal(err)
		}
		got = append(got, l72Obs{id, fmt.Sprintf(format, args...), ok})
	}
	waitRec := func(sub string) []string {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if r := e.records(sub); len(r) > 0 {
				return r
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil
	}
	settle := func() { time.Sleep(6 * time.Second) } // past the default 5s malformed_backoff_max: each cell starts unstruck

	r := e.client(e.tlsPort, "good")
	red := waitRec(`"event":"redeem"`)
	cell("a", len(r) == 1 && r[0].Status == "pass" && r[0].Flags&1 == 1 && len(red) == 1 &&
		strings.Contains(red[0], `"transport":"tls"`) && strings.Contains(red[0], `"cert_sha256"`) && !strings.Contains(red[0], `"key_ref"`),
		"client: %+v; redeem record: %s", r, strings.Join(red, " "))

	for _, c := range []struct {
		id, cert, outcome string
		args             []string
	}{
		{"b", "good", "version_refused", []string{"-max-tls12"}},
		{"c", "", "no_client_certificate", nil},
		{"d", "other_ca", "unknown_ca", nil},
		{"e", "expired", "certificate_expired", nil},
		{"f", "other_device", "identity_mismatch", nil},
		{"g", "revoked", "certificate_revoked", nil},
		{"i", "good", "sni_mismatch", []string{"-server-name", "wrong.l72.example"}},
	} {
		settle()
		r := e.client(e.tlsPort, c.cert, c.args...)
		rec := waitRec(`"tls_outcome":"` + c.outcome + `"`)
		ossl := ""
		if c.id == "b" || c.id == "c" {
			settle() // the Go client's refusal struck 127.0.0.1; openssl starts unstruck
		}
		switch c.id {
		case "b":
			ossl = e.openssl(1, "-tls1_2", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile)
		case "c":
			ossl = e.openssl(1, "-tls1_3", "-CAfile", e.caFile, "-servername", "tacacs.l72.example")
		}
		e.write("openssl-"+c.id+".txt", []byte(ossl))
		cell(c.id, len(rec) > 0 && len(r) == 1 && r[0].Status == "none",
			"client: %+v; record: %s; openssl (evidence/L72-reference/openssl-%s.txt): %s", r, strings.Join(rec, " "),
			c.id, l72AlertLine(ossl))
	}
	// -server-name wrong.l72.example also fails the client's own check of
	// port49's certificate; the server's refusal at the ClientHello comes first,
	// and the record says which.

	settle()
	r = e.client(e.tlsPort, "good", "-count", "3", "-replay")
	cell("j", len(r) == 3 && !r[0].Resumed && r[1].Resumed && !r[2].Resumed && r[2].Handshake == "ok",
		"three connections offering the first ticket: resumed %v, %v, %v; statuses %s %s %s",
		r[0].Resumed, r[1].Resumed, r[2].Resumed, r[0].Status, r[1].Status, r[2].Status)

	sess := filepath.Join(e.dir, "sess.pem")
	e.write("early.bin", []byte("early data"))
	first := e.openssl(2, "-tls1_3", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile,
		"-servername", "tacacs.l72.example", "-sess_out", sess)
	second := e.openssl(2, "-tls1_3", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile,
		"-servername", "tacacs.l72.example", "-sess_in", sess, "-early_data", filepath.Join(e.dir, "early.bin"))
	e.write("openssl-k.txt", []byte(first+"\n----\n"+second))
	cell("k", strings.Contains(second, "Early data was not sent") || strings.Contains(second, "Early data was rejected"),
		"openssl's second run says: %s (evidence/L72-reference/openssl-k.txt)", l72EarlyLine(second))

	settle()
	r = e.client(e.tlsPort, "good", "-obfuscated")
	rec := waitRec(`"diagnosis":"obfuscated_over_tls"`)
	cell("l", len(r) == 1 && r[0].Status == "error" && r[0].Flags&1 == 1 && r[0].After == "eof" && len(rec) > 0,
		"client: %+v; record: %s", r, strings.Join(rec, " "))

	settle()
	tcpDev := e.client(e.tlsPort, "good", "-source", "127.0.0.2")
	unknown := e.client(e.tlsPort, "good", "-source", "127.0.0.3")
	mm, un := waitRec(`"diagnosis":"transport_mismatch"`), waitRec(`"diagnosis":"unadmitted_source"`)
	cell("m", len(tcpDev) == 1 && tcpDev[0].Handshake == "error" && len(unknown) == 1 && unknown[0].Handshake == "error" &&
		len(mm) > 0 && len(un) > 0,
		"tcp device: %+v; unknown address: %+v; records: %s | %s", tcpDev, unknown, strings.Join(mm, " "), strings.Join(un, " "))

	settle()
	before := len(e.records(`"diagnosis":"transport_mismatch"`))
	r = e.client(e.tcpPort, "", "-plain")
	time.Sleep(time.Second)
	after := e.records(`"diagnosis":"transport_mismatch"`)
	cell("n", len(r) == 1 && r[0].After == "reset" && len(after) == before+1,
		"client: %+v; the records: %s", r, strings.Join(after, " "))

	settle()
	r = e.client(e.tlsPort, "", "-silent")
	rec = waitRec(`"tls_outcome":"handshake_timeout"`)
	cell("o", len(r) == 1 && r[0].ClosedMS >= 1800 && r[0].ClosedMS <= 4000 && len(rec) > 0,
		"client: %+v (handshake_timeout 2s); record: %s", r, strings.Join(rec, " "))

	// (h) needs its own port49d: a CRL source that cannot be fetched and no kept list.
	e.daemon.Process.Kill()
	e.daemon.Wait()
	h := newL72Env(t, "unreachable")
	rs := h.client(h.tlsPort, "good", "-count", "2") // the second at once, inside the 2s decline window
	rec = func() []string { time.Sleep(time.Second); return h.records(`"tls_outcome":"status_unavailable"`) }()
	cell("h", len(rs) == 2 && rs[0].Status == "none" && rs[1].Handshake == "error" &&
		len(rec) == 1 && !strings.Contains(h.log.String(), `"tls_outcome":"handshake_failed"`),
		"first: %+v; second (inside the decline window): %+v; records: %s", rs[0], rs[1], strings.Join(rec, " "))

	l72Note(t, e, h, string(osslVersion), got)
}
```

Write each observation's check with the expectation the ruling states. Where the run disagrees,
the cell is recorded as observed, `ok` false. Never adjust an expectation to make a run pass;
Task 13 decides what a disagreement means.

`l72AlertLine(s)` returns the first line of an openssl transcript containing `alert`, or
`(no alert line)`. `l72EarlyLine(s)` returns the first line containing `Early data`, or
`(no early data line)`. Write both as small string scans in `l72_test.go`.

`l72Note` writes `tests/lab/results/L72-reference.md` and the evidence. Add it, `l72Obs` and the
two scans to `l72_test.go`:

```go
// l72Obs is one cell's observation, and whether it agrees with decision 50.
type l72Obs struct {
	id, observed string
	ok           bool
}

func l72AlertLine(s string) string { return l72FirstLine(s, "alert", "(no alert line)") }
func l72EarlyLine(s string) string { return l72FirstLine(s, "Early data", "(no early data line)") }

func l72FirstLine(s, sub, none string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(line)
		}
	}
	return none
}

// l72Note writes the evidence and the note, after checking that neither
// holds a secret, then fails the test if any cell disagreed.
func l72Note(t *testing.T, e, h *l72Env, osslVersion string, got []l72Obs) {
	t.Helper()
	files := map[string][]byte{"decisions.jsonl": e.log.Bytes(), "decisions-h.jsonl": h.log.Bytes()}
	matches, _ := filepath.Glob(filepath.Join(e.dir, "openssl-*.txt"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(m)] = b
	}
	claims := map[string]string{}
	for _, c := range l72Cells {
		claims[c.id] = c.claim
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# L72 — reference clients\n\n")
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** reference clients on the lab host, no device\n")
	fmt.Fprintf(&b, "- **Image version:** %s; Go %s (`tests/lab/cmd/tacacs-tls-client`)\n",
		strings.TrimSpace(osslVersion), runtime.Version())
	fmt.Fprintf(&b, "- **Capture:** tests/lab/evidence/L72-reference/\n")
	fmt.Fprintf(&b, "- **Run:** %s\n\n", runLine())
	fmt.Fprintf(&b, "## Claim\n\nspec §15 L72, cell by cell.\n\n## Observation\n\n")
	fmt.Fprintf(&b, "| cell | claim | observed | agrees with decision 50 |\n|---|---|---|---|\n")
	var disagree []string
	for _, o := range got {
		mark := "yes"
		if !o.ok {
			mark, disagree = "**no**", append(disagree, o.id)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", o.id, claims[o.id],
			strings.ReplaceAll(o.observed, "|", "\\|"), mark)
	}
	note := labcreds.RedactNote(b.String())
	secrets := append(append([]string{}, e.secrets...), h.secrets...)
	for name, body := range files {
		if hits := labcreds.Contains(body, secrets); len(hits) > 0 {
			t.Fatalf("INVALID: evidence %s holds a secret; nothing written", name)
		}
	}
	if hits := labcreds.Contains([]byte(note), secrets); len(hits) > 0 {
		t.Fatal("INVALID: the note holds a secret; nothing written")
	}
	evDir := filepath.Join(root, "tests", "lab", "evidence", "L72-reference")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(evDir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "tests", "lab", "results", "L72-reference.md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
	if len(disagree) > 0 {
		t.Fatalf("cells %v disagree with decision 50: the note records what was observed", disagree)
	}
}
```

`labcreds.Contains`'s exact signature is `tests/lab/labcreds/labcreds.go:288`; adapt the call to
its return type if it is not a slice.

- [ ] **Step 4: Check that it builds and the unit tests pass**

Run: `go build ./tests/lab/cmd/tacacs-tls-client/ && go vet -tags lab ./tests/lab/ && go test ./tests/lab/ -run 'TestL72' -v`
Expected: the build and vet are clean; `TestL72CellsAreTheRegistersCells` and
`TestL72ParsesTheClientsLine` PASS. The `lab`-tagged test is not run here; Task 13 runs it.

- [ ] **Step 5: The README section**

Append to `tests/lab/README.md`:

```markdown
## L72: the RFC 9887 listener against reference clients

`go test -tags lab ./tests/lab/ -run TestL72 -v -timeout 20m` on the lab host. It needs no
containerlab and no device: it builds port49d and `tests/lab/cmd/tacacs-tls-client`, makes a PKI in
a temporary directory, and starts port49d with both listeners on 127.0.0.1 (a `tls` device at
127.0.0.1, a `tcp` device at 127.0.0.2, nothing at 127.0.0.3). It needs `openssl` 3.x on `PATH`.
Every key, secret and token is random, held in memory or in a 0600 file under the test's
temporary directory, and checked out of the note and the evidence before either is written.
The note is `results/L72-reference.md`, and the evidence (decision log lines and openssl
transcripts) is `evidence/L72-reference/`. No device's RFC 9887 behaviour is measured here; that is
L73, open until an image carries a client (L71).
```

- [ ] **Step 6: Commit**

```bash
git add tests/lab/cmd/tacacs-tls-client tests/lab/l72_test.go tests/lab/l72_unit_test.go tests/lab/l72_cells.go tests/lab/README.md
git commit -m "test: the L72 harness, port49's RFC 9887 listener against reference clients

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 12: The image probe (L71)

**Files:**
- Create: `tests/lab/l71_test.go` (build tag `lab`)
- Create: `tests/lab/l71_unit_test.go` (no tag)
- Create: `tests/lab/l71_probes.go` (no tag)

**Interfaces:**
- Consumes: `lab`, `eachPlatform`, `withAdminCLI`, `eosCLI`, `iosxeCLI`, `nxosCLI`, `junosCLI`,
  `cliConn.in`, `cliConn.expect`, `negativeFinding`, `l.result`, `breakglassUser` and
  `breakglassPassword` (`tests/lab/harness_test.go`, `cli_test.go`).
- Produces: `tests/lab/results/L71-<platform>.md` per image.

- [ ] **Step 1: Write the probe table and its unit test**

Create `tests/lab/l71_probes.go`:

```go
package lab

import "strings"

// l71Probe is how one platform's CLI is asked whether it has an RFC 9887
// client: lines typed to reach the right mode, the help request typed
// without a newline (so nothing is configured), and the words that mean
// "yes" in the help it prints. cleanup leaves the mode with nothing
// committed.
type l71Probe struct {
	enter   []string
	ask     []string // each typed, then "?" with no newline, then Ctrl-U
	yes     []string
	cleanup []string
}

var l71Probes = map[string]l71Probe{
	"arista_eos": {enter: []string{"configure"}, ask: []string{"tacacs-server host 192.0.2.71 "},
		yes: []string{"ssl-profile", "tls"}, cleanup: []string{"end"}},
	"cisco_iosxe": {enter: []string{"configure terminal", "tacacs server l71probe"}, ask: []string{""},
		yes: []string{"tls"}, cleanup: []string{"exit", "no tacacs server l71probe", "end"}},
	"cisco_nxos": {enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 192.0.2.71 ", "tacacs-server "},
		yes: []string{"tls", "secure"}, cleanup: []string{"end"}},
	"juniper_vjunos-router": {enter: []string{"configure"}, ask: []string{"set system tacplus-server 192.0.2.71 "},
		yes: []string{"tls"}, cleanup: []string{"exit configuration-mode"}},
	"juniper_vsrx": {enter: []string{"configure"}, ask: []string{"set system tacplus-server 192.0.2.71 "},
		yes: []string{"tls"}, cleanup: []string{"exit configuration-mode"}},
}

// l71Says reports whether help, a CLI's answer to "?", lists one of yes as
// an option word: the first token of an indented help line, exactly.
func l71Says(help string, yes []string) (string, bool) {
	for _, line := range strings.Split(help, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, y := range yes {
			if f[0] == y {
				return strings.TrimSpace(line), true
			}
		}
	}
	return "", false
}
```

Create `tests/lab/l71_unit_test.go`:

```go
package lab

import "testing"

func TestL71ProbesEveryPlatform(t *testing.T) {
	for _, p := range []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_vjunos-router", "juniper_vsrx"} {
		if pr, ok := l71Probes[p]; !ok || len(pr.ask) == 0 || len(pr.yes) == 0 || len(pr.cleanup) == 0 {
			t.Errorf("%s: %+v", p, pr)
		}
	}
}

func TestL71SaysReadsOptionWordsOnly(t *testing.T) {
	help := "  key             Set key\n  port            TCP port\n  single-connection  Use one connection\n"
	if _, ok := l71Says(help, []string{"tls"}); ok {
		t.Fatal("no tls option, yet yes")
	}
	if line, ok := l71Says(help+"  tls             TLS settings\n", []string{"tls"}); !ok || line != "tls             TLS settings" {
		t.Fatalf("%q %v", line, ok)
	}
	if _, ok := l71Says("% Invalid input: tls is not a command\n", []string{"tls"}); ok {
		t.Fatal("an error line mentioning tls read as an option")
	}
}
```

- [ ] **Step 2: Run the unit tests**

Run: `go test ./tests/lab/ -run 'TestL71' -v`
Expected: PASS.

- [ ] **Step 3: Write the lab test**

Create `tests/lab/l71_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const l71Claim = "Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own " +
	"help with nothing configured or committed (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor " +
	"documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and an " +
	"unnamed Junos release; every lab image predates them."

func TestL71TLSClientSupport(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatal(err)
		}
		probe, ok := l71Probes[l.p.name]
		if !ok {
			t.Fatalf("no L71 probe for %s", l.p.name)
		}
		open := map[string]func(*lab) (*cliConn, error){
			"arista_eos":            func(l *lab) (*cliConn, error) { return l.eosCLI(breakglassUser, breakglassPassword) },
			"cisco_iosxe":           func(l *lab) (*cliConn, error) { return l.iosxeCLI(breakglassUser, breakglassPassword) },
			"cisco_nxos":            func(l *lab) (*cliConn, error) { return l.nxosCLI(breakglassUser, breakglassPassword) },
			"juniper_vjunos-router": func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) },
			"juniper_vsrx":          func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) },
		}[l.p.name]
		var obs strings.Builder
		l.withAdminCLI(t, open, func(c *cliConn) error {
			for _, line := range probe.enter {
				if _, err := c.sendExpect(line, 20*time.Second, c.prompt); err != nil {
					return fmt.Errorf("%q: %w", line, err)
				}
			}
			for _, ask := range probe.ask {
				from := len(c.transcript())
				if _, err := c.in.Write([]byte(ask + "?")); err != nil {
					return err
				}
				help, err := c.expectFrom(from, 20*time.Second, c.prompt)
				if _, werr := c.in.Write([]byte{0x15}); werr != nil { // Ctrl-U: the typed line is dropped, never entered
					return werr
				}
				if err != nil {
					return fmt.Errorf("help for %q: %w", ask, err)
				}
				if line, yes := l71Says(help, probe.yes); yes {
					fmt.Fprintf(&obs, "**Has a client.** Typed `%s?`; the help lists:\n\n```\n%s\n```\n\nFull help:\n\n```\n%s\n```\n\n",
						ask, line, strings.TrimRight(help, "\n"))
				} else {
					obs.WriteString(negativeFinding{Claim: fmt.Sprintf("the help for `%s?` lists none of %v, so this "+
						"image offers no RFC 9887 client there", ask, probe.yes),
						Sent: ask + "?", Got: help}.render(t))
					obs.WriteString("\n")
				}
			}
			for _, line := range probe.cleanup {
				if _, err := c.sendExpect(line, 20*time.Second, c.prompt); err != nil {
					return fmt.Errorf("cleanup %q: %w", line, err)
				}
			}
			return nil
		})
		l.result(t, "L71", l71Claim, obs.String())
	})
}
```

`c.prompt` is the idle prompt the CLI helpers learn. If a helper's prompt does not match
configuration mode (`(config)#`, `[edit]`), pass the platform's configuration prompt pattern to
`expect`. Read how `junos_viewcfg_test.go:525` and the EOS L16 tests wait in configuration
mode, and copy that wait. `sendExpect` and `expectFrom` are `cli_test.go:113` and `:84`.

- [ ] **Step 4: Check that it builds**

Run: `go vet -tags lab ./tests/lab/ && go test ./tests/lab/ -run TestL71 -v`
Expected: vet clean; the two unit tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/l71_test.go tests/lab/l71_unit_test.go tests/lab/l71_probes.go
git commit -m "test: the L71 probe, which lab images carry an RFC 9887 client

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 13: The lab runs: L72, then L71

**Files:**
- Create: `tests/lab/results/L72-reference.md`, `tests/lab/evidence/L72-reference/*` (written by
  the run)
- Create: `tests/lab/results/L71-<platform>.md`, five (written by the run)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 rows L71, L72; decision 50 where a
  result contradicts it)

**Interfaces:**
- Consumes: Tasks 11 and 12.
- Produces: closed L71 and L72, or the cells a run left open, said.

- [ ] **Step 1: Prepare the run**

On beehive, from the branch's head:

```bash
git -C ~/git/port49 worktree add --detach /tmp/port49-run-l7x HEAD
test ! -e /tmp/port49-STOP-LAB || { echo "STOP sentinel present: do not run"; exit 1; }
```

Start a background stall watchdog before each run, and re-arm it on every wake. It must
check that the test process's output file grew in the last 10 minutes, and say so if not. An
idle "waiting" proves nothing (the lab's standing rule).

- [ ] **Step 2: Run L72**

```bash
cd /tmp/port49-run-l7x && go test -tags lab ./tests/lab/ -run TestL72ReferenceClients -v -timeout 20m 2>&1 | tee /tmp/port49-run-l7x/l72.out
```

Expected: PASS, and `tests/lab/results/L72-reference.md` with every cell `agrees`. If the run is
INVALID (a setup fault: a build, openssl missing, port49d not starting), it writes no note: fix
the cause and run again. If a cell disagrees, the note is written and the test fails. Then read
the cell: the device-independent behaviour it measured is port49's own. Either the code is
wrong against decision 50 (fix the code in a `fix:` commit with a test, and run again), or the
ruling assumed what `crypto/tls` does not do. In the second case the doc is wrong (CLAUDE.md
rule 4): edit decision 50's ruling and the §10 text to what was measured, cite the note, and
say so in the commit.

- [ ] **Step 3: Run L71**

```bash
cd /tmp/port49-run-l7x && PORT49_LAB_PLATFORMS=eos,iosxe,nxos,vjunos,vsrx \
  go test -tags lab ./tests/lab/ -run TestL71TLSClientSupport -v -timeout 3h 2>&1 | tee /tmp/port49-run-l7x/l71.out
```

Expected: five notes, each a measured negative with its transcript (the vendor floors are
later than every image). If an image's help lists a client, its note says so. L73 can then be
measured on that image: stop here, report it, and do not close L73 in this plan.

- [ ] **Step 4: Bring the notes back and close the rows**

Copy `tests/lab/results/L71-*.md`, `L72-reference.md` and `tests/lab/evidence/L72-reference/` from
the run worktree into the branch. Then edit spec §15:
- L72's Status: `closed — measured <date>; tests/lab/results/L72-reference.md`, then one sentence
  per cell giving what was observed, as L69's row does.
- L71's Status: `closed — measured <date>; tests/lab/results/L71-*.md`, then the per-image
  answer. That closes it only if all five images were measured. A row with one image missing
  stays open and says which.

Run `git -C ~/git/port49 worktree remove /tmp/port49-run-l7x` only after copying. (L72 has no
raw pcap; its evidence is the copied files.)

- [ ] **Step 5: Commit**

```bash
git add tests/lab/results/L71-*.md tests/lab/results/L72-reference.md tests/lab/evidence/L72-reference docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L71 and L72

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 14: The roadmap's record and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status paragraph; "Plan 11"; "Plan 12"; "Plan 13")

**Interfaces:**
- Consumes: everything above.
- Produces: "Plan 11 — As built", and what plans 12 and 13 inherit.

- [ ] **Step 1: Write "Plan 11 — As built"**

Under "## Plan 11 — RFC 9887 TLS listener (§19 step 11)", replace its Status line with
`Status: **executed <date>** (\`2026-10-16-11-tls-listener.md\`, branch \`feature/tls-listener\`;
fourteen tasks; decision 50; L71 and L72 closed, L73 open)`. Then add "### Plan 11 — As built",
written as Plan 10's is, with these parts:
- what was built, by task, with the commit IDs;
- the rulings as recorded (decision 50), and any that a review or a lab result changed, with
  the reason;
- Ryan's answers to Q1 and Q2, or "pending";
- L71's and L72's results in a sentence each; L73 open;
- "Carried forward", the list in Step 2.

- [ ] **Step 2: Carry forward**

Add to "## Plan 12 — Deployment":

```markdown
**Carried from plan 11** (decision 50):
- The reference device AAA configuration for `transport: tls`, per platform, written from L73 once
  an image carries a client (plan 11 Q1): port (300; Cisco's documents default 6049), SNI, the
  client certificate's enrolment (subjectAltName as `device_identity` expects, clientAuth), and no
  non-TLS fallback server for the same host (RFC 9887 §5.1.1).
- Every deployment shape exposes `tls_listener.listen` (default 300) beside 49, with the source
  address preserved as for 49. Binding 300 needs what binding 49 does.
- Alarms: `rate(port49_tls_handshakes_total{outcome!~"ok|resumed"}[5m])` by outcome;
  `port49_tls_device_certificate_expiry_seconds < 7 * 86400`;
  `port49_tls_server_certificate_expiry_seconds < 14 * 86400`;
  `port49_cert_status_unavailable_total` increasing while TLS devices are admitted.
- The load test includes full TLS 1.3 handshakes per connection (tickets off, the default) at the
  §5 target rate. Whether tickets should default on is that number's to decide.
```

Add to "## Plan 13 — User and admin documentation", under **Inherits**: "From plan 11: an RFC
9887 page (the two listeners, `listen: none`, `tls_listener`'s keys, device identity by
inventory name or address, revocation, the 3am table, migrating a device from `tcp` to `tls`
with the window where a device lists both servers kept short (RFC 9887 §6.1), and the server
certificate's names: the DNS-ID or IP-ID devices are configured with, and any wildcard confined to
a subdomain only TACACS+ servers use (RFC 9887 §5.1.6)), and the `tls_outcome` vocabulary in the
reference."

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 11's record, and what plans 12 and 13 inherit from it

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **New listener.** `tls_listener:` in port49d.yaml serves TACACS+ over TLS 1.3 with mutual
  certificates (RFC 9887), on `:300` by default. `listen: none` turns the RFC 8907 listener
  off. One port49d may run both. The start says so in a notice, since RFC 9887 §5.1.1 does not
  recommend one host for both.
- **Device records.** `transport: tls` is now served. Such a device takes no shared key: key
  groups and a `key_ref` pin do not apply to it. Its certificate must chain to
  `tls_listener.client_ca_file` (stored issuing CAs in `intermediates_file`), carry clientAuth
  or no extended key usage, and name the device. It names it by a subjectAltName dNSName equal
  to its inventory name (or the name under `device_identity.dns_suffixes`), or by an iPAddress
  among its inventory addresses. Nothing per device is configured.
- **Revocation is required.** `tls_listener.certificate_status` has the broker's shape. Choose
  `crls`, `ocsp` or `disabled: true` explicitly. By default a status that cannot be established
  declines the device (it falls to its local method); `on_unavailable: allow` admits it and
  alarms.
- **Each device speaks one transport.** A device on the listener its record does not name is
  declined, `transport_mismatch`, with no strike: a `tls` device cannot be downgraded to 49.
- **Records.** An exchange over TLS carries `device.transport: "tls"` and `device.cert_sha256`, and
  no `key_ref`. TCP records are unchanged. A refusal is `unvalidated` with diagnosis
  `tls_refused` and a `tls_outcome`: `version_refused`, `no_client_certificate`, `unknown_ca`,
  `certificate_expired`, `certificate_invalid`, `certificate_revoked`, `status_unavailable`,
  `identity_mismatch`, `sni_mismatch`, `early_data_refused`, `handshake_timeout` or
  `handshake_failed`. Two new diagnoses are `transport_mismatch` and `obfuscated_over_tls`; one
  new inventory change is `transport_changed`.
- **Metrics.**
  - `port49_tls_handshakes_total{outcome}`;
  - `port49_tls_device_certificate_expiry_seconds`;
  - `port49_tls_server_certificate_expiry_seconds`;
  - `port49_devices_by_transport{transport}`;
  - `port49_connection_events_total` gains `tls_refused`, `transport_mismatch` and
    `obfuscated_over_tls`.
- **Lines.** A device certificate within `expiry_warning` (default 14 days) of expiry is named once
  a day. Each refusal is said at most once per device and outcome every 10 minutes. The
  listener's files reload every `reload_interval` (1m) and at SIGHUP, and a bad set keeps the old
  one and says why.
- **Resumption** is off by default (`session_ticket_lifetime: 0s`). When on, a ticket is single-use
  and bounded by the lifetime, and the certificate is verified again at every resumption.
- **Not built:** PSK and raw-public-key authentication (RFC 9887 MAYs), configurable TLS 1.3 cipher
  suites, and the TLS Cached Information Extension (none in Go's `crypto/tls`).
- **Devices:** vendor documentation puts clients in Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco
  NX-OS 10.6(1)F and Junos. No lab image has one (L71), and every device behaviour is unmeasured
  (L73). Cisco's documents configure port 6049, not 300. Point such a device at 300, or set
  `tls_listener.listen` to `:6049`.
