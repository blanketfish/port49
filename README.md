# port49

Kubernetes-native TACACS+ server with certificate-based user identity and declarative policy.

> **Status: early design.** Nothing is implemented yet.
> See [`docs/design/`](docs/design/) for the current design work.

## What it is

port49 is a TACACS+ server (RFC 8907, with RFC 9887 TLS 1.3 support) that brings
certificate-based *user* identity to network devices that will never support
certificates themselves.

Engineers authenticate once with a certificate. Short-lived, single-use, device-bound
tokens are then minted transparently for each device login. The network device sees an
ordinary TACACS+ password exchange and needs no changes at all.

## Why

Existing TACACS+ implementations are mature and correct, but they were designed for a
different operational era: single-process daemons, bespoke configuration languages, and
shared secrets that in practice are never rotated. port49 targets three gaps:

- **Certificate identity for the user**, not just for the transport.
- **Declarative, reviewable authorization policy** instead of hand-maintained templates.
- **Horizontal, container-native scaling** with no local state.

## License

Apache-2.0 (design document §18); see [`LICENSE`](LICENSE).
