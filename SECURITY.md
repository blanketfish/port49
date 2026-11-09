# Security policy

port49 sits in the path of every login to the network devices it serves, so we treat a security
report as the most important kind of issue.

## Reporting a vulnerability

Please report it privately, not in a public issue, pull request or discussion. Use either:

- **GitHub's private vulnerability reporting:** on this repository's **Security** tab, choose
  **Report a vulnerability**.
- **Email:** `security@blanketfish.com`.

Include what you can of:

- the version or commit, and how port49 was deployed (systemd, container or Kubernetes);
- the component: port49d, the broker, the CLI, the Python client or the Ansible collection;
- the steps to reproduce, and what an attacker gains.

Never send a real credential, token, private key or device configuration. A redacted log, or a
fake value standing in for the secret, is enough.

We'll acknowledge your report and keep you informed as we work on it. Once a fix is released, we'll
credit you in the advisory, unless you'd rather we didn't.

## Supported versions

port49 is pre-release. Until the first beta, `v0.1.0`, fixes land on `main` only.
