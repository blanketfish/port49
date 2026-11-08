# port49

A TACACS+ server that gives unmodified network devices certificate-based or OIDC-based identity,
with declarative policy.

## Why port49

- **Identity on devices that will never support it.** People and machines sign in with a certificate
  or through your identity provider, and the device sees ordinary TACACS+ and needs no change.
- **Nothing to steal.** A device login uses a short-lived, single-use token minted for one device,
  where a shared password would sit in every config backup.
- **Policy as reviewed code.** Authorization is a file in your repository, and `port49 policy diff`
  fails a change that widens access until a test or a written acknowledgment accounts for it.
- **Built for a bad day.** The failure behavior of each platform is measured in the lab, and the
  [qualified platforms](docs/qualified-platforms.md) list says which ones and what was measured.
- **Runs where you run things.** systemd, a container or Helm are peer ways to deploy it, and none
  is required.

## One login

```sh
port49 login --oidc
# port49: logged in to <broker>; the session ends at <time> (agent pid <pid>, log <path>)

port49 ssh <device>                      # a shell; the token never reaches your screen
port49 ssh <device> -- show version      # one command
port49 ssh --ttl 5m <device>             # ask for a shorter-lived token
```

## Status

Beta. The first beta will be `v0.1.0`; no release is tagged yet. Until `1.0.0`, configuration may break
between releases, and each such change is called out in the release notes. See
[Versions](https://blanketfish.github.io/port49/operate/versions/).

## Documentation

The site is at <https://blanketfish.github.io/port49/>. To contribute, start with
[Contributing](docs/site/contributing/index.md).

## License

Apache-2.0; see [`LICENSE`](LICENSE).
