# port49

port49 lets you sign in to network devices with your SSO or a certificate instead of a shared
TACACS+ password — no changes to the devices.

## Why port49

- **Nothing to steal.** Each login uses a short-lived, single-use token minted for one device.
  There's no shared password sitting in every config backup.
- **Identity on devices that will never support it.** People and machines sign in with a certificate
  or through your identity provider. The device needs no software or firmware change, only standard
  TACACS+ configuration.
- **Policy as reviewed code.** Authorization is a file in your repository, and `port49 policy diff`
  fails a change that widens access until a
  [test](https://blanketfish.github.io/port49/latest/admin/policy/#writing-tests) or a written acknowledgment
  accounts for it.
- **Built for a bad day.** Failure and break-glass behavior is measured in the lab, platform by
  platform, and each [device page](https://blanketfish.github.io/port49/latest/admin/devices/) says what
  was measured and what is still open.

## One login

```sh
port49 login --oidc                      # sign in once at your identity provider
port49 ssh <device>                      # a shell; the token never reaches your screen
port49 ssh <device> -- show version      # one command
```

`port49 login` prints the broker it logged in to and when the session ends.

## Status

Pre-release. The first beta will be `v0.1.0`. Until `1.0.0`, configuration may break between
releases, and each such change is called out in the release notes. See
[Versions](https://blanketfish.github.io/port49/latest/operate/versions/).

## Documentation

The site is at <https://blanketfish.github.io/port49/>. Deploy it with systemd, a container or Helm;
see the site. To contribute, start with [Contributing](docs/site/contributing/index.md).

## License

Apache-2.0; see [`LICENSE`](LICENSE).
