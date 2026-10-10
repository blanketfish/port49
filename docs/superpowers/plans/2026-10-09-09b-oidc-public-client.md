# Plan 9b: The OIDC Public Client — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the second part of design §19 step 9, "Agent in full": the agent's OpenID Connect
public client. A person logs in with `port49 login --oidc`, signs in at the identity provider the
broker lists, and the agent holds that session as plan 7h's broker expects it: the ID token as
each request's bearer, renewed silently with the provider's refresh token, and extended by a
fresh sign-in that answers the broker's refresh challenge. It is written into the spec first, and
measured on Keycloak and one device.

**Plan 9 is split four ways** (roadmap, "Plan 9"). This is 9b, plan 7h's hand-off.
- **9a** (merged, PR #44): sweeps by scope, the per-user config file, `port49 ssh`.
- **9c:** hardware-backed client keys and the broker certificate's CRL check.
- **9d:** host keys carried by inventory, and the Python and Ansible clients.

What 9b builds:

- **The sign-in (decision 43 rulings 1–6).** The authorization-code flow with PKCE, S256 only,
  over a loopback redirect on `127.0.0.1` and an ephemeral port (RFC 8252), with no client
  secret. It runs in the command's own process, `port49 login` or `port49 refresh`, never in the
  agent.
  - Every sign-in asks `prompt=login`, so a login is a fresh authentication, as the certificate
    path's handshake is.
  - `state`, the `nonce` and RFC 9207's `iss` are checked.
  - On a host with no display no browser is launched. The address is always printed, and on a
    terminal the address the browser ended on can be pasted back, so a person on a jump host
    signs in from their laptop's browser.
  - The device authorization grant is ruled out (ruling 5).
- **What the agent holds (rulings 7–11, 13).** The ID token and the refresh token, in the
  agent's memory alone, never on disk.
  - They reach the agent on an inherited pipe at login, and over its socket at a refresh.
  - The agent makes itself non-dumpable on Linux.
  - Every broker request carries the ID token as its bearer. It is renewed at three quarters of
    its own life, measured on the agent's clock from when it arrived, so a clock skewed from the
    provider's never refuses it. A renewal that moves `auth_time` is refused.
  - **The provider down:** the token works until its life ends, then `port49 token` says the
    provider did not renew it, when, and when the session ends, and never "log in again".
  - **`invalid_grant`:** the provider ended the session, and the agent ends too.
- **The refresh (ruling 12).** `port49 refresh`, and `port49 login` with an OIDC agent running,
  run three steps:
  - the agent asks the broker for its challenge;
  - the command signs in with that challenge as the `nonce`;
  - the agent sends the new ID token to `/v1/refresh`, and holds it only on a 200.
- **`/v1/config` (ruling 14).** Each `oidc` entry gains `max_token_age_seconds`, so the agent
  renews before the broker's `max_token_age` refuses a long-lived ID token.
- **The config file (ruling 15).** It gains `method`, `oidc_issuer`, `oidc_ca` and
  `oidc_redirect_port`.
- **Lab (ruling 18).** Two new rows:
  - **L55:** Keycloak as this client meets it. It covers which redirect registration admits an
    ephemeral loopback port, PKCE enforcement, the `iss` parameter, the refresh-token grant, and
    what the grant answers after a logout and at the provider's own session limits.
  - **L56:** the real CLI end to end on Keycloak and vEOS: login, silent renewal, refresh,
    logout, and the provider stopped and started.

**Architecture:**
- **`internal/oidc` (`client.go`, new file):** `ReadIDToken` and `ReadDiscovery`, the client's
  reading of an ID token and a discovery document, on the package's exact-name claim parser. The
  broker's verifier is untouched.
- **`internal/oidc/oidctest`:** `AuthServer`, an authorization server on the test issuer
  (`/authorize`, `/token` with PKCE and refresh-token rotation), and `Browser` and `Redirected`.
- **`internal/oidcclient` (new):** `Discover`, `Login`, `Renew`, `Skew`, `AuthorizationURL`;
  `Provider`, `Endpoints`, `Tokens`; `UnreachableError`, `ProviderError`, `ErrSessionEnded`.
- **`internal/broker/api`:** `OIDCProvider.MaxTokenAgeSeconds`. **`internal/broker`:**
  `config` fills it.
- **`internal/agent`:**
  - `Config.OIDC` and `OIDCConfig`. `oidc.go` holds the session: bearer, renewal loop, errors.
  - `Agent.OIDCChallenge` and `OIDCRefresh`; `Status.Method` and `OIDCIssuer`.
  - The socket's `POST /oidc/challenge` and `POST /oidc/refresh`, and the client's methods for
    them.
  - `RenewFailedError`, `ErrBrowserRequired`, `ErrNotOIDC`.
- **`internal/userconfig`:** the four new keys; `WithoutOIDCCA`.
- **`cmd/port49`:**
  - `oidc.go`: `loginOIDC`, `refreshOIDC`, `signIn`, `oidcHandoff`, `pickProvider`,
    `browserCommand`, `fetchBrokerConfig`;
  - `harden_linux.go`;
  - `sessionFlags`' new flags, and `brokerPool`, `oidcRoots`, `oidcConfig`, `startAgent` factored
    out of `config` and `login`;
  - `refreshCmd`'s OIDC branch.
- **`tests/lab`:** `l55_test.go`, `l56_test.go`, `l55_l56_unit_test.go`; `make lab-oidc` runs L55,
  and `make lab-oidc-agent` runs L56.

**Tech Stack:**
- Go 1.26, module `github.com/rhwendt/port49`, **no cgo**, and **no new module in the build
  graph**.
  - The standard library does the HTTP, the PKCE hash and the loopback listener.
  - `golang.org/x/term` (direct since 9a) reads the paste with echo off.
  - `golang.org/x/sys/unix` (direct) gives `Prctl`.
- Keycloak 26.4, digest-pinned in `tests/lab/oidc/compose.yaml` and `tests/lab/compose/oidc.yaml`
  (plan 7h).

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2 (the human OIDC row);
  - §5.6 (session lifetime, the OIDC refresh as built);
  - §12 (`port49 login`, `port49 refresh`);
  - §13: decision 17, decision 39 (rulings 4, 5, 15, 16, 18, 20), decision 42 ruling 6, and the
    new decision 43;
  - §15: L45, L46, L47, and the new L55 and L56.
- `docs/design/2026-08-21-port49-design.md`:
  - §7 ("The paths differ in what the agent holds");
  - §17 (Surface, Errors, Client libraries).
- The roadmap `docs/superpowers/plans/README.md`: "Plan 9" (9b's outline), "Plan 7h — As built"
  (its "Plan 9" carry), "Plan 9a — As built".
- House style: plan 9a (`2026-10-09-09a-sweeps-and-ssh.md`). This plan is written against `main`
  at `39e6004`.

**Prerequisite:** plan 9a merged (`main` at `39e6004`).

## Questions for Ryan

None. Each choice the roadmap leaves open is ruled below (R1–R8) on reasoning, and Task 1 writes
it into decision 43. None weakens a control: each is the stricter of the options. Ryan may
override any; R2 and R3 are the two he is likeliest to want to see.

## Rulings where the brief is open

- **R1. The tokens live in the agent's memory, never on disk** (the roadmap's open question;
  design §7 called it "a bearer on disk").
  - A file would let the session survive an agent restart. Against that, anyone who copies it
    holds the person's IdP session until the provider's own limit, days on some providers, from
    any host.
  - In memory, an agent that stops (a reboot, `kill`) ends the OIDC session, and `port49 login`
    signs in again. That is the certificate path's rule exactly: there a dropped connection is one
    more PIN.
  - With the provider down at 3am, a file would buy nothing. The refresh token cannot be used
    without the provider, and the ID token it renews lives minutes.
  - On Linux the agent sets itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`). No core file is
    written, and another process of the same user cannot `ptrace` it or read `/proc/<pid>/mem`,
    so the refresh token cannot be lifted out of a running agent. The socket still lets that user
    mint while the agent runs, as it always did. That is reach for the session's life, not the
    provider's.
- **R2. A browser-less host signs in by pasting the address back; the device authorization grant
  (RFC 8628) is not built** (the roadmap: "the device-code grant is not in decision 39, so 9b's
  spec task decides it").
  - **Why not the device grant:**
    - RFC 8628 has no `nonce`. A refresh must answer the broker's challenge in the ID token's
      `nonce` (decision 39 ruling 15), so a device-grant session could never be extended.
    - Its user code, typed into another device, is the phishing route RFC 8628 §5.4 warns of. An
      attacker starts a flow and talks a person into entering the code.
    - It is a grant the provider must enable per client.
  - **The paste:**
    - The command prints the authorization URL. The person opens it on any browser and signs in.
      The provider redirects that browser to `http://127.0.0.1:<port>/callback?code=…&state=…`,
      which fails to load on their laptop.
    - They paste that address at the prompt, with echo off. The code is bound to the PKCE verifier
      this process holds, so the address is useless anywhere else, and it is spent within the
      second.
    - It keeps every property of the loopback flow: PKCE, `state`, `nonce`, `prompt=login`, `iss`.
  - **3am, SSH'd into a bastion:** `port49 login --oidc` prints the URL and asks for the paste.
    No `ssh -L`, no second grant to enable.
- **R3. Every sign-in asks `prompt=login`, the login as well as the refresh.**
  - On the certificate path a login is a handshake, one use of the key. A login that reused an IdP
    SSO session from hours ago would start the port49 session with an old `auth_time`, a ceiling
    the person did not choose, and no proof anyone is at the keyboard now.
  - The cost is the provider's password, and its MFA, at each `port49 login`. That is the
    certificate path's PIN.
- **R4. The client does not verify the ID token's signature.**
  - OIDC Core §3.1.3.7 item 6 allows TLS validation of the token endpoint in its place. The broker
    verifies every request against the provider's keys (decision 39).
  - The client does check the shape and the claims that bind the token to this sign-in:
    - an algorithm decision 39 ruling 3 accepts;
    - `iss`, `aud` and `azp`;
    - `nonce`;
    - `sub` and `auth_time` present, and `iat` no later than `exp`.
  - A key-set client in the agent would be a second JWKS cache to age out, for no decision the
    agent makes.
- **R5. A new OIDC agent does not refresh at login.**
  - On the certificate path a new agent refreshes once, so live device sessions an earlier login
    left are extended. On the OIDC path a refresh is a second sign-in carrying the broker's
    challenge: a second password.
  - So the login prints nothing about it, and `port49 refresh` extends those sessions when the
    person chooses. A login with an OIDC agent already running is a refresh, as on the certificate
    path.
- **R6. `/v1/config` names `max_token_age_seconds` per OIDC provider** (decision 39 ruling 16,
  amended).
  - The broker refuses a token issued longer ago than `max_token_age` (2h) whatever its `exp`
    says. A provider issuing day-long ID tokens would otherwise see every mint refused at 2h,
    with nothing the agent could predict.
  - It is one integer of discovery data, never fleet data.
- **R7. Time on the client is measured from receipt.**
  - The agent renews at three quarters of the token's own life (`exp − iat`, capped by
    `max_token_age`), counted on its wall clock from when the token arrived. It never compares
    `exp` with its own clock.
  - A 401 `trust_domain_unresolved` on a request is answered once by renewing and sending again.
    That covers a laptop that slept past the token's end, and a clock the broker disagrees with.
  - The session's end is `received + max_session_age − (iat − auth_time)`.
  - A skew over 5 minutes between the token's `iat` and this host's clock is warned at login,
    never refused. The broker's clock judges.
- **R8. A renewal must keep `iss`, `sub` and `auth_time`** (OIDC Core §12.2).
  - A provider that moved `auth_time` on a refresh-token grant would silently extend the bearer's
    session clock (decision 39 ruling 9) with no authentication. So that token is refused, the
    held one is sent until its life ends, and the failure is said.
  - L46 measured that Keycloak keeps `auth_time`.

## What this plan does not do

- **No new reason code.** The decision log is untouched; every refusal the agent meets is one the
  broker already writes. `internal/decision/reasons.go` is unchanged.
- **No new broker API error code.** The agent's socket gains two of its own:
  - `503 identity_provider_unreachable`, beside 7d's `revocation_running`;
  - `409 browser_required`.
  
  They go in design §17's error list as the socket's, not the broker's.
- **No new broker endpoint.** `/v1/config` gains one field.
- **No new metric.** The agent has none.
- **No change to the broker's verifier, logout or refresh.** 7h built them. 9b is their client.
- **No device authorization grant (R2), no token on disk (R1), and no hardware key (9c).**
- **No hosted provider.** L47 (Entra ID, Okta) stays open and unassigned. The operator notes say
  "measured on Keycloak".
- **No claim about Keycloak before L55 closes:** which redirect registration admits an
  ephemeral port, whether it enforces PKCE, what its refresh grant answers after a logout or at
  its session limits.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **`port49 login --oidc` on a desktop** (Task 7, `TestLoginOIDCStartsAnAgentThatMints`):

  ```
  port49: sign in at https://kc.example.com/realms/corp in the browser that opened; if none did, open this address:
    https://kc.example.com/realms/corp/protocol/openid-connect/auth?client_id=port49-cli&code_challenge=…&prompt=login&…
  port49: logged in to https://port49-broker.example.com:8443 through https://kc.example.com/realms/corp; the session ends at 2026-10-09T21:00:00Z (agent pid 4242, log /run/user/1000/port49/agent.log)
  ```
- **On a jump host with no display** (Task 7, `TestLoginOIDCWithAPastedAddress`):

  ```
  port49: open this address in a browser and sign in at https://kc.example.com/realms/corp:
    https://kc.example.com/realms/corp/protocol/openid-connect/auth?…
  port49: waiting up to 5m0s. If the browser ends on a page that cannot be reached (it runs on another host), copy that page's address and paste it here (it is not shown), then press Enter:
  ```

  A pasted address that is not the sign-in's (Task 4, `TestAPastedAddressCompletesTheSignIn`):

  ```
  port49: that is not the address the sign-in was sent back to (http://127.0.0.1:43117/callback?…); paste the address again:
  ```
- **The provider down, past the ID token's life** (Task 5, `TestAProviderOutageEndsNothing`),
  exit 1, the agent still running:

  ```
  port49 token: your identity provider at https://kc.example.com/realms/corp did not renew your ID token (your identity provider at https://kc.example.com/realms/corp did not answer: Post "https://kc.example.com/realms/corp/protocol/openid-connect/token": dial tcp 10.0.0.5:443: connect: connection refused); it ended at 2026-10-09T03:05:00Z, so nothing was sent to the broker; the agent tries again every 30s, and your session lasts until 2026-10-09T15:00:00Z; run the command again once the provider answers
  ```
- **The provider ended the session** (Task 5, `TestInvalidGrantEndsTheSession`), exit 1, the
  agent gone:

  ```
  port49 token: the session is over; run `port49 login`: your identity provider no longer renews this session: it was signed out, or reached the provider's own session limit (invalid_grant: Session not active)
  ```
- **A back-channel logout** (Task 5, `TestALogoutEndsTheOIDCSessionWithTheBrokersWords`). The
  broker's own words, plan 7h's:

  ```
  port49 token: the session is over: your identity provider ended your sessions at 2026-10-09T03:00:00Z (back-channel logout); log in again from 2026-10-09T03:01:01Z
  ```
- **`port49 refresh` on the OIDC path** (Task 7, `TestAnOIDCRefreshSignsInAgainAndExtends`). It
  prints the sign-in lines, then plan 7b's per-device lines:

  ```
  refreshed at 2026-10-09T20:52:00Z; this login lasts until 2026-10-10T08:52:00Z
    leaf1 (alice)  extended to 2026-10-10T08:52:00Z
  ```

  A provider that did not ask the password again (Task 7,
  `TestAProviderThatIgnoresPromptLoginIsRefreshNotFresh`), exit 1:

  ```
  port49 refresh: the broker refused the refresh: your identity provider did not authenticate you again (prompt=login was not honoured); the session was not extended (refresh_not_fresh)
  ```
- **A provider that issues no refresh token** (Task 7, `TestLoginWithoutARefreshTokenSaysWhen`),
  on stderr, and the login succeeds:

  ```
  port49 login: https://kc.example.com/realms/corp issued no refresh token, so this session ends with the ID token, at 2026-10-09T03:05:00Z; ask its administrator to allow refresh tokens for client port49-cli (some providers issue one only for the offline_access scope, which the broker's verifier then lists in scopes)
  ```

## Operator notes

These are for the PR body and plan 13's operator guide. Plan 13 owns the guide. Every line is
pinned by a test or a lab row. A line in *italics* rests on an open lab row and is restated
when it closes.

- **`port49 login --oidc` signs in at the identity provider your broker lists.** With `method:
  oidc` in `~/.config/port49/config.yaml`, plain `port49 login` does the same.
  - It needs `broker` and `broker_ca`, as a certificate login does, and no certificate.
  - With several providers listed, name one with `--issuer` or `oidc_issuer`.
  - A provider whose TLS certificate a private CA issued needs `oidc_ca` or `--oidc-ca`. Without
    one the system's roots are trusted.
- **Register port49 at your provider as a public client:** no secret, the authorization-code
  flow, PKCE with S256 required. Its client id is the broker verifier's `client_id`.
  - *Its redirect URI: port49 listens on `http://127.0.0.1:<port>/callback`, on a free port each
    time (RFC 8252). Which registration admits that on Keycloak is L55's; until it closes,
    register `http://127.0.0.1:<fixed>/callback` and set `oidc_redirect_port: <fixed>`.*
  - Ask for the claim the broker maps (`email`, say) in the verifier's `scopes`: port49 asks for
    exactly those.
- **Every login and every refresh asks for your password** (and your MFA) at the provider. A login
  is a fresh authentication, as a certificate login is a use of the key.
- **On a host with no browser** (a jump host over SSH), port49 prints the address. Open it in your
  laptop's browser and sign in. The browser then fails to load a `127.0.0.1` page: copy that
  page's address and paste it at port49's prompt. It is not shown, and it is useless anywhere but
  this one sign-in. `--no-browser` prints the address without trying to open a browser.
- **Nothing is written to disk.** The agent holds the session in memory. When the agent stops, a
  reboot say, `port49 login` signs in again. On Linux the agent is non-dumpable, so no process of
  yours can read the session out of it.
- **The ID token is renewed in the background** with the provider's refresh token, within its
  lifetime, with no browser.
  - *If your provider ends sessions sooner than `session.max_session_age_default` (12h), port49's
    session ends there with "your identity provider no longer renews this session". On Keycloak
    that limit is "SSO Session Max"; whether a `port49 refresh` restarts it is L55's.*
  - Set the provider's limit at or above the broker's.
- **When your provider is down,** `port49 token` keeps working until the ID token's lifetime ends
  (on Keycloak, the realm's Access Token Lifespan).
  - Then it says the provider did not renew the token, when the token ended and when your session
    ends. It never says to log in again: the agent keeps trying every 30s and resumes on its own.
  - Open device sessions go on. Certificate logins and break-glass are not affected.
- **`port49 refresh`** extends your live device sessions after a fresh sign-in, as on the
  certificate path. A login while an OIDC agent runs does the same. A *new* agent does not extend
  sessions an earlier login left: run `port49 refresh` for those.
- **A back-channel logout ends the agent.** `port49 token` prints the broker's words, with the
  time from which a new login is taken.
- **An egress proxy.** `HTTPS_PROXY` is honoured for the provider and never for the broker.
- **Clocks.** port49's client never refuses a token by its own clock. A host more than 5 minutes
  from the provider's clock is warned at login, since the broker judges every token by its own.

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module in the build graph**: `go.mod` and `go.sum` are unchanged.
- snake_case everywhere it is data: `max_token_age_seconds`, `method`, `oidc_issuer`, `oidc_ca`,
  `oidc_redirect_port`, `oidc_issuer` on `/status`, `id_token`, `refresh_token`, `received_at`,
  `authorization_endpoint`, `token_endpoint`, `iss_parameter`, `ca_pem`, `redirect_port`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan adds
  none.**
- **No token, code, verifier, refresh token or broker challenge is logged or printed.**
  - The authorization URL is printed on the operator's terminal and passed to the browser
    launcher. It carries `state`, the `nonce` (a refresh's challenge) and the `code_challenge`.
    The browser must carry all three to the provider (decision 39 ruling 15), and none signs
    anyone in: PKCE binds the code to the verifier this process holds (RFC 7636 §1).
  - The agent never sees that URL, and its log holds none of these values.
  - The tokens reach the agent on an inherited pipe or its 0600 socket, never argv or the
    environment.
  - Every test that runs a sign-in asserts that stdout, stderr and the agent's log hold none of
    `AuthServer.Issued()` (`credentialsNowhere`).
  - `Tokens`, `OIDCSignIn`, `OIDCRefreshRequest` and `oidcHandoff` withhold their secrets in
    `String` and `GoString`.
  - An error names the provider and its OAuth error code, never a body.
- No device identity and no principal in a metric label. No metric is added.
- **Fail closed, never widen.** Each of these is a refusal:
  - a callback whose `iss` names another issuer;
  - a callback with no `iss` from a provider that promised one;
  - a provider that offers PKCE methods without S256;
  - an ID token whose `nonce`, `iss`, `aud` or `azp` is not this sign-in's;
  - a renewal that moves `auth_time` or names another `sub`;
  - a refresh signed in as another user;
  - an `oidc_ca` others can write.
- **The lab register rules** (CLAUDE.md 1–4). Task 1 opens L55 and L56, and Task 8 measures
  them. Until L55 closes, no doc says which redirect registration Keycloak accepts, that it
  enforces PKCE, or what its refresh grant answers at its limits.
- Verify with `make test && make vet`, and `make test-race` on every touched package, and report
  the real output.
- Conventional Commits, on branch `feature/oidc-public-client`. Commit messages end with:

  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```
- Implementers never run `git checkout`, `restore`, `reset`, `stash` or `clean`.

## Review Focus

The five inputs or conditions most likely to bite a person, and the test that pins each:

1. **The identity provider is down at 3am, with an agent running.**
   - **Expected:** `port49 token` mints with the held ID token until its usable life ends. Then
     it exits 1 saying the provider did not renew the token, when it ended and when the session
     ends, and never "log in again". The agent keeps running and renews on its own once the
     provider answers, with no login.
   - **Pinned by** Task 5's `TestAProviderOutageEndsNothing` (before the end, at the end, after
     recovery) and Task 8's L56 cell 6 on a stopped Keycloak.
2. **A browser-less shell** (SSH to a jump host, WSL with no display).
   - **Expected:** no browser is launched without a display. The address is printed, and a pasted
     address completes the sign-in. A paste that is not this sign-in's is refused, saying why, and
     asked again. The terminal's echo is restored however the sign-in ends.
   - **Pinned by** Task 4's `TestAPastedAddressCompletesTheSignIn`, Task 7's
     `TestBrowserCommand` and `TestLoginOIDCWithAPastedAddress`.
3. **A forged answer on the loopback port** (another local user, or a provider mix-up).
   - **Expected:** a callback with another `state` is answered 400 and waited past. One naming
     another `iss` ends the sign-in with a refusal. A code is never exchanged without this
     process's verifier.
   - **Pinned by** Task 4's `TestACallbackWithAnotherStateIsIgnored` and
     `TestAnIssParameterNamingAnotherIssuerIsRefused`, and Task 2's
     `TestTheTokenEndpointRefusesAWrongVerifier`.
4. **A provider that misbehaves on renewal.** It moves `auth_time`, names another `sub`, sends no
   ID token, or answers `invalid_grant`.
   - **Expected:** the first three are refused, the held token is kept until its life ends, and
     the failure is said. `invalid_grant` ends the session with "run `port49 login`".
   - **Pinned by** Task 3's `TestARenewalThatMovesAuthTimeIsRefused` and
     `TestARenewalNamingAnotherSubIsRefused`, and Task 5's `TestARenewalThatMovesAuthTimeIsNotUsed`
     and `TestInvalidGrantEndsTheSession`.
5. **Time.** A laptop suspended past the token's end, or a host clock minutes off the provider's.
   - **Expected:** the client refuses nothing by its own clock. A broker 401
     `trust_domain_unresolved` on an aged-out token is answered by one renewal and one resend,
     and the session goes on. A skew over 5 minutes is warned at login.
   - **Pinned by** Task 5's `TestATokenAgedOutUnderSleepIsRenewedAndSentAgain` and
     `TestTheUsableLifeIsCountedFromReceipt`, and Task 7's `TestASkewedClockIsWarnedNotRefused`.

## Conflict scan: where tasks share a file or an interface

- **`internal/oidc`:** Task 3 adds `client.go`. **`internal/oidc/oidctest`:** Task 2 adds
  `authserver.go` and edits `issuer.go` (`NewIssuer`'s mux and discovery).
- **`internal/broker/api/api.go` and `internal/broker/broker.go`:** Task 2 alone (one field).
- **`internal/oidcclient`:** Task 3 creates it (`oidcclient.go`). Task 4 adds `login.go`.
- **`internal/agent`:**
  - Task 5 creates `oidc.go` and `oidc_test.go`, and edits `agent.go` (`Config`, `New`,
    `Connect`, `doOn`, `post`, `exchange`, `over`, `Status`, `Handler`, `answer`) and `socket.go`
    (`Token`, `roundTrip`).
  - Task 6 adds `oidcrefresh.go` and `oidcrefresh_test.go`, and edits `agent.go` (`Refresh`,
    `Handler`, `answer`) and `socket.go` (`Refresh`, `roundTrip`, two methods).
- **`internal/userconfig`:** Task 7 alone.
- **`cmd/port49`:** Task 7 alone. It edits `main.go`, `refresh.go` and `main_test.go`
  (`newLabBroker` becomes `newLabBrokerWith`), and creates `oidc.go`, `harden_linux.go`,
  `harden_other.go`, `oidc_test.go` and `oidc_login_linux_test.go`.
- **The spec and the design:** Task 1 writes them. Task 8 closes L55 and L56 and fixes any text
  their results contradict.
- **`tests/lab/`, `Makefile` and `tests/lab/README.md`:** Task 8 alone.

Task 2 needs Task 1. Tasks 3 and 4 run in order after 2. Task 5 needs 4. Task 6 needs 5. Task 7
needs 6. Task 8 needs 1–7. Task 9 is last.

## File Structure

**Create:**
- `internal/oidc/client.go`, `internal/oidc/client_test.go`.
- `internal/oidc/oidctest/authserver.go`, `internal/oidc/oidctest/authserver_test.go`.
- `internal/oidcclient/oidcclient.go`, `oidcclient_test.go`, `login.go`, `login_test.go`.
- `internal/agent/oidc.go`, `oidc_test.go`, `oidcrefresh.go`, `oidcrefresh_test.go`.
- `cmd/port49/oidc.go`, `oidc_test.go`, `oidc_login_linux_test.go`, `harden_linux.go`,
  `harden_other.go`.
- `tests/lab/l55_test.go`, `tests/lab/l56_test.go`, `tests/lab/l55_l56_unit_test.go`.
- `tests/lab/results/L55-keycloak.md` and `tests/lab/results/L56-arista_eos.md`, written by the
  run, with their evidence.

**Modify:**
- `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md` (Task
  1; Task 8 closes L55 and L56).
- `internal/oidc/oidctest/issuer.go` (Task 2).
- `internal/broker/api/api.go`, `internal/broker/broker.go`, `internal/broker/oidcserver_test.go`
  (Task 2).
- `internal/agent/agent.go`, `internal/agent/socket.go` (Tasks 5, 6).
- `internal/userconfig/userconfig.go`, `userconfig_test.go` (Task 7).
- `cmd/port49/main.go`, `refresh.go`, `main_test.go`, `config_test.go` (Task 7).
- `Makefile` (`lab-oidc`, `lab-oidc-agent`) and `tests/lab/README.md` (Task 8).
- `docs/superpowers/plans/README.md` (Task 9).

---

### Task 1: The spec says what plan 9b builds: decision 43, §5.6, §12, L55 and L56

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.6 (after the OIDC refresh as built);
  - §12 (`port49 refresh`, `port49 login`);
  - §13: decision 39 ruling 16, decision 42 ruling 6, and decision 43 (new);
  - §15 (L55, L56).
- Modify: `docs/design/2026-08-21-port49-design.md`: §7 (the OIDC path's session), §17 (Errors,
  Client libraries).

**Interfaces:**
- Consumes: rulings R1–R8 above.
- Produces: decision 43, rulings 1–18, which every later task cites; L55 and L56, which Task 8
  measures.

This task is docs only. Each step is an edit with the exact text. Where a step says "replace", the
old text is quoted and appears once; check with `grep -n` before editing.

- [ ] **Step 1: Decision 43, after decision 42**

Find the end of decision 42 with `grep -n "address for the one connection (Task 7)\.$"
docs/design/2026-08-23-policy-engine-spec.md`. That line ends decision 42; a blank line and `---`
follow it. Between that line and the blank line, insert a blank line and:

```markdown
**43. The agent in full, second part: the OIDC public client.** *Plan 9b, 2026-10-09.* Rulings
rest on reasoning unless they say data. The plan's rulings R1–R8 were ruled by the controller on
recommendation; Ryan may override any. Rulings 4, 9 and 10 are provisional on L55 (Keycloak) and
L47 (hosted providers, open).

- **1. The flow** (data: RFC 6749 §4.1, RFC 7636, RFC 8252, OIDC Core §3.1).
  - **What it is.** The authorization-code flow with PKCE, `S256` only, as a public client with no
    client secret.
  - **Where it runs.** `port49 login --oidc` and `port49 refresh` run it in their own process,
    never in the agent, which never listens on a TCP port.
  - **The provider's PKCE.** A provider whose discovery lists `code_challenge_methods_supported`
    without `S256` is refused. One that lists none is used, with `S256` sent; whether Keycloak
    enforces it is L55's.
  - Tasks 3 and 4.
- **2. The provider** (data: OIDC Discovery §4).
  - **Which one.** The one `/v1/config`'s `oidc` lists, or the one `--issuer` or `oidc_issuer`
    names exactly. None listed is "this broker takes no OIDC login". Several and none named is a
    refusal that lists them.
  - **Its discovery document.** `issuer` must equal the configured issuer. `authorization_endpoint`
    and `token_endpoint` must be `https` URLs with a host and no credentials. Each member is read
    by its exact name.
  - **Reaching it.** No redirect is followed. `HTTPS_PROXY` is honoured, as the broker's key
    fetch honours it (decision 39 ruling 4). TLS is against `oidc_ca`, else the system's roots.
  - Tasks 3 and 7.
- **3. The request.** It carries:
  - `response_type=code`, `client_id`, and `redirect_uri`;
  - `scope`: the verifier's scopes, `openid` first;
  - `state`: 32 random bytes;
  - `nonce`: 32 random bytes at a login, the broker's challenge at a refresh;
  - `code_challenge`: S256 of a 32-byte verifier;
  - `prompt=login`, at a login as at a refresh. A login is a fresh authentication, as the
    certificate path's handshake is, so the session clock starts there.

  Task 4.
- **4. The redirect** (data: RFC 8252 §7.3, RFC 9207; provisional on L55).
  - **The listener.** `http://127.0.0.1:<port>/callback`, on a listener bound to `127.0.0.1`
    alone. The port is ephemeral, or `oidc_redirect_port` for a provider that registers one. It
    answers `GET /callback` and nothing else.
  - **Another `state`.** An answer that does not carry this sign-in's `state` is answered 400 and
    waited past: anyone on the host can reach the port.
  - **This sign-in's answer.** The first answer carrying the `state` ends the wait. Its `iss`, when
    present, must be the issuer, and is required when discovery says the provider sends it. An
    `error` ends the sign-in with the provider's code.
  - **The page.** It holds no token, with `Cache-Control: no-store` and `Referrer-Policy:
    no-referrer`.
  - **The wait.** 5 minutes, the life of a refresh challenge (decision 39 ruling 15).
  - Task 4.
- **5. No browser.**
  - **When one is launched.** `$BROWSER` when set. On Linux, `xdg-open` only with `DISPLAY` or
    `WAYLAND_DISPLAY` set. On macOS, `open` outside an SSH session. `--no-browser` launches none.
    The authorization URL is always printed on stderr.
  - **The paste.** When stdin is a terminal, the address the browser ended on may be pasted back,
    and is not echoed. A browser on another host cannot reach `127.0.0.1`, but its address bar
    holds the answer.
  - **No device grant.** The device authorization grant (RFC 8628) is not built:
    - it carries no `nonce`, so a session it starts could never answer ruling 15's refresh
      challenge;
    - its user code is a phishing route (RFC 8628 §5.4);
    - a provider must enable it per client.
  - Tasks 4 and 7.
- **6. The exchange and the ID token** (data: OIDC Core §3.1.3.7).
  - **The exchange.** The token endpoint, form-encoded, with `code_verifier` and no secret.
  - **What the client reads of the ID token:**
    - a compact JWS whose `alg` is one decision 39 ruling 3 accepts;
    - `iss` exact;
    - `aud` naming `client_id`, and `azp` as decision 39 ruling 2 reads it;
    - `nonce` equal to the request's;
    - `sub`, `iat`, `exp` and `auth_time` present, and `iat` no later than `exp`;
    - every claim by its exact name.
  - **No signature check here.** It came from the token endpoint over TLS (item 6), and the
    broker verifies every request.
  - **No clock here.** The client never refuses a token by its own clock. A skew over 5 minutes
    between `iat` and this host's clock is warned at login.
  - Tasks 3 and 7.
- **7. What the agent holds** (design §7).
  - **Where.** The ID token and the refresh token, in the agent's memory, never on disk. They come
    from the login on an inherited pipe, never argv or the environment, and from `port49 refresh`
    over the agent's 0600 socket.
  - **Non-dumpable.** On Linux the agent sets itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`):
    no core file, and no process of the same user reads its memory or traces it.
  - **An agent that stops ends the OIDC session,** as a dropped connection ends the certificate
    path's.
  - Tasks 5 and 7.
- **8. The bearer.**
  - **Each request.** Every broker request carries `Authorization: Bearer` with the held ID token,
    and no client certificate. Each request is a connection, since the broker closes a
    certificate-less one when idle.
  - **A refused token.** A 401 `trust_domain_unresolved` is answered once by renewing and sending
    the same request again. A second refusal ends the session.
  - Task 5.
- **9. Silent renewal** (data: RFC 6749 §6, OIDC Core §12.2; measured on Keycloak, L46;
  provisional on L55).
  - **The grant.** The refresh-token grant, with the sign-in's scope.
  - **When.** At three quarters of the token's usable life: `exp − iat`, capped by `/v1/config`'s
    `max_token_age_seconds`, counted on this host's wall clock from when the token arrived, never
    by reading `exp` against it. And before a request within 15s of the usable life's end.
  - **What a renewed token must keep.** The held `iss`, `sub` and `auth_time`. One that moves
    `auth_time` is refused: it would extend the bearer's session clock (decision 39 ruling 9) with
    no authentication. A renewal never extends the ceiling.
  - **A rotated refresh token** replaces the held one.
  - Tasks 3 and 5.
- **10. The provider unreachable, or ending the session** (provisional on L55).
  - **A failed renewal.** One that fails any way but `invalid_grant` leaves the held token in use
    until its usable life ends, and is tried every 30s. Then each call is answered, on the agent's
    socket, `503 identity_provider_unreachable`. It names the provider, when the token ended and
    when the session ends, and never says to log in again.
  - **`invalid_grant`.** The provider ended the session (a sign-out, its own session limit), and
    the agent ends: run `port49 login`.
  - **No refresh token.** Without one, the session ends with the ID token, said at login.
  - Task 5.
- **11. The broker's answers on the OIDC path.**
  - `503 identity_provider_unavailable` ends nothing and is said with its Retry-After.
  - `401 credential_revoked` ends the session in the broker's words: a back-channel logout says
    when a new login is taken, a mark who lifts it.
  - `401 session_expired`, `identity_unmapped`, and a second `trust_domain_unresolved` end it.
  - Task 5.
- **12. The refresh** (decision 39 ruling 15).
  - **Who runs it.** `port49 refresh`, and `port49 login` while an OIDC agent runs for the same
    broker and provider.
  - **The steps.** The agent asks the broker for a challenge with its bearer, and hands it to the
    command with the provider's sign-in parameters. The command signs in with the challenge as the
    `nonce`. The agent checks the new ID token names the held `iss` and `sub`, and sends `POST
    /v1/refresh` with it as the bearer.
  - **The outcome.** On a 200 the agent holds the new tokens and the session's end moves.
    Otherwise it holds the old ones, and a refusal of the new token ends nothing.
  - **A new agent.** A new OIDC agent does not refresh at login, since that would be a second
    sign-in. `port49 refresh` extends live device sessions an earlier login left.
  - Tasks 6 and 7.
- **13. The session's end.** `max_session_age` after the ID token's `auth_time`, reckoned from
  receipt: `received + max_session_age − (iat − auth_time)`. Without a refresh token, the token's
  usable life ends it sooner. After a refresh, the broker's `session_ends_at`. Task 5.
- **14. `/v1/config`.** Each `oidc` entry carries `max_token_age_seconds`, the broker's
  `max_token_age` (decision 39 ruling 5); 0 or absent from an older broker means `exp` alone.
  Task 2.
- **15. The config file and the flags** (amends decision 42 ruling 6).
  - **The file.** `config.yaml` gains:
    - `method`: `x509` (the default) or `oidc`;
    - `oidc_issuer`;
    - `oidc_ca`, a path held to ruling 6's ownership rule as `broker_ca` is, and read once;
    - `oidc_redirect_port`.
  - **The flags.** `port49 login` takes `--oidc`, `--issuer`, `--oidc-ca`, `--redirect-port` and
    `--no-browser`, each overriding its key. `--cert` or `--key` on the command line makes it a
    certificate login, and beside `--oidc` it is a usage error.
  - **`broker_ca`** stays required: it is the broker's TLS, on either path.
  - Task 7.
- **16. The agent's socket.**
  - **`GET /status`** gains `method` (`x509` or `oidc`) and `oidc_issuer`.
  - **The new routes.** `POST /oidc/challenge` answers the challenge and the sign-in parameters.
    `POST /oidc/refresh` takes `{id_token, refresh_token}`.
  - **`POST /refresh`** on an OIDC agent answers `409 browser_required`.
  - **A login meeting another agent.** One with another method or another issuer exits 1 naming
    it, as one with another certificate does.
  - Tasks 5, 6 and 7.
- **17. What is never logged or printed:**
  - the ID token, the refresh token, the code, the verifier, a token response's body, and the
    challenge outside the authorization URL;
  - the agent's log, which holds no URL either.

  The authorization URL is printed on the operator's terminal and handed to the browser. It
  carries `state`, the `nonce` and the `code_challenge`, which the browser must carry to the
  provider, and none of which signs anyone in. A provider's refusal is said by its OAuth error
  code and its description, made printable. All tasks.
- **18. The lab.**
  - **L55:** Keycloak as this client meets it.
  - **L56:** the CLI end to end on Keycloak and vEOS.
  - **L47** (hosted providers) stays open. Until L55 closes, no doc says which redirect
    registration admits an ephemeral port on Keycloak, that it enforces PKCE, or what its refresh
    grant answers after a logout or at its session limits.
  - Task 8.
```

- [ ] **Step 2: Decision 39 ruling 16 and decision 42 ruling 6 point at decision 43**

Replace

```markdown
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10.
```

with

```markdown
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10. Plan 9b adds `max_token_age_seconds` to each entry (decision 43 ruling 14).
```

In decision 42 ruling 6, replace

```markdown
  - **Where and what.** `$XDG_CONFIG_HOME/port49/config.yaml`, else
    `~/.config/port49/config.yaml`, holding `broker`, `broker_ca`, `cert` and `key`.
```

with

```markdown
  - **Where and what.** `$XDG_CONFIG_HOME/port49/config.yaml`, else
    `~/.config/port49/config.yaml`, holding `broker`, `broker_ca`, `cert` and `key`. Plan 9b adds
    `method`, `oidc_issuer`, `oidc_ca` and `oidc_redirect_port` (decision 43 ruling 15).
```

- [ ] **Step 3: §5.6, the agent's side of the OIDC refresh**

After the line ``auth_time`) and L47 (hosted providers, open).`` (`grep -n "(hosted providers,
open)\.$"`), insert a blank line and:

```markdown
**The agent's side, as built (plan 9b; §13 decision 43).**

- **The sign-in.** `port49 refresh` asks the agent for the broker's challenge and signs in at the
  provider with `prompt=login`, the challenge as the `nonce`, in a browser or by a pasted address.
  The agent then sends the new ID token to `/v1/refresh`, and holds it only once the broker
  answers 200.
- **Silent renewal.** Between refreshes the agent renews the ID token with the provider's refresh
  token. A renewed token keeps the original `auth_time`, so it never extends the ceiling (L46).
- **A provider that moves `auth_time`** on that grant has its token refused, since the bearer's
  session clock would move with no authentication.
```

- [ ] **Step 4: §12, `port49 refresh` and `port49 login` on the OIDC path**

Replace

```markdown
otherwise; it also refreshes once after a new session connects. `port49 token` warns on stderr when
```

with

```markdown
otherwise; it also refreshes once after a new session connects. On the OIDC path (§13 decision 43
ruling 12), the refresh is a sign-in at the provider with `prompt=login`, carrying the broker's
challenge as its `nonce`, and a new OIDC session does not refresh at login. `port49 token` warns on stderr when
```

After the line `42 ruling 6).` that ends the `port49 login` paragraph (`grep -n "^42 ruling
6)\.$"`), insert a blank line and:

```markdown
**`port49 login --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser]`**, or
`method: oidc` in the config file, signs in at the identity provider `/v1/config` lists, by the
authorization-code flow with PKCE, and starts the agent holding the ID token and the provider's
refresh token in memory.
- **The browser.** One is opened on a host with a display. The address is always printed, and on
  a terminal the address the browser ended on can be pasted back.
- **Renewal.** The agent renews the ID token in the background, and says when the provider does
  not answer.
- §13 decision 43.
```

- [ ] **Step 5: §15, L55 and L56 after L54**

After the row that begins `| **L54** |` (`grep -n "^| \*\*L54\*\*"`), insert:

```markdown
| **L55** | Keycloak as port49's public client meets it (plan 9b). **The redirect:** for port49-cli registered with `http://127.0.0.1:18749/callback`, `http://127.0.0.1/callback`, `http://127.0.0.1/*` and `http://127.0.0.1:*/callback` in turn, whether the admin API takes the registration and whether an authorization request naming `http://127.0.0.1:<port>/callback` is accepted (the login form shown) for the registered port, another fixed port and an ephemeral one (RFC 8252 §7.3). **PKCE:** with `S256`, whether a code exchanged with the right verifier, a wrong one and none is answered, and with which `error`; whether `code_challenge_method=plain` is accepted. **Discovery and the answer:** `code_challenge_methods_supported`, `authorization_response_iss_parameter_supported`, and whether the authorization response carries `iss` (RFC 9207). **The refresh-token grant:** whether it returns an ID token, whether it rotates the refresh token, whether the renewed ID token keeps `iss`, `sub`, `aud`, `sid` and `auth_time` and carries no `nonce`, and whether a rotated-out refresh token is still taken. **What it answers** (status and `error`) after an RP-initiated logout, after an administrator's sign-out of the user, after `ssoSessionIdleTimeout` with no grant, and after `ssoSessionMaxLifespan`; and whether a `prompt=login` sign-in inside the SSO session restarts the session's maximum lifespan. | §13 decision 43 rulings 1, 4, 9 and 10; the operator notes' redirect registration and "set the provider's session limit at or above the broker's" (plan 13) | Keycloak (26.x) | open — added 2026-10-09 |
| **L56** | The agent's OIDC session end to end on Keycloak and one device (plan 9b), with the real `port49` CLI and the realm's Access Token Lifespan at 60s. Whether: `port49 login --oidc --no-browser` signs in through a scripted browser and starts the agent; `port49 token` mints and the device takes the token over SSH; `port49 token` still mints after at least two ID-token lifetimes with no browser; `port49 refresh` asks the password again and extends the device session; an administrator's sign-out ends the agent, `port49 token` printing the broker's logout words, and a login from the time they name works; with Keycloak stopped, `port49 token` mints until the held ID token's life ends, then exits 1 saying the provider did not renew it and not to log in, the agent still running, and with Keycloak started again a `port49 token` mints with no login (or, if Keycloak lost its sessions, what the agent says). No token, code or verifier in the CLI's output or the agent's log. | §13 decision 43 rulings 5, 7, 9, 10, 11 and 12; the operator notes (plan 13) | Keycloak (26.x); EOS | open — added 2026-10-09 |
```

- [ ] **Step 6: Design §7, the OIDC path as built**

Replace

```markdown
stops trusting `jwks_max_age` (24h) after the last successful fetch. The agent's public client is
plan 9's.
```

with

```markdown
stops trusting `jwks_max_age` (24h) after the last successful fetch. The agent's public client is
plan 9b's (below).
```

After the paragraph that ends `adoption and is **not required for v1**.` (`grep -n "not required
for v1\*\*\.$"`), insert a blank line and:

```markdown
As built (plan 9b; policy engine spec §13 decision 43 rulings 1–13):
- **The sign-in.** `port49 login --oidc` signs in by the authorization-code flow with PKCE (S256),
  in the command's own process, over a loopback redirect, with `prompt=login`: a login is a fresh
  authentication.
- **Not on disk.** The refresh token is held in the agent's memory and never written. The agent
  is non-dumpable on Linux, so the file this section warns of does not exist. An agent that stops
  ends the session, as a dropped connection does on the certificate path.
- **Renewal.** The agent renews the ID token, each request's bearer, with the refresh token, and
  a renewed token never moves `auth_time`.
- **No browser.** On a host with no browser the address is printed, and the one the browser ends
  on is pasted back.
- **No device grant.** The device authorization grant is not built: it carries no `nonce` for the
  refresh challenge, and its user code is a phishing route.
```

- [ ] **Step 7: Design §17, the socket's two codes and the client**

After the line that begins `503  revocation_running` (`grep -n "^503  revocation_running"`),
insert:

```
503  identity_provider_unreachable    the agent's socket, not the broker: the agent's ID token's life ended and the identity provider did not renew it; nothing was sent; the agent keeps trying (plan 9b)
409  browser_required                 the agent's socket: POST /refresh on an OIDC session, whose refresh is a sign-in `port49 refresh` runs (plan 9b)
```

Replace

```markdown
Only interactive human use requires session management and SSH integration.
```

with

```markdown
Only interactive human use requires session management and SSH integration. As built (plan 9b):
`port49 login --oidc` is the OIDC public client, and `port49 refresh` its fresh sign-in.
```

- [ ] **Step 8: Check and commit**

Run: `grep -c "decision 43" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md`
Expected: at least 6 in the spec and 1 in the design.

Run: `grep -n "^| \*\*L5[56]\*\*" docs/design/2026-08-23-policy-engine-spec.md`
Expected: two rows, each ending `| open — added 2026-10-09 |`.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs(spec): decision 43, the OIDC public client; L55 and L56 opened"
```

---

### Task 2: The servers the client talks to: an authorization server on the test issuer, and `max_token_age_seconds`

**Files:**
- Create: `internal/oidc/oidctest/authserver.go`, `internal/oidc/oidctest/authserver_test.go`
- Modify: `internal/oidc/oidctest/issuer.go` (`Issuer.auth`, two routes, discovery members)
- Modify: `internal/broker/api/api.go` (`OIDCProvider.MaxTokenAgeSeconds`),
  `internal/broker/broker.go` (`config`), `internal/broker/oidcserver_test.go`

**Interfaces:**
- Consumes: `oidctest.Issuer` (`URL`, `Token`, `Roots`, `mu`), `oidc.DefaultTiming`.
- Produces, for Tasks 3–8:
  - `func (i *Issuer) AuthServer(t testing.TB, clientID, sub string, claims map[string]any) *AuthServer`
  - `type AuthServer struct { ClientID, Sub string; Claims map[string]any; Now func() time.Time; … }`
  - `func (a *AuthServer) SetLifetime(d time.Duration)`, `SetAuthTime(at time.Time)`,
    `MoveAuthTimeOnRefresh()`, `NoRefreshToken()`, `NoIssParameter()`, `Deny(code string)`,
    `FailRefresh(status int, code string)`
  - `func (a *AuthServer) Authorizations() []url.Values`, `Grants() []url.Values`, `Issued() []string`
  - `func (a *AuthServer) SignIn(t testing.TB, nonce string) (idToken, refresh string)`
  - `func (i *Issuer) Browser() func(string) error`, `func (i *Issuer) Redirected(u string) (string, error)`
  - `api.OIDCProvider.MaxTokenAgeSeconds int` (`json:"max_token_age_seconds,omitempty"`)

- [ ] **Step 1: Write the failing tests**

Create `internal/oidc/oidctest/authserver_test.go`:

```go
package oidctest

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// claimsOf is a JWS's claims, decoded without verification: the test reads
// what the server signed.
func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// authorize asks i's /authorize for a code with verifier's S256 challenge,
// redirecting to a loopback port nothing listens on, and returns the
// redirect's query without following it.
func authorize(t *testing.T, i *Issuer, verifier, nonce string) (url.Values, string) {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	redirect := "http://127.0.0.1:1/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"st"}, "nonce": {nonce}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	loc, err := i.Redirected(i.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query(), redirect
}

// token posts form to i's /token and returns the status and the answer.
func token(t *testing.T, i *Issuer, form url.Values) (int, map[string]any) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.PostForm(i.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTheCodeFlowIssuesAnIDTokenForTheVerifier(t *testing.T) {
	i := NewIssuer(t)
	a := i.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	q, redirect := authorize(t, i, "verifier-0123456789-0123456789-0123456789", "n-1")
	if q.Get("state") != "st" || q.Get("iss") != i.URL || q.Get("code") == "" {
		t.Fatalf("the answer: state %q iss %q code present %v", q.Get("state"), q.Get("iss"), q.Get("code") != "")
	}
	code, out := token(t, i, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {redirect}, "client_id": {"port49-cli"},
		"code_verifier": {"verifier-0123456789-0123456789-0123456789"}})
	if code != 200 || out["refresh_token"] == "" {
		t.Fatalf("exchange: %d, refresh token present %v", code, out["refresh_token"] != nil)
	}
	if c := claimsOf(t, out["id_token"].(string)); c["sub"] != "sub-alice" || c["nonce"] != "n-1" ||
		c["aud"] != "port49-cli" || c["iss"] != i.URL {
		t.Fatalf("the ID token's claims: sub %v nonce %v aud %v iss %v", c["sub"], c["nonce"], c["aud"], c["iss"])
	}
	if got := a.Authorizations(); len(got) != 1 || got[0].Get("prompt") != "login" {
		t.Fatalf("authorizations recorded: %d", len(got))
	}
}

// A code is exchanged once, with the verifier its challenge was made from
// (RFC 7636 §4.6): a wrong verifier and a second use are invalid_grant.
func TestTheTokenEndpointRefusesAWrongVerifier(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	right := "verifier-0123456789-0123456789-0123456789"
	q, redirect := authorize(t, i, right, "n")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirect},
		"client_id": {"port49-cli"}, "code_verifier": {right + "x"}}
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a wrong verifier: %d %v", code, out["error"])
	}
	form.Set("code_verifier", right)
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a code tried once already: %d %v", code, out["error"])
	}
}

// The refresh-token grant keeps auth_time and sid, carries no nonce, and
// rotates the refresh token; the old one is refused.
func TestARefreshKeepsAuthTimeAndRotates(t *testing.T) {
	i := NewIssuer(t)
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	a := i.AuthServer(t, "port49-cli", "sub-alice", nil)
	a.SetAuthTime(at)
	_, rt := a.SignIn(t, "n")
	code, out := token(t, i, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {"port49-cli"}})
	if code != 200 {
		t.Fatalf("refresh: %d", code)
	}
	c := claimsOf(t, out["id_token"].(string))
	if c["auth_time"] != float64(at.Unix()) || c["nonce"] != nil || c["sid"] != "s-sub-alice" {
		t.Fatalf("the renewed ID token: auth_time %v (want %d) nonce %v sid %v", c["auth_time"], at.Unix(),
			c["nonce"], c["sid"])
	}
	if out["refresh_token"] == rt {
		t.Fatal("the refresh token was not rotated")
	}
	if code, out := token(t, i, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {"port49-cli"}}); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a rotated-out refresh token: %d %v", code, out["error"])
	}
	a.FailRefresh(400, "invalid_grant")
	if code, _ := token(t, i, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {out["refresh_token"].(string)}, "client_id": {"port49-cli"}}); code != 400 {
		t.Fatalf("FailRefresh: %d", code)
	}
}

// Discovery names the endpoints once an authorization server exists, and
// Browser follows the provider's redirect to a loopback listener.
func TestDiscoveryAndTheBrowser(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.Get(i.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["authorization_endpoint"] != i.URL+"/authorize" || doc["token_endpoint"] != i.URL+"/token" ||
		doc["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", doc)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan url.Values, 1)
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.URL.Query() }))
	}()
	defer ln.Close()
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "state": {"s"},
		"redirect_uri": {"http://" + ln.Addr().String() + "/callback"}, "code_challenge": {"c"},
		"code_challenge_method": {"S256"}}
	if err := i.Browser()(i.URL + "/authorize?" + q.Encode()); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v.Get("code") == "" || !strings.HasPrefix(v.Get("iss"), "https://") {
		t.Fatalf("the callback: code present %v, iss %q", v.Get("code") != "", v.Get("iss"))
	}
}
```

In `internal/broker/oidcserver_test.go`, add `"github.com/rhwendt/port49/internal/oidc"` to the
imports and, at the end of `TestConfigNamesTheHumanOIDCVerifiers`, before its closing brace:

```go
	// Ruling 14 (decision 43): the agent renews before max_token_age.
	if want := int(oidc.DefaultTiming.MaxTokenAge / time.Second); c.OIDC[0].MaxTokenAgeSeconds != want {
		t.Fatalf("max_token_age_seconds %d, want %d: %s", c.OIDC[0].MaxTokenAgeSeconds, want, w.Body)
	}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidc/oidctest/ ./internal/broker/ -run 'TestTheCodeFlow|TestTheTokenEndpoint|TestARefreshKeeps|TestDiscoveryAndTheBrowser|TestConfigNamesTheHumanOIDCVerifiers' -count=1`
Expected: FAIL to build: `i.AuthServer undefined`, `c.OIDC[0].MaxTokenAgeSeconds undefined`.

- [ ] **Step 3: The authorization server**

Create `internal/oidc/oidctest/authserver.go`:

```go
package oidctest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// AuthServer is the issuer's authorization server for one public client
// (plan 9b): GET /authorize answers at once, as a provider holding a live
// session does, by redirecting to the request's loopback redirect_uri with
// a code for Sub; POST /token takes that code with its PKCE verifier
// (authorization_code) or a refresh token it issued (refresh_token), which
// it rotates. Discovery then names both endpoints, S256 and the iss
// parameter (RFC 9207).
type AuthServer struct {
	ClientID string
	Sub      string
	// Claims go into every ID token beside iss, aud, sub, iat, exp,
	// auth_time, sid and a sign-in's nonce.
	Claims map[string]any
	// Now is the provider's clock; nil is time.Now.
	Now func() time.Time

	t           testing.TB
	i           *Issuer
	mu          sync.Mutex
	lifetime    time.Duration
	authTime    time.Time
	moveAuth    bool
	noRefresh   bool
	noIss       bool
	deny        string
	failStatus  int
	failCode    string
	codes       map[string]grant
	refreshes   map[string]grant
	asked       []url.Values
	grants      []url.Values
	issued      []string
}

// grant is what a code or a refresh token stands for.
type grant struct {
	redirect, challenge, nonce, sid string
	authTime, expires               time.Time
}

// AuthServer makes i an authorization server for clientID, signing in sub
// with claims. ID tokens live five minutes, and each sign-in is an
// authentication at Now.
func (i *Issuer) AuthServer(t testing.TB, clientID, sub string, claims map[string]any) *AuthServer {
	a := &AuthServer{ClientID: clientID, Sub: sub, Claims: claims, t: t, i: i, lifetime: 5 * time.Minute,
		codes: map[string]grant{}, refreshes: map[string]grant{}}
	i.mu.Lock()
	i.auth = a
	i.mu.Unlock()
	return a
}

func (a *AuthServer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// SetLifetime is every later ID token's exp − iat.
func (a *AuthServer) SetLifetime(d time.Duration) { a.mu.Lock(); a.lifetime = d; a.mu.Unlock() }

// SetAuthTime makes every later sign-in reuse an authentication at at, as a
// provider ignoring prompt=login does; the zero time makes each one an
// authentication at Now again.
func (a *AuthServer) SetAuthTime(at time.Time) { a.mu.Lock(); a.authTime = at; a.mu.Unlock() }

// MoveAuthTimeOnRefresh makes the refresh-token grant set auth_time to Now,
// as no provider may (OIDC Core §12.2).
func (a *AuthServer) MoveAuthTimeOnRefresh() { a.mu.Lock(); a.moveAuth = true; a.mu.Unlock() }

// NoRefreshToken issues no refresh token from then on.
func (a *AuthServer) NoRefreshToken() { a.mu.Lock(); a.noRefresh = true; a.mu.Unlock() }

// NoIssParameter drops iss from the authorization response and from
// discovery.
func (a *AuthServer) NoIssParameter() { a.mu.Lock(); a.noIss = true; a.mu.Unlock() }

// Deny answers every later authorization with error=code.
func (a *AuthServer) Deny(code string) { a.mu.Lock(); a.deny = code; a.mu.Unlock() }

// FailRefresh answers every refresh-token grant with status and the OAuth
// error code; status 0 answers them again.
func (a *AuthServer) FailRefresh(status int, code string) {
	a.mu.Lock()
	a.failStatus, a.failCode = status, code
	a.mu.Unlock()
}

// Authorizations is every /authorize query, in order.
func (a *AuthServer) Authorizations() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.asked...)
}

// Grants is every /token form, in order.
func (a *AuthServer) Grants() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.grants...)
}

// Issued is every code, ID token and refresh token given out: the values no
// output may hold.
func (a *AuthServer) Issued() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.issued...)
}

// SignIn is a sign-in with no browser: an ID token for Sub carrying nonce
// (none for ""), authenticated at Now or at SetAuthTime's time, and its
// refresh token ("" under NoRefreshToken).
func (a *AuthServer) SignIn(t testing.TB, nonce string) (idToken, refresh string) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	g := grant{nonce: nonce, sid: "s-" + a.Sub, authTime: a.signInTime()}
	return a.answer(g, nonce)
}

// signInTime is a new sign-in's auth_time. Called with a.mu held.
func (a *AuthServer) signInTime() time.Time {
	if !a.authTime.IsZero() {
		return a.authTime
	}
	return a.now()
}

// answer is g's ID token and, unless NoRefreshToken, a new refresh token
// for g. Called with a.mu held.
func (a *AuthServer) answer(g grant, nonce string) (string, string) {
	now := a.now()
	c := map[string]any{"iss": a.i.URL, "aud": a.ClientID, "sub": a.Sub, "iat": now.Unix(),
		"exp": now.Add(a.lifetime).Unix(), "auth_time": g.authTime.Unix(), "sid": g.sid}
	if nonce != "" {
		c["nonce"] = nonce
	}
	for k, v := range a.Claims {
		c[k] = v
	}
	id := a.i.Token(a.t, "k1", c)
	a.issued = append(a.issued, id)
	if a.noRefresh {
		return id, ""
	}
	rt := opaque()
	a.refreshes[rt] = g
	a.issued = append(a.issued, rt)
	return id, rt
}

func (a *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, q)
	redirect := q.Get("redirect_uri")
	u, err := url.Parse(redirect)
	if q.Get("client_id") != a.ClientID || err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		u.Path != "/callback" {
		http.Error(w, "oidctest: an unknown client or a redirect_uri that is not loopback", http.StatusBadRequest)
		return
	}
	back := u.Query()
	back.Set("state", q.Get("state"))
	if !a.noIss {
		back.Set("iss", a.i.URL)
	}
	switch {
	case a.deny != "":
		back.Set("error", a.deny)
		back.Set("error_description", "oidctest: denied")
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		back.Set("error", "invalid_request")
	default:
		code := opaque()
		a.codes[code] = grant{redirect: redirect, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
			sid: "s-" + a.Sub, authTime: a.signInTime(), expires: a.now().Add(time.Minute)}
		a.issued = append(a.issued, code)
		back.Set("code", code)
	}
	u.RawQuery = back.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f := r.PostForm
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants = append(a.grants, f)
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "oidctest: " + code})
	}
	if f.Get("client_id") != a.ClientID || f.Has("client_secret") {
		fail(http.StatusUnauthorized, "invalid_client")
		return
	}
	var g grant
	nonce := ""
	switch f.Get("grant_type") {
	case "authorization_code":
		var ok bool
		g, ok = a.codes[f.Get("code")]
		delete(a.codes, f.Get("code"))
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || a.now().After(g.expires) || f.Get("redirect_uri") != g.redirect ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		nonce = g.nonce
	case "refresh_token":
		if a.failStatus != 0 {
			fail(a.failStatus, a.failCode)
			return
		}
		var ok bool
		g, ok = a.refreshes[f.Get("refresh_token")]
		delete(a.refreshes, f.Get("refresh_token"))
		if !ok {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		if a.moveAuth {
			g.authTime = a.now()
		}
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	id, rt := a.answer(g, nonce)
	body := map[string]any{"token_type": "Bearer", "access_token": opaque(), "expires_in": int(a.lifetime / time.Second),
		"id_token": id}
	if rt != "" {
		body["refresh_token"] = rt
	}
	_ = json.NewEncoder(w).Encode(body)
}

// opaque is 32 random bytes, base64url.
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Browser is a browser that trusts the issuer: it opens a URL and follows
// the provider's redirect to the loopback callback, as a person's browser
// does once they have signed in. It errs unless the last answer is 200.
func (i *Issuer) Browser() func(string) error {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	return func(u string) error {
		resp, err := c.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("oidctest browser: %s", resp.Status)
		}
		return nil
	}
}

// Redirected opens u and returns where the provider redirected it, without
// following: what a person on a remote shell copies from the address bar.
func (i *Issuer) Redirected(u string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("oidctest: /authorize answered %s", resp.Status)
	}
	return resp.Header.Get("Location"), nil
}
```

In `internal/oidc/oidctest/issuer.go`:

- Add a field to `Issuer`, after `fetches atomic.Int64`:

  ```go
  	auth      *AuthServer // nil: /authorize and /token answer 404
  ```

- In `NewIssuer`'s discovery handler, replace

  ```go
  		i.mu.Lock()
  		status, hook := i.status, i.discovery
  		i.mu.Unlock()
  ```

  with

  ```go
  		i.mu.Lock()
  		status, hook, auth := i.status, i.discovery, i.auth
  		i.mu.Unlock()
  ```

  and replace

  ```go
  		if hook != nil {
  			hook(doc)
  		}
  ```

  with

  ```go
  		if auth != nil {
  			auth.mu.Lock()
  			doc["authorization_endpoint"] = i.URL + "/authorize"
  			doc["token_endpoint"] = i.URL + "/token"
  			doc["code_challenge_methods_supported"] = []string{"S256"}
  			doc["authorization_response_iss_parameter_supported"] = !auth.noIss
  			auth.mu.Unlock()
  		}
  		if hook != nil {
  			hook(doc)
  		}
  ```

- After the `GET /moved` route, add:

  ```go
  	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
  		i.mu.Lock()
  		a := i.auth
  		i.mu.Unlock()
  		if a == nil {
  			http.NotFound(w, r)
  			return
  		}
  		a.authorize(w, r)
  	})
  	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
  		i.mu.Lock()
  		a := i.auth
  		i.mu.Unlock()
  		if a == nil {
  			http.NotFound(w, r)
  			return
  		}
  		a.token(w, r)
  	})
  ```

`a.i.Token` takes `i.mu` while `a.mu` is held; nothing takes the two the other way round (the
discovery handler releases `i.mu` before it takes `auth.mu`), so there is no lock-order cycle.

- [ ] **Step 4: `max_token_age_seconds`**

In `internal/broker/api/api.go`, replace

```go
// OIDCProvider is one human OIDC verifier as GET /v1/config names it.
type OIDCProvider struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}
```

with

```go
// OIDCProvider is one human OIDC verifier as GET /v1/config names it.
// MaxTokenAgeSeconds is broker.identity's max_token_age: the agent renews an
// ID token before it is that old, whatever its exp says (plan 9b; spec §13
// decision 43 ruling 14). 0 from an older broker.
type OIDCProvider struct {
	Issuer             string   `json:"issuer"`
	ClientID           string   `json:"client_id"`
	Scopes             []string `json:"scopes"`
	MaxTokenAgeSeconds int      `json:"max_token_age_seconds,omitempty"`
}
```

In `internal/broker/broker.go`'s `config`, replace

```go
			c.OIDC = append(c.OIDC, api.OIDCProvider{Issuer: v.Issuer, ClientID: v.ClientID, Scopes: scopes})
```

with

```go
			c.OIDC = append(c.OIDC, api.OIDCProvider{Issuer: v.Issuer, ClientID: v.ClientID, Scopes: scopes,
				MaxTokenAgeSeconds: int(b.Identity.Timing.MaxTokenAge / time.Second)})
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/oidc/... ./internal/broker/ -count=1`
Expected: PASS.

Run: `go test -race ./internal/oidc/oidctest/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/oidctest/authserver.go internal/oidc/oidctest/authserver_test.go \
  internal/oidc/oidctest/issuer.go internal/broker/api/api.go \
  internal/broker/broker.go internal/broker/oidcserver_test.go
git commit -m "feat(oidc): a test authorization server with PKCE and rotation; /v1/config names max_token_age_seconds"
```

---

### Task 3: Reading an ID token as a client, discovery, the token endpoint, and renewal

**Files:**
- Create: `internal/oidc/client.go`, `internal/oidc/client_test.go`
- Create: `internal/oidcclient/oidcclient.go`, `internal/oidcclient/request.go`,
  `internal/oidcclient/oidcclient_test.go`

**Interfaces:**
- Consumes: `oidc.ParseCompact`, `known`, `payload`, `exact`, `claims`, `claimNames`, `audiences`,
  `humanAudience`, `numericDate`, `printableID`, `exactObject`, `discoveryMember` (all in
  `internal/oidc`); `oidc.NewClient`; `printsafe.Line`; Task 2's `AuthServer`.
- Produces, for Tasks 4–7:
  - `type oidc.IDToken struct { Issuer, Subject, Sid, Nonce string; AuthTime, IssuedAt, Expires time.Time }`
  - `func oidc.ReadIDToken(raw, issuer, clientID, nonce string) (oidc.IDToken, error)`
  - `type oidc.Discovery struct { AuthorizationEndpoint, TokenEndpoint string; CodeChallengeMethods []string; IssParameter bool }`
  - `func oidc.ReadDiscovery(raw []byte, issuer string) (oidc.Discovery, error)`
  - `type oidcclient.Provider struct { Issuer, ClientID string; Scopes []string; Roots *x509.CertPool }`
  - `type oidcclient.Endpoints struct { Authorization, Token string; IssParameter bool }`
  - `type oidcclient.Tokens struct { ID oidc.IDToken; IDRaw, Refresh string; Received time.Time }`
  - `func oidcclient.Discover(ctx context.Context, p Provider) (Endpoints, error)`
  - `func oidcclient.Renew(ctx context.Context, p Provider, e Endpoints, refresh string, held oidc.IDToken, now func() time.Time) (Tokens, error)`
  - `func oidcclient.Skew(t Tokens) time.Duration`
  - `func exchange(ctx context.Context, p Provider, e Endpoints, code, redirect, verifier, nonce string, now func() time.Time) (Tokens, error)` (unexported, for Task 4)
  - `func oidcclient.AuthorizationURL(p Provider, e Endpoints, redirect, state, nonce, challenge string) (string, error)`;
    `challengeOf`, `opaque` (unexported, for Task 4)
  - `var oidcclient.ErrSessionEnded error`; `type oidcclient.UnreachableError struct{ Issuer string; Err error }`;
    `type oidcclient.ProviderError struct{ Issuer string; Status int; Code, Description string }`

- [ ] **Step 1: Write the failing tests**

Create `internal/oidc/client_test.go`:

```go
package oidc_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// ReadIDToken checks what a public client checks (decision 43 ruling 6), and
// never a date against a clock.
func TestReadIDTokenChecksWhatAClientChecks(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	now := time.Now()
	good := map[string]any{"iss": iss.URL, "aud": "port49-cli", "sub": "sub-alice", "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "nonce": "n-1", "sid": "s-1"}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	id, err := oidc.ReadIDToken(iss.Token(t, "k1", good), iss.URL, "port49-cli", "n-1")
	if err != nil || id.Subject != "sub-alice" || id.Sid != "s-1" || id.Nonce != "n-1" ||
		id.AuthTime.Unix() != now.Unix() {
		t.Fatalf("a good token: %v %v", id, err)
	}
	// An expired token is read: the client judges no date by its clock.
	old := with("exp", now.Add(-time.Hour).Unix())
	old["iat"] = now.Add(-2 * time.Hour).Unix()
	if _, err := oidc.ReadIDToken(iss.Token(t, "k1", old), iss.URL, "port49-cli", ""); err != nil {
		t.Fatalf("an expired token is the broker's to refuse: %v", err)
	}
	for name, c := range map[string]struct {
		claims map[string]any
		nonce  string
		want   string
	}{
		"another issuer":                {with("iss", "https://evil.example"), "", "was not issued by"},
		"another audience":              {with("aud", "other"), "", "aud does not name"},
		"several audiences and no azp":  {with("aud", []string{"port49-cli", "other"}), "", "no azp"},
		"another azp":                   {with("azp", "other"), "", "azp is not"},
		"no sub":                        {with("sub", nil), "", "no usable sub"},
		"no auth_time":                  {with("auth_time", nil), "", "no auth_time"},
		"a date as a string":            {with("iat", "1700000000"), "", "NumericDate"},
		"exp before iat":                {with("exp", now.Add(-time.Minute).Unix()), "", "expires before"},
		"another nonce":                 {good, "n-2", "nonce is not"},
		"no nonce when one was sent":    {with("nonce", nil), "n-1", "nonce is not"},
		"a claim named twice in cases": {with("SUB", "x"), "", "twice"},
	} {
		_, err := oidc.ReadIDToken(iss.Token(t, "k1", c.claims), iss.URL, "port49-cli", c.nonce)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// alg none and an HMAC are refused before any claim is read.
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	for _, alg := range []string{"none", "HS256"} {
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
		if _, err := oidc.ReadIDToken(head+"."+body+".c2ln", iss.URL, "port49-cli", ""); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Errorf("alg %s: %v", alg, err)
		}
	}
	// String withholds the nonce.
	if s := id.String() + id.GoString(); strings.Contains(s, "n-1") {
		t.Fatalf("String holds the nonce: %s", s)
	}
}

func TestReadDiscovery(t *testing.T) {
	ok := `{"issuer":"https://kc.example/r","authorization_endpoint":"https://kc.example/r/auth",` +
		`"token_endpoint":"https://kc.example/r/token","code_challenge_methods_supported":["plain","S256"],` +
		`"authorization_response_iss_parameter_supported":true}`
	d, err := oidc.ReadDiscovery([]byte(ok), "https://kc.example/r")
	if err != nil || d.AuthorizationEndpoint != "https://kc.example/r/auth" || d.TokenEndpoint != "https://kc.example/r/token" ||
		len(d.CodeChallengeMethods) != 2 || !d.IssParameter {
		t.Fatalf("%+v %v", d, err)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"another issuer":         {strings.Replace(ok, `"issuer":"https://kc.example/r"`, `"issuer":"https://kc.example/x"`, 1), "another issuer"},
		"an http token endpoint": {strings.Replace(ok, `"https://kc.example/r/token"`, `"http://kc.example/r/token"`, 1), "token_endpoint"},
		"credentials in a URL":   {strings.Replace(ok, `"https://kc.example/r/auth"`, `"https://u:p@kc.example/r/auth"`, 1), "authorization_endpoint"},
		"a member twice":         {strings.Replace(ok, `{"issuer"`, `{"token_endpoint":"https://x/t","issuer"`, 1), "distinct members"},
		"methods not a list":     {strings.Replace(ok, `["plain","S256"]`, `"S256"`, 1), "code_challenge_methods_supported"},
	} {
		if _, err := oidc.ReadDiscovery([]byte(c.doc), "https://kc.example/r"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
```

Create `internal/oidcclient/oidcclient_test.go`:

```go
package oidcclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// provider is iss as port49-cli's provider, with an authorization server
// signing in sub-alice.
func provider(t *testing.T) (*oidctest.Issuer, *oidctest.AuthServer, Provider) {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	as := iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	return iss, as, Provider{Issuer: iss.URL, ClientID: "port49-cli", Scopes: []string{"openid"}, Roots: iss.Roots()}
}

// held is a sign-in's tokens as the agent would hold them.
func held(t *testing.T, iss *oidctest.Issuer, as *oidctest.AuthServer) Tokens {
	t.Helper()
	raw, rt := as.SignIn(t, "")
	id, err := oidc.ReadIDToken(raw, iss.URL, "port49-cli", "")
	if err != nil {
		t.Fatal(err)
	}
	return Tokens{ID: id, IDRaw: raw, Refresh: rt, Received: time.Now().Round(0)}
}

func TestDiscoverReadsTheEndpoints(t *testing.T) {
	iss, _, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil || e.Authorization != iss.URL+"/authorize" || e.Token != iss.URL+"/token" || !e.IssParameter {
		t.Fatalf("%+v %v", e, err)
	}
}

// A provider offering PKCE methods without S256 is refused; one listing none
// is used (decision 43 ruling 1).
func TestAProviderWithoutS256IsRefused(t *testing.T) {
	iss, _, p := provider(t)
	iss.Discovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	if _, err := Discover(context.Background(), p); err == nil || !strings.Contains(err.Error(), "S256") {
		t.Fatalf("plain only: %v", err)
	}
	iss.Discovery(func(d map[string]any) { delete(d, "code_challenge_methods_supported") })
	if _, err := Discover(context.Background(), p); err != nil {
		t.Fatalf("none listed: %v", err)
	}
}

func TestAProviderThatDoesNotAnswerIsUnreachable(t *testing.T) {
	iss, _, p := provider(t)
	iss.Close()
	var u *UnreachableError
	if _, err := Discover(context.Background(), p); !errors.As(err, &u) || u.Issuer != iss.URL {
		t.Fatalf("%v", err)
	}
}

// The code is exchanged with its verifier and no secret, and the ID token's
// nonce must be the request's.
func TestTheExchangeChecksTheNonce(t *testing.T) {
	iss, as, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	code := func(nonce string) string {
		u, err := AuthorizationURL(p, e, "http://127.0.0.1:1/callback", "st", nonce, base64.RawURLEncoding.EncodeToString(sum[:]))
		if err != nil {
			t.Fatal(err)
		}
		loc, err := iss.Redirected(u)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := url.Parse(loc)
		return v.Query().Get("code")
	}
	got, err := exchange(context.Background(), p, e, code("n-1"), "http://127.0.0.1:1/callback", verifier, "n-1", time.Now)
	if err != nil || got.ID.Subject != "sub-alice" || got.Refresh == "" || got.Received.IsZero() {
		t.Fatalf("%v %v", got, err)
	}
	if g := as.Grants(); g[0].Get("code_verifier") != verifier || g[0].Has("client_secret") {
		t.Fatalf("the exchange sent a secret or no verifier")
	}
	if _, err := exchange(context.Background(), p, e, code("n-1"), "http://127.0.0.1:1/callback", verifier, "n-2", time.Now); err == nil ||
		!strings.Contains(err.Error(), "nonce") {
		t.Fatalf("another nonce: %v", err)
	}
}

// Renew keeps auth_time and the sub, and takes the rotated refresh token.
func TestRenewKeepsAuthTimeAndTakesTheRotatedToken(t *testing.T) {
	iss, as, p := provider(t)
	as.SetAuthTime(time.Now().Add(-time.Hour))
	e, _ := Discover(context.Background(), p)
	h := held(t, iss, as)
	got, err := Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now)
	if err != nil || !got.ID.AuthTime.Equal(h.ID.AuthTime) || got.Refresh == "" || got.Refresh == h.Refresh ||
		got.IDRaw == h.IDRaw {
		t.Fatalf("%v %v", got, err)
	}
	if g := as.Grants(); g[0].Get("grant_type") != "refresh_token" || g[0].Get("scope") != "openid" {
		t.Fatalf("the grant: %v %v", g[0].Get("grant_type"), g[0].Get("scope"))
	}
}

// A renewal that moves auth_time is refused (OIDC Core §12.2; R8).
func TestARenewalThatMovesAuthTimeIsRefused(t *testing.T) {
	iss, as, p := provider(t)
	as.SetAuthTime(time.Now().Add(-time.Hour))
	e, _ := Discover(context.Background(), p)
	h := held(t, iss, as)
	as.MoveAuthTimeOnRefresh()
	if _, err := Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now); err == nil ||
		!strings.Contains(err.Error(), "auth_time") {
		t.Fatalf("%v", err)
	}
}

func TestARenewalNamingAnotherSubIsRefused(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	h := held(t, iss, as)
	h.ID.Subject = "sub-bob"
	if _, err := Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now); err == nil ||
		!strings.Contains(err.Error(), "another sub") {
		t.Fatalf("%v", err)
	}
}

// invalid_grant is the provider ending the session; a 5xx is the provider
// not answering; neither error holds the refresh token.
func TestRenewalFailuresSayWhich(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	h := held(t, iss, as)
	as.FailRefresh(http.StatusBadRequest, "invalid_grant")
	_, err := Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now)
	if !errors.Is(err, ErrSessionEnded) || !strings.Contains(err.Error(), "invalid_grant") ||
		strings.Contains(err.Error(), h.Refresh) {
		t.Fatalf("invalid_grant: %v", err)
	}
	as.FailRefresh(http.StatusServiceUnavailable, "temporarily_unavailable")
	_, err = Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now)
	var u *UnreachableError
	if !errors.As(err, &u) || errors.Is(err, ErrSessionEnded) || strings.Contains(err.Error(), h.Refresh) {
		t.Fatalf("a 503: %v", err)
	}
	as.FailRefresh(http.StatusUnauthorized, "invalid_client")
	_, err = Renew(context.Background(), p, e, h.Refresh, h.ID, time.Now)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Code != "invalid_client" || errors.Is(err, ErrSessionEnded) {
		t.Fatalf("invalid_client: %v", err)
	}
}

// Tokens never prints a token.
func TestTokensWithholdThemselves(t *testing.T) {
	iss, as, _ := provider(t)
	h := held(t, iss, as)
	if s := h.String() + h.GoString(); strings.Contains(s, h.IDRaw) || strings.Contains(s, h.Refresh) {
		t.Fatalf("%s", s)
	}
}

func TestSkew(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	if s := Skew(Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(7 * time.Minute)}); s != 7*time.Minute {
		t.Fatalf("%v", s)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidc/ ./internal/oidcclient/ -count=1`
Expected: FAIL to build: `oidc.ReadIDToken undefined`, `oidc.ReadDiscovery undefined`, `no Go
files in internal/oidcclient` (or `undefined: Discover`).

- [ ] **Step 3: `internal/oidc/client.go`**

```go
package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"
)

// IDToken is an ID token as port49's public client reads it (plan 9b; spec
// §13 decision 43 ruling 6): the claims it checks, from a token it does not
// verify by signature. The token came from the provider's token endpoint
// over TLS, which OIDC Core §3.1.3.7 item 6 allows in place of the
// signature, and the broker verifies it on every request. Nothing here
// authorizes anything; it decides what the agent sends and when.
type IDToken struct {
	Issuer   string
	Subject  string
	Sid      string
	Nonce    string
	AuthTime time.Time
	IssuedAt time.Time
	Expires  time.Time
}

// String withholds the nonce, which answers a refresh challenge.
func (t IDToken) String() string {
	return fmt.Sprintf("IDToken{issuer %s sub %s sid %s auth_time %s iat %s exp %s}", t.Issuer, t.Subject, t.Sid,
		t.AuthTime.UTC().Format(time.RFC3339), t.IssuedAt.UTC().Format(time.RFC3339), t.Expires.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t IDToken) GoString() string { return t.String() }

// ReadIDToken reads raw as an ID token issued to clientID by issuer: a
// compact JWS whose alg is one Ruling 3 accepts (none and the HMACs are
// ErrAlgorithm); iss exactly issuer; aud naming clientID, and azp as
// humanAudience reads it; sub, iat, exp and auth_time present and iat no
// later than exp; every claim by its exact name; and, when nonce is not "",
// a nonce claim equal to it. It compares no date with a clock: the broker's
// clock judges the token (decision 43 ruling 6).
func ReadIDToken(raw, issuer, clientID, nonce string) (IDToken, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	if !slices.Contains(known, j.Header.Alg) {
		return IDToken{}, fmt.Errorf("the ID token's alg: %w", ErrAlgorithm)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	var c claims
	if err := exact(all, &c, claimNames); err != nil {
		return IDToken{}, errors.New("the ID token: a claim is not of its type")
	}
	auds, ok := audiences(c.Aud)
	switch {
	case c.Iss != issuer:
		return IDToken{}, fmt.Errorf("the ID token was not issued by %s", issuer)
	case !ok:
		return IDToken{}, errors.New("the ID token has no aud")
	}
	if r := humanAudience(auds, c.Azp, clientID); r != nil {
		return IDToken{}, fmt.Errorf("the ID token: %s", r.why)
	}
	iat, okIat := numericDate(c.Iat)
	exp, okExp := numericDate(c.Exp)
	at, okAt := numericDate(c.AuthTime)
	switch {
	case !printableID(c.Sub):
		return IDToken{}, errors.New("the ID token has no usable sub")
	case !okIat || !okExp:
		return IDToken{}, errors.New("the ID token's iat or exp is not a NumericDate")
	case len(c.AuthTime) == 0:
		return IDToken{}, errors.New("the ID token has no auth_time")
	case !okAt:
		return IDToken{}, errors.New("the ID token's auth_time is not a NumericDate")
	case exp.Before(iat):
		return IDToken{}, errors.New("the ID token expires before it was issued")
	case nonce != "" && c.Nonce != nonce:
		return IDToken{}, errors.New("the ID token's nonce is not the one port49 sent")
	case c.Sid != "" && !printableID(c.Sid):
		return IDToken{}, errors.New("the ID token's sid is not printable")
	}
	return IDToken{Issuer: c.Iss, Subject: c.Sub, Sid: c.Sid, Nonce: c.Nonce, AuthTime: at, IssuedAt: iat,
		Expires: exp}, nil
}

// Discovery is what port49's public client reads of a provider's discovery
// document (OIDC Discovery §3; RFC 8414 §2; RFC 9207 §3), each member by its
// exact name and none repeated, as the key fetch reads issuer and jwks_uri.
type Discovery struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	// CodeChallengeMethods is code_challenge_methods_supported; nil when the
	// document does not list it.
	CodeChallengeMethods []string
	// IssParameter is authorization_response_iss_parameter_supported.
	IssParameter bool
}

// ReadDiscovery reads raw as issuer's discovery document: its issuer must be
// issuer exactly (OIDC Discovery §4.3), and the two endpoints https URLs with
// a host and no credentials.
func ReadDiscovery(raw []byte, issuer string) (Discovery, error) {
	doc, err := exactObject(raw)
	if err != nil {
		return Discovery{}, errors.New("the discovery document is not a JSON object of distinct members")
	}
	if iss, _ := discoveryMember(doc, "issuer"); iss != issuer {
		return Discovery{}, errors.New("the discovery document names another issuer (OpenID Connect Discovery §4.3)")
	}
	var d Discovery
	d.AuthorizationEndpoint, _ = discoveryMember(doc, "authorization_endpoint")
	d.TokenEndpoint, _ = discoveryMember(doc, "token_endpoint")
	for _, m := range []struct{ name, u string }{{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint}} {
		u, err := url.Parse(m.u)
		if m.u == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return Discovery{}, fmt.Errorf("the discovery document's %s is not an https URL without credentials", m.name)
		}
	}
	if v, ok := doc["code_challenge_methods_supported"]; ok && json.Unmarshal(v, &d.CodeChallengeMethods) != nil {
		return Discovery{}, errors.New("the discovery document's code_challenge_methods_supported is not a list of strings")
	}
	if v, ok := doc["authorization_response_iss_parameter_supported"]; ok && json.Unmarshal(v, &d.IssParameter) != nil {
		return Discovery{}, errors.New("the discovery document's authorization_response_iss_parameter_supported is not a boolean")
	}
	return d, nil
}
```

`known` is `jws.go`'s list of the five algorithms; `claims`, `claimNames`, `payload`, `exact`,
`audiences`, `numericDate`, `printableID` and `humanAudience` are `verify.go`'s; `exactObject` is
`jws.go`'s and `discoveryMember` `keyset.go`'s. None changes.

- [ ] **Step 4: `internal/oidcclient/oidcclient.go`**

```go
// Package oidcclient is port49's OpenID Connect public client (plan 9b; spec
// §13 decision 43): the authorization-code flow with PKCE (S256) over a
// loopback redirect (RFC 8252), which `port49 login --oidc` and `port49
// refresh` run in their own process, and the refresh-token grant the agent
// renews its ID token with. There is no client secret. The tokens, the code
// and the verifier go nowhere but the token endpoint and the agent; an error
// names the provider and its OAuth error code, never a token or a body.
package oidcclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// maxBody bounds a discovery document and a token response.
const maxBody = 1 << 20

// Provider is one identity provider as the broker's /v1/config names it, and
// the anchor port49 reaches it with.
type Provider struct {
	Issuer   string
	ClientID string
	Scopes   []string
	// Roots is the provider's TLS anchor (oidc_ca); nil is the system's roots.
	Roots *x509.CertPool
}

// Endpoints is what discovery gives the client (decision 43 ruling 2).
type Endpoints struct {
	Authorization string
	Token         string
	// IssParameter is whether the provider puts iss in its authorization
	// response (RFC 9207), which the callback then requires.
	IssParameter bool
}

// Tokens is one token response: the ID token, read, and its raw form; the
// refresh token, "" when the provider issued none; and when it arrived, on
// this host's wall clock (Round(0): a laptop's sleep counts).
type Tokens struct {
	ID       oidc.IDToken
	IDRaw    string
	Refresh  string
	Received time.Time
}

// String withholds both tokens.
func (t Tokens) String() string {
	return fmt.Sprintf("Tokens{%v refresh token %t received %s}", t.ID, t.Refresh != "",
		t.Received.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t Tokens) GoString() string { return t.String() }

// Skew is how far this host's clock was from the provider's when t arrived:
// positive when this host is ahead (decision 43 ruling 6).
func Skew(t Tokens) time.Duration { return t.Received.Sub(t.ID.IssuedAt) }

// ErrSessionEnded is the provider refusing the refresh token (invalid_grant):
// it ended the session, and only a new sign-in starts another (ruling 10).
var ErrSessionEnded = errors.New("your identity provider no longer renews this session: it was signed out, " +
	"or reached the provider's own session limit")

// UnreachableError is a provider that did not answer: a transport fault, a
// timeout, or a 5xx.
type UnreachableError struct {
	Issuer string
	Err    error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("your identity provider at %s did not answer: %v", e.Issuer, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// ProviderError is the token endpoint refusing (RFC 6749 §5.2): its status,
// error code and description, made printable.
type ProviderError struct {
	Issuer      string
	Status      int
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	s := fmt.Sprintf("your identity provider at %s refused: %s (HTTP %d)", e.Issuer, e.Code, e.Status)
	if e.Description != "" {
		s += ": " + e.Description
	}
	return s
}

// Discover reads p's discovery document (oidc.ReadDiscovery) and refuses a
// provider that offers PKCE methods without S256; one that lists none is
// used, S256 sent (decision 43 ruling 1).
func Discover(ctx context.Context, p Provider) (Endpoints, error) {
	raw, err := get(ctx, p, strings.TrimSuffix(p.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return Endpoints{}, err
	}
	d, err := oidc.ReadDiscovery(raw, p.Issuer)
	if err != nil {
		return Endpoints{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	if d.CodeChallengeMethods != nil && !slices.Contains(d.CodeChallengeMethods, "S256") {
		return Endpoints{}, fmt.Errorf("%s does not offer PKCE with S256 (it lists %s); port49 signs in with S256 only",
			p.Issuer, printsafe.Line(strings.Join(d.CodeChallengeMethods, ", "), 100))
	}
	return Endpoints{Authorization: d.AuthorizationEndpoint, Token: d.TokenEndpoint, IssParameter: d.IssParameter}, nil
}

// get is one GET of u at p: oidc.NewClient's TLS, timeout, proxy and no
// redirect; 200 and 1 MiB at most.
func get(ctx context.Context, p Provider, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	case resp.StatusCode >= 500:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("GET %s answered %s", u, resp.Status)}
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: GET %s answered %s", p.Issuer, u, resp.Status)
	case len(body) > maxBody:
		return nil, fmt.Errorf("%s: GET %s: over %d bytes", p.Issuer, u, maxBody)
	}
	return body, nil
}

// tokenResponse is the token endpoint's 200 (RFC 6749 §5.1), the members
// port49 reads.
type tokenResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// tokenRequest posts form to e's token endpoint. A transport fault or a 5xx
// is an *UnreachableError, any other refusal a *ProviderError; neither holds
// the form or the body.
func tokenRequest(ctx context.Context, p Provider, e Endpoints, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return tokenResponse{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return tokenResponse{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	case len(body) > maxBody:
		return tokenResponse{}, &UnreachableError{Issuer: p.Issuer, Err: errors.New("the token endpoint's answer is over 1 MiB")}
	case resp.StatusCode >= 500:
		return tokenResponse{}, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("the token endpoint answered %s", resp.Status)}
	case resp.StatusCode != http.StatusOK:
		var oe struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		return tokenResponse{}, &ProviderError{Issuer: p.Issuer, Status: resp.StatusCode,
			Code: printsafe.Line(oe.Error, 64), Description: printsafe.Line(oe.Description, 200)}
	}
	var t tokenResponse
	if json.Unmarshal(body, &t) != nil || t.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("%s: the token endpoint's answer carries no id_token", p.Issuer)
	}
	return t, nil
}

// exchange is the code's exchange (RFC 6749 §4.1.3, RFC 7636 §4.5): the
// verifier, no secret, and an ID token whose nonce is the request's.
func exchange(ctx context.Context, p Provider, e Endpoints, code, redirect, verifier, nonce string,
	now func() time.Time) (Tokens, error) {
	t, err := tokenRequest(ctx, p, e, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {p.ClientID}, "code_verifier": {verifier}})
	if err != nil {
		return Tokens{}, err
	}
	id, err := oidc.ReadIDToken(t.IDToken, p.Issuer, p.ClientID, nonce)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	return Tokens{ID: id, IDRaw: t.IDToken, Refresh: t.RefreshToken, Received: now().Round(0)}, nil
}

// Renew is the refresh-token grant (RFC 6749 §6; decision 43 ruling 9). The
// renewed ID token must name held's sub and keep its auth_time (OIDC Core
// §12.2): one that moved it is refused, since it would extend the session
// clock with no authentication. invalid_grant is ErrSessionEnded. Refresh is
// "" when the provider did not rotate it; the caller keeps the old one.
func Renew(ctx context.Context, p Provider, e Endpoints, refresh string, held oidc.IDToken,
	now func() time.Time) (Tokens, error) {
	t, err := tokenRequest(ctx, p, e, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {p.ClientID}, "scope": {strings.Join(p.Scopes, " ")}})
	var pe *ProviderError
	if errors.As(err, &pe) && pe.Code == "invalid_grant" {
		why := "invalid_grant"
		if pe.Description != "" {
			why += ": " + pe.Description
		}
		return Tokens{}, fmt.Errorf("%w (%s)", ErrSessionEnded, why)
	}
	if err != nil {
		return Tokens{}, err
	}
	id, err := oidc.ReadIDToken(t.IDToken, p.Issuer, p.ClientID, "")
	switch {
	case err != nil:
		return Tokens{}, fmt.Errorf("%s: the renewed %w", p.Issuer, err)
	case id.Subject != held.Subject:
		return Tokens{}, fmt.Errorf("%s: the renewed ID token names another sub than the session's", p.Issuer)
	case !id.AuthTime.Equal(held.AuthTime):
		return Tokens{}, fmt.Errorf("%s: the renewed ID token moved auth_time from %s to %s with no authentication "+
			"(OpenID Connect Core §12.2), so it is not used", p.Issuer, held.AuthTime.UTC().Format(time.RFC3339),
			id.AuthTime.UTC().Format(time.RFC3339))
	}
	return Tokens{ID: id, IDRaw: t.IDToken, Refresh: t.RefreshToken, Received: now().Round(0)}, nil
}
```

Create `internal/oidcclient/request.go`, the request `TestTheExchangeChecksTheNonce` builds and
Task 4's sign-in sends:

```go
package oidcclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// AuthorizationURL is the sign-in's request (decision 43 ruling 3) on e's
// authorization endpoint, keeping any query it already has: the code flow,
// the verifier's S256 challenge, state, nonce, the verifier's scopes with
// openid first, and prompt=login, at a login as at a refresh.
func AuthorizationURL(p Provider, e Endpoints, redirect, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(e.Authorization)
	if err != nil {
		return "", fmt.Errorf("%s's authorization_endpoint: %w", p.Issuer, err)
	}
	scopes := p.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "client_id": p.ClientID, "redirect_uri": redirect,
		"scope": strings.Join(scopes, " "), "state": state, "nonce": nonce, "code_challenge": challenge,
		"code_challenge_method": "S256", "prompt": "login"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// challengeOf is verifier's S256 code challenge (RFC 7636 §4.2).
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// opaque is 32 random bytes, base64url: a verifier, a state or a nonce of
// 43 characters (RFC 7636 §4.1).
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/oidc/... ./internal/oidcclient/ -count=1 && go test -race ./internal/oidcclient/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/client.go internal/oidc/client_test.go internal/oidcclient/
git commit -m "feat(oidcclient): read an ID token as a client, discovery, the code exchange and renewal"
```

---

### Task 4: The sign-in: the request, the loopback listener, and the pasted address

**Files:**
- Create: `internal/oidcclient/login.go`, `internal/oidcclient/login_test.go`

**Interfaces:**
- Consumes: Task 3's `Provider`, `Endpoints`, `Tokens`, `exchange`, `AuthorizationURL`,
  `challengeOf`, `opaque`; Task 2's `AuthServer`, `Issuer.Browser`, `Issuer.Redirected`;
  `printsafe.Line`.
- Produces, for Tasks 6 and 7:
  - `const SignInWait = 5 * time.Minute`
  - `type LoginOptions struct { Nonce string; Port int; Browser func(url string) error; Paste func() (string, error); Out io.Writer; Now func() time.Time }`
  - `func Login(ctx context.Context, p Provider, e Endpoints, o LoginOptions) (Tokens, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/oidcclient/login_test.go`:

```go
package oidcclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// credentialsNowhere fails if text holds any value the provider issued.
func credentialsNowhere(t *testing.T, text string, issued []string) {
	t.Helper()
	for _, v := range issued {
		if strings.Contains(text, v) {
			t.Fatalf("a code or token was printed")
		}
	}
}

// redirectOf is the redirect_uri an authorization URL names.
func redirectOf(t *testing.T, authURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := url.Parse(u.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The request is decision 43 ruling 3's, the redirect a loopback port, and
// the tokens the provider's; nothing printed holds a credential.
func TestASignInReturnsTokensForTheVerifier(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var out bytes.Buffer
	got, err := Login(context.Background(), p, e, LoginOptions{Browser: iss.Browser(), Out: &out})
	if err != nil || got.ID.Subject != "sub-alice" || got.Refresh == "" {
		t.Fatalf("%v %v\n%s", got, err, out.String())
	}
	q := as.Authorizations()[0]
	r, _ := url.Parse(q.Get("redirect_uri"))
	for k, want := range map[string]string{"response_type": "code", "client_id": "port49-cli", "scope": "openid",
		"code_challenge_method": "S256", "prompt": "login"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || len(q.Get("nonce")) != 43 ||
		r.Scheme != "http" || r.Hostname() != "127.0.0.1" || r.Port() == "0" || r.Path != "/callback" {
		t.Fatalf("the request: challenge %d state %d nonce %d redirect %s", len(q.Get("code_challenge")),
			len(q.Get("state")), len(q.Get("nonce")), r)
	}
	if !strings.Contains(out.String(), "in the browser that opened") {
		t.Fatalf("%s", out.String())
	}
	credentialsNowhere(t, out.String(), as.Issued())
	// The listener is gone once Login returns.
	if c, err := net.DialTimeout("tcp", r.Host, time.Second); err == nil {
		c.Close()
		t.Fatalf("%s still listens", r.Host)
	}
}

// A refresh's sign-in carries the broker's challenge as its nonce, and the
// ID token must echo it.
func TestTheChallengeIsTheNonce(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	got, err := Login(context.Background(), p, e, LoginOptions{Nonce: "challenge-n", Browser: iss.Browser()})
	if err != nil || got.ID.Nonce != "challenge-n" || as.Authorizations()[0].Get("nonce") != "challenge-n" {
		t.Fatalf("%v %v", got, err)
	}
}

// An answer with another state is refused and waited past: anyone on the
// host can reach the port (ruling 4).
func TestACallbackWithAnotherStateIsIgnored(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var status int
	browse := func(u string) error {
		r := redirectOf(t, u)
		resp, err := http.Get("http://" + r.Host + "/callback?state=forged&code=x")
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.StatusCode
		return iss.Browser()(u)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err != nil || status != 400 {
		t.Fatalf("forged answer %d, then %v", status, err)
	}
}

// An answer with this sign-in's state naming another issuer ends it (RFC
// 9207: a mix-up), and so does one with no iss from a provider that sends it.
func TestAnIssParameterNamingAnotherIssuerIsRefused(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	answer := func(extra string) func(string) error {
		return func(u string) error {
			v, _ := url.Parse(u)
			go func() {
				resp, err := http.Get(fmt.Sprintf("http://%s/callback?state=%s&code=x%s", redirectOf(t, u).Host,
					url.QueryEscape(v.Query().Get("state")), extra))
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		}
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("&iss=https%3A%2F%2Fevil.example")}); err == nil ||
		!strings.Contains(err.Error(), "RFC 9207") {
		t.Fatalf("another iss: %v", err)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("")}); err == nil ||
		!strings.Contains(err.Error(), "carries no iss") {
		t.Fatalf("no iss from a provider that sends it: %v", err)
	}
}

// A provider's refusal is said by its code.
func TestADeniedSignInSaysTheProvidersCode(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	as.Deny("access_denied")
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: iss.Browser()}); err == nil ||
		!strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("%v", err)
	}
}

// With no browser the address is printed and a pasted one completes the
// sign-in; a paste that is not this sign-in's answer is refused, saying
// why, and asked again (ruling 5).
func TestAPastedAddressCompletesTheSignIn(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	authURL := make(chan string, 1)
	var mu sync.Mutex
	var out bytes.Buffer
	pastes := 0
	paste := func() (string, error) {
		mu.Lock()
		pastes++
		n := pastes
		mu.Unlock()
		u := <-authURL
		authURL <- u
		if n == 1 {
			return "http://example.com/elsewhere", nil
		}
		return iss.Redirected(u)
	}
	got, err := Login(context.Background(), p, e, LoginOptions{
		Browser: func(u string) error { authURL <- u; return errors.New("no display") },
		Paste:   paste, Out: &lockedWriter{mu: &mu, w: &out}})
	mu.Lock()
	text := out.String()
	mu.Unlock()
	if err != nil || got.ID.Subject != "sub-alice" {
		t.Fatalf("%v %v\n%s", got, err, text)
	}
	for _, want := range []string{"open this address in a browser", "paste it here (it is not shown)",
		"that is not the address the sign-in was sent back to", "paste the address again"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %s", want, text)
		}
	}
	credentialsNowhere(t, text, as.Issued())
}

// A fixed port is the one the redirect names (oidc_redirect_port).
func TestAFixedPortIsUsed(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := Login(context.Background(), p, e, LoginOptions{Port: port, Browser: iss.Browser()}); err != nil {
		t.Fatal(err)
	}
	if r, _ := url.Parse(as.Authorizations()[0].Get("redirect_uri")); r.Port() != fmt.Sprint(port) {
		t.Fatalf("redirect %s, want port %d", r, port)
	}
}

// A cancelled sign-in stops listening and says so.
func TestACancelledSignInStops(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, p, e, LoginOptions{Browser: func(string) error { return nil }}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// lockedWriter serializes writes from Login and its paste reader.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidcclient/ -run 'TestASignIn|TestTheChallengeIsTheNonce|TestACallback|TestAnIssParameter|TestADenied|TestAPasted|TestAFixedPort|TestACancelled' -count=1`
Expected: FAIL to build: `undefined: Login`, `undefined: LoginOptions`.

- [ ] **Step 3: `internal/oidcclient/login.go`**

```go
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// SignInWait is how long a sign-in waits for the browser: the life of the
// broker's refresh challenge (spec §13 decision 39 ruling 15), so a
// refresh's sign-in never outlives the nonce it carries.
const SignInWait = 5 * time.Minute

// LoginOptions is one sign-in.
type LoginOptions struct {
	// Nonce is the request's nonce: the broker's challenge for a refresh,
	// or "" for a login, which draws its own.
	Nonce string
	// Port is the loopback listener's; 0 is an ephemeral one (RFC 8252 §7.3).
	Port int
	// Browser opens the authorization URL; nil, or an error, means no
	// browser opened.
	Browser func(url string) error
	// Paste, when not nil, reads one address the browser ended on, from a
	// terminal and not echoed (decision 43 ruling 5).
	Paste func() (string, error)
	// Out is where the address and the waiting line go: stderr.
	Out io.Writer
	Now func() time.Time
}

// Login runs one sign-in (decision 43 rulings 1, 3–5): the authorization
// request with PKCE (S256) and prompt=login, its answer taken at a
// 127.0.0.1 listener or pasted, and the code exchanged. The authorization
// URL is printed to o.Out: it carries state, the nonce and the
// code_challenge, none a credential, since the code is bound to the
// verifier this call holds.
func Login(ctx context.Context, p Provider, e Endpoints, o LoginOptions) (Tokens, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	verifier, state, nonce := opaque(), opaque(), o.Nonce
	if nonce == "" {
		nonce = opaque()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return Tokens{}, fmt.Errorf("listening on 127.0.0.1:%d for the sign-in's answer: %w", o.Port, err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	authURL, err := AuthorizationURL(p, e, redirect, state, nonce, challengeOf(verifier))
	if err != nil {
		ln.Close()
		return Tokens{}, err
	}
	w := &waiter{state: state, issuer: p.Issuer, requireIss: e.IssParameter, redirect: redirect,
		done: make(chan answer, 1)}
	srv := &http.Server{Handler: w, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	if o.Browser != nil && o.Browser(authURL) == nil {
		fmt.Fprintf(o.Out, "port49: sign in at %s in the browser that opened; if none did, open this address:\n  %s\n",
			p.Issuer, authURL)
	} else {
		fmt.Fprintf(o.Out, "port49: open this address in a browser and sign in at %s:\n  %s\n", p.Issuer, authURL)
	}
	if o.Paste != nil {
		fmt.Fprintf(o.Out, "port49: waiting up to %s. If the browser ends on a page that cannot be reached (it runs on "+
			"another host), copy that page's address and paste it here (it is not shown), then press Enter:\n", SignInWait)
		go w.readPastes(o.Paste, o.Out)
	}
	wait, cancel := context.WithTimeout(ctx, SignInWait)
	defer cancel()
	var a answer
	select {
	case a = <-w.done:
	case <-wait.Done():
		if ctx.Err() != nil {
			return Tokens{}, ctx.Err()
		}
		return Tokens{}, fmt.Errorf("no sign-in answer reached port49 within %s; run the command again", SignInWait)
	}
	if a.err != nil {
		return Tokens{}, a.err
	}
	return exchange(ctx, p, e, a.code, redirect, verifier, nonce, o.Now)
}

// answer is a sign-in's outcome: a code, or why there is none.
type answer struct {
	code string
	err  error
}

// waiter takes the provider's answer at /callback, or pasted. The first
// answer carrying this sign-in's state ends the wait; one carrying another
// state is refused and waited past, since anyone on the host can reach the
// port (decision 43 ruling 4).
type waiter struct {
	state, issuer, redirect string
	requireIss              bool
	once                    sync.Once
	done                    chan answer
}

func (w *waiter) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodGet || r.URL.Path != "/callback" {
		http.NotFound(rw, r)
		return
	}
	a, ours := w.judge(r.URL.Query())
	if !ours {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: this is not the sign-in port49 is waiting for; nothing was done.")
		return
	}
	w.deliver(a)
	if a.err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: the sign-in failed; your terminal says why.")
		return
	}
	fmt.Fprintln(rw, "port49: signed in. You can close this tab and go back to your terminal.")
}

// deliver hands the first answer to Login; later ones are dropped.
func (w *waiter) deliver(a answer) { w.once.Do(func() { w.done <- a }) }

// judge reads one answer's query (RFC 6749 §4.1.2, RFC 9207 §2.4). ours is
// whether it carries this sign-in's state, and only then is it judged.
func (w *waiter) judge(q url.Values) (answer, bool) {
	if len(q["state"]) != 1 || q.Get("state") != w.state {
		return answer{}, false
	}
	switch iss, has := q.Get("iss"), q.Has("iss"); {
	case has && iss != w.issuer:
		return answer{err: fmt.Errorf("the sign-in's answer names the issuer %q, not %s: it came from another "+
			"provider (RFC 9207), so it is refused", printsafe.Line(iss, 200), w.issuer)}, true
	case !has && w.requireIss:
		return answer{err: fmt.Errorf("the sign-in's answer carries no iss, which %s says it always sends (RFC 9207), "+
			"so it is refused", w.issuer)}, true
	}
	if e := q.Get("error"); e != "" {
		msg := fmt.Sprintf("%s refused the sign-in: %s", w.issuer, printsafe.Line(e, 64))
		if d := q.Get("error_description"); d != "" {
			msg += ": " + printsafe.Line(d, 200)
		}
		return answer{err: errors.New(msg)}, true
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return answer{err: errors.New("the sign-in's answer carries no code")}, true
	}
	return answer{code: q.Get("code")}, true
}

// readPastes reads pasted addresses until one is this sign-in's answer, or
// paste fails (the terminal closed). Nothing pasted is printed.
func (w *waiter) readPastes(paste func() (string, error), out io.Writer) {
	for {
		s, err := paste()
		if err != nil {
			return
		}
		a, why := w.pasted(s)
		if why != "" {
			fmt.Fprintf(out, "port49: %s; paste the address again:\n", why)
			continue
		}
		w.deliver(a)
		return
	}
}

// pasted is one pasted address as an answer, or why it is not one.
func (w *waiter) pasted(s string) (answer, string) {
	u, err := url.Parse(strings.TrimSpace(s))
	want, _ := url.Parse(w.redirect)
	if err != nil || u.Scheme != want.Scheme || u.Host != want.Host || u.Path != want.Path {
		return answer{}, "that is not the address the sign-in was sent back to (" + w.redirect + "?…)"
	}
	a, ours := w.judge(u.Query())
	if !ours {
		return answer{}, "that address answers another sign-in (its state is not this one's)"
	}
	return a, ""
}
```

`AuthorizationURL`, `challengeOf` and `opaque` are Task 3's, in `request.go`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/oidcclient/ -count=1 && go test -race ./internal/oidcclient/ -count=1 && go vet ./internal/oidcclient/`
Expected: PASS, and vet silent.

- [ ] **Step 5: Commit**

```bash
git add internal/oidcclient/login.go internal/oidcclient/login_test.go
git commit -m "feat(oidcclient): the sign-in over a loopback redirect with PKCE, state, nonce and iss, and a pasted address"
```

---

### Task 5: The agent holds an OIDC session: the bearer, silent renewal, and the provider down

**Files:**
- Create: `internal/agent/oidc.go`, `internal/agent/oidc_test.go`
- Modify: `internal/agent/agent.go` (`Config`, `Agent`, `New`, `end` (and `endBy`, new), `Connect`,
  `post`, `exchange`, `doOn`, the four `sessionOver` call sites, `Status`, `Handler`, `answer`)
- Modify: `internal/agent/socket.go` (`Client.Token`, `roundTrip`)

**Interfaces:**
- Consumes: Task 3's `oidc.ReadIDToken`, `oidc.IDToken`, `oidcclient.Provider`, `Endpoints`,
  `Tokens`, `Renew`, `Discover`, `ErrSessionEnded`; Task 2's `AuthServer` and
  `api.OIDCProvider.MaxTokenAgeSeconds`; the agent's `ErrSessionOver`, `RevokedError`, `sessionOver`,
  `unavailable`, `drain`, `writeJSON`, `socketFor` (test).
- Produces, for Tasks 6 and 7:
  - `type OIDCConfig struct { Provider oidcclient.Provider; Endpoints oidcclient.Endpoints; Tokens oidcclient.Tokens; CAPEM []byte; RedirectPort int }`
  - `Config.OIDC *OIDCConfig`
  - `type RenewFailedError struct { Issuer string; Ended, SessionEndsAt time.Time; Err error; Detail string }`
  - `Status.Method string` (`json:"method,omitempty"`), `Status.OIDCIssuer string` (`json:"oidc_issuer,omitempty"`)
  - `(*oidcSession).current() oidcclient.Tokens`, `(*oidcSession).install(oidcclient.Tokens)`;
    `bearerKey{}` (a request context key: the bearer a request carries in place of the held one);
    `final(error) bool`; `(*Agent).over(status int, e api.Error) error`

- [ ] **Step 1: Write the failing tests**

Create `internal/agent/oidc_test.go`:

```go
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/oidcclient"
)

// oidcBroker is a broker on the OIDC path as the agent meets it. GET
// /v1/config lists iss (unless unlisted); every other route reads the
// bearer as a client would and refuses one past its exp by the broker's
// clock, or the next refuseNext of them, 401 trust_domain_unresolved. It
// answers Connection: close, as the broker answers a certificate-less
// request (plan 7h).
type oidcBroker struct {
	iss  *oidctest.Issuer
	now  func() time.Time
	url  string
	pool *x509.CertPool

	mu          sync.Mutex
	maxTokenAge int
	unlisted    bool
	refuseNext  int
	revoked     bool
	unavailable bool
	refreshCode string
	nonce       string
	bearers     []string
	refreshes   []string
	certs       int
}

func newOIDCBroker(t *testing.T, iss *oidctest.Issuer, now func() time.Time) *oidcBroker {
	t.Helper()
	fb := &oidcBroker{iss: iss, now: now}
	srv := httptest.NewUnstartedServer(fb)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	fb.url = srv.URL
	fb.pool = x509.NewCertPool()
	fb.pool.AddCert(srv.Certificate())
	return fb
}

func (fb *oidcBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fb.certs++
	}
	w.Header().Set("Connection", "close")
	if r.URL.Path == "/v1/config" {
		c := api.Config{Methods: []string{"oidc"}, MaxSessionAgeSeconds: 3600, BatchMax: 4, CeilingWarningSeconds: 1800}
		if !fb.unlisted {
			c.OIDC = []api.OIDCProvider{{Issuer: fb.iss.URL, ClientID: "port49-cli", Scopes: []string{"openid"},
				MaxTokenAgeSeconds: fb.maxTokenAge}}
		}
		writeJSON(w, http.StatusOK, c)
		return
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	fb.bearers = append(fb.bearers, raw)
	tok, err := oidc.ReadIDToken(raw, fb.iss.URL, "port49-cli", "")
	if err != nil || !fb.now().Before(tok.Expires) || fb.refuseNext > 0 {
		if fb.refuseNext > 0 {
			fb.refuseNext--
		}
		writeJSON(w, http.StatusUnauthorized, api.Error{Error: "trust_domain_unresolved", Detail: "the token has expired"})
		return
	}
	switch r.URL.Path {
	case "/v1/identity":
		writeJSON(w, http.StatusOK, api.Identity{Principal: "user:alice@example.com", Method: "oidc"})
	case "/v1/tokens":
		switch {
		case fb.revoked:
			writeJSON(w, http.StatusUnauthorized, api.Error{Error: "credential_revoked", Detail: "your identity provider " +
				"ended your sessions at 2026-10-09T03:00:00Z (back-channel logout); log in again from 2026-10-09T03:01:01Z"})
		case fb.unavailable:
			w.Header().Set("Retry-After", "30")
			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "identity_provider_unavailable",
				Detail: "the broker cannot use your identity provider's keys right now, so it minted nothing; retry shortly"})
		default:
			var req api.MintRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			writeJSON(w, http.StatusOK, api.MintResponse{Principal: "user:alice@example.com", Results: []api.MintItem{{
				Device: req.Devices[0], Verdict: "permit", Username: "alice", Login: "LOGIN-TOKEN"}}})
		}
	case "/v1/refresh/challenge":
		fb.nonce = fmt.Sprintf("challenge-%d", len(fb.bearers))
		writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: fb.nonce,
			ExpiresAt: fb.now().Add(5 * time.Minute).UTC().Format(time.RFC3339)})
	case "/v1/refresh":
		fb.refreshes = append(fb.refreshes, raw)
		switch {
		case tok.Nonce != fb.nonce:
			writeJSON(w, http.StatusUnauthorized, api.Error{Error: "refresh_challenge_missing",
				Detail: "the token's nonce is no live challenge of this broker's"})
		case fb.refreshCode != "":
			writeJSON(w, http.StatusUnauthorized, api.Error{Error: fb.refreshCode, Detail: "your identity provider did " +
				"not authenticate you again (prompt=login was not honoured); the session was not extended"})
		default:
			ends := tok.AuthTime.Add(time.Hour).UTC().Format(time.RFC3339)
			writeJSON(w, http.StatusOK, api.RefreshResponse{AuthTime: tok.AuthTime.UTC().Format(time.RFC3339),
				SessionEndsAt: ends, Sessions: []api.RefreshedSession{{Device: "leaf1", Username: "alice",
					Outcome: "extended", SessionExpires: ends}}})
		}
	default:
		http.NotFound(w, r)
	}
}

// oidcLog is an agent log tests read while the agent writes it.
type oidcLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *oidcLog) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *oidcLog) String() string             { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// oidcRig is an OIDC agent on a fake broker, holding a sign-in from an
// authorization server; the three share the rig's clock, which stands
// still unless advanced (real: the wall clock).
type oidcRig struct {
	iss  *oidctest.Issuer
	as   *oidctest.AuthServer
	fb   *oidcBroker
	a    *Agent
	log  oidcLog
	mu   sync.Mutex
	at   time.Time
	real bool
}

func (r *oidcRig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.real {
		return time.Now().Round(0)
	}
	return r.at
}

func (r *oidcRig) advance(d time.Duration) { r.mu.Lock(); r.at = r.at.Add(d); r.mu.Unlock() }

// newOIDCRig builds the rig, runs setup, and connects the agent.
func newOIDCRig(t *testing.T, setup func(*oidcRig)) *oidcRig {
	t.Helper()
	r := &oidcRig{at: time.Now().Round(0)}
	r.iss = oidctest.NewIssuer(t)
	r.as = r.iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	r.as.Now = r.clock
	r.fb = newOIDCBroker(t, r.iss, r.clock)
	if setup != nil {
		setup(r)
	}
	a, err := r.dial(t)
	if err != nil {
		t.Fatalf("connect: %v\n%s", err, r.log.String())
	}
	r.a = a
	return r
}

// dial is a new agent holding a fresh sign-in, connected.
func (r *oidcRig) dial(t *testing.T) (*Agent, error) {
	t.Helper()
	p := oidcclient.Provider{Issuer: r.iss.URL, ClientID: "port49-cli", Scopes: []string{"openid"}, Roots: r.iss.Roots()}
	e, err := oidcclient.Discover(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	raw, rt := r.as.SignIn(t, "")
	id, err := oidc.ReadIDToken(raw, r.iss.URL, "port49-cli", "")
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{BrokerURL: r.fb.url, BrokerCA: r.fb.pool, Now: r.clock, Log: &r.log,
		OIDC: &OIDCConfig{Provider: p, Endpoints: e, CAPEM: r.iss.CertPEM(),
			Tokens: oidcclient.Tokens{ID: id, IDRaw: raw, Refresh: rt, Received: r.clock()}}})
	t.Cleanup(func() { a.end(errors.New("the test is over")) })
	_, err = a.Connect(context.Background())
	return a, err
}

func (r *oidcRig) mint() (api.MintItem, error) {
	return r.a.Mint(context.Background(), "leaf1", false, time.Minute)
}

// lastGrant is the provider's last /token form's grant_type.
func (r *oidcRig) lastGrant() string {
	g := r.as.Grants()
	if len(g) == 0 {
		return ""
	}
	return g[len(g)-1].Get("grant_type")
}

// noCredentials fails if the agent's log holds any value the provider issued.
func (r *oidcRig) noCredentials(t *testing.T) {
	t.Helper()
	for _, v := range r.as.Issued() {
		if strings.Contains(r.log.String(), v) {
			t.Fatal("the agent's log holds a token")
		}
	}
}

func ended(a *Agent) bool {
	select {
	case <-a.Done():
		return true
	default:
		return false
	}
}

// Every request carries the held ID token as its bearer and no client
// certificate, each on its own connection, with no "reconnected" line
// (decision 43 ruling 8).
func TestAnOIDCSessionSendsItsIDTokenAsTheBearer(t *testing.T) {
	r := newOIDCRig(t, nil)
	if _, err := r.mint(); err != nil {
		t.Fatal(err)
	}
	r.fb.mu.Lock()
	bearers, certs := append([]string(nil), r.fb.bearers...), r.fb.certs
	r.fb.mu.Unlock()
	if certs != 0 || len(bearers) != 2 || bearers[0] != r.a.oidc.current().IDRaw || bearers[1] != bearers[0] {
		t.Fatalf("%d certificates, %d bearers", certs, len(bearers))
	}
	if r.a.Handshakes() < 3 || strings.Contains(r.log.String(), "reconnected") {
		t.Fatalf("handshakes %d, log %s", r.a.Handshakes(), r.log.String())
	}
}

// The usable life is the token's own, from receipt, never its exp read
// against this host's clock (ruling 9; R7).
func TestTheUsableLifeIsCountedFromReceipt(t *testing.T) {
	recv := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	iat := recv.Add(-3 * time.Hour) // this host three hours ahead of the provider
	tok := oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: iat, Expires: iat.Add(5 * time.Minute)}, Received: recv}
	if got := usableEnd(tok, 0); !got.Equal(recv.Add(5 * time.Minute)) {
		t.Fatalf("usable end %s", got)
	}
	if got := renewAt(tok, 0); !got.Equal(recv.Add(225 * time.Second)) {
		t.Fatalf("renew at %s", got)
	}
	tok.ID.Expires = iat.Add(24 * time.Hour)
	if got := usableEnd(tok, 2*time.Hour); !got.Equal(recv.Add(2 * time.Hour)) {
		t.Fatalf("max_token_age: %s", got)
	}
}

// Within nearEnd of its usable end the token is renewed before the request;
// the renewed one keeps auth_time.
func TestTheIDTokenIsRenewedBeforeItsUsableEnd(t *testing.T) {
	r := newOIDCRig(t, nil)
	first := r.a.oidc.current()
	r.advance(290 * time.Second)
	if _, err := r.mint(); err != nil {
		t.Fatal(err)
	}
	now := r.a.oidc.current()
	if r.lastGrant() != "refresh_token" || now.IDRaw == first.IDRaw || !now.ID.AuthTime.Equal(first.ID.AuthTime) {
		t.Fatalf("grant %q, renewed %v, auth_time kept %v", r.lastGrant(), now.IDRaw != first.IDRaw,
			now.ID.AuthTime.Equal(first.ID.AuthTime))
	}
}

// /v1/config's max_token_age_seconds caps a long-lived token's usable life
// (ruling 14).
func TestMaxTokenAgeShortensTheUsableLife(t *testing.T) {
	r := newOIDCRig(t, func(r *oidcRig) {
		r.as.SetLifetime(time.Hour)
		r.fb.maxTokenAge = 600
	})
	r.advance(590 * time.Second)
	if _, err := r.mint(); err != nil || r.lastGrant() != "refresh_token" {
		t.Fatalf("%v, last grant %q", err, r.lastGrant())
	}
}

// A token the broker refuses as expired (a laptop that slept, a skewed
// clock) is renewed once and the request sent again; the session goes on.
func TestATokenAgedOutUnderSleepIsRenewedAndSentAgain(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.fb.mu.Lock()
	r.fb.refuseNext = 1
	r.fb.mu.Unlock()
	if _, err := r.mint(); err != nil || ended(r.a) {
		t.Fatalf("%v, ended %v", err, ended(r.a))
	}
	r.fb.mu.Lock()
	b := r.fb.bearers
	r.fb.mu.Unlock()
	if r.lastGrant() != "refresh_token" || b[len(b)-1] == b[len(b)-2] {
		t.Fatalf("not renewed and resent: grant %q", r.lastGrant())
	}
	// Refused twice, the session ends in the provider's words, not a certificate's.
	r.fb.mu.Lock()
	r.fb.refuseNext = 2
	r.fb.mu.Unlock()
	if _, err := r.mint(); !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "identity provider's token") ||
		strings.Contains(err.Error(), "certificate") {
		t.Fatalf("%v", err)
	}
}

// The provider down: the held token is used to its usable end, then each
// call is a RenewFailedError that ends nothing and never says to log in;
// once the provider answers, the next call renews and mints (ruling 10).
func TestAProviderOutageEndsNothing(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.as.FailRefresh(http.StatusServiceUnavailable, "temporarily_unavailable")
	r.advance(290 * time.Second)
	if _, err := r.mint(); err != nil {
		t.Fatalf("within the token's life: %v", err)
	}
	r.advance(20 * time.Second)
	_, err := r.mint()
	var rf *RenewFailedError
	if !errors.As(err, &rf) || errors.Is(err, ErrSessionOver) || strings.Contains(err.Error(), "port49 login") ||
		!strings.Contains(err.Error(), "did not renew your ID token") || ended(r.a) {
		t.Fatalf("past it: %v, ended %v", err, ended(r.a))
	}
	// Over the socket: 503 identity_provider_unreachable, the same words.
	if _, err := socketFor(t, r.a).Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.As(err, &rf) ||
		!strings.Contains(err.Error(), "did not renew your ID token") {
		t.Fatalf("over the socket: %v", err)
	}
	r.as.FailRefresh(0, "")
	if _, err := r.mint(); err != nil {
		t.Fatalf("once the provider answers: %v", err)
	}
	if l := r.log.String(); !strings.Contains(l, "renewing the ID token failed") || !strings.Contains(l, "renewed again") {
		t.Fatalf("log: %s", l)
	}
	r.noCredentials(t)
}

// invalid_grant is the provider ending the session: the agent ends, saying
// to log in (ruling 10).
func TestInvalidGrantEndsTheSession(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.as.FailRefresh(http.StatusBadRequest, "invalid_grant")
	r.advance(290 * time.Second)
	_, err := r.mint()
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "port49 login") ||
		!strings.Contains(err.Error(), "invalid_grant") || !ended(r.a) {
		t.Fatalf("%v, ended %v", err, ended(r.a))
	}
	if !strings.Contains(r.log.String(), "your identity provider ended the session") {
		t.Fatalf("the log blames someone else: %s", r.log.String())
	}
	r.noCredentials(t)
}

// A renewal that moves auth_time is not used: the held token goes on to
// its end, and the failure names auth_time (R8).
func TestARenewalThatMovesAuthTimeIsNotUsed(t *testing.T) {
	r := newOIDCRig(t, func(r *oidcRig) { r.as.SetAuthTime(r.at.Add(-30 * time.Minute)) })
	r.as.MoveAuthTimeOnRefresh()
	first := r.a.oidc.current()
	r.advance(290 * time.Second)
	if _, err := r.mint(); err != nil || r.a.oidc.current().IDRaw != first.IDRaw {
		t.Fatalf("%v, token replaced %v", err, r.a.oidc.current().IDRaw != first.IDRaw)
	}
	r.advance(20 * time.Second)
	if _, err := r.mint(); err == nil || !strings.Contains(err.Error(), "auth_time") {
		t.Fatalf("%v", err)
	}
}

// A back-channel logout ends the session in the broker's words (ruling 11).
func TestALogoutEndsTheOIDCSessionWithTheBrokersWords(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.fb.mu.Lock()
	r.fb.revoked = true
	r.fb.mu.Unlock()
	_, err := r.mint()
	var rv *RevokedError
	if !errors.As(err, &rv) || !strings.Contains(err.Error(), "back-channel logout") || !ended(r.a) {
		t.Fatalf("%v, ended %v", err, ended(r.a))
	}
}

// The broker's own key outage is retried later and ends nothing.
func TestTheBrokersKeyOutageEndsNothing(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.fb.mu.Lock()
	r.fb.unavailable = true
	r.fb.mu.Unlock()
	if _, err := r.mint(); err == nil || !strings.Contains(err.Error(), "identity_provider_unavailable") ||
		!strings.Contains(err.Error(), "retry in 30s") || ended(r.a) {
		t.Fatalf("%v, ended %v", err, ended(r.a))
	}
}

// The session ends max_session_age after auth_time, reckoned from receipt
// (ruling 13).
func TestAnOIDCSessionEndsAtAuthTimePlusMaxSessionAge(t *testing.T) {
	r := newOIDCRig(t, func(r *oidcRig) { r.as.SetAuthTime(r.at.Add(-30 * time.Minute)) })
	if got, want := r.a.SessionEndsAt(), r.at.Add(30*time.Minute); !got.Equal(want) {
		t.Fatalf("ends %s, want %s", got, want)
	}
}

// Without a refresh token the session ends with the ID token.
func TestWithoutARefreshTokenTheSessionEndsWithTheIDToken(t *testing.T) {
	r := newOIDCRig(t, func(r *oidcRig) { r.as.NoRefreshToken() })
	if got, want := r.a.SessionEndsAt(), r.at.Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("ends %s, want %s", got, want)
	}
	r.advance(310 * time.Second)
	if _, err := r.mint(); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("%v", err)
	}
}

// A broker that does not list the session's provider fails Connect.
func TestTheBrokerNotListingTheProviderFailsConnect(t *testing.T) {
	r := &oidcRig{at: time.Now().Round(0)}
	r.iss = oidctest.NewIssuer(t)
	r.as = r.iss.AuthServer(t, "port49-cli", "sub-alice", nil)
	r.as.Now = r.clock
	r.fb = newOIDCBroker(t, r.iss, r.clock)
	r.fb.unlisted = true
	if _, err := r.dial(t); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Fatalf("%v", err)
	}
}

// GET /status names the method and the provider (ruling 16).
func TestStatusNamesTheMethodAndIssuer(t *testing.T) {
	r := newOIDCRig(t, nil)
	st, err := socketFor(t, r.a).Status(context.Background())
	if err != nil || st.Method != "oidc" || st.OIDCIssuer != r.iss.URL || st.CertFingerprint != "" {
		t.Fatalf("%+v %v", st, err)
	}
}

// The loop renews with no request at three quarters of the token's life.
func TestTheRenewalLoopRenewsWithNoRequest(t *testing.T) {
	r := newOIDCRig(t, func(r *oidcRig) {
		r.real = true
		r.as.SetLifetime(4 * time.Second)
	})
	for deadline := time.Now().Add(6 * time.Second); r.lastGrant() != "refresh_token"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no renewal within 6s of a 4s token")
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/agent/ -run 'OIDC|UsableLife|Renew|MaxTokenAge|AgedOut|ProviderOutage|InvalidGrant|KeyOutage|NotListing|MethodAndIssuer' -count=1`
Expected: FAIL to build: `unknown field OIDC in struct literal of type Config`, `undefined: OIDCConfig`.

- [ ] **Step 3: `internal/agent/oidc.go`**

```go
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidcclient"
)

// OIDCConfig is an OIDC session's start (plan 9b; spec §13 decision 43): the
// provider, its endpoints and the sign-in's tokens, which the agent holds in
// memory alone (ruling 7).
type OIDCConfig struct {
	Provider  oidcclient.Provider
	Endpoints oidcclient.Endpoints
	Tokens    oidcclient.Tokens
	// CAPEM is Provider.Roots as PEM, for a refresh's sign-in; nil is the
	// system's roots.
	CAPEM []byte
	// RedirectPort is the loopback port a sign-in listens on; 0 is ephemeral.
	RedirectPort int
}

// String withholds the tokens.
func (c OIDCConfig) String() string {
	return fmt.Sprintf("OIDCConfig{%s %s %v}", c.Provider.Issuer, c.Provider.ClientID, c.Tokens)
}

// GoString is String.
func (c OIDCConfig) GoString() string { return c.String() }

// Renewal's timings (rulings 9 and 10). Vars so a test can shorten them.
var (
	// renewWait bounds one renewal.
	renewWait = 10 * time.Second
	// renewRetry is how often a renewal that failed is tried again.
	renewRetry = 30 * time.Second
	// nearEnd is how near its usable end a token is renewed before a
	// request is sent with it.
	nearEnd = 15 * time.Second
)

// oidcSession is what an OIDC agent holds in place of the certificate
// path's connection: the tokens, renewed in the background and before a
// request that would carry one too old (rulings 7–10).
type oidcSession struct {
	cfg      OIDCConfig
	now      func() time.Time
	log      io.Writer
	end      func(error)
	deadline func() time.Time
	renew    func(ctx context.Context, refresh string, held oidc.IDToken) (oidcclient.Tokens, error)

	// renewMu runs one renewal at a time.
	renewMu sync.Mutex

	mu          sync.Mutex
	tokens      oidcclient.Tokens
	maxTokenAge time.Duration
	failing     error // the last renewal's failure; nil after a success
	ended       error // set once the session is over
	installed   chan struct{}
}

func newOIDCSession(c OIDCConfig, now func() time.Time, log io.Writer, end func(error),
	deadline func() time.Time) *oidcSession {
	s := &oidcSession{cfg: c, now: now, log: log, end: end, deadline: deadline, tokens: c.Tokens,
		installed: make(chan struct{}, 1)}
	s.renew = func(ctx context.Context, refresh string, held oidc.IDToken) (oidcclient.Tokens, error) {
		return oidcclient.Renew(ctx, c.Provider, c.Endpoints, refresh, held, now)
	}
	return s
}

// current is the held tokens.
func (s *oidcSession) current() oidcclient.Tokens {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

func (s *oidcSession) setMaxTokenAge(d time.Duration) {
	s.mu.Lock()
	s.maxTokenAge = d
	s.mu.Unlock()
}

// usableEnd is when t stops being sent: its own life (exp − iat), capped by
// max_token_age, counted from when it arrived on this host's clock; never
// its exp read against this clock, which may disagree with the provider's
// (ruling 9).
func usableEnd(t oidcclient.Tokens, maxTokenAge time.Duration) time.Time {
	life := t.ID.Expires.Sub(t.ID.IssuedAt)
	if maxTokenAge > 0 && maxTokenAge < life {
		life = maxTokenAge
	}
	return t.Received.Add(life)
}

// renewAt is three quarters of the way from t's arrival to its usable end.
func renewAt(t oidcclient.Tokens, maxTokenAge time.Duration) time.Time {
	return t.Received.Add(usableEnd(t, maxTokenAge).Sub(t.Received) * 3 / 4)
}

// bearer is the ID token a request carries. Within nearEnd of its usable
// end it is renewed first; a renewal that fails leaves it in use until that
// end. force renews whatever its age: the broker refused it. Past the end
// with no renewal it is a *RenewFailedError; with no refresh token, or once
// the provider ended the session, ErrSessionOver.
func (s *oidcSession) bearer(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	t, ended, maxAge := s.tokens, s.ended, s.maxTokenAge
	s.mu.Unlock()
	if ended != nil {
		return "", ended
	}
	end, now := usableEnd(t, maxAge), s.now()
	if !force && now.Before(end.Add(-nearEnd)) {
		return t.IDRaw, nil
	}
	if t.Refresh == "" {
		if !force && now.Before(end) {
			return t.IDRaw, nil
		}
		over := fmt.Errorf("%w: your identity provider issued no refresh token, so the session ended with its ID "+
			"token at %s", ErrSessionOver, end.UTC().Format(time.RFC3339))
		s.finish(over)
		return "", over
	}
	nt, err := s.renewNow(ctx, t)
	switch {
	case err == nil:
		return nt.IDRaw, nil
	case errors.Is(err, ErrSessionOver):
		return "", err
	case !force && now.Before(end):
		return t.IDRaw, nil // still usable; the loop tries again
	}
	if force && now.Before(end) {
		end = now // the broker refused it now
	}
	return "", &RenewFailedError{Issuer: s.cfg.Provider.Issuer, Ended: end, SessionEndsAt: s.deadline(), Err: err}
}

// renewNow renews once, unless a renewal that finished while this one
// waited for renewMu already replaced seen. invalid_grant ends the session.
func (s *oidcSession) renewNow(ctx context.Context, seen oidcclient.Tokens) (oidcclient.Tokens, error) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	s.mu.Lock()
	cur, ended := s.tokens, s.ended
	s.mu.Unlock()
	switch {
	case ended != nil:
		return oidcclient.Tokens{}, ended
	case cur.IDRaw != seen.IDRaw:
		return cur, nil
	}
	ctx, cancel := context.WithTimeout(ctx, renewWait)
	defer cancel()
	nt, err := s.renew(ctx, cur.Refresh, cur.ID)
	switch {
	case errors.Is(err, oidcclient.ErrSessionEnded):
		over := fmt.Errorf("%w: %v", ErrSessionOver, err)
		s.finish(over)
		return oidcclient.Tokens{}, over
	case err != nil:
		s.mu.Lock()
		first := s.failing == nil
		s.failing = err
		s.mu.Unlock()
		if first {
			fmt.Fprintf(s.log, "port49 agent: renewing the ID token failed: %v; trying again every %s\n", err, renewRetry)
		}
		return oidcclient.Tokens{}, err
	}
	if nt.Refresh == "" {
		nt.Refresh = cur.Refresh // not rotated
	}
	s.install(nt)
	return nt, nil
}

// install holds t from now on, and wakes the loop to reckon from it.
func (s *oidcSession) install(t oidcclient.Tokens) {
	s.mu.Lock()
	recovered := s.failing != nil
	s.tokens, s.failing = t, nil
	s.mu.Unlock()
	if recovered {
		fmt.Fprintln(s.log, "port49 agent: the ID token was renewed again")
	}
	select {
	case s.installed <- struct{}{}:
	default:
	}
}

// finish ends the session with why, once.
func (s *oidcSession) finish(why error) {
	s.mu.Lock()
	if s.ended == nil {
		s.ended = why
	}
	s.mu.Unlock()
	s.end(why)
}

// run renews the held token at renewAt, and every renewRetry while renewal
// fails, until done closes, the session ends, or it holds no refresh token.
func (s *oidcSession) run(done <-chan struct{}) {
	for {
		s.mu.Lock()
		t, failing, ended, maxAge := s.tokens, s.failing, s.ended, s.maxTokenAge
		s.mu.Unlock()
		if ended != nil || t.Refresh == "" {
			return
		}
		wait := renewAt(t, maxAge).Sub(s.now())
		if failing != nil {
			wait = renewRetry
		}
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-done:
			timer.Stop()
			return
		case <-s.installed:
			timer.Stop()
			continue
		case <-timer.C:
		}
		_, _ = s.renewNow(context.Background(), t)
	}
}

// RenewFailedError is a request not sent: the held ID token's usable life
// is over and the provider did not renew it (ruling 10). It ends nothing;
// the agent keeps trying. Detail is the whole line, when it came back
// through the agent's socket.
type RenewFailedError struct {
	Issuer        string
	Ended         time.Time
	SessionEndsAt time.Time
	Err           error
	Detail        string
}

func (e *RenewFailedError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("agent: your identity provider at %s did not renew your ID token (%v); it ended at %s, so "+
		"nothing was sent to the broker; the agent tries again every %s, and your session lasts until %s; run the "+
		"command again once the provider answers", e.Issuer, e.Err, e.Ended.UTC().Format(time.RFC3339), renewRetry,
		e.SessionEndsAt.UTC().Format(time.RFC3339))
}

func (e *RenewFailedError) Unwrap() error { return e.Err }

// final reports whether err is the OIDC session's own, which no resend
// changes: the session is over, or its token could not be renewed. A caller
// returns it as it is, never as "the broker is unreachable".
func final(err error) bool {
	var rf *RenewFailedError
	return errors.Is(err, ErrSessionOver) || errors.As(err, &rf)
}

// bearerKey carries, on a request's context, the ID token the request
// carries in place of the held one: a refresh's new token (ruling 12).
type bearerKey struct{}

// withBearer is req with tok as its bearer.
func withBearer(req *http.Request, tok string) *http.Request {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// bearerDo is doOn on the OIDC path (ruling 8): the held ID token as the
// bearer, or the one bearerKey names. A 401 trust_domain_unresolved to the
// held token is answered once by renewing it and sending the request again:
// a token can age out under a sleeping laptop or a clock the broker's
// disagrees with. A renewal that fails then is the provider's fault, not
// the broker's refusal, and ends nothing.
func (a *Agent) bearerDo(c *http.Client, req *http.Request) (*http.Response, error) {
	if tok, ok := req.Context().Value(bearerKey{}).(string); ok {
		return c.Do(withBearer(req, tok))
	}
	tok, err := a.oidc.bearer(req.Context(), false)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(withBearer(req, tok))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var e api.Error
	resendable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	if json.Unmarshal(body, &e) != nil || e.Error != "trust_domain_unresolved" || !resendable {
		return resp, nil
	}
	tok, err = a.oidc.bearer(req.Context(), true)
	if err != nil {
		return nil, err
	}
	again := req.Clone(req.Context())
	if req.GetBody != nil {
		if again.Body, err = req.GetBody(); err != nil {
			return resp, nil
		}
	}
	return c.Do(withBearer(again, tok))
}

// over is sessionOver for this session. On the OIDC path a token the broker
// refuses after a renewal, and a principal it cannot map, end it too, in
// words that name the provider, never a certificate (ruling 11).
func (a *Agent) over(status int, e api.Error) error {
	if a.oidc != nil && status == http.StatusUnauthorized {
		switch e.Error {
		case "trust_domain_unresolved":
			return fmt.Errorf("%w: the broker refuses your identity provider's token, renewed or not (%s)",
				ErrSessionOver, e.Detail)
		case "identity_unmapped":
			return fmt.Errorf("%w: %s", ErrSessionOver, e.Detail)
		}
	}
	return sessionOver(status, e)
}

// connectOIDC finishes Connect on the OIDC path (ruling 13): the broker must
// list the session's provider, it must take the held ID token (GET
// /v1/identity), and the session ends max_session_age after the token's
// auth_time, reckoned from when the token arrived. Called with the wire
// held.
func (a *Agent) connectOIDC(ctx context.Context, c api.Config) error {
	p := a.oidc.cfg.Provider
	var entry *api.OIDCProvider
	for i := range c.OIDC {
		if c.OIDC[i].Issuer == p.Issuer && c.OIDC[i].ClientID == p.ClientID {
			entry = &c.OIDC[i]
		}
	}
	if entry == nil {
		return fmt.Errorf("agent: the broker at %s does not list %s (client %s) among the identity providers it "+
			"takes", a.broker, p.Issuer, p.ClientID)
	}
	a.oidc.setMaxTokenAge(time.Duration(entry.MaxTokenAgeSeconds) * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.broker+"/v1/identity", nil)
	if err != nil {
		return err
	}
	resp, err := a.do(req)
	if err != nil {
		if final(err) {
			return err
		}
		return fmt.Errorf("agent: connecting to the broker at %s: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		if over := a.over(resp.StatusCode, e); over != nil {
			return over
		}
		if busy := unavailable(resp, e); busy != nil {
			return busy
		}
		return fmt.Errorf("agent: %s/v1/identity answered %s: %s %s", a.broker, resp.Status, e.Error, e.Detail)
	}
	t := a.oidc.current()
	age := max(t.ID.IssuedAt.Sub(t.ID.AuthTime), 0)
	deadline := t.Received.Add(time.Duration(c.MaxSessionAgeSeconds)*time.Second - age)
	if t.Refresh == "" {
		if end := usableEnd(t, time.Duration(entry.MaxTokenAgeSeconds)*time.Second); end.Before(deadline) {
			deadline = end
		}
	}
	a.mu.Lock()
	a.deadline = deadline
	a.ceilingWarning = time.Duration(c.CeilingWarningSeconds) * time.Second
	a.mu.Unlock()
	go a.oidc.run(a.done)
	return nil
}
```

- [ ] **Step 4: Wire it into `agent.go` and `socket.go`**

In `internal/agent/agent.go`:

- In `Config`, after `Log io.Writer`, add:

  ```go
  	// OIDC, when set, makes this an OIDC session (plan 9b; spec §13
  	// decision 43): Cert is empty, every request carries the held ID token
  	// as its bearer, and the agent renews it with the provider's refresh
  	// token. Nil is the certificate path.
  	OIDC *OIDCConfig
  ```

- In `Agent`, after `fingerprint string`, add:

  ```go
  	// oidc is the OIDC session; nil on the certificate path.
  	oidc *oidcSession
  ```

- In `New`, after the `if a.log == nil { … }` block, add:

  ```go
  	if c.OIDC != nil {
  		a.oidc = newOIDCSession(*c.OIDC, a.now, a.log,
  			func(why error) { a.endBy("your identity provider", why) }, a.SessionEndsAt)
  	}
  ```

- Replace `end` with:

  ```go
  // end records why the broker ended the session and closes Done, once.
  func (a *Agent) end(why error) { a.endBy("the broker", why) }

  // endBy is end naming who ended the session: the broker, or on the OIDC
  // path the identity provider (decision 43 ruling 10).
  func (a *Agent) endBy(who string, why error) {
  	a.endOnce.Do(func() {
  		fmt.Fprintf(a.log, "port49 agent: %s ended the session: %v\n", who, why)
  		close(a.done)
  	})
  }
  ```

  and replace

  ```go
  			if n := a.handshakes.Add(1); n > 1 {
  ```

  with

  ```go
  			// A bearer's connection closes after each answer (plan 7h), so on
  			// the OIDC path a new one is no reconnect.
  			if n := a.handshakes.Add(1); n > 1 && a.oidc == nil {
  ```

- In `Connect`, replace

  ```go
  	resp, err := a.do(req)
  	if err != nil {
  		if refused := a.refusal(err); refused != nil {
  ```

  with

  ```go
  	resp, err := a.do(req)
  	if err != nil {
  		if final(err) {
  			return api.Config{}, err
  		}
  		if refused := a.refusal(err); refused != nil {
  ```

  and after the `if c.MaxSessionAgeSeconds <= 0 { … }` block, before `a.mu.Lock()`, insert:

  ```go
  	if a.oidc != nil {
  		// The config's body is read to its end first: the transport holds
  		// one connection, and the identity check needs it.
  		drain(resp.Body)
  		if err := a.connectOIDC(ctx, c); err != nil {
  			return api.Config{}, err
  		}
  		return c, nil
  	}
  ```

- In `post`, replace

  ```go
  		resp, err := a.do(req)
  		if err == nil {
  			return resp, nil
  		}
  		a.client.CloseIdleConnections()
  ```

  with

  ```go
  		resp, err := a.do(req)
  		if err == nil {
  			return resp, nil
  		}
  		if final(err) {
  			return nil, err
  		}
  		a.client.CloseIdleConnections()
  ```

- In `exchange`, replace

  ```go
  		if resp, err = a.doOn(c, req); err == nil {
  			break
  		}
  		a.client.CloseIdleConnections()
  ```

  with

  ```go
  		if resp, err = a.doOn(c, req); err == nil {
  			break
  		}
  		if final(err) {
  			return err
  		}
  		a.client.CloseIdleConnections()
  ```

- In `doOn`, as its first statement:

  ```go
  	if a.oidc != nil {
  		return a.bearerDo(c, req)
  	}
  ```

- Replace each of the four calls `sessionOver(resp.StatusCode, e)` (in `Connect`, `Mint`,
  `exchange` and `refreshRefused`; `grep -n "sessionOver(resp.StatusCode" internal/agent/agent.go`
  lists them) with `a.over(resp.StatusCode, e)`. `sessionOver` itself is unchanged; `over` calls it.

- In `Status`, after `Sessions`, add:

  ```go
  	// Method is how the session authenticated: x509 or oidc (plan 9b;
  	// decision 43 ruling 16). An agent older than 9b sends none: x509.
  	Method string `json:"method,omitempty"`
  	// OIDCIssuer is an OIDC session's provider.
  	OIDCIssuer string `json:"oidc_issuer,omitempty"`
  ```

- In `Handler`'s `GET /status`, replace

  ```go
  		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
  			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
  			CeilingWarningSeconds: int(warn / time.Second), Sessions: sessions})
  ```

  with

  ```go
  		method, issuer := "x509", ""
  		if a.oidc != nil {
  			method, issuer = "oidc", a.oidc.cfg.Provider.Issuer
  		}
  		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
  			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
  			CeilingWarningSeconds: int(warn / time.Second), Sessions: sessions, Method: method, OIDCIssuer: issuer})
  ```

- In `Handler`'s `POST /token` switch, before `case err != nil:`, add:

  ```go
  		case errors.As(err, new(*RenewFailedError)):
  			// The provider, not the broker: nothing was sent, and the session
  			// goes on (decision 43 ruling 10).
  			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "identity_provider_unreachable", Detail: err.Error()})
  ```

- In `answer`, before `case errors.As(err, &refused):`, add the same case.

In `internal/agent/socket.go`:

- In `Client.Token`'s `case http.StatusServiceUnavailable:`, after the `revocation_running` check,
  add:

  ```go
  		if e.Error == "identity_provider_unreachable" {
  			return api.MintItem{}, &RenewFailedError{Detail: e.Detail}
  		}
  ```

- In `roundTrip`'s switch, before `case e.Error != "":`, add:

  ```go
  	case resp.StatusCode == http.StatusServiceUnavailable && e.Error == "identity_provider_unreachable":
  		return &RenewFailedError{Detail: e.Detail}
  ```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/agent/ -count=1 && go test -race ./internal/agent/ -count=1`
Expected: PASS, the certificate path's tests unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/oidc.go internal/agent/oidc_test.go internal/agent/agent.go internal/agent/socket.go
git commit -m "feat(agent): hold an OIDC session: the ID token as bearer, silent renewal, the provider down ends nothing"
```

---

### Task 6: The agent's side of an OIDC refresh: the challenge, the new tokens, the socket

**Files:**
- Create: `internal/agent/oidcrefresh.go`, `internal/agent/oidcrefresh_test.go`
- Modify: `internal/agent/agent.go` (`Refresh`, `Handler`, `answer`), `internal/agent/socket.go`
  (`Client.Refresh`, `roundTrip`, two methods)

**Interfaces:**
- Consumes: Task 5's `oidcSession` (`current`, `install`, `cfg`), `bearerKey`, `final`, `over`,
  `oidcRig`, `oidcBroker`; the agent's `exchange`, `takeWire`, `giveWire`, `do`, `refreshRefused`,
  `deadlineChanged`, `refreshMu`.
- Produces, for Task 7:
  - `type OIDCSignIn struct { Nonce, ExpiresAt, Issuer, ClientID string; Scopes []string; AuthorizationEndpoint, TokenEndpoint string; IssParameter bool; CAPEM string; RedirectPort int }`
    (JSON `nonce`, `expires_at`, `issuer`, `client_id`, `scopes`, `authorization_endpoint`,
    `token_endpoint`, `iss_parameter`, `ca_pem`, `redirect_port`)
  - `type OIDCRefreshRequest struct { IDToken string \`json:"id_token"\`; RefreshToken string \`json:"refresh_token,omitempty"\` }`
  - `func (a *Agent) OIDCChallenge(ctx context.Context) (OIDCSignIn, error)`
  - `func (a *Agent) OIDCRefresh(ctx context.Context, r OIDCRefreshRequest) (api.RefreshResponse, error)`
  - `func (c *Client) OIDCChallenge(ctx context.Context) (OIDCSignIn, error)`
  - `func (c *Client) OIDCRefresh(ctx context.Context, r OIDCRefreshRequest) (api.RefreshResponse, error)`
  - `var ErrBrowserRequired, ErrNotOIDC error`

- [ ] **Step 1: Write the failing tests**

Create `internal/agent/oidcrefresh_test.go`:

```go
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The refresh, as `port49 refresh` drives it over the socket: the agent's
// challenge carries the provider's sign-in parameters; the sign-in answers
// it; the agent sends the new token as the refresh's bearer and holds it
// once the broker answers 200 (decision 43 ruling 12).
func TestAnOIDCRefreshExtendsWithTheNewToken(t *testing.T) {
	r := newOIDCRig(t, nil)
	c := socketFor(t, r.a)
	ctx := context.Background()
	si, err := c.OIDCChallenge(ctx)
	if err != nil || si.Nonce == "" || si.Issuer != r.iss.URL || si.ClientID != "port49-cli" ||
		si.AuthorizationEndpoint != r.iss.URL+"/authorize" || si.TokenEndpoint != r.iss.URL+"/token" ||
		!si.IssParameter || !strings.Contains(si.CAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("%v %v", si, err)
	}
	r.advance(time.Minute)
	raw, rt := r.as.SignIn(t, si.Nonce)
	out, err := c.OIDCRefresh(ctx, OIDCRefreshRequest{IDToken: raw, RefreshToken: rt})
	if err != nil || len(out.Sessions) != 1 || out.Sessions[0].Outcome != "extended" {
		t.Fatalf("%+v %v", out, err)
	}
	held := r.a.oidc.current()
	r.fb.mu.Lock()
	refreshed := r.fb.refreshes
	r.fb.mu.Unlock()
	if held.IDRaw != raw || held.Refresh != rt || len(refreshed) != 1 || refreshed[0] != raw {
		t.Fatalf("the agent holds the new token %v, the broker saw it %v", held.IDRaw == raw, len(refreshed) == 1)
	}
	if ends, _ := time.Parse(time.RFC3339, out.SessionEndsAt); !r.a.SessionEndsAt().Equal(ends) {
		t.Fatalf("the session ends at %s, the broker said %s", r.a.SessionEndsAt(), out.SessionEndsAt)
	}
	// The next mint carries the new token.
	if _, err := r.mint(); err != nil {
		t.Fatal(err)
	}
	r.fb.mu.Lock()
	last := r.fb.bearers[len(r.fb.bearers)-1]
	r.fb.mu.Unlock()
	if last != raw {
		t.Fatal("the mint after the refresh did not carry the new token")
	}
}

// A refresh signed in as another user changes nothing and sends nothing.
func TestARefreshByAnotherUserChangesNothing(t *testing.T) {
	r := newOIDCRig(t, nil)
	first := r.a.oidc.current()
	si, err := r.a.OIDCChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bob := r.iss.IDToken(t, "k1", "port49-cli", "sub-bob", r.clock(), map[string]any{"nonce": si.Nonce})
	if _, err := r.a.OIDCRefresh(context.Background(), OIDCRefreshRequest{IDToken: bob}); err == nil ||
		!strings.Contains(err.Error(), "another user") {
		t.Fatalf("%v", err)
	}
	r.fb.mu.Lock()
	n := len(r.fb.refreshes)
	r.fb.mu.Unlock()
	if n != 0 || r.a.oidc.current().IDRaw != first.IDRaw {
		t.Fatalf("%d refreshes sent, token replaced %v", n, r.a.oidc.current().IDRaw != first.IDRaw)
	}
}

// A refused refresh keeps the held tokens and the session.
func TestARefusedRefreshKeepsTheHeldTokens(t *testing.T) {
	r := newOIDCRig(t, nil)
	r.fb.mu.Lock()
	r.fb.refreshCode = "refresh_not_fresh"
	r.fb.mu.Unlock()
	first := r.a.oidc.current()
	si, _ := r.a.OIDCChallenge(context.Background())
	raw, _ := r.as.SignIn(t, si.Nonce)
	_, err := r.a.OIDCRefresh(context.Background(), OIDCRefreshRequest{IDToken: raw})
	if err == nil || !strings.Contains(err.Error(), "refresh_not_fresh") || errors.Is(err, ErrSessionOver) ||
		ended(r.a) || r.a.oidc.current().IDRaw != first.IDRaw {
		t.Fatalf("%v, ended %v", err, ended(r.a))
	}
}

// POST /refresh on an OIDC agent asks for the browser; the OIDC routes on a
// certificate agent say it is not one.
func TestTheRefreshRoutesKnowTheirSession(t *testing.T) {
	r := newOIDCRig(t, nil)
	if _, err := socketFor(t, r.a).Refresh(context.Background()); !errors.Is(err, ErrBrowserRequired) {
		t.Fatalf("POST /refresh on OIDC: %v", err)
	}
	cert := newRig(t)
	if _, err := socketFor(t, cert.a).OIDCChallenge(context.Background()); !errors.Is(err, ErrNotOIDC) {
		t.Fatalf("POST /oidc/challenge on a certificate: %v", err)
	}
}

// Neither type prints what it carries.
func TestTheSignInTypesWithholdTheirSecrets(t *testing.T) {
	s := fmt.Sprint(OIDCSignIn{Nonce: "n0nce-n0nce"}, OIDCRefreshRequest{IDToken: "eyJ-id", RefreshToken: "rt-123"})
	s += fmt.Sprintf("%#v %#v", OIDCSignIn{Nonce: "n0nce-n0nce"}, OIDCRefreshRequest{IDToken: "eyJ-id", RefreshToken: "rt-123"})
	for _, v := range []string{"n0nce-n0nce", "eyJ-id", "rt-123"} {
		if strings.Contains(s, v) {
			t.Fatalf("%q printed: %s", v, s)
		}
	}
}
```

`newRig(t)` is the certificate path's test rig (`agent_test.go`); its agent is the field `a`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/agent/ -run 'OIDCRefresh|AnotherUser|RefusedRefresh|RefreshRoutes|WithholdTheirSecrets' -count=1`
Expected: FAIL to build: `undefined: OIDCRefreshRequest`, `c.OIDCChallenge undefined`.

- [ ] **Step 3: `internal/agent/oidcrefresh.go`**

```go
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidcclient"
)

// ErrBrowserRequired is POST /refresh on an OIDC session, whose refresh is a
// sign-in the command runs (decision 43 ruling 16).
var ErrBrowserRequired = errors.New("agent: this session signed in at your identity provider, so its refresh is a " +
	"sign-in there: run `port49 refresh`, which opens a browser or prints the address")

// ErrNotOIDC is an OIDC route on a certificate session.
var ErrNotOIDC = errors.New("agent: this session is a certificate's; `port49 refresh` refreshes it with no browser")

// OIDCSignIn is POST /oidc/challenge's answer: the broker's refresh
// challenge, and what the command running the sign-in needs to run it
// against this session's provider (ruling 12).
type OIDCSignIn struct {
	Nonce                 string   `json:"nonce"`
	ExpiresAt             string   `json:"expires_at"`
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	Scopes                []string `json:"scopes"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IssParameter          bool     `json:"iss_parameter"`
	CAPEM                 string   `json:"ca_pem,omitempty"`
	RedirectPort          int      `json:"redirect_port,omitempty"`
}

// String withholds the nonce, the broker's challenge.
func (s OIDCSignIn) String() string {
	return fmt.Sprintf("OIDCSignIn{%s %s expires %s}", s.Issuer, s.ClientID, s.ExpiresAt)
}

// GoString is String.
func (s OIDCSignIn) GoString() string { return s.String() }

// OIDCRefreshRequest is POST /oidc/refresh: the sign-in's tokens.
type OIDCRefreshRequest struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// String withholds both tokens.
func (r OIDCRefreshRequest) String() string {
	return fmt.Sprintf("OIDCRefreshRequest{refresh token %t}", r.RefreshToken != "")
}

// GoString is String.
func (r OIDCRefreshRequest) GoString() string { return r.String() }

// OIDCChallenge is POST /v1/refresh/challenge with the held bearer, and the
// provider's sign-in parameters beside it.
func (a *Agent) OIDCChallenge(ctx context.Context) (OIDCSignIn, error) {
	if a.oidc == nil {
		return OIDCSignIn{}, ErrNotOIDC
	}
	var ch api.RefreshChallenge
	if err := a.exchange(ctx, a.client, nil, http.MethodPost, "/v1/refresh/challenge", nil, &ch); err != nil {
		return OIDCSignIn{}, err
	}
	c := a.oidc.cfg
	return OIDCSignIn{Nonce: ch.Nonce, ExpiresAt: ch.ExpiresAt, Issuer: c.Provider.Issuer,
		ClientID: c.Provider.ClientID, Scopes: c.Provider.Scopes, AuthorizationEndpoint: c.Endpoints.Authorization,
		TokenEndpoint: c.Endpoints.Token, IssParameter: c.Endpoints.IssParameter, CAPEM: string(c.CAPEM),
		RedirectPort: c.RedirectPort}, nil
}

// OIDCRefresh is POST /v1/refresh with the sign-in's new ID token as its
// bearer (decision 39 ruling 15; decision 43 ruling 12). The token must name
// the held issuer and sub: a sign-in as someone else refreshes nothing. On a
// 200 the agent holds the new tokens and the session's end is the broker's
// session_ends_at; on anything else it holds the old ones, and only
// credential_revoked ends the session (refreshRefused).
func (a *Agent) OIDCRefresh(ctx context.Context, r OIDCRefreshRequest) (api.RefreshResponse, error) {
	if a.oidc == nil {
		return api.RefreshResponse{}, ErrNotOIDC
	}
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	select {
	case <-a.done:
		return api.RefreshResponse{}, ErrSessionOver
	default:
	}
	held := a.oidc.current()
	id, err := oidc.ReadIDToken(r.IDToken, held.ID.Issuer, a.oidc.cfg.Provider.ClientID, "")
	if err != nil {
		return api.RefreshResponse{}, fmt.Errorf("agent: the sign-in's %w", err)
	}
	if id.Subject != held.ID.Subject {
		return api.RefreshResponse{}, errors.New("agent: you signed in at your identity provider as another user " +
			"than this session's; nothing was refreshed. Sign in as the session's user, or stop the agent and run " +
			"`port49 login`")
	}
	received := a.now().Round(0)
	if err := a.takeWire(ctx, false, "refreshed", "port49 refresh"); err != nil {
		return api.RefreshResponse{}, err
	}
	defer a.giveWire(false)
	req, err := http.NewRequestWithContext(context.WithValue(ctx, bearerKey{}, r.IDToken), http.MethodPost,
		a.broker+"/v1/refresh", http.NoBody)
	if err != nil {
		return api.RefreshResponse{}, err
	}
	resp, err := a.do(req)
	if err != nil {
		if final(err) {
			return api.RefreshResponse{}, err
		}
		return api.RefreshResponse{}, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		out, _, err := a.refreshRefused(resp, "the refresh")
		return out, err
	}
	var out api.RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return api.RefreshResponse{}, fmt.Errorf("agent: the broker's answer to the refresh: %w", err)
	}
	ends, err := time.Parse(time.RFC3339, out.SessionEndsAt)
	if err != nil {
		return api.RefreshResponse{}, fmt.Errorf("agent: the broker's answer to the refresh names no session_ends_at: %w", err)
	}
	refresh := r.RefreshToken
	if refresh == "" {
		refresh = held.Refresh
	}
	a.oidc.install(oidcclient.Tokens{ID: id, IDRaw: r.IDToken, Refresh: refresh, Received: received})
	a.mu.Lock()
	a.deadline = ends
	a.refreshed = out.Sessions
	a.mu.Unlock()
	select {
	case a.deadlineChanged <- struct{}{}:
	default:
	}
	return out, nil
}
```

- [ ] **Step 4: Wire the routes and the client**

In `internal/agent/agent.go`:

- In `Refresh`, as its first statement:

  ```go
  	if a.oidc != nil {
  		return api.RefreshResponse{}, ErrBrowserRequired
  	}
  ```

- In `Handler`'s `POST /refresh` switch, before `case errors.Is(err, ErrSessionOver):`, add:

  ```go
  		case errors.Is(err, ErrBrowserRequired):
  			writeJSON(w, http.StatusConflict, api.Error{Error: "browser_required", Detail: err.Error()})
  ```

- In `Handler`, after the `POST /revoke` route, add:

  ```go
  	mux.HandleFunc("POST /oidc/challenge", func(w http.ResponseWriter, r *http.Request) {
  		out, err := a.OIDCChallenge(r.Context())
  		answer(w, out, err)
  	})
  	mux.HandleFunc("POST /oidc/refresh", func(w http.ResponseWriter, r *http.Request) {
  		var req OIDCRefreshRequest
  		if err := decodeOne(r.Body, &req); err != nil || req.IDToken == "" {
  			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "send the sign-in's id_token"})
  			return
  		}
  		out, err := a.OIDCRefresh(r.Context(), req)
  		answer(w, out, err)
  	})
  ```

- In `answer`, before `case errors.As(err, &revoked):`, add:

  ```go
  	case errors.Is(err, ErrBrowserRequired):
  		writeJSON(w, http.StatusConflict, api.Error{Error: "browser_required", Detail: err.Error()})
  	case errors.Is(err, ErrNotOIDC):
  		writeJSON(w, http.StatusConflict, api.Error{Error: "not_oidc", Detail: err.Error()})
  ```

In `internal/agent/socket.go`:

- In `Client.Refresh`'s switch, before `case http.StatusServiceUnavailable:`, add:

  ```go
  	case http.StatusConflict:
  		_ = json.NewDecoder(resp.Body).Decode(&e)
  		if e.Error == "browser_required" {
  			return api.RefreshResponse{}, ErrBrowserRequired
  		}
  		return api.RefreshResponse{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
  ```

- In `roundTrip`'s switch, before `case e.Error != "":`, add:

  ```go
  	case resp.StatusCode == http.StatusConflict && e.Error == "browser_required":
  		return ErrBrowserRequired
  	case resp.StatusCode == http.StatusConflict && e.Error == "not_oidc":
  		return ErrNotOIDC
  ```

- After `Explain`, add:

  ```go
  // OIDCChallenge asks the agent for the broker's refresh challenge and the
  // provider's sign-in parameters (decision 43 ruling 12).
  func (c *Client) OIDCChallenge(ctx context.Context) (OIDCSignIn, error) {
  	var out OIDCSignIn
  	return out, c.roundTrip(ctx, http.MethodPost, "/oidc/challenge", nil, &out)
  }

  // OIDCRefresh hands the agent a sign-in's tokens for the refresh.
  func (c *Client) OIDCRefresh(ctx context.Context, r OIDCRefreshRequest) (api.RefreshResponse, error) {
  	var out api.RefreshResponse
  	return out, c.roundTrip(ctx, http.MethodPost, "/oidc/refresh", r, &out)
  }
  ```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/agent/ -count=1 && go test -race ./internal/agent/ -count=1 && go vet ./internal/agent/`
Expected: PASS, and vet silent.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/oidcrefresh.go internal/agent/oidcrefresh_test.go internal/agent/agent.go internal/agent/socket.go
git commit -m "feat(agent): an OIDC refresh: the challenge with the provider's parameters, the new token as bearer"
```

---

### Task 7: `port49 login --oidc`, `port49 refresh` on the OIDC path, and the config file's keys

**Files:**
- Modify: `internal/userconfig/userconfig.go`, `internal/userconfig/userconfig_test.go`
- Create: `cmd/port49/oidc.go`, `cmd/port49/oidc_test.go`, `cmd/port49/oidc_login_linux_test.go`,
  `cmd/port49/harden_linux.go`, `cmd/port49/harden_other.go`
- Modify: `cmd/port49/main.go` (usage, `sessionFlags`, `login`, `startAgent` (new, from `login`),
  `agentMain`), `cmd/port49/refresh.go`, `cmd/port49/main_test.go` (`newLabBrokerWith`),
  `cmd/port49/config_test.go`

**Interfaces:**
- Consumes: Task 3's `oidcclient.Provider`, `Endpoints`, `Tokens`, `Discover`, `Skew`;
  `oidc.ReadIDToken`; Task 4's `oidcclient.Login`, `LoginOptions`; Task 5's `agent.OIDCConfig`,
  `Config.OIDC`, `Status.Method`, `Status.OIDCIssuer`; Task 6's `Client.OIDCChallenge`,
  `Client.OIDCRefresh`, `OIDCRefreshRequest`; Task 2's `AuthServer`, `Issuer.Browser`,
  `Issuer.Redirected`, `AuthServer.Issued`; `userconfig.ReadPrivate`; `printRefresh`, `unprefixed`,
  `stopAgentAt`, `privateSocket`, `privateDir`, `labConfig`, `runningAgent`, `configBroker`,
  `runCLIEnv` (tests).
- Produces (the end of the chain):
  - `userconfig.File.Method`, `OIDCIssuer`, `OIDCCA`, `OIDCRedirectPort`, `OIDCCAPEM`;
    `userconfig.WithoutOIDCCA()`;
  - `loginOIDC`, `refreshOIDC`, `signIn`, `startAgent`, `browserCommand`, `pickProvider`,
    `fetchBrokerConfig`, `warnSkew`, `harden`;
  - `oidcHandoff` (JSON: `issuer`, `client_id`, `scopes`, `ca_pem`, `authorization_endpoint`,
    `token_endpoint`, `iss_parameter`, `redirect_port`, `id_token`, `refresh_token`,
    `received_at`).

- [ ] **Step 1: Write the failing tests**

In `internal/userconfig/userconfig_test.go`, add:

```go
// The OIDC keys (decision 43 ruling 15): oidc_ca is resolved and read once
// through the walk, as broker_ca is.
func TestTheOIDCKeysAreRead(t *testing.T) {
	p := private(t, "config.yaml", "method: oidc\noidc_issuer: https://kc.example/r\noidc_ca: idp.pem\n"+
		"oidc_redirect_port: 18749\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok, err := Load(p)
	if err != nil || !ok || f.Method != "oidc" || f.OIDCIssuer != "https://kc.example/r" || f.OIDCCA != ca ||
		string(f.OIDCCAPEM) != "PEM" || f.OIDCRedirectPort != 18749 {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	if f, _, err := Load(p, WithoutOIDCCA()); err != nil || f.OIDCCAPEM != nil {
		t.Fatalf("WithoutOIDCCA: %q %v", f.OIDCCAPEM, err)
	}
}

func TestAnOIDCCAOthersCanWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "oidc_ca: idp.pem\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), ca+" is writable by others") ||
		!strings.Contains(err.Error(), "oidc_ca in") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnknownMethodOrABadPortIsRefused(t *testing.T) {
	for body, want := range map[string]string{
		"method: saml\n":             `method "saml"`,
		"oidc_redirect_port: 70000\n": "is not a port",
		"oidc_redirect_port: -1\n":    "is not a port",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}
```

Create `cmd/port49/oidc_test.go`:

```go
package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidcclient"
)

// A browser is launched only where one can be seen (decision 43 ruling 5).
func TestBrowserCommand(t *testing.T) {
	for _, c := range []struct {
		goos string
		env  map[string]string
		want string
	}{
		{"linux", map[string]string{"DISPLAY": ":0"}, "xdg-open U"},
		{"linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, "xdg-open U"},
		{"linux", map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, ""},
		{"linux", nil, ""},
		{"darwin", nil, "open U"},
		{"darwin", map[string]string{"SSH_TTY": "/dev/ttys001"}, ""},
		{"linux", map[string]string{"BROWSER": "firefox"}, "firefox U"},
		{"darwin", map[string]string{"BROWSER": "firefox", "SSH_TTY": "/dev/ttys001"}, "firefox U"},
	} {
		got := strings.Join(browserCommand(c.goos, func(k string) string { return c.env[k] }, "U"), " ")
		if got != c.want {
			t.Errorf("%s %v: %q, want %q", c.goos, c.env, got, c.want)
		}
	}
}

func TestPickProvider(t *testing.T) {
	one := api.Config{Methods: []string{"x509", "oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}}}
	two := api.Config{Methods: []string{"oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}, {Issuer: "https://b"}}}
	if p, err := pickProvider(one, ""); err != nil || p.Issuer != "https://a" {
		t.Fatalf("one: %v %v", p, err)
	}
	if p, err := pickProvider(two, "https://b"); err != nil || p.Issuer != "https://b" {
		t.Fatalf("named: %v %v", p, err)
	}
	for name, c := range map[string]struct {
		conf   api.Config
		issuer string
		want   string
	}{
		"none listed":  {api.Config{Methods: []string{"x509"}}, "", "takes no OIDC login"},
		"two unnamed":  {two, "", "name one with --issuer or oidc_issuer"},
		"not listed":   {two, "https://c", "does not list https://c"},
		"by its slash": {one, "https://a/", "does not list"},
	} {
		if _, err := pickProvider(c.conf, c.issuer); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestTheHandoffWithholdsItsTokens(t *testing.T) {
	h := oidcHandoff{Issuer: "https://a", ClientID: "c", IDToken: "eyJ-id-token", RefreshToken: "rt-123"}
	for _, s := range []string{fmt.Sprint(h), fmt.Sprintf("%#v %+v", h, h)} {
		if strings.Contains(s, "eyJ-id-token") || strings.Contains(s, "rt-123") {
			t.Fatalf("%s", s)
		}
	}
}

// A skew over 5 minutes is said, never refused (ruling 6).
func TestASkewedClockIsWarnedNotRefused(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	var b bytes.Buffer
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(2 * time.Minute)})
	if b.Len() != 0 {
		t.Fatalf("2m: %q", b.String())
	}
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(-7 * time.Minute)})
	if !strings.Contains(b.String(), "this host's clock is 7m0s behind your identity provider's") {
		t.Fatalf("%q", b.String())
	}
}

// --cert or --key beside --oidc is a usage error.
func TestLoginOIDCRefusesCertificateFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"login", "--oidc", "--cert", "c.pem", "--broker", configBroker, "--broker-ca", "ca.pem"},
		&out, &errb); code != 2 || !strings.Contains(errb.String(), "--cert and --key are a certificate login's") {
		t.Fatalf("code %d %q", code, errb.String())
	}
}
```

In `cmd/port49/config_test.go`, add:

```go
// method: oidc in the file makes a plain login an OIDC one: against a
// running certificate agent it is refused, naming that agent.
func TestTheConfigFileCanChooseOIDC(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("method: oidc\n")
	f.Close()
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"login", "--config", cfg, "--socket", sock}, &out, &errb)
	if code != 1 || refreshes() != 0 || !strings.Contains(errb.String(), "with a certificate") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
```

Create `cmd/port49/oidc_login_linux_test.go`:

```go
//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
)

// oidcLab is a real OIDC-only broker (newLabBrokerWith) trusting an issuer
// whose authorization server signs alice in.
type oidcLab struct {
	*labBroker
	iss   *oidctest.Issuer
	as    *oidctest.AuthServer
	idpCA string
}

func newOIDCLab(t *testing.T) *oidcLab {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	l := newLabBrokerWith(t, 12*time.Hour, iss)
	o := &oidcLab{labBroker: l, iss: iss,
		as: iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})}
	o.as.Now = l.now
	o.idpCA = filepath.Join(privateDir(t), "idp-ca.pem")
	if err := os.WriteFile(o.idpCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *oidcLab) flags(socket string) []string {
	return []string{"--oidc", "--broker", o.url, "--broker-ca", filepath.Join(o.dir, testpki.LabCA),
		"--oidc-ca", o.idpCA, "--socket", socket}
}

// driveBrowser makes the sign-in's browser the issuer's: it follows the
// provider's redirect to the loopback listener, as a person's does.
func driveBrowser(t *testing.T, iss *oidctest.Issuer) {
	t.Helper()
	saved, savedTerm := openBrowser, stdinIsTerminal
	openBrowser = func(u string) error {
		go func() { _ = iss.Browser()(u) }()
		return nil
	}
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { openBrowser, stdinIsTerminal = saved, savedTerm })
}

// credentialsNowhere fails if any text holds a value the provider issued.
func credentialsNowhere(t *testing.T, issued []string, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, v := range issued {
			if strings.Contains(text, v) {
				t.Fatal("a code or token reached the terminal or the agent's log")
			}
		}
	}
}

// peerPid is the pid of the process listening on sock.
func peerPid(t *testing.T, sock string) int {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var cred *syscall.Ucred
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	if cred == nil {
		t.Fatal("no peer credentials")
	}
	return int(cred.Pid)
}

// The real path: login signs in, starts an agent holding the session, and
// `port49 token` mints through it; the agent is non-dumpable; nothing the
// provider issued reaches the terminal or the log.
func TestLoginOIDCStartsAnAgentThatMints(t *testing.T) {
	o := newOIDCLab(t)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url+" through "+o.iss.URL+"; the session ends at ") ||
		strings.Contains(out.String(), "refreshed at") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if q := o.as.Authorizations(); len(q) != 1 || q[0].Get("prompt") != "login" {
		t.Fatalf("%d sign-ins", len(q))
	}
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 || strings.TrimSpace(tok.String()) == "" {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
	st, err := agent.NewClient(sock).Status(context.Background())
	if err != nil || st.Method != "oidc" || st.OIDCIssuer != o.iss.URL {
		t.Fatalf("%+v %v", st, err)
	}
	if os.Getuid() != 0 {
		// A non-dumpable process's /proc/<pid> files are root's (proc(5)).
		fi, err := os.Stat(fmt.Sprintf("/proc/%d/environ", peerPid(t, sock)))
		if err != nil {
			t.Fatal(err)
		}
		if uid := fi.Sys().(*syscall.Stat_t).Uid; uid != 0 {
			t.Fatalf("the agent is dumpable: its /proc/<pid>/environ is uid %d's", uid)
		}
	}
	log, _ := os.ReadFile(filepath.Join(filepath.Dir(sock), "agent.log"))
	credentialsNowhere(t, o.as.Issued(), out.String(), errb.String(), terr.String(), string(log))
}

// `port49 refresh` signs in again with prompt=login and the broker's
// challenge as the nonce, and extends the live context; `port49 login`
// with the agent running does the same.
func TestAnOIDCRefreshSignsInAgainAndExtends(t *testing.T) {
	o := newOIDCLab(t)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("refresh: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	q := o.as.Authorizations()
	if len(q) != 2 || q[1].Get("prompt") != "login" || q[1].Get("nonce") == "" || q[1].Get("nonce") == q[0].Get("nonce") {
		t.Fatalf("the refresh's sign-in: %d sign-ins", len(q))
	}
	o.step(11 * time.Second) // past the challenge pacing
	out.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+o.url+" through "+o.iss.URL+"; refreshing\n") ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("a second login: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	credentialsNowhere(t, o.as.Issued(), out.String(), errb.String())
}

// A provider that did not ask for the password again is refused by the
// broker, and the session is unchanged.
func TestAProviderThatIgnoresPromptLoginIsRefreshNotFresh(t *testing.T) {
	o := newOIDCLab(t)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	o.as.SetAuthTime(o.now().Add(-time.Hour))
	errb.Reset()
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "refresh_not_fresh") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, err := agent.NewClient(sock).Status(context.Background()); err != nil {
		t.Fatalf("the agent ended: %v", err)
	}
}

// With no browser, the address is printed and a pasted one completes the
// sign-in (ruling 5).
func TestLoginOIDCWithAPastedAddress(t *testing.T) {
	o := newOIDCLab(t)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	urls := make(chan string, 1)
	saved := [3]any{openBrowser, stdinIsTerminal, readPaste}
	openBrowser = func(u string) error { urls <- u; return fmt.Errorf("no display") }
	stdinIsTerminal = func() bool { return true }
	readPaste = func() (string, error) { return o.iss.Redirected(<-urls) }
	t.Cleanup(func() {
		openBrowser = saved[0].(func(string) error)
		stdinIsTerminal = saved[1].(func() bool)
		readPaste = saved[2].(func() (string, error))
	})
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "open this address in a browser") ||
		!strings.Contains(errb.String(), "paste it here (it is not shown)") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	credentialsNowhere(t, o.as.Issued(), out.String(), errb.String())
}

// A provider that issues no refresh token: the login says when the session
// ends, and succeeds.
func TestLoginWithoutARefreshTokenSaysWhen(t *testing.T) {
	o := newOIDCLab(t)
	o.as.NoRefreshToken()
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "issued no refresh token, so this session ends with the ID token") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// The provider down at login: said, exit 1, no agent started.
func TestLoginOIDCWithTheProviderDownSaysSo(t *testing.T) {
	o := newOIDCLab(t)
	o.iss.Close()
	sock := privateSocket(t)
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "did not answer") || !strings.Contains(errb.String(), "try again once it answers") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("an agent started")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/userconfig/ ./cmd/port49/ -run 'OIDC|BrowserCommand|PickProvider|Handoff|Skewed|UnknownMethod|ChooseOIDC|PromptLogin|PastedAddress|RefreshToken' -count=1`
Expected: FAIL to build: `unknown field Method`, `undefined: browserCommand`, `undefined:
newLabBrokerWith`.

- [ ] **Step 3: The config file's keys**

In `internal/userconfig/userconfig.go`:

- In the package comment, replace `config.yaml,\n// which gives \`port49 login\` its broker, broker CA, certificate and key;` with
  `config.yaml,\n// which gives \`port49 login\` its broker, broker CA, certificate and key, or its\n// identity provider (spec §13 decision 43 ruling 15);`.

- Replace `File` with:

  ```go
  // File is config.yaml. Every key is optional; `port49 login` takes each one
  // its flags leave out. Paths are resolved by Load: relative to the file's
  // directory, and ~/ the home directory.
  type File struct {
  	Broker   string `yaml:"broker"`
  	BrokerCA string `yaml:"broker_ca"`
  	Cert     string `yaml:"cert"`
  	Key      string `yaml:"key"`
  	// Method is how `port49 login` authenticates: x509, the default, or oidc
  	// (decision 43 ruling 15).
  	Method string `yaml:"method"`
  	// OIDCIssuer names the provider to sign in at when the broker lists
  	// several.
  	OIDCIssuer string `yaml:"oidc_issuer"`
  	// OIDCCA is the CA that issued the provider's TLS certificate; none is
  	// the system's roots.
  	OIDCCA string `yaml:"oidc_ca"`
  	// OIDCRedirectPort is the loopback port a sign-in returns to; 0 picks a
  	// free one.
  	OIDCRedirectPort int `yaml:"oidc_redirect_port"`

  	// BrokerCAPEM is the bytes of the file BrokerCA names, read once by Load
  	// through the same ownership walk; nil under WithoutCA or with no CA named.
  	BrokerCAPEM []byte `yaml:"-"`
  	// OIDCCAPEM is OIDCCA's bytes, read as BrokerCAPEM is; nil under
  	// WithoutOIDCCA or with none named.
  	OIDCCAPEM []byte `yaml:"-"`
  }
  ```

- Replace

  ```go
  type loadOptions struct{ skipCA bool }
  ```

  with

  ```go
  type loadOptions struct{ skipCA, skipOIDCCA bool }

  // WithoutOIDCCA is WithoutCA for oidc_ca, which --oidc-ca overrides.
  func WithoutOIDCCA() Option { return func(o *loadOptions) { o.skipOIDCCA = true } }
  ```

- In `Load`, replace

  ```go
  	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key} {
  ```

  with

  ```go
  	switch f.Method {
  	case "", "x509", "oidc":
  	default:
  		return File{}, false, fmt.Errorf("%s: method %q: port49 logs in by x509 or oidc", path, f.Method)
  	}
  	if f.OIDCRedirectPort < 0 || f.OIDCRedirectPort > 65535 {
  		return File{}, false, fmt.Errorf("%s: oidc_redirect_port %d is not a port", path, f.OIDCRedirectPort)
  	}
  	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key, &f.OIDCCA} {
  ```

  and before `return f, true, nil` add:

  ```go
  	// The provider's CA decides who the sign-in's tokens come from, as the
  	// broker CA decides the broker: held to the same line, read once.
  	if f.OIDCCA != "" && !o.skipOIDCCA {
  		if f.OIDCCAPEM, err = ReadPrivate(f.OIDCCA, maxCA, "identity provider CA"); err != nil {
  			return File{}, false, fmt.Errorf("oidc_ca in %s: %w", path, err)
  		}
  	}
  ```

- [ ] **Step 4: `cmd/port49/harden_linux.go` and `harden_other.go`**

```go
//go:build linux

package main

import "golang.org/x/sys/unix"

// harden makes the agent process non-dumpable (spec §13 decision 43 ruling
// 7): no core file is written, and no process of this user can ptrace it or
// read its memory, where an OIDC session's refresh token lives. /proc/<pid>
// becomes root's.
func harden() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
```

```go
//go:build !linux

package main

// harden is Linux's alone (harden_linux.go); elsewhere the OS's own
// protection of a process's memory is all there is.
func harden() error { return nil }
```

- [ ] **Step 5: `cmd/port49/oidc.go`**

```go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidcclient"
)

// loginOIDC is `port49 login` on the OIDC path (spec §13 decision 43): it
// signs in at the provider the broker lists, in this process, and starts
// the agent with the tokens on an inherited pipe. With an OIDC agent running
// for this broker it refreshes that agent instead, a sign-in carrying the
// broker's challenge (ruling 12).
func loginOIDC(sf *sessionFlags, stdout, stderr io.Writer) int {
	ctx := context.Background()
	if sf.broker == "" {
		fmt.Fprintf(stderr, "port49 login: --broker and --broker-ca are required, as flags or in %s\n", sf.configFile)
		return 2
	}
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		var other string
		switch {
		case strings.TrimRight(sf.broker, "/") != st.Broker:
			other = fmt.Sprintf("an agent logged in to %s", st.Broker)
		case st.Method != "oidc":
			other = fmt.Sprintf("an agent for %s with a certificate", st.Broker)
		case sf.issuer != "" && sf.issuer != st.OIDCIssuer:
			other = fmt.Sprintf("an agent for %s through %s", st.Broker, st.OIDCIssuer)
		}
		if other != "" {
			fmt.Fprintf(stderr, "port49 login: %s already holds %s; run 'port49 refresh' to extend that session, "+
				"stop that agent first, or use --socket\n", other, sf.socket)
			return 1
		}
		fmt.Fprintf(stdout, "port49: already logged in to %s through %s; refreshing\n", st.Broker, st.OIDCIssuer)
		return refreshOIDC(ctx, agent.NewClient(sf.socket), sf.noBrowser, "port49 login", stdout, stderr)
	}
	pool, err := sf.brokerPool()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	roots, caPEM, err := sf.oidcRoots()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	conf, err := fetchBrokerConfig(ctx, sf.broker, pool)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	prov, err := pickProvider(conf, sf.issuer)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	p := oidcclient.Provider{Issuer: prov.Issuer, ClientID: prov.ClientID, Scopes: prov.Scopes, Roots: roots}
	e, err := oidcclient.Discover(ctx, p)
	if err != nil {
		fmt.Fprintf(stderr, "port49 login: %v; try again once it answers\n", err)
		return 1
	}
	tokens, err := signIn(ctx, p, e, "", sf.redirectPort, sf.noBrowser, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	warnSkew(stderr, "port49 login", tokens)
	if tokens.Refresh == "" {
		fmt.Fprintf(stderr, "port49 login: %s issued no refresh token, so this session ends with the ID token, at %s; "+
			"ask its administrator to allow refresh tokens for client %s (some providers issue one only for the "+
			"offline_access scope, which the broker's verifier then lists in scopes)\n", p.Issuer,
			tokens.Received.Add(tokens.ID.Expires.Sub(tokens.ID.IssuedAt)).UTC().Format(time.RFC3339), p.ClientID)
	}
	return startAgent(sf, &oidcHandoff{Issuer: p.Issuer, ClientID: p.ClientID, Scopes: p.Scopes, CAPEM: string(caPEM),
		AuthorizationEndpoint: e.Authorization, TokenEndpoint: e.Token, IssParameter: e.IssParameter,
		RedirectPort: sf.redirectPort, IDToken: tokens.IDRaw, RefreshToken: tokens.Refresh,
		ReceivedAt: tokens.Received.UTC().Format(time.RFC3339Nano)}, stdout, stderr)
}

// refreshOIDC is `port49 refresh`, and `port49 login` with an OIDC agent
// running (ruling 12): the agent's challenge, a sign-in carrying it, and the
// agent's refresh with the new tokens. what names the command in its lines.
func refreshOIDC(ctx context.Context, c *agent.Client, noBrowser bool, what string, stdout, stderr io.Writer) int {
	si, err := c.OIDCChallenge(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", what, unprefixed(err))
		return 1
	}
	var roots *x509.CertPool
	if si.CAPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(si.CAPEM)) {
			fmt.Fprintf(stderr, "%s: the agent's identity provider CA holds no PEM certificate\n", what)
			return 1
		}
	}
	p := oidcclient.Provider{Issuer: si.Issuer, ClientID: si.ClientID, Scopes: si.Scopes, Roots: roots}
	e := oidcclient.Endpoints{Authorization: si.AuthorizationEndpoint, Token: si.TokenEndpoint,
		IssParameter: si.IssParameter}
	tokens, err := signIn(ctx, p, e, si.Nonce, si.RedirectPort, noBrowser, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v; your session is unchanged\n", what, err)
		return 1
	}
	out, err := c.OIDCRefresh(ctx, agent.OIDCRefreshRequest{IDToken: tokens.IDRaw, RefreshToken: tokens.Refresh})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", what, unprefixed(err))
		return 1
	}
	printRefresh(stdout, out)
	return 0
}

// The sign-in's browser and terminal, vars so a test drives them.
var (
	// openBrowser opens a URL in this host's browser (launchBrowser).
	openBrowser = launchBrowser
	// stdinIsTerminal is whether a pasted address can be read.
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// readPaste reads one pasted address with echo off.
	readPaste = func() (string, error) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		return strings.TrimSpace(string(b)), err
	}
)

// signIn runs one sign-in in this process (rulings 3–5): a browser when
// this host has one, the address on stderr always, and on a terminal a
// pasted address, not echoed. The terminal is restored however the sign-in
// ends; a paste still being read when the browser's answer arrives is left
// to the process's exit.
func signIn(ctx context.Context, p oidcclient.Provider, e oidcclient.Endpoints, nonce string, port int,
	noBrowser bool, stderr io.Writer) (oidcclient.Tokens, error) {
	o := oidcclient.LoginOptions{Nonce: nonce, Port: port, Out: stderr, Now: time.Now}
	if !noBrowser {
		o.Browser = openBrowser
	}
	if stdinIsTerminal() {
		fd := int(os.Stdin.Fd())
		if saved, err := term.GetState(fd); err == nil {
			defer func() { _ = term.Restore(fd, saved) }()
		}
		o.Paste = readPaste
	}
	return oidcclient.Login(ctx, p, e, o)
}

// browserCommand is the command that opens url here, or nil for none (ruling
// 5): $BROWSER when set; on Linux and the BSDs xdg-open, only with a display,
// since on a remote shell it falls back to a text browser on the operator's
// own terminal; on macOS open, outside an SSH session.
func browserCommand(goos string, env func(string) string, url string) []string {
	if b := env("BROWSER"); b != "" {
		return []string{b, url}
	}
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		if env("DISPLAY") != "" || env("WAYLAND_DISPLAY") != "" {
			return []string{"xdg-open", url}
		}
	case "darwin":
		if env("SSH_CONNECTION") == "" && env("SSH_TTY") == "" {
			return []string{"open", url}
		}
	}
	return nil
}

// launchBrowser runs browserCommand detached, with no terminal: a browser
// that falls back to text must not take the operator's.
func launchBrowser(url string) error {
	argv := browserCommand(runtime.GOOS, os.Getenv, url)
	if argv == nil {
		return errors.New("no browser on this host")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// pickProvider is the provider a login signs in at (ruling 2): the one the
// broker lists, or the one issuer names exactly.
func pickProvider(c api.Config, issuer string) (api.OIDCProvider, error) {
	var listed []string
	for _, p := range c.OIDC {
		listed = append(listed, p.Issuer)
	}
	switch {
	case len(c.OIDC) == 0:
		return api.OIDCProvider{}, fmt.Errorf("the broker takes no OIDC login: it lists no identity provider "+
			"(its methods: %s)", strings.Join(c.Methods, ", "))
	case issuer != "":
		for _, p := range c.OIDC {
			if p.Issuer == issuer {
				return p, nil
			}
		}
		return api.OIDCProvider{}, fmt.Errorf("the broker does not list %s; it lists %s", issuer, strings.Join(listed, ", "))
	case len(c.OIDC) > 1:
		return api.OIDCProvider{}, fmt.Errorf("the broker lists %d identity providers (%s); name one with --issuer or "+
			"oidc_issuer", len(c.OIDC), strings.Join(listed, ", "))
	}
	return c.OIDC[0], nil
}

// fetchBrokerConfig is the broker's GET /v1/config, which needs no
// credential (design §17), over TLS 1.3 to the broker's CA alone and never
// through a proxy: the broker is the operator's own.
func fetchBrokerConfig(ctx context.Context, broker string, pool *x509.CertPool) (api.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(broker, "/")+"/v1/config", nil)
	if err != nil {
		return api.Config{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		var verify *tls.CertificateVerificationError
		if errors.As(err, &verify) {
			return api.Config{}, fmt.Errorf("the broker's certificate at %s does not verify (%v); check that the broker "+
				"CA (--broker-ca) is the CA that issued it", broker, verify.Err)
		}
		return api.Config{}, fmt.Errorf("the broker at %s is unreachable: %w", broker, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return api.Config{}, fmt.Errorf("%s/v1/config answered %s", broker, resp.Status)
	}
	var conf api.Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&conf); err != nil {
		return api.Config{}, fmt.Errorf("%s/v1/config: %w", broker, err)
	}
	return conf, nil
}

// warnSkew says when this host's clock is more than 5 minutes from the
// provider's (ruling 6): never a refusal, since the broker judges every
// token by its own clock.
func warnSkew(stderr io.Writer, what string, t oidcclient.Tokens) {
	skew, dir := oidcclient.Skew(t), "ahead of"
	if skew < 0 {
		skew, dir = -skew, "behind"
	}
	if skew <= 5*time.Minute {
		return
	}
	fmt.Fprintf(stderr, "%s: this host's clock is %s %s your identity provider's; the broker judges every token by "+
		"its own clock, so set this host's clock if the broker refuses yours\n", what, skew.Round(time.Second), dir)
}

// oidcHandoff is what `port49 login` hands the agent it starts, on an
// inherited pipe, never argv or the environment (ruling 7): the provider,
// its endpoints, and the sign-in's tokens.
type oidcHandoff struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	Scopes                []string `json:"scopes"`
	CAPEM                 string   `json:"ca_pem,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IssParameter          bool     `json:"iss_parameter"`
	RedirectPort          int      `json:"redirect_port,omitempty"`
	IDToken               string   `json:"id_token"`
	RefreshToken          string   `json:"refresh_token,omitempty"`
	ReceivedAt            string   `json:"received_at"`
}

// String withholds the tokens.
func (h oidcHandoff) String() string { return fmt.Sprintf("oidcHandoff{%s %s}", h.Issuer, h.ClientID) }

// GoString is String.
func (h oidcHandoff) GoString() string { return h.String() }

// Format is String for every verb, %+v included, which would print the
// fields.
func (h oidcHandoff) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, h.String()) }

// maxHandoff bounds the sign-in read from the login.
const maxHandoff = 64 << 10

// readHandoff reads the sign-in the login wrote on descriptor fd, to EOF.
// An error never quotes it: it holds the tokens.
func readHandoff(fd int) (oidcHandoff, error) {
	in := os.NewFile(uintptr(fd), "oidc-handoff")
	if in == nil {
		return oidcHandoff{}, fmt.Errorf("--oidc-fd %d is not an open descriptor", fd)
	}
	defer in.Close()
	raw, err := io.ReadAll(io.LimitReader(in, maxHandoff+1))
	if err != nil {
		return oidcHandoff{}, fmt.Errorf("reading the sign-in from the login: %w", err)
	}
	if len(raw) > maxHandoff {
		return oidcHandoff{}, fmt.Errorf("the sign-in from the login is over %d bytes", maxHandoff)
	}
	var h oidcHandoff
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil {
		return oidcHandoff{}, errors.New("the sign-in from the login does not decode")
	}
	return h, nil
}

// config is h as the agent's OIDCConfig.
func (h oidcHandoff) config() (agent.OIDCConfig, error) {
	var roots *x509.CertPool
	if h.CAPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(h.CAPEM)) {
			return agent.OIDCConfig{}, errors.New("the identity provider CA from the login holds no PEM certificate")
		}
	}
	id, err := oidc.ReadIDToken(h.IDToken, h.Issuer, h.ClientID, "")
	if err != nil {
		return agent.OIDCConfig{}, fmt.Errorf("the sign-in from the login: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, h.ReceivedAt)
	if err != nil {
		return agent.OIDCConfig{}, fmt.Errorf("the sign-in from the login names no received_at: %w", err)
	}
	return agent.OIDCConfig{
		Provider:     oidcclient.Provider{Issuer: h.Issuer, ClientID: h.ClientID, Scopes: h.Scopes, Roots: roots},
		Endpoints:    oidcclient.Endpoints{Authorization: h.AuthorizationEndpoint, Token: h.TokenEndpoint, IssParameter: h.IssParameter},
		Tokens:       oidcclient.Tokens{ID: id, IDRaw: h.IDToken, Refresh: h.RefreshToken, Received: at},
		CAPEM:        []byte(h.CAPEM),
		RedirectPort: h.RedirectPort,
	}, nil
}

// oidcRoots is the provider's TLS anchor (ruling 15): the config file's
// oidc_ca, read through its walk; --oidc-ca's file; or nil, the system's
// roots. pem is its bytes, for the agent's later sign-ins.
func (s *sessionFlags) oidcRoots() (*x509.CertPool, []byte, error) {
	caPEM := s.oidcCAPEM
	if caPEM == nil && s.oidcCA != "" {
		var err error
		if caPEM, err = os.ReadFile(s.oidcCA); err != nil {
			return nil, nil, err
		}
	}
	if caPEM == nil {
		return nil, nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("%s holds no PEM certificate", s.oidcCA)
	}
	return pool, caPEM, nil
}

// oidcConfig is the agent child's session on the OIDC path: the broker CA
// from descriptor 3 and the sign-in from oidcFD, both written by the login
// that started it.
func (s *sessionFlags) oidcConfig(log io.Writer) (agent.Config, error) {
	if s.broker == "" {
		return agent.Config{}, errors.New("--broker is required")
	}
	pool, err := s.brokerPool()
	if err != nil {
		return agent.Config{}, err
	}
	h, err := readHandoff(s.oidcFD)
	if err != nil {
		return agent.Config{}, err
	}
	oc, err := h.config()
	if err != nil {
		return agent.Config{}, err
	}
	return agent.Config{BrokerURL: s.broker, BrokerCA: pool, Now: time.Now, Log: log, OIDC: &oc}, nil
}
```

- [ ] **Step 6: `cmd/port49/main.go`**

- In `usage`, replace

  ```
    port49 login [--config FILE] [--broker URL] [--cert FILE] [--key FILE] [--broker-ca FILE] [--socket PATH]
                 (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml)
  ```

  with

  ```
    port49 login [--config FILE] [--broker URL] [--broker-ca FILE] [--socket PATH] [--cert FILE --key FILE |
                 --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser]]
                 (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml; --oidc
                 signs in at your identity provider in a browser, or prints the address to open elsewhere)
  ```

  and replace `  port49 refresh [--socket PATH]` with `  port49 refresh [--no-browser] [--socket PATH]`.

- In `sessionFlags`, after `brokerCAFD int`, add:

  ```go
  	// The OIDC path (plan 9b; spec §13 decision 43 ruling 15).
  	oidc         bool
  	issuer       string
  	oidcCA       string
  	redirectPort int
  	noBrowser    bool
  	// oidcCAPEM is oidc_ca's bytes, read by userconfig.Load through its walk.
  	oidcCAPEM []byte
  	// oidcFD is an inherited descriptor the login's sign-in comes on (the
  	// agent child's; hidden: the login sets it). 0 is unset.
  	oidcFD int
  ```

- In `register`, before the `--config` flag, add:

  ```go
  	fs.BoolVar(&s.oidc, "oidc", false, "sign in at the identity provider the broker lists, in place of a certificate")
  	fs.StringVar(&s.issuer, "issuer", "", "with --oidc: which provider, when the broker lists several")
  	fs.StringVar(&s.oidcCA, "oidc-ca", "", "with --oidc: the CA that issued your identity provider's certificate "+
  		"(PEM); the system's roots otherwise")
  	fs.IntVar(&s.redirectPort, "redirect-port", 0, "with --oidc: the loopback port the sign-in returns to; 0 picks a free one")
  	fs.BoolVar(&s.noBrowser, "no-browser", false, "with --oidc: open no browser; print the address to sign in at")
  	fs.IntVar(&s.oidcFD, "oidc-fd", 0, "internal: the descriptor the login passes the sign-in on")
  ```

- Replace `fill` and `args` with:

  ```go
  // fill takes from the config file each value the command line left out
  // (decision 42 ruling 6; decision 43 ruling 15). A missing file at the
  // default path is no file; one --config names must be there, and is read
  // and checked even when every flag is given. A flag wins: --oidc, or
  // --cert or --key, which make a certificate login, over the file's method.
  func (s *sessionFlags) fill(fs *flag.FlagSet) error {
  	set := map[string]bool{}
  	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
  	if !set["config"] && s.complete() {
  		return nil
  	}
  	var opts []userconfig.Option
  	if s.brokerCA != "" {
  		opts = append(opts, userconfig.WithoutCA()) // --broker-ca wins; the file's is unused
  	}
  	if s.oidcCA != "" {
  		opts = append(opts, userconfig.WithoutOIDCCA())
  	}
  	f, ok, err := userconfig.Load(s.configFile, opts...)
  	switch {
  	case err != nil:
  		return err
  	case !ok && set["config"]:
  		return fmt.Errorf("%s: no such file", s.configFile)
  	case !ok:
  		return nil
  	}
  	if s.brokerCA == "" {
  		s.brokerCA, s.brokerCAPEM = f.BrokerCA, f.BrokerCAPEM
  	}
  	if s.oidcCA == "" {
  		s.oidcCA, s.oidcCAPEM = f.OIDCCA, f.OIDCCAPEM
  	}
  	s.broker = cmp.Or(s.broker, f.Broker)
  	s.cert, s.key = cmp.Or(s.cert, f.Cert), cmp.Or(s.key, f.Key)
  	if !set["oidc"] && !set["cert"] && !set["key"] {
  		s.oidc = f.Method == "oidc"
  	}
  	s.issuer = cmp.Or(s.issuer, f.OIDCIssuer)
  	if !set["redirect-port"] {
  		s.redirectPort = f.OIDCRedirectPort
  	}
  	return nil
  }

  // complete is whether the command line names all this command needs, so
  // the config file is not read: the agent child is handed all of it, and a
  // certificate login with all four flags reads no file, as before.
  func (s *sessionFlags) complete() bool {
  	if s.oidcFD != 0 {
  		return s.broker != "" && s.brokerCA != ""
  	}
  	return !s.oidc && s.broker != "" && s.cert != "" && s.key != "" && s.brokerCA != ""
  }

  func (s *sessionFlags) args() []string {
  	a := []string{"--broker", s.broker, "--broker-ca", s.brokerCA, "--socket", s.socket}
  	if !s.oidc {
  		a = append(a, "--cert", s.cert, "--key", s.key)
  	}
  	return a
  }
  ```

- Replace `config` with `brokerPool` and a shorter `config`:

  ```go
  // brokerPool is the broker CA's pool, from the bytes the config file's walk
  // read, the login's descriptor, or --broker-ca's path, in that order. It
  // keeps the bytes in brokerCAPEM for the agent the login starts. Required,
  // not defaulted: with no pool the agent would trust every public CA for a
  // broker whose certificate a private CA issued.
  func (s *sessionFlags) brokerPool() (*x509.CertPool, error) {
  	if s.brokerCA == "" {
  		return nil, errors.New("--broker-ca is required: the CA that issued the broker's certificate; the system's " +
  			"roots are not trusted for the broker")
  	}
  	caPEM := s.brokerCAPEM
  	// source is where the bytes came from, for the message when they hold no
  	// certificate: the path is only read in the default case.
  	source := s.brokerCA
  	var err error
  	switch {
  	case caPEM != nil:
  		source = "the broker CA read for " + s.configFile + " (" + s.brokerCA + ")"
  	case s.brokerCAFD != 0:
  		source = "the broker CA the login passed (from " + s.brokerCA + ")"
  		// The login read the CA once and passed the bytes; the path is not
  		// read again.
  		in := os.NewFile(uintptr(s.brokerCAFD), "broker-ca")
  		if in == nil {
  			return nil, fmt.Errorf("--broker-ca-fd %d is not an open descriptor", s.brokerCAFD)
  		}
  		defer in.Close()
  		if caPEM, err = io.ReadAll(io.LimitReader(in, maxBrokerCA+1)); err != nil {
  			return nil, fmt.Errorf("reading the broker CA from the login: %w", err)
  		}
  		if len(caPEM) > maxBrokerCA {
  			return nil, fmt.Errorf("the broker CA is over %d bytes", maxBrokerCA)
  		}
  	default:
  		// Named by --broker-ca: the operator's own choice of path.
  		if caPEM, err = os.ReadFile(s.brokerCA); err != nil {
  			return nil, err
  		}
  	}
  	s.brokerCAPEM = caPEM
  	pool := x509.NewCertPool()
  	if !pool.AppendCertsFromPEM(caPEM) {
  		return nil, fmt.Errorf("%s holds no PEM certificate", source)
  	}
  	return pool, nil
  }

  func (s *sessionFlags) config(log io.Writer) (agent.Config, error) {
  	if s.broker == "" || s.cert == "" || s.key == "" {
  		return agent.Config{}, fmt.Errorf("--broker, --cert, --key and --broker-ca are all required, as flags "+
  			"or in %s", s.configFile)
  	}
  	if s.brokerCA == "" {
  		return agent.Config{}, errors.New("--broker-ca is required: the CA that issued the broker's certificate; " +
  			"the system's roots are not trusted for the broker")
  	}
  	// Refused if the key is a symlink or readable by anyone but its owner
  	// (keyfile; pre-flight F14).
  	cert, err := keyfile.LoadX509KeyPair(s.cert, s.key)
  	if err != nil {
  		return agent.Config{}, fmt.Errorf("loading the client certificate: %w", err)
  	}
  	pool, err := s.brokerPool()
  	if err != nil {
  		return agent.Config{}, err
  	}
  	return agent.Config{BrokerURL: s.broker, Cert: cert, BrokerCA: pool, Now: time.Now, Log: log}, nil
  }
  ```

- In `login`, replace

  ```go
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	if err := sf.fill(fs); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 2
  	}
  	cfg, err := sf.config(stderr)
  ```

  with

  ```go
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	set := map[string]bool{}
  	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
  	if sf.oidc && (set["cert"] || set["key"]) {
  		fmt.Fprintln(stderr, "port49 login: --cert and --key are a certificate login's; --oidc signs in at your "+
  			"identity provider instead")
  		return 2
  	}
  	if err := sf.fill(fs); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 2
  	}
  	if sf.oidc {
  		return loginOIDC(&sf, stdout, stderr)
  	}
  	cfg, err := sf.config(stderr)
  ```

  and in its running-agent switch, before `case agent.CertFingerprint(cfg.Cert) != st.CertFingerprint:`,
  add:

  ```go
  		case st.Method == "oidc":
  			other = fmt.Sprintf("an agent for %s through %s", st.Broker, st.OIDCIssuer)
  ```

- Move the rest of `login`, from `dir := filepath.Dir(sf.socket)` to its end, into a new
  function, and end `login` with `return startAgent(&sf, nil, stdout, stderr)`. The new function:

  ```go
  // startAgent starts the agent in its own session, detached, and waits until
  // its socket answers. The broker CA's bytes go to it on descriptor 3 and, on
  // the OIDC path, the sign-in on descriptor 4 (decision 43 ruling 7), so it
  // reads neither path again and no token is in its argv or environment. The
  // certificate path then refreshes once, so the device sessions an earlier
  // login left are extended; the OIDC path does not, since its refresh is a
  // second sign-in (ruling 12).
  func startAgent(sf *sessionFlags, h *oidcHandoff, stdout, stderr io.Writer) int {
  	ctx := context.Background()
  	dir := filepath.Dir(sf.socket)
  	if err := agent.PrivateDir(dir); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
  		return 1
  	}
  	logPath := filepath.Join(dir, "agent.log")
  	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	defer logf.Close()
  	self, err := os.Executable()
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	caR, caW, err := os.Pipe()
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	defer caR.Close()
  	defer caW.Close()
  	args := append(append([]string{"agent"}, sf.args()...), "--broker-ca-fd", "3")
  	extra := []*os.File{caR}
  	var hR, hW *os.File
  	if h != nil {
  		if hR, hW, err = os.Pipe(); err != nil {
  			fmt.Fprintln(stderr, "port49 login:", err)
  			return 1
  		}
  		defer hR.Close()
  		defer hW.Close()
  		args = append(args, "--oidc-fd", "4")
  		extra = append(extra, hR)
  	}
  	cmd := exec.Command(self, args...)
  	cmd.Stdout, cmd.Stderr = logf, logf
  	cmd.ExtraFiles = extra
  	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
  	if err := cmd.Start(); err != nil {
  		fmt.Fprintln(stderr, "port49 login: starting the agent:", err)
  		return 1
  	}
  	caR.Close()
  	// Goroutines: a pipe holds 64 KiB, and the CA may be larger. An agent
  	// that dies leaves the write failing, which ends it.
  	go func() {
  		_, _ = caW.Write(sf.brokerCAPEM)
  		caW.Close()
  	}()
  	if h != nil {
  		hR.Close()
  		body, err := json.Marshal(h)
  		if err != nil {
  			_ = cmd.Process.Kill()
  			fmt.Fprintln(stderr, "port49 login:", err)
  			return 1
  		}
  		go func() {
  			_, _ = hW.Write(body)
  			hW.Close()
  		}()
  	}
  	exited := make(chan error, 1)
  	go func() { exited <- cmd.Wait() }()
  	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
  		select {
  		case err := <-exited:
  			tail, _ := os.ReadFile(logPath)
  			fmt.Fprintf(stderr, "port49 login: the agent exited (%v); the end of %s:\n%s", err, logPath, lastLines(string(tail), 10))
  			return 1
  		case <-time.After(100 * time.Millisecond):
  		}
  		st, err := agent.NewClient(sf.socket).Status(ctx)
  		if err != nil {
  			continue
  		}
  		if h != nil {
  			fmt.Fprintf(stdout, "port49: logged in to %s through %s; the session ends at %s (agent pid %d, log %s)\n",
  				st.Broker, st.OIDCIssuer, st.SessionEndsAt, cmd.Process.Pid, logPath)
  			return 0
  		}
  		fmt.Fprintf(stdout, "port49: logged in to %s; the session ends at %s (agent pid %d, log %s)\n",
  			st.Broker, st.SessionEndsAt, cmd.Process.Pid, logPath)
  		// The session is up whatever the refresh does: a failure is
  		// said, and the login still succeeds.
  		if out, err := agent.NewClient(sf.socket).Refresh(ctx); err != nil {
  			fmt.Fprintln(stderr, "port49 login: logged in, but the refresh of your live device sessions failed:",
  				unprefixed(err))
  		} else {
  			printRefresh(stdout, out)
  		}
  		return 0
  	}
  	_ = cmd.Process.Kill()
  	fmt.Fprintf(stderr, "port49 login: the agent did not answer within 15s; see %s\n", logPath)
  	return 1
  }
  ```

  `login` keeps `ctx := context.Background()` for its running-agent check. `main.go` already
  imports everything `startAgent` uses (`encoding/json`, `os/exec`, `syscall`).

- In `agentMain`, as its first statement:

  ```go
  	// Before any credential is read (decision 43 ruling 7).
  	if err := harden(); err != nil {
  		fmt.Fprintf(stderr, "port49 agent: could not make the agent non-dumpable (%v); it runs on\n", err)
  	}
  ```

  and replace

  ```go
  	cfg, err := sf.config(stderr)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
  		return 2
  	}
  ```

  with

  ```go
  	var cfg agent.Config
  	var err error
  	if sf.oidcFD != 0 {
  		cfg, err = sf.oidcConfig(stderr)
  	} else {
  		cfg, err = sf.config(stderr)
  	}
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
  		return 2
  	}
  ```

- [ ] **Step 7: `cmd/port49/refresh.go`**

Replace `refreshCmd`'s body from `socket := fs.String(…)` to `out, err := agent.NewClient(*socket).Refresh(context.Background())` with:

```go
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	noBrowser := fs.Bool("no-browser", false, "an OIDC session: open no browser; print the address to sign in at")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx := context.Background()
	c := agent.NewClient(*socket)
	// An OIDC session's refresh is a sign-in, run here (decision 43 ruling 12).
	if st, err := c.Status(ctx); err == nil && st.Method == "oidc" {
		return refreshOIDC(ctx, c, *noBrowser, "port49 refresh", stdout, stderr)
	}
	out, err := c.Refresh(ctx)
```

- [ ] **Step 8: `newLabBrokerWith` in `cmd/port49/main_test.go`**

Rename `newLabBroker` to `newLabBrokerWith(t *testing.T, maxAge time.Duration, iss *oidctest.Issuer)
*labBroker`, add `func newLabBroker(t *testing.T, maxAge time.Duration) *labBroker { return
newLabBrokerWith(t, maxAge, nil) }`, and add `"github.com/rhwendt/port49/internal/oidc"` and
`"github.com/rhwendt/port49/internal/oidc/oidctest"` to the imports. In the renamed body, with
`iss` not nil, the broker is OIDC-only on iss (decision 39), and the seeded context is indexed by
principal alone:

- After the `l.b = &broker.Broker{…}` statement, add:

  ```go
  	if iss != nil {
  		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
  			MaxAge: 24 * time.Hour, Now: l.now, M: l.b.Metrics})
  		l.b.NoX509 = true
  		l.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: l.now, M: l.b.Metrics,
  			Verifiers: []*oidc.Verifier{{VerifierConfig: oidc.VerifierConfig{Domain: oidc.Humans, Issuer: iss.URL,
  				ClientID: "port49-cli", PrincipalClaim: oidc.ClaimPreferredUsername,
  				PrincipalDomains: []string{"example.com"}, Scopes: []string{"openid"},
  				Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks}}}
  	}
  ```

- Replace

  ```go
  	leaf, err := x509.ParseCertificate(cli.Certificate[0])
  	if err != nil {
  		t.Fatal(err)
  	}
  	if err := l.st.IndexContext(ctx, "user:alice@example.com", "",
  		store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)),
  		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
  		t.Fatal(err)
  	}

  	srv, err := l.b.Server("127.0.0.1:0", srvCert, pool)
  ```

  with

  ```go
  	leaf, err := x509.ParseCertificate(cli.Certificate[0])
  	if err != nil {
  		t.Fatal(err)
  	}
  	certKey, anchor := store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)), pool
  	if iss != nil {
  		// An OIDC context has no certificate; an OIDC-only broker takes no anchor.
  		certKey, anchor = "", nil
  	}
  	if err := l.st.IndexContext(ctx, "user:alice@example.com", "", certKey,
  		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
  		t.Fatal(err)
  	}

  	srv, err := l.b.Server("127.0.0.1:0", srvCert, anchor)
  ```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `go test ./internal/userconfig/ ./cmd/port49/ -count=1`
Expected: PASS, every earlier `cmd/port49` and `userconfig` test unchanged.

Run: `go vet ./... && go test -race ./internal/userconfig/ ./cmd/port49/ -count=1`
Expected: PASS, and vet silent.

- [ ] **Step 10: Commit**

```bash
git add internal/userconfig/ cmd/port49/
git commit -m "feat(port49): login --oidc and the OIDC refresh: a sign-in in the command, tokens to the agent on a pipe, a non-dumpable agent"
```

---

### Task 8: Lab L55 (Keycloak as the client meets it) and L56 (end to end on vEOS)

**Files:**
- Create: `tests/lab/l55_test.go`, `tests/lab/l56_test.go`, `tests/lab/l55_l56_unit_test.go` (each
  `//go:build lab`)
- Create, by the run: `tests/lab/results/L55-keycloak.md`, `tests/lab/results/L56-arista_eos.md`, and
  `tests/lab/evidence/L55-keycloak.json`; the L56 capture through `make evidence`
- Modify: `Makefile` (`lab-oidc-l55`, `lab-oidc-agent`), `tests/lab/README.md` (an "OIDC agent"
  section), `docs/design/2026-08-23-policy-engine-spec.md` §15 (L55, L56 statuses), decision 43, and
  any text the results contradict

**Interfaces:**
- Consumes: `bin/port49` (`make build`); from the lab harness: `startKeycloak`, `keycloakClient`,
  `waitDiscovery`, `formAction`, `claimsOf`, `oidcEvidence`, `writeOIDCResult`, `leakIn`,
  `scrubbed`, `randomSecret`, `wideCell`, `oneLineMax`, `errCause`, `kcHost`, `kcPort`, `kcRealm`,
  `kcClient`, `kcRedirect`, `oidcAlice`, `oidcAlicePassword`, `oidcBrokerLogout`, `oidcE2EFiles`,
  `oidcE2EPKI`, `oidcBroker` (`mintRetry`), `brokerClient`, `sliceBrokerURL`, `slicePKIDir`, `root`,
  `platformSelection`, `labFor`, `l.startComposeWith`, `c.run`, `c.local`, `l.capture`, `l.shell`,
  `l.runPermitted`, `l.result`, `(k *keycloak) adminFromEnv`, `Admin`, `adminDo`, `UserID`,
  `LogoutUser`, `SetLogoutURL`, `EndSession`, `know`, `known`.
- Produces: the two rows' notes. Until they close, decision 43's rulings 1, 4, 9 and 10 stay
  provisional, and no doc says which redirect registration Keycloak accepts.

The lab runs on the SER8 (memory: lab runs allowed; lab stays single-occupant). L55 needs Docker
alone. L56 needs the compose stack, containerlab and the EOS image.

- [ ] **Step 1: The pure helpers and their unit test**

Create `tests/lab/l55_l56_unit_test.go`:

```go
//go:build lab

package lab

import (
	"strings"
	"testing"
	"time"
)

func TestL56AuthURLReadsPort49sLine(t *testing.T) {
	for line, want := range map[string]string{
		"  https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x": "https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x",
		"port49: open this address in a browser and sign in at https://keycloak.port49.lab:18443/realms/port49-lab:":      "",
		"  http://127.0.0.1:18749/callback": "",
	} {
		if got, ok := l56AuthURL(line); got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", line, got, ok)
		}
	}
}

func TestL56LoginFromReadsTheBrokersTime(t *testing.T) {
	at, ok := l56LoginFrom("port49 token: the session is over: your identity provider ended your sessions at " +
		"2026-10-10T03:00:00Z (back-channel logout); log in again from 2026-10-10T03:01:01Z\n")
	if !ok || !at.Equal(time.Date(2026, 10, 10, 3, 1, 1, 0, time.UTC)) {
		t.Fatalf("%v %v", at, ok)
	}
	if _, ok := l56LoginFrom("port49 token: no agent"); ok {
		t.Fatal("read a time from nothing")
	}
}

func TestL55AcceptedIsTheLoginForm(t *testing.T) {
	form := []byte(`<form id="kc-form-login" class="x" action="https://k/login-actions/authenticate?x=1" method="post">`)
	if !l55Accepted(200, form) || l55Accepted(400, []byte("Invalid parameter: redirect_uri")) || l55Accepted(200, []byte("<html/>")) {
		t.Fatal("misread")
	}
}

func TestL56FilesAskForTheEmailScope(t *testing.T) {
	files := map[string]string{
		"port49-broker.yaml": "broker:\n  client_ca_file: /etc/port49/ca.pem\n  listen: x\n",
		"policy.yaml":        "subjects:\ngrants:\n",
	}
	if err := l56Files(files); err != nil {
		t.Fatal(err)
	}
	if want := "        principal_claim: email\n        scopes: [openid, email]\n"; !strings.Contains(files["port49-broker.yaml"], want) {
		t.Fatalf("%s", files["port49-broker.yaml"])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags lab ./tests/lab/ -run 'TestL56AuthURL|TestL56LoginFrom|TestL55Accepted|TestL56Files' -count=1`
Expected: FAIL to build: `undefined: l56AuthURL`.

- [ ] **Step 3: L55**

Create `tests/lab/l55_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const l55Claim = "Keycloak as port49's public client meets it (plan 9b): which redirect registration admits an " +
	"authorization request naming http://127.0.0.1:<port>/callback, for the registered port and for another, " +
	"ephemeral one (RFC 8252 §7.3); whether a code is exchanged with the right S256 verifier, a wrong one and none, " +
	"and whether code_challenge_method=plain is accepted; discovery's code_challenge_methods_supported and " +
	"authorization_response_iss_parameter_supported, and whether the authorization response carries iss (RFC " +
	"9207); whether the refresh-token grant returns an ID token keeping iss, sub, aud, sid and auth_time with no " +
	"nonce, whether it rotates the refresh token and still takes a rotated-out one; what it answers after an " +
	"RP-initiated logout, an administrator's sign-out, ssoSessionIdleTimeout and ssoSessionMaxLifespan; and whether " +
	"a prompt=login sign-in inside the SSO session restarts the session's maximum lifespan (policy engine spec §15 " +
	"L55; §13 decision 43 rulings 1, 4, 9 and 10)."

// l55Accepted is whether Keycloak took an authorization request: it showed
// the login form, rather than its "Invalid parameter" page.
func l55Accepted(status int, body []byte) bool { return status == http.StatusOK && formAction.Match(body) }

// l55Browser is a browser of its own: a fresh cookie jar, so no SSO session.
func (k *keycloak) l55Browser() *http.Client {
	c := keycloakClient(k.ca)
	c.Jar, _ = cookiejar.New(nil)
	return c
}

// l55Authorize is an authorization request for port49-cli naming redirect,
// with an S256 challenge for verifier, a fresh state, and extra.
func (k *keycloak) l55Authorize(t *testing.T, redirect, verifier string, extra url.Values) string {
	t.Helper()
	state := randomSecret(t)
	k.know(verifier, state)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {redirect},
		"scope": {"openid email"}, "state": {state}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for key, v := range extra {
		q[key] = v
	}
	return k.URL + "/protocol/openid-connect/auth?" + q.Encode()
}

// authorizeAccepted asks with a fresh browser and reports whether Keycloak
// showed the login form.
func (k *keycloak) authorizeAccepted(t *testing.T, redirect string, extra url.Values) bool {
	t.Helper()
	resp, err := k.l55Browser().Get(k.l55Authorize(t, redirect, randomSecret(t)+randomSecret(t), extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return l55Accepted(resp.StatusCode, body)
}

// l55SignIn signs alice in with browser and returns the code, its verifier,
// and the authorization response's query (the code registered as secret).
func (k *keycloak) l55SignIn(t *testing.T, browser *http.Client, extra url.Values) (string, string, url.Values) {
	t.Helper()
	verifier := randomSecret(t) + randomSecret(t)
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, verifier, extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: authorize answered %s with no login form; no note is written", resp.Status)
		}
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {oidcAlice},
			"password": {oidcAlicePassword}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("INVALID: no code (%s, redirect %s); no note is written", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	return loc.Query().Get("code"), verifier, loc.Query()
}

// tokenTry posts form to the token endpoint and returns the status and the
// answer, registering every token in it as secret; it never fails the test.
func (k *keycloak) tokenTry(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := k.HTTP.PostForm(k.URL+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token endpoint: %s", errCause(err))
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, key := range []string{"id_token", "access_token", "refresh_token"} {
		if v, ok := out[key].(string); ok {
			k.know(v)
		}
	}
	return resp.StatusCode, out
}

// exchange is the code's exchange with verifierSent ("" sends none).
func (k *keycloak) l55Exchange(t *testing.T, code, verifierSent string) (int, map[string]any) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {kcRedirect},
		"client_id": {kcClient}}
	if verifierSent != "" {
		form.Set("code_verifier", verifierSent)
	}
	return k.tokenTry(t, form)
}

func (k *keycloak) l55Refresh(t *testing.T, rt string) (int, map[string]any) {
	return k.tokenTry(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {kcClient},
		"scope": {"openid email"}})
}

// l55Said is a token answer as a cell: its status, and its error or what it
// carried.
func l55Said(status int, out map[string]any) string {
	if e, ok := out["error"]; ok {
		return fmt.Sprintf("%d %v", status, e)
	}
	var has []string
	for _, key := range []string{"id_token", "refresh_token"} {
		if _, ok := out[key]; ok {
			has = append(has, key)
		}
	}
	return fmt.Sprintf("%d with %s", status, strings.Join(has, ", "))
}

// redirects and setRedirects read and replace port49-cli's redirect URIs;
// setRedirects reports whether Keycloak took them, read back.
func (k *keycloak) redirects(t *testing.T) (map[string]any, []string) {
	t.Helper()
	var clients []map[string]any
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("%d clients named %s", len(clients), kcClient)
	}
	var uris []string
	for _, u := range clients[0]["redirectUris"].([]any) {
		uris = append(uris, u.(string))
	}
	return clients[0], uris
}

func (k *keycloak) setRedirects(t *testing.T, uris []string) bool {
	t.Helper()
	c, _ := k.redirects(t)
	c["redirectUris"] = uris
	b, _ := json.Marshal(c)
	req, _ := http.NewRequest("PUT", "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+"/clients/"+c["id"].(string),
		strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("PUT the client: %s", errCause(err))
	}
	resp.Body.Close()
	_, got := k.redirects(t)
	return resp.StatusCode/100 == 2 && slices.Equal(got, uris)
}

func l55FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestL55PublicClient(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L55-keycloak")
	var obs strings.Builder
	obs.WriteString("| step | observed |\n|---|---|\n")
	cell := func(step, what string) {
		fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what))
		ev(step, what)
	}

	// 1. Discovery and the answer's iss.
	var disc map[string]any
	resp, err := k.HTTP.Get(k.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %s", errCause(err))
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	cell("1a. discovery code_challenge_methods_supported", fmt.Sprint(disc["code_challenge_methods_supported"]))
	cell("1b. discovery authorization_response_iss_parameter_supported",
		fmt.Sprint(disc["authorization_response_iss_parameter_supported"]))
	_, _, q := k.l55SignIn(t, k.l55Browser(), nil)
	cell("1c. the authorization response's iss", fmt.Sprintf("present %v, the issuer %v", q.Has("iss"), q.Get("iss") == k.URL))

	// 2. The redirect registrations, each against the registered port and an ephemeral one.
	_, orig := k.redirects(t)
	defer k.setRedirects(t, orig)
	ephemeral := l55FreePort(t)
	for _, reg := range []string{kcRedirect, "http://127.0.0.1/callback", "http://127.0.0.1/*", "http://127.0.0.1:*/callback"} {
		if !k.setRedirects(t, []string{reg}) {
			cell("2. registration "+reg, "not taken by the admin API")
			continue
		}
		var parts []string
		for _, port := range []int{18749, ephemeral} {
			parts = append(parts, fmt.Sprintf("port %d %s", port, map[bool]string{true: "accepted", false: "refused"}[
				k.authorizeAccepted(t, fmt.Sprintf("http://127.0.0.1:%d/callback", port), nil)]))
		}
		cell("2. registration "+reg, strings.Join(parts, "; "))
	}
	if !k.setRedirects(t, []string{kcRedirect}) {
		t.Fatal("INVALID: the realm's own redirect could not be put back; no note is written")
	}

	// 3. PKCE.
	for _, c := range []struct{ name, how string }{{"the right verifier", "right"}, {"a wrong verifier", "wrong"},
		{"no verifier", "none"}} {
		code, verifier, _ := k.l55SignIn(t, k.l55Browser(), nil)
		sent := map[string]string{"right": verifier, "wrong": verifier + "x", "none": ""}[c.how]
		cell("3. the exchange with "+c.name, l55Said(k.l55Exchange(t, code, sent)))
	}
	cell("3d. code_challenge_method=plain", map[bool]string{true: "accepted", false: "refused"}[
		k.authorizeAccepted(t, kcRedirect, url.Values{"code_challenge_method": {"plain"},
			"code_challenge": {randomSecret(t) + randomSecret(t)}})])

	// 4. The refresh-token grant.
	code, verifier, _ := k.l55SignIn(t, k.l55Browser(), url.Values{"nonce": {"n-l55"}})
	_, first := k.l55Exchange(t, code, verifier)
	idA, _ := first["id_token"].(string)
	rtA, _ := first["refresh_token"].(string)
	st, second := k.l55Refresh(t, rtA)
	idB, _ := second["id_token"].(string)
	rtB, _ := second["refresh_token"].(string)
	cell("4a. the refresh-token grant", l55Said(st, second))
	cell("4b. it rotates the refresh token", fmt.Sprint(rtB != "" && rtB != rtA))
	if idA != "" && idB != "" {
		_, a := claimsOf(idA)
		_, b := claimsOf(idB)
		var kept []string
		for _, c := range []string{"iss", "sub", "aud", "sid", "auth_time"} {
			kept = append(kept, fmt.Sprintf("%s %v", c, fmt.Sprint(a[c]) == fmt.Sprint(b[c])))
		}
		cell("4c. the renewed ID token keeps", strings.Join(kept, ", ")+fmt.Sprintf("; nonce %v", b["nonce"]))
	}
	cell("4d. the rotated-out refresh token, used again", l55Said(k.l55Refresh(t, rtA)))

	// 5. After an RP-initiated logout, and 6. after an administrator's sign-out.
	code, verifier, _ = k.l55SignIn(t, k.l55Browser(), nil)
	_, s5 := k.l55Exchange(t, code, verifier)
	k.EndSession(t, s5["id_token"].(string))
	cell("5. the refresh grant after an RP-initiated logout", l55Said(k.l55Refresh(t, s5["refresh_token"].(string))))
	code, verifier, _ = k.l55SignIn(t, k.l55Browser(), nil)
	_, s6 := k.l55Exchange(t, code, verifier)
	k.LogoutUser(t, k.UserID(t, oidcAlice))
	cell("6. the refresh grant after an administrator's sign-out", l55Said(k.l55Refresh(t, s6["refresh_token"].(string))))

	// 7 and 8. The session limits, shortened for the run and put back.
	k.adminDo(t, "PUT", "", map[string]any{"ssoSessionIdleTimeout": 60, "ssoSessionMaxLifespan": 150}, nil)
	defer k.adminDo(t, "PUT", "", map[string]any{"ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 36000}, nil)
	code, verifier, _ = k.l55SignIn(t, k.l55Browser(), nil)
	_, s7 := k.l55Exchange(t, code, verifier)
	time.Sleep(75 * time.Second)
	cell("7. the refresh grant 75s after the last use, ssoSessionIdleTimeout 60s", l55Said(k.l55Refresh(t, s7["refresh_token"].(string))))
	browser := k.l55Browser()
	t0 := time.Now()
	code, verifier, _ = k.l55SignIn(t, browser, nil)
	_, s8 := k.l55Exchange(t, code, verifier)
	rt := s8["refresh_token"].(string)
	var line []string
	for _, at := range []time.Duration{40 * time.Second, 80 * time.Second, 100 * time.Second, 120 * time.Second, 165 * time.Second} {
		time.Sleep(time.Until(t0.Add(at)))
		if at == 100*time.Second {
			// A prompt=login sign-in in the same browser: the same SSO session.
			c2, v2, _ := k.l55SignIn(t, browser, nil)
			_, s := k.l55Exchange(t, c2, v2)
			if r, ok := s["refresh_token"].(string); ok {
				rt = r
			}
			line = append(line, "+100s prompt=login sign-in")
			continue
		}
		st, out := k.l55Refresh(t, rt)
		if r, ok := out["refresh_token"].(string); ok {
			rt = r
		}
		line = append(line, fmt.Sprintf("+%ds %s", int(at/time.Second), l55Said(st, out)))
	}
	cell("8. ssoSessionMaxLifespan 150s, grants every 40s, a prompt=login sign-in at +100s", strings.Join(line, "; "))
	writeOIDCResult(t, k, "L55", l55Claim, obs.String(), evPath)
}
```

`locShape` is `oidcflow_test.go`'s. `k.adminDo(t, "PUT", "", …)` is the realm itself
(`/admin/realms/port49-lab`), which takes a partial representation.

- [ ] **Step 4: L56**

Create `tests/lab/l56_test.go`:

```go
//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

const l56Claim = "The agent's OIDC session end to end on Keycloak and one device (plan 9b), with the real port49 " +
	"CLI and the realm's Access Token Lifespan at 60s: port49 login --oidc --no-browser signs in through a " +
	"scripted browser and starts the agent; port49 token mints and the device takes the token over SSH; port49 " +
	"token still mints after two ID-token lifetimes with no browser; port49 refresh asks the password again and " +
	"extends the device session; an administrator's sign-out ends the agent with the broker's logout words and a " +
	"login from the time they name works; with Keycloak stopped, port49 token mints until the held ID token's life " +
	"ends, then says the provider did not renew it and not to log in, the agent still running, and with Keycloak " +
	"started again a port49 token mints with no login (or what the agent says if Keycloak lost its sessions); no " +
	"compact JWS in the CLI's output or the agent's log (policy engine spec §15 L56; §13 decision 43)."

// l56AuthURL is the authorization URL port49 prints on its own line,
// indented two spaces.
func l56AuthURL(line string) (string, bool) {
	if !strings.HasPrefix(line, "  https://") || strings.ContainsAny(strings.TrimSpace(line), " \t") {
		return "", false
	}
	return strings.TrimSpace(line), true
}

var loginFrom = regexp.MustCompile(`log in again from (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)`)

// l56LoginFrom is the time the broker's logout words say a login is taken from.
func l56LoginFrom(text string) (time.Time, bool) {
	m := loginFrom.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, m[1])
	return at, err == nil
}

// l56Files is the end to end's files, the human verifier asking for the
// email scope its principal claim needs.
func l56Files(files map[string]string) error {
	if err := oidcE2EFiles(files); err != nil {
		return err
	}
	const at = "        principal_claim: email\n"
	if !strings.Contains(files["port49-broker.yaml"], at) {
		return fmt.Errorf("port49-broker.yaml has no human verifier's principal_claim to follow")
	}
	files["port49-broker.yaml"] = strings.Replace(files["port49-broker.yaml"], at, at+"        scopes: [openid, email]\n", 1)
	return nil
}

// l56Proxy is a CONNECT proxy on loopback that takes the CLI to Keycloak by
// its issuer's name, which this host does not resolve: the test's own client
// dials it through kcDial. It tunnels to that one name alone. It is lab
// plumbing, and the note says so.
func l56Proxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != kcHost+":"+kcPort {
			http.Error(w, "l56 proxy: "+kcHost+" alone", http.StatusForbidden)
			return
		}
		up, err := net.DialTimeout("tcp", "127.0.0.1:"+kcPort, 10*time.Second)
		if err != nil {
			http.Error(w, "l56 proxy: "+err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		_, _ = io.Copy(conn, up)
		conn.Close()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// l56CLI is bin/port49 as an operator runs it: its own config directory
// and agent socket, the broker's CA, Keycloak's CA, and the proxy.
type l56CLI struct {
	bin, sock string
	env       []string
	flags     []string
}

func newL56CLI(t *testing.T, proxy, idpCA string) *l56CLI {
	t.Helper()
	bin := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("bin/port49 is not built (`make build`): %v", err)
	}
	home, err := os.MkdirTemp("", "p49l56")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	c := &l56CLI{bin: bin, sock: filepath.Join(home, "run", "agent.sock"),
		env: append(os.Environ(), "XDG_CONFIG_HOME="+home, "HTTPS_PROXY=http://"+proxy, "NO_PROXY=127.0.0.1",
			"BROWSER=", "DISPLAY=", "WAYLAND_DISPLAY=")}
	c.flags = []string{"--oidc", "--no-browser", "--redirect-port", "18749", "--broker", sliceBrokerURL,
		"--broker-ca", filepath.Join(root, slicePKIDir, testpki.LabCA), "--oidc-ca", idpCA, "--socket", c.sock}
	t.Cleanup(c.stopAgent)
	return c
}

// l56Run is one command's outcome, scrubbed of every registered secret.
type l56Run struct {
	code           int
	stdout, stderr string
	form           bool // the scripted browser was shown the password form
}

func (r l56Run) cell() string {
	return fmt.Sprintf("exit %d; stdout %q; stderr %q", r.code, oneLineMax(r.stdout, 300), oneLineMax(r.stderr, 400))
}

// signIn runs port49 with args, reads the address from its stderr, signs in
// as alice in the scripted browser, and lets Keycloak's redirect reach
// port49's listener on 127.0.0.1:18749.
func (c *l56CLI) signIn(t *testing.T, kc *keycloak, browser *http.Client, args ...string) l56Run {
	t.Helper()
	cmd := exec.Command(c.bin, args...)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	errR, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	urls := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(errR)
		sc.Buffer(make([]byte, 64<<10), 64<<10)
		for sc.Scan() {
			stderr.WriteString(sc.Text() + "\n")
			if u, ok := l56AuthURL(sc.Text()); ok {
				select {
				case urls <- u:
				default:
				}
			}
		}
	}()
	r := l56Run{code: -1}
	select {
	case u := <-urls:
		if p, err := url.Parse(u); err == nil {
			kc.know(p.Query().Get("state"), p.Query().Get("nonce"), p.Query().Get("code_challenge"))
		}
		r.form = kc.browse(t, browser, u, oidcAlice, oidcAlicePassword)
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
	}
	waited := make(chan error, 1)
	go func() { <-done; waited <- cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-waited
	}
	r.code = cmd.ProcessState.ExitCode()
	r.stdout, r.stderr = scrubbed(stdout.String(), kc.known()), scrubbed(stderr.String(), kc.known())
	return r
}

// browse is a person's browser on an address port49 printed: it signs in
// when Keycloak shows the form, then follows the redirect to port49's
// loopback listener. It reports whether the form was shown.
func (k *keycloak) browse(t *testing.T, browser *http.Client, authURL, user, pass string) bool {
	t.Helper()
	resp, err := browser.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := false
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: the address port49 printed answered %s with no login form", resp.Status)
		}
		form = true
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "http://127.0.0.1:18749/callback") {
		t.Fatalf("INVALID: Keycloak did not send the browser to port49's listener (%s, %s)", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	cb, err := (&http.Client{Timeout: 10 * time.Second}).Get(loc.String())
	if err != nil {
		t.Fatalf("the callback: %s", errCause(err))
	}
	cb.Body.Close()
	return form
}

// run runs port49 with args and no sign-in.
func (c *l56CLI) run(kc *keycloak, args ...string) l56Run {
	cmd := exec.Command(c.bin, args...)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	r := l56Run{code: cmd.ProcessState.ExitCode(), stdout: stdout.String(), stderr: stderr.String()}
	if args[0] == "token" && r.code == 0 {
		kc.know(strings.TrimSpace(r.stdout))
	}
	r.stdout, r.stderr = scrubbed(r.stdout, kc.known()), scrubbed(r.stderr, kc.known())
	return r
}

// token mints device and returns the token, registered as secret.
func (c *l56CLI) token(kc *keycloak, device string) (string, l56Run) {
	cmd := exec.Command(c.bin, "token", "--socket", c.sock, device)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	tok := strings.TrimSpace(stdout.String())
	if cmd.ProcessState.ExitCode() != 0 {
		tok = ""
	}
	kc.know(tok)
	return tok, l56Run{code: cmd.ProcessState.ExitCode(), stdout: "[the token]",
		stderr: scrubbed(stderr.String(), kc.known())}
}

// stopAgent ends the agent listening on the socket, by its peer credentials.
func (c *l56CLI) stopAgent() {
	conn, err := net.Dial("unix", c.sock)
	if err != nil {
		return
	}
	var cred *syscall.Ucred
	if raw, err := conn.(*net.UnixConn).SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	conn.Close()
	if cred != nil && cred.Pid > 0 && int(cred.Pid) != os.Getpid() {
		_ = syscall.Kill(int(cred.Pid), syscall.SIGTERM)
	}
}

func TestL56AgentEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		if p.name != "arista_eos" {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) { l56(t, labFor(t, p)) })
		return
	}
	t.Skip("PORT49_LAB_PLATFORMS does not select arista_eos")
}

// l56 is the claim measured on one device. A fault in the setup is INVALID
// and stops before the note, as the 7h end to end's (oidcEndToEnd).
func l56(t *testing.T, l *lab) {
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
	complete := false
	var kc *keycloak

	now := time.Now()
	idpCA, err := testpki.NewCA("port49 lab oidc l56 CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: l56Files, Prepare: func(c *composeStack) error {
		brokerCA, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
		if err != nil {
			return err
		}
		return oidcE2EPKI(filepath.Join(c.local, "oidc"), idpCA, brokerCA, time.Now())
	}})
	stop := l.capture(t, "L56")
	defer stop()
	var cli *l56CLI
	defer func() {
		if !complete {
			if len(failed) > 0 {
				t.Errorf("L56, before it stopped: %s", strings.Join(failed, "; "))
			}
			return
		}
		note := "The CLI reaches Keycloak through a CONNECT proxy in the test (`l56Proxy`), since this host does " +
			"not resolve keycloak.port49.lab; that is lab plumbing, not part of the claim.\n\n" +
			"| step | observed |\n|---|---|\n" + obs.String()
		log, _ := os.ReadFile(filepath.Join(filepath.Dir(cli.sock), "agent.log"))
		if err := leakIn(string(log), kc.known()); err != nil {
			failed = append(failed, "the agent's log: "+err.Error())
		}
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if err := oidcNoteLeak(note, kc.known()); err != nil {
			t.Errorf("the L56 note is not written: %v", err)
			return
		}
		l.result(t, "L56", l56Claim, note)
		if len(failed) > 0 {
			t.Errorf("L56: %s", strings.Join(failed, "; "))
		}
	}()

	kc = &keycloak{URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm, ca: idpCA, HTTP: keycloakClient(idpCA)}
	kc.know(labSecrets...)
	kc.adminFromEnv(t, filepath.Join(c.local, "oidc", "admin.env"))
	kc.know(kc.admin)
	waitDiscovery(t, kc, 3*time.Minute)
	kc.SetLogoutURL(t, oidcBrokerLogout)
	kc.adminDo(t, "PUT", "", map[string]any{"accessTokenLifespan": 60}, nil)
	br := oidcBroker{c: brokerClient(t), kc: kc, base: sliceBrokerURL}
	// The broker takes Keycloak's tokens once its key fetch and start gate
	// allow (as oidcEndToEnd waits); a fault here is setup, not the claim.
	if tok, said := br.mintRetry(t, kc.Login(t, oidcAlice, oidcAlicePassword, nil).IDToken, l.p.node, 3*time.Minute); tok == "" {
		t.Fatalf("INVALID: the broker never took a Keycloak token: %s", said)
	}
	cli = newL56CLI(t, l56Proxy(t), filepath.Join(c.local, "oidc", "idp-ca.pem"))
	browser := keycloakClient(idpCA)
	browser.Jar, _ = cookiejar.New(nil)

	// 1. Login.
	r := cli.signIn(t, kc, browser, append([]string{"login"}, cli.flags...)...)
	cell("1. port49 login --oidc --no-browser, a scripted browser", r.cell()+fmt.Sprintf("; password asked %v", r.form))
	if r.code != 0 {
		t.Fatalf("INVALID: the login failed: %s", r.cell())
	}
	// 2. A token, and the device takes it.
	tok, tr := cli.token(kc, l.p.node)
	cell("2a. port49 token", tr.cell())
	if tok == "" {
		t.Fatalf("INVALID: the first token: %s", tr.cell())
	}
	sh, err := l.shell(oidcAlice, tok)
	if err != nil {
		t.Fatalf("INVALID: SSH with the token: %v", err)
	}
	res := l.runPermitted(sh, "show version", 20*time.Second)
	sh.Close()
	cell("2b. SSH as alice with it, `show version`", res.cell)
	// 3. Two ID-token lifetimes, no browser.
	time.Sleep(130 * time.Second)
	tok, tr = cli.token(kc, l.p.node)
	cell("3. port49 token 130s later (two 60s ID-token lifetimes), no browser", tr.cell())
	if tok == "" {
		fail("no token after two ID-token lifetimes: %s", tr.cell())
	}
	// 4. Refresh: a fresh sign-in, the device session extended.
	r = cli.signIn(t, kc, browser, "refresh", "--no-browser", "--socket", cli.sock)
	cell("4. port49 refresh --no-browser", r.cell()+fmt.Sprintf("; password asked %v", r.form))
	if r.code != 0 || !r.form || !strings.Contains(r.stdout, "extended to") {
		fail("the refresh: %s, password asked %v", r.cell(), r.form)
	}
	// 5. An administrator's sign-out ends the agent; a login from the time named works.
	kc.LogoutUser(t, kc.UserID(t, oidcAlice))
	time.Sleep(5 * time.Second)
	_, tr = cli.token(kc, l.p.node)
	cell("5a. port49 token after an administrator's sign-out", tr.cell())
	if tr.code == 0 || !strings.Contains(tr.stderr, "back-channel logout") {
		fail("after the sign-out: %s", tr.cell())
	}
	time.Sleep(2 * time.Second)
	gone := cli.run(kc, "identity", "--socket", cli.sock)
	cell("5b. the agent after it", gone.cell())
	if from, ok := l56LoginFrom(tr.stderr); ok {
		time.Sleep(time.Until(from) + time.Second)
	}
	browser.Jar, _ = cookiejar.New(nil) // the sign-out ended the browser's SSO session too
	r = cli.signIn(t, kc, browser, append([]string{"login"}, cli.flags...)...)
	cell("5c. port49 login again, from the time named", r.cell())
	if r.code != 0 {
		t.Fatalf("INVALID: the second login failed, so step 6 has no session: %s", r.cell())
	}
	// 6. Keycloak stopped, then started.
	if _, err := c.run("stop", "keycloak"); err != nil {
		t.Fatalf("INVALID: stopping Keycloak: %v", err)
	}
	_, tr = cli.token(kc, l.p.node)
	cell("6a. port49 token at once, Keycloak stopped", tr.cell())
	time.Sleep(75 * time.Second)
	_, tr = cli.token(kc, l.p.node)
	cell("6b. port49 token 75s later, Keycloak stopped", tr.cell())
	if tr.code == 0 || !strings.Contains(tr.stderr, "did not renew your ID token") || strings.Contains(tr.stderr, "port49 login") {
		fail("Keycloak down past the token's life: %s", tr.cell())
	}
	st := cli.run(kc, "identity", "--socket", cli.sock)
	cell("6c. the agent, Keycloak stopped", st.cell())
	if strings.Contains(st.stderr, "no agent") {
		fail("the agent ended while Keycloak was down: %s", st.cell())
	}
	if _, err := c.run("start", "keycloak"); err != nil {
		t.Fatalf("INVALID: starting Keycloak: %v", err)
	}
	waitDiscovery(t, kc, 3*time.Minute)
	var after string
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Second) {
		tok, tr = cli.token(kc, l.p.node)
		after = tr.cell()
		if tok != "" || strings.Contains(tr.stderr, "the session is over") {
			break
		}
	}
	cell("6d. port49 token once Keycloak answers again", after)
	complete = true
}
```

`l.shell`, `l.runPermitted` and `res.cell` are the harness's (`l29_shell_test.go`,
`directory_e2e_test.go`). `c.run` is the compose stack's `docker compose` with its overlays, so
`stop keycloak` and `start keycloak` act on the stack's own Keycloak.

- [ ] **Step 5: The unit tests pass**

Run: `go test -tags lab ./tests/lab/ -run 'TestL56AuthURL|TestL56LoginFrom|TestL55Accepted|TestL56Files' -count=1 && make lab-unit`
Expected: PASS.

- [ ] **Step 6: The targets and the README**

In `Makefile`, add `lab-oidc-l55 lab-oidc-agent` to `.PHONY`, and after `lab-oidc`:

```make
# L55 (plan 9b): Keycloak as port49's OIDC public client meets it. Needs
# Docker with Compose v2.24.4+; about 8 minutes, most of it the session-limit
# waits. lab-oidc re-measures the closed L45 and L46; this runs L55 alone.
lab-oidc-l55:
	go test -tags lab ./tests/lab/ -run 'TestL55' -count=1 -v -timeout 30m

# L56 (plan 9b): the OIDC agent end to end, bin/port49 against the compose
# stack's Keycloak and vEOS. Needs the compose stack, containerlab, the EOS
# image and `make build`.
lab-oidc-agent:
	PORT49_LAB_PLATFORMS=arista_eos go test -tags lab ./tests/lab/ -run 'TestL56' -count=1 -v -timeout 60m
```

In `tests/lab/README.md`, after the identity-provider section, add a section "OIDC agent (plan
9b): L55 and L56" saying, in the README's style:
- `make lab-oidc-l55` measures L55 on the standalone Keycloak. It changes `port49-cli`'s redirect
  URIs and the realm's session limits for the run and puts them back.
- `make build && make lab-oidc-agent` measures L56: `bin/port49 login --oidc --no-browser` on the
  compose stack, a scripted browser signing in from the address port49 prints.
- The CLI reaches `keycloak.port49.lab` through a CONNECT proxy the test runs on loopback
  (`HTTPS_PROXY`), since the host does not resolve that name. port49 never sends the broker through
  a proxy.
- The realm's Access Token Lifespan is 60s for L56.
- Keycloak is stopped and started by `docker compose stop|start keycloak`. If its dev-mode database
  loses the session across that, the note records what the agent said.

- [ ] **Step 7: Run L55, then L56**

Run: `make build && make lab-oidc-l55`
Expected: PASS; `tests/lab/results/L55-keycloak.md` and `tests/lab/evidence/L55-keycloak.json`
written. Read the note. If a step shows a setup fault (INVALID), fix the harness and run again; never
record it.

Run: `make lab-oidc-agent` (with the SER8's lab up, as `make lab-oidc`'s end to end needs). Run a
background stall watchdog while it runs (memory: lab run watchdog).
Expected: PASS; `tests/lab/results/L56-arista_eos.md` written; `make evidence` writes the
redacted capture.

- [ ] **Step 8: Close the rows, and fix what the results contradict**

For each row, follow CLAUDE.md's rule 3. The row's Status becomes `closed — measured <date>;
tests/lab/results/L55-keycloak.md` (L56: `tests/lab/results/L56-arista_eos.md`), with the
observation in one paragraph as L45's and L46's rows carry it. A cell the claim's code got wrong is
not closed over: fix the code on this branch first, re-run, and close on the run that passed.

Then rule 4: if a result contradicts a doc, the doc is wrong.
- **Decision 43 rulings 1, 4, 9 and 10.** Replace "provisional on L55 (Keycloak) and L47" with
  "measured on Keycloak, L55 closed; provisional on L47".
- **Ruling 4.** State which redirect registration Keycloak admitted for an ephemeral port. If none
  did, say Keycloak needs a fixed port and `oidc_redirect_port`; the client's ephemeral default
  stands, from RFC 8252.
- **This plan's operator notes**, which Task 9 copies: replace each italic line with what was
  measured.

Commit the harness and the notes first, and make the spec edits after that commit, so the second
commit holds them alone, as CLAUDE.md asks:

```bash
git add tests/lab/ Makefile
git commit -m "test(lab): L55 and L56, the OIDC public client on Keycloak and vEOS"
# now edit §15's two Status cells and decision 43 as above
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L55 and L56"
```

A code fix the run called for is its own `fix(...)` commit before the first, with its test.

---

### Task 9: The roadmap's as-built entry

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 9" and the status paragraph)

- [ ] **Step 1: Write the as-built entry**

Under `## Plan 9 — Agent in full (§19 step 9)`, after `### Plan 9a — As built` and its body, add
`### Plan 9b — As built`. Its body is three short bullet lists, as 9a's is:
- **Built:** the commits, the test count from `make test`, and L55's and L56's status.
- **Carried:** to 9c, 9d, plan 12, plan 13 or the pre-beta review, each with its reason. At least
  these:
  - **Plan 13:** this plan's operator notes as the lab corrected them.
  - **Plan 12:** a provider's session limit at or above `max_session_age`, as a deployment
    requirement.
  - **L47:** stays unassigned.
- **Operator-facing notes:** this plan's "Operator notes" section, corrected to what L55 and L56
  measured, with no line left in italics.

In the status paragraph, after the sentence that says 9b is written, add the date 9b executed, its
branch (`feature/oidc-public-client`) and its base.

- [ ] **Step 2: Verify the branch and commit**

Run: `make test && make vet`
Expected: PASS, and `gofmt -l .` lists nothing.

Run: `make test-race`
Expected: PASS.

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap, plan 9b as built"
```

