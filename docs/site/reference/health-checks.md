---
title: Health checks
description: Which health check to use for port49d and the broker in each deployment.
---

# Health checks

`port49d` and `port49-broker` both have a `healthcheck` subcommand for an image with no shell and no
curl. `port49-inventory healthcheck` takes the same flags. The subcommand asks the process's own
`metrics_listen` and exits 0 or 1.

| Command | Asks | Means |
|---|---|---|
| `port49d healthcheck` | `/healthz` | Liveness: the process runs and its metrics listener is bound. |
| `port49d healthcheck --ready` | `/readyz` | Readiness: the TACACS+ listener is serving. 503 while it waits for the store or drains. |

The broker's `/readyz` is its own: 503 `starting` until its API is up, then 200. The default and
`--ready` mean the same for it as for port49d.

Without the subcommand, `curl <host>:9049/readyz` asks port49d and `curl <host>:9050/readyz` asks the
broker. `serving` with a 200 means the process is up. Anything else is a 503 with a line that says why:
`starting`, `waiting for the store` or `draining`.

## Which one to use

Use `/healthz`, the default, for anything that restarts a container or holds something back when it is
unhealthy: Docker Swarm, an autoheal sidecar, a Nomad `check_restart`, an ECS container health check
that replaces the task, and a Compose `depends_on` with `condition: service_healthy`.

Use `--ready` (`/readyz`) only to route or to display: Compose's own `healthy` in `docker compose ps`, or
a load balancer's member check.

Whenever port49d waits for its store it keeps its listener closed, and `/readyz` answers `503 waiting
for the store: the TACACS+ listener stays closed until etcd answers`. Two cases differ in how long it
waits:

- A store lost while port49d runs. It waits with no limit and comes back by itself when etcd does.
  Devices find TCP 49 refused and fall to their local method meanwhile.
- A cold start while the store is down. It waits `start_timeout` (30 seconds by default; `0` waits as
  long as it takes), then exits 1, and systemd or compose starts it again.

A supervisor that restarts on `--ready` turns the first case into a restart loop, and adds restarts of
its own to the second. Each restart throws away what the process holds in memory, its cached directory
membership and pins. The restarted process serves from its stored snapshot only up to
`session.staleness_ceiling`. A store outage must never restart-loop port49d.

!!! warning "The shipped compose.yaml probes with `--ready`, and `docker stack deploy` acts on it"
    `compose.yaml` runs `healthcheck --ready` for port49d and the broker. That is right for
    `docker compose`, which only reports `healthy` and restarts nothing on it. Docker Swarm
    (`docker stack deploy`) restarts a container that turns unhealthy, so deployed to Swarm as shipped,
    port49d is restarted again and again for as long as the store is down. To adapt the file to Swarm,
    change both `healthcheck` blocks: remove `--ready` so they probe `/healthz`, and
    raise `retries` from 3 to 6. The shipped `interval: 10s` and `retries: 3` are a 30-second window,
    which is too short (next section).

## Window for a check that restarts

Give a check that restarts on failure a window of more than 30 seconds. Even `/healthz` has a gap:
between one run of port49d and the next after a store loss, `/healthz` and `/readyz` are unbound for
seconds.

- The chart meets this. It probes `/healthz` every 10 seconds with six failures, which is 60 seconds.
- Compose's shipped healthcheck (10 seconds, three retries, a 30-second start period) does not, and does
  not need to, because compose restarts nothing on it.

On Kubernetes, `/readyz` is the readiness probe, so a not-ready pod leaves the Service, and `/healthz` is
the liveness probe.
