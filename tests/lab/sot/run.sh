#!/bin/bash
# run.sh: record one L27 stack (spec §15 L27, plan 6a Task 2). See README.md.
#
#   tests/lab/sot/run.sh <stack> [legacy|l30|l32|l33|e2e]
#   stack: netbox-3.7 | netbox-4 | nautobot-1.6 | nautobot-2 | nautobot-3
#
# l30 (spec §15 L30, plan 6b Task 2) also seeds 120 devices, reads the list
# 50 at a time to its end, reads one page through an nginx reverse proxy
# (the compose files' l30 profile), and writes tests/lab/sot/l30/<stack>/.
#
# l32, l33 and e2e (plan 6c) seed 120 devices into tests/lab/logs, bring up
# the l32 profile's two TLS proxies, and run one Go test against the stack:
# TestL32Connector, TestL33Webhooks or TestSoTDeviceEndToEnd.
#
# Generates fresh random lab credentials into a 0600 env file outside the
# repository, brings the stack up, waits (10 minute deadline) for
# /api/status/, runs the recorder (10 minute deadline) with the stack's auth
# scheme, saves the compose log with every credential replaced by <redacted>,
# and always tears the stack down with `down -v`. It never prints a
# credential. Run it from the repository root, as a user in the docker group
# (or under `sg docker -c`).
set -euo pipefail

stack=${1:?usage: run.sh <netbox-3.7|netbox-4|nautobot-1.6|nautobot-2|nautobot-3> [legacy|l30|l32|l33|e2e]}
legacy=${2:-}
case $stack in
netbox-3.7) product=netbox port=18037 project=port49-l27-netbox37 ;;
netbox-4) product=netbox port=18080 project=port49-l27-netbox4 ;;
nautobot-1.6) product=nautobot port=18016 project=port49-l27-nautobot16 ;;
nautobot-2) product=nautobot port=18020 project=port49-l27-nautobot2 ;;
nautobot-3) product=nautobot port=18030 project=port49-l27-nautobot3 ;;
*) echo "run.sh: unknown stack $stack" >&2; exit 64 ;;
esac
case $legacy in
"" | legacy | l30 | l32 | l33 | e2e) ;;
*) echo "run.sh: second argument is 'legacy', 'l30', 'l32', 'l33', 'e2e' or nothing" >&2; exit 64 ;;
esac

root=$(pwd)
compose=$root/tests/lab/sot/compose/$stack.yml
[ -f "$compose" ] || { echo "run.sh: run from the repository root ($compose not found)" >&2; exit 64; }
suffix=""
[ "$legacy" = legacy ] && suffix=-legacy
out=$root/tests/lab/sot/fixtures/$stack$suffix
mkdir -p "$root/tests/lab/logs"
log=$root/tests/lab/logs/l27-$stack$suffix.log

# The env file lives outside the repository. L27_ENV_DIR keeps it (for a
# count-only secret audit after the run); otherwise it is deleted on exit.
# The curl header file and the recorder binary live in a private temporary
# directory that is always deleted on exit.
envdir=${L27_ENV_DIR:-}
keep=1
if [ -z "$envdir" ]; then envdir=$(mktemp -d); keep=0; fi
envf=$envdir/l27-$stack$suffix.env
tmp=$(mktemp -d)
bin=$tmp/sot-record
hdr=$tmp/auth-header

scheme=Token
flags=()
case $stack in
netbox-4) scheme=Bearer; flags+=(-probe-v1-token) ;;
nautobot-2) flags+=(-depth1-read) ;;
nautobot-3) flags+=(-depth1-read) ;;
esac
[ "$legacy" = legacy ] && flags+=(-prefer-legacy)

# The proxy service is in the compose files' l30 profile, but compose
# interpolates every service, profiled or not: both variables are set on
# every run so a file's ${L30_…:?} fails only when run by hand without them.
export L30_PROXY_PORT=$((port + 1000)) L30_PROXY_CONF=$tmp/l30-proxy.conf
upstream=netbox
[ "$product" = nautobot ] && upstream=nautobot
sed "s/netbox:8080/$upstream:8080/" "$root/tests/lab/sot/compose/l30-proxy.conf" >"$L30_PROXY_CONF"
chmod 644 "$L30_PROXY_CONF"
profile=()
if [ "$legacy" = l30 ]; then
	out=$root/tests/lab/sot/l30/$stack
	log=$root/tests/lab/logs/l30-$stack.log
	flags+=(-devices 120 -page-limit 50 -proxy "http://127.0.0.1:$L30_PROXY_PORT")
	# Nautobot 1.6 took only the legacy spelling (L27).
	[ "$stack" = nautobot-1.6 ] && flags+=(-prefer-legacy)
	profile=(--profile l30)
fi
case $legacy in
l32 | l33 | e2e)
	# The recorder seeds 120 devices and records into logs, never into the
	# committed fixtures; the Go test after it is the run's measurement.
	out=$root/tests/lab/logs/$legacy-$stack-seed
	log=$root/tests/lab/logs/$legacy-$stack.log
	flags+=(-devices 120 -page-limit 50)
	[ "$stack" = nautobot-1.6 ] && flags+=(-prefer-legacy)
	profile=(--profile l32)
	;;
esac

dc() { docker compose --env-file "$envf" -f "$compose" "${profile[@]}" "$@"; }
cleanup() {
	set +e
	if [ -f "$envf" ]; then
		dc logs --no-color >"$log.compose" 2>&1
		# Every generated value, and a v2 token's key and secret, out of the
		# log. The sed script is a 0600 file, so no value is on a command line.
		(
			umask 077
			while IFS='=' read -r _ v; do
				[ -n "$v" ] && printf 's/%s/<redacted>/g\n' "$v"
			done <"$envf" >"$tmp/redact.sed"
		)
		sed -i -f "$tmp/redact.sed" "$log.compose"
		dc down -v >>"$log" 2>&1
		echo "run.sh: $stack$suffix torn down at $(date -u +%FT%TZ)" >>"$log"
	fi
	[ "$keep" = 1 ] || rm -rf "$envdir"
	rm -rf "$tmp"
}
# Set before any credential exists, so every exit removes what was written.
trap cleanup EXIT
trap 'exit 3' TERM INT

# L32 and L33 (plan 6c): two TLS proxies in the l32 profile, and the lab PKI they
# and port49-inventory's webhook present. Set on every run, as L30's are.
pki=$tmp/pki
go run ./tests/lab/cmd/sot-pki -dir "$pki"
export L32_PKI=$pki L32_HOST_PORT=$((port + 2000)) L32_XFH_PORT=$((port + 3000))
export L32_HOST_CONF=$tmp/l32-proxy-host.conf L32_XFH_CONF=$tmp/l32-proxy-xfh.conf
sed "s/netbox:8080/$upstream:8080/g" "$root/tests/lab/sot/compose/l32-proxy-host.conf" >"$L32_HOST_CONF"
sed "s/netbox:8080/$upstream:8080/g" "$root/tests/lab/sot/compose/l32-proxy-xfh.conf" >"$L32_XFH_CONF"
chmod 644 "$L32_HOST_CONF" "$L32_XFH_CONF"

rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1" || true; }
umask 077
{
	echo "L27_DB_PASSWORD=$(rnd 24)"
	echo "L27_SECRET_KEY=$(rnd 60)"
	echo "L27_ADMIN_PASSWORD=$(rnd 24)"
	if [ "$stack" = netbox-4 ]; then
		# NetBox 4.7 via netbox-docker 5.1.1 provisions a v2 token only, and
		# only with a pepper set: the key is 12 characters, the token 40,
		# both [A-Za-z0-9], sent as "Authorization: Bearer nbt_<key>.<token>".
		k=$(rnd 12) t=$(rnd 40)
		echo "L27_API_KEY=$k"
		echo "L27_API_TOKEN=$t"
		echo "L27_TOKEN_PEPPER=$(rnd 60)"
		echo "L27_TOKEN=nbt_$k.$t"
	else
		# A v1 token: 40 hex, sent as "Authorization: Token <token>".
		echo "L27_TOKEN=$(openssl rand -hex 20)"
	fi
} >"$envf"
set -a
. "$envf"
set +a
# curl reads the header from this 0600 file (-H @file), so the token is never
# on a command line; printf is a builtin and runs no process.
printf 'Authorization: %s %s\n' "$scheme" "$L27_TOKEN" >"$hdr"
umask 022
export L27_WEBHOOK_SECRET=l27-lab-webhook-secret # public, lab only: 6b's verifier is tested against it

: >"$log"
echo "run.sh: $stack$suffix up at $(date -u +%FT%TZ)" | tee -a "$log"
go build -o "$bin" ./tests/lab/cmd/sot-record
dc up -d >>"$log" 2>&1 || { echo "run.sh: compose up failed; see $log" | tee -a "$log"; exit 1; }
deadline=$(($(date +%s) + 600))
until curl -fsS -o /dev/null -H @"$hdr" "http://127.0.0.1:$port/api/status/" 2>/dev/null; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "run.sh: STALL: /api/status/ not answered in 10 minutes" | tee -a "$log"
		tail -40 "$log" >&2
		exit 2
	fi
	sleep 10
done
echo "run.sh: status answered at $(date -u +%FT%TZ)" | tee -a "$log"
# The worker reaches the recorder on the stack network's gateway.
gw=$(docker network inspect "${project}_default" --format '{{(index .IPAM.Config 0).Gateway}}')
rm -rf "$out"
rc=0
timeout 600 "$bin" -product "$product" -url "http://127.0.0.1:$port" -out "$out" \
	-webhook-listen "$gw:18999" -auth-scheme "$scheme" "${flags[@]}" >>"$log" 2>&1 || rc=$?
echo "run.sh: recorder exit $rc at $(date -u +%FT%TZ)" | tee -a "$log"
grep -E '^sot-record: (netbox|nautobot) at ' "$log" || true
case $legacy in l32) test=TestL32Connector ;; l33) test=TestL33Webhooks ;; e2e) test=TestSoTDeviceEndToEnd ;; *) test="" ;; esac
if [ "$rc" = 0 ] && [ -n "$test" ]; then
	# The host's docker0 address: host-gateway, as the worker resolves
	# port49-inventory.lab.
	bridge=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
	extra=()
	[ "$legacy" = e2e ] && extra=(PORT49_LAB_PLATFORMS=arista_eos)
	env "${extra[@]}" L32_STACK="$stack" L32_PRODUCT="$product" L32_CA="$pki/ca.pem" \
		L32_HOST_URL="https://127.0.0.1:$L32_HOST_PORT" L32_XFH_URL="https://127.0.0.1:$L32_XFH_PORT" \
		L33_DIRECT_URL="http://127.0.0.1:$port" L33_PKI="$pki" L33_HOOK_BIND="$bridge:18444" \
		timeout 3600 go test -tags lab ./tests/lab/ -run "^$test\$" -count=1 -timeout 55m -v >>"$log" 2>&1 || rc=$?
	echo "run.sh: $test exit $rc at $(date -u +%FT%TZ)" | tee -a "$log"
fi
exit "$rc"
