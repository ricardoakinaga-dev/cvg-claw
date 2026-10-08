#!/usr/bin/env bash
# Canonical Phase 11 runner. Invoke with a NEW log path from any directory:
#   bash /path/to/cvg-claw/scripts/certify-controlled.sh /path/to/new-run.log
# The historical evidence wrapper remains frozen. Running this command invokes
# the certification writer; its caller must separately hold that authority.
# Startup covers PostgreSQL readiness and certification create/start together.
# Workload wait has no startup deadline; cancel with INT/TERM/HUP when needed.
set -euo pipefail

if (( $# != 1 )); then
  printf 'usage: %s NEW_LOG_PATH\n' "$0" >&2
  exit 64
fi

startup_seconds=${CERTIFY_STARTUP_TIMEOUT_SECONDS:-60}
cleanup_seconds=${CERTIFY_CLEANUP_TIMEOUT_SECONDS:-10}
for budget in "$startup_seconds" "$cleanup_seconds"; do
  if [[ ! $budget =~ ^[1-9][0-9]{0,2}$ ]] || (( 10#$budget > 300 )); then
    printf 'timeout budgets must be integers from 1 to 300 seconds\n' >&2
    exit 64
  fi
done

for dependency in docker node timeout setsid mktemp readlink; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf 'missing dependency: %s\n' "$dependency" >&2
    exit 69
  fi
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
node_binary=$(readlink -f -- "$(command -v node)")
node_root=${CERTIFY_NODE_ROOT:-$(dirname -- "$(dirname -- "$node_binary")")}
node_root=$(cd -- "$node_root" && pwd -P)
if [[ $("$node_root/bin/node" --version) != v22.23.2 ]]; then
  printf 'certification requires Node v22.23.2\n' >&2
  exit 69
fi

# Only a newly created synthetic database URL is passed to the container.
unset DATABASE_URL TEST_DATABASE_URL PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
log=$1
mkdir -p -- "$(dirname -- "$log")"
# Refuse to overwrite an existing evidence log, including historical logs.
set -o noclobber
: > "$log"
set +o noclobber

state_dir=$(mktemp -d "${TMPDIR:-/tmp}/cvg-certify.XXXXXXXXXX")
pg_cidfile=$state_dir/pg.cid
cert_cidfile=$state_dir/cert.cid
port_file=$state_dir/port
cert_waitfile=$state_dir/cert.wait
active_pid=''

terminate_child_group() {
  [[ -n $active_pid ]] || return 0
  # Commands run in their own session. Signals reach their descendants too,
  # without signalling the calling terminal or another certification process.
  kill -TERM -- "-$active_pid" 2>/dev/null || true
  for (( attempt = 0; attempt < 20; attempt++ )); do
    if ! kill -0 -- "-$active_pid" 2>/dev/null; then break; fi
    sleep 0.05
  done
  kill -KILL -- "-$active_pid" 2>/dev/null || true
  wait "$active_pid" 2>/dev/null || true
  active_pid=''
}

run_child() {
  local status=0
  setsid "$@" &
  active_pid=$!
  wait "$active_pid" || status=$?
  terminate_child_group
  return "$status"
}

cleanup() {
  local original_status=$?
  local cidfile cid logs_status cleanup_failed=0
  trap - EXIT
  trap '' INT TERM HUP
  set +e
  terminate_child_group
  for cidfile in "$cert_cidfile" "$pg_cidfile"; do
    [[ -s $cidfile ]] || continue
    IFS= read -r cid < "$cidfile"
    # A name alone never proves ownership. Docker writes the immutable ID into
    # our private cidfile on creation, including a later start failure.
    if [[ ! $cid =~ ^[a-f0-9]{64}$ ]]; then
      printf 'cleanup failed: invalid container receipt %s\n' "$cidfile" >> "$log"
      cleanup_failed=1
      continue
    fi
    if [[ $cidfile == "$cert_cidfile" ]]; then
      # Detached start/wait must not lose the certification stdout/stderr.
      # Collection also has its own bound and never replaces the original exit.
      logs_status=0
      run_child timeout --foreground --signal=TERM --kill-after=1s \
        "${cleanup_seconds}s" docker logs "$cid" >> "$log" 2>&1 || logs_status=$?
      if (( logs_status != 0 )); then
        printf 'log collection failed: container %s exit %s\n' \
          "$cid" "$logs_status" >> "$log"
      fi
    fi
    # PostgreSQL creates an anonymous data volume. Remove those attached to
    # this owned container too; named volumes and bind sources are preserved.
    if ! run_child timeout --foreground --signal=TERM --kill-after=1s \
      "${cleanup_seconds}s" docker rm -f --volumes -- "$cid" >> "$log" 2>&1; then
      printf 'cleanup failed: container %s\n' "$cid" >> "$log"
      cleanup_failed=1
    fi
  done
  rm -f -- "$pg_cidfile" "$cert_cidfile" "$port_file" "$cert_waitfile"
  rmdir -- "$state_dir"
  printf 'cleanup failures %s\nrunner exit %s\n' \
    "$cleanup_failed" "$original_status" >> "$log"
  exit "$original_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

pg_name=${state_dir##*/}-pg
cert_name=${state_dir##*/}-runner
deadline=$(( SECONDS + startup_seconds ))

startup_docker() {
  local remaining=$(( deadline - SECONDS ))
  local status=0
  if (( remaining <= 0 )); then
    printf 'startup budget exhausted before docker %s\n' "$1" >&2
    return 124
  fi
  run_child timeout --foreground --signal=TERM --kill-after=1s \
    "${remaining}s" docker "$@" || status=$?
  # timeout may report SIGKILL after escalation. Keep the startup timeout
  # distinguishable from an ordinary Docker failure or an operator signal.
  if (( status == 137 && SECONDS >= deadline )); then status=124; fi
  printf 'startup docker %s exit %s\n' "$1" "$status" >&2
  return "$status"
}

startup_docker run -d --name "$pg_name" --cidfile "$pg_cidfile" \
  -e POSTGRES_PASSWORD=throwaway-cert-pass \
  -p 127.0.0.1::5432 postgres:16-alpine >> "$log" 2>&1

startup_docker port "$pg_name" 5432/tcp > "$port_file" 2>> "$log"
address=$(cat -- "$port_file")
if [[ ! $address =~ ^127\.0\.0\.1:([0-9]{1,5})$ ]]; then
  printf 'invalid disposable PostgreSQL loopback binding\n' >> "$log"
  exit 65
fi
port=${BASH_REMATCH[1]}
if (( 10#$port < 1 || 10#$port > 65535 )); then exit 65; fi

until startup_docker exec "$pg_name" pg_isready -U postgres >> "$log" 2>&1; do
  if (( SECONDS >= deadline )); then
    printf 'PostgreSQL startup timed out\n' >> "$log"
    exit 124
  fi
  run_child sleep 0.1
done

startup_docker create --init --name "$cert_name" --cidfile "$cert_cidfile" \
  --network host --user "$(id -u):$(id -g)" \
  -v "$repo:$repo" -v "$node_root:/opt/node22:ro" -w "$repo" \
  -e HOME=/tmp/certhome \
  -e PATH=/opt/node22/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e "TEST_DATABASE_URL=postgres://postgres:throwaway-cert-pass@$address/postgres" \
  -e PHASE11_ALLOW_DISPOSABLE_POSTGRES=1 \
  mcr.microsoft.com/playwright:v1.59.1-noble@sha256:b0ab6f3cb99aa7803adbc14d9027ec1785fc6e433b97e134e0f8fe61683b6b53 \
  bash -euc 'mkdir -p "$HOME"; git config --global --add safe.directory "$PWD"; node -v; npm run certify:phase11' \
  >> "$log" 2>&1
cert_id=$(cat -- "$cert_cidfile")
if [[ ! $cert_id =~ ^[a-f0-9]{64}$ ]]; then
  printf 'invalid certification container receipt\n' >> "$log"
  exit 65
fi
# start returns after starting the process, without attaching to the workload.
# It consumes the remaining shared startup budget, not a fresh full allowance.
startup_docker start "$cert_id" >> "$log" 2>&1
printf 'certification started; waiting independently of startup budget\n' >> "$log"

# docker wait exits 0 on a successful wait API call and prints the CONTAINER
# exit code. Keep that result separate from a Docker transport failure/signal.
wait_status=0
run_child docker wait "$cert_id" > "$cert_waitfile" 2>> "$log" || wait_status=$?
printf 'docker wait exit %s; raw container result:\n' "$wait_status" >> "$log"
cat -- "$cert_waitfile" >> "$log"
printf '\n' >> "$log"
if (( wait_status != 0 )); then
  printf 'certification wait failed: docker exit %s\n' "$wait_status" >> "$log"
  exit "$wait_status"
fi
cert_status=$(cat -- "$cert_waitfile")
if [[ ! $cert_status =~ ^[0-9]{1,3}$ ]] || (( 10#$cert_status > 255 )); then
  printf 'invalid certification wait result; no workload status confirmed\n' >> "$log"
  exit 65
fi
cert_status=$((10#$cert_status))
printf 'certify exit %s\n' "$cert_status" >> "$log"
exit "$cert_status"
