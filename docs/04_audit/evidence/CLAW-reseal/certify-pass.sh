#!/usr/bin/env bash
# Phase 11 certification pass inside the CI-parity Playwright image with a disposable PostgreSQL.
set -u
REPO=/home/ricardo/cvg-claw
NODE22=$HOME/.nvm/versions/node/v22.23.2
LOG=${1:?log path}
docker rm -f claw-cert-pg >/dev/null 2>&1
docker run -d --name claw-cert-pg -e POSTGRES_PASSWORD=throwaway-cert-pass -p 127.0.0.1:55441:5432 postgres:16-alpine >/dev/null
until docker exec claw-cert-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$REPO:$REPO" -v "$NODE22:/opt/node22:ro" -w "$REPO" \
  -e HOME=/tmp/certhome -e PATH=/opt/node22/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e TEST_DATABASE_URL=postgres://postgres:throwaway-cert-pass@127.0.0.1:55441/postgres \
  -e PHASE11_ALLOW_DISPOSABLE_POSTGRES=1 \
  mcr.microsoft.com/playwright:v1.59.1-noble \
  bash -c 'mkdir -p $HOME && git config --global --add safe.directory '"$REPO"' && node -v && npm run certify:phase11' >"$LOG" 2>&1
echo "certify exit $?" >>"$LOG"
echo "roles: $(docker exec claw-cert-pg psql -U postgres -tAc "select count(*) from pg_roles where rolname not like 'pg_%' and rolname<>'postgres'")" >>"$LOG"
docker rm -f claw-cert-pg >/dev/null 2>&1
echo "teardown done" >>"$LOG"
