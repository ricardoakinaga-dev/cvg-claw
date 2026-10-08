#!/bin/sh
# Only used on new, individually labelled disposable AUD06 volumes.
set -eu
test "${CVG_AUD06_SYNTHETIC:-}" = true
test "${POSTGRES_DB:-}" = cvg_aud06
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv migration_password AUD06_MIGRATION_PASSWORD
\getenv runtime_password AUD06_RUNTIME_PASSWORD
CREATE ROLE cvg_aud06_migration LOGIN PASSWORD :'migration_password'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE cvg_aud06_runtime LOGIN PASSWORD :'runtime_password'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE ALL ON DATABASE cvg_aud06 FROM PUBLIC;
GRANT CONNECT ON DATABASE cvg_aud06 TO cvg_aud06_migration, cvg_aud06_runtime;
-- Migration 0001 uses transaction-scoped temporary authority tables.
GRANT TEMPORARY ON DATABASE cvg_aud06 TO cvg_aud06_migration;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER ROLE cvg_aud06_migration SET search_path TO cvg_aud06;
ALTER ROLE cvg_aud06_runtime SET search_path TO cvg_aud06;
SQL
if [ "${AUD06_SOURCE_DB:-false}" = true ]; then
  psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 \
    --command 'CREATE SCHEMA cvg_aud06 AUTHORIZATION cvg_aud06_migration;'
fi
