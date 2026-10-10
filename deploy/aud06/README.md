# AUD06 disposable synthetic stack

This composition runs the actual API entrypoint twice, the continuous governed
kernel worker, the built React web application behind Caddy TLS, and PostgreSQL 16. A second independent PostgreSQL container and volume receive the restore.
It qualifies only `CONTROLLED_LOCAL_SYNTHETIC_ONLY`. Production and real pilot
effects remain `NO_GO`; no human signoff or real RPO/RTO is implied.

## Execute

From the repository root, as a non-root Linux user with Docker access, Docker
Compose, OpenSSL and Node **22.23.2**:

```sh
node scripts/aud06-stack-run.mjs
node node_modules/vitest/vitest.mjs run tests/aud06-stack.test.js
```

On this workstation the pinned executable is:

```sh
/home/ricardo/.nvm/versions/node/v22.23.2/bin/node scripts/aud06-stack-run.mjs
```

The runner creates an immutable temporary build-context copy and a file hash
manifest, installs from the existing lockfile, and builds the `aud06-runtime`
and `aud06-web` Dockerfile targets. It generates a new resource prefix, secrets,
one-day localhost certificate, and two ephemeral loopback ports every time.
It does not use `.env`, `TEST_DATABASE_URL`, existing databases, browser-builder
ports 3199/4173, or global test/coverage output. API, worker and database containers
have no default Internet route on their dedicated internal network. Caddy also
joins a separately owned edge bridge so Docker can publish its two ports, both
explicitly on `127.0.0.1`. The edge has a default route; this is not an air-gapped
Caddy deployment. Its private-network IP alone (plus internal loopback health
checks) is trusted for forwarded protocol/client IP; Caddy overwrites incoming XFF.

Each execution applies all canonical migrations, including 0030, in a separate
container twice; it compares the complete migration ledger. Runtime auto-migrate
is disabled. The worker must pass its existing role/RLS/migration preflight,
process a synthetic outbox event, stop, and process a second persisted event after
restart. Each event must have exactly one recorded controlled effect.

HTTP redirects to the ephemeral TLS port. HTTPS probes verify the generated
certificate explicitly, reject it without that trust anchor, inspect security
headers, retrieve the built web JS asset, and observe API health/readiness. A
302-request burst must produce 300 successes and two shared 429s across both API
replicas despite changing untrusted tenant/XFF headers. Revoking quota SELECT
must cause both replicas to return generic 503s; regranting must restore service.

The API and durable worker entrypoints explicitly receive
`CVG_TELEMETRY_MODE=local_file`,
`CVG_TELEMETRY_PROFILE=CONTROLLED_LOCAL_SYNTHETIC`, and
`CVG_TELEMETRY_ROOT=/tmp/<unique-run-id>-telemetry`. Each of the two API replicas
and the worker gets its own writable bind volume, backed by a new private directory
under the runner's temporary root. Each API writes its own `api.jsonl`; the worker
writes `worker.jsonl`. The runtime UID/GID match the invoking non-root user so
these directories stay private without broad write permissions. Migration/tools
containers do not receive telemetry configuration or volumes.

The runner retrieves collector files while the processes are still running to
prove periodic export, then checks that their bytes survive worker restart. It
sends a synthetic canary through API requests and the controlled worker payload,
rejects raw payload/secret fields, canaries, temporary paths and the throwaway
database credentials in exports, and saves the original file bytes with hashes.
For each API, a final actual route request produces a correlation ID verified
absent from the file immediately before SIGTERM; after exit0 the final file must
contain that buffered record. Worker shutdown must export its drain event and
metrics. The runner checks successful stopped processes and absence of
`telemetry.export_failed` diagnostics. Docker stdout alone cannot satisfy this
collector-file gate.

After collecting API metrics and the actual sanitized files, it stops all
application writers. It fingerprints every source table, creates a custom-format
`pg_dump`, restores into the other container with `pg_restore --exit-on-error
--single-transaction`, and compares all row counts/SHA-256 hashes, RLS flags,
table owners, constraints, indexes and policies. It also verifies that the source
fingerprint did not change during the drill. No existing restore target is used.
Constraint comparison uses PostgreSQL's `pg_get_constraintdef(oid, true)` so
redundant nested-AND parentheses introduced by BETWEEN parsing do not create a
false mismatch after dump/restore. Raw definitions remain in command stderr
evidence; every canonical definition and validated flag is still compared.

## Evidence and teardown

Every run writes under `docs/04_audit/evidence/AUD06/stack/<unique-run-id>/`:
command arguments, start/end timestamps, real exit statuses, raw stdout/stderr,
public certificate, source manifest, HTTP results, periodic/shutdown collector
JSONL files for all three processes, dump, integrity comparison,
summary, teardown observations, and `SHA256SUMS`. Private keys and credentials
stay in the temporary directory and are deleted after verified teardown.
The temporary source snapshot also records concurrent source drift explicitly.

Cleanup inspects the exact run label and name before removing any resource.
It attempts cleanup on success, failure, SIGINT and SIGTERM, preserves a failing
result, and records remaining containers/networks/volumes. It removes only its
image tags; Docker's shared build cache and downloaded base images are retained.
SIGKILL or daemon/host failure can prevent cleanup; a failed cleanup records the
temporary directory and residual resources for an operator, without reporting PASS.

## Limits and integration requests

The original production Docker targets/preflight are retained. Negative runs of
both actual production entrypoints must still fail without attestation.
`NODE_ENV=test` deliberately selects simulation identity and no real webhook
verification; the internal network, loopback binding and explicit false real-effect
flags are part of this synthetic boundary, not a production deployment recipe.

The API currently requires `DATABASE_MIGRATION_URL` even when auto-migration is
off and uses that connection for DDL-owner checks. Its synthetic containers therefore
receive distinct migration credentials; the worker receives runtime credentials
only. Removing migration authority from API containers requires an app-owned
startup-contract change and separate tests, not a deployment bypass.

These negative output checks cover the synthetic markers and structural fields
under test; they do not certify absence of every possible sensitive datum.
Local file export is not a production telemetry collector or external destination
qualification. The small, quiesced recovery drill does not establish production
RPO/RTO, load capacity, failover, real provider/channel/identity/RAG integration,
institutional approval, release certification, or independent audit acceptance.
Lead owns canonical runtime/log/backlog updates and integrated qualification.
