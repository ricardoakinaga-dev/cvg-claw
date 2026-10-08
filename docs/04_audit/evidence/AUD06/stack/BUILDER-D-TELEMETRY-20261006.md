# Builder D — telemetry integration handoff

**IMPLEMENTED — CONTROLLED_LOCAL_SYNTHETIC_ONLY.** This is builder evidence,
not independent acceptance or human approval. Production remains **NO_GO**.
This handoff supersedes the stdout-only telemetry qualification in
`BUILDER-D-20261006.md`; previous runs, failures and manifests remain unchanged.

## Implementation and reproduction

Latest changes are confined to these six files:

| File | Change |
| --- | --- |
| `deploy/aud06/compose.yaml` | Explicit local_file/profile/root configuration for both APIs and the durable worker; three separate writable bind volumes under their private /tmp roots; non-root runtime UID/GID matches the invoking user. |
| `deploy/aud06/README.md` | Actual collector-file proof, shutdown procedure, private-volume ownership and limits. |
| `scripts/aud06-stack-run.mjs` | Capture periodic/final bytes, inspect mounts, prove buffered API records survive SIGTERM, require worker drain/metrics and successful process exits. |
| `scripts/aud06-stack-telemetry.mjs` | Prepare exclusive directories; reject empty/malformed/unbounded exports, selected sensitive fields, synthetic canaries, raw temporary paths and generated test credentials; verify append-only history. |
| `scripts/aud06-stack-db.ts` | Include a synthetic sensitive marker in the controlled outbound fixture. |
| `tests/aud06-stack.test.js` | Five additional verifier tests; 11 focused tests total. |

The earlier stack files remain part of this delivery: `Dockerfile`,
`deploy/aud06/Caddyfile`, `deploy/aud06/init-db.sh`,
`deploy/aud06/tsconfig.helpers.json`, and `scripts/aud06-migrate.ts`.
Builder D did not edit apps, packages, package manifests, masters or `.gauntlet`,
and did not commit, push or create descendant agents. Gauss owns the entrypoint
and collector implementation. Its code was present and imported before the
integrated smoke began.

Run from the repository root as a non-root Linux user with Docker access:

```sh
/home/ricardo/.nvm/versions/node/v22.23.2/bin/node scripts/aud06-stack-run.mjs
/home/ricardo/.nvm/versions/node/v22.23.2/bin/node node_modules/vitest/vitest.mjs run tests/aud06-stack.test.js
```

The stack passes `CVG_TELEMETRY_MODE=local_file`,
`CVG_TELEMETRY_PROFILE=CONTROLLED_LOCAL_SYNTHETIC` and
`CVG_TELEMETRY_ROOT=/tmp/<run-id>-telemetry` only to the application processes.
Each API has a separate `api.jsonl`; the worker has its own `worker.jsonl`.
The host directories are private, newly created for each run, and removed by
the existing owned-resource cleanup. No real data or credentials are used.

## Executed result

Successful run: `cvg-aud06-stack-1791329672460-6eb12909dc`.
Started `2026-10-06T23:34:32.460Z`, ended `2026-10-06T23:35:22.878Z`;
runner **exit 0**. `sourceDriftSinceSnapshot` was empty at completion.

All file references in this section are inside that run directory.

| Boundary | Observed evidence |
| --- | --- |
| Periodic export | `telemetry-periodic.json` and three `telemetry-<service>-periodic.jsonl` files were captured before process shutdown. |
| API shutdown drain | Each actual API emitted a final route record whose `meta.correlationId` was absent from its file immediately before SIGTERM and present afterward. Both processes exited 0. Exact IDs and probe results are in `summary.json` and `commands.jsonl`. |
| Final API files | Each replica exported two batches / three log records. The requests intentionally lacked operator identity and returned 401 while exercising the real error-log path; this does not qualify an authenticated operator journey. |
| Final worker file | Ten batches containing 42 log records and 26 metrics; readiness, processing and drain events were present. Previously exported bytes survived worker restart. |
| Sanitization | None of the supplied canary, controlled payload markers, generated database passwords, selected sensitive-field keys or raw /tmp paths appeared in captured exports. No telemetry.export_failed diagnostic was observed. |
| Stack regression | Actual services healthy; 31 migrations applied twice with identical ledger; two controlled outbox events processed once across restart; HTTP redirect/TLS and web asset checks passed. |
| Shared quota | 300 HTTP 200 and two HTTP 429 across two actual replicas; storage denial returned 503 on both and service recovered after regrant. |
| Restore | Separate owned PostgreSQL target restored all 44 tables / 41 rows with matching row hashes and compared schema metadata. Source fingerprint stayed unchanged. |
| Production gate | Both actual production entrypoints still exited 1 without attestation. No production gate was synthesized. |
| Teardown | Successful cleanup, with zero owned containers, networks and volumes remaining. Later label-scoped Docker queries also returned empty; pgrep found no stack runner. |

Final targeted checks passed: **11/11 tests**, ESLint, helper typecheck and
Prettier. Raw artifacts are `telemetry-final-focused-tests.json`,
`telemetry-final-eslint.json`, `telemetry-final-typecheck.log`, and
`telemetry-final-prettier.log` in this parent directory. The recorded earlier
validation at `validation-telemetry-1791329534699/` also passed, before the final
shutdown-probe correction. No global suite, coverage or browser suite was run.

`sha256sum --check --status SHA256SUMS` on the successful run executed with exit 0.

| Artifact | SHA-256 |
| --- | --- |
| Successful run SHA256SUMS | `388d338da821fd6c0782183b2b939d7337595410a04cb02070c838f8cd86f326` |
| Source manifest | `bd290caee596b469b39168b33084c5908bc322ac289c09613c240928e3444552` |
| Final api-a JSONL | `e297ab1ae0a96cfdffb6bf952b785200bf7a4873d2032b40923f8f6f6c6de8a9` |
| Final api-b JSONL | `f705d1055045c419aa6717ec5c0543d8c7d78cbde00e47ce8e78992a3f98c958` |
| Final worker JSONL | `73f0838849704ddbff7c7006d0dc7c518795b2dae9c0bf7f41466248f691483d` |
| PostgreSQL dump | `3f8cf7cd7549e3b8bb034d6cba9c18dbe49005c6ba5e5088c0827495966d0c91` |
| Restored database fingerprint | `a358df3010beac1a834973dfe3acf32bb7357e874b4c63c5d66b40556b5d8d6c` |

## Failures, limitations and requests to lead

The first telemetry integration run,
`cvg-aud06-stack-1791329560215-f727da8b86`, preserved exit 1 and successful
teardown. Periodic export passed; the shutdown verifier incorrectly looked for
`body.correlationId` instead of the actual `body.meta.correlationId`. The corrected
probe also checks the response header; the complete subsequent run passed.

Some grouped read/validation calls, the later `git diff --check` call, and an
additional post-run source rehash/receipt call were blocked by the platform with:
"Esta chamada de ferramenta foi bloqueada pela OpenAI porque não foi possível
determinar o status de segurança da solicitação." They did not execute and are
not counted as passed checks. This was not a repository test failure. Individual
test/lint/typecheck/format commands and run-evidence checksum verification did
execute successfully. Source binding is qualified at the successful runner's
completion time; no later source-rehash result is claimed.

Lead should reconcile canonical state/log/backlog, review the candidate independently,
and bind integrated qualification to its final sources. The API still receives
distinct migration credentials for its existing DDL-owner startup checks; removing
that authority requires an app-owned contract change. An inherited edge observation
also remains: the API response in the first telemetry run had two
Strict-Transport-Security header lines, one from each layer; consolidation is a
separate edge follow-up, not part of this telemetry-only adaptation.

These files demonstrate controlled local export, not a production collector,
external destination, full privacy certification, real RPO/RTO, institutional
approval, pilot completion or signoff. The API JSONL sample contains logs, not
metrics/spans; API metrics were separately observed through /health/metrics.
No processes or disposable resources from this lane remain live.
