# CLAW-W1-06 — recibo do selo Phase 11 da Onda 1 — 2026-10-05

## Resultado

- certificationId: `phase11-72fa77fcda6fad8c-muv8q8tu`
- candidateId: `72fa77fcda6fad8cfdc893e8341cd5a6d371e9b5b2b9ef5eaa274cf3ee076267` (congelado em `185f821`; certificado no HEAD `dfe2c1d`, que só acrescenta evidências fora do escopo)
- Decisão: `CONDITIONAL_GO` / `AAA_CANDIDATE`; perfil elegível `STAGING`.
- Gates: 35/35 PASS. Invariantes: 16/16 PASS.
- Bloqueios restantes: só os 8 gates externos e humanos (`modelProvider`, `channel`, `externalIdentity`, `institutionalRag`, `rpoRto`, `pilot`, `rollback`, `humanSignoff`).

## Execução

- Receita: [certify-pass.sh](../CLAW-reseal/certify-pass.sh), contêiner `mcr.microsoft.com/playwright:v1.59.1-noble`, Node `22.23.2`, `postgres:16-alpine` descartável em `127.0.0.1:55441`.
- Log: [certify-pass2-20261005.log](certify-pass2-20261005.log), SHA-256 `e1f8636c12398b18fb79d8bb148fb8b008b913e4c907e098141ab80634013995`; `certify exit 0`.
- Teardown: contêiner PostgreSQL removido; o log registra 6 papéis residuais antes da remoção, o mesmo achado P2 já conhecido (os testes não fazem `DROP ROLE`).

## Verificação independente do wrapper

O crítico apontou (P2) que `certify-pass.sh` não propaga o exit da certificação. Por isso o selo foi conferido fora do wrapper, sob Node `22.23.2`:

- `npm run certification:verify:phase11`: exit 0, `failures: []`.
- `npm run promotion:check -- --expect=EXTERNAL_ONLY`: exit 0, `production_assurance_incomplete`, "Only human/external gates remain; no internal blocker was found."

## Hashes do selo

| Arquivo                                  | SHA-256                                                            |
| ---------------------------------------- | ------------------------------------------------------------------ |
| `certification/current.json`             | `821918628e19e714e688ce40928c9a02560aa099aea5ec0ec38b0a4a0098a6a0` |
| `certification/phase11/phase11-result.json` | `15c9f0a4a0ec67ff6daa5a1c54ffdf0356e5cef97171e9c68f63abd56e2ad9d9` |
| `certification/phase11/manifest.json`    | `859aa0b8999dd822777bd90f4437f22330d22bdb5ddce83b1c7d82f1947154dc` |

## Limites

A governança (`99_runtime_state.md`, execution log, backlog, `CURRENT.md`) não foi tocada depois do selo, para não deixá-lo obsoleto. A atualização dela entra junto com o próximo BUILD (CLAW-W1-07, renovação da política de tombstone até 2027-06-30), que gera novo candidato. Staging e produção permanecem `NO_GO`.
