# Pedido de parecer do crítico independente — candidato cvg-claw 2414ae15 — 2026-10-04

Status deste documento: **PEDIDO**. Não é parecer e não autoriza selo.

## Binding do candidato congelado

- candidateId: `2414ae1538227881cb294abd051d3ce593c266c59f7f0c6e6173a417f9b49ecd`
- commit: `f8c2639d47831e4058e0807e5ce3d414a846298c`
- treeHash: `0e984dc75c6619d59d611910d0ed2d58f4aecd737119b7a6a3bc8c5096a765ce`
- fingerprint (`sha256-candidate-v1`, sem exclusões extras): `02cde40a6ce757ff4cdb55ceb148a63301b61bb476ebc7907fd23dde3dce14d8`

## Delta desde o último candidato com parecer (`b0f7c17a` @ `3dc0093`)

1. `9fd105c` — renomeação para `cvg-claw` (nome do pacote raiz e do lock, AGENTS, README, docs) e Discovery 0026 v1.
2. `498ae11` — `npm audit fix`: fastify 5.12.3→5.12.5, fast-uri 3.1.6→3.1.8 e 4.1.4→4.2.1, undici 7.29.0→7.30.0, brace-expansion 5.0.9→5.0.12 (só `package-lock.json`); Discovery 0026 v2.
3. `af5f348` — teste `retention-postgres.test.ts`: tombstone "recente" passa de data fixa `2026-09-01` para 5 dias antes da execução (a minimização usa o relógio do PostgreSQL com horizonte de 30 dias). Nenhum código de produto alterado.
4. `f8c2639` — congelamento dos documentos de governança.

## Evidência da passada 1 (descartada, reproduzível)

- `phase11-9aa3401dfcfa9b77-muugfayu` no commit `af5f348`, contêiner `mcr.microsoft.com/playwright:v1.59.1-noble` com Node `22.23.2` e `postgres:16-alpine` descartável: 33/35 gates e 16/16 invariantes PASS; pendentes `independent_critic` e `PHASE11_FORMAL_CLOSURE`.

## O que o crítico deve entregar

- `docs/04_audit/evidence/AUD19/AUD19-08-critic-report.json` no schema `phase11-critic-report` v1, com `binding` e `fingerprint` acima, `critic.freshContext: true`, identidade separada do builder (`cvg-lead-agent`), entrada só de artefatos, sem escrita no worktree durante a revisão e sem reaproveitar conclusões do builder.
- Validar com `node scripts/phase11-2-evidence-check.mjs --critic` antes da passada 2.

## Limites

Staging/produção `NO_GO`. Os 8 gates externos/humanos seguem pendentes; este selo não habilita piloto.
