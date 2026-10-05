# Pedido de parecer do crítico independente — candidato cvg-claw 72fa77fc (Onda 1) — 2026-10-05

Status deste documento: **PEDIDO**. Não é parecer e não autoriza selo. Substitui o [pedido de 2026-10-04](../CLAW-reseal/critic-request-20261004.md) para `2414ae15`, que deixou de valer com a Onda 1.

## Decisões do usuário (2026-10-05)

- Commit da Onda 1 autorizado.
- Crítico independente pelo opencode (agente `gauntlet-critic`, só leitura, contexto novo).
- `git push` para `origin` autorizado.

## Binding do candidato congelado

- candidateId: `72fa77fcda6fad8cfdc893e8341cd5a6d371e9b5b2b9ef5eaa274cf3ee076267`
- commit: `185f82168a11e813c218f2e6da1c49b671bf451f`
- treeHash: `d3c0ed467fd3ad307e8665678b54c092ff9255fb3354c36da0a96d656a105569`
- fingerprint (`sha256-candidate-v1`, sem exclusões extras): `ad6087e1cad09d16ec532dc5e893a21e4d4e7759f4f30d1bec6cab4a6ec11865`
- 1.217 arquivos no escopo; worktree limpo no cálculo.
- Método conferido: o mesmo cálculo no commit `f8c2639` reproduz `2414ae15…` e `02cde40a…` do pedido anterior.

## Delta desde o último candidato com parecer (`b0f7c17a` @ `3dc0093`)

1. Itens 1–4 do [pedido anterior](../CLAW-reseal/critic-request-20261004.md): renomeação, `npm audit fix` (só lock), correção de data em `retention-postgres.test.ts`, congelamento de governança.
2. `6fec2a6` — Onda 1:
   - `apps/api/src/__tests__/journeys-api.test.ts`: troca a exigência de ano `2026-` por data ISO posterior à execução (bomba-relógio; só teste).
   - `package.json`: só o campo `description`.
   - `.env.example`: nome do banco local de exemplo `cvg_claw`.
   - Documentos: auditoria 0575, roadmap 0346, backlog 0347, ponteiros em 0301, 0302, `ROADMAP_PRODUCAO.md`, `BACKLOG_PRODUCAO.md`, `CURRENT.md`, backlog master, runtime state, execution log e `current_state.json`.
3. `185f821` — congelamento de governança (estado, log, backlog, `CURRENT.md`, `current_state.json`).

Nenhum código de produto, migração, script, threshold ou configuração de teste mudou.

## Verificação local do builder (para conferência, não como conclusão)

Node `22.23.2`: typecheck, lint, Prettier, `docs:check` e `npm test` (307 arquivos PASS/12 skipped; 2.682 testes PASS/194 skips/0 falhas) antes do commit. Varredura de tempo em [CLAW-W1-03](CLAW-W1-03-time-bomb-sweep-20261005.md).

## O que o crítico deve entregar

- `docs/04_audit/evidence/AUD19/AUD19-08-critic-report.json` no schema `phase11-critic-report` v1, com o binding e o fingerprint acima, `critic.freshContext: true`, identidade separada do builder (`cvg-lead-agent`), entrada só de artefatos, sem escrita no worktree durante a revisão e sem reaproveitar conclusões do builder.
- Validação: `node scripts/phase11-2-evidence-check.mjs --critic` antes da passada 2.

## Limites

Staging/produção `NO_GO`. Os 8 gates externos/humanos seguem pendentes; este selo não habilita piloto.
