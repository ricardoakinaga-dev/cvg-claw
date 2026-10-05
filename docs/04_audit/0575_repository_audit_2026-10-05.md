# 0575 — Auditoria do repositório cvg-claw — 2026-10-05

## Escopo e critério

- **ID:** `AUD-20261005-CLAW`.
- **Objeto:** repositório `cvg-claw` em `main`, commit `3b62f15`, avaliado como base para o agente hospitalar (Discovery [0026](../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md)).
- **Método:** leitura das fontes canônicas ([AGENTS operacional](../07_agents/AGENTS.md), [CURRENT](../CURRENT.md), [runtime state](../99_runtime_state.md), [backlog master](../30_backlog_master.md)), inspeção de código e execução local de gates sob Node `22.23.2`. Sem escrita no repositório durante a auditoria, sem dados reais, sem commit, push ou deploy.
- **Escala:** 90–100 excelente; 75–89 bom com lacunas menores; 60–74 aceitável com lacunas que pedem plano; 40–59 fraco; 0–39 ausente ou bloqueante. A nota geral é média ponderada e não substitui nenhum gate obrigatório.
- **Relatório completo entregue ao usuário:** documento compartilhado "Auditoria cvg-claw — Relatório Completo" (claude.ai); este arquivo é o registro canônico no repositório.

## Verificações executadas

| Verificação                      | Resultado                                                                                    |
| -------------------------------- | -------------------------------------------------------------------------------------------- |
| typecheck, lint, Prettier        | PASS                                                                                         |
| `docs:check` (Node 22.23.2)      | PASS; 2.159 links, 647 JSONs                                                                 |
| `docs:check` (Node 24 do host)   | FAIL esperado por `node_runtime_mismatch`                                                    |
| `npm audit`                      | 0 vulnerabilidades                                                                           |
| `test:coverage` (sem PostgreSQL) | 307 arquivos PASS/12 skipped; 2.682 testes PASS/194 skips/0 falhas                           |
| Coverage                         | statements 93,02%, branches 90,19%, functions 91,23%, lines 93,49%                           |
| PostgreSQL, E2E, certificação    | Não reexecutados; valem os recibos de 2026-10-04 (passada 1: 33/35 gates, 16/16 invariantes) |

## Notas

| #   | Item                         | Peso | Nota |
| --- | ---------------------------- | ---- | ---- |
| 1   | Governança e processo CVG    | 8    | 70   |
| 2   | Documentação                 | 7    | 60   |
| 3   | Produto e Discovery cvg-claw | 9    | 30   |
| 4   | Arquitetura e código         | 11   | 76   |
| 5   | Testes e qualidade           | 11   | 88   |
| 6   | Segurança de aplicação       | 11   | 74   |
| 7   | Guardrails de autonomia      | 10   | 62   |
| 8   | CI/CD e supply chain         | 7    | 66   |
| 9   | Certificação e release       | 5    | 55   |
| 10  | Infraestrutura e deploy      | 7    | 30   |
| 11  | Integrações reais            | 6    | 15   |
| 12  | Observabilidade              | 3    | 60   |
| 13  | Dados e conformidade         | 5    | 68   |
|     | **Nota geral ponderada**     | 100  | 60   |

Leitura: a base de engenharia está perto de 80; a prontidão do cvg-claw para piloto está perto de 30.

## Achados

| #   | Severidade | Achado                                                                                        | Onde                                                                        |
| --- | ---------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| A1  | Alta       | Discovery 0026 em `DRAFT`, 6 perguntas abertas; sem PRD nem SPEC                              | `docs/00_discovery/0026_*.md`                                               |
| A2  | Alta       | Worker só compõe o modelo sintético `deterministic-v1`                                        | `apps/worker/src/kernel-composition.ts`                                     |
| A3  | Alta       | Console web envia identidade em headers simulados; sem emissor de `x-cvg-operator-token`      | `apps/web/src/api/client.ts`                                                |
| A4  | Alta       | N0–N3 só existe na documentação; o código usa `level_1_collect`/`level_2_suggest` em `policy` | `packages/shared/src/enums.ts`, `packages/policy`, `packages/policy-engine` |
| A5  | Alta       | Sem manifests de deploy, TLS/CSP/HSTS, job de migração ou backup                              | `deploy/nginx.web.conf`                                                     |
| A6  | Média      | CI `Verify` vermelho; 4 commits sem push; `certification/current.json` aponta para `b3b715e`  | `certification/current.json`                                                |
| A7  | Média      | Catálogo de capabilities sem faturamento nem contexto veterinário                             | `packages/policy-engine/src/capabilities.ts`                                |
| A8  | Média      | Rate limit em memória, sem efeito com várias réplicas                                         | `apps/api/src/rate-limit.ts`                                                |
| A9  | Média      | 136 arquivos de teste com datas fixas; uma já quebrou o gate em 2026-10-01                    | `retention-postgres.test.ts` e outros                                       |
| A10 | Média      | Estado, log e backlog somam 1,1 MB; `docs/` tem 3.132 arquivos                                | `docs/99_*`, `docs/20_*`, `docs/30_*`                                       |
| A11 | Baixa      | Arquivos acima de 3 mil linhas                                                                | `apps/api/src/server.ts`, `orchestration.ts`, `postgres.ts`                 |
| A12 | Baixa      | Renomeação incompleta (descrição do pacote, banco do `.env.example`, upstream do nginx)       | `package.json`, `.env.example`, `deploy/nginx.web.conf`                     |

## Encaminhamento

O plano em ondas está no [roadmap 0346](../03_build/0346_claw_waves_roadmap_20261005.md) e no [backlog 0347](../03_build/0347_claw_waves_backlog_20261005.md). Staging e produção permanecem `NO_GO`.
