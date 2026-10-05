# AUD-20261004 — auditoria do repositório, passos para produção e avaliação do cvg-claw

Registro do parecer entregue ao usuário em 2026-10-04 (antes da renomeação para `cvg-claw`). Os números de gates refletem o momento da auditoria; o estado posterior está na [passagem de sessão](session-handoff-20261004.md).

## Veredito

Não pronto para produção. Engenharia e testes maduros; faltavam selo válido, CI verde e integrações reais (modelo de IA, WhatsApp, login).

## Gates na auditoria (Node 22.23.2)

| Gate | Resultado |
| --- | --- |
| typecheck, lint, Prettier, `docs:check` | PASS |
| `certification:verify:phase11` | PASS |
| `npm test` | 2.681 PASS, 1 FAIL (`promotion-expectation`, acoplado ao selo local), 194 skip |
| `npm audit` | 4 vulnerabilidades (fastify < 5.12.5; fast-uri) — corrigidas depois em `498ae11` |
| CI `Verify` | vermelho (integridade Phase 11) |
| `promotion:check --requested PRODUCTION` | inelegível |

## Achados

1. Re-selo local não commitado em `NO_GO` por causa das baselines visuais (geradas na imagem do CI, selo rodado no host). Descartado depois.
2. Worker só usa o modelo sintético `deterministic-v1` (`apps/worker/src/kernel-composition.ts`); providers `openai-compatible`/`ollama` existem mas não estão compostos.
3. Adapter de canal `evolution` (WhatsApp) existe mas não é usado.
4. Painel web envia headers de simulação; em produção a API exige `x-cvg-operator-token` e não há emissor.
5. `deploy/nginx.web.conf` sem TLS/CSP/HSTS; sem compose/k8s/IaC; sem job de migração (só `POSTGRES_AUTO_MIGRATE=true` em execução avulsa); sem backup configurado.
6. P2 abertos: release de claim no shutdown, paginação real, observabilidade da API.
7. Pontos fortes: preflight de produção fail-closed (RLS, deny-by-default, aprovações e journal em Postgres, efeitos reais desligados, atestação HMAC dos 8 gates externos), imagem Docker endurecida, runbooks.

## Passos para produção

**Fase 0 — repositório verde:** resolver o selo local; `npm audit fix` e recertificar; push com `Verify`/`Security` verdes; desacoplar `promotion-expectation` do selo vivo.

**Fase 1 — integrações (cada uma com task, SPEC e aprovação):** provider de LLM real no worker atrás de flag; canal `evolution`; identidade (no cvg-claw: token emitido pelo `cvg-his-v4`); P2 de shutdown, paginação e observabilidade; fonte de RAG aprovada ou RAG fora do piloto.

**Fase 2 — infraestrutura:** Postgres gerenciado com `DATABASE_URL` (RLS) e `DATABASE_MIGRATION_URL`, backup/PITR; manifests para `api`/`worker`/`web` com `--read-only` e secret manager; job de migração; TLS e headers no edge; variáveis do preflight (`NODE_ENV=production`, `CVG_WORKER_RUNTIME=kernel`, `CVG_POLICY_MODE=deny_by_default`, `CVG_ALLOW_REAL_EFFECTS=false`, `CVG_OPERATOR_IDENTITY_KEYRING`, `WEBHOOK_SIGNING_SECRET` ≥ 32, IDs de tenant/agent).

**Fase 3 — 8 gates externos** ([plano](../AUD20/AUD20-external-gates-execution-plan-20260925.md)): homologar provider, canal, identidade e RAG; metas RPO/RTO com restore real; ensaio de rollback; sessão de acessibilidade `AUD20-19`.

**Fase 4 — liberação:** recertificar e fixar a imagem por digest; atestação externa assinada com os 8 sinais `APPROVED`; `production:preflight` e `promotion:check` elegíveis; piloto controlado em modo assistido; sign-off humano e deploy.

## Avaliação: evoluir para o cvg-claw

A base serve bem: orquestrador objetivo → plano → etapas com orçamento de iterações, policy deny-by-default com capabilities, aprovações persistentes, outbox/journal idempotentes, takeover humano, multi-tenant com RLS, auditoria e ADRs de plataforma. Faltam o LLM real, ferramentas tipadas para o sistema de gestão, identidade e catálogo de capabilities do hospital.

Autonomia proposta em níveis: N0 informar, N1 preparar com aprovação, N2 executar ação reversível de baixo risco, N3 nunca (clínico, prontuário, financeiro).

Riscos: escopo crescer antes do primeiro piloto; peso da governança atual; responsabilidade por ação autônoma. Recomendação: levar o kernel a um piloto real primeiro, com a Discovery do cvg-claw em paralelo, e reutilizar o kernel com um preset novo em vez de reescrever. Desdobramento na [Discovery 0026](../../../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md).
