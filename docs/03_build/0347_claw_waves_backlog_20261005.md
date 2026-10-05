# 0347 — Backlog cvg-claw em ondas

Fontes: [roadmap 0346](0346_claw_waves_roadmap_20261005.md), [auditoria 0575](../04_audit/0575_repository_audit_2026-10-05.md), [Discovery 0026](../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md) e [backlog master](../30_backlog_master.md).

Formato de cada item: o que, onde, como, dependência e critério de pronto (`docs/07_agents/AGENTS.md`). Itens das Ondas 2 a 8 estão `PLANNED`: planejado não é autorização de código. Cada BUILD exige SPEC aprovada e admissão própria. A Onda 1 foi admitida pelo usuário em 2026-10-05 ([recibo](../04_audit/evidence/CLAW-W1/CLAW-W1-admission-20261005.md)). Staging e produção permanecem `NO_GO`.

## Onda 1 — Base sólida (admitida)

### CLAW-W1-01 — Registrar a auditoria 0575

- **O que:** gravar no repositório a auditoria de 2026-10-05 com notas por item e achados A1–A12.
- **Onde:** `docs/04_audit/0575_repository_audit_2026-10-05.md`.
- **Como:** somente documentação; números conferidos com os gates executados.
- **Dependência:** nenhuma.
- **Critério de pronto:** arquivo criado e linkado em `CURRENT.md`; `docs:check` PASS.
- **Estado (2026-10-05):** executado.

### CLAW-W1-02 — Roadmap e backlog em ondas

- **O que:** publicar o roadmap 0346 e este backlog; apontar masters, `CURRENT.md`, backlog master e `ROADMAP_PRODUCAO.md` para eles.
- **Onde:** `docs/03_build/0346_*`, `docs/03_build/0347_*`, `docs/03_build/0301_roadmap.md`, `docs/03_build/0302_backlog_master.md`, `docs/CURRENT.md`, `docs/30_backlog_master.md`, `docs/ROADMAP_PRODUCAO.md`.
- **Como:** documentos novos; nos existentes, só um parágrafo de ponteiro no topo, sem reescrever histórico.
- **Dependência:** CLAW-W1-01.
- **Critério de pronto:** links válidos; `docs:check` PASS.
- **Estado (2026-10-05):** executado.

### CLAW-W1-03 — Eliminar testes que expiram com o tempo

- **O que:** encontrar testes que falham quando o relógio avança e corrigi-los, sem alterar código de produto.
- **Onde:** testes Vitest em `apps/`, `packages/` e `tests/`; receita de varredura em `docs/04_audit/evidence/CLAW-W1/`.
- **Como:** rodar a suíte com `Date` adiantado 400 dias por um preload (`NODE_OPTIONS=--import`); para cada falha, trocar a data fixa por uma data relativa ao relógio injetado ou ao momento da execução; registrar a receita para reuso.
- **Dependência:** nenhuma.
- **Critério de pronto:** suíte PASS com relógio real; com relógio +400 dias, toda falha corrigida ou classificada como artefato do método; zero mudança em código de produto; achado A9 fechado para o lado Node.
- **Estado (2026-10-05):** executado. Uma bomba-relógio real corrigida (`journeys-api.test.ts`) e 5 artefatos classificados. Ver [relatório da varredura](../04_audit/evidence/CLAW-W1/CLAW-W1-03-time-bomb-sweep-20261005.md).

### CLAW-W1-04 — Concluir a renomeação de baixo risco

- **O que:** remover resíduos do nome antigo que não estão vinculados a evidência.
- **Onde:** `package.json` (descrição) e `.env.example` (nome do banco local).
- **Como:** só texto e configuração de exemplo. As tags `cvg-aud19-*` de imagem ficam, porque scripts e recibos de digest dependem delas; o upstream `secretary-api` do nginx muda junto com os manifests em CLAW-W5-01; `serviceName` da telemetria segue a task própria do backlog master.
- **Dependência:** nenhuma.
- **Critério de pronto:** `npm ci` aceita o lock sem mudança; typecheck, lint e testes PASS.
- **Estado (2026-10-05):** executado (descrição do pacote e banco `cvg_claw` no `.env.example`).

### CLAW-W1-05 — Congelar o novo candidato e atualizar o pedido ao crítico

- **O que:** como W1-01 a W1-04 mudam bytes fora das exclusões, o candidato `2414ae15` deixa de valer; congelar o novo candidato e registrar o pedido.
- **Onde:** `docs/04_audit/evidence/CLAW-W1/`.
- **Como:** commit local dos itens W1-01 a W1-04; calcular candidateId, treeHash e fingerprint com `scripts/lib/certification-rules.mjs`; descrever o delta.
- **Dependência:** W1-01 a W1-04.
- **Critério de pronto:** pedido com binding conferível e delta completo; worktree limpo.

### CLAW-W1-06 — Parecer, passada 2, selo, push e CI verde

- **O que:** fechar o ciclo de certificação do candidato atual.
- **Onde:** `docs/04_audit/evidence/AUD19/AUD19-08-critic-report.json`, `certification/`, GitHub Actions.
- **Como:** crítico independente de contexto novo, só leitura; passada 2 com [certify-pass.sh](../04_audit/evidence/CLAW-reseal/certify-pass.sh) na imagem Playwright; commit do selo com recibo só em `docs/04_audit/evidence/`; `git push`.
- **Dependência:** W1-05; decisão humana sobre a forma do crítico e autorização de push.
- **Critério de pronto:** `certification:verify:phase11` PASS; `promotion:check` inelegível só pelos gates externos; `Verify` e `Security` verdes em `origin/main`.

### CLAW-W1-07 — Renovar a janela de aprovação da política de tombstone

- **O que:** a constante `INBOUND_TOMBSTONE_POLICY_VALID_UNTIL` (`packages/persistence/src/retention.ts:47`) expira em `2027-01-01T02:59:59Z`. A partir daí a minimização de tombstones inbound falha fechado e os testes PostgreSQL que a exercitam falham.
- **Onde:** `packages/persistence/src/retention.ts` e a aprovação da política de retenção em `docs/02_spec/`.
- **Como:** decisão humana de renovar a política com nova janela e nova aprovação registrada; depois, task própria para atualizar a constante e os testes de borda.
- **Dependência:** decisão humana; prazo antes de 2026-12-31.
- **Critério de pronto:** nova janela aprovada e vigente; gate PostgreSQL PASS; teste de expiração atualizado para a nova data.

## Onda 2 — Produto definido (PLANNED)

### CLAW-W2-01 — Validar a Discovery 0026

- **O que:** responder às 6 perguntas abertas e registrar `DISCOVERY_READY`.
- **Onde:** `docs/00_discovery/0026_*.md` e `0090_discovery_validation.md`.
- **Como:** sessão com o usuário e o setor de faturamento; respostas registradas com data e responsável.
- **Dependência:** Onda 1.
- **Critério de pronto:** validação aprovada por humano; dono de produto, DPO e responsável técnico nomeados.

### CLAW-W2-02 — PRD do piloto de faturamento

- **O que:** produto F01–F04, com métricas e linha de base medida.
- **Onde:** `docs/01_prd/`.
- **Como:** `prd-engine`; métricas: tempo de fechamento de conta, contas com itens faltando, recebíveis vencidos, taxa de aprovação sem edição, incidentes.
- **Dependência:** W2-01.
- **Critério de pronto:** `0090_prd_validation.md` aprovado.

### CLAW-W2-03 — SPEC do modelo de autonomia N0–N3

- **O que:** um único enum de autonomia, o mapeamento capability → nível, limites de volume e custo para N2 e a parada global.
- **Onde:** `docs/02_spec/`; alvo de código `packages/shared`, `packages/policy`, `packages/policy-engine`.
- **Como:** resolver a duplicidade entre `AutonomyLevel` (`level_1_collect`, `level_2_suggest`) e o modelo de capabilities; definir migração sem perda de negativos existentes.
- **Dependência:** W2-02.
- **Critério de pronto:** SPEC aprovada; negativos N3 enumerados.

### CLAW-W2-04 — SPEC do catálogo de capabilities de faturamento

- **O que:** capabilities `encounter.read`, `billing.read`, `billing.draft`, `receivable.read`, `reconciliation.read`, `message.draft` ao tutor, com nível, risco e dono.
- **Onde:** `docs/02_spec/`; alvo `packages/policy-engine/src/capabilities.ts`.
- **Como:** derivar do mapa F01–F04 da Discovery; efeitos financeiros seguem N3.
- **Dependência:** W2-03.
- **Critério de pronto:** SPEC aprovada; cada capability com dono humano.

### CLAW-W2-05 — SPEC do contrato com o `cvg-his-v4`

- **O que:** subconjunto versionado da OpenAPI do HIS, eventos consumidos, conta de serviço e emissão do token de operador.
- **Onde:** `docs/02_spec/`; HIS em release identificado (hoje HEAD destacado `fdc591ae`).
- **Como:** contrato versionado e testes de contrato nos dois repositórios.
- **Dependência:** W2-02.
- **Critério de pronto:** SPEC aprovada nos dois lados.

## Onda 3 — Núcleo do agente hospitalar (PLANNED)

| ID         | O que                                               | Onde                                                           | Dependência | Critério de pronto                                                     |
| ---------- | --------------------------------------------------- | -------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------- |
| CLAW-W3-01 | Enum N0–N3 único; uma só fonte de política          | `packages/shared`, `packages/policy`, `packages/policy-engine` | W2-03       | Negativos antigos e novos PASS; nenhum caminho N3 executável           |
| CLAW-W3-02 | Capabilities de faturamento com dono e nível        | `packages/policy-engine`                                       | W2-04       | Catálogo validado por zod; grants deny-by-default                      |
| CLAW-W3-03 | Limites de volume/custo N2 e parada global auditada | `packages/policy-engine`, `apps/api`, `apps/worker`            | W3-01       | Parada global testada sob carga; evento de auditoria por ativação      |
| CLAW-W3-04 | Preset do agente de faturamento                     | `packages/platform`                                            | W3-02       | Preset versionado e imutável; evals do preset PASS                     |
| CLAW-W3-05 | Modularizar `apps/api/src/server.ts` por rota       | `apps/api/src/routes`                                          | W3-01       | Sem mudança de comportamento; suíte e e2e PASS; arquivo < 1.500 linhas |

## Onda 4 — Integrações em sandbox (PLANNED)

| ID         | O que                                                                          | Onde                                    | Dependência  | Critério de pronto                                                     |
| ---------- | ------------------------------------------------------------------------------ | --------------------------------------- | ------------ | ---------------------------------------------------------------------- |
| CLAW-W4-01 | Provider de LLM real atrás de flag, com evals holdout                          | `apps/worker`, `packages/model-gateway` | Onda 3       | Evals holdout PASS; flag desligada por padrão; custo por tarefa medido |
| CLAW-W4-02 | Cliente tipado do HIS gerado da OpenAPI e testes de contrato                   | `packages/tools` ou pacote novo         | W2-05        | Contrato PASS contra HIS local com dados sintéticos                    |
| CLAW-W4-03 | Consumidor idempotente de eventos do HIS                                       | `apps/worker`                           | W4-02        | Reentrega e restart sem duplicar efeito                                |
| CLAW-W4-04 | Token de operador emitido pelo HIS; console sem headers simulados em `trusted` | `cvg-his-v4`, `apps/web`                | W2-05        | Login do HIS abre o console; header forjado rejeitado                  |
| CLAW-W4-05 | Ferramentas F01/F04 (N0) e F02/F03 (N1)                                        | `packages/tools`, `packages/workflows`  | W4-02, W3-02 | Ponta a ponta sandbox com aprovação antes de qualquer escrita          |

## Onda 5 — Plataforma de staging (PLANNED)

| ID         | O que                                              | Onde                                | Dependência | Critério de pronto                                |
| ---------- | -------------------------------------------------- | ----------------------------------- | ----------- | ------------------------------------------------- |
| CLAW-W5-01 | Manifests `api`/`worker`/`web` read-only, secrets  | `deploy/`                           | Onda 4      | Subida limpa em staging; upstream renomeado       |
| CLAW-W5-02 | Job de migração separado                           | `deploy/`, `packages/persistence`   | W5-01       | Migração idempotente com `DATABASE_MIGRATION_URL` |
| CLAW-W5-03 | TLS, CSP, HSTS e headers na borda                  | `deploy/nginx.web.conf`             | W5-01       | Scan de headers PASS                              |
| CLAW-W5-04 | Rate limit compartilhado                           | `apps/api/src/rate-limit.ts`        | W5-01       | Limite vale com 2+ réplicas                       |
| CLAW-W5-05 | Exportação OTel, dashboards, alertas, SLO          | `packages/observability`, `deploy/` | W5-01       | Alerta disparado e atendido em ensaio             |
| CLAW-W5-06 | Backup com PITR e restore medido                   | infraestrutura                      | W5-02       | RPO/RTO medidos dentro da meta                    |
| CLAW-W5-07 | Imagem por digest e deploy automatizado de staging | `.github/workflows`                 | W5-01       | Deploy reproduzível pelo digest                   |

## Ondas 6 a 8 (PLANNED)

| ID         | O que                                                    | Dependência  | Critério de pronto                                      |
| ---------- | -------------------------------------------------------- | ------------ | ------------------------------------------------------- |
| CLAW-W6-01 | Dossiês dos gates externos aplicáveis                    | Onda 5       | Cada gate `APPROVED` por responsável nomeado            |
| CLAW-W6-02 | LGPD: base legal, registro de tratamento, parecer do DPO | W2-01        | Parecer assinado                                        |
| CLAW-W6-03 | Piloto assistido N0 (F01, F04)                           | W6-01, W6-02 | Métricas contra linha de base; zero incidente           |
| CLAW-W7-01 | Piloto N1 (F02, F03) com aprovação obrigatória           | Onda 6       | Metas do PRD atingidas; nenhum efeito sem aprovação     |
| CLAW-W7-02 | Painel de métricas do piloto                             | W7-01        | Métricas visíveis ao dono de produto                    |
| CLAW-W8-01 | Recertificação Phase 11 do digest de produção            | Onda 7       | `certification:verify:phase11` PASS no digest           |
| CLAW-W8-02 | Atestação externa assinada                               | W8-01        | Gates `APPROVED` com assinatura verificável             |
| CLAW-W8-03 | Preflight, promotion check, sign-off e deploy            | W8-02        | Deploy autorizado do digest avaliado; rollback ensaiado |
| CLAW-W8-04 | Processo de promoção N2 capability a capability          | W8-03        | Cada promoção com PRD/SPEC e decisão humana             |

## Trilha G (PLANNED, paralela)

- **CLAW-G-01:** governança proporcional ao risco; requer decisão humana.
- **CLAW-G-02:** arquivamento mensal de runtime state e execution log.
- **CLAW-G-03:** `CURRENT.md` reduzido ao estado corrente.
