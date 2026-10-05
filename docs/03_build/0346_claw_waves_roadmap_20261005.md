# 0346 — Roadmap cvg-claw em ondas até produção

Fontes: [auditoria 0575](../04_audit/0575_repository_audit_2026-10-05.md), [Discovery 0026](../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md), [backlog 0347](0347_claw_waves_backlog_20261005.md), [roadmap 0344](0344_post_audit_roadmap_20260925.md) e [CURRENT](../CURRENT.md).

Este roadmap substitui 0344 como sequência corrente a partir de 2026-10-05. 0344, 0342, 0340 e `ROADMAP_PRODUCAO.md` permanecem como histórico e referência. Ondas são dependências, não datas: uma onda só começa quando o gate de saída da anterior estiver registrado. Cada onda entrega algo verificável e deixa o sistema em estado estável.

Regras que valem para todas as ondas:

- Pipeline `DISCOVERY -> PRD -> SPEC -> BUILD -> AUDIT`; nenhum BUILD sem task registrada e gate aprovado.
- Somente dados sintéticos até a Onda 6, e dados reais só com autorização humana registrada.
- N3 (diagnóstico, prescrição, prontuário definitivo, liberação de exame, efeito financeiro) fica bloqueado em todas as ondas.
- Nenhuma capability sobe de nível sem PRD/SPEC próprio e decisão humana registrada.
- Staging fica `NO_GO` até o gate da Onda 5; produção fica `NO_GO` até o gate da Onda 8.

## Visão geral

| Onda | Nome                        | Entrega verificável                                                                     | Gate de saída                                                                               |
| ---- | --------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 1    | Base sólida                 | Repositório verde, plano registrado, testes sem bombas-relógio, selo do código atual    | Suíte PASS com relógio +400 dias; selo Phase 11 do candidato atual; `Verify` verde          |
| 2    | Produto definido            | Discovery validada, PRD do piloto de faturamento, SPECs de autonomia e integração       | `0090` Discovery, PRD validation e SPEC validation aprovados por humano                     |
| 3    | Núcleo do agente hospitalar | Autonomia N0–N3 no código, catálogo de faturamento, limites e parada global             | Negativos provam N3 inexecutável; coverage ≥90%; crítica independente                       |
| 4    | Integrações em sandbox      | LLM real atrás de flag, cliente do `cvg-his-v4`, token de operador, ferramentas F01–F04 | Fluxo ponta a ponta com HIS sintético: evento → plano → rascunho → aprovação → efeito draft |
| 5    | Plataforma de staging       | Manifests, migração, TLS, rate limit compartilhado, observabilidade, backup             | Staging `GO` com dados sintéticos; `production:preflight` PASS em staging                   |
| 6    | Homologação e piloto N0     | Gates externos, LGPD, piloto assistido de F01 e F04 com faturistas                      | Métricas N0 contra linha de base; zero incidente; decisão humana de seguir                  |
| 7    | Piloto N1                   | F02 e F03 com rascunho e aprovação humana                                               | Taxa de aprovação sem edição e incidentes dentro da meta do PRD                             |
| 8    | Produção controlada         | Recertificação por digest, atestação assinada, sign-off e deploy                        | `promotion:check` elegível; sign-off humano; deploy autorizado                              |

Caminho crítico: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8. A trilha de governança (G) roda em paralelo a partir da Onda 2.

## Onda 1 — Base sólida

**Objetivo:** partir de um repositório verde e honesto antes de qualquer escopo novo.

- **Entrada:** auditoria 0575; candidato `2414ae15` congelado para o crítico.
- **Entregas:** auditoria e plano registrados (W1-01, W1-02); testes sem datas que expiram (W1-03); renomeação de baixo risco concluída (W1-04); novo candidato congelado com pedido ao crítico (W1-05); parecer, passada 2, selo, push e CI verde (W1-06); decisão sobre a janela da política de tombstone (W1-07).
- **Gate de saída:** suíte unitária PASS com o relógio adiantado 400 dias, salvo artefatos classificados; `certification:verify:phase11` PASS no candidato atual; `Verify` e `Security` verdes em `origin/main`.
- **Decisões humanas:** forma do crítico independente (opencode ou subagente de contexto novo, só leitura); autorização de commit e `git push`; renovação da janela da política de tombstone, que expira em 2027-01-01 (W1-07).

## Onda 2 — Produto definido

**Objetivo:** transformar a Discovery 0026 em produto e engenharia aprovados para o piloto de faturamento.

- **Entrada:** Onda 1 concluída.
- **Entregas:** respostas às 6 perguntas e `DISCOVERY_READY` (W2-01); PRD do piloto F01–F04 com linha de base (W2-02); SPEC do modelo de autonomia N0–N3 (W2-03); SPEC do catálogo de capabilities de faturamento (W2-04); SPEC do contrato com o `cvg-his-v4` (W2-05).
- **Gate de saída:** `0090_discovery_validation.md`, `0090_prd_validation.md` e `0190_spec_validation.md` do novo escopo aprovados com revisão humana.
- **Decisões humanas:** dono de produto, DPO, responsável técnico, prioridade F01–F04, proposta de identidade.

## Onda 3 — Núcleo do agente hospitalar

**Objetivo:** levar ao código o modelo de autonomia e as capabilities do piloto, ainda sem integração externa.

- **Entrada:** SPECs W2-03 e W2-04 aprovadas.
- **Entregas:** enum N0–N3 único e uma só fonte de política (W3-01); capabilities de faturamento com dono e nível (W3-02); limites de volume e custo para N2 e parada global auditada (W3-03); preset de agente de faturamento sobre o kernel (W3-04); `server.ts` modularizado por rota sem mudança de comportamento (W3-05).
- **Gate de saída:** evals e testes negativos provam que nenhuma capability N3 executa por nenhum caminho; coverage ≥90% nos quatro eixos; crítica independente PASS.

## Onda 4 — Integrações em sandbox

**Objetivo:** ligar o agente ao mundo real em ambiente controlado, com dados sintéticos.

- **Entrada:** Onda 3 concluída; SPEC W2-05 aprovada.
- **Entregas:** provider de LLM real atrás de flag, com evals holdout (W4-01); cliente tipado do `cvg-his-v4` e testes de contrato (W4-02); consumidor idempotente de eventos do HIS (W4-03); emissão do `x-cvg-operator-token` pelo HIS e console sem headers simulados em modo `trusted` (W4-04); ferramentas F01–F04 (W4-05).
- **Gate de saída:** fluxo ponta a ponta contra um `cvg-his-v4` local com dados sintéticos, auditado nos dois lados, com aprovação humana antes de qualquer escrita.
- **Decisões humanas:** provider de LLM e contrato de tratamento de dados com o fornecedor.

## Onda 5 — Plataforma de staging

**Objetivo:** ter um ambiente de staging operável, observável e recuperável.

- **Entrada:** Onda 4 concluída.
- **Entregas:** manifests de `api`, `worker` e `web` com `--read-only` e secret manager (W5-01); job de migração separado (W5-02); TLS, CSP e HSTS na borda (W5-03); rate limit compartilhado (W5-04); exportação OTel, dashboards, alertas e SLO (W5-05); backup com PITR e restore medido (W5-06); imagem por digest e deploy automatizado de staging (W5-07).
- **Gate de saída:** staging `GO` com dados sintéticos; `production:preflight` PASS em staging; restore medido contra RPO/RTO acordados.
- **Decisões humanas:** provedor de infraestrutura, metas de RPO/RTO e SLO.

## Onda 6 — Homologação e piloto N0

**Objetivo:** primeiro contato com o setor de faturamento, só leitura e alerta.

- **Entrada:** Onda 5 concluída.
- **Entregas:** dossiês dos gates externos aplicáveis (provider, identidade, RPO/RTO, rollback, sessão de acessibilidade) (W6-01); LGPD com base legal, registro de tratamento e parecer do DPO (W6-02); piloto assistido de F01 e F04 (W6-03).
- **Gate de saída:** métricas N0 medidas contra a linha de base do PRD; zero incidente de dado ou de ação; decisão humana registrada para seguir à Onda 7.
- **Decisões humanas:** autorização de dados reais no piloto e lista de faturistas participantes.

## Onda 7 — Piloto N1

**Objetivo:** o agente prepara, o humano aprova.

- **Entrada:** Onda 6 concluída.
- **Entregas:** F02 (rascunho de conta em `draft` no HIS) e F03 (rascunho de cobrança ao tutor) com aprovação humana obrigatória (W7-01); painel de métricas do piloto (W7-02).
- **Gate de saída:** taxa de aprovação sem edição, tempo de ciclo e incidentes dentro das metas do PRD; nenhum efeito sem aprovação no journal.

## Onda 8 — Produção controlada

**Objetivo:** liberar o piloto como produção, com escopo limitado e reversível.

- **Entrada:** Onda 7 concluída.
- **Entregas:** recertificação Phase 11 do digest de produção (W8-01); atestação externa assinada com os gates `APPROVED` (W8-02); `production:preflight` e `promotion:check` elegíveis, sign-off e deploy (W8-03); processo de promoção N2 capability a capability (W8-04).
- **Gate de saída:** deploy autorizado do digest avaliado; runbooks de rollback ensaiados; dono humano nomeado por capability.

## Trilha G — governança proporcional ao risco (paralela, a partir da Onda 2)

- **G-01:** propor rigor por nível de risco (recibo hash-bound e crítico só para mudanças de risco alto), como pede a Discovery 0026; requer decisão humana.
- **G-02:** arquivar runtime state e execution log por mês, mantendo o arquivo corrente curto e com a entrada mais recente no topo.
- **G-03:** reduzir `CURRENT.md` a estado corrente, movendo o histórico de AUD20-17 para evidência.

A trilha G não altera gates nem o status de release.
