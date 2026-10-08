# 0349 — Backlog integral AUD06

Fonte: [auditoria 0576](../04_audit/0576_repository_audit_2026-10-06.md).
[Roadmap](0348_aud06_roadmap.md), [SPEC e critérios](../02_spec/aud06_remediation_20261006.md).
Estados oficiais; COMPLETED exige evidência, não só mudança de arquivo.

| ID       | Achado           | O que / onde / como                                                     | Depende de                        | Aceite                                                                   | Estado                 |
| -------- | ---------------- | ----------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------ | ---------------------- |
| AUD06-01 | Todos            | Criar roadmap, backlog, PRD/SPEC e barra Q01–Q14 em docs                | Auditoria                         | Q01; links válidos, escopo completo                                      | COMPLETED              |
| AUD06-02 | F01              | Atualizar source-map-js no lockfile com instalação reproduzível         | 01                                | Q02; audit sem high/critical, build/testes                               | COMPLETED              |
| AUD06-03 | F02              | N3 canônico e irredutível em policy-engine, negativos no runtime        | 01                                | Q03; cinco operações DENY sem executor, sem promoção                     | COMPLETED              |
| AUD06-04 | F03              | Ambiente visual CI e runner Playwright pinados; diagnóstico por imagens | 01                                | Q04; 75/75 nos três browsers, tolerâncias preservadas                    | COMPLETED              |
| AUD06-05 | F07              | Runner scripts/ preserva exit, cleanup próprio e prazo                  | 01                                | Q05; sucesso/falha/timeout/sinal demonstrados                            | COMPLETED              |
| AUD06-06 | F05              | Implementar decisão de retenção em retention.ts e testes                | 01; receipt CLAW-W1-07            | Q06; janela, aviso, fronteiras e PostgreSQL PASS                         | COMPLETED              |
| AUD06-07 | F05/F08          | Reconciliar CURRENT/runtime/matriz/backlog, manter histórico            | 01                                | Q07; checker e ponteiros refletem o estado observado                     | COMPLETED              |
| AUD06-08 | F08              | Extrair registrador coeso da API e reduzir acoplamento de cliente       | 03/04 para integração             | Q08; regressão pública e redução medida                                  | COMPLETED              |
| AUD06-09 | F06              | Composição descartável API/worker/web/banco, migração, TLS/headers      | 01                                | Q09; startup/health/teardown isolados observados                         | COMPLETED              |
| AUD06-10 | F06              | Rate compartilhado, coleta/exportação e ensaio de restore               | 09                                | Q10; duas réplicas, falha de storage, telemetria, integridade restaurada | COMPLETED              |
| AUD06-11 | F04              | Resolver Discovery 0026 e contratos/integrações HIS/piloto              | Respostas de produto e identidade | Q11; contratos aprovados e fluxo ponta a ponta qualificado               | WAITING_HUMAN_APPROVAL |
| AUD06-12 | Todos            | Regressão integrada e Gauntlet com crítica fresca                       | 02–10                             | Q12; testes, PostgreSQL, E2E, critic sem achado material                 | COMPLETED              |
| AUD06-13 | F03/certificação | Selar candidato após docs estáveis; validar CI do mesmo candidato       | 12; autoridade de publicação      | Q13; certificado+Verify/Security com SHA correspondente                  | IN_PROGRESS            |
| AUD06-14 | F04/F06          | Oito gates externos/humanos em ambiente e janela autorizados            | 11/13; owners/ambiente            | Q14; evidências reais e signoff, sem síntese de aprovação                | WAITING_HUMAN_APPROVAL |

## Evidências e pendências externas

Recibos ficam em `docs/04_audit/evidence/AUD06/`; resultados entram aqui após
revisão. Itens 11/14 continuam parte da conclusão integral. Não serão removidos
do escopo para declarar sucesso da parte local. Nenhum owner ou valor de
baseline do piloto será presumido. Faturas/mensagens reais não são enviadas.

## Integração local em execução — 2026-10-06

Planejamento Q01 e barreira N3 Q03 têm aceite local; os demais itens implementados
aguardam integração/crítica. Os recibos de cada tarefa constam na
[matriz](tracking/aud06_tasks.json). A cópia de qualificação está registrada em
[integração](../04_audit/evidence/AUD06/integration-worktree.json).
A prova de tipos do cliente confirma JavaScript executável idêntico ao HEAD,
com redução de 1.543 para 1.015 linhas. O ensaio completo da stack inclui
telemetria por processo, duas réplicas, falha de storage e restore. Esses
ensaios sintéticos não satisfazem os gates externos do piloto.

## Etapa de produto/piloto adiada pelo usuário

AUD06-11 permanece sem aceite e com disposição DEFERRED_BY_USER. O usuário
adiou as definições do piloto e manteve a prioridade F01/F03; identidade HIS
permanece em avaliação. [Recibo](../04_audit/evidence/AUD06/recovery-20261007/user-pilot-steering.json).
A etapa não será cobrada novamente durante a qualificação técnica. Os gates
externos não são considerados satisfeitos por esse adiamento.

### Rework I1 — 2026-10-07

AUD06-09/10 retornam a BUILD local limitado: limpeza após falha de logs,
prazo de aquisição da quota e nova prova do worker atual. AUD06-12 continua
IN_PROGRESS: E2E 75/75 PASS no candidato anterior a este rework; verify
interrompido (143), sem aceite. Critic I1 aprovou Q05/Q08 e pediu REVISE em
Q09/Q10. Lead é proprietário de quota e masters; builder de stack possui
somente runner/testes do stack e nova evidência. Piloto segue adiado.

### Rework Q07 e integridade final — 2026-10-07

Verify-7 exit0: 332 arquivos/3059 testes em unit e cobertura; PostgreSQL
32/369 zero-skip; navegadores 75/75; audit sem vulnerabilidades. Snapshot
19387020... preservado. Crítico final observou divergência 09/10 entre tabela
e matriz (corrigida) e escreveu cache ignorado via symlink no principal.
Parecer INVALID para Q12, não reutilizado como aceite. Q07 em rework:
checker agora exige todas as linhas e caminho fixo; RED6FAIL/7PASS, GREEN25/25
incluindo integridade documental. Nova regressão e crítico isolado exigidos.

### Aceite técnico local — 2026-10-07

AUD06-01..10 e AUD06-12 COMPLETED somente no escopo local sintético, conforme
[aceite](../04_audit/evidence/AUD06/recovery-20261007/local-technical-acceptance.json)
e [parecer independente](../04_audit/evidence/AUD06/recovery-20261007/final-critic-v4/final-report.json).
Verify9 332/3066 unit e coverage; PostgreSQL32/369 sem skips; browsers75/75.
O rework e as falhas anteriores permanecem históricos. AUD06-13 IN_PROGRESS
para preparar certificação local sobre docs estáveis; selo/CI ainda pendentes.
AUD06-11 adiado pelo usuário e AUD06-14 sem aceite; resultado global FAIL/NO_GO.
[Reauditoria0577](../04_audit/0577_aud06_remediation_reaudit_2026-10-07.md):74,27/100.
