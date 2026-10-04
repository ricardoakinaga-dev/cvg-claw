# Discovery proposta CLAW-01 — cvg-claw, agente autônomo governado do hospital

## Registro

- ID: DISCOVERY-CLAW-01
- Versão: 2 (contexto veterinário, piloto e integração com o `cvg-his-v4`)
- Responsável pela proposta: executor local; dono de produto do cvg-claw a designar
- Atualização: 2026-10-04
- Origem: decisão do usuário de evoluir a `cvg-agent-secretary-v2` (Esmeralda V2) para o `cvg-claw`, com repositório GitHub dedicado
- Tier proposto: T1_PROGRAM; risco operacional HIGH (dados pessoais e financeiros de tutores; efeitos em faturamento)

## Estado

- task proposta: CLAW-01
- fase: DISCOVERY
- disposição local: DRAFT; nenhum gate `DISCOVERY_READY` registrado
- execução permitida nesta etapa: leitura e documentação local
- PRD, SPEC e BUILD do novo escopo: não admitidos
- dados reais, integração externa, staging e produção: NO_GO
- relação com o programa corrente: AUD20 e o piloto da secretária continuam; esta Discovery não reabre nem substitui tasks AUD20

## Decisões e fatos registrados na v2 (2026-10-04)

- **Hospital veterinário.** O sistema de gestão é o `cvg-his-v4`, desenvolvido pelo próprio usuário (repositório local `/home/ricardo/cvg-his-v4`; "HIS veterinário V4").
- **Setor do primeiro piloto:** faturamento/convênios (decisão do usuário).
- **Identidade:** login e senha na própria plataforma do ERP (`cvg-his-v4`), que é a autoridade de identidade.
- No `cvg-his-v4`, "convênio" hoje é **só uma forma de pagamento** (`insurance` em vendas de balcão, conta contábil `1.1.05-convenios`). Não há fluxo de autorização prévia, guia ou glosa. Por isso UC-C01/UC-C02 abaixo foram reescritos para o que o HIS realmente tem.

## Problema

O hospital tem tarefas administrativas e operacionais de alto volume, repetitivas e espalhadas entre setores e sistemas: autorização de convênio, glosas, pendências de alta, regulação de leitos, chamados internos, agendamento interno e comunicação entre equipes. Hoje essas tarefas dependem de pessoas que consultam vários sistemas, montam documentos e acompanham prazos manualmente.

A Esmeralda V2 atende só a conversa com paciente (secretária). O cvg-claw propõe um agente que **planeja e executa tarefas** de várias etapas para as equipes do hospital, sempre dentro de limites de autonomia explícitos, com aprovação humana e trilha de auditoria.

A visão original já previa isso: "A Esmeralda V2 deve nascer como `Agent Platform Hospitalar`, nao como bot de WhatsApp" ([README](../README.md)).

## Hipótese de valor

- Reduzir o tempo de ciclo de tarefas administrativas (por exemplo, guia de convênio preparada antes do paciente chegar).
- Reduzir glosas e perdas por prazo.
- Liberar as equipes de consulta e redigitação entre sistemas.
- Manter cada ação rastreável, com um humano responsável.

Métricas candidatas (linha de base a medir no setor piloto): tempo médio por tarefa, volume tratado por pessoa, taxa de glosa, pendências vencidas, taxa de aprovação dos rascunhos do agente sem edição e incidentes.

## Níveis de autonomia (proposta)

| Nível         | O agente faz                                                  | Condição                                                                                                   |
| ------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| N0 — Informar | Consulta, resume, alerta                                      | Somente leitura, com escopo de tenant/setor                                                                |
| N1 — Preparar | Monta rascunho; humano aprova antes de qualquer efeito        | `approval-engine` obrigatório                                                                              |
| N2 — Executar | Ação reversível, de baixo risco, com limite de volume e custo | Capability promovida por PRD/SPEC + decisão humana; journal e compensação                                  |
| N3 — Nunca    | Bloqueado sempre                                              | Diagnóstico, prescrição, triagem com decisão, prontuário definitivo, liberação de exame, efeito financeiro |

Regra: nenhuma capability sobe de nível sem PRD/SPEC próprio e decisão humana registrada. As capabilities hoje negadas (`clinical.diagnose`, `clinical.prescribe`, `patient.record.write`, `exam.release`, `finance.write`) permanecem N3.

## Casos de uso candidatos (a validar com o hospital)

| ID     | Caso                                                    | Setor                     | Nível inicial       | Sistemas envolvidos                               |
| ------ | ------------------------------------------------------- | ------------------------- | ------------------- | ------------------------------------------------- |
| UC-C01 | Detectar atendimento encerrado sem faturamento completo | Faturamento               | N0                  | `cvg-his-v4` (encounters, billing)                |
| UC-C02 | Preparar rascunho de conta/orçamento para revisão       | Faturamento               | N1                  | `cvg-his-v4` (billing estimate/items)             |
| UC-C03 | Acompanhar pendências da alta                           | Enfermagem/administrativo | N0                  | Sistema de gestão hospitalar/prontuário (leitura) |
| UC-C04 | Painel e alertas de leitos                              | Regulação/NIR             | N0                  | Sistema de gestão hospitalar                      |
| UC-C05 | Abrir e encaminhar chamados internos                    | TI/manutenção/hotelaria   | N2 (após piloto N1) | Ferramenta de chamados                            |
| UC-C06 | Agendamento interno e lembretes às equipes              | Administrativo            | N1                  | Agenda corporativa, canal interno                 |
| UC-C07 | Secretária do paciente (Esmeralda)                      | Recepção/central          | N1 (escopo atual)   | Canal WhatsApp, agenda                            |

## Piloto de faturamento: mapa de integração com o `cvg-his-v4`

Levantamento read-only do `cvg-his-v4` (OpenAPI com 433 caminhos em `apps/api/src/openapi.yaml`, catálogo de eventos em `packages/modules/event-bus/src/event-catalog.ts`, RBAC em `packages/rbac`):

| Caso do piloto                                                   | Gatilho no HIS                                     | Leitura                                                                              | Efeito (só após aprovação)                             | Nível |
| ---------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------ | ----- |
| F01 — Atendimento encerrado sem conta ou com itens não faturados | eventos `encounter.closed`, `inpatient.discharged` | `GET /billing/{encounterId}`, `/billing/{encounterId}/items`, leitura do atendimento | nenhum; alerta para a equipe                           | N0    |
| F02 — Rascunho de conta/orçamento                                | F01 ou pedido do faturista                         | `/billing/estimate`, itens do atendimento                                            | criar itens/conta em `draft` via `POST /billing/items` | N1    |
| F03 — Recebíveis vencidos e cobrança                             | rotina diária                                      | `GET /financial/aging`, `/financial/receivables`                                     | rascunho de mensagem ao tutor; envio só com aprovação  | N1    |
| F04 — Divergências de conciliação (cartão/PIX/convênio)          | eventos `payment.*`, `receivable.*`                | `/financial/reconciliation`, `/financial/reconciliation/cards`                       | nenhum; relatório para o financeiro                    | N0    |

Fora do piloto (N3): `PATCH /billing/{encounterId}/status` para `settled`, `/financial/receivables/{id}/settle`, pagamentos, estornos e qualquer lançamento no ledger.

### Identidade e acesso

- **Operador → cvg-claw:** o `cvg-his-v4` continua dono do login (usuário/senha + MFA). Proposta: o backend do HIS emite, para o usuário já logado, o token curto `x-cvg-operator-token` (HMAC com `kid`, audiência `cvg-api`, 5 min) que o cvg-claw já valida no modo `trusted` (`CVG_OPERATOR_IDENTITY_KEYRING`). A tela do cvg-claw pode abrir dentro do HIS. Isso fecha a lacuna do web sem token apontada na auditoria AUD-20261004.
- **cvg-claw → HIS:** conta de serviço com API key do módulo `api-keys` do HIS, com permissões mínimas (`billing.read`, `encounters.read`, `inpatient.read` e leitura financeira; `billing.manage` só para F02 e só depois da aprovação). Cada chamada leva o operador que aprovou e o id de correlação, para aparecer na auditoria dos dois lados.
- O `cvg-his-v4` também tem cliente OIDC (`packages/modules/auth/src/oidc.ts`); fica como alternativa futura se o hospital adotar um IdP.

## O que a base atual já cobre

- Orquestrador com objetivo → plano → etapas, limite de iterações e controle de replanejamento (migrações 0019–0023).
- `policy-engine` que nega por padrão, com capabilities e grants.
- `approval-engine` com aprovações persistentes; outbox, effect journal e idempotência.
- Handoff e human takeover (INV-014); multi-tenant com RLS; trilha de auditoria e tracing.
- ADRs de plataforma: control plane/data plane, versões imutáveis de agente, secrets por referência, capability gateway ([docs/platform/adr](../platform/adr)).
- Preset de agente (`packages/platform/src/secretary-preset.ts`), modelo para um preset hospitalar.

## Lacunas conhecidas

1. Provider de LLM real não composto no worker (hoje `deterministic-v1`); sem ele não há planejamento autônomo.
2. Ferramentas tipadas para a API do `cvg-his-v4` (cliente gerado a partir do OpenAPI, só os endpoints do piloto) e consumidor dos eventos do HIS.
3. Emissão do `x-cvg-operator-token` pelo `cvg-his-v4` (mudança no HIS) e mapeamento dos papéis do RBAC do HIS para capabilities do cvg-claw.
4. Catálogo de capabilities hospitalar com dono por capability.
5. Observabilidade de produção da API e botão de parada global operado pelo hospital.

## Riscos

- **Regulatório (veterinário):** a LGPD vale para os dados dos tutores (pessoais e financeiros), com base legal, DPO e registro de tratamento; o dado de saúde do animal não é dado sensível de pessoa, mas segue confidencial. Atos privativos do médico-veterinário (diagnóstico, prescrição) ficam N3. A regra de dispositivo médico da ANVISA (RDC 657/2022) é de saúde humana e não se aplica ao escopo do piloto; confirmar com o jurídico se houver produto de uso veterinário regulado.
- **Escopo:** ampliar antes do piloto da secretária mantém tudo em `NO_GO`. Recomendação: piloto da secretária primeiro, Discovery do cvg-claw em paralelo.
- **Integração:** o HIS é próprio, então não há dependência de fornecedor; o risco passa a ser acoplamento entre os dois repositórios. Mitigar com contrato versionado (OpenAPI + eventos) e testes de contrato. O `cvg-his-v4` está em HEAD destacado (`fdc591ae`); a integração deve mirar um release identificado do HIS.
- **Governança:** o processo atual (recibos vinculados a hash e crítica independente em toda mudança) não escala para o escopo hospitalar; propor rigor por nível de risco.
- **Responsabilidade:** cada tipo de ação autônoma precisa de um dono humano nomeado.

## Perguntas abertas (bloqueiam `DISCOVERY_READY`)

Respondidas na v2: setor piloto (faturamento), sistema de gestão (`cvg-his-v4`), identidade (login do ERP).

1. Qual o hospital veterinário (nome/unidades) e quem são os faturistas participantes do piloto?
2. "Convênio" no hospital inclui planos de saúde pet com autorização prévia ou glosa, ou é só forma de pagamento como no HIS hoje?
3. Quem é o dono de produto, o DPO e o responsável técnico do cvg-claw?
4. Qual o volume mensal e a linha de base: atendimentos encerrados, contas com itens faltando, recebíveis vencidos, tempo de fechamento de conta?
5. A prioridade entre F01–F04 está correta (F01 e F03 primeiro)?
6. Aceita a proposta de identidade (HIS emite o token do operador; cvg-claw usa API key de serviço no HIS)?

## Próximo passo

Responder às perguntas abertas, validar F01–F04 com o faturamento e registrar a validação em `0090_discovery_validation.md`. Só então abrir o PRD do piloto de faturamento. Mudanças no `cvg-his-v4` (emissão do token) seguem o processo daquele repositório.
