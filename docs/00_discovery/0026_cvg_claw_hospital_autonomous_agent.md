# Discovery proposta CLAW-01 — cvg-claw, agente autônomo governado do hospital

## Registro

- ID: DISCOVERY-CLAW-01
- Versão: 1
- Responsável pela proposta: executor local; dono de produto do cvg-claw a designar
- Atualização: 2026-10-04
- Origem: decisão do usuário de evoluir a `cvg-agent-secretary-v2` (Esmeralda V2) para o `cvg-claw`, com repositório GitHub dedicado
- Tier proposto: T1_PROGRAM; risco operacional HIGH (dados sensíveis de saúde, LGPD art. 11)

## Estado

- task proposta: CLAW-01
- fase: DISCOVERY
- disposição local: DRAFT; nenhum gate `DISCOVERY_READY` registrado
- execução permitida nesta etapa: leitura e documentação local
- PRD, SPEC e BUILD do novo escopo: não admitidos
- dados reais, integração externa, staging e produção: NO_GO
- relação com o programa corrente: AUD20 e o piloto da secretária continuam; esta Discovery não reabre nem substitui tasks AUD20

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

| ID     | Caso                                       | Setor                     | Nível inicial       | Sistemas envolvidos                                         |
| ------ | ------------------------------------------ | ------------------------- | ------------------- | ----------------------------------------------------------- |
| UC-C01 | Preparar autorização/guia de convênio      | Faturamento/autorização   | N1                  | Sistema de gestão hospitalar, portais de operadoras         |
| UC-C02 | Triar e preparar resposta a glosas         | Faturamento               | N1                  | Sistema de gestão hospitalar, demonstrativos das operadoras |
| UC-C03 | Acompanhar pendências da alta              | Enfermagem/administrativo | N0                  | Sistema de gestão hospitalar/prontuário (leitura)           |
| UC-C04 | Painel e alertas de leitos                 | Regulação/NIR             | N0                  | Sistema de gestão hospitalar                                |
| UC-C05 | Abrir e encaminhar chamados internos       | TI/manutenção/hotelaria   | N2 (após piloto N1) | Ferramenta de chamados                                      |
| UC-C06 | Agendamento interno e lembretes às equipes | Administrativo            | N1                  | Agenda corporativa, canal interno                           |
| UC-C07 | Secretária do paciente (Esmeralda)         | Recepção/central          | N1 (escopo atual)   | Canal WhatsApp, agenda                                      |

## O que a base atual já cobre

- Orquestrador com objetivo → plano → etapas, limite de iterações e controle de replanejamento (migrações 0019–0023).
- `policy-engine` que nega por padrão, com capabilities e grants.
- `approval-engine` com aprovações persistentes; outbox, effect journal e idempotência.
- Handoff e human takeover (INV-014); multi-tenant com RLS; trilha de auditoria e tracing.
- ADRs de plataforma: control plane/data plane, versões imutáveis de agente, secrets por referência, capability gateway ([docs/platform/adr](../platform/adr)).
- Preset de agente (`packages/platform/src/secretary-preset.ts`), modelo para um preset hospitalar.

## Lacunas conhecidas

1. Provider de LLM real não composto no worker (hoje `deterministic-v1`); sem ele não há planejamento autônomo.
2. Ferramentas tipadas para o sistema de gestão hospitalar/prontuário (HL7/FHIR ou API do fornecedor), portais de operadoras e ferramenta de chamados.
3. Identidade corporativa (SSO/OIDC) e mapeamento de cargos do hospital para papéis e capabilities.
4. Catálogo de capabilities hospitalar com dono por capability.
5. Observabilidade de produção da API e botão de parada global operado pelo hospital.

## Riscos

- **Regulatório:** LGPD (dado sensível de saúde: base legal, DPO, RIPD). Função clínica pode enquadrar o software como dispositivo médico (ANVISA, RDC 657/2022); o escopo proposto evita função clínica.
- **Escopo:** ampliar antes do piloto da secretária mantém tudo em `NO_GO`. Recomendação: piloto da secretária primeiro, Discovery do cvg-claw em paralelo.
- **Integração:** acesso ao sistema de gestão hospitalar depende de fornecedor, TI e contrato.
- **Governança:** o processo atual (recibos vinculados a hash e crítica independente em toda mudança) não escala para o escopo hospitalar; propor rigor por nível de risco.
- **Responsabilidade:** cada tipo de ação autônoma precisa de um dono humano nomeado.

## Perguntas abertas (bloqueiam `DISCOVERY_READY`)

1. Qual o hospital/rede e qual o setor do primeiro piloto?
2. Qual o sistema de gestão hospitalar (Tasy, MV, Soul, outro) e que tipo de acesso existe (FHIR, HL7, API, banco de leitura)?
3. Quais operadoras/convênios concentram o volume?
4. Qual o IdP corporativo (AD, Entra ID, outro)?
5. Quem é o dono de produto, o DPO e o responsável técnico do cvg-claw?
6. Qual o volume atual e a linha de base das tarefas candidatas?
7. Quais casos de uso o hospital considera prioritários?

## Próximo passo

Responder às perguntas abertas, validar a tabela de casos de uso com o setor piloto e registrar a validação em `0090_discovery_validation.md`. Só então abrir o PRD do cvg-claw.
