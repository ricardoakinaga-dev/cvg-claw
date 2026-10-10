# 0576 — Auditoria do repositório cvg-claw — 2026-10-06

- Task: `AUD-20261006-CLAW`.
- Solicitação: ler a documentação, auditar o repositório e atribuir notas de 0 a 100 a cada item avaliado.
- Referência avaliada: commit `1a66436ffed42b656aa980bd64ac6bed45548ba4`, inicialmente sem alterações locais rastreadas.
- Ambiente das verificações: Node `22.23.2`; o shell tinha Node `24.20.0` como padrão, substituído explicitamente nos comandos de validação.
- Escopo autorizado: inspeção, verificações sintéticas e documentação. Esta rodada não admite BUILD de produto nem altera os limites de autonomia.
- Evidências: [diretório da rodada](evidence/AUD-20261006-CLAW/README.md) e [recibo de execução](evidence/AUD-20261006-CLAW/verification-receipt.md).

## Parecer executivo

**Nota geral ponderada: 61,11/100, apresentada como 61/100.** O repositório tem uma base técnica relevante para desenvolvimento controlado: testes extensos, separação entre runtime e políticas, controles de identidade, persistência e verificação de certificação. A maturidade do agente hospitalar efetivamente conectado é inferior à maturidade dessa base.

**Produção e piloto com efeitos reais permanecem NO_GO.** Há oito requisitos externos/humanos pendentes no verificador, uma vulnerabilidade alta na cadeia de desenvolvimento/build, CI visual reprovado e uma diferença entre a regra institucional N3 e a decisão padrão do motor genérico de políticas. A média não supera esses bloqueios e não representa percentual de segurança ou probabilidade de sucesso em produção.

O selo do commit de referência passou na verificação de integridade desta rodada. Isso não significa que uma nova execução de todos os gates passaria hoje: o `npm audit` atual falha e o último `Verify` desse mesmo commit falhou em Browser E2E. Além disso, a gravação deste relatório e dos registros obrigatórios altera arquivos incluídos no hash do candidato. A qualificação do commit de referência deve permanecer distinguida da qualificação do worktree documental resultante; não foi executado novo selo nesta auditoria.

## Método e limites de evidência

Foram lidos os quatro documentos obrigatórios de governança, índices e documentos de Discovery/PRD/SPEC, a auditoria anterior, backlog em ondas e recibos posteriores da Onda 1. A inspeção de implementação concentrou-se em API, identidade, cliente web, composição do worker, políticas/capabilities, retenção, telemetria, Docker/Nginx e workflows. É uma auditoria por áreas e amostragem orientada a risco, não uma revisão linha a linha de todos os arquivos.

Os resultados locais foram obtidos com dados sintéticos e variáveis de integrações reais desativadas. A suíte padrão com cobertura foi executada. PostgreSQL dedicado, navegadores, restauração, provider real, canal real e identidade institucional não foram reexecutados localmente nesta rodada. Para CI, foram consultados os resultados efetivos de 2026-10-05 vinculados ao commit auditado. Esta rodada foi realizada por um auditor; o parecer independente da certificação anterior não equivale a uma segunda revisão independente deste relatório.

As notas usam as mesmas 13 dimensões e pesos da [auditoria 0575](0575_repository_audit_2026-10-05.md), mas são reavaliadas com as evidências atuais. Escala: 0–19, ausência de operação demonstrada; 20–39, definição ou implementação parcial; 40–59, lacunas relevantes; 60–79, implementação local útil com ressalvas; 80–89, evidência técnica forte com limites; 90–100, atendimento robusto ao escopo avaliado. Os pesos totalizam 100; a fórmula é `soma(nota × peso) / 100`.

## Notas por item

| Item avaliado                          |    Peso | Nota / 100 | Fundamentação                                                                                                                                                       |
| -------------------------------------- | ------: | ---------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Governança e processo                  |       8 |         72 | Gates, tarefas e decisões rastreáveis; o estado operacional depende de reconciliar documentos congelados com recibos posteriores.                                   |
| Documentação e rastreabilidade         |       7 |         60 | Verificação de links e JSON passa; índices ainda descrevem como futuras etapas já concluídas, e os três masters somavam 16.613 linhas.                              |
| Definição do produto e requisitos      |       9 |         32 | Discovery 0026 identifica o agente hospitalar e o piloto, mas permanece DRAFT com seis perguntas abertas e novas PRD/SPEC pendentes.                                |
| Arquitetura e qualidade do código      |      11 |         77 | API, worker e pacotes especializados; runtime, journal e políticas têm fronteiras explícitas. Arquivos centrais grandes aumentam o custo de mudança.                |
| Testes e qualidade verificável         |      11 |         84 | 2.682 testes locais aprovados e cobertura alta no conjunto instrumentado; 194 ignorados e nove falhas visuais no CI impedem aprovação integral.                     |
| Segurança da aplicação                 |      11 |         76 | Identidade confiável, controle de replay, validação de tenant e permissões; integração institucional de identidade ainda não qualificada.                           |
| Autonomia e barreiras de segurança     |      10 |         55 | Worker controlado limita efeitos, mas o motor genérico exige aprovação para cinco operações que precisam de proibição N3; modelo N0–N3 ainda não consolidado.       |
| CI/CD e cadeia de dependências         |       7 |         56 | Pipeline amplo, ações fixadas e runtime pinado; último Verify falhou e auditoria atual detecta dependência de build com severidade alta.                            |
| Certificação e gates de liberação      |       5 |         80 | Integridade do selo de referência PASS e recusa de produção correta; oito qualificações externas/humanas seguem pendentes.                                          |
| Infraestrutura e implantação           |       7 |         32 | Docker com usuário sem privilégios e proxy entregues; falta demonstrar implantação hospitalar reproduzível, TLS, limitação compartilhada e recuperação operacional. |
| Integrações reais                      |       6 |         18 | Contratos e adaptadores existem, mas o worker controlado usa provider determinístico e efeitos sintéticos; HIS, canal, identidade e RAG não qualificados.           |
| Observabilidade e operação             |       3 |         62 | Correlação, auditoria e adaptador OpenTelemetry implementados; composição padrão em memória e coleta/alertas operacionais não demonstrados.                         |
| Dados, retenção e conformidade técnica |       5 |         72 | Controles de tenant, persistência e retenção definidos; renovação sintética aprovada ainda não implementada e requisitos institucionais reais pendentes.            |
| **Total ponderado**                    | **100** |  **61,11** | **61/100 após arredondamento.**                                                                                                                                     |

A certificação melhorou em relação à auditoria anterior. A nova verificação também trouxe evidência adversa de dependências e tornou mais precisa a lacuna N3. Por isso, a evolução da nota total é pequena; ela não foi inferida apenas da quantidade de testes aprovados.

## Verificações executadas

| Verificação                        | Resultado observado                                                | Alcance                                                                                            |
| ---------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| TypeScript, ESLint e build         | PASS                                                               | Comandos locais com Node 22.23.2.                                                                  |
| Prettier                           | PASS no baseline                                                   | Verificação local, sem correção de produto.                                                        |
| Documentação                       | PASS no baseline                                                   | 2.218 links, nenhum quebrado; 654 JSON, nenhum inválido.                                           |
| Vitest com cobertura               | PASS                                                               | 307 arquivos aprovados e 12 ignorados; 2.682 testes aprovados, 194 ignorados, nenhuma falha.       |
| Cobertura V8                       | 93,02% statements; 90,19% branches; 91,23% functions; 93,49% lines | Valores do conjunto instrumentado pela configuração atual.                                         |
| `npm audit --json`                 | FAIL, uma vulnerabilidade alta                                     | Dependência transitiva de desenvolvimento/build.                                                   |
| `npm audit --omit=dev --json`      | PASS, zero vulnerabilidades reportadas                             | Árvore sem dependências de desenvolvimento; não é prova de ausência universal de vulnerabilidades. |
| `phase11-verify.mjs`               | PASS antes dos registros documentais                               | Integridade do candidato certificado e dos artefatos, sem falhas.                                  |
| Promoção para PRODUCTION           | Recusada, expectativa EXTERNAL_ONLY satisfeita                     | Oito requisitos externos/humanos pendentes no baseline.                                            |
| Sondagem sintética do PolicyEngine | Cinco decisões REQUIRE_APPROVAL                                    | Avaliação em memória; nenhum executor ou efeito acionado.                                          |
| CI Verify do commit auditado       | FAIL                                                               | Browser E2E: nove falhas, 66 aprovados; etapas anteriores passaram.                                |
| CI Security do commit auditado     | SUCCESS em 2026-10-05                                              | Resultado histórico consultado nesta rodada; não substitui o audit de dependências executado hoje. |

As exclusões em [vitest.config.mts](../../vitest.config.mts) incluem o frontend e partes cobertas por gates dedicados. Portanto, 93,49% de linhas não é cobertura de todo o produto. Os 194 testes ignorados não foram contados como aprovados. O comando agregador `npm run verify` não foi reexecutado integralmente: seus componentes foram verificados individualmente e o componente de auditoria de dependências falhou.

## Achados e prioridades

### F01 — P1: vulnerabilidade alta na cadeia de desenvolvimento/build

O `source-map-js` instalado é `1.2.1`; o [recibo atual do npm](evidence/AUD-20261006-CLAW/npm-audit.json) reporta `GHSA-68fv-2mgg-jv7q`, negação de serviço por processamento de offsets de source maps, com correção disponível fora da faixa vulnerável anterior a `1.2.2`. A árvore observada o inclui por Vite/PostCSS, jsdom/css-tree e ferramentas de cobertura.

O [audit sem devDependencies](evidence/AUD-20261006-CLAW/npm-audit-production.json) retorna zero. Não foi demonstrada exposição da API implantada a essa falha. O impacto comprovado é a reprovação do gate de segurança completo e a necessidade de atualizar a dependência de build de forma verificada.

**Encaminhamento:** admitir atualização do lockfile para versão corrigida compatível, verificar instalação reproduzível e executar novamente auditoria, build e testes afetados. Aceite: zero alertas high/critical nesse gate, sem regressão, seguido da qualificação do candidato alterado. Nenhuma atualização automática foi aplicada nesta auditoria.

### F02 — P1: regra N3 não é uma negação global no motor genérico

O AGENTS raiz estabelece N3 sempre bloqueado. Em [grants.ts](../../packages/policy-engine/src/grants.ts) e [engine.ts](../../packages/policy-engine/src/engine.ts), os perfis clínico e financeiro têm operações sensíveis modeladas como dependentes de aprovação. Uma sondagem com tenant/operador sintéticos, papel Admin e documento padrão retornou `REQUIRE_APPROVAL` para `finance.write`, `clinical.diagnose`, `clinical.prescribe`, `patient.record.write` e `exam.release`.

Isso demonstra uma diferença de decisão, não a execução dessas operações. A composição controlada do worker restringe seus efeitos a duas capabilities sintéticas; a auditoria não demonstrou bypass operacional nem execução clínica/financeira após aprovação. Entretanto, reutilizar o motor genérico em novos perfis sem um deny obrigatório deixaria a regra institucional dependente da composição externa.

**Encaminhamento:** em PRD/SPEC admitidas, formalizar N0–N3 e a classificação de ações, distinguir rascunho de escrita definitiva e fazer N3 retornar DENY antes de qualquer aprovação. Aceite: negativos demonstram que perfil, papel, documento e aprovação não transformam N3 em operação executável. A enumeração atual em [enums.ts](../../packages/shared/src/enums.ts) ainda usa `level_1_collect` e `level_2_suggest`.

### F03 — P1: CI visual reprovado no commit efetivamente auditado

O run `37376612377`, HEAD `1a66436ffed42b656aa980bd64ac6bed45548ba4`, passou em Verify, cobertura crítica, integridade, gate de promoção, smokes, evals, chaos, licenças, SBOM e PostgreSQL, mas falhou em Browser E2E. O [recibo do job](evidence/AUD-20261006-CLAW/ci-verify.json) e o [trecho bruto do navegador](evidence/AUD-20261006-CLAW/ci-browser-excerpt.log) confirmam **nove falhas e 66 testes aprovados**.

São os três cenários de [visual-shell.spec.ts](../../tests/e2e/visual-shell.spec.ts), repetidos em Chromium, Firefox e WebKit: shell, dead-letter e matriz de orquestração. Um exemplo registra imagem esperada de 351 × 4.006 pixels e recebida de 351 × 4.125, com diferença de 0,08 e reprovação em `toHaveScreenshot` na linha 474. O log confirma diferença visual, mas não basta para decidir entre regressão do produto e divergência de ambiente/fontes/baseline.

**Encaminhamento:** reproduzir no ambiente de paridade, inspecionar imagem esperada/recebida/diff e corrigir a causa. Atualizar snapshots somente após revisão de que o resultado é o desejado. Aceite: os três cenários passam nos três navegadores no CI do novo commit. Não se recomenda simplesmente aumentar tolerância para obter verde.

### F04 — P1 antes de piloto: produto e integrações operacionais incompletos

A [Discovery 0026](../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md) permanece DRAFT. O [backlog 0347](../03_build/0347_claw_waves_backlog_20261005.md) já prevê requisitos de cobrança, autonomia e identidade HIS; sua existência não equivale a aceite de produto ou integração funcional.

Em [kernel-composition.ts](../../apps/worker/src/kernel-composition.ts), `createControlledModelGateway` utiliza provider determinístico, a telemetria padrão é em memória e o executor controlado devolve resultado sintético. Há implementações de providers no pacote model-gateway, mas presença de adaptadores e testes locais não prova uso por um agente hospitalar conectado.

O [cliente web](../../apps/web/src/api/client.ts) envia cabeçalhos de operador/tenant. O modo de identidade confiável da API exige `x-cvg-operator-token`, com controles em [operator-identity.ts](../../apps/api/src/operator-identity.ts). O código de assinatura/verificação existe; a emissão institucional pelo HIS e seu uso ponta a ponta no cliente não foram qualificados. Não se trata de afirmar ausência de criptografia ou bypass de autenticação.

**Encaminhamento:** responder às seis questões, aprovar os contratos de cobrança somente N0/N1 inicialmente, conectar identidade institucional em sandbox e qualificar separadamente provider, canal e RAG aprovado. Aceite: fluxo de ponta a ponta com identidade, tenant, fonte aprovada, aprovação/handoff e trilha verificáveis, sem promoção automática de autonomia.

### F05 — P2: estado congelado e decisão de retenção precisam de reconciliação

CURRENT, runtime, backlog e `current_state.json` ainda pedem crítica, selo, push e decisão de renovação. Os recibos posteriores comprovam que crítica/selo/publicação aconteceram e que a renovação sintética já foi aprovada. O congelamento foi intencional para preservar o hash do candidato; a divergência operacional é real, porém tem causa documentada.

O [recibo de renovação](evidence/CLAW-W1/CLAW-W1-07-tombstone-policy-renewal-decision-20261005.json) aprova validade até `2027-06-30T23:59:59-03:00`, mantendo retenção de 30 dias e escopo sintético. [retention.ts](../../packages/persistence/src/retention.ts) ainda implementa o limite anterior `2027-01-01T02:59:59.000Z`, equivalente a 31/12/2026 às 23:59:59 em São Paulo. A política **não está vencida em 06/10/2026**. Falta implementar a decisão já aprovada, com prazo registrado de 30/11/2026; não falta solicitar a mesma decisão novamente.

**Encaminhamento:** reconciliar o estado canônico com os recibos durante a próxima atualização controlada e executar CLAW-W1-07 com os testes de limite/aviso previstos. Aceite: índice, estado, backlog e implementação refletem o mesmo marco; nova certificação cobre os bytes alterados. O checker de consistência passar hoje não prova que todas as ações descritas ainda estão pendentes.

### F06 — P1 antes de operação externa: implantação e observabilidade não demonstradas

[Dockerfile](../../Dockerfile) utiliza runtime sem privilégios e há um [Nginx entregue](../../deploy/nginx.web.conf), porém sua configuração escuta HTTP na porta 8080. TLS pode existir em infraestrutura externa; isso não foi demonstrado nesta auditoria. Também não foram encontrados manifests de implantação hospitalar completos no conjunto inspecionado.

O [rate limiter](../../apps/api/src/rate-limit.ts) é em memória por processo: múltiplas réplicas não compartilham esse contador. O [adaptador OpenTelemetry](../../packages/observability/src/otel.ts) existe, mas a composição controlada padrão não comprova exportação, alertas e acompanhamento operacional. RPO/RTO, rollback e piloto permanecem explicitamente não qualificados no gate.

**Encaminhamento:** entregar implantação reproduzível com TLS/proxy confiável, estratégia de limite entre réplicas, coleta/alertas e ensaio de backup/restauração em ambiente descartável. Aceite: evidências próprias de instalação, falha, recuperação e observação no ambiente-alvo. A nota baixa avalia a implantação demonstrada, não uma alegação de que o hospital necessariamente esteja sem proteção externa.

### F07 — P2: wrapper de certificação não propaga o resultado final

Por inspeção, [certify-pass.sh](evidence/CLAW-reseal/certify-pass.sh) usa `set -u`, registra o código do comando Docker em texto e continua até um `echo` de teardown. Não preserva esse código para o `exit` do wrapper. Assim, o sucesso do último comando pode ocultar do chamador uma certificação que falhou. O script não foi executado nesta auditoria.

**Encaminhamento:** preservar o status da certificação, executar limpeza garantida e encerrar com o status original. Aceite: falha simulada da certificação resulta em código diferente de zero, com limpeza executada. Esse problema do wrapper não invalida por si só o selo de referência, que foi verificado diretamente nesta rodada.

### F08 — P2: concentração de código e acúmulo de histórico

No baseline, `apps/api/src/server.ts` tinha 4.570 linhas, `apps/worker/src/kernel-composition.ts` 1.949 e `apps/web/src/api/client.ts` 1.543. Runtime, execution log e backlog somavam 16.613 linhas. Tamanho não prova defeito; em conjunto com funções de composição, roteamento e cliente concentradas, aumenta o esforço de revisão e reconciliação de estado.

**Encaminhamento:** priorizar extrações pequenas nas fronteiras já definidas e separar índices correntes do histórico preservado. Aceite: contratos e comportamento mantidos, sem misturar refatoração estrutural com correções de segurança ou promoção de autonomia.

## Sequência recomendada de trabalho

1. Admitir e corrigir F01, F03 e F07 na base técnica; validar no runtime e ambiente de CI fixados.
2. Formalizar o novo escopo e a regra N3 antes de conectar capacidades hospitalares reais; executar F02/F04 pelas PRD/SPEC correspondentes.
3. Reconciliar o estado e implementar a renovação sintética já aprovada, sem reabrir a decisão humana existente.
4. Qualificar implantação, identidade, provider, canal, RAG, recuperação e piloto controlado; somente então reavaliar os gates de liberação.

O [recibo de promoção do baseline](evidence/AUD-20261006-CLAW/baseline-promotion.json) identifica os oito itens: `modelProvider`, `channel`, `externalIdentity`, `institutionalRag`, `rpoRto`, `pilot`, `rollback` e `humanSignoff`. São gates separados; a nota média não os substitui.

## Encerramento e estado após o relatório

Relatório, evidências e registros obrigatórios foram concluídos sem alterações no código de produto, lockfile, permissões ou configuração de produção. Os resultados da checagem documental final constam no [recibo de encerramento](evidence/AUD-20261006-CLAW/final-validation.json).

A verificação do worktree após o registro da auditoria retorna **FAIL por drift documental**: o novo relatório e CURRENT, runtime state, execution log e backlog master alteram o candidato. O [selo do baseline](evidence/AUD-20261006-CLAW/baseline-certification.json) continua sendo a evidência do commit auditado; a [verificação final](evidence/AUD-20261006-CLAW/final-certification.json) descreve a necessidade de recertificar a versão resultante. Não foi realizado reseal, commit, push ou deploy. Os achados são pendências de remediação, não autorização automática para novas capabilities ou liberação.

Fonte de supply chain: [advisory referenciado pelo npm](https://github.com/advisories/GHSA-68fv-2mgg-jv7q). Fonte de CI: [Verify do commit auditado](https://github.com/ricardoakinaga-dev/cvg-claw/actions/runs/37376612377) e [Security do mesmo commit](https://github.com/ricardoakinaga-dev/cvg-claw/actions/runs/37376612496). Os recibos locais distinguem resultados coletados diretamente, resumos transcritos e verificações não executadas.
