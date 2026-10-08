# 0577 — Reauditoria AUD06 após remediação local — 2026-10-07

**Aceite técnico local; resultado global FAIL / NO_GO.** Referência técnica: candidato
`380ccc525d3c8313463bf8a845f634fb34757d8c85682b6ee7601a59a4a4495d`,
1.252 arquivos admitidos, sobre HEAD `1a66436ffed42b656aa980bd64ac6bed45548ba4`.
Não houve commit, publicação ou liberação do candidato principal.

Nota geral ponderada: **74,27/100**, comparada a **61,11/100** na auditoria 0576.
As notas são julgamento do lead sobre a prontidão evidenciada. A média usa as
mesmas 13 dimensões e pesos, totalizando 100; não equivale a probabilidade de
sucesso ou percentual de segurança. Q11, Q13 e Q14 continuam não satisfeitos.
A crítica independente final aprovou Q01–Q10 e Q12; produção permanece NO_GO.

| Item avaliado                          |    Peso |     Antes | Nota / 100 | Fundamentação                                                                                                      |
| -------------------------------------- | ------: | --------: | ---------: | ------------------------------------------------------------------------------------------------------------------ |
| Governança e processo                  |       8 |        72 |         85 | Roadmap, SPEC, matriz e índice corrente rastreáveis; aceite técnico local registrado; gates humanos pendentes.     |
| Documentação e rastreabilidade         |       7 |        60 |         80 | Checker verifica todas as tarefas AUD06; histórico preservado e masters ainda extensos.                            |
| Definição do produto e requisitos      |       9 |        32 |         32 | Prioridade F01/F03 registrada; definições do piloto adiadas pelo usuário.                                          |
| Arquitetura e qualidade do código      |      11 |        77 |         82 | Health e contratos web extraídos; cliente reduzido a 1.015 linhas e JavaScript preservado; hotspots remanescentes. |
| Testes e qualidade verificável         |      11 |        84 |         92 | Regressão 3.066/3.066, PostgreSQL 369/369 e browsers 75/75; crítica técnica independente válida.                   |
| Segurança da aplicação                 |      11 |        76 |         84 | Dependência corrigida, quota compartilhada e falha 503; identidade institucional não qualificada.                  |
| Autonomia e barreiras de segurança     |      10 |        55 |         96 | Cinco operações N3 são DENY irredutível; negativos e barreira de executor demonstrados sem efeitos reais.          |
| CI/CD e cadeia de dependências         |       7 |        56 |         80 | Node e imagem Playwright pinados, tolerâncias mantidas, audit local sem vulnerabilidades; CI remoto atual ausente. |
| Certificação e gates de liberação      |       5 |        80 |         55 | Selo histórico íntegro, mas não vinculado ao candidato modificado; nova certificação não executada.                |
| Infraestrutura e implantação           |       7 |        32 |         72 | Stack sintética real com TLS, migração, isolamento e teardown; ambiente hospitalar não qualificado.                |
| Integrações reais                      |       6 |        18 |         18 | Contratos HIS inspecionados, sem emissão institucional ou fluxo autorizado ponta a ponta.                          |
| Observabilidade e operação             |       3 |        62 |         78 | Exportação sanitizada, reinício e drain observados; alertas e operação institucional não qualificados.             |
| Dados, retenção e conformidade técnica |       5 |        72 |         84 | Renovação aprovada implementada e restore íntegro; requisitos institucionais pendentes.                            |
| **Total ponderado**                    | **100** | **61,11** |  **74,27** | **74/100 após arredondamento.**                                                                                    |

## Evidência técnica atual

- `verify-9`: exit 0; format, docs, typecheck, lint, build, testes, cobertura e
  audit. Tanto unit quanto coverage: 332 arquivos, 3.066 testes PASS, sem skips.
- Cobertura: statements 97,16%; branches 94,38%; functions 96,81%; lines 97,77%.
  Todos os pisos globais e todos os módulos críticos de branches ≥95% passaram.
  Trata-se do conjunto instrumentado, não de todo o produto.
- PostgreSQL dedicado: 32 arquivos, 369 testes PASS, sem skips, exit 0.
  Banco próprio descartável removido pelo ID imutável, ausência confirmada.
- Browsers: 75 PASS em Chromium, Firefox e WebKit, imagem e Node pinados,
  baselines/tolerâncias preservadas. Captura WebKit inspecionada pelo lead.
- Stack `cvg-aud06-stack-1791422392227-f517287933`: exit 0; 31 migrations
  repetidas sem mudança, 300 aceitos + 2 limitados entre réplicas, storage 503 e
  recuperação, reinício/drain do worker, 42 logs + 26 métricas sanitizados,
  restauração de 44 tabelas e 41 registros. Teardown sem erros; recursos próprios
  ausentes. 370 fontes atuais e hashes de 110 comandos vinculados.
- N3: crítica independente e sondagens negativas preservadas. Não houve nova
  capability, aumento de autonomia ou executor clínico/financeiro.

## Falhas preservadas e validade

A revisão final anterior foi INVALID porque o crítico executou teste usando
cache compartilhado e escreveu em `node_modules` do repositório principal.
O seu achado de divergência entre backlog e matriz foi corrigido: todas as
tarefas AUD06 agora são comparadas, com RED 6 FAIL/7 PASS e GREEN 25/25.
A regressão completa acima cobre essa correção. A nova revisão fresh-context em clone independente aprovou o escopo técnico:
1.252 fontes intactas e 24.147 arquivos intactos no sentinel final. O parecer
anterior continua inválido e não concede aceite.

As primeiras verificações interrompidas ou reprovadas, tentativas inválidas de
harness e problemas de preparação da cópia permanecem nas evidências. Uma
comparação posterior usou algoritmos de hash diferentes e reportou falso drift;
o recibo de correção demonstra igualdade de todos os arquivos. O campo antigo
`treeHash` dos recibos de fonte contém `computeCandidateId` (`aaa-candidate-v1`),
distinto do hash de árvore comportamental. Não houve mudança de fonte.

## Limites e próximo passo

A avaliação HIS indica que as rotas F01/F03 exigem Bearer, sessão e ACL; API key
isolada não satisfaz esse contrato. O emissor institucional do token curto não
foi localizado no escopo inspecionado. Escritas em `/billing/items` e
`/billing/estimate` são efeitos financeiros sujeitos a N3. A nota de prontidão
do desenho de identidade é 55/100, registrada separadamente. Não foi admitido
BUILD dessa integração, nem reaberta a coleta de dados do piloto.

Provider, canal, identidade externa, RAG institucional, RPO/RTO, piloto,
rollback e signoff humano continuam não qualificados. A restauração sintética
não substitui objetivos institucionais de recuperação. A exportação local não
prova operação de collector externo ou alertas.

Próximo passo: preparar nova certificação local sobre documentação estável.
O aceite técnico local está registrado; a publicação e os gates reais permanecem
sem nova autorização inferida.
CI remoto do mesmo SHA e os gates externos continuam pendentes. O resultado
global contra Q01–Q14 permanece sem PASS.

## Rastreabilidade e validade após o registro

A avaliação é por áreas e amostragem orientada a risco, com leitura dos gates e
artefatos reais. As notas são do lead; o crítico independente I1 Descartes decidiu
os critérios técnicos contra a barra v4, sem receber o rascunho ou suas notas.
A comparação PRE/POST da cópia inteira e a conferência posterior do lead passaram.
Não houve efeito real ou integração externa nesta rodada.

A gravação deste relatório e do aceite no estado/backlog altera o hash documental
do candidato. As verificações de runtime acima continuam vinculadas aos bytes
380ccc52...; a versão documental resultante exige novo binding e qualificação
para certificação. Não foi executado novo selo principal ou CI remoto.

[Barra Q01–Q14](evidence/AUD06/quality-bar.json),
[aceite local](evidence/AUD06/recovery-20261007/local-technical-acceptance.json),
[parecer independente](evidence/AUD06/recovery-20261007/final-critic-v4/final-report.txt),
[parecer estruturado](evidence/AUD06/recovery-20261007/final-critic-v4/final-report.json),
[manifesto de regressão](evidence/AUD06/recovery-20261007/technical-v4-verification-manifest.json),
[cobertura](evidence/AUD06/recovery-20261007/coverage-v4-adjudication-v2.json),
[stack atual](evidence/AUD06/stack/cvg-aud06-stack-1791422392227-f517287933/summary.json),
[avaliação de identidade](evidence/AUD06/recovery-20261007/identity-evaluation.md) e
[gates externos](evidence/AUD06/recovery-20261007/release-readiness.json).

Baseline: [0576](0576_repository_audit_2026-10-06.md).
Roadmap e pendências: [0348](../03_build/0348_aud06_roadmap.md),
[0349](../03_build/0349_aud06_backlog.md).

## Correção posterior Q05 — preparação da certificação

Após esta auditoria congelada, uma prova Docker real demonstrou volume anônimo
residual no runner canônico. A task05 foi reaberta antes da mudança, com addendum
SPEC/barra v5 sem reduzir os critérios. `docker rm -f --volumes -- ID` corrige
exclusivamente os volumes anônimos do contêiner próprio; RED2FAIL e GREEN43/43,
Docker real0/37 e named/bind preservados. Crítico fresco I1 APPROVE e aceite
local registrados. Nenhuma fonte da stack370 foi alterada; a prova continua
vinculada. A primeira certificação provisória foi interrompida143 e não é PASS.

[CriticQ05](evidence/AUD06/recovery-20261007/runner-volume-independent-critic/report.json),
[aceite](evidence/AUD06/recovery-20261007/runner-volume-local-acceptance.json),
[prova de bind](evidence/AUD06/recovery-20261007/runner-volume-bind-post-check.json) e
[binding da stack](evidence/AUD06/recovery-20261007/stack-after-wrapper-rework-binding.json).
A nota deste relatório permanece74,27/100; ainda não há selo principal nem CI
atuais aceitos. A qualificação posterior usará novo candidato e recibos próprios.
