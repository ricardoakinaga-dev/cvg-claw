# 0348 — Roadmap e ExecPlan AUD06

Objetivo integral: criar roadmap/backlog e implementar o plano de melhoria da
auditoria 0576, cobrindo F01–F08 até sua verificação, sem substituir gates reais
por resultados sintéticos. [Backlog](0349_aud06_backlog.md) é a fonte dos estados;
[SPEC](../02_spec/aud06_remediation_20261006.md) é o contrato de implementação.

## Contexto e baseline

Base Git 1a66436, com relatório 0576 e masters documentais não commitados. Esses
arquivos pertencem à auditoria anterior e serão preservados. Node 22.23.2;
baseline Vitest 2.682 PASS/194 skips; Browser CI 9 FAIL/66 PASS; source-map-js
1.2.1 vulnerável; selo stale devido a documentação, não falha de código provada.
O antigo Gauntlet IMP50 permanece histórico; este programa tem identidade AUD06.

## Marcos e demonstrações

| Marco                           | Tarefas | Resultado observável                                                                      | Dependência        |
| ------------------------------- | ------- | ----------------------------------------------------------------------------------------- | ------------------ |
| M0 — Contratos                  | 01      | Roadmap, backlog, SPEC e barra publicados                                                 | Auditoria          |
| M1 — Barreiras e confiabilidade | 02–06   | Audit limpo, N3 DENY, E2E reproduzível, runner correto, retenção vigente                  | M0                 |
| M2 — Manutenção e operação      | 07–10   | Estado reconciliado, fronteira extraída, stack/observação/restore demonstrados localmente | M1 para integração |
| M3 — Produto e integração       | 11      | Discovery validada, contratos HIS e integração testada                                    | Decisões de 0026   |
| M4 — Qualificação               | 12–14   | Regressão, críticas, selo/CI e oito gates externos válidos                                | Marcos anteriores  |

## Execução e ownership

Lead cria contratos, atualiza dependências, integra mudanças e mantém estado.
Builder A: N3/policy-engine e testes de política; Builder B: CI/Playwright e
artefatos visuais próprios; Builder C: retenção e runner em arquivos separados.
Após esses retornos, atribuir refatoração e infraestrutura em lanes exclusivas.
Não rodar duas suítes que compartilhem coverage/, portas ou banco.

## Verificação

Usar executáveis de Node 22.23.2. Gates: npm run typecheck, npm run lint,
npm run format:check, npm run docs:check, npm run build, npm test,
npm run test:coverage, npm run test:postgres em banco descartável,
Browser E2E em Playwright pinado e npm audit. Testes focados precedem regressão.
Após integrar, crítico fresh-context diferente dos builders, sem escrita;
comparar hashes e exigir evidência direta por Q01–Q14.

## Progresso e decisões

2026-10-06: solicitação executiva recebida; auditoria anterior conferida e
preservada. Correções locais admitidas; decisões de piloto e signoff não
fabricadas. Nenhum deployment real é consequência do pedido de implementação.

## Riscos

Baseline de imagens varia com SO/fontes; alinhar ambiente antes de mudar imagens.
N3 é correção restritiva e requer ajustar testes que contradizem AGENTS, mantendo
negativos anteriores de outras capabilities. Estado/selo vinculam documentação;
finalizar documentos antes de re-selar. Infraestrutura existente não deve ser
interrompida; recursos de testes têm nomes e dados próprios.

## Concrete Steps

1. AUD06-02: atualizar a dependência vulnerável e registrar audit/build atuais.
2. Executar lanes 03–06 e integrar após crítica.
3. Reconciliar estado e executar 08–10, preservando a dependência humana de 11.
4. Qualificar 12–14 somente com evidência correspondente; manter todo item
   pendente no backlog até seu aceite, mesmo se a rodada local terminar.

## Recuperação

Ler AGENTS, CURRENT, backlog 0349, esta SPEC e os últimos recibos AUD06; conferir
git diff e handles vivos. Não repetir comandos com efeito cuja conclusão seja
desconhecida. Retomar a próxima ação do estado corrente, não históricos IMP50.
Status global só pode ser COMPLETED após todos Q01–Q14 satisfeitos.

## Atualização 2026-10-07

Piloto AUD06-11 adiado explicitamente pelo usuário; F01/F03 mantidos, identidade
HIS em avaliação. Manutenção técnica continua. Crítica I1 levou a rework limitado
de cleanup/quota e atualização da evidência do worker. Próxima dependência:
regressão integrada e nova crítica; Q11/Q13/Q14 sem aceite global.
