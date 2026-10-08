# Recibo de verificação — AUD-20261006-CLAW

Data: 2026-10-06. Referência: `1a66436ffed42b656aa980bd64ac6bed45548ba4`.
Auditoria solicitada pelo usuário, com mudanças admitidas apenas em documentação
e evidências. Este recibo é uma síntese das saídas de ferramentas observadas;
somente arquivos identificados como saídas brutas preservam a saída do comando.

## Resultados locais observados antes das mudanças documentais

Todos os comandos Node utilizaram `/home/ricardo/.nvm/versions/node/v22.23.2/bin`.

| Comando | Resultado |
| --- | --- |
| `npm run typecheck` | PASS |
| `npm run lint` | PASS |
| `npm run build` | PASS |
| `npm run format:check` | PASS |
| `node scripts/docs-check.mjs` | PASS; 2.218 links e 654 JSON válidos |
| `npm run test:coverage` | Exit 0; 307 arquivos PASS, 12 ignorados; 2.682 testes PASS, 194 ignorados; zero falhas |
| `npm audit --json` | Exit 1; uma vulnerabilidade high, zero critical |
| `npm audit --omit=dev --json` | Exit 0; zero vulnerabilidades reportadas |
| `node scripts/phase11-verify.mjs` | Exit 0; PASS, failures vazio |
| `node scripts/promotion-check.mjs --requested PRODUCTION --expect=EXTERNAL_ONLY` | Exit 0; produção inelegível, oito gates externos/humanos, expectativa satisfeita |

A execução de cobertura removeu `DATABASE_URL`, `DATABASE_MIGRATION_URL`,
`TEST_DATABASE_URL`, `BASE_URL` e `NODE_OPTIONS` herdadas. Usou `NODE_ENV=test`,
`API_PERSISTENCE_MODE=memory` e `ENABLE_REAL_CHANNELS`, `ENABLE_REAL_RAG`,
`ENABLE_REAL_PAYMENTS`, `ENABLE_REAL_MEDICAL_RECORDS` como `false`.

A suíte levou 1.170,36 segundos segundo sua própria saída. O log integral não
foi salvo; os totais foram transcritos da conclusão observada. A cobertura
agregada foi copiada do JSON V8 para [coverage-total.json](coverage-total.json).
Não houve nova execução local de PostgreSQL dedicado ou Browser E2E.

## Artefatos coletados diretamente

- [baseline-certification.json](baseline-certification.json): saída bruta do verificador, com os documentos de produto ainda no baseline.
- [baseline-promotion.json](baseline-promotion.json): saída bruta do gate de promoção nas mesmas condições.
- [npm-audit.json](npm-audit.json) e [npm-audit-production.json](npm-audit-production.json): saídas brutas do audit na coleta de evidências.
- [ci-verify.json](ci-verify.json): saída de `gh run view 37376612377 --repo ricardoakinaga-dev/cvg-claw --json conclusion,headSha,jobs,url`.
- [ci-browser-excerpt.log](ci-browser-excerpt.log): últimas 120 linhas da seção Browser E2E obtida pela API de logs do job `111987497992`; preserva timestamps e caracteres ANSI.

As gravações sob `docs/04_audit/evidence/` são excluídas do hash do candidato
pelas regras existentes; a coleta desses recibos não alterou o baseline.

## Sondagem de políticas — resultado transcrito

Foi executada avaliação direta de `PolicyEngine` com relógio fixo em
`2026-10-06T00:00:00Z`, tenant/operador/agente sintéticos, papel `Admin`,
documento padrão e recurso sintético do mesmo tenant. Nenhum executor foi
invocado. As saídas observadas foram:

| Capability | Perfil | Decisão |
| --- | --- | --- |
| `finance.write` | `financial` | `REQUIRE_APPROVAL` |
| `clinical.diagnose` | `clinical` | `REQUIRE_APPROVAL` |
| `clinical.prescribe` | `clinical` | `REQUIRE_APPROVAL` |
| `patient.record.write` | `clinical` | `REQUIRE_APPROVAL` |
| `exam.release` | `clinical` | `REQUIRE_APPROVAL` |

Esta tabela é a transcrição do resultado da avaliação concluída, não um arquivo
bruto de execução nem prova de efeito real. Uma tentativa posterior de repetir
a sondagem em uma chamada agrupada para salvá-la foi bloqueada pela verificação
automática da plataforma; essa repetição não foi executada.

## CI e resolução de divergência de fonte

A consulta direta pelo `gh` do ambiente confirmou:

- Verify `37376612377`: HEAD `1a66436ffed42b656aa980bd64ac6bed45548ba4`, FAIL em Browser E2E, nove falhas visuais e 66 aprovados.
- Security `37376612496`: mesmo HEAD, SUCCESS.
- Runs `37376536727` e `37376536752`, do commit `58f8f5f1fc4b219be36c1b70539e42d61ca1a7d0`: CANCELLED.

Uma consulta anterior por conector retornou detalhes incompatíveis com o
workflow do commit e citou `tests/e2e/demo.spec.ts`, arquivo ausente tanto no
checkout quanto no escopo de testes verificado. Esses detalhes foram
descartados. O relatório usa os metadados e logs obtidos diretamente por `gh`,
conferidos com `.github/workflows/verify.yml` e com os caminhos reais.

## Validação documental final

Os resultados finais estão em [final-validation.json](final-validation.json),
com a [checagem documental](final-docs-check.json) e a
[verificação do candidato resultante](final-certification.json).

A verificação de certificação após os registros retorna FAIL por drift do
candidato. O escopo observado contém somente o novo relatório 0576 e as
mudanças em CURRENT, runtime state, execution log e backlog master. Os
artefatos de certificação, o código de produto e o lockfile foram preservados;
não houve reseal para ocultar esse drift. A nota refere-se ao commit de
referência, cuja verificação está preservada em baseline-certification.json.

A primeira coleta documental final abriu o próprio arquivo JSON de resultado
antes da varredura, levando o checker a encontrá-lo temporariamente vazio. Isso
foi um erro de coleta desta auditoria. A coleta final executa o checker primeiro
e grava sua saída após o término; o resultado final é registrado separadamente
daquela tentativa. Não foi necessário alterar o checker de produto.

Status da rodada documental: `COMPLETED`. Os achados de produto e os gates de
liberação continuam pendentes conforme o relatório e o backlog.
