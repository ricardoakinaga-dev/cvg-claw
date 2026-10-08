# SPEC AUD06 — remediação controlada

Versão: 1. Data: 2026-10-06. PRD: [0034](../01_prd/0034_aud06_remediation.md).
Roadmap/ExecPlan: [0348](../03_build/0348_aud06_roadmap.md).
Backlog: [0349](../03_build/0349_aud06_backlog.md).

## Admissão e fronteiras

A solicitação humana atual "crie um roadmap, um backlog e depois implemente todo
o plano de melhoria" admite implementação das correções descritas na auditoria
e preparação local sintética. Registra-se SPEC_APPROVED_CONTROLLED_BUILD para
AUD06-02..10 em manutenção da base. Não é alegação de aprovação humana separada
de um hash recém-gerado, nem sign-off de produto, piloto ou produção. A regra N3
já é mandatória em AGENTS; sua implementação restringe poderes, não os amplia.
AUD06-11..14 preservam gates próprios e evidência externa quando aplicável.

## Contratos de execução

- AUD06-02: atualizar apenas source-map-js transitivo por lockfile a partir do
  registry verificado, sem major upgrades ou npm audit fix --force. Node 22.23.2.
- AUD06-03: catálogo canônico de autonomia em policy-engine; deny irredutível das
  cinco capabilities N3 antes de grants/documentos. Grants não as oferecem.
  Negativos com todos os perfis/papéis, documento ALLOW de prioridade elevada,
  emergência e tentativa de aprovação; runtime/tool executor não pode agir.
  Preservar compatibilidade do enum legado até migração contratada, deixando
  explícito que ele não é a autoridade de execução. Não criar permissões N2.
- AUD06-04: alinhar o Browser E2E CI ao Playwright 1.59.1 noble já usado no selo.
  Manter todos os gates e Node pinado; snapshots/tolerâncias não são relaxados.
  Registrar diff visual de diagnóstico e testar Chromium/Firefox/WebKit.
- AUD06-05: runner shell canônico em scripts/, caminhos relativos, nomes únicos
  de recursos próprios, readiness com prazo, trap de limpeza, exit preservado.
  Wrapper histórico imutável; callers novos usam runner corrigido. Teste por
  executável Docker simulado com falha, sucesso, timeout e sinal, sem containers
  reais para testar caminhos de destruição; execução real só descartável própria.
- AUD06-06: aplicar receipt CLAW-W1-07 existente: validade 2027-07-01T02:59:59Z,
  referência e approvedAt exatos; preservar horizon 30, estados UNCERTAIN,
  batches/locks. Teste de expiração, aviso e PostgreSQL descartável.
- AUD06-07: CURRENT e current_state.json apontam a AUD06. Uma fonte machine-
  readable para tarefas/ação; sincronizar parser atual, não alargar seu contrato
  silenciosamente. Preservar registros antigos com qualificação histórica.
  A matriz AUD20 permanece imutável; o checker seleciona a matriz pelo programa
  em uma allowlist fechada AUD20-REM-v2/AUD06, verifica o caminho declarado e
  recusa programa desconhecido ou caminho divergente. Testar ambas as rotas e
  tentativas de selecionar arquivo fora do conjunto permitido.
- AUD06-08: extração limitada de registrador de rotas coesas de server.ts,
  injeção explícita, zero ciclos. Não misturar políticas/HTTP/auth à refatoração.
  Fronteira selecionada: health/live/ready/metrics em routes/health.ts; o
  registrador recebe probes/config e métricas, mantendo ordem dos hooks e
  envelopes. Cliente web separa contratos de tipos em api/contracts.ts,
  reexportados pelo client.ts para manter compatibilidade de consumidores.
- AUD06-09: separar infraestrutura sintética de configurações reais. Containers
  non-root/read-only quando suportado, portas somente loopback, rede dedicada,
  limites/health, migração descartável e teardown. TLS e headers devem ser
  verificáveis sem chaves reais; produção continua barrada por preflight.
- AUD06-10: limites compartilhados e exportação de telemetria exigem opções
  explícitas, deny/fail-closed em falha de storage e isolamento por tenant;
  ensaio de restauração só em recurso próprio descartável e com integridade.
  Rate limit HTTP pré-autenticação usa IP verificado pelo Fastify, nunca tenant
  fornecido em header. A opção API_RATE_LIMIT_STORE=postgres usa a conexão de
  runtime, migration aditiva 0030, chave SHA-256 e namespace fixo api-http-v1.
  Transação serializada por namespace limita cardinalidade e incrementa contador
  com relógio do banco; falha do store retorna 503 genérico sem fallback ALLOW.
  A migração cria somente metadados de quota e não muda tabelas clínicas.
  A opção é explícita em ambientes de validação; produção com múltiplas réplicas
  deve usar store compartilhado e demonstrar o gate antes de liberação.
  A composição de telemetria do ensaio usa opt-in
  CVG_TELEMETRY_MODE=local_file e
  CVG_TELEMETRY_PROFILE=CONTROLLED_LOCAL_SYNTHETIC; raiz temporária exclusiva
  CVG_TELEMETRY_ROOT, nomes constantes api.jsonl/worker.jsonl e sanitizer já
  existente. Desativado por padrão, sem rede, sem dados reais e recusado em
  produção. Exportar durante a execução e drenar no shutdown; falhas de escrita
  devem ser observáveis sem registrar payload, segredo ou caminho bruto.
  Usar o sink do worker durável e o collector injetável da API; provar a saída
  em arquivo por processo/stack real, além dos testes de ciclo de vida.
- AUD06-11: contratos do piloto HIS dependem das respostas ainda ausentes em 0026. É permitido inspecionar código/contratos locais e preparar a decisão;
  não criar falso aceite ou integração real para fechar a task.
- AUD06-12: testes, typecheck, lint, format, coverage, PostgreSQL e E2E sobre
  candidato integrado; recibos brutos, códigos de saída e limitações.
- AUD06-13: crítica fresca e certificação local; não trocar o ponteiro selado
  por pacote reprovado. Publicação/CI remoto exigem candidato e autoridade.
- AUD06-14: provider/canal/IdP/RAG/RPO-RTO/piloto/rollback/signoff reais requerem
  evidências próprias. Nunca derivar VALIDATED_REAL de uma fixture sintética.

## Coordenação e qualidade congelada

Três builders ativos no máximo, um slot reservado à crítica, profundidade um,
fork_context=false, sem override de modelo. Lead é único escritor de masters,
lockfile, roadmap, backlog, state e qualidade. Nenhum filho cria descendentes.
Escritores têm ownership exclusivo; banco, portas e resultados de testes também.
Critic não recebe racional/histórico do builder; sentinel pré/pós em seus alvos.

Q01 roadmap e backlog cobrem F01–F08 e dependências reais; Q02 audit high/critical
zero; Q03 N3 deny sem executor; Q04 Browser E2E 75/75 no ambiente pinado; Q05
runner mantém falha+cleanup; Q06 janela aprovada+fronteiras; Q07 estado consistente
e histórico preservado; Q08 extração sem regressão; Q09 stack sobe/para isolada;
Q10 rate/telemetria/restore provados; Q11 contratos e integrações do piloto
qualificados; Q12 regressão e crítica fresca; Q13 selo+CI candidate-bound; Q14
oito gates externos atendidos por fontes reais. Todos required; Q11/Q14
permanecem não satisfeitos na falta de evidência. Não há PASS global parcial.

## Rollback e recuperação

Preservar o trabalho de auditoria não commitado. Reverter apenas diffs próprios
identificados se necessário; nunca git reset/clean. Logs longos ficam no diretório
de evidências AUD06. Retry só com hipótese/evidência nova; conservar primeira
falha. Não tocar no banco real nem usar credenciais ambientais herdadas em testes.
Mudança de fonte/contrato invalida evidência anterior e exige nova verificação.

## Correção admitida por crítica I1 — 2026-10-07

Mantidos os alvos Q09/Q10 e a autoridade local sintética de AUD06-09/10.
Corrigir F-I1-01 separando tentativas de stop, logs e remoção de contêiner
positivamente identificado; preservar falhas de diagnóstico e nunca remover
recurso estrangeiro. Corrigir F-I1-02 limitando aquisição PostgreSQL com prazo
de 2 segundos, liberando conexões tardias sem consultas e sem fallback ALLOW.
Configurar também o timeout nativo do pool de runtime. Provar saturação,
rejeição tardia e liberação; repetir o stack real para o worker atual (F-I1-03).
São correções dos contratos já admitidos, sem ampliar capabilities ou piloto.

## Correção de consistência Q07 — 2026-10-07

A crítica final identificou estados diferentes entre tabela 0349 e matriz
AUD06 para tarefas não correntes. Reconciliar a tabela e validar todas as
linhas AUD06 (IDs únicos, presença exata e estado oficial idêntico), incluindo
negativos para tarefa não corrente. Leitura do backlog deve usar caminho fixo
AUD06, sem ampliar caminhos aceitos; comportamento histórico AUD20 preservado.
Este gate completa Q07 sem alterar alvo ou capability. O parecer que escreveu
cache ignorado no principal permanece INVALID; obter novo crítico fresh-context
sem symlink de dependências compartilhadas e com artefatos apenas em /tmp.

## Addendum corretivo Q05 — volume anônimo próprio — 2026-10-07

A execução local provisória e sondagem real sem iniciar banco demonstraram
que `docker rm -f` deixa o volume anônimo criado pela imagem PostgreSQL.
AUD06-05 retorna a BUILD limitado: remover os volumes anônimos associados ao
contêiner criado e identificado pelo cidfile privado, usando a operação Docker
sobre esse ID imutável. Não enumerar/prunar volumes globais, nem remover volumes
externos/nomeados ou fontes de bind mount. Preservar exit original e limites.
Provar RED/GREEN no executável fake e com Docker real próprio, inclusive status
0/37 e preservação de recurso externo ao runner. Q01–Q14 permanecem inalterados;
não há nova capability ou aprovação de publicação/instituição.
