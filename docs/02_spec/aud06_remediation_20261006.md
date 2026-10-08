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

## Addendum corretivo Q13 — scanner de SQL pré-kernel — 2026-10-08

A passada local2 foi NO_GO: o scanner acusa o INSERT de quota já admitido
em AUD06-10, reconhecendo somente os stores de replay. A crítica independente
classifica as escritas estáticas em api_rate_limit_buckets como infraestrutura
de segurança pré-kernel, sem efeito clínico/financeiro. AUD06-13 admite BUILD
limitado do scanner e testes: permitir somente essa tabela no arquivo exato
apps/api/src/postgres-rate-limit.ts; outras escritas ou efeitos nesse arquivo
continuam proibidos. Não acrescentar allowlist irrestrita por arquivo.
Detectar INSERT INTO, UPDATE de tabela e DELETE FROM, inclusive outra escrita
em CTE/statement misto; alvos dinâmicos/desconhecidos não recebem exceção.
Provar negativos clínicos/financeiros/agendamento, variantes de case/espaço/
comentário, quota fora do arquivo e HTTP/mensagens; preservar positivos dos
stores anteriores e UPSERT/expiração de quota. Incluir arquivos fonte novos
ainda não rastreados na mesma fronteira e recusar falha de inventário Git.
Critérios Q01–Q14 permanecem obrigatórios e inalterados; este é reparo de
medição, não admissão de efeito N3. Congelar novo candidato e repetir
qualificação após RED/GREEN e crítica, preservando todos os recibos NO_GO.

### Rework independente do scanner Q13 — 2026-10-08

Crítica focada I1 REJECT: três P1 de medição reproduzidos em22 sondagens,
10 PASS incorretos. Completar o reparo já admitido: aliases SQL entre aspas,
comentários SQL --, reconhecimento de comentários do código sem truncar URLs
ou literais, e exclusão somente de nomes de arquivos test/spec ancorados.
Fontes de produção em diretórios com .test./.spec. devem ser inventariadas,
rastreadas ou novas. Provar os exemplos negativos independentes, além dos
controles benignos e da exceção restrita. Não promover os48 testes anteriores
a aceite; preservar REJECT e sentinel13arquivos intactos. Nenhuma fronteira
de domínio, alvo Q01–Q14 ou gate externo muda. Novo congelamento/reteste.

### Rework lexical de templates e SQL Q13 — 2026-10-08

Crítica I1 v7 REJECT: quatro PASS incorretos em44 sondagens. Separar
expressões executáveis de template do texto SQL: nenhuma máscara de valor ou
comentário SQL pode ocultar fetch/sendMessage/HTTP real de uma interpolação,
inclusive aninhada. Texto recebe placeholders desconhecidos, enquanto ASTs
das expressões são inspecionadas independentemente. Corrigir aspas de valores
SQL ordinários versus E-prefixed e identificadores entre aspas; barra invertida
ordinária não pode ocultar a próxima escrita. Léxico não resolvido não recebe
exceção de quota. Preservar valores inertes, apóstrofos dobrados, E-strings
benignas e interpolação pura. RED/GREEN dos casos independentes e requalificação
obrigatórios; passada3 interrompida143, com cleanup0 e recursos próprios
ausentes, permanece sem PASS. Q01–Q14/gates reais e autoridade inalterados.

### Rework estrutural Q13 — 2026-10-08

Crítico fresco v8 REJECT,3P1/1P2:99 sondagens,18 PASS inseguros e5 rejeições
benignas definitivas. Admitir reparo estrutural limitado: análise de chamadas
por AST (opcionais, parênteses, casts, tags e expressões de template), sem
confundir literais inertes com chamadas. Análise SQL em helper próprio, lexer
de comentários/valores/identificadores/dollar-quote e validação do prefixo de
INSERT/UPDATE/DELETE antes de admitir arquivo+tabela de quota. Gramática
incerta rejeita a exceção; valores/identificadores quoted não são comandos.
SQL literal de query deve ser inspecionado separado de expressões executáveis
no host; reconhecer literais e composição estática, rejeitando alvo desconhecido.
Preservar stores de replay originais, sem ampliar qualquer fronteira de domínio.
Lead possui scanner/integrador, masters e testes de caminho público; builder
SQL possui somente scripts/lib/bypass-sql-audit.mjs e seu teste isolado.
Contrato helper: auditSqlWrites(text,{allowQuota,allowSecurityStore}) retorna
lista de achados {id,reason,offset,target?}, incluindo léxico/gramática não
resolvidos; nenhum efeito/DB/instalação. RED/GREEN independentes, revisão fresca
e qualificação integrada obrigatórios. Q01–Q14 permanecem inalterados.

A análise AST deve recusar query de expressão não resolvida, inclusive fora
da quota. O encaminhador preexistente em
apps/api/src/server/bootstrap-persistence.ts pode ser reconhecido somente
como propriedade query com arrow direta client.query(text, values), argumentos
iguais aos próprios parâmetros, sem transformação ou efeito adicional. Não é
exceção de escrita/tabela; registrar essa passagem no relatório, manter a
checagem dos consumidores e provar negativos para query literal ou corpo
alterado nesse arquivo. Strings/tokens inertes não são chamadas; chamadas
opcionais, membros computados literais, genéricos, casts, call/apply, aliases
estáticos e tags conhecidos continuam detectáveis. Não alegar análise completa
de efeitos construídos; revisão do artefato e guards runtime permanecem exigidos.

Constantes SQL só podem ser inferidas quando únicas, const e não reatribuídas
ou mutadas. Para o readiness existente, enumerar todas as variantes de um
for-of sobre lista literal const de identificadores (máximo64), sem chamadas
nas opções; nenhuma tabela ou variante recebe dispensa de análise. Lista
mutada, tabela desconhecida ou mistura com escrita de domínio rejeita.
Arrays/casts SQL comuns precisam ser reconhecidos pelo lexer sem esconder
comandos subsequentes; repetir scanner sobre as59fontes reais após integração.

### Rework de identidade lexical e comandos SQL Q13 — 2026-10-08

Crítico fresco v9 REJECT,6P1/1P2,127 sondagens e14replays; sentinel
25.133 arquivos intactos. Corrigir resolução por identidade lexical no local
de uso: parâmetros, catch, destructuring e imports não herdam constantes
homônimas externas. Usar símbolos do parser TypeScript e declinações
conservadoras, sem dependência nova ou execução de fixture. Propriedades SQL
obedecem ordem efetiva, inclusive spreads/nomes computados; override desconhecido
ou getter rejeita. Templates, concatenação e config usam um único caminho
recursivo de variantes para preservar toda composição estática. Const não
significa objeto imutável: aliases, mutação computada/indireta e escape para
chamada não modelada invalidam inferência de array/config. Alias benigno
sem mutação continua analisável. Imports, destructuring e membros de objetos
estáticos preservam efeitos conhecidos; funções locais puras homônimas não
são classificadas por nome apenas. Corpo local com efeito real continua
inspecionado. Manter forwarder existente estritamente limitado.

SQL executável fora da gramática admitida deve rejeitar, incluindo TRUNCATE,
DROP, COPY FROM, SELECT INTO, CREATE AS, DO e comandos procedurais. Valores
dollar-quoted de SELECT permanecem inertes; DO não recebe dispensa por seu
corpo quoted. Transações e consultas diagnósticas preexistentes devem ser
discriminadas de escritas. Não ampliar grant de quota/replay ou permitir
comando desconhecido por ausência de token INSERT/UPDATE/DELETE.
Lead possui scanner e testes públicos; builder SQL possui somente helper
e seu teste. RED/GREEN para todos os casos discriminantes, scanner59fontes,
crítica fresca e novo binding obrigatórios. Candidato ed573464 anterior STALE;
passada4 preparada mas não iniciada. Q01–Q14, escopo sintético, gates humanos
e autoridade de publicação permanecem inalterados.

### Rework de alcance de objetos e invocação Q13 — 2026-10-08

Crítico fresco v10 REJECT4P1/2P2,115 sondagens CLI e135 casos SQL,
25.167 arquivos intactos. Corrigir invalidadores transitivos: referências
contidas em arrays/objetos, spreads, closures, tags e argumentos de construtor
escapam juntos para chamada não modelada. Destinos de atribuição destructuring
devem invalidar símbolos/objetos reais, não o objeto sintático do padrão.
Dispensa de método leitor requer origem nativa verificada, nunca apenas nome
join/slice em método local; preservar método local puro e listas primitivas
nativas. Namespace/default de node-fetch preserva o efeito HTTP por aliases
estáticos. Separar construção bind de invocação e compor argumentos prefixados
com argumentos reais de call/apply; bind não invocado é inerte. Forwarder exato
exclui defaults/rest/opcionais/transformações de parâmetros. Nenhum novo grant
de domínio, SQL, autonomia ou effect boundary. Helper SQL permanece frozen
d668aeaa, sem nova mudança; revisão encontrou zero P1 em sua amostra limitada.

RED/GREEN discriminantes, corpus59fontes e crítica fresca obrigatórios.
Candidato31be26 anterior não aceito; passada4 não iniciada. Antes do ensaio,
materializar os recibos excluídos faltantes na cópia e repetir docs:check;
precheck encontrou27 referências em8 caminhos ausentes, sem alteração durante
a crítica. Lead possui scanner/testes/masters; Q01–Q14, piloto adiado e
publicação/gates reais permanecem inalterados.

Precisão de alcance: uma closure que apenas lê uma lista primitiva fechada não
expõe a referência; retornos/armazenamentos que expõem objetos continuam
invalidados transitivamente. Valores escalares não herdam o tratamento de
config de query; coerções locais com efeitos são inspecionadas. Propriedades
adicionais de funções não eliminam sua identidade lexical nem suas referências
carregadas. Controles negativos e positivos devem discriminar essas situações
sem conceder dispensa ao readiness por caminho de arquivo.

### Rework de seleção estrutural e exposição por armazenamento Q13 — 2026-10-08

Crítico fresco v11 REJECT4P1/1P2,93 sondagens e18replays;1256 fontes
e25.190 arquivos intactos, com5atimes de leitura explicitamente qualificados.
Registrar antes de BUILD: usar seleção estrutural compartilhada para índices
literais/arrays/destructuring e transportar a origem callable HTTP/query.
Atribuições destructuring também transportam referências RHS para os destinos
reais; não basta marcar os símbolos destinos como mutados. Closures expõem
referências por retorno e por armazenamento; getters retornando objetos devem
participar desse alcance. Leitura de índice primitivo, length ou join nativo
não expõe a própria lista fechada. Cópias contendo somente valores primitivos
permanecem distintas do objeto original. Nenhuma execução de fixture ou dispensa
por caminho de arquivo; helper SQL frozen e critérios Q01–Q14 intactos.
Lead possui scanner/testes; novo RED/GREEN e corpus59, freeze e crítica fresca
antes da passada4. Candidato04ff9c61 não aceito; piloto/publicação/gates reais
continuam sem aceite.

A seleção estrutural também cobre rest literal e defaults: um valor definido
preserva sua origem; undefined/posição omitida aplica o default. Defaults do
padrão não são atribuições incondicionais independentes. Rest exclui as chaves
selecionadas e mantém origens do restante estático; spreads desconhecidos não
são inferidos. Um receptor de escrita invalida sua identidade e aliases reais,
enquanto a exposição de um container invalida referências alcançáveis. Métodos
nativos de array não recebem o tratamento de config local com método homônimo;
overrides explícitos de método preservam o efeito atribuído. Não ampliar os
limites declarados de inferência nem alegar análise universal de funções JS.

### Rework de projeção compartilhada de origem Q13 — 2026-10-08

Crítico fresco v12 REJECT5P1/1P2 em184 sondagens;28.068 entradas intactas,
com atime igualmente intacto. Registrar antes de BUILD: default shorthand em
atribuição de objeto deve manter callable; seleção por membro/índice deve
transportar argumentos prefixados de bind; destructuring de propriedades
armazenadas deve manter aliases reais. Defaults de parâmetros de closures
participam da referência retornada. Invalidar a origem selecionada antes de
invalidar seu container de seleção; não perder identidade por ordem de taint.
Cópia slice primitiva não expõe o original; cópia rasa com objetos conserva
as referências internas. Compartilhar projeção com identidade estável de
alocações sintéticas de rest/cópia para todos os consumidores relevantes,
sem inferir SQL de origem mutada ou tratar cópia distinta como alias do original.
RED/GREEN, corpus59, novo freeze e crítica fresca obrigatórios. Helper/runtime
intactos, passada4 não iniciada, candidato017c464a rejeitado. Q01–Q14, piloto
adiado, publicação e gates reais permanecem inalterados.
