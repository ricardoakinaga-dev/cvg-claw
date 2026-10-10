# Revisão dos comentários sobre a crítica e a publicação — 2026-10-08

**Veredito atual: ajustes locais concluídos; publicação aguarda autorização humana.** O apontamento de confidencialidade era procedente e `d55c9f0` permanece revogado. O pacote limpo `716bf465` está no repositório principal; o checkout contaminado não tem mais remote. Os originais privados foram preservados fora do repositório antes da substituição das cópias do working tree por referências somente de caminhos e hashes.

## Constatações

| Apontamento | Verificação |
| --- | --- |
| Código privado em repositório público | Confirmado pela API do GitHub: `cvg-claw` público, `cvg-his-v4` privado. Os dois arquivos estavam em `d55c9f0`, embora fora do hash das fontes. O manifest registra 20 arquivos privados e 62 trechos, totalizando 105.535 bytes de texto; os arquivos completos medem 160.174 e 29.765 bytes. Os hashes das 20 fontes locais coincidem; 55 trechos coincidem integralmente com os intervalos de linhas. A classificação não depende de todos os trechos terem o mesmo formato. |
| Timeout de Verify | Risco confirmado, sem previsão exata de CI. Atual: unit 735,045 s; coverage 825,302 s; Verify 1.533,315 s; bypass 229,569 s. Anterior: 319,791 / 397,789 / 868,890 / 0,040 s. O job remoto limita a execução a 40 minutos. O último job durou 24m31s; a execução completa, com espera, durou 26m03s. A diferença de Verify acrescenta cerca de 11m04s, projetando aproximadamente 35m35s de job ou 37m07s incluindo a espera anterior. Hardware, pull e variância impedem tratar isso como garantia. Unit e coverage não devem ser somados novamente ao total de Verify. |
| Ancestralidade no merge | Confirmado em `scripts/phase11-verify.mjs`: exige que `7c1fdfc` seja ancestral do HEAD. As três opções de merge estão habilitadas no GitHub. Squash/rebase que recriem a cadeia quebram o vínculo; usar merge commit ou fast-forward que preserve a âncora. O pacote substitui `certification/current.json`; isso precisa constar explicitamente no PR. |
| Alegação sobre `d55c9f0` | A suíte completa rodou na âncora `7c1fdfc`. Em `d55c9f0` houve materialização, docs-check, verifier e checagens de diff. O diff do working tree limpo, com saída vazia, não prevê CI. A formulação correta é “materializado com verificações específicas”; não “suíte completa executada nesse commit”. |
| Permanência em `/tmp` | Confirmado: o branch anterior existia apenas no checkout temporário. Disco a 89%, aproximadamente 18 GiB em diretórios `cvg-aud06*`. Nesta máquina a política observada é `/tmp` com 30 dias, não remoção indiscriminada a cada boot. Ainda assim, `/tmp` não é armazenamento durável. |
| Crescimento/processo | Scanner: 2.047 linhas adicionadas e 50 removidas; crescimento líquido de 1.997, de 94 para 2.091 linhas. Teste: 6.713 linhas. Correção da minha contagem anterior: são 16 seções datadas de 08/10 na SPEC, 8 de nível `##` e 8 de nível `###`. No histórico de `716bf465`, são 15 commits com emails inválidos: 10 com `aud06-local@invalid` e 5 com `aud06-local@test.invalid`. A contagem anterior era parcial. Os três masters somavam 1.334.353 bytes na primeira revisão; runtime sozinho media 510.591. A legibilidade precisa melhorar. |

A base remota foi conferida por leitura e continua em `1a66436`. O último Verify remoto falhou em Browser E2E. As contagens técnicas 35/35, unit 4.338 + 200 skips reconciliados, PostgreSQL 369, E2E 75 e cobertura 97,77%/94,38% permanecem válidas para a execução local registrada. Nenhum novo gate completo ou CI remoto foi executado nesta revisão.

## Falha do processo de aceitação

O planner fechou links Markdown e verificou hashes/existência; isso não classifica confidencialidade. A exclusão das evidências do hash de comportamento foi confundida com ausência de risco de publicação. A crítica final examinou principalmente o candidato técnico e os resultados brutos, enquanto documentos históricos/evidências extensas foram tratados como conteúdo opaco. Faltou uma revisão explícita do payload público e de sua ancestralidade.

O parecer técnico anterior permanece como registro histórico do escopo local. Sua existência não sustenta o aceite do pacote público. A declaração de readiness de `d55c9f0` foi revogada, sem reescrever os resultados originais nem modificar as evidências privadas.

## Correções locais realizadas

- Rematerialização a partir da âncora limpa, sem criar um descendente de `d55c9f0`. Apagar os arquivos somente no tip não eliminaria o conteúdo do histórico.
- Os dois arquivos públicos de referência contêm somente caminhos relativos e SHA256. Originais preservados localmente; nenhum código privado reproduzido neste relatório.
- Novo commit: `716bf465fb17389e24fde589978fd6a31ac324c8`. As 1.256 fontes continuam idênticas ao candidato `f15cece0`.
- Armazenamento durável em `/home/ricardo/.local/share/cvg-aud06/publication-confidentiality-q_9kh_5s/repo`.
- Importação local do branch `codex/aud06-remediation-20261008` no repositório principal, sem checkout e sem mudança do working tree.
- Controle limitado aos materiais conhecidos: os dois arquivos antigos são detectados como negativos; 6.052 blobs alcançáveis do commit novo não contêm os hashes/trechos conhecidos pesquisados. A análise decodifica strings JSON; não afirma detectar universalmente todo código proprietário.
- Docs-check e `phase11-verify` executados no commit novo, ambos exit 0. A suíte completa continua atribuída à âncora original.

Provas: [rematerialização](publication-confidentiality-rematerialization.json), [conteúdo e histórico](publication-confidentiality-check.json), [checks específicos](publication-confidentiality-materialized-checks.json) e [importação local](publication-safe-local-fetch.json).

## Segunda revisão: riscos locais resolvidos

O relatório fornecido pelo usuário descreve uma comparação mais ampla de todo o HIS contra 424 arquivos novos do histórico, além de checks em clone independente. Essa confirmação é evidência relatada pelo auditor; não foi reexecutada nesta rodada nem substitui a qualificação limitada do nosso controle de 6.052 blobs.

- `git remote remove origin` executado no checkout antigo. A leitura posterior confirma zero remotes. Commit contaminado e patch permanecem como material forense local; não são candidatos de publicação. A remoção evita o push acidental por `origin`, mas não impede alguém de informar uma URL explicitamente.
- Originais privados copiados para diretório durável fora do repositório, com permissão `0700` e arquivos `0600`; SHA256 e tamanho conferidos antes de substituir os dois arquivos de MAIN pelas versões limpas de `716bf465`. Não há mais originais privados nesses caminhos do working tree que um checkout possa sobrescrever.
- Branch local confirmado em `716bf465fb17389e24fde589978fd6a31ac324c8`, sem checkout/reset do working tree. Nenhuma fonte certificada foi alterada.

Recibo: [segurança local e preservação](publication-local-safety-followup.json). O arquivo privado `archive-receipt.json` acompanha os originais fora do repositório.

## Decisões propostas para o draft e o merge

Adota-se, como proposta técnica para o draft, manter os 40 minutos e medir uma execução real após autorização. A projeção de aproximadamente 35,6 minutos não garante margem. Se ocorrer timeout, preservar a falha e requalificar uma mudança de workflow antes de prosseguir. Não houve mudança de limite, fonte ou suíte nesta rodada.

Para o merge futuro, usar merge commit preservando `7c1fdfc`, sem squash ou rebase. A abertura de draft não autoriza merge. A descrição do PR explicita a troca do ponteiro de certificação, a diferença entre suíte na âncora e checks de materialização e os limites locais. Nenhuma configuração do GitHub foi alterada.

O commit `716bf465` foi preservado para manter a revisão independente aplicável ao mesmo SHA. Sua nota de correção em inglês e a falta de espaço em `anchor7c1fdfc` são detalhes editoriais reconhecidos; não se afirma que foram corrigidos nesse commit. O resumo operacional e a minuta atuais estão em português.

Nenhum push, PR, alteração de configuração remota, deploy, limpeza destrutiva de `/tmp` ou retomada do piloto foi realizado. Produção permanece NO_GO, N3 DENY, piloto adiado pelo usuário e gates externos pendentes.

## Verificação desta rodada

Docs-check em MAIN: exit 0, Node22.23.2, 2.840 links e 6.940 JSON válidos; próximo passo sincronizado. Após o check, conferidos novamente hashes/permissões do arquivo privado, equivalência das referências limpas com `716bf465`, ausência de remotes no checkout antigo e ancestralidade da âncora. Recibo: [docs-check](publication-local-safety-docs-check.json). Não houve repetição da suíte completa nem alteração do commit revisado.
