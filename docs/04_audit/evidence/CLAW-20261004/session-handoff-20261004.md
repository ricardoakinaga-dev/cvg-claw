# Passagem de sessão — cvg-claw — 2026-10-04

Documento para retomar o trabalho em uma nova sessão (a pasta do repositório mudou de `/home/ricardo/cvg-agent-secretary-v2` para `/home/ricardo/cvg-claw`). Fica em `docs/04_audit/evidence/`, fora do escopo do candidato, para não invalidar o binding do crítico.

## Onde paramos

- Branch `main`. Commits locais **ainda não enviados** ao GitHub: `498ae11`, `af5f348`, `f8c2639` (e o commit desta passagem). Enviar com `git push`.
- Candidato congelado para o crítico: `2414ae1538227881cb294abd051d3ce593c266c59f7f0c6e6173a417f9b49ecd` no commit `f8c2639`. Qualquer mudança fora de `docs/04_audit/evidence/`, `certification/phase11/` e demais exclusões de `scripts/lib/certification-rules.mjs` muda o candidato e exige novo pedido ao crítico.
- Certificação: passada 1 com **33/35 gates e 16/16 invariantes PASS**. Faltam `independent_critic` e `PHASE11_FORMAL_CLOSURE`.
- CI `Verify` na `main` do GitHub continua vermelho até o selo novo ser commitado.

## Próximos passos, em ordem

1. **Parecer do crítico independente** para o candidato `2414ae15`. Pedido com binding e delta em [critic-request-20261004.md](../CLAW-reseal/critic-request-20261004.md). Decisão pendente do usuário: rodar o crítico no opencode (como nos pareceres anteriores) ou autorizar um subagente de contexto novo, somente leitura. O parecer vai para `docs/04_audit/evidence/AUD19/AUD19-08-critic-report.json` e é validado com `node scripts/phase11-2-evidence-check.mjs --critic`.
2. **Passada 2 da certificação** com a receita [certify-pass.sh](../CLAW-reseal/certify-pass.sh): contêiner `mcr.microsoft.com/playwright:v1.59.1-noble`, Node `22.23.2` montado do host, `postgres:16-alpine` descartável em `127.0.0.1:55441`, `PHASE11_ALLOW_DISPOSABLE_POSTGRES=1`. Uso: `bash docs/04_audit/evidence/CLAW-reseal/certify-pass.sh /caminho/do/log`. Não rodar a certificação direto no host: os testes visuais só batem na imagem de paridade do CI.
3. Conferir `npm run certification:verify:phase11` e `npm run promotion:check` (esperado: inelegível só pelos 8 gates externos). Commitar `certification/` e um recibo **somente** em `docs/04_audit/evidence/` (não tocar `docs/99_runtime_state.md` etc. depois do selo, ou o selo fica obsoleto).
4. `git push` e conferir `Verify`/`Security` no GitHub.
5. Responder às 6 perguntas abertas da [Discovery 0026](../../../00_discovery/0026_cvg_claw_hospital_autonomous_agent.md) e só então abrir o PRD do piloto de faturamento.

## Decisões do usuário registradas nesta sessão

- Projeto renomeado para `cvg-claw`; repositório dedicado `https://github.com/ricardoakinaga-dev/cvg-claw` (o antigo é o remote `legacy`).
- Hospital veterinário; sistema de gestão é o próprio `cvg-his-v4` (`/home/ricardo/cvg-his-v4`, lido apenas, em HEAD destacado `fdc591ae`).
- Piloto em faturamento/convênios; login pelo próprio ERP.
- Re-selo local `NO_GO` descartado; recertificação autorizada.

## Achados ainda abertos (auditoria AUD-20261004)

Ver [relatório da auditoria e passos de produção](AUD-20261004-audit-and-production-steps.md). Em resumo: provider de LLM, canal e identidade não compostos; nginx sem TLS/CSP/HSTS; sem manifests de deploy nem job de migração; P2 de shutdown/paginação/observabilidade; outras datas fixas em testes de retenção a varrer.

## Execução nesta sessão (para rastreio)

| Item | Resultado |
| --- | --- |
| Gates locais (Node 22.23.2) | typecheck, lint, Prettier, `docs:check` PASS |
| `npm audit fix` | 4 → 0 vulnerabilidades |
| Passada 1a (`498ae11`) | 31/35; `postgres`/`coverage` FAIL por teste com data fixa |
| Correção (`af5f348`) | `retention-postgres.test.ts` 13/13 PASS |
| Passada 1b (`af5f348`) | 33/35 gates, 16/16 invariantes |
| Congelamento (`f8c2639`) | candidato `2414ae15…` |
