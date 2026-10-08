# 0027 — Discovery da remediação AUD06

Data: 2026-10-06. Fonte: [auditoria 0576](../04_audit/0576_repository_audit_2026-10-06.md).

O usuário solicitou criar roadmap/backlog e implementar todo o plano de melhoria,
com gauntlet-loop, orchestrate e engineering-framework. A auditoria precedente
produziu progresso verificável; esta rodada inicia sua remediação.

O problema conhecido são F01–F08: dependência vulnerável, divergência N3, CI
visual, integração incompleta, estado/retencão, implantação, wrapper e concentração
de código. Usuários afetados: desenvolvedores, operadores e, futuramente, equipes
do hospital. Resultado: correções demonstradas por testes, base operacional
reproduzível e rastreabilidade das pendências até qualificação real.

O escopo de manutenção da base existente é suficientemente definido para PRD.
Nenhuma alteração pode promover capability, executar efeito clínico/financeiro,
usar dados reais, publicar serviço ou presumir aprovação externa. A renovação
sintética de retenção tem decisão anterior válida e será executada sem pedi-la
novamente. Incertezas de F04 pertencem à Discovery 0026: participantes, convênio,
responsáveis, baseline, prioridade e proposta de identidade. A solicitação ampla
não inventa essas respostas. Permanecem na rota de conclusão integral.

Gate: DISCOVERY_READY para manutenção da base e infraestrutura sintética descritas
no PRD 0034; Discovery 0026 continua DRAFT para o novo produto hospitalar.
