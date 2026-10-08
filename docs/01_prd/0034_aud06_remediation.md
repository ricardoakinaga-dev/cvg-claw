# 0034 — PRD de remediação AUD06

Fonte: [Discovery 0027](../00_discovery/0027_aud06_remediation.md).
Autorização: solicitação atual do usuário para implementar o plano de melhoria.

## Resultado e aceite

1. F01: a instalação reproduzível usa source-map-js corrigido; audit completo
   sem high/critical; build e regressão preservados.
2. F02: operações N3 retornam DENY independentemente de perfil, papel, documento,
   aprovação ou emergência. Rascunho permanece distinto de efeito definitivo.
   Nenhuma promoção N2; N0/N1 continuam limitados ao escopo existente.
3. F03: os testes visuais passam nos três navegadores em ambiente reproduzível,
   conservando screenshots aprovadas e tolerâncias. Regressão real deve ser
   corrigida, não ocultada por atualização cega de snapshots.
4. F05: janela de tombstone implementa a decisão de 05/10/2026, inclui fronteiras
   de expiração e aviso de 30 dias; estado corrente não pede decisões concluídas.
5. F07: falha de certificação produz exit não zero; recursos próprios são limpos
   também no erro/interrupção; não remover containers de outras sessões.
6. F08: extrair uma fronteira útil de API e cliente com contrato preservado;
   fonte corrente compacta e histórico preservado. Sem reescrita de evidências.
7. F06: composição local sintética de API/worker/web/banco com controles de rede,
   migração separada, procedimento verificável de TLS, limites por réplica,
   telemetria e recuperação. Ausência de prova operacional não vira PASS real.
8. F04: resolver contratos técnicos a partir das fontes HIS existentes; registrar
   pendências humanas precisas; qualificar integrações somente após seus gates.
9. Regressão integrada, crítica independente e evidência vinculada ao candidato.
   Certificação, CI publicado e oito gates externos são entregas separadas.

## Limites e métricas

Escopo CONTROLLED_LOCAL_SYNTHETIC_ONLY. Qualificação de produção requer os oito
gates já existentes. Não inventar DPO, faturistas, credenciais, consentimento,
baseline ou aceite. Não alterar contratos de qualidade para fazê-los passar.
Métricas: falhas/high/critical, decisões N3 indevidas, testes/branches, recursos
residuais, tamanho dos módulos extraídos, resultados de E2E/recuperação e gates.

PRODUCT_DEFINED para manutenção corretiva (itens 1–7 e 9). Item 8 mantém a
dependência de Discovery/PRD/SPEC do piloto, não concedida por este PRD.
