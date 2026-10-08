# Avaliação do desenho de identidade HIS → Claw

Decisão atual: **manter F01/F03 como prioridades; desenho em avaliação, sem aceite
de integração**. As definições do piloto foram adiadas pelo usuário. Esta leitura
não reabre a etapa nem implementa emissão de tokens ou efeitos financeiros.

## Resultado

O Claw já valida tokens HMAC com audience `cvg-api`, tenant obrigatório,
`iat`/`exp`/`jti`, duração máxima padrão de cinco minutos e `kid` obrigatório
quando há keyring. Possui rotação/revogação de chaves e proteção contra replay.
Em produção, a composição exige store PostgreSQL e guard vinculado à keyring;
validação local não prova identidade institucional.

No HIS capturado em `ac40acc03144f9b643b1f5138097a2c71906d963`, o emissor do
`x-cvg-operator-token` não foi localizado no escopo inspecionado. API keys com
permissões explícitas existem, mas as rotas F01/F03 exigem Bearer, sessão
atualizada e ACL. A resolução de account por API key não equivale a passar
esse guard. Portanto, a credencial de serviço proposta ainda é incompatível
com as rotas selecionadas quando usada sozinha.

O token identifica o operador; não prova aprovação de uma cobrança específica.
É necessário um contrato de delegação, origem do tenant e mapeamento dos papéis
a partir da autoridade HIS. Tokens são de uso único devido ao JTI: o emissor
precisaria obter um token novo por requisição, respeitando retries sem replay.
HMAC compartilhado também permite ao detentor da chave assinar; separar os
limites de confiança e a custódia de chaves requer decisão de contrato.

## Notas 0–100

Notas de prontidão evidenciada, atribuídas pelo lead: 0 = ausente; 25 = proposta
com incompatibilidade; 50 = implementação parcial; 75 = controles locais
consistentes com qualificação pendente; 100 = contrato e execução institucional
qualificados. A média não substitui um gate obrigatório.

| Item | Nota | Fundamentação |
| --- | ---: | --- |
| Assinatura e audience no Claw | 85 | Implementação e testes locais; emissor institucional não qualificado. |
| Tenant obrigatório e identidade tipada | 85 | Validação existe; origem HIS e mapeamento de papéis não aprovados. |
| Validade curta, rotação e revogação | 85 | TTL/exp/kid e keyring existem; operação institucional não observada. |
| Proteção contra replay | 75 | Controles locais e exigência de store compartilhado; execução PostgreSQL desta sondagem omitida. |
| Emissor do token no HIS | 10 | Proposto; não localizado no escopo estático capturado. |
| Credencial de serviço nas rotas F01/F03 | 20 | API key existe, porém as rotas usam outro contrato de autenticação. |
| Delegação e aprovação por operação | 25 | Proposta não fecha vínculo entre operador, serviço e aprovador. |

Média aritmética destes sete itens: **55,00/100**. Parecer: corrigir o contrato
antes de admitir BUILD da integração. N3 permanece DENY mesmo com aprovação.

## Limites e evidências

[Manifesto HIS](HIS-contract-reference-manifest.json) e
[leitura completa capturada](HIS-contract-reference.txt) vinculam rotas, RBAC,
eventos e fontes HIS. A referência de Discovery `fdc591ae` é histórica.

[Testes locais](identity-local-review-tests.log): exit 0, 37 PASS/4 skips,
Node 22.23.2; PostgreSQL não foi configurado nesta sondagem. Os quatro skips
não qualificam proteção entre réplicas. O
[manifesto desta avaliação](identity-evaluation-manifest.json) fixa fontes e log.

As leituras F01 precisam definir o inventário esperado de cobranças; as rotas
existentes não provam detecção completa. F03 ainda precisa de contrato de
rascunho/aprovação/canal. `POST /billing/estimate` e `POST /billing/items`
persistem valores financeiros; classificar o item como draft não remove o
efeito N3. Nenhuma dessas escritas foi executada.
