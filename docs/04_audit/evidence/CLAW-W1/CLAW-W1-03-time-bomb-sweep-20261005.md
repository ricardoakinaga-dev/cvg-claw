# CLAW-W1-03 — varredura de testes que expiram com o tempo — 2026-10-05

## Método

- Node `22.23.2`; suíte unitária completa (`vitest run --no-file-parallelism --maxWorkers=2`) sem PostgreSQL.
- O preload [clock-shift.mjs](clock-shift.mjs) (SHA-256 `f55a04c6373726d26aad8bda076fca0ae98d1e083abfa39ee58397d84cdbc6a4`) adianta `Date.now()` e `new Date()` em N dias, sem mexer em datas explícitas:

```bash
CLOCK_SHIFT_DAYS=400 NODE_OPTIONS="--import $PWD/docs/04_audit/evidence/CLAW-W1/clock-shift.mjs" \
  npx vitest run --no-file-parallelism --maxWorkers=2
```

- Limites do método: o relógio do PostgreSQL, o `mtime` do sistema de arquivos e processos filhos com `env` próprio não são adiantados. Falhas nesses pontos são artefatos e foram classificadas uma a uma.

## Resultado com relógio +400 dias (2027-11-09)

Primeira rodada: 307 arquivos, 6 falharam; 2.682 testes, 6 falharam.

| Teste                                                                                  | Classificação | Causa                                                                                                   |
| -------------------------------------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------- |
| `apps/api/src/__tests__/journeys-api.test.ts` — future slots                           | **Real**      | Exigia `startsAt` em `2026-`; slots são gerados a partir de amanhã, então quebraria a partir de 2026-12-31 |
| `packages/agent-runtime/.../orchestration-branch-hardening.test.ts` — system clock     | Artefato      | `instanceof` entre a classe do preload e `Date` original; resolvido no preload v2 (`Symbol.hasInstance`) |
| `packages/persistence/.../retention.test.ts` — erasure ledger                          | Artefato      | Mesmo `instanceof`; resolvido no preload v2                                                             |
| `packages/agent-runtime/.../effect-journal-edges.test.ts` — live writer lock           | Artefato      | Lock considerado velho porque o `mtime` do arquivo usa o relógio real (`effect-journal.ts:844`)         |
| `packages/channel-gateway/.../channel-effect-journal-edges.test.ts` — journal lock     | Artefato      | Mesmo motivo (`effect-journal-file.ts:412`)                                                             |
| `tests/aud19-external-evidence.test.js` — synthetic attestation                        | Artefato      | O script roda em processo filho com `env` próprio, sem o preload, e vê `issuedAt` no futuro              |

Correção aplicada (somente teste): `journeys-api.test.ts` passa a exigir data ISO válida e posterior ao momento da execução.

Reexecução dos 6 arquivos após a correção: relógio real 148/148 PASS; relógio +400 dias 145/148, com as 3 falhas restantes classificadas como artefato acima.

## Revisão estática dos testes PostgreSQL

Os 30 arquivos de `test:postgres` foram varridos em busca de datas fixas a partir de 2026-10-01. Há uma só, em `retention-postgres.test.ts:1318` (`2027-01-01T03:00:00Z`), que testa **de propósito** a expiração da janela aprovada da política de tombstone.

As demais datas fixas são passado distante (`OLD`) ou são avaliadas contra o relógio injetado (`clock: () => NOW`), e não contra o relógio do PostgreSQL.

## Achado de produto (fora do escopo de correção)

`packages/persistence/src/retention.ts:47` fixa `INBOUND_TOMBSTONE_POLICY_VALID_UNTIL = '2027-01-01T02:59:59.000Z'`.

A partir dessa data, `assertInboundTombstonePolicyEffective` falha fechado com o relógio do banco. Esse é o comportamento desenhado (janela de aprovação imutável), mas a minimização de tombstones inbound para em produção e os testes PostgreSQL que a exercitam passam a falhar.

A renovação é decisão humana com nova aprovação da política, registrada como CLAW-W1-07 no [backlog 0347](../../../03_build/0347_claw_waves_backlog_20261005.md), com prazo antes de 2026-12-31.
