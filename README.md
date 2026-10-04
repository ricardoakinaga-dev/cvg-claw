# cvg-claw

Agente autônomo governado para tarefas hospitalares. O cvg-claw planeja e executa tarefas de várias etapas para as equipes do hospital, dentro de níveis de autonomia explícitos, com aprovação humana e trilha de auditoria.

O projeto evolui a Esmeralda V2 (`cvg-agent-secretary-v2`). A secretária do paciente passa a ser o primeiro preset de agente sobre o mesmo kernel. O histórico e as evidências anteriores mantêm o nome original.

## Estado

- Discovery do novo escopo: [docs/00_discovery/0026](docs/00_discovery/0026_cvg_claw_hospital_autonomous_agent.md) (`DRAFT`).
- Estado operacional: [docs/CURRENT.md](docs/CURRENT.md) e [docs/99_runtime_state.md](docs/99_runtime_state.md).
- Staging e produção: `NO_GO`. Nenhum dado real é usado.

## Níveis de autonomia

| Nível         | O agente faz                                                      |
| ------------- | ----------------------------------------------------------------- |
| N0 — Informar | Consulta, resume e alerta                                         |
| N1 — Preparar | Monta rascunho; um humano aprova                                  |
| N2 — Executar | Ação reversível de baixo risco, com limites                       |
| N3 — Nunca    | Diagnóstico, prescrição, prontuário definitivo, efeito financeiro |

## Estrutura

- `apps/api`, `apps/worker`, `apps/web`: API, worker durável e console de operação.
- `packages/`: kernel do agente, runtime, políticas, aprovações, gateways de modelo e canal, persistência, observabilidade e workflows.
- `docs/`: pipeline CVG (`DISCOVERY -> PRD -> SPEC -> BUILD -> AUDIT`). Regras para agentes em [AGENTS.md](AGENTS.md).
- `certification/`: pacote de certificação Phase 11.

## Desenvolvimento

Requer Node `22.23.2` (ver `.nvmrc`).

```bash
npm ci
npm run typecheck && npm run lint
npm test
npm run verify   # gate completo
```

Testes de PostgreSQL usam `TEST_DATABASE_URL` com um banco descartável.
