import { describe, expect, it, vi } from 'vitest'
import { ApprovalEngine } from '@cvg/approval-engine'
import {
  DeterministicModelProvider,
  ModelGateway,
  PromptRegistry
} from '@cvg/model-gateway'
import { HashChainedAuditLedger, InMemoryTelemetry } from '@cvg/observability'
import {
  AgentProfileNameSchema,
  PolicyEngine,
  PolicyRegistry,
  type Capability
} from '@cvg/policy-engine'
import { RoleSchema } from '@cvg/shared'
import type { GovernedTurnInput } from '../contracts.ts'
import { InMemoryEffectJournal } from '../effect-journal.ts'
import { createExecutionProposal } from '../proposal.ts'
import { GovernedAgentRuntime } from '../runtime.ts'

const TENANT = 'tenant_00000000-0000-4000-8000-000000000001'
const NOW = new Date('2026-10-06T12:00:00.000Z')
const N3 = [
  'finance.write',
  'clinical.diagnose',
  'clinical.prescribe',
  'patient.record.write',
  'exam.release'
] as const satisfies readonly Capability[]

function turn(capability: Capability): GovernedTurnInput {
  return {
    tenantId: TENANT,
    operatorId: 'aud06_requester',
    operatorRole: 'System',
    agentId: 'agent_00000000-0000-4000-8000-000000000001',
    agentVersion: 'aud06-synthetic-v1',
    agentProfile: capability === 'finance.write' ? 'financial' : 'clinical',
    conversationId: 'aud06_synthetic_conversation',
    correlationId: 'corr_00000000-0000-4000-8000-000000000001',
    capability,
    action: capability,
    resource: {
      type: 'appointment',
      id: 'aud06_synthetic_resource',
      tenantId: TENANT
    },
    dataClassification: 'INTERNAL',
    prompt: { promptId: 'aud06-synthetic', version: '1' },
    modelProfile: 'fast',
    modelMessages: {
      messages: [{ role: 'user', content: 'synthetic fixture' }]
    }
  }
}

function harness() {
  const prompts = new PromptRegistry()
  prompts.register({
    promptId: 'aud06-synthetic',
    version: '1',
    content: 'Synthetic test only.',
    owner: 'fixture-owner',
    approvedBy: 'fixture-reviewer',
    status: 'approved',
    effectiveFrom: '2026-01-01T00:00:00.000Z',
    classification: 'INTERNAL',
    tenantId: TENANT
  })
  const respond = vi.fn(() => ({
    text: 'synthetic result',
    usage: { inputTokens: 1, outputTokens: 1 },
    providerId: 'deterministic',
    model: 'deterministic-v1',
    externalCall: false
  }))
  const modelGateway = new ModelGateway({
    providers: [new DeterministicModelProvider({ respond })],
    profiles: {
      fast: {
        name: 'fast',
        providerId: 'deterministic',
        model: 'deterministic-v1',
        location: 'local',
        temperature: 0,
        maxTokens: 128,
        timeoutMs: 5000,
        maxCostUsd: 1,
        estimatedCostUsd: 0,
        maxRetries: 0,
        pricing: { inputPer1kUsd: 0, outputPer1kUsd: 0 }
      }
    },
    prompts,
    clock: () => NOW,
    retry: { maxRetries: 0 }
  })
  const registry = new PolicyRegistry()
  registry.register({
    policyId: 'aud06.synthetic.allow-all',
    version: '1',
    effectiveFrom: '2026-01-01T00:00:00.000Z',
    rules: [
      {
        id: 'allow-all',
        priority: 100,
        effect: 'ALLOW',
        reason: 'Synthetic override attempt'
      }
    ]
  })
  const approvals = new ApprovalEngine({ clock: () => NOW })
  const toolExecutor = vi.fn(async () => ({ result: { synthetic: true } }))
  const outbox = vi.fn(async () => ({ eventId: 'evt_aud06_synthetic' }))
  const telemetry = new InMemoryTelemetry({ clock: () => NOW })
  const audit = new HashChainedAuditLedger()
  const runtime = new GovernedAgentRuntime({
    policy: new PolicyEngine({ documents: registry.list(), clock: () => NOW }),
    approvals,
    modelGateway,
    telemetry,
    audit,
    toolExecutor,
    outbox,
    clock: () => NOW,
    effectJournal: new InMemoryEffectJournal({ clock: () => NOW }),
    // All adapters are spies. Scope must be declared so that a missing policy
    // guard would reach the executor instead of an unrelated scope denial.
    effectScopes: {
      'finance.write': 'controlled_fake',
      'clinical.diagnose': 'controlled_fake',
      'clinical.prescribe': 'controlled_fake',
      'patient.record.write': 'controlled_fake',
      'exam.release': 'controlled_fake',
      'appointment.cancel': 'controlled_fake'
    }
  })
  return { runtime, approvals, respond, toolExecutor, outbox, telemetry, audit }
}

function storedApproval(approvals: ApprovalEngine, input: GovernedTurnInput) {
  // A structurally valid legacy approval is seeded in memory to exercise
  // revalidation, including the actual proposal hash and frozen payload.
  const proposal = createExecutionProposal(
    {
      ...input,
      policyVersion: '1',
      promptVersion: input.prompt.version,
      payload: { synthetic: true }
    },
    { now: NOW }
  )
  const record = approvals.request({
    tenantId: input.tenantId,
    operatorId: input.operatorId,
    agentId: input.agentId,
    agentVersion: input.agentVersion,
    action: input.action,
    resource: { type: input.resource.type, id: input.resource.id! },
    payload: proposal.payload,
    policyVersion: proposal.policyVersion,
    promptVersion: input.prompt.version,
    correlationId: input.correlationId,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    capability: input.capability,
    dataClassification: input.dataClassification,
    proposalPayload: proposal.payload
  })
  approvals.submit(TENANT, record.approvalId, input.operatorId)
  approvals.approve(TENANT, record.approvalId, {
    approverId: 'aud06_other_reviewer'
  })
  expect(approvals.get(TENANT, record.approvalId).status).toBe('APPROVED')
  return record.approvalId
}

describe('AUD06 Q03: runtime denies N3 before model, approval or executor', () => {
  it.each(N3)(
    'blocks fresh %s requests for every role and profile',
    async (capability) => {
      for (const operatorRole of RoleSchema.options) {
        for (const agentProfile of AgentProfileNameSchema.options) {
          const h = harness()
          const requestApproval = vi.spyOn(h.approvals, 'request')
          const result = await h.runtime.runTurn({
            ...turn(capability),
            operatorRole,
            agentProfile
          })
          expect(result.outcome).toBe('denied')
          expect(result.reason).toBe('policy_denied')
          expect(result.decision).toMatchObject({
            decision: 'DENY',
            reason: 'autonomy_n3_blocked'
          })
          expect(result.approvalId).toBeUndefined()
          expect(requestApproval).not.toHaveBeenCalled()
          expect(h.respond).not.toHaveBeenCalled()
          expect(h.toolExecutor).not.toHaveBeenCalled()
          expect(h.outbox).not.toHaveBeenCalled()
          expect(h.audit.verify().valid).toBe(true)
        }
      }
    }
  )

  it.each(N3)(
    'rejects an existing valid approval and repeated execution of %s',
    async (capability) => {
      const h = harness()
      const input = turn(capability)
      const approvalId = storedApproval(h.approvals, input)
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const result = await h.runtime.runTurn({ ...input, approvalId })
        expect(result.outcome).toBe('denied')
        expect(result.reason).toBe('policy_changed')
        expect(result.decision).toMatchObject({
          decision: 'DENY',
          reason: 'autonomy_n3_blocked'
        })
        expect(h.approvals.get(TENANT, approvalId)).toMatchObject({
          status: 'APPROVED',
          executionCount: 0
        })
      }
      expect(h.respond).not.toHaveBeenCalled()
      expect(h.toolExecutor).not.toHaveBeenCalled()
      expect(h.outbox).not.toHaveBeenCalled()
    }
  )

  it.each(N3)(
    'rejects a disguised %s action on a draft capability',
    async (action) => {
      const h = harness()
      const result = await h.runtime.runTurn({
        ...turn('message.draft'),
        agentProfile: 'secretary',
        action
      })
      expect(result.decision).toMatchObject({
        decision: 'DENY',
        reason: 'action_capability_mismatch'
      })
      expect(h.respond).not.toHaveBeenCalled()
      expect(h.toolExecutor).not.toHaveBeenCalled()
      expect(h.outbox).not.toHaveBeenCalled()
    }
  )

  it('retains the existing cancellation approval flow against a synthetic executor', async () => {
    const h = harness()
    const input = {
      ...turn('appointment.cancel'),
      agentProfile: 'secretary' as const
    }
    const requested = await h.runtime.runTurn(input)
    expect(requested.outcome).toBe('approval_required')
    expect(h.toolExecutor).not.toHaveBeenCalled()
    const approvalId = requested.approvalId!
    h.approvals.submit(TENANT, approvalId, input.operatorId)
    h.approvals.approve(TENANT, approvalId, {
      approverId: 'aud06_other_reviewer'
    })
    const result = await h.runtime.runTurn({ ...input, approvalId })
    expect(result.outcome).toBe('executed')
    expect(h.toolExecutor).toHaveBeenCalledTimes(1)
    expect(h.outbox).toHaveBeenCalledTimes(1)
  })
})
