import type {
  TimelineItem,
  ConversationPageView,
  ApprovalDecision,
  OperatorIdentity,
  TenantScopedOperatorIdentity,
  PlatformAgentView,
  PlatformVersionView,
  PlatformSafetyPreflightView,
  PlatformTraceView,
  PlatformTracePageView,
  PlatformTestCaseView,
  PlatformTestSuiteView,
  PlatformTestSuiteRunView,
  PlatformPluginCatalogStatus,
  PlatformPluginManifestView,
  PlatformPluginCatalogView,
  PlatformKnowledgeSourceStatus,
  PlatformKnowledgeSourceView,
  PlatformReleaseCandidateStatus,
  PlatformReleaseCandidateGateView,
  PlatformReleaseCandidateView,
  ApprovalView,
  TaskView,
  DeadLetterView,
  OrchestrationGoalStatus,
  OrchestrationGoalDetailView,
  OrchestrationGoalPageView,
  JourneyCandidateView,
  JourneyOwnerDraftView,
  JourneyPatientDraftView,
  JourneySlotView,
  JourneyAppointmentDraftView,
  TaskStatus,
  AuditEventView,
  AuditEvidenceReviewView,
  AuditEvidenceCheckpointView
} from './contracts.ts'
export type {
  TimelineItem,
  ConversationView,
  ConversationPageView,
  ApprovalDecision,
  OperatorRole,
  OperatorIdentity,
  TenantScopedOperatorIdentity,
  PlatformAgentView,
  PlatformVersionView,
  PlatformSafetyPreflightView,
  PlatformTraceView,
  PlatformTestCaseView,
  PlatformTestSuiteView,
  PlatformTestSuiteRunView,
  PlatformPluginCatalogStatus,
  PlatformPluginToolView,
  PlatformPluginManifestView,
  PlatformPluginCatalogView,
  PlatformKnowledgeSourceStatus,
  PlatformKnowledgeSourceView,
  PlatformReleaseCandidateStatus,
  PlatformReleaseCandidateGateKey,
  PlatformReleaseCandidateGateView,
  PlatformReleaseCandidateView,
  ApprovalView,
  TaskView,
  DeadLetterView,
  OrchestrationGoalStatus,
  OrchestrationGoalView,
  OrchestrationGoalDetailView,
  OrchestrationGoalPageView,
  JourneyCandidateView,
  JourneyOwnerDraftView,
  JourneyPatientDraftView,
  JourneySlotView,
  JourneyAppointmentDraftView,
  TaskStatus,
  AuditEventView,
  AuditEvidenceReviewView,
  AuditEvidenceCheckpointStatus,
  AuditEvidenceCheckpointView
} from './contracts.ts'
import { redactSensitiveText, type ApiEnvelope } from '@cvg/shared'

export class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string
  ) {
    super(message)
    this.name = 'ApiRequestError'
  }
}

export function isApiConflict(error: unknown): boolean {
  return error instanceof ApiRequestError && error.status === 409
}

function redactPlatformPayload<T>(payload: T): T {
  return redactPlatformValue(payload) as T
}

function redactPlatformValue(value: unknown): unknown {
  if (typeof value === 'string') return redactSensitiveText(value)
  if (Array.isArray(value)) return value.map(redactPlatformValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [
        key,
        redactPlatformValue(nestedValue)
      ])
    )
  }
  return value
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = init ? await fetch(path, init) : await fetch(path)
  const envelope = (await response.json()) as ApiEnvelope<T>
  if (!envelope.success || !envelope.data) {
    throw new ApiRequestError(
      envelope.error?.message ?? 'Request failed',
      response.status,
      envelope.error?.code ?? 'request_failed'
    )
  }
  return envelope.data
}

function operatorHeaders(identity: OperatorIdentity) {
  const headers: Record<string, string> = {
    'x-operator-id': identity.operatorId,
    'x-operator-role': identity.role
  }
  if (identity.tenantId) headers['x-tenant-id'] = identity.tenantId
  return headers
}

function requireAgentId(agentId: string): string {
  const normalizedAgentId = agentId.trim()
  if (!normalizedAgentId) {
    throw new Error('agentId is required for scoped platform reads')
  }
  return normalizedAgentId
}

function operatorInit(
  identity: OperatorIdentity,
  signal?: AbortSignal
): RequestInit {
  return {
    headers: operatorHeaders(identity),
    ...(signal ? { signal } : {})
  }
}

export const apiClient = {
  async listConversations(
    identity: OperatorIdentity,
    input: { limit: number; offset: number } = { limit: 25, offset: 0 }
  ): Promise<ConversationPageView> {
    return request(
      `/v1/conversations?limit=${input.limit}&offset=${input.offset}`,
      operatorInit(identity)
    )
  },

  async getTimeline(
    conversationId: string,
    identity: OperatorIdentity
  ): Promise<{ messages: TimelineItem[] }> {
    return request(
      `/v1/conversations/${conversationId}/timeline`,
      operatorInit(identity)
    )
  },

  async listApprovals(identity: OperatorIdentity): Promise<ApprovalView[]> {
    return request('/v1/approvals', operatorInit(identity))
  },

  async decideApproval(input: {
    approvalRequestId: string
    decision: ApprovalDecision
    identity: OperatorIdentity
    note: string
  }): Promise<ApprovalView> {
    return request(`/v1/approvals/${input.approvalRequestId}/decision`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ decision: input.decision, note: input.note })
    })
  },

  async listTasks(identity: OperatorIdentity): Promise<TaskView[]> {
    return request('/v1/tasks', operatorInit(identity))
  },

  async listDeadLetters(
    identity: TenantScopedOperatorIdentity
  ): Promise<DeadLetterView[]> {
    return request('/v1/outbox/dead-letters', operatorInit(identity))
  },

  async listOrchestrationGoals(
    identity: OperatorIdentity,
    input: { limit?: number; status?: OrchestrationGoalStatus } = {}
  ): Promise<OrchestrationGoalPageView> {
    const params = new URLSearchParams()
    params.set('limit', String(input.limit ?? 25))
    if (input.status) params.set('status', input.status)
    return request(
      `/v1/orchestration/goals?${params.toString()}`,
      operatorInit(identity)
    )
  },

  async getOrchestrationGoal(
    identity: OperatorIdentity,
    goalId: string
  ): Promise<OrchestrationGoalDetailView> {
    return request(
      `/v1/orchestration/goals/${encodeURIComponent(goalId)}`,
      operatorInit(identity)
    )
  },

  async requeueDeadLetter(input: {
    identity: TenantScopedOperatorIdentity
    eventId: string
  }): Promise<DeadLetterView> {
    return request(`/v1/outbox/dead-letters/${input.eventId}/requeue`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: '{}'
    })
  },

  async updateTaskStatus(input: {
    taskId: string
    status: TaskStatus
    identity: OperatorIdentity
  }): Promise<TaskView> {
    return request(`/v1/tasks/${input.taskId}/status`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ status: input.status })
    })
  },

  async searchJourneyOwners(
    identity: OperatorIdentity,
    phone: string,
    signal?: AbortSignal
  ): Promise<{ matches: JourneyCandidateView[] }> {
    return request(
      `/v1/journeys/owners/search?phone=${encodeURIComponent(phone)}`,
      operatorInit(identity, signal)
    )
  },

  async createJourneyOwnerDraft(input: {
    identity: OperatorIdentity
    phone: string
    name?: string
    idempotencyKey: string
    signal?: AbortSignal
  }): Promise<JourneyOwnerDraftView> {
    return request('/v1/journeys/owner-drafts', {
      method: 'POST',
      ...(input.signal ? { signal: input.signal } : {}),
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        phone: input.phone,
        ...(input.name ? { name: input.name } : {}),
        idempotencyKey: input.idempotencyKey
      })
    })
  },

  async listJourneyOwnerDrafts(
    identity: OperatorIdentity
  ): Promise<JourneyOwnerDraftView[]> {
    return request('/v1/journeys/owner-drafts', operatorInit(identity))
  },

  async searchJourneyPatients(input: {
    identity: OperatorIdentity
    ownerDraftId?: string
    ownerCandidateId?: string
    name?: string
    signal?: AbortSignal
  }): Promise<{ matches: JourneyCandidateView[] }> {
    const params = new URLSearchParams()
    if (input.ownerDraftId) params.set('ownerDraftId', input.ownerDraftId)
    if (input.ownerCandidateId)
      params.set('ownerCandidateId', input.ownerCandidateId)
    if (input.name) params.set('name', input.name)
    const suffix = params.toString() ? `?${params.toString()}` : ''
    return request(
      `/v1/journeys/patients/search${suffix}`,
      operatorInit(input.identity, input.signal)
    )
  },

  async createJourneyPatientDraft(input: {
    identity: OperatorIdentity
    ownerDraftId: string
    ownerCandidateId: string
    name: string
    species?: string
    idempotencyKey: string
    signal?: AbortSignal
  }): Promise<JourneyPatientDraftView> {
    return request('/v1/journeys/patient-drafts', {
      method: 'POST',
      ...(input.signal ? { signal: input.signal } : {}),
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        ownerDraftId: input.ownerDraftId,
        ownerCandidateId: input.ownerCandidateId,
        name: input.name,
        ...(input.species ? { species: input.species } : {}),
        idempotencyKey: input.idempotencyKey
      })
    })
  },

  async listJourneyPatientDrafts(
    identity: OperatorIdentity
  ): Promise<{ drafts: JourneyPatientDraftView[] }> {
    return request('/v1/journeys/patient-drafts', operatorInit(identity))
  },

  async linkJourneyPatient(input: {
    identity: OperatorIdentity
    patientDraftId: string
    candidateId: string
    signal?: AbortSignal
  }): Promise<JourneyPatientDraftView> {
    return request(`/v1/journeys/patient-drafts/${input.patientDraftId}/link`, {
      method: 'POST',
      ...(input.signal ? { signal: input.signal } : {}),
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ candidateId: input.candidateId })
    })
  },

  async listJourneySlots(
    identity: OperatorIdentity,
    signal?: AbortSignal
  ): Promise<{ slots: JourneySlotView[] }> {
    return request('/v1/journeys/slots', operatorInit(identity, signal))
  },

  async createJourneyAppointmentDraft(input: {
    identity: OperatorIdentity
    patientDraftId: string
    slot: string
    idempotencyKey: string
    signal?: AbortSignal
  }): Promise<JourneyAppointmentDraftView> {
    return request('/v1/journeys/appointment-drafts', {
      method: 'POST',
      ...(input.signal ? { signal: input.signal } : {}),
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        patientDraftId: input.patientDraftId,
        slot: input.slot,
        idempotencyKey: input.idempotencyKey
      })
    })
  },

  async listJourneyAppointmentDrafts(
    identity: OperatorIdentity
  ): Promise<{ drafts: JourneyAppointmentDraftView[] }> {
    return request('/v1/journeys/appointment-drafts', operatorInit(identity))
  },

  async createJourneyTask(input: {
    identity: OperatorIdentity
    sessionId: string
    title: string
    description: string
    idempotencyKey: string
    signal?: AbortSignal
  }): Promise<TaskView> {
    return request('/v1/journeys/tasks', {
      method: 'POST',
      ...(input.signal ? { signal: input.signal } : {}),
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        sessionId: input.sessionId,
        title: input.title,
        description: input.description,
        idempotencyKey: input.idempotencyKey
      })
    })
  },

  async getAudit(
    sessionId: string,
    identity: OperatorIdentity
  ): Promise<{ events: AuditEventView[] }> {
    return request(`/v1/audit/sessions/${sessionId}`, operatorInit(identity))
  },

  async getAuditEvidence(input: {
    identity: OperatorIdentity
    sessionId: string
    limit?: number
    offset?: number
  }): Promise<AuditEvidenceReviewView> {
    const params = new URLSearchParams()
    params.set('sessionId', input.sessionId)
    params.set('limit', String(input.limit ?? 10))
    params.set('offset', String(input.offset ?? 0))
    return request(
      `/v1/observability/audit-evidence?${params.toString()}`,
      operatorInit(input.identity)
    )
  },

  async createAuditEvidenceCheckpoint(input: {
    identity: OperatorIdentity
    eventIds: string[]
    filters?: {
      sessionId?: string
      correlationId?: string
      type?: string
      actorId?: string
    }
  }): Promise<{ checkpoint: AuditEvidenceCheckpointView }> {
    return request('/v1/observability/audit-evidence/checkpoints', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        eventIds: input.eventIds,
        ...(input.filters ? { filters: input.filters } : {})
      })
    })
  },

  async listAuditEvidenceCheckpoints(
    identity: OperatorIdentity
  ): Promise<{ checkpoints: AuditEvidenceCheckpointView[] }> {
    return request(
      '/v1/observability/audit-evidence/checkpoints',
      operatorInit(identity)
    )
  },

  async transitionAuditEvidenceCheckpoint(input: {
    identity: OperatorIdentity
    checkpointId: string
    expectedStatus: 'SEALED'
  }): Promise<{ checkpoint: AuditEvidenceCheckpointView }> {
    return request(
      `/v1/observability/audit-evidence/checkpoints/${input.checkpointId}/transition`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: JSON.stringify({
          status: 'ARCHIVED',
          expectedStatus: input.expectedStatus
        })
      }
    )
  },

  async requestAuditEvidenceExportApproval(input: {
    identity: OperatorIdentity
    sessionId: string
  }): Promise<ApprovalView> {
    return request('/v1/approvals', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        sessionId: input.sessionId,
        proposedAction: 'audit_evidence_export_review',
        summary: `Solicitar revisao humana para export controlado de audit evidence da sessao ${input.sessionId} sem despacho externo.`,
        riskLevel: 'high'
      })
    })
  },

  async listPlatformAgents(
    identity: OperatorIdentity & { tenantId: string }
  ): Promise<PlatformAgentView[]> {
    return request('/v1/admin/agents', operatorInit(identity))
  },

  async createPlatformAgent(input: {
    identity: OperatorIdentity & { tenantId: string }
    slug: string
    name: string
    description: string
  }): Promise<PlatformAgentView> {
    return request('/v1/admin/agents', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        slug: input.slug,
        name: input.name,
        description: input.description
      })
    })
  },

  async createPlatformVersion(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    config: Record<string, unknown>
  }): Promise<PlatformVersionView> {
    return request(`/v1/admin/agents/${input.agentId}/versions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ config: input.config })
    })
  },

  async clonePlatformVersion(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    config?: Record<string, unknown>
  }): Promise<PlatformVersionView> {
    return request(
      `/v1/admin/agents/${input.agentId}/versions/${input.versionId}/clone`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: JSON.stringify(input.config ? { config: input.config } : {})
      }
    )
  },

  async listPlatformVersions(
    identity: OperatorIdentity & { tenantId: string },
    agentId: string
  ): Promise<PlatformVersionView[]> {
    return request(
      `/v1/admin/agents/${agentId}/versions`,
      operatorInit(identity)
    )
  },

  async transitionPlatformVersion(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    target: 'TESTING' | 'APPROVED' | 'ARCHIVED' | 'DRAFT'
    expectedStatus?: string
  }): Promise<PlatformVersionView> {
    return request(
      `/v1/admin/agents/${input.agentId}/versions/${input.versionId}/transition`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: JSON.stringify({
          target: input.target,
          ...(input.expectedStatus
            ? { expectedStatus: input.expectedStatus }
            : {})
        })
      }
    )
  },

  async publishPlatformVersion(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    releaseCandidateId: string
    expectedStatus?: string
  }): Promise<PlatformVersionView> {
    return request(
      `/v1/admin/agents/${input.agentId}/versions/${input.versionId}/publish`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: JSON.stringify({
          releaseCandidateId: input.releaseCandidateId,
          ...(input.expectedStatus
            ? { expectedStatus: input.expectedStatus }
            : {})
        })
      }
    )
  },

  async runPlatformSafetyPreflight(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
  }): Promise<PlatformSafetyPreflightView> {
    return request(
      `/v1/admin/agents/${input.agentId}/versions/${input.versionId}/publish-preflight`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: '{}'
      }
    )
  },

  async rollbackPlatformVersion(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    releaseCandidateId: string
    expectedStatus?: string
  }): Promise<PlatformVersionView> {
    return request(`/v1/admin/agents/${input.agentId}/rollback`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        versionId: input.versionId,
        releaseCandidateId: input.releaseCandidateId,
        ...(input.expectedStatus
          ? { expectedStatus: input.expectedStatus }
          : {})
      })
    })
  },

  async runPlatformTestLab(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    message: string
    approvedKnowledge?: {
      version: string
      answer: string
      source: string
    }
  }): Promise<PlatformTraceView> {
    const trace = await request<PlatformTraceView>('/v1/admin/test-lab/runs', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        agentId: input.agentId,
        versionId: input.versionId,
        message: input.message,
        history: [],
        approvedKnowledge: input.approvedKnowledge
      })
    })
    return redactPlatformPayload(trace)
  },

  async evaluatePlatformTestLab(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    cases: Array<{
      id: string
      message: string
      history?: string[]
      expectedPolicyDecision?: string
      expectedResponseMode: 'answer' | 'clarify' | 'handoff' | 'blocked'
      expectedHandoff?: boolean
      approvedKnowledge?: {
        version: string
        answer: string
        source: string
      }
    }>
  }): Promise<{
    passed: boolean
    results: Array<{
      caseId: string
      passed: boolean
      failures: string[]
      trace: PlatformTraceView
    }>
  }> {
    const result = await request<{
      passed: boolean
      results: Array<{
        caseId: string
        passed: boolean
        failures: string[]
        trace: PlatformTraceView
      }>
    }>('/v1/admin/test-lab/evaluate', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        agentId: input.agentId,
        versionId: input.versionId,
        cases: input.cases
      })
    })
    return redactPlatformPayload(result)
  },

  async createPlatformTestSuite(input: {
    identity: OperatorIdentity & { tenantId: string }
    slug: string
    name: string
    description: string
    agentId: string
    versionId: string
    cases: PlatformTestCaseView[]
  }): Promise<PlatformTestSuiteView> {
    return request('/v1/admin/test-lab/suites', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        slug: input.slug,
        name: input.name,
        description: input.description,
        agentId: input.agentId,
        versionId: input.versionId,
        cases: input.cases
      })
    })
  },

  async listPlatformTestSuites(
    identity: OperatorIdentity & { tenantId: string },
    agentId: string
  ): Promise<PlatformTestSuiteView[]> {
    const query = `?agentId=${encodeURIComponent(requireAgentId(agentId))}`
    return request(`/v1/admin/test-lab/suites${query}`, operatorInit(identity))
  },

  async evaluatePlatformTestSuite(input: {
    identity: OperatorIdentity & { tenantId: string }
    suiteId: string
    versionId?: string
  }): Promise<PlatformTestSuiteRunView> {
    return request(`/v1/admin/test-lab/suites/${input.suiteId}/evaluate`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ versionId: input.versionId })
    })
  },

  async comparePlatformTestSuite(input: {
    identity: OperatorIdentity & { tenantId: string }
    suiteId: string
    versionAId: string
    versionBId: string
  }): Promise<PlatformTestSuiteRunView> {
    return request(`/v1/admin/test-lab/suites/${input.suiteId}/compare`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        versionAId: input.versionAId,
        versionBId: input.versionBId
      })
    })
  },

  async listPlatformTestSuiteRuns(
    identity: OperatorIdentity & { tenantId: string },
    suiteId: string,
    limit = 10
  ): Promise<PlatformTestSuiteRunView[]> {
    const page = await request<{
      items: PlatformTestSuiteRunView[]
      pageInfo: {
        limit: number
        offset: number
        total: number
        hasNextPage: boolean
      }
    }>(
      `/v1/admin/test-lab/suites/${suiteId}/runs?limit=${limit}`,
      operatorInit(identity)
    )
    return redactPlatformPayload(page.items)
  },

  async listPlatformTestRuns(
    identity: OperatorIdentity & { tenantId: string },
    limit = 10
  ): Promise<PlatformTraceView[]> {
    const page = await request<PlatformTracePageView>(
      `/v1/admin/test-lab/runs?limit=${limit}`,
      operatorInit(identity)
    )
    return redactPlatformPayload(page.items)
  },

  async listPlatformExecutionTraces(
    identity: OperatorIdentity & { tenantId: string },
    limit = 10
  ): Promise<PlatformTraceView[]> {
    const page = await request<PlatformTracePageView>(
      `/v1/admin/execution-traces?limit=${limit}`,
      operatorInit(identity)
    )
    return redactPlatformPayload(page.items)
  },

  async listPlatformPluginCatalog(
    identity: OperatorIdentity & { tenantId: string },
    name?: string
  ): Promise<PlatformPluginCatalogView[]> {
    const query = name ? `?name=${encodeURIComponent(name)}` : ''
    return request(`/v1/admin/plugins/catalog${query}`, operatorInit(identity))
  },

  async createPlatformPluginCatalog(input: {
    identity: OperatorIdentity & { tenantId: string }
    manifest: PlatformPluginManifestView
  }): Promise<PlatformPluginCatalogView> {
    return request('/v1/admin/plugins/catalog', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({ manifest: input.manifest })
    })
  },

  async transitionPlatformPluginCatalog(input: {
    identity: OperatorIdentity & { tenantId: string }
    pluginId: string
    target: PlatformPluginCatalogStatus
    expectedStatus?: PlatformPluginCatalogStatus
  }): Promise<PlatformPluginCatalogView> {
    return request(`/v1/admin/plugins/catalog/${input.pluginId}/transition`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        target: input.target,
        ...(input.expectedStatus
          ? { expectedStatus: input.expectedStatus }
          : {})
      })
    })
  },

  async listPlatformKnowledgeSources(
    identity: OperatorIdentity & { tenantId: string }
  ): Promise<PlatformKnowledgeSourceView[]> {
    return request('/v1/admin/knowledge-sources', operatorInit(identity))
  },

  async createPlatformKnowledgeSource(input: {
    identity: OperatorIdentity & { tenantId: string }
    source: string
    version: string
    label: string
    description: string
  }): Promise<PlatformKnowledgeSourceView> {
    return request('/v1/admin/knowledge-sources', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        source: input.source,
        version: input.version,
        label: input.label,
        description: input.description
      })
    })
  },

  async transitionPlatformKnowledgeSource(input: {
    identity: OperatorIdentity & { tenantId: string }
    sourceId: string
    target: PlatformKnowledgeSourceStatus
    expectedStatus?: PlatformKnowledgeSourceStatus
  }): Promise<PlatformKnowledgeSourceView> {
    return request(`/v1/admin/knowledge-sources/${input.sourceId}/transition`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        target: input.target,
        ...(input.expectedStatus
          ? { expectedStatus: input.expectedStatus }
          : {})
      })
    })
  },

  async listPlatformReleaseCandidates(
    identity: OperatorIdentity & { tenantId: string },
    agentId: string
  ): Promise<PlatformReleaseCandidateView[]> {
    const query = `?agentId=${encodeURIComponent(requireAgentId(agentId))}`
    return request(
      `/v1/admin/release-candidates${query}`,
      operatorInit(identity)
    )
  },

  async createPlatformReleaseCandidate(input: {
    identity: OperatorIdentity & { tenantId: string }
    agentId: string
    versionId: string
    gateResults: PlatformReleaseCandidateGateView[]
  }): Promise<PlatformReleaseCandidateView> {
    return request('/v1/admin/release-candidates', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...operatorHeaders(input.identity)
      },
      body: JSON.stringify({
        agentId: input.agentId,
        versionId: input.versionId,
        gateResults: input.gateResults
      })
    })
  },

  async transitionPlatformReleaseCandidate(input: {
    identity: OperatorIdentity & { tenantId: string }
    candidateId: string
    target: PlatformReleaseCandidateStatus
    expectedStatus?: PlatformReleaseCandidateStatus
  }): Promise<PlatformReleaseCandidateView> {
    return request(
      `/v1/admin/release-candidates/${input.candidateId}/transition`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...operatorHeaders(input.identity)
        },
        body: JSON.stringify({
          target: input.target,
          ...(input.expectedStatus
            ? { expectedStatus: input.expectedStatus }
            : {})
        })
      }
    )
  }
}
