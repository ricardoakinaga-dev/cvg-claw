/** Public client DTOs. This module has no runtime or HTTP dependencies. */
export interface TimelineItem {
  id: string
  direction: 'inbound' | 'outbound'
  body: string
  createdAt: string
}

export interface ConversationView {
  id: string
  channel: string
  senderRef: string
  status: string
  correlationId: string
  openSessionId: string | null
  lastMessageBody: string | null
  lastMessageAt: string | null
  updatedAt: string
}

export interface ConversationPageView {
  items: ConversationView[]
  pageInfo: {
    limit: number
    offset: number
    total: number
    hasNextPage: boolean
  }
}

export type ApprovalDecision = 'approved' | 'rejected' | 'assumed'

export type OperatorRole = 'Operator' | 'Approver' | 'Supervisor' | 'Admin'

export interface OperatorIdentity {
  operatorId: string
  role: OperatorRole
  tenantId?: string
}

export type TenantScopedOperatorIdentity = OperatorIdentity & {
  tenantId: string
}

export interface PlatformAgentView {
  id: string
  slug: string
  name: string
  description: string
  activeVersionId: string | null
}

export interface PlatformVersionView {
  id: string
  agentId: string
  version: number
  status: string
  config: Record<string, unknown>
}

export interface PlatformSafetyPreflightView {
  passed: boolean
  caseCount: number
  externalCall: boolean
  cases: Array<{
    caseId: string
    passed: boolean
    failures: string[]
    policyDecision: string | null
    responseMode: string
    handoffRequested: boolean
    externalCall: boolean
  }>
  failures: Array<{ caseId: string; reasons: string[] }>
}

export interface PlatformTraceView {
  traceId: string
  agentId: string
  versionId: string
  configVersion: string
  executionMode: 'TEST_LAB' | 'CONTROLLED_RUNTIME'
  conversationId?: string
  sessionId?: string
  intent: { name: string; confidence: number }
  risk?: { level: string; reason: string }
  policy: Array<{ decision: string; reason: string }>
  knowledge: { status: string; source?: string; version?: string }
  tools: Array<{ name: string; status: string }>
  toolResults?: Array<{
    name: string
    status: string
    output: { redacted: true } | null
  }>
  handoff: {
    requested: boolean
    reason: string | null
    state: 'BOT_ACTIVE' | 'HANDOFF_REQUESTED'
    destination?: string
    priority?: 'low' | 'medium' | 'high'
  }
  response: { text: string; mode: string }
  outputPolicy?: {
    decision: 'allowed' | 'rewritten'
    reason: string
    mode: string
    redacted: boolean
  }
  provider: { provider: string; model: string; externalCall: false }
  prompt?: {
    version: string
    blockIds: string[]
    status?: string
    checksum?: string
  }
  status?: 'completed' | 'blocked' | 'failed'
  startedAt?: string
  completedAt?: string
  latencyMs?: number
  tokenUsage?: {
    prompt: number
    completion: number
    total: number
    estimated: true
  }
  spans?: Array<{
    name: string
    status: string
    durationMs: number
  }>
  createdAt?: string
}

export interface PlatformTracePageView {
  items: PlatformTraceView[]
  pageInfo: {
    limit: number
    offset: number
    total: number
    hasNextPage: boolean
  }
}

export interface PlatformTestCaseView {
  id: string
  message: string
  history?: string[]
  expectedPolicyDecision?: string
  expectedResponseMode: 'answer' | 'clarify' | 'handoff' | 'blocked'
  expectedHandoff?: boolean
  approvedKnowledge?: { version: string; answer: string; source: string }
}

export interface PlatformTestSuiteView {
  id: string
  tenantId: string
  slug: string
  name: string
  description: string
  agentId: string
  versionId: string
  version: number
  cases: PlatformTestCaseView[]
  previousSuiteId: string | null
  createdBy: string
  createdAt: string
  updatedAt: string
}

export interface PlatformTestSuiteRunView {
  id: string
  tenantId: string
  suiteId: string
  agentId: string
  variants: Array<{
    label: 'A' | 'B'
    versionId: string
    passed: boolean
    results: Array<{
      caseId: string
      passed: boolean
      failures: string[]
      trace: PlatformTraceView
    }>
  }>
  passed: boolean
  createdBy: string
  createdAt: string
}

export type PlatformPluginCatalogStatus = 'DRAFT' | 'APPROVED' | 'ARCHIVED'

export interface PlatformPluginToolView {
  name: string
  permission: string
  risk: 'low' | 'medium' | 'high' | 'critical'
  requiresApproval: boolean
}

export interface PlatformPluginManifestView {
  name: string
  version: string
  capabilities: string[]
  permissions: string[]
  tools: PlatformPluginToolView[]
  hooks: string[]
  dependencies: string[]
  configSchemaVersion: string
}

export interface PlatformPluginCatalogView {
  tenantId: string
  id: string
  manifest: PlatformPluginManifestView
  status: PlatformPluginCatalogStatus
  createdBy: string
  approvedBy: string | null
  createdAt: string
  updatedAt: string
}

export type PlatformKnowledgeSourceStatus = 'DRAFT' | 'APPROVED' | 'ARCHIVED'

export interface PlatformKnowledgeSourceView {
  tenantId: string
  id: string
  source: string
  version: string
  label: string
  description: string
  status: PlatformKnowledgeSourceStatus
  createdBy: string
  approvedBy: string | null
  createdAt: string
  updatedAt: string
}

export type PlatformReleaseCandidateStatus =
  | 'DRAFT'
  | 'VALIDATED'
  | 'REJECTED'
  | 'ARCHIVED'

export type PlatformReleaseCandidateGateKey =
  | 'safety_preflight'
  | 'test_lab_regression'
  | 'snapshot_integrity'
  | 'external_boundary'

export interface PlatformReleaseCandidateGateView {
  key: PlatformReleaseCandidateGateKey
  status: 'PASS' | 'FAIL'
  evidenceRef: string
}

export interface PlatformReleaseCandidateView {
  tenantId: string
  id: string
  agentId: string
  versionId: string
  evidenceDigest: string
  gateResults: PlatformReleaseCandidateGateView[]
  status: PlatformReleaseCandidateStatus
  createdBy: string
  validatedBy: string | null
  createdAt: string
  updatedAt: string
  validatedAt: string | null
}

export interface ApprovalView {
  id: string
  sessionId: string
  proposedAction: string
  summary: string
  riskLevel: string
  status: string
  correlationId?: string
  createdAt?: string
  updatedAt?: string
}

export interface TaskView {
  id: string
  sessionId: string
  title: string
  priority: string
  status: string
  description?: string
  correlationId?: string
  createdAt?: string
  updatedAt?: string
  dueAt?: string
}

export interface DeadLetterView {
  id: string
  type: string
  status: string
  correlationId: string
  traceId: string | null
  conversationId: string | null
  sessionId: string | null
  inboundMessageId: string | null
  attempts: number
  lastError: string | null
  createdAt: string
  availableAt: string | null
  deadLetteredAt: string | null
}

export type OrchestrationGoalStatus =
  | 'OBSERVING'
  | 'UNDERSTANDING'
  | 'PLANNING'
  | 'GOVERNING'
  | 'WAITING_APPROVAL'
  | 'EXECUTING'
  | 'OBSERVING_RESULT'
  | 'EVALUATING'
  | 'REPLANNING'
  | 'WAITING_EXTERNAL'
  | 'HUMAN_HANDOFF'
  | 'PENDING_RETURN'
  | 'UNCERTAIN'
  | 'COMPLETED'
  | 'BLOCKED'
  | 'FAILED'
  | 'CANCELLED'
  | 'BUDGET_EXHAUSTED'
  | 'LOOP_DETECTED'

export interface OrchestrationGoalView {
  id: string
  tenantId: string
  status: OrchestrationGoalStatus
  objective: string | null
  correlationId: string
  inboundMessageId: string | null
  conversationId: string | null
  sessionId: string | null
  activePlanId: string | null
  version: number
  lastReason: string | null
  lastError: string | null
  deadline: string | null
  createdAt: string
  updatedAt: string
  budget: {
    maxSteps: number
    maxReplans: number
    maxIterations: number
    maxModelCalls: number
    maxToolCalls: number
    maxDurationMs: number
    maxCostUsd: number
    usage: {
      steps: number
      replans: number
      iterations: number
      modelCalls: number
      toolCalls: number
      costUsd: number
    }
  }
}

export interface OrchestrationGoalDetailView extends OrchestrationGoalView {
  successCriteria: Array<Record<string, unknown>>
  executionSnapshot: {
    agentVersion: string | null
    promptVersion: string | null
    policyVersion: string | null
    modelProfile: string | null
    toolVersions: Record<string, string>
  }
  replanCount: number
  operatorState: {
    state: OrchestrationGoalStatus
    reason: string | null
    error: string | null
    deadline: string | null
    deadlineExpired: boolean
    activePlanVersion: number | null
    currentStepId: string | null
    currentStepStatus: string | null
    leaseOwner: string | null
    leaseUntil: string | null
    approvalId: string | null
    handoffRequired: boolean
    evidenceCount: number
    verifiedEvidenceCount: number
    lastObservationAt: string | null
    lastEvaluation: {
      result: string
      reason: string | null
      createdAt: string
    } | null
  }
  plans: Array<{
    id: string
    goalId: string
    tenantId: string
    version: number
    parentPlanId: string | null
    triggeringEvaluationId: string | null
    status: string
    reason: string | null
    fingerprint: string
    createdAt: string
    updatedAt: string
    steps: Array<{
      id: string
      goalId: string
      planId: string
      type: string
      description: string | null
      dependencies: string[]
      requiredCapabilities: string[]
      riskLevel: string
      approvalRequirement: string
      status: string
      attemptCount: number
      approvalId: string | null
      toolId: string | null
      toolVersion: string | null
      resultHash: string | null
      lastError: string | null
      startedAt: string | null
      completedAt: string | null
      version: number
      createdAt: string
      updatedAt: string
      attempts: Array<{
        id: string
        workerId: string
        correlationId: string
        startedAt: string
        finishedAt: string | null
        outcome: string | null
        errorClass: string | null
      }>
    }>
  }>
  observations: Array<{
    id: string
    planId: string
    stepId: string | null
    kind: string
    resultDigest: string | null
    evidence: Array<{
      source: string
      reference: string | null
      verified: boolean
      key: string | null
      digest: string | null
    }>
    createdAt: string
  }>
  evaluations: Array<{
    id: string
    planId: string
    stepId: string | null
    evaluatorType: string
    result: string
    reason: string | null
    evidence: Array<{
      source: string
      reference: string | null
      verified: boolean
      key: string | null
      digest: string | null
    }>
    createdAt: string
  }>
}

export interface OrchestrationGoalPageView {
  items: OrchestrationGoalView[]
  pageInfo: { limit: number; hasNextPage: boolean }
}

export interface JourneyCandidateView {
  id: string
  displayName: string
  kind: 'owner' | 'patient'
  ownerId?: string
}

export interface JourneyOwnerDraftView {
  id: string
  conversationId: string | null
  sessionId: string | null
  phone: string | null
  name: string | null
  candidateIds: string[]
  status: 'draft' | 'linked' | 'expired'
  idempotencyKey: string
  createdAt: string
  updatedAt: string
  expiresAt: string
}

export interface JourneyPatientDraftView {
  id: string
  ownerDraftId: string | null
  ownerCandidateId: string | null
  conversationId: string | null
  sessionId: string | null
  name: string | null
  species: string | null
  candidateIds: string[]
  status: 'draft' | 'linked' | 'expired'
  idempotencyKey: string
  createdAt: string
  updatedAt: string
  expiresAt: string
}

export interface JourneySlotView {
  id: string
  startsAt: string
  sourceVersion: string
}

export interface JourneyAppointmentDraftView {
  id: string
  patientDraftId: string
  conversationId: string | null
  sessionId: string | null
  slot: string
  sourceVersion: string
  status: 'proposed' | 'awaiting_approval' | 'expired' | 'cancelled'
  confirmationBlocked: true
  idempotencyKey: string
  createdAt: string
  updatedAt: string
  expiresAt: string
}

export type TaskStatus = 'open' | 'in_progress' | 'done' | 'canceled'

export interface AuditEventView {
  id: string
  type: string
  actorId?: string
  actorType: string
  correlationId?: string
  createdAt: string
  payload?: Record<string, unknown>
}

export interface AuditEvidenceReviewView {
  summary: {
    totalEvents: number
    byType: Record<string, number>
    byActorType: Record<string, number>
    byCorrelationId: Record<string, number>
    bySessionId: Record<string, number>
  }
  page: {
    items: AuditEventView[]
    pageInfo: {
      limit: number
      offset: number
      total: number
      hasNextPage: boolean
    }
  }
  export: {
    format: 'json'
    controlled: boolean
    externalDispatch: boolean
    requestedBy: string
  }
  governance?: {
    retention: {
      policyId: string
      approvedForRealData: boolean
      humanSignoffRequired: boolean
    }
    payload: {
      mode: 'minimized'
      rawPayloadReturned: boolean
      redactedFields: string[]
    }
    export: {
      externalDispatch: boolean
      externalExportRequiresApproval: boolean
    }
  }
}

export type AuditEvidenceCheckpointStatus = 'SEALED' | 'ARCHIVED'

export interface AuditEvidenceCheckpointView {
  tenantId: string
  id: string
  filters: {
    sessionId?: string
    correlationId?: string
    type?: string
    actorId?: string
  }
  eventIds: string[]
  eventCount: number
  evidenceDigest: string
  status: AuditEvidenceCheckpointStatus
  createdBy: string
  updatedBy: string
  createdAt: string
  updatedAt: string
}
