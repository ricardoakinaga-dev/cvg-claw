import { describe, expect, it } from 'vitest'
import { AutonomyLevelSchema, RoleSchema } from '@cvg/shared'
import {
  AGENT_PROFILE_GRANTS,
  AgentProfileNameSchema,
  CapabilityGrantSchema,
  OPERATOR_ROLE_CAPABILITIES,
  canApproveCapability,
  grantFor,
  roleAllowsCapability,
  type CapabilityGrant
} from '../grants.ts'
import { CapabilitySchema, type Capability } from '../capabilities.ts'
import {
  CAPABILITY_AUTONOMY,
  capabilityAutonomyLevel,
  isN3Capability
} from '../autonomy.ts'
import { PolicyRegistry, type PolicyEffect } from '../documents.ts'
import { PolicyEngine, type PolicyEvaluationInput } from '../engine.ts'

// Independent institutional oracle: do not derive this list from grants or
// from the implementation being tested (AGENTS / AUD06 SPEC Q03).
const N3 = [
  'finance.write',
  'clinical.diagnose',
  'clinical.prescribe',
  'patient.record.write',
  'exam.release'
] as const satisfies readonly Capability[]
const TENANT = 'aud06_synthetic_tenant'
const NOW = new Date('2026-10-06T12:00:00.000Z')

function request(capability: Capability): PolicyEvaluationInput {
  return {
    tenantId: TENANT,
    operatorId: 'aud06_synthetic_operator',
    operatorRole: 'System',
    agentId: 'aud06_synthetic_agent',
    agentProfile: 'clinical',
    capability,
    action: capability,
    correlationId: 'corr_aud06_synthetic_policy'
  }
}

function overridePolicy(effect: PolicyEffect, tenantScoped: boolean) {
  const registry = new PolicyRegistry()
  registry.register({
    policyId: 'aud06.synthetic.override',
    version: '1',
    ...(tenantScoped ? { tenantId: TENANT } : {}),
    effectiveFrom: '2026-01-01T00:00:00.000Z',
    rules: [
      {
        id: 'maximum-priority-override',
        priority: 100,
        effect,
        reason: 'Synthetic attempt to override the institutional ceiling'
      }
    ]
  })
  return new PolicyEngine({ documents: registry.list(), clock: () => NOW })
}

describe('AUD06 Q03: irreducible institutional N3 ceiling', () => {
  it('classifies every capability without granting N2 or reinterpreting the legacy enum', () => {
    expect(Object.keys(CAPABILITY_AUTONOMY).sort()).toEqual(
      [...CapabilitySchema.options].sort()
    )
    expect(Object.isFrozen(CAPABILITY_AUTONOMY)).toBe(true)
    expect(Object.values(CAPABILITY_AUTONOMY)).not.toContain('N2')
    for (const capability of CapabilitySchema.options) {
      const blocked = (N3 as readonly Capability[]).includes(capability)
      expect(isN3Capability(capability)).toBe(blocked)
      expect(capabilityAutonomyLevel(capability)).toBe(
        blocked ? 'N3' : capability.endsWith('.read') ? 'N0' : 'N1'
      )
    }
    expect(AutonomyLevelSchema.options).toEqual([
      'level_1_collect',
      'level_2_suggest'
    ])
  })

  it.each(N3)(
    'cannot promote or delete the immutable classification of %s',
    (capability) => {
      for (const level of ['N0', 'N1', 'N2']) {
        expect(Reflect.set(CAPABILITY_AUTONOMY, capability, level)).toBe(false)
        expect(
          Reflect.defineProperty(CAPABILITY_AUTONOMY, capability, {
            value: level
          })
        ).toBe(false)
      }
      expect(Reflect.deleteProperty(CAPABILITY_AUTONOMY, capability)).toBe(
        false
      )
      expect(capabilityAutonomyLevel(capability)).toBe('N3')
      expect(
        new PolicyEngine({ clock: () => NOW }).evaluate(request(capability))
          .decision
      ).toBe('DENY')
    }
  )

  it.each(N3)(
    'denies %s across roles, profiles, policies and emergency context',
    (capability) => {
      const policies = [
        new PolicyEngine({ clock: () => NOW }),
        overridePolicy('ALLOW', false),
        overridePolicy('ALLOW', true),
        overridePolicy('REQUIRE_APPROVAL', false)
      ]
      const contexts: PolicyEvaluationInput['context'][] = [
        undefined,
        {},
        { emergency: false, medicalOperator: false },
        { emergency: true },
        { medicalOperator: true },
        { emergency: true, medicalOperator: true }
      ]
      for (const policy of policies) {
        for (const operatorRole of RoleSchema.options) {
          for (const agentProfile of AgentProfileNameSchema.options) {
            for (const context of contexts) {
              const decision = policy.evaluate({
                ...request(capability),
                operatorRole,
                agentProfile,
                ...(context === undefined ? {} : { context })
              })
              expect(
                decision,
                `${capability}/${operatorRole}/${agentProfile}`
              ).toMatchObject({
                decision: 'DENY',
                reason: 'autonomy_n3_blocked',
                policyId: 'builtin.deny_by_default',
                capability,
                risk: 'HIGH_RISK_WRITE',
                correlationId: 'corr_aud06_synthetic_policy',
                evaluatedAt: NOW.toISOString()
              })
            }
          }
        }
      }
    }
  )

  it.each(N3)(
    'offers no profile, role or approval grant for %s',
    (capability) => {
      for (const level of ['allow', 'require_approval']) {
        expect(
          CapabilityGrantSchema.safeParse({ capability, level }).success
        ).toBe(false)
      }
      for (const profile of AgentProfileNameSchema.options) {
        expect(
          AGENT_PROFILE_GRANTS[profile].map((grant) => grant.capability)
        ).not.toContain(capability)
        expect(grantFor(profile, capability)).toBeUndefined()
      }
      for (const role of RoleSchema.options) {
        expect(OPERATOR_ROLE_CAPABILITIES[role]).not.toContain(capability)
        expect(roleAllowsCapability(role, capability)).toBe(false)
        expect(canApproveCapability(role, capability)).toBe(false)
      }
    }
  )

  it('keeps non-N3 grant schema validation and approval authority intact', () => {
    expect(
      CapabilityGrantSchema.safeParse({
        capability: 'schedule.read',
        level: 'allow'
      }).success
    ).toBe(true)
    expect(
      CapabilityGrantSchema.safeParse({
        capability: 'appointment.cancel',
        level: 'require_approval'
      }).success
    ).toBe(true)
    expect(canApproveCapability('Approver', 'appointment.cancel')).toBe(true)
    expect(canApproveCapability('Operator', 'appointment.cancel')).toBe(false)
  })

  it.each(N3)(
    'cannot regrant %s through mutable legacy grant tables',
    (capability) => {
      const grants = AGENT_PROFILE_GRANTS.clinical as CapabilityGrant[]
      const roles = OPERATOR_ROLE_CAPABILITIES.System as Capability[]
      const grantCount = grants.length
      const roleCount = roles.length
      try {
        // Simulate stale configuration without mocking the authorization engine.
        grants.push({ capability, level: 'allow' })
        roles.push(capability)
        expect(
          overridePolicy('ALLOW', true).evaluate(request(capability))
        ).toMatchObject({
          decision: 'DENY',
          reason: 'autonomy_n3_blocked'
        })
        expect(grantFor('clinical', capability)).toBeUndefined()
        expect(roleAllowsCapability('System', capability)).toBe(false)
        expect(canApproveCapability('System', capability)).toBe(false)
      } finally {
        grants.splice(grantCount)
        roles.splice(roleCount)
      }
    }
  )
})
