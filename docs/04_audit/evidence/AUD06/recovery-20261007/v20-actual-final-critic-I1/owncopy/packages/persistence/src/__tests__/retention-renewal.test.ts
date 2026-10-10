// @vitest-environment node
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  INBOUND_TOMBSTONE_HORIZON_DAYS,
  INBOUND_TOMBSTONE_POLICY_APPROVAL_REF,
  INBOUND_TOMBSTONE_POLICY_APPROVED_AT,
  INBOUND_TOMBSTONE_POLICY_VALID_UNTIL,
  INBOUND_TOMBSTONE_POLICY_VERSION,
  RETENTION_TARGETS,
  assertInboundTombstonePolicyEffective
} from '../retention.ts'

const renewalRef =
  'docs/04_audit/evidence/CLAW-W1/CLAW-W1-07-tombstone-policy-renewal-decision-20261005.json'
const renewal = JSON.parse(
  readFileSync(resolve(process.cwd(), renewalRef), 'utf8')
)
const validUntil = Date.parse('2027-07-01T02:59:59.000Z')
const approvedAt = Date.parse('2026-10-05T12:00:42.000Z')
const warningWindowMs = 30 * 86_400_000

// This is a maintenance sentinel, not a change to the operational policy:
// CI must demand a new human decision before the current approval expires.
function assertRenewalNotDue(now: Date): void {
  expect(
    now.getTime(),
    `Renew tombstone approval: 30-day warning for ${INBOUND_TOMBSTONE_POLICY_VALID_UNTIL}`
  ).toBeLessThan(
    Date.parse(INBOUND_TOMBSTONE_POLICY_VALID_UNTIL) - warningWindowMs
  )
}

describe('AUD06-06 synthetic tombstone renewal', () => {
  it('binds constants to the exact approved renewal receipt', () => {
    expect(renewal.status).toBe('APPROVED')
    expect(renewal.environmentAndEffectScope).toBe(
      'CONTROLLED_LOCAL_SYNTHETIC_ONLY'
    )
    expect(renewal.policyRulesChanged).toBe(false)
    expect(renewal.releaseEligible).toBe(false)
    expect(INBOUND_TOMBSTONE_POLICY_APPROVAL_REF).toBe(renewalRef)
    expect(INBOUND_TOMBSTONE_POLICY_APPROVED_AT).toBe(
      new Date(renewal.decidedAt).toISOString()
    )
    expect(INBOUND_TOMBSTONE_POLICY_APPROVED_AT).toBe(
      '2026-10-05T12:00:42.000Z'
    )
    expect(INBOUND_TOMBSTONE_POLICY_VALID_UNTIL).toBe(
      new Date(renewal.validUntil).toISOString()
    )
    expect(INBOUND_TOMBSTONE_POLICY_VALID_UNTIL).toBe(
      '2027-07-01T02:59:59.000Z'
    )
    expect(INBOUND_TOMBSTONE_POLICY_VERSION).toBe(renewal.policyVersion)
  })

  it.each([
    ['the approval instant', approvedAt],
    ['one millisecond after approval', approvedAt + 1],
    ['the previous expiry', Date.parse('2027-01-01T02:59:59.000Z')],
    ['the renewed interval', Date.parse('2027-01-01T03:00:00.000Z')],
    ['one millisecond before expiry', validUntil - 1],
    ['the inclusive expiry instant', validUntil]
  ])('accepts %s', (_label, milliseconds) => {
    expect(() =>
      assertInboundTombstonePolicyEffective(new Date(milliseconds))
    ).not.toThrow()
  })

  it('rejects the millisecond before renewal approval', () => {
    expect(() =>
      assertInboundTombstonePolicyEffective(new Date(approvedAt - 1))
    ).toThrow('approval is not effective')
  })

  it('rejects the millisecond after expiry', () => {
    expect(() =>
      assertInboundTombstonePolicyEffective(new Date(validUntil + 1))
    ).toThrow('approval has expired')
  })

  it('preserves the 30-day horizon and protected UNCERTAIN states', () => {
    expect(INBOUND_TOMBSTONE_HORIZON_DAYS).toBe(30)
    expect(INBOUND_TOMBSTONE_HORIZON_DAYS).toBe(
      renewal.postTombstoneHorizonDays
    )
    for (const id of [
      'effect_journal',
      'runtime_approvals',
      'orchestrator_goals'
    ]) {
      const target = RETENTION_TARGETS.find((entry) => entry.id === id)!
      expect(target.neverExpireStates).toContain('UNCERTAIN')
      expect(target.eligibleStates).not.toContain('UNCERTAIN')
    }
    expect(
      RETENTION_TARGETS.find((target) => target.id === 'inbound_idempotency')
        ?.retentionMode
    ).toBe('tombstone')
  })

  it('fails the maintenance sentinel exactly 30 days before expiry', () => {
    const warningAt = validUntil - warningWindowMs
    expect(() => assertRenewalNotDue(new Date(warningAt - 1))).not.toThrow()
    expect(() => assertRenewalNotDue(new Date(warningAt))).toThrow(
      '30-day warning'
    )
    expect(() => assertRenewalNotDue(new Date(warningAt + 1))).toThrow(
      '30-day warning'
    )
    // Warning does not revoke the still-effective policy prematurely.
    expect(() =>
      assertInboundTombstonePolicyEffective(new Date(warningAt))
    ).not.toThrow()
  })

  it('has more than 30 days left on the actual maintenance clock', () => {
    assertRenewalNotDue(new Date())
  })
})
