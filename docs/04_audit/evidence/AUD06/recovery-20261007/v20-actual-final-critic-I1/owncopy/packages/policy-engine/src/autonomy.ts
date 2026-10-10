import type { Capability } from './capabilities.ts'

/**
 * Institutional execution classification (AGENTS / AUD06 Q03).
 * N0: information; N1: preparation subject to existing approval/effect gates;
 * N2: reversible low-risk autonomy, reserved and not granted by this catalog;
 * N3: always blocked, including with human approval or emergency context.
 *
 * The shared AutonomyLevel enum (level_1_collect / level_2_suggest) remains a
 * legacy conversation contract. It is not an execution authority and must not
 * be converted into an institutional grant or used to promote a capability.
 */
export type InstitutionalAutonomyLevel = 'N0' | 'N1' | 'N2' | 'N3'

/**
 * Canonical, exhaustive and immutable at runtime: values are primitives, so
 * freezing this object also protects every classification. There is no
 * runtime setter, tenant override or profile-dependent promotion. Changing a
 * classification requires the admitted PRD/SPEC and recorded human decision.
 * N0/N1 classifications do not authorize effects or replace existing grants,
 * approval floors, resource/action bindings or controlled effect scopes.
 */
export const CAPABILITY_AUTONOMY: Readonly<
  Record<Capability, InstitutionalAutonomyLevel>
> = Object.freeze({
  'schedule.read': 'N0',
  'appointment.create': 'N1',
  'appointment.modify': 'N1',
  'appointment.confirm': 'N1',
  'appointment.reschedule': 'N1',
  'appointment.cancel': 'N1',
  'conversation.read': 'N0',
  'message.draft': 'N1',
  'message.send': 'N1',
  'patient.summary.read': 'N0',
  'patient.record.read': 'N0',
  'patient.record.write': 'N3',
  'exam.read': 'N0',
  'exam.release': 'N3',
  'finance.read': 'N0',
  'finance.write': 'N3',
  'hospitalization.manage': 'N1',
  'clinical.diagnose': 'N3',
  'clinical.prescribe': 'N3',
  'admin.policy.manage': 'N1',
  'admin.agent.manage': 'N1'
})

export function capabilityAutonomyLevel(
  capability: Capability
): InstitutionalAutonomyLevel {
  return CAPABILITY_AUTONOMY[capability]
}

export function isN3Capability(capability: Capability): boolean {
  return capabilityAutonomyLevel(capability) === 'N3'
}
