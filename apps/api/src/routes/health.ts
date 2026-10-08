import type { FastifyInstance } from 'fastify'
import { createCorrelationId, fail, ok } from '@cvg/shared'
import {
  evaluateReadinessWithProbes,
  type ReadinessProbeInput
} from '../readiness.ts'
import type { ControlledRequestMetrics } from '../request-metrics.ts'

export const healthRoute = '/health'
export const liveRoute = '/live'
export const readyRoute = '/ready'

/** Owns only the public health/readiness contracts, after global HTTP hooks. */
export function registerHealthRoutes(
  app: FastifyInstance,
  options: {
    readiness: () => ReadinessProbeInput
    metrics: ControlledRequestMetrics
    metricsEnabled: boolean
  }
): void {
  app.get(healthRoute, async () =>
    ok({ status: 'ok', runtime: 'api' }, createCorrelationId())
  )
  app.get(liveRoute, async () =>
    ok({ status: 'ok', runtime: 'api', probe: 'live' }, createCorrelationId())
  )
  app.get(readyRoute, async (_request, reply) => {
    const readiness = await evaluateReadinessWithProbes(options.readiness())
    reply.header('cache-control', 'no-store')
    reply.code(readiness.ready ? 200 : 503)
    return ok(readiness, createCorrelationId())
  })
  app.get('/health/metrics', async (_request, reply) => {
    const correlationId = createCorrelationId()
    reply.header('cache-control', 'no-store')
    if (!options.metricsEnabled) {
      reply.code(404)
      return fail('invalid_action', 'Not found', correlationId)
    }
    return ok({ metrics: options.metrics.snapshot() }, correlationId)
  })
}
