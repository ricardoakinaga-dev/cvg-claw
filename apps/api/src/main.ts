import { buildServerFromEnv, type RuntimeLogEntry } from './server.ts'
import { createConfiguredOperatorIdentityResolver } from './operator-identity.ts'
import { serializeStartupFailure } from './startup-failure.ts'
import { createShutdownController, parseEnv } from '@cvg/shared'
import { createRuntimeCollector } from '@cvg/observability'
import { assertProductionBootstrap } from '../../../scripts/lib/production-preflight-core.mjs'

async function start() {
  assertProductionBootstrap(process.env)
  parseEnv(process.env)
  const operatorIdentityResolver = createConfiguredOperatorIdentityResolver(
    process.env
  )
  const runtimeLogger = (entry: RuntimeLogEntry): void => {
    const line = JSON.stringify({ ...entry, stream: 'api.runtime' })
    if (entry.status === 'error') console.error(line)
    else console.log(line)
  }
  const runtimeCollector = createRuntimeCollector(process.env, 'api')
  let app: Awaited<ReturnType<typeof buildServerFromEnv>> | undefined
  try {
    app = await buildServerFromEnv(process.env, {
      ...(operatorIdentityResolver ? { operatorIdentityResolver } : {}),
      ...(runtimeCollector ? { runtimeCollector } : {}),
      runtimeLogger
    })
    const server = app
    const shutdown = createShutdownController({
      close: async () => {
        try {
          await server.close()
        } finally {
          await runtimeCollector?.close()
        }
      },
      exit: (code) => process.exit(code),
      log: (event) => {
        if (event.type !== 'shutdown.started') {
          console.error(
            JSON.stringify({ event: event.type, signal: event.signal })
          )
        }
      }
    })
    shutdown.install(process)
    const port = Number(process.env.PORT ?? 3000)
    await app.listen({ port, host: '0.0.0.0' })
  } catch (error) {
    // The collector may already be running when construction or listen fails.
    // Preserve the startup error while draining and stopping its timer.
    await app?.close().catch(() => undefined)
    await runtimeCollector?.close().catch(() => undefined)
    throw error
  }
}

start().catch((error) => {
  console.error(serializeStartupFailure(error))
  process.exit(1)
})
