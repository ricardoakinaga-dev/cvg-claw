import {
  CONTROLLED_LOCAL_SYNTHETIC_PROFILE,
  createControlledLocalCollector,
  resolveControlledLocalRoot,
  type CollectorExport,
  type ControlledLocalCollectorContext,
  type ControlledLocalCollectorRole,
  type ObservabilityCollectorPort
} from './collector.ts'

export const RUNTIME_COLLECTOR_FLUSH_INTERVAL_MS = 1_000
const CONFIGURATION_ERROR = 'Runtime telemetry configuration is invalid'
const EXPORT_ERROR = 'Controlled telemetry export failed'

export interface RuntimeCollectorFailure {
  event: 'telemetry.export_failed'
  role: ControlledLocalCollectorRole
  message: typeof EXPORT_ERROR
}

export interface RuntimeCollectorOptions {
  /** Bounded cadence; one batch per tick, with no concurrent exports. */
  flushIntervalMs?: number
  onError?: (failure: RuntimeCollectorFailure) => void
}

/** Explicit harness configuration only. Disabled mode does not touch disk. */
export function parseRuntimeCollectorConfig(
  env: NodeJS.ProcessEnv,
  role: ControlledLocalCollectorRole
): ControlledLocalCollectorContext | undefined {
  const mode = env.CVG_TELEMETRY_MODE ?? 'disabled'
  if (mode === 'disabled') return undefined
  if (
    mode !== 'local_file' ||
    (role !== 'api' && role !== 'worker') ||
    (env.NODE_ENV !== 'development' && env.NODE_ENV !== 'test') ||
    process.env.NODE_ENV === 'production' ||
    env.CVG_TELEMETRY_PROFILE !== CONTROLLED_LOCAL_SYNTHETIC_PROFILE ||
    [
      'ENABLE_REAL_CHANNELS',
      'ENABLE_REAL_RAG',
      'ENABLE_REAL_PAYMENTS',
      'ENABLE_REAL_MEDICAL_RECORDS'
    ].some((key) => env[key] === 'true')
  ) {
    throw new Error(CONFIGURATION_ERROR)
  }
  try {
    return Object.freeze({
      mode,
      profile: CONTROLLED_LOCAL_SYNTHETIC_PROFILE,
      root: resolveControlledLocalRoot(env.CVG_TELEMETRY_ROOT ?? ''),
      role
    })
  } catch {
    // Filesystem errors can contain paths, usernames or credentials. Never
    // hand their message/cause to a process startup logger.
    throw new Error(CONFIGURATION_ERROR)
  }
}

/**
 * Owns the local collector's timer and serializes every flush/close caller,
 * including the API's existing onClose hook. The factory retains the existing
 * sanitizer and its 512-record buffer / 256-record batch caps. The caller must
 * supply its own exclusive temporary root and stop producers before close().
 */
export function createRuntimeCollector(
  env: NodeJS.ProcessEnv,
  role: ControlledLocalCollectorRole,
  options: RuntimeCollectorOptions = {}
): ObservabilityCollectorPort | undefined {
  const context = parseRuntimeCollectorConfig(env, role)
  if (!context) return undefined
  const interval =
    options.flushIntervalMs ?? RUNTIME_COLLECTOR_FLUSH_INTERVAL_MS
  if (!Number.isInteger(interval) || interval < 100 || interval > 60_000) {
    throw new Error(CONFIGURATION_ERROR)
  }
  let collector: ObservabilityCollectorPort
  try {
    collector = createControlledLocalCollector(context)
  } catch {
    throw new Error(CONFIGURATION_ERROR)
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  let active: Promise<CollectorExport> | undefined
  let closing: Promise<void> | undefined

  const reportFailure = (): Error => {
    const failure: RuntimeCollectorFailure = {
      event: 'telemetry.export_failed',
      role,
      message: EXPORT_ERROR
    }
    if (options.onError) {
      try {
        options.onError(failure)
      } catch {
        console.error(JSON.stringify(failure))
      }
    } else {
      console.error(JSON.stringify(failure))
    }
    return new Error(EXPORT_ERROR)
  }

  const cancelTimer = (): void => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
  }
  const schedule = (): void => {
    if (closing !== undefined) return
    cancelTimer()
    timer = setTimeout(() => {
      timer = undefined
      // flush reports the generic failure; the timer must never generate an
      // unhandled rejection or start an overlapping retry.
      void flush().catch(() => undefined)
    }, interval)
    timer.unref?.()
  }
  const flush = (): Promise<CollectorExport> => {
    if (closing !== undefined) {
      return Promise.reject(new Error('Runtime telemetry collector is closed'))
    }
    if (active !== undefined) return active
    cancelTimer()
    active = Promise.resolve()
      .then(() => collector.flush())
      .catch(() => {
        throw reportFailure()
      })
      .finally(() => {
        active = undefined
        schedule()
      })
    return active
  }
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    cancelTimer()
    const pending = active
    closing = Promise.resolve().then(async () => {
      let failed = false
      try {
        await pending
      } catch {
        failed = true
      }
      try {
        // close seals and drains both bounded batches even after a failed
        // in-flight flush. It never races a write from the timer or API hook.
        await collector.close()
      } catch {
        failed = true
        reportFailure()
      }
      if (failed) throw new Error(EXPORT_ERROR)
    })
    return closing
  }
  schedule()
  return {
    kind: collector.kind,
    enabled: collector.enabled,
    recordSpan: (span) => {
      if (closing === undefined) collector.recordSpan(span)
    },
    recordMetric: (metric) => {
      if (closing === undefined) collector.recordMetric(metric)
    },
    recordLog: (log) => {
      if (closing === undefined) collector.recordLog(log)
    },
    redaction: () => collector.redaction(),
    flush,
    close
  }
}
