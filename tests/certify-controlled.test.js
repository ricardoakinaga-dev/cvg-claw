// @vitest-environment node
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const runner = join(root, 'scripts/certify-controlled.sh')
const historical = join(
  root,
  'docs/04_audit/evidence/CLAW-reseal/certify-pass.sh'
)
const fixtures = []
const playwrightImage =
  'mcr.microsoft.com/playwright:v1.59.1-noble@sha256:b0ab6f3cb99aa7803adbc14d9027ec1785fc6e433b97e134e0f8fe61683b6b53'

// A real executable boundary: every Docker invocation is intercepted on PATH.
// Container state lives only in temporary files; no Docker daemon is contacted.
const fakeDocker = `#!/usr/bin/env node
const fs = require('node:fs')
const path = require('node:path')
const { randomBytes } = require('node:crypto')
const { spawn } = require('node:child_process')
const args = process.argv.slice(2)
const dir = process.env.FAKE_DOCKER_STATE
const record = (event) => fs.appendFileSync(path.join(dir, 'events'), JSON.stringify({ at: Date.now(), ...event }) + '\\n')
const value = (flag) => args[args.indexOf(flag) + 1]
const load = (id) => JSON.parse(fs.readFileSync(path.join(dir, id), 'utf8'))
const save = (entry) => fs.writeFileSync(path.join(dir, entry.id), JSON.stringify(entry))
record({ event: 'call', args, pid: process.pid })
const hang = () => {
  process.on('SIGTERM', () => {})
  const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); console.log("ready"); setInterval(() => {}, 1000)'], { stdio: ['ignore', 'pipe', 'ignore'] })
  child.stdout.once('data', () => record({ event: 'child-ready', pid: process.pid, childPid: child.pid }))
  setInterval(() => {}, 1000)
}
const stalled = (stage) => {
  record({ event: 'stalled', stage })
  hang()
}
const status = () => process.env.FAKE_CERT_SIGNAL
  ? ({ SIGTERM: 143, SIGKILL: 137 })[process.env.FAKE_CERT_SIGNAL]
  : Number(process.env.FAKE_CERT_EXIT || 0)
const finish = (entry, attached) => {
  const output = () => {
    record({ event: 'workload-exit', id: entry.id, code: status() })
    if (attached) process.exit(status())
    else console.log(process.env.FAKE_WAIT_OUTPUT ?? status())
  }
  if (process.env.FAKE_HANG === 'cert') hang()
  else setTimeout(output, Math.max(0, entry.startedAt + Number(process.env.FAKE_WORKLOAD_MS || 0) - Date.now()))
}
if (args[0] === 'run' || args[0] === 'create') {
  const kind = args.includes('postgres:16-alpine') ? 'pg' : 'cert'
  if (kind === 'cert' && process.env.FAKE_STALL_STAGE === 'create-before') {
    stalled('create-before')
    return
  }
  if (process.env.FAKE_FAIL_CREATE === kind) process.exit(23)
  const id = randomBytes(32).toString('hex')
  const name = args.includes('--name') ? value('--name') : id
  const entry = { id, name, kind }
  save(entry)
  if (args.includes('--cidfile')) fs.writeFileSync(value('--cidfile'), id)
  record({ event: 'created', id, name, kind })
  if (kind === 'cert' && process.env.FAKE_STALL_STAGE === 'create-after') {
    stalled('create-after')
    return
  }
  if (args[0] === 'create') {
    setTimeout(() => console.log(id), Number(process.env.FAKE_CREATE_DELAY_MS || 0))
    return
  }
  if (process.env.FAKE_FAIL_START === kind) process.exit(24)
  if (kind === 'cert' && process.env.FAKE_STALL_STAGE === 'start') {
    stalled('start')
    return
  }
  if (process.env.FAKE_HANG === kind) hang()
  else if (kind === 'pg') console.log(id)
  else finish({ ...entry, startedAt: Date.now() }, true)
} else if (args[0] === 'start') {
  const entry = load(args.at(-1))
  if (process.env.FAKE_STALL_STAGE === 'start') {
    stalled('start')
    return
  }
  if (process.env.FAKE_FAIL_START === entry.kind) process.exit(24)
  setTimeout(() => {
    entry.startedAt = Date.now()
    save(entry)
    record({ event: 'started', id: entry.id })
    console.log(entry.id)
  }, Number(process.env.FAKE_START_DELAY_MS || 0))
} else if (args[0] === 'wait') {
  const entry = load(args.at(-1))
  if (!entry.startedAt) process.exit(98)
  if (process.env.FAKE_WAIT_SIGNAL) process.kill(process.pid, process.env.FAKE_WAIT_SIGNAL)
  else if (process.env.FAKE_WAIT_ERROR) process.exit(Number(process.env.FAKE_WAIT_ERROR))
  else finish(entry, false)
} else if (args[0] === 'logs') {
  if (process.env.FAKE_LOGS_ERROR) process.exit(Number(process.env.FAKE_LOGS_ERROR))
  if (process.env.FAKE_HANG_LOGS) hang()
  else {
    console.log('synthetic certification stdout')
    console.error('synthetic certification stderr')
  }
} else if (args[0] === 'port') {
  if (process.env.FAKE_PORT_FAIL) process.exit(29)
  console.log(process.env.FAKE_BAD_PORT ? '0.0.0.0:5432' : '127.0.0.1:54321')
} else if (args[0] === 'exec') {
  if (args.includes('pg_isready')) {
    if (process.env.FAKE_HANG === 'readiness') hang()
    else process.exit(process.env.FAKE_NOT_READY ? 1 : 0)
  } else console.log('0')
} else if (args[0] === 'rm') {
  for (const requested of args.slice(1).filter((arg) => arg !== '-f' && arg !== '--')) {
    const entry = fs.readdirSync(dir).filter((file) => /^[a-f0-9]{64}$/.test(file))
      .map((file) => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')))
      .find((item) => item.id === requested || item.name === requested)
    record({ event: 'removed', requested, id: entry?.id })
    if (process.env.FAKE_CLEANUP_FAIL) process.exit(58)
    if (!entry) process.exit(97)
    fs.unlinkSync(path.join(dir, entry.id))
  }
} else process.exit(96)
`

function fixture({ legacy = false, env = {} } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'cvg-certify-test-'))
  // Spaces, quotes and shell metacharacters exercise argv handling.
  const repo = join(directory, "repo 'quoted' $literal")
  const bin = join(directory, 'bin')
  const state = join(directory, 'docker')
  mkdirSync(join(repo, 'scripts'), { recursive: true })
  mkdirSync(bin)
  mkdirSync(state)
  const source = legacy ? historical : runner
  const script = join(repo, 'scripts', 'certify-controlled.sh')
  copyFileSync(source, script)
  writeFileSync(join(bin, 'docker'), fakeDocker, { mode: 0o755 })
  // Only the frozen wrapper has an unconditional two-second sleep.
  if (legacy)
    writeFileSync(join(bin, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  const unrelatedId = 'f'.repeat(64)
  writeFileSync(
    join(state, unrelatedId),
    JSON.stringify({ id: unrelatedId, name: 'claw-cert-pg', kind: 'unrelated' })
  )
  const log = join(directory, 'certification.log')
  const handle = {
    directory,
    repo,
    state,
    log,
    unrelatedId,
    events: () =>
      existsSync(join(state, 'events'))
        ? readFileSync(join(state, 'events'), 'utf8')
            .trim()
            .split('\n')
            .filter(Boolean)
            .map((line) => JSON.parse(line))
        : [],
    start: (args = [log]) => {
      const child = spawn('bash', [script, ...args], {
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          FAKE_DOCKER_STATE: state,
          DATABASE_URL: 'postgres://forbidden-inherited.invalid/real',
          TEST_DATABASE_URL: 'postgres://forbidden-inherited.invalid/real',
          CERTIFY_STARTUP_TIMEOUT_SECONDS: '2',
          CERTIFY_CLEANUP_TIMEOUT_SECONDS: '2',
          ...env
        },
        stdio: ['ignore', 'pipe', 'pipe']
      })
      handle.child = child
      let output = ''
      child.stdout.on('data', (data) => (output += data))
      child.stderr.on('data', (data) => (output += data))
      handle.done = new Promise((resolve, reject) => {
        child.once('error', reject)
        child.once('close', (code, signal) => {
          handle.result = { code, signal, output }
          resolve(handle.result)
        })
      })
      return handle.done
    }
  }
  fixtures.push(handle)
  return handle
}

function running(pid) {
  try {
    process.kill(pid, 0)
    // Orphan zombies are terminated, awaiting reaping by the environment's PID 1.
    return !/\) Z /.test(readFileSync(`/proc/${pid}/stat`, 'utf8'))
  } catch {
    return false
  }
}

async function waitFor(predicate) {
  const deadline = Date.now() + 5000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('fixture observation timed out')
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
}

function expectOwnCleanup(handle, { cleanupFailed = false } = {}) {
  const events = handle.events()
  const created = events.filter((event) => event.event === 'created')
  const removed = events.filter((event) => event.event === 'removed')
  expect(removed.map((event) => event.requested).sort()).toEqual(
    created.map((event) => event.id).sort()
  )
  expect(existsSync(join(handle.state, handle.unrelatedId))).toBe(true)
  if (!cleanupFailed)
    for (const event of created)
      expect(existsSync(join(handle.state, event.id))).toBe(false)
  for (const event of events.filter((event) => event.event === 'child-ready')) {
    expect(running(event.pid)).toBe(false)
    expect(running(event.childPid)).toBe(false)
  }
}

afterEach(async () => {
  for (const handle of fixtures.splice(0)) {
    if (handle.child?.exitCode === null && handle.child?.signalCode === null) {
      handle.child.kill('SIGTERM')
      await Promise.race([
        handle.done,
        new Promise((resolve) => setTimeout(resolve, 3000))
      ])
      if (handle.child.exitCode === null && handle.child.signalCode === null)
        handle.child.kill('SIGKILL')
    }
    for (const event of handle.events()) {
      if (event.event === 'child-ready')
        for (const pid of [event.pid, event.childPid])
          if (running(pid)) process.kill(pid, 'SIGKILL')
    }
    if (process.env.CERTIFY_TEST_EVIDENCE_DIR) {
      const destination = join(
        process.env.CERTIFY_TEST_EVIDENCE_DIR,
        handle.directory.split('/').at(-1)
      )
      mkdirSync(destination, { recursive: true })
      writeFileSync(
        join(destination, 'observations.json'),
        JSON.stringify(
          { events: handle.events(), result: handle.result },
          null,
          2
        )
      )
      if (existsSync(handle.log))
        copyFileSync(handle.log, join(destination, 'runner.log'))
    }
    rmSync(handle.directory, { recursive: true, force: true })
  }
})

describe('AUD06-05 controlled certification runner', () => {
  it('records historical RED: exit 37 is masked and a foreign name is removed', async () => {
    expect(
      createHash('sha256').update(readFileSync(historical)).digest('hex')
    ).toBe('b371d11dff92b92adc649d89684e957dda02bfea5e8a86836eb6611eaa71e572')
    const handle = fixture({ legacy: true, env: { FAKE_CERT_EXIT: '37' } })
    expect((await handle.start()).code).toBe(0)
    expect(readFileSync(handle.log, 'utf8')).toContain('certify exit 37')
    expect(existsSync(join(handle.state, handle.unrelatedId))).toBe(false)
  })

  it('has a canonical runner', () => {
    expect(existsSync(runner)).toBe(true)
  })

  it.each([0, 37, 125])(
    'preserves certification exit %i and cleans only its resources',
    async (code) => {
      const handle = fixture({ env: { FAKE_CERT_EXIT: String(code) } })
      expect((await handle.start()).code).toBe(code)
      expectOwnCleanup(handle)
      expect(readFileSync(handle.log, 'utf8')).toContain(`runner exit ${code}`)
      const calls = handle.events().filter((event) => event.event === 'call')
      const pg = calls.find((event) =>
        event.args.includes('postgres:16-alpine')
      )
      const cert = calls.find((event) => event.args.includes(playwrightImage))
      expect(pg.args).toContain('127.0.0.1::5432')
      expect(cert.args).toContain(handle.repo)
      expect(cert.args).toContain(`${handle.repo}:${handle.repo}`)
      expect(cert.args.join(' ')).not.toContain('forbidden-inherited')
      expect(cert.args).toContain(
        'TEST_DATABASE_URL=postgres://postgres:throwaway-cert-pass@127.0.0.1:54321/postgres'
      )
    }
  )

  it.each([
    ['database creation', { FAKE_FAIL_CREATE: 'pg' }, 23],
    ['database start after creation', { FAKE_FAIL_START: 'pg' }, 24],
    ['certification creation', { FAKE_FAIL_CREATE: 'cert' }, 23],
    ['certification start after creation', { FAKE_FAIL_START: 'cert' }, 24],
    ['port discovery', { FAKE_PORT_FAIL: '1' }, 29],
    ['non-loopback port', { FAKE_BAD_PORT: '1' }, 65],
    ['readiness timeout', { FAKE_NOT_READY: '1' }, 124],
    ['hung database startup', { FAKE_HANG: 'pg' }, 124],
    ['hung readiness subprocess', { FAKE_HANG: 'readiness' }, 124],
    ['terminated certification child', { FAKE_CERT_SIGNAL: 'SIGTERM' }, 143],
    ['killed certification child', { FAKE_CERT_SIGNAL: 'SIGKILL' }, 137]
  ])('propagates %s failure with cleanup', async (_label, env, code) => {
    const handle = fixture({
      env: { CERTIFY_STARTUP_TIMEOUT_SECONDS: '2', ...env }
    })
    expect((await handle.start()).code).toBe(code)
    expectOwnCleanup(handle)
  })

  it('uses the exact Playwright digest pinned by Verify', () => {
    const workflow = readFileSync(
      join(root, '.github/workflows/verify.yml'),
      'utf8'
    )
    const pinned = workflow.match(
      /^\s+image: (mcr\.microsoft\.com\/playwright:[^\s]+)$/m
    )?.[1]
    expect(pinned).toBe(playwrightImage)
    expect(readFileSync(runner, 'utf8')).toContain(playwrightImage)
  })

  it.each(['create-before', 'create-after', 'start'])(
    'bounds stalled certification %s without entering workload wait',
    async (stage) => {
      const handle = fixture({
        env: { CERTIFY_STARTUP_TIMEOUT_SECONDS: '2', FAKE_STALL_STAGE: stage }
      })
      const startedAt = Date.now()
      let watchdog
      try {
        const result = await Promise.race([
          handle.start(),
          new Promise((_resolve, reject) => {
            // Includes the startup deadline plus TERM/KILL and cleanup grace.
            // This observer fails the old runner; it does not impose its exit.
            watchdog = setTimeout(
              () =>
                reject(
                  new Error(
                    'startup remained alive beyond its deadline and cleanup grace'
                  )
                ),
              7000
            )
          })
        ])
        expect(result.code).toBe(124)
        expect(Date.now() - startedAt).toBeLessThan(7000)
        const events = handle.events()
        expect(
          events.some(
            (event) => event.event === 'stalled' && event.stage === stage
          )
        ).toBe(true)
        expect(
          events.filter((event) => event.event === 'created')
        ).toHaveLength(stage === 'create-before' ? 1 : 2)
        expect(
          events.some(
            (event) => event.event === 'call' && event.args[0] === 'wait'
          )
        ).toBe(false)
        expectOwnCleanup(handle)
      } finally {
        clearTimeout(watchdog)
      }
    }
  )

  it.each([0, 37])(
    'lets legitimate workload outlast startup and retain exit %i',
    async (code) => {
      const handle = fixture({
        env: {
          CERTIFY_STARTUP_TIMEOUT_SECONDS: '2',
          FAKE_WORKLOAD_MS: '3200',
          FAKE_CERT_EXIT: String(code)
        }
      })
      expect((await handle.start()).code).toBe(code)
      const events = handle.events()
      const started = events.find((event) => event.event === 'started')
      const finished = events.find((event) => event.event === 'workload-exit')
      expect(finished.at - started.at).toBeGreaterThanOrEqual(3100)
      expect(finished.code).toBe(code)
      const log = readFileSync(handle.log, 'utf8')
      expect(log).toContain(`certify exit ${code}`)
      expect(log).toContain('synthetic certification stdout')
      expect(log).toContain('synthetic certification stderr')
      expectOwnCleanup(handle)
    }
  )

  it('shares one startup budget across create and start instead of resetting it', async () => {
    const handle = fixture({
      env: {
        CERTIFY_STARTUP_TIMEOUT_SECONDS: '3',
        FAKE_CREATE_DELAY_MS: '1100',
        FAKE_START_DELAY_MS: '2100'
      }
    })
    expect((await handle.start()).code).toBe(124)
    const calls = handle.events().filter((event) => event.event === 'call')
    expect(calls.some((event) => event.args[0] === 'create')).toBe(true)
    expect(calls.some((event) => event.args[0] === 'start')).toBe(true)
    expect(calls.some((event) => event.args[0] === 'wait')).toBe(false)
    expectOwnCleanup(handle)
  })

  it.each(['create-before', 'start'])(
    'honors cancellation during stalled %s',
    async (stage) => {
      const handle = fixture({ env: { FAKE_STALL_STAGE: stage } })
      const done = handle.start()
      await waitFor(() =>
        handle.events().some((event) => event.event === 'child-ready')
      )
      handle.child.kill('SIGTERM')
      expect((await done).code).toBe(143)
      expectOwnCleanup(handle)
    }
  )

  it.each([
    ['wait transport', { FAKE_WAIT_ERROR: '42' }, 42],
    ['wait SIGTERM', { FAKE_WAIT_SIGNAL: 'SIGTERM' }, 143],
    ['wait SIGKILL', { FAKE_WAIT_SIGNAL: 'SIGKILL' }, 137],
    ['empty result', { FAKE_WAIT_OUTPUT: '' }, 65],
    ['invalid result', { FAKE_WAIT_OUTPUT: 'not-an-exit' }, 65],
    ['multiple results', { FAKE_WAIT_OUTPUT: '0\n37' }, 65],
    ['out-of-range result', { FAKE_WAIT_OUTPUT: '256' }, 65]
  ])(
    'preserves %s failure without claiming certification success',
    async (_label, env, code) => {
      const handle = fixture({ env })
      expect((await handle.start()).code).toBe(code)
      expect(readFileSync(handle.log, 'utf8')).not.toContain('certify exit 0')
      expectOwnCleanup(handle)
    }
  )

  it('preserves the workload result when log collection fails', async () => {
    const handle = fixture({
      env: { FAKE_CERT_EXIT: '37', FAKE_LOGS_ERROR: '28' }
    })
    expect((await handle.start()).code).toBe(37)
    expect(readFileSync(handle.log, 'utf8')).toContain('log collection failed')
    expectOwnCleanup(handle)
  })

  it('bounds stalled log collection while preserving the completed workload result', async () => {
    const handle = fixture({
      env: { FAKE_CERT_EXIT: '37', FAKE_HANG_LOGS: '1' }
    })
    expect((await handle.start()).code).toBe(37)
    expect(readFileSync(handle.log, 'utf8')).toContain('log collection failed')
    expectOwnCleanup(handle)
  })

  it('preserves successful workload status and reports failed cleanup honestly', async () => {
    const handle = fixture({ env: { FAKE_CLEANUP_FAIL: '1' } })
    expect((await handle.start()).code).toBe(0)
    expect(readFileSync(handle.log, 'utf8')).toContain('cleanup failed')
    expectOwnCleanup(handle, { cleanupFailed: true })
  })

  it.each([
    ['SIGINT', 130],
    ['SIGTERM', 143],
    ['SIGHUP', 129]
  ])('cleans containers and child processes on %s', async (signal, code) => {
    const handle = fixture({ env: { FAKE_HANG: 'cert' } })
    const done = handle.start()
    await waitFor(() =>
      handle.events().some((event) => event.event === 'child-ready')
    )
    handle.child.kill(signal)
    expect((await done).code).toBe(code)
    expectOwnCleanup(handle)
  })

  it('uses distinct names across concurrent invocations', async () => {
    const first = fixture()
    const second = fixture()
    const results = await Promise.all([first.start(), second.start()])
    expect(results.map((result) => result.code)).toEqual([0, 0])
    const names = [...first.events(), ...second.events()]
      .filter((event) => event.event === 'created')
      .map((event) => event.name)
    expect(new Set(names).size).toBe(4)
    expectOwnCleanup(first)
    expectOwnCleanup(second)
  })

  it('retains the certification failure when Docker cleanup also fails', async () => {
    const handle = fixture({
      env: { FAKE_CERT_EXIT: '37', FAKE_CLEANUP_FAIL: '1' }
    })
    expect((await handle.start()).code).toBe(37)
    expectOwnCleanup(handle, { cleanupFailed: true })
    expect(readFileSync(handle.log, 'utf8')).toContain('cleanup failed')
  })

  it('rejects an invalid startup budget before contacting Docker', async () => {
    const handle = fixture({
      env: { CERTIFY_STARTUP_TIMEOUT_SECONDS: 'unbounded' }
    })
    expect((await handle.start()).code).toBe(64)
    expect(handle.events()).toEqual([])
  })
})
