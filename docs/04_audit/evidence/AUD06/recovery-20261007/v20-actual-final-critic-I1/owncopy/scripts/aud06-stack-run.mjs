#!/usr/bin/env node
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  TELEMETRY_SERVICES,
  TELEMETRY_CANARY,
  prepareTelemetryDirectories,
  readTelemetryFile,
  assertTelemetryRetained
} from './aud06-stack-telemetry.mjs'

const labelKey = 'org.cvg.aud06.run'
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex')
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export function assertResourceOwnership(name, labels, runId) {
  assert.match(runId, /^cvg-aud06-stack-[a-z0-9-]{5,64}$/)
  assert.ok(
    name.replace(/^\//, '').startsWith(`${runId}-`),
    'foreign resource name'
  )
  assert.equal(labels?.[labelKey], runId, 'foreign resource label')
}

export async function removeOwnedResource({ name, runId, inspect, remove }) {
  const labels = await inspect(name)
  assertResourceOwnership(name, labels, runId)
  await remove(name)
}

export function assertSecurityHeaders(headers, tls = true) {
  assert.ok(headers['content-security-policy'], 'CSP missing')
  assert.equal(headers['x-content-type-options'], 'nosniff')
  assert.equal(headers['x-frame-options'], 'DENY')
  assert.equal(headers['referrer-policy'], 'no-referrer')
  if (tls)
    assert.match(headers['strict-transport-security'] ?? '', /max-age=[1-9]\d*/)
}

export function assertRestoreIntegrity(source, restored) {
  assert.ok(
    source.tables?.length > 0,
    'empty fingerprint cannot qualify a restore'
  )
  assert.ok(
    source.tables.some(
      (table) => table.relname === 'outbox_events' && table.count === 2
    ),
    'durable fixtures missing'
  )
  assert.deepEqual(restored, source, 'restored rows, schema or hashes differ')
}

function snapshot(root, destination) {
  const manifest = []
  function copy(relative) {
    const source = path.join(root, relative)
    const stat = fs.lstatSync(source)
    assert.ok(
      !stat.isSymbolicLink(),
      `build input symlink refused: ${relative}`
    )
    const basename = path.basename(relative)
    if (
      ['node_modules', '__tests__', 'dist', '.git'].includes(basename) ||
      /^\.env(?:\.|$)/.test(basename) ||
      /\.(pem|key|crt|p12|pfx|tsbuildinfo)$/.test(basename)
    )
      return
    const target = path.join(destination, relative)
    if (stat.isDirectory()) {
      fs.mkdirSync(target, { recursive: true })
      for (const name of fs.readdirSync(source).sort())
        copy(path.join(relative, name))
    } else if (stat.isFile()) {
      fs.mkdirSync(path.dirname(target), { recursive: true })
      const bytes = fs.readFileSync(source)
      fs.writeFileSync(target, bytes, { mode: stat.mode & 0o777 })
      manifest.push({ path: relative, sha256: sha(bytes) })
    }
  }
  for (const relative of [
    'Dockerfile',
    '.dockerignore',
    'package.json',
    'package-lock.json',
    'tsconfig.base.json',
    'tsconfig.json',
    'tsconfig.typecheck.json',
    'vite.config.mts',
    'apps',
    'packages',
    'deploy/aud06',
    'scripts/lib/production-preflight-core.mjs',
    'scripts/aud06-migrate.ts',
    'scripts/aud06-stack-db.ts',
    'scripts/aud06-stack-telemetry.mjs',
    'scripts/aud06-stack-run.mjs'
  ])
    copy(relative)
  return manifest.sort((a, b) => a.path.localeCompare(b.path))
}

async function freePort() {
  const server = net.createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const port = server.address().port
  await new Promise((resolve) => server.close(resolve))
  assert.ok(![3199, 4173].includes(port))
  return port
}

function request(url, ca, headers = {}) {
  return new Promise((resolve, reject) => {
    const secure = url.startsWith('https:')
    const req = (secure ? https : http).request(
      url,
      {
        ca,
        headers,
        // DNS-independent loopback binding, retaining localhost hostname verification.
        family: 4,
        agent: false,
        rejectUnauthorized: true,
        timeout: 8_000
      },
      (res) => {
        const chunks = []
        const tls = secure
          ? {
              authorized: res.socket.authorized,
              protocol: res.socket.getProtocol(),
              cipher: res.socket.getCipher(),
              fingerprint256: res.socket.getPeerCertificate().fingerprint256
            }
          : null
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () =>
          resolve({
            url,
            status: res.statusCode,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
            tls
          })
        )
      }
    )
    req.once('timeout', () => req.destroy(new Error('HTTP probe timed out')))
    req.once('error', reject)
    req.end()
  })
}

function jsonLine(output) {
  const line = output.split('\n').findLast((item) => item.startsWith('{'))
  assert.ok(line, 'command produced no JSON evidence')
  return JSON.parse(line)
}

export async function main() {
  assert.equal(process.version, 'v22.23.2', 'run with Node 22.23.2')
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const runId = `cvg-aud06-stack-${Date.now()}-${randomBytes(5).toString('hex')}`
  const evidence = path.join(root, 'docs/04_audit/evidence/AUD06/stack', runId)
  fs.mkdirSync(path.dirname(evidence), { recursive: true })
  fs.mkdirSync(evidence)
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-aud06-stack-'))
  fs.chmodSync(temp, 0o700)
  const context = path.join(temp, 'context')
  const summary = {
    runId,
    scope: 'CONTROLLED_LOCAL_SYNTHETIC_ONLY',
    status: 'IN_PROGRESS',
    production: 'NO_GO',
    realPilot: false,
    realRpoRtoQualified: false,
    humanSignoff: false,
    startedAt: new Date().toISOString(),
    checks: {},
    cleanupErrors: []
  }
  const write = (name, value) =>
    fs.writeFileSync(
      path.join(evidence, name),
      typeof value === 'string' || Buffer.isBuffer(value)
        ? value
        : `${JSON.stringify(value, null, 2)}\n`
    )
  let counter = 0
  let activeChild
  let interrupted = 0
  let cleaning = false
  const signalHandlers = new Map()
  for (const [signal, code] of [
    ['SIGINT', 130],
    ['SIGTERM', 143]
  ]) {
    const handler = () => {
      interrupted = code
      activeChild?.kill('SIGTERM')
    }
    signalHandlers.set(signal, handler)
    process.on(signal, handler)
  }
  const commandEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LANG: 'C.UTF-8'
  }
  // Preserve the selected Docker daemon, never ambient application credentials.
  for (const key of [
    'DOCKER_HOST',
    'DOCKER_CONTEXT',
    'DOCKER_CONFIG',
    'XDG_RUNTIME_DIR'
  ]) {
    if (process.env[key]) commandEnv[key] = process.env[key]
  }
  async function exec(program, args, name, options = {}) {
    if (interrupted && !cleaning) throw new Error('AUD06 run interrupted')
    const id = String(++counter).padStart(3, '0')
    const stdoutFile = `${id}-${name}.${options.binary ? 'dump' : 'stdout.log'}`
    const stderrFile = `${id}-${name}.stderr.log`
    const startedAt = new Date().toISOString()
    const output = await new Promise((resolve) => {
      const stdout = [],
        stderr = []
      let error = null
      const child = spawn(program, args, {
        cwd: root,
        env: commandEnv,
        stdio: ['pipe', 'pipe', 'pipe']
      })
      activeChild = child
      const timer = setTimeout(() => {
        error = 'command_timeout'
        child.kill('SIGTERM')
        const killTimer = setTimeout(() => child.kill('SIGKILL'), 3_000)
        killTimer.unref()
      }, options.timeout ?? 90_000)
      child.stdout.on('data', (chunk) => stdout.push(chunk))
      child.stderr.on('data', (chunk) => stderr.push(chunk))
      child.once('error', (failure) => {
        error = failure.message
      })
      child.stdin.on('error', (failure) => {
        error ??= failure.message
      })
      child.stdin.end(options.input)
      child.once('close', (exitCode, signal) => {
        clearTimeout(timer)
        activeChild = undefined
        resolve({
          exitCode,
          signal,
          error,
          stdout: Buffer.concat(stdout),
          stderr: Buffer.concat(stderr)
        })
      })
    })
    write(stdoutFile, output.stdout)
    write(stderrFile, output.stderr)
    const record = {
      id,
      name,
      command: [program, ...args],
      startedAt,
      endedAt: new Date().toISOString(),
      exitCode: output.exitCode,
      signal: output.signal,
      error: output.error,
      stdoutFile,
      stdoutSha256: sha(output.stdout),
      stderrFile,
      stderrSha256: sha(output.stderr)
    }
    fs.appendFileSync(
      path.join(evidence, 'commands.jsonl'),
      `${JSON.stringify(record)}\n`
    )
    if (!options.allowFailure && (output.exitCode !== 0 || output.error)) {
      throw new Error(
        `${name}: exit=${output.exitCode}, signal=${output.signal}, error=${output.error}; ${output.stderr.toString('utf8').slice(-2500)}`
      )
    }
    return {
      ...record,
      stdout: output.stdout.toString('utf8'),
      stderr: output.stderr.toString('utf8'),
      bytes: output.stdout
    }
  }
  const docker = (args, name, options) => exec('docker', args, name, options)
  const ownershipFormat =
    '{"name":{{json .Name}},"labels":{{json .Config.Labels}}}'
  const imageTags = []
  let composeArgs
  let manifest
  let exitCode = 0
  async function containers() {
    const result = await docker(
      ['ps', '-aq', '--filter', `label=${labelKey}=${runId}`],
      'owned-containers'
    )
    return result.stdout.trim().split(/\s+/).filter(Boolean)
  }
  async function cleanup() {
    cleaning = true
    const failures = []
    async function attempt(operation) {
      try {
        await operation()
      } catch (error) {
        failures.push(String(error))
      }
    }
    await attempt(async () => {
      for (const id of await containers()) {
        await attempt(async () => {
          const metadata = JSON.parse(
            (
              await docker(
                ['inspect', '--format', ownershipFormat, id],
                'cleanup-ownership'
              )
            ).stdout
          )
          assertResourceOwnership(metadata.name, metadata.labels, runId)
          const name = metadata.name.slice(1)
          // Diagnostics must not strand a positively owned container. Retain
          // every failure and remove only the immutable ID inspected above.
          await attempt(() =>
            docker(['stop', '--time', '20', id], `stop-${name}`)
          )
          await attempt(() => docker(['logs', id], `logs-${name}`))
          await attempt(() => docker(['rm', '--force', id], `remove-${name}`))
        })
      }
    })
    for (const kind of ['network', 'volume']) {
      await attempt(async () => {
        const found = await docker(
          [kind, 'ls', '-q', '--filter', `label=${labelKey}=${runId}`],
          `owned-${kind}s`
        )
        for (const identifier of found.stdout
          .trim()
          .split(/\s+/)
          .filter(Boolean)) {
          await attempt(async () => {
            const item = JSON.parse(
              (
                await docker(
                  [kind, 'inspect', identifier],
                  `inspect-owned-${kind}`
                )
              ).stdout
            )[0]
            await removeOwnedResource({
              name: item.Name,
              runId,
              inspect: async () => item.Labels,
              remove: (name) => docker([kind, 'rm', name], `remove-${kind}`)
            })
          })
        }
      })
    }
    for (const tag of imageTags) {
      await attempt(async () => {
        const labels = JSON.parse(
          (
            await docker(
              ['image', 'inspect', '--format', '{{json .Config.Labels}}', tag],
              'image-ownership'
            )
          ).stdout
        )
        assertResourceOwnership(tag, labels, runId)
        await docker(['image', 'rm', tag], 'remove-image-tag')
      })
    }
    const remaining = {}
    for (const [kind, args] of [
      ['containers', ['ps', '-aq']],
      ['networks', ['network', 'ls', '-q']],
      ['volumes', ['volume', 'ls', '-q']]
    ]) {
      await attempt(async () => {
        const result = await docker(
          [...args, '--filter', `label=${labelKey}=${runId}`],
          `remaining-${kind}`
        )
        remaining[kind] = result.stdout.trim().split(/\s+/).filter(Boolean)
        assert.equal(remaining[kind].length, 0, `${kind} remain`)
      })
    }
    summary.cleanupErrors = failures
    summary.teardown = { remaining, passed: failures.length === 0 }
    if (failures.length === 0) fs.rmSync(temp, { recursive: true })
    else summary.retainedTemporaryDirectory = temp
  }
  try {
    console.log(`AUD06 synthetic run: ${runId}`)
    await docker(
      ['version', '--format', '{{json .Server.Version}}'],
      'docker-version'
    )
    await docker(['compose', 'version'], 'compose-version')
    await exec('openssl', ['version'], 'openssl-version')
    const runtimeIdentity = prepareTelemetryDirectories(temp)
    manifest = snapshot(root, context)
    write('source-manifest.json', manifest)
    write('runner-source.mjs', fs.readFileSync(fileURLToPath(import.meta.url)))
    summary.sourceManifestSha256 = sha(
      fs.readFileSync(path.join(evidence, 'source-manifest.json'))
    )
    await docker(
      [
        'network',
        'create',
        '--internal',
        '--driver',
        'bridge',
        '--label',
        `${labelKey}=${runId}`,
        `${runId}-network`
      ],
      'create-network'
    )
    const network = JSON.parse(
      (
        await docker(
          ['network', 'inspect', `${runId}-network`],
          'network-isolation'
        )
      ).stdout
    )[0]
    assert.equal(network.Internal, true)
    // Port publishing needs an edge route. Only Caddy joins this second,
    // separately owned bridge; the application/database network stays internal.
    await docker(
      [
        'network',
        'create',
        '--driver',
        'bridge',
        '--label',
        `${labelKey}=${runId}`,
        '--opt',
        'com.docker.network.bridge.host_binding_ipv4=127.0.0.1',
        `${runId}-edge-network`
      ],
      'create-edge-network'
    )
    await docker(
      ['network', 'inspect', `${runId}-edge-network`],
      'edge-network-isolation'
    )
    const gateway = network.IPAM.Config[0].Gateway.split('.').map(Number)
    assert.equal(gateway[3], 1)
    const edgeIp = [...gateway.slice(0, 3), 201].join('.')
    for (const suffix of ['db-data', 'restore-data']) {
      const name = `${runId}-${suffix}`
      const exists = await docker(
        ['volume', 'inspect', name],
        'volume-must-not-exist',
        { allowFailure: true }
      )
      assert.notEqual(exists.exitCode, 0, 'refusing existing volume')
      await docker(
        ['volume', 'create', '--label', `${labelKey}=${runId}`, name],
        'create-volume'
      )
    }
    const httpPort = await freePort()
    let httpsPort = await freePort()
    while (httpsPort === httpPort) httpsPort = await freePort()
    summary.ports = {
      http: `127.0.0.1:${httpPort}`,
      https: `127.0.0.1:${httpsPort}`
    }
    const env = {
      AUD06_RUN_ID: runId,
      AUD06_CONTEXT: context,
      AUD06_TEMP: temp,
      AUD06_HTTP_PORT: httpPort,
      AUD06_HTTPS_PORT: httpsPort,
      AUD06_EDGE_IP: edgeIp,
      AUD06_RUNTIME_UID: runtimeIdentity.uid,
      AUD06_RUNTIME_GID: runtimeIdentity.gid,
      AUD06_ADMIN_PASSWORD: randomBytes(24).toString('hex'),
      AUD06_MIGRATION_PASSWORD: randomBytes(24).toString('hex'),
      AUD06_RUNTIME_PASSWORD: randomBytes(24).toString('hex')
    }
    const envFile = path.join(temp, 'synthetic.env')
    fs.writeFileSync(
      envFile,
      Object.entries(env)
        .map(([key, value]) => `${key}=${value}\n`)
        .join(''),
      { mode: 0o600 }
    )
    composeArgs = [
      'compose',
      '--env-file',
      envFile,
      '-p',
      runId,
      '-f',
      path.join(context, 'deploy/aud06/compose.yaml')
    ]
    const compose = (args, name, options) =>
      docker([...composeArgs, ...args], name, options)
    const forbiddenTelemetryValues = [
      env.AUD06_ADMIN_PASSWORD,
      env.AUD06_MIGRATION_PASSWORD,
      env.AUD06_RUNTIME_PASSWORD
    ]
    async function captureTelemetry(phase, wait = false) {
      const deadline = Date.now() + (wait ? 10_000 : 0)
      for (;;) {
        try {
          const result = {}
          for (const service of TELEMETRY_SERVICES) {
            result[service] = readTelemetryFile(
              temp,
              service,
              forbiddenTelemetryValues
            )
          }
          for (const service of TELEMETRY_SERVICES) {
            write(`telemetry-${service}-${phase}.jsonl`, result[service].bytes)
          }
          write(`telemetry-${phase}.json`, {
            observedAt: new Date().toISOString(),
            services: Object.fromEntries(
              TELEMETRY_SERVICES.map((service) => [
                service,
                result[service].stats
              ])
            )
          })
          return result
        } catch (error) {
          if (Date.now() >= deadline) throw error
          await pause(100)
        }
      }
    }
    await compose(['config', '--quiet'], 'compose-config')
    await exec(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-sha256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost/OU=AUD06-SYNTHETIC',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        path.join(temp, 'localhost.key'),
        '-out',
        path.join(temp, 'localhost.crt')
      ],
      'ephemeral-certificate'
    )
    fs.chmodSync(path.join(temp, 'localhost.key'), 0o444)
    fs.chmodSync(path.join(temp, 'localhost.crt'), 0o444)
    const ca = fs.readFileSync(path.join(temp, 'localhost.crt'))
    write('localhost-public.crt', ca)
    await exec(
      'openssl',
      [
        'x509',
        '-in',
        path.join(temp, 'localhost.crt'),
        '-noout',
        '-subject',
        '-issuer',
        '-dates',
        '-fingerprint',
        '-sha256'
      ],
      'certificate-inspection'
    )
    console.log(
      'Building digest-pinned runtime and web images from an isolated source snapshot.'
    )
    for (const target of ['runtime', 'web']) {
      const tag = `${runId}-${target}:synthetic`
      await docker(
        [
          'build',
          '--target',
          `aud06-${target}`,
          '--label',
          `${labelKey}=${runId}`,
          '-t',
          tag,
          context
        ],
        `build-${target}`,
        { timeout: 600_000 }
      )
      imageTags.push(tag)
      await docker(
        ['image', 'inspect', '--format', '{{json .Id}}', tag],
        `image-id-${target}`
      )
    }
    console.log(
      'Starting disposable PostgreSQL and applying the canonical migrations twice.'
    )
    await compose(
      ['up', '-d', '--wait', '--wait-timeout', '60', 'db', 'db-restore'],
      'start-databases'
    )
    const migrate = (iteration) =>
      compose(
        [
          'run',
          '--rm',
          '--no-deps',
          '--name',
          `${runId}-migration-${iteration}`,
          'migrate'
        ],
        `migration-${iteration}`
      )
    const firstMigration = jsonLine((await migrate(1)).stdout)
    const secondMigration = jsonLine((await migrate(2)).stdout)
    assert.deepEqual(
      secondMigration,
      firstMigration,
      'migration rerun changed the ledger'
    )
    summary.checks.migration = {
      count: firstMigration.count,
      repeatedWithoutChanges: true,
      sha256: firstMigration.sha256
    }
    let toolCounter = 0
    async function tool(action, ...args) {
      const result = await compose(
        [
          'run',
          '--rm',
          '--no-deps',
          '--name',
          `${runId}-tool-${++toolCounter}`,
          'tools',
          'node',
          '--import',
          'tsx',
          'scripts/aud06-stack-db.ts',
          action,
          ...args
        ],
        `db-${action}`
      )
      return jsonLine(result.stdout)
    }
    await tool('seed', 'before')
    await compose(
      [
        'up',
        '-d',
        '--wait',
        '--wait-timeout',
        '60',
        'api-a',
        'api-b',
        'worker',
        'web'
      ],
      'start-applications'
    )
    summary.checks.startup = true
    for (const service of [
      'db',
      'db-restore',
      'api-a',
      'api-b',
      'worker',
      'web'
    ]) {
      const format =
        '{"name":{{json .Name}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"ports":{{json .HostConfig.PortBindings}},"networks":{{json .NetworkSettings.Networks}},"state":{{json .State}},"memory":{{json .HostConfig.Memory}},"pids":{{json .HostConfig.PidsLimit}},"mounts":{{json .Mounts}}}'
      const metadata = JSON.parse(
        (
          await docker(
            ['inspect', '--format', format, `${runId}-${service}`],
            `security-${service}`
          )
        ).stdout
      )
      assert.ok(metadata.user && !['root', '0', '0:0'].includes(metadata.user))
      assert.equal(metadata.readonly, true)
      assert.ok(metadata.caps.includes('ALL'))
      assert.ok(metadata.security.includes('no-new-privileges:true'))
      assert.ok(metadata.memory > 0 && metadata.pids > 0)
      assert.deepEqual(
        Object.keys(metadata.networks).sort(),
        (service === 'web'
          ? [`${runId}-network`, `${runId}-edge-network`]
          : [`${runId}-network`]
        ).sort()
      )
      for (const bindings of Object.values(metadata.ports ?? {})) {
        for (const binding of bindings ?? [])
          assert.equal(binding.HostIp, '127.0.0.1')
      }
      if (TELEMETRY_SERVICES.includes(service)) {
        const mount = metadata.mounts.find(
          (item) => item.Destination === `/tmp/${runId}-telemetry`
        )
        assert.ok(
          mount?.RW && mount.Type === 'bind',
          'telemetry writable volume missing'
        )
        assert.equal(mount.Source, path.join(temp, 'telemetry', service))
      }
    }
    summary.checks.containerIsolation = true
    const readiness = JSON.parse(
      (
        await docker(
          ['exec', `${runId}-worker`, 'cat', '/tmp/cvg-worker-ready'],
          'worker-readiness'
        )
      ).stdout
    )
    assert.equal(readiness.status, 'ready')
    assert.equal(readiness.durable, true)
    assert.equal(readiness.externalEffects, false)
    async function waitQueue(expected) {
      const deadline = Date.now() + 30_000
      do {
        const result = await tool('queue')
        if (
          result.rows.length === expected &&
          result.rows.every(
            (row) => row.status === 'processed' && row.effects === 1
          )
        )
          return result
        await pause(300)
      } while (Date.now() < deadline)
      throw new Error(
        'durable outbox did not complete exactly one controlled effect per fixture'
      )
    }
    await waitQueue(1)
    // Exercise the actual API log path on both replicas. The input marker must
    // not survive in any collector output, nor may the worker fixture payload.
    for (let index = 0; index < 4; index++) {
      const response = await request(
        `https://localhost:${httpsPort}/v1/conversations?fixture=${TELEMETRY_CANARY}`,
        ca,
        { 'x-aud06-telemetry-canary': TELEMETRY_CANARY }
      )
      assert.ok([200, 401, 403].includes(response.status))
      write(`telemetry-http-input-${index}.json`, response)
    }
    const periodicTelemetry = await captureTelemetry('periodic', true)
    summary.checks.telemetryPeriodicFiles = true
    await docker(
      ['stop', '--time', '20', `${runId}-worker`],
      'worker-graceful-stop'
    )
    await tool('seed', 'after')
    const pending = await tool('queue')
    assert.equal(
      pending.rows.find((row) => row.idempotency_key === 'aud06-stack-after')
        ?.status,
      'pending'
    )
    await docker(['start', `${runId}-worker`], 'worker-restart')
    const completed = await waitQueue(2)
    write('worker-durability.json', { readiness, pending, completed })
    summary.checks.workerRestartDurability = true
    const base = `https://localhost:${httpsPort}`
    const probe = async (name, endpoint, options = {}) => {
      const response = await request(
        `${options.http ? `http://localhost:${httpPort}` : base}${endpoint}`,
        options.http ? undefined : ca,
        options.headers
      )
      write(`${name}.json`, response)
      return response
    }
    const redirect = await probe('http-redirect', '/', { http: true })
    assert.equal(redirect.status, 308)
    assert.equal(redirect.headers.location, `${base}/`)
    assertSecurityHeaders(redirect.headers, false)
    const web = await probe('https-web', '/')
    assert.equal(web.status, 200)
    assert.equal(web.tls.authorized, true)
    assertSecurityHeaders(web.headers)
    assert.match(web.body, /id="root"/)
    const asset = web.body.match(/src="([^"]+\.js)"/)?.[1]
    assert.ok(asset, 'built web JavaScript asset missing')
    const assetResponse = await probe('https-web-asset', asset)
    assert.equal(assetResponse.status, 200)
    assert.ok(assetResponse.body.length > 1000)
    const health = await probe('https-api-health', '/health')
    assert.equal(health.status, 200)
    assert.equal(JSON.parse(health.body).data.runtime, 'api')
    assertSecurityHeaders(health.headers)
    const ready = await probe('https-api-ready', '/ready')
    assert.equal(ready.status, 200)
    assert.equal(JSON.parse(ready.body).data.ready, true)
    let untrustedCertificateRejected = false
    try {
      await request(base, undefined)
    } catch (error) {
      write('untrusted-certificate.json', {
        code: error.code,
        message: error.message
      })
      untrustedCertificateRejected = [
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN'
      ].includes(error.code)
    }
    assert.equal(untrustedCertificateRejected, true)
    summary.checks.httpTlsHeaders = true
    console.log(
      'Exercising shared quota across both API replicas and denying unavailable storage.'
    )
    await tool('quota-reset')
    const burst = []
    for (let index = 0; index < 302; index++) {
      const response = await request(`${base}/health`, ca, {
        'x-forwarded-for': `198.51.100.${(index % 250) + 1}`,
        'x-tenant-id': `synthetic-${index}`
      })
      burst.push({
        index,
        status: response.status,
        upstream: response.headers['x-aud06-upstream'],
        retryAfter: response.headers['retry-after'],
        body: response.body
      })
    }
    write('shared-quota-burst.json', burst)
    assert.equal(burst.filter((row) => row.status === 200).length, 300)
    assert.equal(burst.filter((row) => row.status === 429).length, 2)
    assert.deepEqual(
      new Set(burst.map((row) => row.upstream)),
      new Set(['api-a:3000', 'api-b:3000'])
    )
    write('quota-buckets.json', await tool('quota'))
    await tool('quota-reset')
    await tool('quota-deny')
    const denied = []
    for (let index = 0; index < 4; index++)
      denied.push(await request(`${base}/health`, ca))
    write('quota-storage-failure.json', denied)
    assert.ok(
      denied.every(
        (row) =>
          row.status === 503 &&
          JSON.parse(row.body).error.code === 'rate_limit_unavailable'
      )
    )
    assert.equal(
      new Set(denied.map((row) => row.headers['x-aud06-upstream'])).size,
      2
    )
    await tool('quota-allow')
    assert.equal((await probe('quota-storage-recovery', '/health')).status, 200)
    summary.checks.sharedQuota = {
      accepted: 300,
      limited: 2,
      replicas: 2,
      storageFailureStatus: 503,
      recovered: true
    }
    const metrics = await probe('api-metrics-export', '/health/metrics')
    assert.equal(metrics.status, 200)
    for (const role of ['api', 'worker']) {
      const result = await docker(
        [
          'run',
          '--name',
          `${runId}-production-${role}`,
          '--label',
          `${labelKey}=${runId}`,
          '--network',
          'none',
          '--read-only',
          '--cap-drop',
          'ALL',
          '--security-opt',
          'no-new-privileges:true',
          '--tmpfs',
          '/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000',
          '-e',
          'NODE_ENV=production',
          `${runId}-runtime:synthetic`,
          'node',
          '--import',
          'tsx',
          `apps/${role}/src/main.ts`
        ],
        `production-preflight-${role}`,
        { allowFailure: true }
      )
      assert.equal(result.exitCode, 1)
      assert.match(result.stdout + result.stderr, /preflight/i)
    }
    summary.checks.productionPreflightStillDenies = true
    const beforeShutdown = await captureTelemetry('before-shutdown')
    const shutdownProbes = {}
    for (const service of ['api-a', 'api-b']) {
      // Emit one last real route log, observe that its correlation ID is still
      // buffered, then SIGTERM the same owned entrypoint. Its final file must
      // contain that exact ID after the process exits successfully.
      const script = `
        const fs = require('node:fs');
        (async () => {
          const file = process.env.CVG_TELEMETRY_ROOT + '/api.jsonl';
          for (let attempt = 0; attempt < 3; attempt++) {
            const response = await fetch('http://127.0.0.1:3000/v1/conversations', {
              headers: { 'x-forwarded-proto': 'https', 'x-aud06-telemetry-canary': '${TELEMETRY_CANARY}' }
            });
            const body = await response.json();
            const correlationId = body.meta?.correlationId;
            if (![200, 401, 403].includes(response.status) || typeof correlationId !== 'string' || response.headers.get('x-correlation-id') !== correlationId) throw new Error('shutdown route probe failed');
            if (fs.readFileSync(file, 'utf8').includes(correlationId)) continue;
            fs.writeSync(1, JSON.stringify({ status: response.status, correlationId, bufferedBeforeSignal: true }) + '\\n');
            process.kill(1, 'SIGTERM');
            process.exit(0);
          }
          throw new Error('could not observe a buffered shutdown record');
        })().catch(error => { console.error(error.message); process.exitCode = 1; });
      `
      const probe = await docker(
        ['exec', `${runId}-${service}`, 'node', '-e', script],
        `telemetry-shutdown-${service}`
      )
      shutdownProbes[service] = jsonLine(probe.stdout)
      const stopped = await docker(
        ['wait', `${runId}-${service}`],
        `telemetry-wait-${service}`,
        { timeout: 30_000 }
      )
      assert.equal(
        stopped.stdout.trim(),
        '0',
        'API failed to drain during shutdown'
      )
    }
    await compose(
      ['stop', '--timeout', '20', 'worker', 'api-a', 'api-b', 'web'],
      'quiesce-writers'
    )
    const finalTelemetry = await captureTelemetry('shutdown')
    for (const service of TELEMETRY_SERVICES) {
      assertTelemetryRetained(
        periodicTelemetry[service].bytes,
        finalTelemetry[service].bytes
      )
      assertTelemetryRetained(
        beforeShutdown[service].bytes,
        finalTelemetry[service].bytes
      )
      assert.ok(
        finalTelemetry[service].bytes.length >
          beforeShutdown[service].bytes.length,
        'shutdown did not export additional records'
      )
      if (service !== 'worker') {
        assert.ok(
          finalTelemetry[service].bytes.includes(
            shutdownProbes[service].correlationId
          ),
          'buffered API record lost on shutdown'
        )
      }
      const stopped = JSON.parse(
        (
          await docker(
            [
              'inspect',
              '--format',
              '{"exitCode":{{.State.ExitCode}},"running":{{.State.Running}}}',
              `${runId}-${service}`
            ],
            `telemetry-stopped-${service}`
          )
        ).stdout
      )
      assert.deepEqual(stopped, { exitCode: 0, running: false })
      const output = await docker(
        ['logs', `${runId}-${service}`],
        `telemetry-process-${service}`
      )
      assert.ok(
        !/telemetry\.export_failed/.test(output.stdout + output.stderr),
        'collector export failure observed'
      )
    }
    const workerStats = finalTelemetry.worker.stats
    assert.ok(workerStats.events.includes('worker.continuous_ready'))
    assert.ok(workerStats.events.includes('worker.continuous_drained'))
    assert.ok(
      workerStats.counts.metrics > 0,
      'worker metrics were not exported'
    )
    summary.checks.telemetryExport = {
      mode: 'local_file',
      profile: 'CONTROLLED_LOCAL_SYNTHETIC',
      processFiles: Object.fromEntries(
        TELEMETRY_SERVICES.map((service) => [
          service,
          finalTelemetry[service].stats
        ])
      ),
      periodicFlushObserved: true,
      apiShutdownBufferedRecords: shutdownProbes,
      workerShutdownDrainObserved: true,
      retainedAcrossWorkerRestart: true,
      forbiddenSyntheticValuesAbsent: true,
      apiMetrics: true,
      scope:
        'actual sanitized collector files from isolated synthetic entrypoints'
    }
    console.log(
      'Backing up the quiesced source and verifying a second PostgreSQL instance row by row.'
    )
    const original = await tool('fingerprint')
    const dump = await docker(
      [
        'exec',
        `${runId}-db`,
        'pg_dump',
        '-U',
        'cvg_aud06_admin',
        '-d',
        'cvg_aud06',
        '--schema=cvg_aud06',
        '--format=custom'
      ],
      'postgres-backup',
      { binary: true }
    )
    summary.backupSha256 = sha(dump.bytes)
    await docker(
      [
        'exec',
        '-i',
        `${runId}-db-restore`,
        'pg_restore',
        '-U',
        'cvg_aud06_admin',
        '-d',
        'cvg_aud06',
        '--exit-on-error',
        '--single-transaction'
      ],
      'postgres-restore',
      { input: dump.bytes }
    )
    const restored = await tool('fingerprint-restore')
    const unchanged = await tool('fingerprint')
    assertRestoreIntegrity(original, restored)
    assert.deepEqual(unchanged, original)
    write('restore-integrity.json', {
      original,
      restored,
      sourceUnchanged: true
    })
    summary.checks.restore = {
      tables: original.tables.length,
      rows: original.tables.reduce((sum, table) => sum + table.count, 0),
      sha256: original.sha256,
      target: 'separate disposable PostgreSQL container/volume'
    }
    summary.status = 'IMPLEMENTED_LOCAL_CHECKS_PASSED'
  } catch (error) {
    exitCode = interrupted || 1
    summary.status = 'FAILED'
    summary.error = error instanceof Error ? error.message : String(error)
    console.error(summary.error)
  } finally {
    await cleanup()
    if (summary.cleanupErrors.length) {
      if (exitCode === 0) exitCode = 1
      summary.status = 'FAILED_CLEANUP'
    }
    if (manifest) {
      summary.sourceDriftSinceSnapshot = manifest
        .filter((item) => {
          try {
            return (
              sha(fs.readFileSync(path.join(root, item.path))) !== item.sha256
            )
          } catch {
            return true
          }
        })
        .map((item) => item.path)
    }
    for (const [signal, handler] of signalHandlers)
      process.removeListener(signal, handler)
    summary.exitCode = exitCode
    summary.endedAt = new Date().toISOString()
    write('summary.json', summary)
    write('exit-code.txt', `${exitCode}\n`)
    const hashes = fs
      .readdirSync(evidence)
      .sort()
      .filter((name) => name !== 'SHA256SUMS')
      .map(
        (name) =>
          `${sha(fs.readFileSync(path.join(evidence, name)))}  ${name}\n`
      )
      .join('')
    write('SHA256SUMS', hashes)
    console.log(
      JSON.stringify({
        evidence,
        exitCode,
        sha256sums: sha(hashes),
        checks: summary.checks,
        teardown: summary.teardown
      })
    )
  }
  return exitCode
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  main()
    .then((code) => {
      process.exitCode = code
    })
    .catch((error) => {
      console.error(error.message)
      process.exitCode = 1
    })
}
