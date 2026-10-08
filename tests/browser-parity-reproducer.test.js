import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const script = path.join(
  rootDir,
  'docs/04_audit/evidence/AUD06/visual/reproduce.sh'
)
const ownedId = 'a'.repeat(64)

function reproduce(exitCode, collision = false) {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-browser-parity-'))
  try {
    const bin = path.join(fixture, 'bin')
    const evidence = path.join(fixture, 'docs/04_audit/evidence/AUD06/visual')
    const log = path.join(fixture, 'docker.jsonl')
    fs.mkdirSync(bin)
    fs.mkdirSync(evidence, { recursive: true })
    const executable = (name, content) =>
      fs.writeFileSync(path.join(bin, name), content, { mode: 0o755 })
    executable('git', '#!/bin/sh\nprintf "%s\\n" "$AUD06_FIXTURE_REPO"\n')
    executable('node', '#!/bin/sh\nprintf "v22.23.2\\n"\n')
    executable('npm', '#!/bin/sh\nexit 0\n')
    executable(
      'docker',
      `#!${process.execPath}
const fs = require('node:fs')
const args = process.argv.slice(2)
fs.appendFileSync(process.env.AUD06_DOCKER_LOG, JSON.stringify(args) + '\\n')
if (args[0] === 'run') {
  const cidIndex = args.indexOf('--cidfile')
  if (process.env.AUD06_COLLISION !== '1' && cidIndex >= 0)
    fs.writeFileSync(args[cidIndex + 1], '${ownedId}')
  process.exit(Number(process.env.AUD06_EXIT_CODE))
}
process.exit(args[0] === 'rm' ? 0 : 98)
`
    )
    const result = spawnSync('/bin/bash', [script], {
      cwd: fixture,
      env: {
        PATH: `${bin}:/usr/bin:/bin`,
        AUD06_FIXTURE_REPO: fixture,
        AUD06_DOCKER_LOG: log,
        AUD06_EXIT_CODE: String(exitCode),
        AUD06_COLLISION: collision ? '1' : '0'
      },
      encoding: 'utf8',
      timeout: 10000
    })
    const calls = fs
      .readFileSync(log, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line))
    return { result, calls, remaining: fs.readdirSync(evidence) }
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true })
  }
}

describe('browser parity reproduction resource ownership', () => {
  it.each([0, 17])(
    'preserves Docker exit %i and cleans only its returned ID',
    (code) => {
      const { result, calls, remaining } = reproduce(code)
      expect(result.error).toBeUndefined()
      expect(result.status, result.stderr).toBe(code)
      expect(calls).toHaveLength(2)
      expect(calls[1]).toEqual(['rm', '-f', ownedId])
      expect(calls[0][calls[0].indexOf('--network') + 1]).toBe('none')
      expect(calls[0]).not.toContain('--privileged')
      expect(calls[0]).toContain(
        'mcr.microsoft.com/playwright:v1.59.1-noble@sha256:b0ab6f3cb99aa7803adbc14d9027ec1785fc6e433b97e134e0f8fe61683b6b53'
      )
      expect(calls[0].filter((arg) => arg.endsWith(',readonly'))).toHaveLength(
        2
      )
      expect(remaining).toEqual([])
    }
  )

  it('never deletes a pre-existing container after a name collision', () => {
    const { result, calls, remaining } = reproduce(125, true)
    expect(result.status, result.stderr).toBe(125)
    expect(calls).toHaveLength(1)
    expect(calls[0][0]).toBe('run')
    expect(remaining).toEqual([])
  })
})
