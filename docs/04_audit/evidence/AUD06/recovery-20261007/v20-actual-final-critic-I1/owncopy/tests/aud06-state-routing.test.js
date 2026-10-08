import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { checkRepositoryState } from '../scripts/lib/docs-state-check.mjs'

const temporaryRoots = []

function fixture(program, matrixPath) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-state-routing-'))
  temporaryRoots.push(root)
  const write = (relative, content) => {
    const target = path.join(root, relative)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(
      target,
      typeof content === 'string' ? content : JSON.stringify(content)
    )
  }
  const canonical = {
    schemaVersion: 1,
    kind: 'cvg-current-operational-state',
    program,
    currentTask: 'SYNTHETIC-01',
    currentStatus: 'IN_PROGRESS',
    nextAction: 'verify synthetic task',
    releaseBoundary: { staging: 'NO_GO', production: 'NO_GO' },
    runtime: { node: { exact: '22.23.2', range: '>=22 <23' } },
    sources: {
      currentIndex: 'docs/CURRENT.md',
      runtimeState: 'docs/99_runtime_state.md',
      executionLog: 'docs/20_master_execution_log.md',
      backlog:
        program === 'AUD06'
          ? 'docs/03_build/0349_aud06_backlog.md'
          : 'docs/backlog.md',
      taskMatrix: matrixPath
    },
    certification: {
      currentPointer: 'certification/current.json',
      currentNamespace: 'certification/phase11',
      historicalNamespaces: [
        'certification/findings.json',
        'certification/logs/historical/phase10'
      ]
    }
  }
  write('docs/03_build/tracking/current_state.json', canonical)
  write(matrixPath, {
    schemaVersion: 1,
    program,
    currentTask: canonical.currentTask,
    currentStatus: canonical.currentStatus,
    tasks: [{ id: canonical.currentTask, status: canonical.currentStatus }]
  })
  write(
    'docs/CURRENT.md',
    '- status: `IN_PROGRESS`\n- task corrente: `SYNTHETIC-01`\n- Próxima ação: verify synthetic task\n'
  )
  write('docs/99_runtime_state.md', '- next_action: verify synthetic task\n')
  write('docs/20_master_execution_log.md', 'Synthetic record')
  write(
    canonical.sources.backlog,
    '| ID | Estado |\n| --- | --- |\n| SYNTHETIC-01 | IN_PROGRESS |'
  )
  write('package.json', { engines: { node: '>=22 <23' } })
  write('.nvmrc', '22.23.2\n')
  write('.node-version', '22.23.2\n')
  write(
    '.github/workflows/test.yml',
    'uses: actions/setup-node@synthetic\nnode-version: 22.23.2\n'
  )
  for (const name of ['result.json', 'manifest.json']) {
    write(`certification/phase11/${name}`, {})
  }
  write('certification/findings.json', {})
  write('certification/logs/historical/phase10/README.md', 'Historical')
  write('certification/current.json', {
    schemaVersion: 1,
    kind: 'current-certification-pointer',
    phase: '11',
    authority: 'certification/phase11',
    result: 'certification/phase11/result.json',
    manifest: 'certification/phase11/manifest.json',
    historicalPhase10: {
      package: 'certification/logs/historical/phase10',
      verifier: 'synthetic historical verifier',
      doesNotQualifyCurrent: true
    }
  })
  return { root, write, canonical }
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0))
    fs.rmSync(root, { recursive: true })
})

describe('canonical program task routing', () => {
  it.each([
    ['AUD20-REM-v2', 'docs/03_build/tracking/aud20_v2_findings_matrix.json'],
    ['AUD06', 'docs/03_build/tracking/aud06_tasks.json']
  ])(
    'validates the %s program without another program matrix',
    (program, source) => {
      const { root } = fixture(program, source)
      expect(
        checkRepositoryState(root, { observedNode: 'v22.23.2' }).valid
      ).toBe(true)
    }
  )

  it.each(['unknown', '__proto__', 'toString'])(
    'rejects unknown program %s even with internally matching metadata',
    (program) => {
      const { root } = fixture(
        program,
        'docs/03_build/tracking/aud06_tasks.json'
      )
      expect(
        checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
      ).toContain('canonical_task_matrix_source_invalid')
    }
  )

  it('rejects a substituted path and a program mismatch', () => {
    const { root, write, canonical } = fixture(
      'AUD06',
      'docs/03_build/tracking/aud06_tasks.json'
    )
    write('docs/03_build/tracking/current_state.json', {
      ...canonical,
      sources: { ...canonical.sources, taskMatrix: '../unrelated.json' }
    })
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('canonical_task_matrix_source_invalid')
    write('docs/03_build/tracking/current_state.json', canonical)
    write(canonical.sources.taskMatrix, { program: 'AUD20-REM-v2', tasks: [] })
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('canonical_task_matrix_program_mismatch')
  })
})

describe('AUD06 complete backlog consistency', () => {
  function withNonCurrentTask() {
    const current = fixture('AUD06', 'docs/03_build/tracking/aud06_tasks.json')
    const matrix = JSON.parse(
      fs.readFileSync(
        path.join(current.root, current.canonical.sources.taskMatrix),
        'utf8'
      )
    )
    matrix.tasks.push({ id: 'AUD06-09', status: 'IN_PROGRESS' })
    current.write(current.canonical.sources.taskMatrix, matrix)
    current.write(
      current.canonical.sources.backlog,
      '| ID | Estado |\n| --- | --- |\n| SYNTHETIC-01 | IN_PROGRESS |\n| AUD06-09 | IN_PROGRESS |'
    )
    return { ...current, matrix }
  }
  it('accepts matching non-current task states', () => {
    const { root } = withNonCurrentTask()
    expect(checkRepositoryState(root, { observedNode: 'v22.23.2' }).valid).toBe(
      true
    )
  })
  it.each(['READY_FOR_NEXT_STEP', 'COMPLETED', 'TOMORROW'])(
    'rejects a non-current backlog task with status %s',
    (status) => {
      const { root, write, canonical } = withNonCurrentTask()
      write(
        canonical.sources.backlog,
        `| SYNTHETIC-01 | IN_PROGRESS |\n| AUD06-09 | ${status} |`
      )
      expect(
        checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
      ).toContain('task_backlog_status_mismatch:AUD06-09')
    }
  )
  it('rejects missing and duplicate backlog rows', () => {
    const { root, write, canonical } = withNonCurrentTask()
    write(canonical.sources.backlog, '| SYNTHETIC-01 | IN_PROGRESS |')
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('task_backlog_row_count:AUD06-09')
    write(
      canonical.sources.backlog,
      '| SYNTHETIC-01 | IN_PROGRESS |\n| AUD06-09 | IN_PROGRESS |\n| AUD06-09 | IN_PROGRESS |'
    )
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('task_backlog_row_count:AUD06-09')
  })
  it('rejects duplicate non-current matrix IDs and unknown backlog tasks', () => {
    const { root, write, canonical, matrix } = withNonCurrentTask()
    matrix.tasks.push(matrix.tasks[1])
    write(canonical.sources.taskMatrix, matrix)
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('task_matrix_duplicate:AUD06-09')
    matrix.tasks.pop()
    write(canonical.sources.taskMatrix, matrix)
    write(
      canonical.sources.backlog,
      '| SYNTHETIC-01 | IN_PROGRESS |\n| AUD06-09 | IN_PROGRESS |\n| AUD06-99 | IN_PROGRESS |'
    )
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('task_backlog_unknown_task:AUD06-99')
  })
  it('rejects a substituted backlog path without reading it', () => {
    const { root, write, canonical } = withNonCurrentTask()
    write('docs/03_build/tracking/current_state.json', {
      ...canonical,
      sources: { ...canonical.sources, backlog: '../unrelated.json' }
    })
    expect(
      checkRepositoryState(root, { observedNode: 'v22.23.2' }).failures
    ).toContain('canonical_task_backlog_source_invalid')
  })
})
