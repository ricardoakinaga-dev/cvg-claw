import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const workflow = fs.readFileSync(
  path.join(rootDir, '.github/workflows/verify.yml'),
  'utf8'
)
const playwrightConfig = fs.readFileSync(
  path.join(rootDir, 'playwright.config.ts'),
  'utf8'
)

describe('controlled CI workflow contract', () => {
  it('declares least-privilege and stale-run protection', () => {
    expect(workflow).toContain('permissions:')
    expect(workflow).toContain('contents: read')
    expect(workflow).toContain('concurrency:')
    expect(workflow).toContain('cancel-in-progress: true')
    expect(workflow).toContain('persist-credentials: false')
  })

  it('calls every available construction gate explicitly', () => {
    expect(workflow).toContain('npm ci --ignore-scripts')
    expect(workflow).toContain('npm run readiness')
    expect(workflow).toContain('npm run verify')
    expect(workflow).toContain('npm run test:postgres')
    expect(workflow).toContain('npm run test:e2e')
    expect(workflow).toContain('npm run test:worker:startup')
    expect(workflow).toContain('git diff --check')
    expect(workflow).toContain('node scripts/aud19-critical-coverage.mjs')
    expect(workflow).toContain('npm run certification:verify:phase11')
    expect(workflow).toContain(
      'npm run promotion:check -- --expect=EXTERNAL_ONLY'
    )
    expect(workflow).toContain(
      'npm run production:preflight -- --expect=REJECT'
    )
    expect(workflow).toContain('npm run test:evals')
    expect(workflow).toContain('npm run test:chaos')
    expect(workflow).toContain('npm run licenses:check')
    expect(workflow).toContain('npm run sbom')
  })

  it('runs verification in the approved browser image without host font drift', () => {
    expect(workflow).toMatch(
      /container:\s+image: mcr\.microsoft\.com\/playwright:v1\.59\.1-noble@sha256:b0ab6f3cb99aa7803adbc14d9027ec1785fc6e433b97e134e0f8fe61683b6b53/
    )
    expect(workflow).toContain('options: --shm-size=1g')
    expect(workflow).toContain('shell: bash')
    expect(workflow).toContain('PLAYWRIGHT_BROWSERS_PATH: /ms-playwright')
    expect(workflow).not.toMatch(/playwright install|apt-get install/)
    expect(workflow).not.toContain('continue-on-error')
  })

  it('keeps the Node pin and checks Playwright compatibility before E2E', () => {
    const nodeVersion = fs
      .readFileSync(path.join(rootDir, '.nvmrc'), 'utf8')
      .trim()
    expect(workflow).toContain(`node-version: ${nodeVersion}`)
    expect(workflow).toContain(
      "assert.equal(process.versions.node, fs.readFileSync('.nvmrc', 'utf8').trim())"
    )
    expect(workflow).toContain(
      "assert.equal(require('@playwright/test/package.json').version, '1.59.1')"
    )
    expect(workflow.indexOf('name: Browser environment contract')).toBeLessThan(
      workflow.indexOf('name: Browser E2E')
    )
  })

  it('connects both PostgreSQL gates through the job container service network', () => {
    expect(
      workflow.match(
        /TEST_DATABASE_URL: postgres:\/\/postgres:postgres@postgres:5432\/cvg_test/g
      )
    ).toHaveLength(2)
    expect(workflow).not.toContain('@localhost:5432')
    expect(workflow).not.toContain('5432:5432')
  })

  it('keeps all browsers and refuses implicit snapshot creation', () => {
    for (const browser of ['chromium', 'firefox', 'webkit']) {
      expect(playwrightConfig).toContain(`name: '${browser}'`)
    }
    expect(playwrightConfig).toContain("updateSnapshots: 'none'")
    expect(playwrightConfig).toContain('forbidOnly: Boolean(process.env.CI)')
    expect(playwrightConfig).toContain('reuseExistingServer: !process.env.CI')
    expect(workflow).not.toMatch(/--update-snapshots|--ignore-snapshots/)
  })
})
