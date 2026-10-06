import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const pins = JSON.parse(
  await fs.readFile(path.join(repo, 'scripts/network-assets.json'), 'utf8'),
)
const config = JSON.parse(
  await fs.readFile(
    path.join(repo, 'src-tauri/tauri.network-dev.conf.json'),
    'utf8',
  ),
)
const userConfig = JSON.parse(
  await fs.readFile(
    path.join(repo, 'src-tauri/tauri.network.conf.json'),
    'utf8',
  ),
)

test('all six native target mappings pin official stable assets and exact source commits', () => {
  assert.equal(Object.keys(pins.targets).length, 6)
  assert.match(pins.coreSource, /\/tree\/[a-f0-9]{40}$/)
  assert.match(pins.serviceSource, /\/tree\/[a-f0-9]{40}$/)
  for (const [target, assets] of Object.entries(pins.targets)) {
    for (const asset of Object.values(assets))
      assert.match(asset.sha256, /^[a-f0-9]{64}$/)
    assert.ok(assets.core.name.includes(pins.coreVersion))
    assert.ok(assets.service.name.includes(pins.serviceVersion))
    assert.ok(assets.service.name.includes(target))
    assert.equal(assets.core.name.endsWith('.zip'), target.includes('windows'))
    assert.equal(
      assets.service.name.endsWith('.zip'),
      target.includes('windows'),
    )
    assert.ok(!assets.core.name.toLowerCase().includes('alpha'))
  }
})

test('developer bundle has isolated identity, stable only, and no upstream updater or scheme', () => {
  assert.equal(config.identifier, 'io.github.cosxin.network-control.dev')
  assert.equal(config.productName, 'NetworkControl Dev')
  assert.deepEqual(config.bundle.externalBin, ['sidecar/verge-mihomo'])
  assert.equal(config.bundle.createUpdaterArtifacts, false)
  assert.deepEqual(config.plugins.updater.endpoints, [])
  assert.equal(config.plugins.updater.pubkey, '')
  assert.deepEqual(config.plugins['deep-link'].desktop.schemes, [])
  assert.equal(config.bundle.macOS.infoPlist, null)
  assert.equal(config.bundle.macOS.exceptionDomain, null)
})

test('user bundle keeps its own identity and omits upstream service tools, scheme and updates', () => {
  assert.equal(userConfig.identifier, 'io.github.cosxin.network-control')
  assert.notEqual(userConfig.identifier, config.identifier)
  assert.equal(userConfig.productName, 'NetworkControl')
  assert.equal(userConfig.mainBinaryName, 'network-control')
  assert.deepEqual(userConfig.bundle.externalBin, ['sidecar/verge-mihomo'])
  assert.deepEqual(userConfig.bundle.resources, [
    'resources/network-assets-*.json',
    '../LICENSE',
  ])
  assert.equal(userConfig.bundle.category, 'Utility')
  assert.equal(userConfig.bundle.createUpdaterArtifacts, false)
  assert.deepEqual(userConfig.plugins.updater.endpoints, [])
  assert.equal(userConfig.plugins.updater.pubkey, '')
  assert.deepEqual(userConfig.plugins['deep-link'].desktop.schemes, [
    'networkcontrol',
  ])
  assert.equal(userConfig.bundle.macOS.infoPlist, null)
  assert.equal(userConfig.bundle.macOS.exceptionDomain, null)
})

test('corrupted cached archive fails before staging or downloading', async () => {
  const cache = await fs.mkdtemp(path.join(os.tmpdir(), 'network-assets-test-'))
  try {
    const target = 'aarch64-apple-darwin'
    await fs.writeFile(
      path.join(cache, pins.targets[target].core.name),
      'not a pinned archive',
    )
    assert.throws(
      () =>
        execFileSync(
          process.execPath,
          [
            path.join(repo, 'scripts/network-prebuild.mjs'),
            target,
            '--cache',
            cache,
          ],
          { cwd: repo, stdio: 'pipe' },
        ),
      /Checksum mismatch/,
    )
    assert.deepEqual(await fs.readdir(cache), [pins.targets[target].core.name])
  } finally {
    await fs.rm(cache, { recursive: true, force: true })
  }
})
