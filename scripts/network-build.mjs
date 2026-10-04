import { execFileSync } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const target = args[0]
// --user builds the NetworkControl app; the default stays the isolated developer build.
const userFlavor = args.includes('--user')
const tauriConfig = userFlavor
  ? 'src-tauri/tauri.network.conf.json'
  : 'src-tauri/tauri.network-dev.conf.json'
const feature = userFlavor ? 'network-control' : 'network-dev'
const pins = JSON.parse(
  await fs.readFile(path.join(repo, 'scripts/network-assets.json'), 'utf8'),
)
if (!pins.targets[target])
  throw new Error(
    `Supply a supported target triple: ${Object.keys(pins.targets).join(', ')}`,
  )
const expectedHost = target.includes('apple')
  ? 'darwin'
  : target.includes('windows')
    ? 'win32'
    : 'linux'
if (process.platform !== expectedHost)
  throw new Error(
    `Use a ${expectedHost} native builder for ${target}; this wrapper does not claim cross-platform runtime validation.`,
  )
const manifest = await fs.readFile(
  path.join(repo, 'src-tauri/Cargo.toml'),
  'utf8',
)
if (!new RegExp(`^${feature}\\s*=`, 'm').test(manifest))
  throw new Error(`The ${feature} Rust feature is required before building.`)
execFileSync(
  process.execPath,
  [
    path.join(repo, 'scripts/network-prebuild.mjs'),
    ...args.filter((arg) => !['--bundle', '--debug', '--user'].includes(arg)),
  ],
  { cwd: repo, stdio: 'inherit' },
)
// The inherited resource glob must not accidentally bundle prior mutable/geodata downloads.
const assetManifestName = `network-assets-${target}.json`
const resources = path.join(repo, 'src-tauri/resources')
const assetManifest = JSON.parse(
  await fs.readFile(path.join(resources, assetManifestName), 'utf8'),
)
const allowedResources = new Set([
  assetManifestName,
  ...assetManifest.staged
    .filter((entry) => entry.path.startsWith('src-tauri/resources/'))
    .map((entry) => path.basename(entry.path)),
])
for (const entry of await fs.readdir(resources, { withFileTypes: true })) {
  if (!entry.isFile() || !allowedResources.has(entry.name))
    throw new Error(
      `Unpinned resource ${entry.name}; use a separate clean staging checkout. Existing resources are preserved.`,
    )
}
const bundle = args.includes('--bundle')
if (bundle && expectedHost !== 'darwin')
  throw new Error(
    'Windows/Linux installers remain unqualified; use the native binary build until isolated installer hooks are verified.',
  )
const command = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'
const targetDirectory = path.resolve(
  repo,
  process.env.CARGO_TARGET_DIR ?? 'target',
)
const buildArgs = [
  'exec',
  'tauri',
  'build',
  '--ci',
  '--no-sign',
  '--target',
  target,
  '--config',
  tauriConfig,
  '--features',
  feature,
]
buildArgs.push(...(bundle ? ['--bundles', 'app'] : ['--no-bundle']))
if (args.includes('--debug')) buildArgs.push('--debug')
buildArgs.push('--', '--locked', '--offline')
execFileSync(command, buildArgs, {
  cwd: repo,
  stdio: 'inherit',
  // Windows pnpm is a .cmd wrapper; all command arguments here are fixed or allowlisted.
  shell: process.platform === 'win32',
  env: {
    ...process.env,
    CARGO_TARGET_DIR: targetDirectory,
    CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? '4',
    NODE_OPTIONS: '--max-old-space-size=4096',
    MACOSX_DEPLOYMENT_TARGET: '11.0',
    APPLE_SIGNING_IDENTITY: '',
    APPLE_ID: '',
    APPLE_API_KEY: '',
    APPLE_CERTIFICATE: '',
    TAURI_SIGNING_PRIVATE_KEY: '',
  },
})
if (bundle) {
  const config = JSON.parse(
    await fs.readFile(path.join(repo, tauriConfig), 'utf8'),
  )
  const baseConfig = JSON.parse(
    await fs.readFile(path.join(repo, 'src-tauri/tauri.conf.json'), 'utf8'),
  )
  const output = path.join(
    targetDirectory,
    target,
    args.includes('--debug') ? 'debug' : 'release',
    'bundle',
  )
  const app = path.join(output, 'macos', `${config.productName}.app`)
  const dmgDirectory = path.join(output, 'dmg')
  await fs.mkdir(dmgDirectory, { recursive: true })
  const image = path.join(
    dmgDirectory,
    `${config.productName}_${baseConfig.version}_${target.split('-')[0]}.dmg`,
  )
  const temporary = await fs.mkdtemp(path.join(dmgDirectory, 'network-image-'))
  try {
    const payload = path.join(temporary, 'payload')
    await fs.mkdir(payload)
    await fs.cp(app, path.join(payload, path.basename(app)), {
      recursive: true,
      errorOnExist: true,
      force: false,
    })
    await fs.symlink('/Applications', path.join(payload, 'Applications'))
    // makehybrid/convert write an image without attaching it or automating Finder.
    const intermediate = path.join(temporary, 'raw.dmg')
    const compressed = path.join(temporary, 'image.dmg')
    execFileSync(
      'hdiutil',
      [
        'makehybrid',
        '-hfs',
        '-hfs-volume-name',
        config.productName,
        '-o',
        intermediate,
        payload,
      ],
      { stdio: 'inherit' },
    )
    execFileSync(
      'hdiutil',
      ['convert', intermediate, '-format', 'UDZO', '-o', compressed],
      { stdio: 'inherit' },
    )
    await fs.copyFile(
      compressed,
      image,
      1 /* COPYFILE_EXCL: preserve an existing artifact */,
    )
    console.log(`Created unmounted, unsigned developer disk image: ${image}`)
  } finally {
    // Only our validated mkdtemp-created artifact staging directory is removed.
    await fs.rm(temporary, { recursive: true, force: true })
  }
}
console.log(
  userFlavor
    ? 'NetworkControl build complete. Unsigned and not notarized: macOS asks for confirmation on first launch. Native privileged adapters remain unavailable.'
    : 'Unlaunched developer build complete. No Developer ID signature/notarization; not qualified for distribution. Native privileged adapters remain unavailable.',
)
