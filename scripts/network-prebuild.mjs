import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

import AdmZip from 'adm-zip'
import { list } from 'tar'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const pins = JSON.parse(
  await fs.readFile(path.join(repo, 'scripts/network-assets.json'), 'utf8'),
)
const args = process.argv.slice(2)
const target = args[0]
const cacheArg = args.indexOf('--cache')
const cache = path.resolve(
  cacheArg < 0
    ? path.join(repo, 'node_modules/.network-assets')
    : (args[cacheArg + 1] ?? ''),
)
const selected = pins.targets[target]
if (!selected || (cacheArg >= 0 && !args[cacheArg + 1])) {
  throw new Error(
    `Usage: node scripts/network-prebuild.mjs <target> [--download] [--cache <directory>]. Targets: ${Object.keys(pins.targets).join(', ')}`,
  )
}
const windows = target.includes('windows')
const linux = target.includes('linux')
const extension = windows ? '.exe' : ''
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const MAX_BINARY_BYTES = 128 * 1024 * 1024

async function archiveFor(kind) {
  const asset = selected[kind]
  const file = path.join(cache, asset.name)
  try {
    const bytes = await fs.readFile(file)
    if (sha256(bytes) !== asset.sha256)
      throw new Error(`Checksum mismatch: ${file}`)
    return file
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (!args.includes('--download'))
    throw new Error(
      `Missing ${file}; pass --download once or supply a verified cache.`,
    )
  await fs.mkdir(cache, { recursive: true })
  const base =
    kind === 'core'
      ? `https://github.com/MetaCubeX/mihomo/releases/download/${pins.coreVersion}`
      : `https://github.com/clash-verge-rev/clash-verge-service-ipc/releases/download/${pins.serviceVersion}`
  const temporary = `${file}.${process.pid}.part`
  try {
    execFileSync(
      'curl',
      [
        '--fail',
        '--location',
        '--proto',
        '=https',
        '--proto-redir',
        '=https',
        '--tlsv1.2',
        '--retry',
        '3',
        '--output',
        temporary,
        `${base}/${asset.name}`,
      ],
      { stdio: 'inherit' },
    )
    if (sha256(await fs.readFile(temporary)) !== asset.sha256)
      throw new Error(`Checksum mismatch: ${asset.name}; refusing to stage.`)
    await fs.rename(temporary, file)
  } finally {
    await fs.rm(temporary, { force: true })
  }
  return file
}

async function archiveEntries(file, names) {
  const result = new Map()
  function accept(name, bytes) {
    const base = path.posix.basename(name.replaceAll('\\', '/'))
    if (!names.includes(base)) return
    if (result.has(base)) throw new Error(`Duplicate archive binary: ${base}`)
    if (bytes.length > MAX_BINARY_BYTES)
      throw new Error(`Oversized archive binary: ${base}`)
    result.set(base, bytes)
  }
  if (file.endsWith('.zip')) {
    for (const entry of new AdmZip(file).getEntries()) {
      if (
        !entry.isDirectory &&
        names.includes(path.posix.basename(entry.entryName))
      )
        accept(entry.entryName, entry.getData())
    }
  } else {
    await list({
      file,
      onReadEntry: (entry) => {
        const name = path.posix.basename(entry.path)
        if (entry.type !== 'File' || !names.includes(name)) return
        if (entry.size > MAX_BINARY_BYTES)
          throw new Error(`Oversized archive binary: ${name}`)
        const chunks = []
        entry.on('data', (chunk) => chunks.push(chunk))
        entry.on('end', () => accept(entry.path, Buffer.concat(chunks)))
      },
    })
  }
  for (const name of names)
    if (!result.has(name)) throw new Error(`Missing archive binary: ${name}`)
  return result
}

const staged = []
async function stage(relative, bytes, executable = true, record = true) {
  if (bytes.length > MAX_BINARY_BYTES)
    throw new Error(`Oversized staged file: ${relative}`)
  const file = path.join(repo, relative)
  await fs.mkdir(path.dirname(file), { recursive: true })
  try {
    const existing = await fs.readFile(file)
    if (sha256(existing) !== sha256(bytes))
      throw new Error(`Existing file differs: ${file}. Refusing to overwrite.`)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    await fs.writeFile(file, bytes, {
      flag: 'wx',
      mode: executable ? 0o755 : 0o644,
    })
  }
  if (executable && !windows) await fs.chmod(file, 0o755)
  if (record)
    staged.push({ path: relative, sha256: sha256(bytes), bytes: bytes.length })
}

const coreArchive = await archiveFor('core')
const coreName =
  selected.core.name
    .slice(0, -path.extname(selected.core.name).length)
    .replace(`-${pins.coreVersion}`, '') + extension
const core = windows
  ? (await archiveEntries(coreArchive, [coreName])).get(coreName)
  : gunzipSync(await fs.readFile(coreArchive), {
      maxOutputLength: MAX_BINARY_BYTES,
    })
await stage(`src-tauri/sidecar/verge-mihomo-${target}${extension}`, core)
const services = [
  'clash-verge-service',
  'clash-verge-service-install',
  'clash-verge-service-uninstall',
]
const serviceArchive = await archiveFor('service')
const binaries = await archiveEntries(
  serviceArchive,
  services.map((name) => name + extension),
)
for (const name of services) {
  const file = linux
    ? `src-tauri/sidecar/${name}-${target}`
    : `src-tauri/resources/${name}${extension}`
  await stage(file, binaries.get(name + extension))
}
if (target.includes('apple')) {
  for (const script of ['set_dns.sh', 'unset_dns.sh'])
    await stage(
      `src-tauri/resources/${script}`,
      await fs.readFile(path.join(repo, 'scripts', script)),
      false,
    )
}
const manifest = {
  schemaVersion: 1,
  target,
  coreVersion: pins.coreVersion,
  serviceVersion: pins.serviceVersion,
  coreSource: pins.coreSource,
  serviceSource: pins.serviceSource,
  archives: selected,
  staged,
  alphaAvailable: false,
  geoDataBundled: false,
  nativeRuntimeTested: false,
}
await stage(
  `src-tauri/resources/network-assets-${target}.json`,
  Buffer.from(JSON.stringify(manifest, null, 2) + '\n'),
  false,
  false,
)
console.log(JSON.stringify(manifest, null, 2))
console.log(
  'Verified assets staged only. No binaries were executed, services installed, or host networking changed.',
)
