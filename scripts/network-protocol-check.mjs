// SPDX-License-Identifier: GPL-3.0-only
// Explicit, isolated real-server checks. Never changes the desktop profile or host routing.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { constants } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import dgram from 'node:dgram'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as yaml from 'js-yaml'
import ts from 'typescript'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const options = {}
for (let index = 0; index < args.length; index += 2) {
  assert.ok(
    [
      '--core',
      '--profile',
      '--report',
      '--expected-egress',
      '--hy2-uri',
      '--reality-uri',
    ].includes(args[index]),
    'Unknown option',
  )
  assert.ok(
    args[index + 1] && !options[args[index]],
    'Missing or duplicate option',
  )
  options[args[index]] = args[index + 1]
}
assert.ok(
  options['--core'] &&
    options['--profile'] &&
    options['--report'] &&
    net.isIPv4(options['--expected-egress']),
  'Supply --core FILE --profile FILE --report FILE --expected-egress IP [--hy2-uri FILE --reality-uri FILE]',
)

const sha256 = (data) => createHash('sha256').update(data).digest('hex')
async function privateRead(filename) {
  const handle = await fs.open(
    filename,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  )
  try {
    const stat = await handle.stat()
    assert.ok(
      stat.isFile() && stat.size <= 2 * 1024 * 1024,
      'Input must be an ordinary bounded file',
    )
    if (process.platform !== 'win32')
      assert.ok(
        stat.uid === process.getuid() && !(stat.mode & 0o077),
        'Profile credentials must be owner-private',
      )
    return await handle.readFile('utf8')
  } finally {
    await handle.close()
  }
}
const modules = new Map()
async function sourceModule(name) {
  if (modules.has(name)) return modules.get(name)
  assert.match(name, /^[a-z0-9-]+$/)
  const source = await fs.readFile(
    path.join(repo, 'src/utils/uri-parser', name + '.ts'),
    'utf8',
  )
  let code = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText
  for (const match of [...code.matchAll(/from ['"]\.\/([a-z0-9-]+)['"]/g)]) {
    code = code.replace(
      match[0],
      'from ' + JSON.stringify(await sourceModule(match[1])),
    )
  }
  const url =
    'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
  modules.set(name, url)
  return url
}
async function availablePort() {
  const socket = net.createServer()
  await new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.listen(0, '127.0.0.1', resolve)
  })
  const port = socket.address().port
  await new Promise((resolve) => socket.close(resolve))
  return port
}
const raw = await privateRead(options['--profile'])
let input
try {
  input = yaml.load(raw)
} catch {
  throw new Error('PROFILE_PARSE_FAILED')
}
assert.ok(
  Array.isArray(input?.proxies) &&
    input.proxies.length >= 2 &&
    input.proxies.length <= 16,
  'Supply a bounded test proxy profile',
)
const proxies = structuredClone(input.proxies)
const imports = {}
if (options['--hy2-uri'] || options['--reality-uri']) {
  const { default: parseUri } = await import(await sourceModule('index'))
  for (const [flag, kind] of [
    ['--hy2-uri', 'hysteria2'],
    ['--reality-uri', 'vless'],
  ]) {
    if (!options[flag]) continue
    const parsed = parseUri((await privateRead(options[flag])).trim())
    const index = proxies.findIndex((proxy) => proxy.type === kind)
    assert.ok(
      index >= 0 && parsed.type === kind,
      'URI protocol does not match profile',
    )
    const expected = proxies[index]
    for (const key of [
      'server',
      'port',
      'password',
      'uuid',
      'sni',
      'servername',
      'fingerprint',
      'flow',
      'reality-opts',
      'client-fingerprint',
      'skip-cert-verify',
      'udp',
      'packet-encoding',
    ]) {
      if (expected[key] !== undefined)
        assert.ok(
          JSON.stringify(parsed[key]) === JSON.stringify(expected[key]),
          'URI dropped a required connection or authentication setting',
        )
    }
    proxies[index] = parsed
    imports[kind] = { parser: 'src/utils/uri-parser/index.ts', passed: true }
  }
}
const temporary = await fs.mkdtemp(
  path.join(os.tmpdir(), 'network-control-protocol-check-'),
)
const controllerPort = await availablePort()
const proxyPort = await availablePort()
assert.notEqual(controllerPort, proxyPort, 'Loopback ports collided; retry')
const secret = randomBytes(32).toString('hex')
const report = {
  schemaVersion: 1,
  startedAt: new Date().toISOString(),
  host: process.platform,
  arch: process.arch,
  coreSha256: sha256(await fs.readFile(options['--core'])),
  profileSha256: sha256(raw),
  imports,
  expectedEgress: options['--expected-egress'],
  checks: [],
  systemProxyChanged: false,
  tunEnabled: false,
  desktopUiTested: false,
  crossPlatformRuntimeQualified: false,
}
let child
let phase = 'setup'
let diagnostics = ''
async function api(method, route, body) {
  const response = await fetch(`http://127.0.0.1:${controllerPort}${route}`, {
    method,
    headers: {
      Authorization: `Bearer ${secret}`,
      'Content-Type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(2000),
  })
  assert.ok(response.ok, 'Isolated controller rejected request')
  return response.status === 204 ? null : response.json()
}
async function stopCore() {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null)
    return
  const processToStop = child
  await new Promise((resolve) => {
    const timer = setTimeout(() => processToStop.kill('SIGKILL'), 3000)
    processToStop.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
    processToStop.kill('SIGTERM')
  })
}
async function startCore(nodes) {
  await stopCore()
  const config = {
    'mixed-port': proxyPort,
    port: 0,
    'socks-port': 0,
    'redir-port': 0,
    'tproxy-port': 0,
    'allow-lan': false,
    'bind-address': '127.0.0.1',
    'external-controller': `127.0.0.1:${controllerPort}`,
    secret,
    mode: 'rule',
    'log-level': 'warning',
    ipv6: false,
    'find-process-mode': 'strict',
    tun: { enable: false },
    dns: { enable: false },
    profile: { 'store-selected': false },
    proxies: nodes,
    'proxy-groups': [
      {
        name: 'Protocol Test',
        type: 'select',
        proxies: nodes.map((node) => node.name),
      },
    ],
    rules: ['MATCH,Protocol Test'],
  }
  const file = path.join(temporary, 'config.yaml')
  await fs.writeFile(file, yaml.dump(config), { mode: 0o600 })
  diagnostics = ''
  child = spawn(options['--core'], ['-d', temporary, '-f', file], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const collect = (chunk) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-32768)
  }
  child.stdout.on('data', collect)
  child.stderr.on('data', collect)
  let spawnFailure
  child.on('error', (error) => {
    spawnFailure = error.code || 'SPAWN_FAILED'
  })
  for (let attempt = 0; attempt < 40; attempt++) {
    if (spawnFailure || child.exitCode !== null)
      throw new Error('CORE_START_FAILED')
    try {
      await api('GET', '/version')
      return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
  }
  throw new Error('CORE_START_TIMEOUT')
}
async function tcpEgress() {
  return await new Promise((resolve, reject) => {
    const curl = spawn(
      'curl',
      [
        '--silent',
        '--show-error',
        '--fail',
        '--max-time',
        '12',
        '--noproxy',
        '',
        '--proxy',
        `http://127.0.0.1:${proxyPort}`,
        'https://api4.ipify.org',
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    )
    let data = ''
    curl.stdout.on('data', (chunk) => {
      data += chunk
      if (data.length > 1024) curl.kill()
    })
    curl.once('error', () => reject(new Error('TCP_PROBE_FAILED')))
    curl.once('exit', (code) =>
      code === 0 ? resolve(data.trim()) : reject(new Error('TCP_PROBE_FAILED')),
    )
  })
}
function reader(socket) {
  let buffer = Buffer.alloc(0)
  let pending
  let failed
  const complete = () => {
    if (pending && buffer.length >= pending.length) {
      const current = pending
      pending = null
      const result = buffer.subarray(0, current.length)
      buffer = buffer.subarray(current.length)
      clearTimeout(current.timer)
      current.resolve(result)
    }
  }
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    if (buffer.length > 65536) socket.destroy()
    complete()
  })
  socket.on('error', () => {
    failed = true
    if (pending) {
      clearTimeout(pending.timer)
      pending.reject(new Error('SOCKS_FAILED'))
      pending = null
    }
  })
  return (length) =>
    new Promise((resolve, reject) => {
      if (failed) {
        reject(new Error('SOCKS_FAILED'))
        return
      }
      assert.ok(pending == null, 'Reads must be sequential')
      pending = {
        length,
        resolve,
        reject,
        timer: setTimeout(() => {
          pending = null
          reject(new Error('SOCKS_TIMEOUT'))
        }, 5000),
      }
      complete()
    })
}
async function udpDns() {
  const control = net.connect(proxyPort, '127.0.0.1')
  const read = reader(control)
  const udp = dgram.createSocket('udp4')
  try {
    control.write(Buffer.from([5, 1, 0]))
    assert.deepEqual(await read(2), Buffer.from([5, 0]))
    control.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
    const header = await read(4)
    assert.ok(
      header[0] === 5 && header[1] === 0 && header[3] === 1,
      'Expected IPv4 UDP association',
    )
    const address = await read(6)
    const relay = {
      host: address.subarray(0, 4).join('.'),
      port: address.readUInt16BE(4),
    }
    assert.ok(
      relay.host === '127.0.0.1' || relay.host === '0.0.0.0',
      'UDP relay must be loopback',
    )
    const id = randomBytes(2)
    const query = Buffer.concat([
      id,
      Buffer.from(
        '01000001000000000000076578616d706c6503636f6d0000010001',
        'hex',
      ),
    ])
    const packet = Buffer.concat([
      Buffer.from([0, 0, 0, 1, 1, 1, 1, 1, 0, 53]),
      query,
    ])
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('UDP_DNS_TIMEOUT')),
        10000,
      )
      udp.once('error', () => {
        clearTimeout(timer)
        reject(new Error('UDP_DNS_FAILED'))
      })
      udp.once('message', (response, peer) => {
        clearTimeout(timer)
        try {
          assert.equal(peer.address, '127.0.0.1')
          assert.equal(peer.port, relay.port)
          assert.deepEqual(
            response.subarray(0, 10),
            Buffer.from([0, 0, 0, 1, 1, 1, 1, 1, 0, 53]),
          )
          const dns = response.subarray(10)
          assert.ok(
            dns.length >= 12 &&
              dns.subarray(0, 2).equals(id) &&
              dns[2] & 0x80 &&
              !(dns[3] & 15) &&
              dns.readUInt16BE(6) > 0,
          )
          resolve()
        } catch {
          reject(new Error('UDP_DNS_INVALID_REPLY'))
        }
      })
      udp.send(packet, relay.port, '127.0.0.1')
    })
  } finally {
    control.destroy()
    try {
      udp.close()
    } catch {}
  }
}
try {
  await startCore(proxies)
  report.coreVersion = (await api('GET', '/version')).version
  for (const proxy of proxies) {
    try {
      phase = proxy.name + ':select'
      await api('PUT', '/proxies/Protocol%20Test', { name: proxy.name })
      const observed = await api('GET', '/proxies/Protocol%20Test')
      assert.equal(observed.now, proxy.name)
      phase = proxy.name + ':tcp'
      const tcpStarted = Date.now()
      const egress = await tcpEgress()
      report.lastObservedEgress = net.isIPv4(egress) ? egress : null
      assert.equal(
        egress,
        options['--expected-egress'],
        'Wrong outbound egress',
      )
      const tcpMs = Date.now() - tcpStarted
      phase = proxy.name + ':udp'
      await udpDns()
      report.checks.push({
        name: proxy.name,
        type: proxy.type,
        tcpTlsEgress: true,
        udpDns: true,
        tcpMs,
      })
      console.log(JSON.stringify(report.checks.at(-1)))
    } catch (error) {
      report.checks.push({
        name: proxy.name,
        type: proxy.type,
        passed: false,
        failedPhase: phase,
        failureCategory: /^[A-Z_]+$/.test(error.message)
          ? error.message
          : 'PROBE_OR_CORE_FAILED',
      })
      console.log(JSON.stringify(report.checks.at(-1)))
    }
  }
  const hy2 = proxies.find((proxy) => proxy.type === 'hysteria2')
  assert.ok(
    hy2?.fingerprint,
    'Pinned Hysteria node required for authentication checks',
  )
  assert.ok(
    report.checks.some(
      (check) =>
        check.type === 'hysteria2' && check.tcpTlsEgress && check.udpDns,
    ),
    'Positive Hysteria control must pass before negative tests',
  )
  for (const [kind, changes] of [
    ['wrongCertificatePin', { fingerprint: '00'.repeat(32) }],
    ['wrongPassword', { password: randomBytes(32).toString('hex') }],
  ]) {
    phase = kind
    await startCore([{ ...hy2, ...changes }])
    await assert.rejects(tcpEgress())
    report.checks.push({ type: 'hysteria2', negative: kind, refused: true })
    console.log(JSON.stringify(report.checks.at(-1)))
  }
  phase = 'positiveControlAfterNegativeTests'
  await startCore([hy2])
  assert.equal(await tcpEgress(), options['--expected-egress'])
  report.positiveControlAfterNegativeTests = true
  report.passed = report.checks.every((check) => check.passed !== false)
  if (!report.passed) process.exitCode = 1
} catch (error) {
  // Do not print exception messages, YAML context, URLs, configs or core logs containing credentials.
  report.passed = false
  report.failedPhase = phase
  report.failureCategory = /^[A-Z_]+$/.test(error.message)
    ? error.message
    : 'PROBE_OR_CORE_FAILED'
  process.exitCode = 1
} finally {
  await stopCore()
  try {
    if (!report.passed)
      await fs.writeFile(options['--report'] + '.core.log', diagnostics, {
        mode: 0o600,
        flag: 'wx',
      })
    await fs.writeFile(
      options['--report'],
      JSON.stringify(
        { ...report, finishedAt: new Date().toISOString() },
        null,
        2,
      ) + '\n',
      { mode: 0o600, flag: 'wx' },
    )
  } finally {
    await fs.rm(temporary, { recursive: true })
  }
}
console.log(
  JSON.stringify({
    passed: report.passed,
    failedPhase: report.failedPhase,
    report: options['--report'],
  }),
)
