// SPDX-License-Identifier: GPL-3.0-only
// Explicit, isolated real-server checks. Never changes the desktop profile or host routing.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from 'node:crypto'
import dgram from 'node:dgram'
import { constants } from 'node:fs'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import * as yaml from 'js-yaml'
import ts from 'typescript'

import {
  curlEgress,
  dnsQuestion,
  fixtureOptions,
  negativeProbeFailure,
  reader,
  saveReport,
  validateDns,
} from './network-protocol-probes.mjs'

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
      '--tcp-url',
      '--destination-ip',
      '--ca-file',
      '--udp-dns-port',
      '--dns-name',
      '--expected-dns',
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
  'Supply --core FILE --profile FILE --report FILE --expected-egress IP --tcp-url HTTPS_URL --destination-ip IP --ca-file FILE --udp-dns-port PORT --dns-name NAME --expected-dns IP [--hy2-uri FILE --reality-uri FILE]',
)
const fixture = fixtureOptions(options)

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
const trustedCa = await privateRead(options['--ca-file'])
assert.ok(
  trustedCa.includes('-----BEGIN CERTIFICATE-----'),
  'FIXTURE_CA_INVALID',
)
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
    let parsed
    try {
      parsed = parseUri((await privateRead(options[flag])).trim())
    } catch {
      throw new Error('URI_IMPORT_FAILED')
    }
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
assert.ok(
  proxies.every(
    (proxy) =>
      ['vless', 'hysteria2', 'vmess', 'trojan', 'ss'].includes(proxy.type) &&
      proxy.server === fixture.destinationIp &&
      !proxy['dialer-proxy'] &&
      !proxy.plugin,
  ),
  'Test proxies must connect directly to the supplied fixture IPv4',
)
const reportParent = await fs.realpath(
  path.dirname(path.resolve(options['--report'])),
)
const relativeReportParent = path.relative(
  await fs.realpath(repo),
  reportParent,
)
assert.ok(
  relativeReportParent === '..' ||
    relativeReportParent.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativeReportParent),
  'REPORT_OUTSIDE_CHECKOUT_REQUIRED',
)
options['--report'] = path.join(
  reportParent,
  path.basename(path.resolve(options['--report'])),
)
for (const output of [options['--report'], options['--report'] + '.core.log']) {
  try {
    await fs.lstat(output)
  } catch (error) {
    if (error.code === 'ENOENT') continue
    assert.fail('REPORT_PATH_UNAVAILABLE')
  }
  throw new Error('REPORT_PATH_EXISTS')
}
const coreSha256 = sha256(await fs.readFile(options['--core']))
const controllerPort = await availablePort()
const proxyPort = await availablePort()
assert.notEqual(controllerPort, proxyPort, 'Loopback ports collided; retry')
const temporary = await fs.mkdtemp(
  path.join(os.tmpdir(), 'network-control-protocol-check-'),
)
fixture.caFile = path.join(temporary, 'fixture-ca.pem')
try {
  await fs.writeFile(fixture.caFile, trustedCa, { mode: 0o600, flag: 'wx' })
} catch {
  await fs.rm(temporary, { recursive: true })
  assert.fail('FIXTURE_CA_COPY_FAILED')
}
const secret = randomBytes(32).toString('hex')
const report = {
  schemaVersion: 1,
  startedAt: new Date().toISOString(),
  host: process.platform,
  arch: process.arch,
  coreSha256,
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
let stoppingCore
let activeProbe
let activeUdpProbe
let interruptedSignal
let phase = 'setup'
let diagnostics = ''
const failedDiagnostics = []
function checkInterrupted() {
  if (interruptedSignal) throw new Error('VALIDATION_INTERRUPTED')
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => {
    if (interruptedSignal) return
    interruptedSignal = signal
    process.exitCode = signal === 'SIGINT' ? 130 : 143
    activeProbe?.kill('SIGTERM')
    activeUdpProbe?.()
    void stopCore()
  })
async function api(method, route, body) {
  checkInterrupted()
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
  if (stoppingCore) return stoppingCore
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null)
    return
  const processToStop = child
  stoppingCore = new Promise((resolve) => {
    const timer = setTimeout(() => processToStop.kill('SIGKILL'), 3000)
    processToStop.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
    processToStop.kill('SIGTERM')
  })
  try {
    await stoppingCore
  } finally {
    stoppingCore = null
  }
}
async function startCore(nodes) {
  checkInterrupted()
  await stopCore()
  checkInterrupted()
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
    if (spawnFailure || child.exitCode !== null || child.signalCode !== null)
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
  checkInterrupted()
  return await curlEgress(fixture, proxyPort, {
    onSpawn: (probe) => {
      activeProbe = probe
    },
  })
}
async function udpDns() {
  checkInterrupted()
  const control = net.connect(proxyPort, '127.0.0.1')
  const read = reader(control)
  const udp = dgram.createSocket('udp4')
  activeUdpProbe = () => control.destroy()
  try {
    await new Promise((resolve, reject) => {
      const onError = () => reject(new Error('UDP_BIND_FAILED'))
      udp.once('error', onError)
      udp.bind(0, '127.0.0.1', () => {
        udp.removeListener('error', onError)
        resolve()
      })
    })
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
    const query = dnsQuestion(fixture.dnsName, id)
    const target = Buffer.from([
      0,
      0,
      0,
      1,
      ...fixture.destinationIp.split('.').map(Number),
      fixture.dnsPort >> 8,
      fixture.dnsPort & 255,
    ])
    const packet = Buffer.concat([target, query])
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => finish(new Error('UDP_DNS_TIMEOUT')),
        10000,
      )
      const finish = (error) => {
        clearTimeout(timer)
        control.removeListener('end', onControlClose)
        control.removeListener('close', onControlClose)
        control.removeListener('error', onControlError)
        udp.removeListener('error', onUdpError)
        udp.removeListener('message', onMessage)
        if (error) reject(error)
        else resolve()
      }
      const onControlClose = () => finish(new Error('SOCKS_CLOSED'))
      const onControlError = () => finish(new Error('SOCKS_FAILED'))
      const onUdpError = () => finish(new Error('UDP_DNS_FAILED'))
      const onMessage = (response, peer) => {
        try {
          assert.equal(peer.address, '127.0.0.1')
          assert.equal(peer.port, relay.port)
          assert.deepEqual(response.subarray(0, target.length), target)
          validateDns(
            response.subarray(target.length),
            query,
            fixture.expectedDns,
          )
          finish()
        } catch {
          finish(new Error('UDP_DNS_INVALID_REPLY'))
        }
      }
      control.once('end', onControlClose)
      control.once('close', onControlClose)
      control.once('error', onControlError)
      udp.once('error', onUdpError)
      udp.once('message', onMessage)
      if (control.destroyed || control.readableEnded) {
        onControlClose()
        return
      }
      udp.send(packet, relay.port, '127.0.0.1', (error) => {
        if (error) finish(new Error('UDP_SEND_FAILED'))
      })
    })
  } finally {
    activeUdpProbe = null
    control.destroy()
    try {
      udp.close()
    } catch {}
  }
}
try {
  for (const [index, proxy] of proxies.entries()) {
    const label = `Protocol ${index + 1}`
    const result = { name: label, type: proxy.type }
    try {
      phase = `${label}:${proxy.type}:start`
      await startCore([proxy])
      report.coreVersion = (await api('GET', '/version')).version
      phase = `${label}:${proxy.type}:select`
      await api('PUT', '/proxies/Protocol%20Test', { name: proxy.name })
      const observed = await api('GET', '/proxies/Protocol%20Test')
      assert.equal(observed.now, proxy.name)
      phase = `${label}:${proxy.type}:tcp`
      const tcpStarted = Date.now()
      const egress = await tcpEgress()
      report.lastObservedEgress = net.isIPv4(egress) ? egress : null
      assert.equal(
        egress,
        options['--expected-egress'],
        'Wrong outbound egress',
      )
      result.tcpTlsEgress = true
      result.tcpMs = Date.now() - tcpStarted
      phase = `${label}:${proxy.type}:udp`
      await udpDns()
      result.udpDns = true
      report.checks.push(result)
      console.log(JSON.stringify(report.checks.at(-1)))
    } catch (error) {
      failedDiagnostics.push(JSON.stringify({ phase }) + '\n' + diagnostics)
      report.checks.push({
        ...result,
        passed: false,
        failedPhase: phase,
        failureCategory: /^[A-Z_]+$/.test(error.message)
          ? error.message
          : 'PROBE_OR_CORE_FAILED',
        failureDetails: error.details,
      })
      console.log(JSON.stringify(report.checks.at(-1)))
    }
  }
  report.authenticationPositiveControls = []
  for (const [index, proxy] of proxies.entries()) {
    const label = `Protocol ${index + 1}`
    phase = `${label}:${proxy.type}:authenticationPrecondition`
    const negatives = []
    if (['hysteria2', 'trojan', 'vmess'].includes(proxy.type)) {
      assert.ok(
        proxy.fingerprint && proxy['skip-cert-verify'] === false,
        'TLS test nodes must verify a pinned certificate',
      )
      negatives.push(['wrongCertificatePin', { fingerprint: '00'.repeat(32) }])
    }
    if (['hysteria2', 'trojan', 'ss'].includes(proxy.type))
      negatives.push([
        'wrongPassword',
        { password: randomBytes(32).toString('hex') },
      ])
    if (['vmess', 'vless'].includes(proxy.type))
      negatives.push(['wrongUuid', { uuid: randomUUID() }])
    if (proxy.type === 'vless' && proxy['reality-opts']) {
      const key = generateKeyPairSync('x25519')
        .publicKey.export({ type: 'spki', format: 'der' })
        .subarray(-32)
        .toString('base64url')
      negatives.push([
        'wrongRealityPublicKey',
        { 'reality-opts': { ...proxy['reality-opts'], 'public-key': key } },
      ])
    }
    if (!negatives.length) continue
    assert.ok(
      report.checks.some(
        (check) => check.name === label && check.tcpTlsEgress && check.udpDns,
      ),
      'Positive protocol control must pass before negative tests',
    )
    for (const [kind, changes] of negatives) {
      phase = `${label}:${proxy.type}:${kind}`
      await startCore([{ ...proxy, ...changes }])
      const started = Date.now()
      let refusal
      try {
        await tcpEgress()
      } catch (error) {
        if (!negativeProbeFailure(error)) throw error
        refusal = error
      }
      assert.ok(refusal, 'NEGATIVE_AUTHENTICATION_NOT_REFUSED')
      checkInterrupted()
      assert.ok(
        child?.exitCode === null && child?.signalCode === null,
        'CORE_EXITED',
      )
      await api('GET', '/version')
      report.checks.push({
        name: label,
        type: proxy.type,
        negative: kind,
        refused: true,
        authenticationCauseConfirmed: false,
        failureCategory: refusal.message,
        failureDetails: refusal.details,
        elapsedMs: Date.now() - started,
      })
      console.log(JSON.stringify(report.checks.at(-1)))
    }
    phase = `${label}:${proxy.type}:positiveControlAfterNegativeTests`
    await startCore([proxy])
    assert.equal(await tcpEgress(), options['--expected-egress'])
    report.authenticationPositiveControls.push({
      name: label,
      type: proxy.type,
      passed: true,
    })
  }
  report.positiveControlAfterNegativeTests = true
  report.passed = report.checks.every((check) => check.passed !== false)
  if (!report.passed) process.exitCode = 1
} catch (error) {
  // Do not print exception messages, YAML context, URLs, configs or core logs containing credentials.
  failedDiagnostics.push(JSON.stringify({ phase }) + '\n' + diagnostics)
  report.passed = false
  report.failedPhase = phase
  report.failureCategory = /^[A-Z_]+$/.test(error.message)
    ? error.message
    : 'PROBE_OR_CORE_FAILED'
  report.failureDetails = error.details
  process.exitCode = interruptedSignal
    ? interruptedSignal === 'SIGINT'
      ? 130
      : 143
    : 1
} finally {
  await stopCore()
  try {
    if (interruptedSignal) {
      report.interruptedSignal = interruptedSignal
      report.passed = false
      report.failureCategory = 'VALIDATION_INTERRUPTED'
    }
    await saveReport(options['--report'], report, failedDiagnostics.join('\n'))
  } finally {
    await fs.rm(temporary, { recursive: true })
  }
}
console.log(
  JSON.stringify({
    passed: report.passed,
    failedPhase: report.failedPhase,
    reportSaved: true,
  }),
)
