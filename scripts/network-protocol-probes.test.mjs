// SPDX-License-Identifier: GPL-3.0-only
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import {
  curlEgress,
  dnsQuestion,
  fixtureOptions,
  negativeProbeFailure,
  reader,
  saveReport,
  validateDns,
} from './network-protocol-probes.mjs'

const options = {
  '--tcp-url': 'https://fixture.invalid:8443/egress',
  '--destination-ip': '192.0.2.10',
  '--expected-egress': '192.0.2.10',
  '--ca-file': '/fixture/private-ca.pem',
  '--udp-dns-port': '8053',
  '--dns-name': 'example.invalid',
  '--expected-dns': '192.0.2.42',
}
const fixture = { ...fixtureOptions(options), caFile: options['--ca-file'] }

function fakeCurl() {
  const child = new EventEmitter()
  child.stdout = new EventEmitter()
  child.kill = () => child.emit('close', null, 'SIGKILL')
  let args
  const probe = curlEgress(fixture, 1080, {
    spawnProbe: (command, values, spawnOptions) => {
      assert.equal(command, 'curl')
      assert.deepEqual(spawnOptions.stdio, ['ignore', 'pipe', 'ignore'])
      args = values
      return child
    },
  })
  return { child, probe, args }
}

test('fixture inputs are explicit and cannot select userinfo, redirects or another protocol', () => {
  for (const url of [
    'http://fixture.invalid/egress',
    'https://user:synthetic-secret@fixture.invalid/egress',
    'https://@fixture.invalid/egress',
    'https://[::1]/egress',
    'https://fixture.invalid/egress#fragment',
    'https://fixture.invalid/egress?redirect=elsewhere',
  ])
    assert.throws(() => fixtureOptions({ ...options, '--tcp-url': url }))
  for (const missing of Object.keys(options))
    assert.throws(() => fixtureOptions({ ...options, [missing]: undefined }))
  assert.throws(() => fixtureOptions({ ...options, '--udp-dns-port': '65536' }))
})

test('curl waits for close and retains URL TLS identity while connecting to the explicit fixture IPv4', async () => {
  const { child, probe, args } = fakeCurl()
  assert.equal(args[0], '--disable')
  assert.equal(
    args[args.indexOf('--connect-to') + 1],
    'fixture.invalid:8443:192.0.2.10:8443',
  )
  assert.equal(args[args.indexOf('--cacert') + 1], '/fixture/private-ca.pem')
  assert.equal(args[args.indexOf('--proto') + 1], '=https')
  assert.equal(args.includes('--location'), false)
  assert.equal(args.includes('--insecure'), false)
  let settled = false
  probe.then(() => {
    settled = true
  })
  child.emit('exit', 0)
  await Promise.resolve()
  assert.equal(settled, false)
  child.stdout.emit('data', Buffer.from('192.0.2.10'))
  child.stdout.emit('data', Buffer.from('\n200'))
  child.emit('close', 0, null)
  assert.equal(await probe, '192.0.2.10')
})

test('missing/broken binaries and aborted probes cannot count as negative authentication controls or reveal errors', async () => {
  for (const kind of ['missing', 'abort', 'bad-options']) {
    const { child, probe } = fakeCurl()
    if (kind === 'missing') {
      child.emit(
        'error',
        Object.assign(new Error('synthetic-secret'), { code: 'ENOENT' }),
      )
      child.emit('close', -2, null)
    } else if (kind === 'abort') child.emit('close', null, 'SIGTERM')
    else child.emit('close', 2, null)
    const error = await probe.catch((failure) => failure)
    assert.equal(negativeProbeFailure(error), false)
    assert.equal(
      JSON.stringify({
        category: error.message,
        details: error.details,
      }).includes('synthetic-secret'),
      false,
    )
  }
  const { child, probe } = fakeCurl()
  child.emit('close', 28, null)
  const error = await probe.catch((failure) => failure)
  assert.equal(error.message, 'TCP_TIMEOUT')
  assert.equal(negativeProbeFailure(error), true)
})

test('redirect and oversized fixture replies fail without becoming authentication refusals', async () => {
  for (const response of ['192.0.2.10\n302', 'x'.repeat(1025)]) {
    const { child, probe } = fakeCurl()
    child.stdout.emit('data', Buffer.from(response))
    if (response.length < 1025) child.emit('close', 0, null)
    const error = await probe.catch((failure) => failure)
    assert.equal(negativeProbeFailure(error), false)
    assert.ok(
      ['TCP_HTTP_REDIRECT', 'TCP_PROBE_OUTPUT_LIMIT'].includes(error.message),
    )
  }
})

test('a clean SOCKS end/close rejects pending and future reads immediately rather than timing out', async () => {
  for (const event of ['end', 'close']) {
    const socket = new EventEmitter()
    socket.destroy = () => socket.emit('close')
    const read = reader(socket)
    const pending = read(2)
    socket.emit(event)
    await assert.rejects(pending, /SOCKS_CLOSED/)
    await assert.rejects(read(2), /SOCKS_CLOSED/)
  }
})

test('DNS fixture responses must match the question, transaction and explicit synthetic answer', () => {
  const query = dnsQuestion('example.invalid', Buffer.from([0x12, 0x34]))
  const header = Buffer.from(query)
  header[2] = 0x81
  header[3] = 0x80
  header.writeUInt16BE(1, 6)
  const response = Buffer.concat([
    header,
    Buffer.from('c00c000100010000003c0004c000022a', 'hex'),
  ])
  validateDns(response, query, '192.0.2.42')
  assert.throws(() => validateDns(response, query, '192.0.2.43'))
  assert.throws(() =>
    validateDns(response.subarray(0, -1), query, '192.0.2.42'),
  )
  const wrongId = Buffer.from(response)
  wrongId[0]++
  assert.throws(() => validateDns(wrongId, query, '192.0.2.42'))
  const wrongPointer = Buffer.from(response)
  wrongPointer.writeUInt16BE(0xcfff, query.length)
  assert.throws(() => validateDns(wrongPointer, query, '192.0.2.42'))
  const wrongOwner = Buffer.from(response)
  wrongOwner.writeUInt16BE(0xc014, query.length)
  assert.throws(() => validateDns(wrongOwner, query, '192.0.2.42'))
  const cyclicPointer = Buffer.from(response)
  cyclicPointer.writeUInt16BE(0xc000 | query.length, query.length)
  assert.throws(() => validateDns(cyclicPointer, query, '192.0.2.42'))
})

test('diagnostic write failure cannot suppress the private exclusive JSON report or partial TCP evidence', async () => {
  const writes = []
  const report = {
    passed: false,
    checks: [{ tcpTlsEgress: true, tcpMs: 12, udpDns: false }],
  }
  await saveReport(
    '/fixture/report.json',
    report,
    'synthetic-private-diagnostics',
    async (filename, content, flags) => {
      writes.push({ filename, content, flags })
      if (filename.endsWith('.core.log'))
        throw new Error('synthetic-write-failure')
    },
  )
  assert.equal(writes.length, 2)
  for (const write of writes)
    assert.deepEqual(write.flags, { mode: 0o600, flag: 'wx' })
  const saved = JSON.parse(writes[1].content)
  assert.equal(saved.privateDiagnosticsSaved, false)
  assert.equal(saved.checks[0].tcpTlsEgress, true)
  assert.equal(saved.checks[0].tcpMs, 12)
  assert.equal(
    writes[1].content.includes('synthetic-private-diagnostics'),
    false,
  )
})
