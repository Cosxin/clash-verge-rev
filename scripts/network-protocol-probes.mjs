// SPDX-License-Identifier: GPL-3.0-only
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import net from 'node:net'

export function fixtureOptions(options) {
  let url
  try {
    url = new URL(options['--tcp-url'])
  } catch {
    throw new Error('FIXTURE_URL_INVALID')
  }
  assert.ok(
    url.protocol === 'https:' &&
      /^https:\/\//i.test(options['--tcp-url']) &&
      !/^https:\/\/[^/?#]*@/i.test(options['--tcp-url']) &&
      !url.username &&
      !url.password &&
      !url.hash &&
      !url.search &&
      !url.hostname.includes(':'),
    'FIXTURE_URL_INVALID',
  )
  assert.ok(net.isIPv4(options['--destination-ip']), 'FIXTURE_IP_INVALID')
  assert.ok(net.isIPv4(options['--expected-egress']), 'FIXTURE_EGRESS_INVALID')
  assert.ok(net.isIPv4(options['--expected-dns']), 'FIXTURE_DNS_INVALID')
  const port = options['--udp-dns-port']
  assert.ok(
    /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535,
    'FIXTURE_PORT_INVALID',
  )
  const name = options['--dns-name']
  assert.ok(
    typeof name === 'string' &&
      name.length <= 253 &&
      name
        .split('.')
        .every((label) =>
          /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label),
        ),
    'FIXTURE_DNS_NAME_INVALID',
  )
  assert.ok(options['--ca-file'], 'FIXTURE_CA_REQUIRED')
  return {
    url,
    destinationIp: options['--destination-ip'],
    dnsPort: Number(port),
    dnsName: name,
    expectedDns: options['--expected-dns'],
  }
}

function failure(category, details = {}) {
  return Object.assign(new Error(category), { details })
}

function curlFailure(code, signal, spawnCode) {
  if (signal || spawnCode === 'ABORT_ERR')
    return failure('TCP_PROBE_ABORTED', {
      signal: ['SIGTERM', 'SIGKILL', 'SIGINT'].includes(signal)
        ? signal
        : 'OTHER',
    })
  if (spawnCode)
    return failure('TCP_PROBE_SPAWN_FAILED', {
      spawnCode: ['ENOENT', 'EACCES', 'ENOEXEC', 'EINVAL'].includes(spawnCode)
        ? spawnCode
        : 'OTHER',
    })
  const categories = {
    5: 'TCP_PROXY_RESOLUTION_FAILED',
    6: 'TCP_DESTINATION_RESOLUTION_FAILED',
    7: 'TCP_CONNECT_FAILED',
    22: 'TCP_HTTP_FAILED',
    28: 'TCP_TIMEOUT',
    35: 'TCP_TLS_FAILED',
    51: 'TCP_TLS_IDENTITY_FAILED',
    52: 'TCP_EMPTY_REPLY',
    55: 'TCP_SEND_FAILED',
    56: 'TCP_RECEIVE_FAILED',
    60: 'TCP_TLS_TRUST_FAILED',
    97: 'TCP_PROXY_HANDSHAKE_FAILED',
  }
  return failure(categories[code] || 'TCP_PROBE_HARNESS_FAILED', {
    exitCode: Number.isInteger(code) && code >= 0 && code <= 255 ? code : null,
  })
}

export function negativeProbeFailure(error) {
  return [22, 28, 35, 51, 52, 55, 56, 60, 97].includes(error.details?.exitCode)
}

export async function curlEgress(
  fixture,
  proxyPort,
  { spawnProbe = spawn, onSpawn = () => {} } = {},
) {
  return await new Promise((resolve, reject) => {
    // --disable must be first: a user's curlrc must not add redirects or bypass TLS.
    const curl = spawnProbe(
      'curl',
      [
        '--disable',
        '--silent',
        '--show-error',
        '--fail',
        '--globoff',
        '--max-time',
        '12',
        '--proto',
        '=https',
        '--max-redirs',
        '0',
        '--noproxy',
        '',
        '--proxy',
        `http://127.0.0.1:${proxyPort}`,
        '--connect-to',
        `${fixture.url.hostname}:${fixture.url.port || '443'}:${fixture.destinationIp}:${fixture.url.port || '443'}`,
        '--cacert',
        fixture.caFile,
        '--write-out',
        '\n%{http_code}',
        fixture.url.href,
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    )
    onSpawn(curl)
    let data = ''
    let terminalFailure
    const watchdog = setTimeout(() => {
      terminalFailure = failure('TCP_PROBE_HARNESS_TIMEOUT')
      curl.kill('SIGKILL')
    }, 15000)
    curl.stdout.on('data', (chunk) => {
      if (terminalFailure) return
      data += chunk
      if (data.length > 1024) {
        data = ''
        terminalFailure = failure('TCP_PROBE_OUTPUT_LIMIT')
        curl.kill('SIGKILL')
      }
    })
    curl.once('error', (error) => {
      terminalFailure = curlFailure(null, null, error.code || 'OTHER')
    })
    curl.once('close', (code, signal) => {
      clearTimeout(watchdog)
      onSpawn(null)
      if (terminalFailure) reject(terminalFailure)
      else if (code !== 0 || signal) reject(curlFailure(code, signal))
      else {
        const separator = data.lastIndexOf('\n')
        const status = data.slice(separator + 1)
        if (separator < 0 || status !== '200')
          reject(
            failure(
              /^3\d\d$/.test(status)
                ? 'TCP_HTTP_REDIRECT'
                : 'TCP_FIXTURE_RESPONSE_INVALID',
            ),
          )
        else resolve(data.slice(0, separator).trim())
      }
    })
  })
}

export function reader(socket) {
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
  const fail = (category) => {
    failed ||= category
    if (pending) {
      clearTimeout(pending.timer)
      pending.reject(failure(category))
      pending = null
    }
  }
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    if (buffer.length > 65536) {
      fail('SOCKS_OUTPUT_LIMIT')
      socket.destroy()
    } else complete()
  })
  socket.on('error', () => fail('SOCKS_FAILED'))
  socket.on('end', () => fail('SOCKS_CLOSED'))
  socket.on('close', () => fail('SOCKS_CLOSED'))
  return (length) =>
    new Promise((resolve, reject) => {
      if (failed) {
        reject(failure(failed))
        return
      }
      assert.ok(pending == null, 'Reads must be sequential')
      pending = {
        length,
        resolve,
        reject,
        timer: setTimeout(() => {
          pending = null
          reject(failure('SOCKS_TIMEOUT'))
        }, 5000),
      }
      complete()
    })
}

export function dnsQuestion(name, id) {
  return Buffer.concat([
    id,
    Buffer.from('01000001000000000000', 'hex'),
    ...name
      .split('.')
      .flatMap((label) => [Buffer.from([label.length]), Buffer.from(label)]),
    Buffer.from([0, 0, 1, 0, 1]),
  ])
}

function dnsName(dns, start) {
  const labels = []
  const seen = new Set()
  let offset = start
  let nextOffset
  let size = 1
  for (let step = 0; step < 128; step++) {
    assert.ok(offset < dns.length && !seen.has(offset))
    seen.add(offset)
    const length = dns[offset]
    if ((length & 0xc0) === 0xc0) {
      assert.ok(offset + 1 < dns.length)
      const pointer = ((length & 0x3f) << 8) | dns[offset + 1]
      assert.ok(pointer >= 12 && pointer < offset)
      nextOffset ??= offset + 2
      offset = pointer
    } else if (!length) {
      return {
        name: labels.join('.').toLowerCase(),
        nextOffset: nextOffset ?? offset + 1,
      }
    } else {
      assert.ok(length < 64 && offset + 1 + length <= dns.length)
      size += length + 1
      assert.ok(size <= 255)
      labels.push(
        dns.subarray(offset + 1, offset + 1 + length).toString('latin1'),
      )
      offset += length + 1
    }
  }
  assert.fail('DNS_NAME_INVALID')
}

export function validateDns(dns, query, expectedIp) {
  assert.ok(
    dns.length >= query.length &&
      dns.subarray(0, 2).equals(query.subarray(0, 2)),
  )
  assert.ok(
    dns[2] & 0x80 && !(dns[2] & 0x78) && !(dns[2] & 2) && !(dns[3] & 15),
  )
  assert.equal(dns.readUInt16BE(4), 1)
  assert.ok(dns.subarray(12, query.length).equals(query.subarray(12)))
  const question = dnsName(query, 12).name
  let offset = query.length
  let matched = false
  for (let index = 0; index < dns.readUInt16BE(6); index++) {
    const owner = dnsName(dns, offset)
    offset = owner.nextOffset
    assert.ok(offset + 10 <= dns.length)
    const type = dns.readUInt16BE(offset)
    const klass = dns.readUInt16BE(offset + 2)
    const length = dns.readUInt16BE(offset + 8)
    offset += 10
    assert.ok(offset + length <= dns.length)
    if (type === 1 && klass === 1) {
      assert.equal(owner.name, question)
      assert.equal(length, 4)
      matched ||= dns.subarray(offset, offset + 4).join('.') === expectedIp
    }
    offset += length
  }
  assert.ok(matched)
}

export async function saveReport(
  filename,
  report,
  diagnostics,
  writeFile = fs.writeFile,
) {
  if (!report.passed) {
    try {
      await writeFile(`${filename}.core.log`, diagnostics.slice(-1024 * 1024), {
        mode: 0o600,
        flag: 'wx',
      })
      report.privateDiagnosticsSaved = true
    } catch {
      report.privateDiagnosticsSaved = false
    }
  }
  await writeFile(
    filename,
    `${JSON.stringify({ ...report, finishedAt: new Date().toISOString() }, null, 2)}\n`,
    {
      mode: 0o600,
      flag: 'wx',
    },
  )
}
