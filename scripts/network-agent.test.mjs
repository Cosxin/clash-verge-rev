import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  confirmAfterReadback,
  leaseCommand,
  plan,
  status,
  trial,
} from './network-agent.mjs'

const execute = promisify(execFile)
const script = fileURLToPath(new URL('./network-agent.mjs', import.meta.url))
const executable = '/fixtures/control-agent'
const input = {
  controlProcessPaths: [executable],
  group: 'Data',
  select: 'trial',
  ttlSeconds: 30,
  exclusive: true,
}

async function mockCore(t) {
  const fixture = {
    requests: [],
    flows: [
      { metadata: { processPath: executable }, chains: ['agent', 'Control'] },
    ],
    proxies: {
      Control: { type: 'Selector', now: 'agent', all: ['agent', 'alt'] },
      Data: { type: 'Selector', now: 'old', all: ['old', 'trial', 'other'] },
      old: { type: 'Direct' },
      trial: { type: 'Direct' },
      other: { type: 'Direct' },
      agent: { type: 'Direct' },
      alt: { type: 'Direct' },
    },
  }
  const secret = 'isolated-fixture-secret-never-an-active-profile'
  const server = http.createServer(async (request, response) => {
    fixture.requests.push({ method: request.method, path: request.url })
    try {
      assert.equal(request.headers.authorization, `Bearer ${secret}`)
      assert.ok(
        (request.method === 'GET' &&
          ['/proxies', '/connections', '/configs'].includes(request.url)) ||
          (['GET', 'PUT'].includes(request.method) &&
            request.url.startsWith('/proxies/')),
        'forbidden endpoint used',
      )
      let result
      if (request.url === '/proxies') result = { proxies: fixture.proxies }
      else if (request.url === '/connections')
        result = { connections: fixture.flows }
      else if (request.url === '/configs')
        result = {
          mode: 'rule',
          'find-process-mode': 'strict',
          tun: { enable: false, secret },
          secret,
          authentication: [secret],
        }
      else {
        const group =
          fixture.proxies[
            decodeURIComponent(request.url.slice('/proxies/'.length))
          ]
        assert.ok(group)
        if (request.method === 'PUT') {
          const chunks = []
          for await (const chunk of request) chunks.push(chunk)
          const payload = JSON.parse(Buffer.concat(chunks).toString())
          assert.deepEqual(Object.keys(payload), ['name'])
          assert.ok(group.all.includes(payload.name))
          group.now = payload.name
          fixture.onPut?.(payload.name)
          response.statusCode = 204
          response.end()
          return
        }
        result = group
      }
      response.end(JSON.stringify(result))
    } catch (error) {
      response.statusCode = 500
      response.end(JSON.stringify({ error: error.message }))
    }
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  fixture.core = {
    controller: `http://127.0.0.1:${server.address().port}`,
    secret,
  }
  t.after(() => {
    server.close()
    server.closeAllConnections()
  })
  return fixture
}
async function ownTrial(t, fixture) {
  const result = await trial(fixture.core, input)
  assert.equal(result.state, 'awaiting_confirmation')
  const lease = JSON.parse(await fs.readFile(result.leaseFile, 'utf8'))
  assert.deepEqual(Object.keys(lease).sort(), [
    'deadline',
    'endpoint',
    'token',
    'trialId',
  ])
  assert.equal(JSON.stringify(lease).includes(fixture.core.secret), false)
  assert.equal((await fs.stat(result.leaseFile)).mode & 0o777, 0o600)
  assert.equal(
    (await fs.stat(path.dirname(result.leaseFile))).mode & 0o777,
    0o700,
  )
  t.after(async () => {
    try {
      await leaseCommand('rollback', result.leaseFile)
    } catch {
      /* expired watchdog may already be gone */
    }
    await fs.unlink(result.leaseFile)
    await fs.rmdir(path.dirname(result.leaseFile))
  })
  return result
}
function puts(fixture) {
  return fixture.requests.filter((request) => request.method === 'PUT').length
}

test('read-only status/plan protect every live control chain and refuse missing evidence or unsafe scope', async (t) => {
  const fixture = await mockCore(t)
  assert.equal((await status(fixture.core)).readOnly, true)
  const prepared = await plan(fixture.core, input)
  assert.deepEqual(prepared.protectedGroups, ['Control', 'agent'])
  assert.equal(prepared.previous, 'old')
  fixture.proxies.trial = { type: 'Selector', now: 'Control', all: ['Control'] }
  await assert.rejects(plan(fixture.core, input), /protected/)
  fixture.proxies.trial = { type: 'Selector', now: 'other', all: ['other'] }
  fixture.proxies.other = { type: 'Selector', now: 'trial', all: ['trial'] }
  await assert.rejects(plan(fixture.core, input), /cycle/)
  fixture.proxies.other = { type: 'Direct' }
  delete fixture.proxies.trial
  await assert.rejects(plan(fixture.core, input), /unresolved/)
  fixture.proxies.trial = { type: 'Direct' }
  fixture.proxies.old = { type: 'Selector', now: 'Control', all: ['Control'] }
  await assert.rejects(plan(fixture.core, input), /protected/)
  fixture.proxies.old = { type: 'Direct' }
  await assert.rejects(
    plan(fixture.core, { ...input, group: 'Control', select: 'alt' }),
    /protected/,
  )
  fixture.flows.push({
    metadata: { processPath: executable },
    chains: ['old', 'Data'],
  })
  await assert.rejects(plan(fixture.core, input), /protected/)
  fixture.flows = []
  await assert.rejects(
    plan(fixture.core, input),
    /live core connection evidence/,
  )
  await assert.rejects(
    status({ ...fixture.core, controller: 'http://example.com' }),
    /loopback/,
  )
  await assert.rejects(
    trial(fixture.core, { ...input, exclusive: false }),
    /exclusive:true/,
  )
  assert.equal(puts(fixture), 0)
})

test('CLI requires explicit private credentials and never prints the core secret', async (t) => {
  const fixture = await mockCore(t)
  fixture.flows[0].metadata = {
    ...fixture.flows[0].metadata,
    sourceIP: '127.0.0.1',
    sourcePort: '50100',
    destinationIP: '192.0.2.1',
    destinationPort: '443',
    host: 'fixture.invalid',
    network: 'tcp',
    secret: fixture.core.secret,
  }
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), 'network-agent-test-'),
  )
  const secretFile = path.join(directory, 'secret')
  await fs.writeFile(secretFile, fixture.core.secret, { mode: 0o600 })
  t.after(async () => {
    await fs.unlink(secretFile)
    await fs.rmdir(directory)
  })
  const output = await execute(process.execPath, [
    script,
    'status',
    '--controller',
    fixture.core.controller,
    '--secret-file',
    secretFile,
  ])
  assert.equal(JSON.parse(output.stdout).readOnly, true)
  assert.deepEqual(JSON.parse(output.stdout).config, {
    mode: 'rule',
    findProcessMode: 'strict',
    tun: { enable: false },
  })
  assert.equal(JSON.parse(output.stdout).flows[0].processPath, executable)
  assert.equal(JSON.parse(output.stdout).sensitiveLocalMetadata, true)
  assert.equal(output.stdout.includes(fixture.core.secret), false)
  await assert.rejects(
    execute(process.execPath, [script, 'status']),
    /Command failed/,
  )
  assert.equal(puts(fixture), 0)
})

test('delayed confirmation readback crossing deadline/freshness never reaches acceptance', async () => {
  let clock = 1000,
    accepted = false
  const readback = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5))
    clock = 1020
    return { now: 'trial' }
  }
  await assert.rejects(
    confirmAfterReadback(
      { connectivityOk: true, checkedAt: 1000 },
      1000,
      1010,
      readback,
      () => {
        accepted = true
      },
      () => clock,
    ),
    /expired/,
  )
  assert.equal(accepted, false)
  clock = 1000
  await assert.rejects(
    confirmAfterReadback(
      { connectivityOk: true, checkedAt: 1000 },
      1000,
      20_000,
      async () => {
        clock = 11_001
        return { now: 'trial' }
      },
      () => {
        accepted = true
      },
      () => clock,
    ),
    /fresh/,
  )
  assert.equal(accepted, false)
})

test('armed detached watchdog survives CLI parent SIGKILL after PUT and restores at real TTL with vanished control flows', {
  timeout: 40_000,
}, async (t) => {
  const fixture = await mockCore(t)
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), 'network-agent-parent-test-'),
  )
  const secretFile = path.join(directory, 'secret')
  const inputFile = path.join(directory, 'input.json')
  await fs.writeFile(secretFile, fixture.core.secret, { mode: 0o600 })
  await fs.writeFile(inputFile, JSON.stringify(input), { mode: 0o600 })
  t.after(async () => {
    for (const name of await fs.readdir(directory)) {
      const target = path.join(directory, name)
      if ((await fs.stat(target)).isDirectory()) await fs.rmdir(target)
      else await fs.unlink(target)
    }
    await fs.rmdir(directory)
  })
  let parent
  fixture.onPut = (member) => {
    if (member === 'trial') {
      fixture.flows = []
      parent.kill('SIGKILL')
    }
  }
  parent = spawn(
    process.execPath,
    [
      script,
      'trial',
      '--controller',
      fixture.core.controller,
      '--secret-file',
      secretFile,
      '--input',
      inputFile,
    ],
    { env: { ...process.env, TMPDIR: directory }, stdio: 'ignore' },
  )
  await new Promise((resolve, reject) => {
    parent.once('error', reject)
    parent.once('exit', (code, signal) => {
      if (signal === 'SIGKILL') resolve()
      else reject(new Error(`Trial parent exited before kill: ${code}`))
    })
  })
  const deadline = Date.now() + 35_000
  while (fixture.proxies.Data.now !== 'old' && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 150))
  }
  await new Promise((resolve) => setTimeout(resolve, 100))
  assert.equal(fixture.proxies.Data.now, 'old')
  assert.equal(puts(fixture), 2)
})

test('fresh caller probe confirms; stale/no probe is refused and confirmed trial is not rolled back', async (t) => {
  const fixture = await mockCore(t)
  const result = await ownTrial(t, fixture)
  await assert.rejects(
    leaseCommand('confirm', result.leaseFile, {
      connectivityOk: true,
      checkedAt: result.appliedAt - 1,
    }),
    /HTTP 400/,
  )
  const confirmed = await leaseCommand('confirm', result.leaseFile, {
    connectivityOk: true,
    checkedAt: Date.now(),
  })
  assert.equal(confirmed.state, 'confirmed')
  assert.equal(
    (await leaseCommand('rollback', result.leaseFile)).state,
    'confirmed',
  )
  assert.equal(fixture.proxies.Data.now, 'trial')
  assert.equal(puts(fixture), 1)
})

test('observed other-actor selection and newly protected control chains prevent rollback writes', async (t) => {
  const fixture = await mockCore(t)
  const result = await ownTrial(t, fixture)
  fixture.proxies.Data.now = 'other'
  const conflict = await leaseCommand('rollback', result.leaseFile)
  assert.equal(conflict.state, 'conflict')
  assert.equal(conflict.ok, false)
  assert.equal(fixture.proxies.Data.now, 'other')
  assert.equal(puts(fixture), 1)
  const second = await ownTrial(t, fixture)
  fixture.flows = [
    { metadata: { processPath: executable }, chains: ['trial', 'Data'] },
  ]
  const blocked = await leaseCommand('rollback', second.leaseFile)
  assert.equal(blocked.state, 'failed')
  assert.equal(blocked.ok, false)
  assert.match(blocked.reason, /protected|protects/)
  assert.equal(puts(fixture), 2)
})
