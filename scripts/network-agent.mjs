import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { constants, createReadStream, closeSync, writeSync } from 'node:fs'
import fs from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const MAX_INPUT = 128 * 1024
const MAX_REPLY = 2 * 1024 * 1024
const SEMANTICS = 'checked_before_write_not_atomic'
const HELP = `Network agent: status | plan | trial | confirm | rollback
status/plan are read-only. Supply --controller http://127.0.0.1:PORT (or [::1])
and --secret-file FILE; no controller/profile/secret is discovered automatically.
plan/trial: --input FILE, or bounded JSON stdin:
{"controlProcessPaths":["/canonical/agent/executable"],"group":"existing Selector",
 "select":"existing member","ttlSeconds":30,"exclusive":true}
Every control executable must have live core /connections evidence before trial.
All their current chain names are protected. Missing evidence is a refusal.
trial requires exclusive:true: no profile reload, core restart, GUI or other route
writers during the lease. Mihomo has NO authenticated instance ID or atomic CAS;
identical-name core/profile replacements cannot be detected and cross-restart
recovery is not guaranteed. Observed selection conflicts are skipped,
but GET/PUT races cannot be excluded. No disconnect-proof claim is made.
A detached watchdog is armed before PUT and attempts checked rollback at TTL.
Existing TCP connections are NOT rematched. No configuration/mode/TUN/DNS writes,
restart, native-ban or connection-deletion endpoint is used. GET /configs exposes only
mode/find-process-mode/tun.enable; status flow metadata is sensitive local information.
Visible selected dependencies cannot touch protected nodes; hidden dialer-proxy
dependencies cannot be proved from the API. Windows trials are refused.
confirm/rollback/status: --lease FILE. confirm also requires --input FILE (or stdin)
{"connectivityOk":true,"checkedAt":EPOCH_MILLISECONDS}, after your OWN fresh real
connectivity probe. This is caller attestation, not a CLI-verified internet check.
Secret goes to watchdog over a private pipe, never args/env/lease. Lease file contains
only watchdog endpoint/token/trialId/deadline; protect it like a short-lived credential.
Rollback protects newly observed control chains even if earlier control flows vanish.
Watchdog/core loss can prevent rollback; an unconfirmed result is never success.`

function check(condition, message) {
  if (!condition) throw new Error(message)
}
function hasControl(value) {
  return [...value].some(
    (character) =>
      character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
  )
}
function decode(data) {
  try {
    return JSON.parse(data)
  } catch {
    throw new Error('Invalid JSON document')
  }
}
function endpoint(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('Invalid explicit loopback endpoint')
  }
  check(
    url.protocol === 'http:' &&
      ['127.0.0.1', '[::1]'].includes(url.hostname) &&
      !url.username &&
      !url.password &&
      url.pathname === '/' &&
      !url.search &&
      !url.hash,
    'Only explicit numeric loopback HTTP endpoints without paths/credentials are allowed',
  )
  return url
}
async function bounded(stream, limit = MAX_INPUT) {
  const chunks = []
  let size = 0
  for await (const chunk of stream) {
    size += Buffer.byteLength(chunk)
    check(size <= limit, 'Input exceeds its bound')
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf8')
}
async function privateFile(name, limit) {
  let file
  try {
    file = await fs.open(name, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const stat = await file.stat()
    check(
      stat.isFile() && stat.size <= limit,
      'Explicit file must be ordinary and bounded',
    )
    if (process.platform !== 'win32') {
      check(
        stat.uid === process.getuid() && (stat.mode & 0o077) === 0,
        'Explicit credential/lease file must be owner-private',
      )
    }
    return await bounded(file.createReadStream({ autoClose: false }), limit)
  } catch (error) {
    throw new Error(
      error.code
        ? `Cannot read explicit private file (${error.code})`
        : error.message,
    )
  } finally {
    await file?.close()
  }
}
function request(base, token, method, route, body) {
  const url = endpoint(base)
  return new Promise((resolve, reject) => {
    const outgoing = http.request(
      {
        hostname: url.hostname.replace(/^\[|\]$/g, ''),
        port: url.port || 80,
        path: route,
        method,
        agent: false,
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      },
      async (response) => {
        try {
          const data = await bounded(response, MAX_REPLY)
          check(
            response.statusCode >= 200 && response.statusCode < 300,
            `Loopback endpoint refused request (HTTP ${response.statusCode})`,
          )
          resolve(data ? decode(data) : {})
        } catch (error) {
          reject(error)
        } finally {
          clearTimeout(timer)
        }
      },
    )
    const timer = setTimeout(
      () => outgoing.destroy(new Error('Bounded loopback request timed out')),
      2000,
    )
    outgoing.once('error', (error) => {
      clearTimeout(timer)
      reject(new Error(`Loopback request failed (${error.code || 'timeout'})`))
    })
    outgoing.end(body === undefined ? undefined : JSON.stringify(body))
  })
}
function changeInput(input) {
  check(
    input &&
      typeof input === 'object' &&
      !Array.isArray(input) &&
      Object.keys(input).every((key) =>
        [
          'controlProcessPaths',
          'group',
          'select',
          'ttlSeconds',
          'exclusive',
        ].includes(key),
      ),
    'Change input contains unsupported fields',
  )
  const paths = input.controlProcessPaths
  check(
    Array.isArray(paths) &&
      paths.length > 0 &&
      paths.length <= 32 &&
      new Set(paths).size === paths.length,
    'Supply 1–32 unique control executable paths',
  )
  for (const value of paths) {
    const canonical =
      typeof value === 'string' &&
      value.length <= 2048 &&
      !hasControl(value) &&
      !value.endsWith('/') &&
      !value.endsWith('\\') &&
      !value.includes(' (deleted)') &&
      ((value.startsWith('/') && path.posix.normalize(value) === value) ||
        (/^[A-Za-z]:\\/.test(value) && path.win32.normalize(value) === value))
    check(
      canonical,
      'Control process paths must be canonical absolute executable paths',
    )
  }
  for (const key of ['group', 'select'])
    check(
      typeof input[key] === 'string' &&
        input[key].length > 0 &&
        input[key].length <= 256 &&
        !hasControl(input[key]),
      'Invalid Selector/member name',
    )
  check(
    Number.isInteger(input.ttlSeconds) &&
      input.ttlSeconds >= 30 &&
      input.ttlSeconds <= 120,
    'ttlSeconds must be an integer from 30 to 120',
  )
  check(
    input.exclusive === undefined || typeof input.exclusive === 'boolean',
    'exclusive must be boolean',
  )
  return input
}
function protectedChains(connections, paths, requireEvery) {
  check(
    Array.isArray(connections),
    'Core did not provide live connection evidence',
  )
  const protectedNames = new Set()
  const counts = Object.fromEntries(paths.map((name) => [name, 0]))
  for (const flow of connections) {
    const executable = flow?.metadata?.processPath
    if (!paths.includes(executable)) continue
    check(
      Array.isArray(flow.chains) &&
        flow.chains.length > 0 &&
        flow.chains.every(
          (name) =>
            typeof name === 'string' && name.length > 0 && name.length <= 256,
        ),
      'A control flow has ambiguous/missing chain evidence',
    )
    counts[executable] += 1
    for (const name of flow.chains) protectedNames.add(name)
  }
  check(
    !requireEvery || Object.values(counts).every((count) => count > 0),
    'Every control executable requires live core connection evidence; no route is guessed',
  )
  return {
    protectedGroups: [...protectedNames].sort(),
    controlEvidence: counts,
  }
}
function selector(group, select) {
  check(
    group?.type === 'Selector' &&
      typeof group.now === 'string' &&
      Array.isArray(group.all) &&
      group.all.every((name) => typeof name === 'string') &&
      group.all.includes(group.now) &&
      group.all.includes(select),
    'Only an existing Selector and existing members may be changed',
  )
}
function dependencies(proxies, selected, protectedNames) {
  const stack = [[selected, []]],
    visited = new Set()
  let edges = 0
  while (stack.length) {
    const [name, ancestors] = stack.pop()
    check(
      !protectedNames.includes(name),
      'Selected visible dependency touches a protected control chain',
    )
    check(
      !ancestors.includes(name) && ancestors.length < 32,
      'Visible dependency cycle/depth is unsafe',
    )
    if (visited.has(name)) continue
    visited.add(name)
    check(visited.size <= 1024, 'Visible dependency graph is oversized')
    const proxy = proxies?.[name]
    check(
      proxy && typeof proxy.type === 'string',
      'Selected visible dependency is unresolved',
    )
    const group =
      ['Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay'].includes(
        proxy.type,
      ) || proxy.all !== undefined
    if (group) {
      check(
        Array.isArray(proxy.all) && proxy.all.length > 0,
        'Visible group dependencies are ambiguous',
      )
      edges += proxy.all.length
      check(
        edges <= 4096 &&
          proxy.all.every(
            (member) => typeof member === 'string' && member.length <= 256,
          ),
        'Visible dependency graph is oversized/invalid',
      )
      for (const member of proxy.all) stack.push([member, [...ancestors, name]])
    }
  }
}
export async function confirmAfterReadback(
  payload,
  appliedAt,
  deadline,
  readCurrent,
  accept,
  now = Date.now,
) {
  const fresh = () => {
    const time = now()
    check(time < deadline, 'Trial expired before confirmation acceptance')
    check(
      payload?.connectivityOk === true &&
        Number.isSafeInteger(payload.checkedAt) &&
        payload.checkedAt >= appliedAt &&
        time - payload.checkedAt >= 0 &&
        time - payload.checkedAt <= 10_000,
      'Confirmation requires your fresh post-trial real connectivity-check attestation',
    )
  }
  fresh()
  const current = await readCurrent()
  fresh()
  return accept(current)
}
export async function status(core) {
  const [proxies, flows, config] = await Promise.all([
    request(core.controller, core.secret, 'GET', '/proxies'),
    request(core.controller, core.secret, 'GET', '/connections'),
    request(core.controller, core.secret, 'GET', '/configs'),
  ])
  check(
    proxies.proxies && Array.isArray(flows.connections),
    'Malformed core status',
  )
  const text = (value, limit) =>
    typeof value === 'string'
      ? value.slice(0, limit).replaceAll(core.secret, '[redacted]')
      : ''
  const currentFlows = flows.connections.slice(0, 100).map((flow) => {
    const meta = flow.metadata || {}
    return {
      id: text(flow.id, 128),
      processPath: text(meta.processPath, 2048),
      sourceIP: text(meta.sourceIP, 128),
      sourcePort: text(String(meta.sourcePort ?? ''), 16),
      destinationIP: text(meta.destinationIP, 128),
      destinationPort: text(String(meta.destinationPort ?? ''), 16),
      host: text(meta.host, 253),
      network: text(meta.network, 16),
      chains: Array.isArray(flow.chains)
        ? flow.chains.slice(0, 16).map((name) => text(name, 256))
        : [],
    }
  })
  return {
    ok: true,
    readOnly: true,
    liveConnections: flows.connections.length,
    config: {
      mode: ['rule', 'global', 'direct'].includes(config.mode)
        ? config.mode
        : null,
      findProcessMode: ['always', 'strict', 'off'].includes(
        config['find-process-mode'],
      )
        ? config['find-process-mode']
        : null,
      tun: {
        enable:
          typeof config.tun?.enable === 'boolean' ? config.tun.enable : null,
      },
    },
    flows: currentFlows,
    truncatedFlowCount: flows.connections.length - currentFlows.length,
    sensitiveLocalMetadata: true,
    selectors: Object.fromEntries(
      Object.entries(proxies.proxies)
        .filter(([, group]) => group.type === 'Selector')
        .map(([name, group]) => [
          text(name, 256),
          {
            selected: text(group.now, 256),
            members: Array.isArray(group.all)
              ? group.all.slice(0, 512).map((member) => text(member, 256))
              : [],
          },
        ]),
    ),
  }
}
export async function plan(core, raw) {
  const input = changeInput(raw)
  const [graph, flows] = await Promise.all([
    request(core.controller, core.secret, 'GET', '/proxies'),
    request(core.controller, core.secret, 'GET', '/connections'),
  ])
  const group = graph.proxies?.[input.group]
  selector(group, input.select)
  const evidence = protectedChains(
    flows.connections,
    input.controlProcessPaths,
    true,
  )
  check(
    !evidence.protectedGroups.includes(input.group),
    'Refusing change to a protected control-flow group',
  )
  dependencies(graph.proxies, input.select, evidence.protectedGroups)
  dependencies(graph.proxies, group.now, evidence.protectedGroups)
  check(
    group.now !== input.select,
    'Requested Selector member is already selected',
  )
  return {
    ok: true,
    readOnly: true,
    group: input.group,
    previous: group.now,
    select: input.select,
    ttlSeconds: input.ttlSeconds,
    ...evidence,
    rollbackSemantics: SEMANTICS,
    warning:
      'Exclusive owner: no profile reload/core restart/GUI or other route writers. Core/profile replacement and hidden dialer-proxy dependencies unverified; no cross-restart recovery or disconnect-proof guarantee; existing TCP is not rematched',
  }
}
async function watchdog(config) {
  const { core, input, prepared } = config
  changeInput(input)
  check(
    input.exclusive === true && process.platform !== 'win32',
    'Mutating trials require exclusive Unix ownership',
  )
  endpoint(core.controller)
  const lease = {
    endpoint: '',
    token: randomBytes(32).toString('hex'),
    trialId: randomBytes(16).toString('hex'),
    deadline: 0,
  }
  let state = 'armed',
    appliedAt = 0,
    attempted = false,
    reason = '',
    queue = Promise.resolve(),
    expiry
  const snapshot = () => ({
    ok: ['awaiting_confirmation', 'confirmed', 'rolled_back'].includes(state),
    state,
    trialId: lease.trialId,
    deadline: lease.deadline,
    appliedAt,
    reason,
    rollbackSemantics: SEMANTICS,
  })
  const serialize = (operation) => {
    const next = queue.then(operation)
    queue = next.catch(() => {})
    return next
  }
  const finish = () => {
    clearTimeout(expiry)
    setTimeout(() => {
      server.close()
      server.closeAllConnections()
    }, 10_000).unref()
  }
  const rollback = async () => {
    if (['confirmed', 'rolled_back', 'conflict', 'failed'].includes(state))
      return snapshot()
    if (!attempted) {
      state = 'failed'
      reason = 'Trial was never submitted'
      finish()
      return snapshot()
    }
    try {
      const flows = await request(
        core.controller,
        core.secret,
        'GET',
        '/connections',
      )
      const evidence = protectedChains(
        flows.connections,
        input.controlProcessPaths,
        false,
      )
      check(
        !evidence.protectedGroups.includes(input.group),
        'Rollback blocked: a current control chain now protects this group',
      )
      const graph = await request(
        core.controller,
        core.secret,
        'GET',
        '/proxies',
      )
      dependencies(graph.proxies, prepared.previous, evidence.protectedGroups)
      const current = await request(
        core.controller,
        core.secret,
        'GET',
        `/proxies/${encodeURIComponent(input.group)}`,
      )
      selector(current, prepared.previous)
      if (current.now !== input.select) {
        state = 'conflict'
        reason = 'Selection changed by another actor; no rollback write'
      } else {
        await request(
          core.controller,
          core.secret,
          'PUT',
          `/proxies/${encodeURIComponent(input.group)}`,
          { name: prepared.previous },
        )
        const restored = await request(
          core.controller,
          core.secret,
          'GET',
          `/proxies/${encodeURIComponent(input.group)}`,
        )
        check(
          restored.now === prepared.previous,
          'Rollback readback is unconfirmed',
        )
        state = 'rolled_back'
      }
    } catch (error) {
      state = 'failed'
      reason = error.message
    }
    finish()
    return snapshot()
  }
  const server = http.createServer(async (incoming, response) => {
    try {
      check(
        incoming.headers.authorization === `Bearer ${lease.token}`,
        'Unauthorized watchdog request',
      )
      if (incoming.method === 'GET' && incoming.url === '/status') {
        response.end(JSON.stringify(snapshot()))
        return
      }
      check(
        incoming.method === 'POST' &&
          ['/confirm', '/rollback'].includes(incoming.url),
        'Unsupported watchdog action',
      )
      const payload = decode(await bounded(incoming, 4096))
      const result = await serialize(async () => {
        if (incoming.url === '/rollback') return rollback()
        check(state === 'awaiting_confirmation', 'Trial is not confirmable')
        return confirmAfterReadback(
          payload,
          appliedAt,
          lease.deadline,
          () =>
            request(
              core.controller,
              core.secret,
              'GET',
              `/proxies/${encodeURIComponent(input.group)}`,
            ),
          (current) => {
            if (current.now !== input.select) {
              state = 'conflict'
              reason = 'Selection changed; confirmation refused'
            } else state = 'confirmed'
            finish()
            return snapshot()
          },
        )
      })
      response.end(JSON.stringify(result))
    } catch (error) {
      response.statusCode = 400
      response.end(JSON.stringify({ ok: false, error: error.message }))
    }
  })
  server.requestTimeout = 3000
  server.headersTimeout = 3000
  server.keepAliveTimeout = 500
  server.maxConnections = 16
  server.setTimeout(3000, (socket) => socket.destroy())
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  lease.endpoint = `http://127.0.0.1:${server.address().port}`
  lease.deadline = Date.now() + input.ttlSeconds * 1000
  expiry = setTimeout(() => {
    serialize(rollback)
  }, input.ttlSeconds * 1000)
  await serialize(async () => {
    try {
      const fresh = await plan(core, input)
      check(
        fresh.previous === prepared.previous,
        'Selector changed before trial; refusing write',
      )
      attempted = true
      await request(
        core.controller,
        core.secret,
        'PUT',
        `/proxies/${encodeURIComponent(input.group)}`,
        { name: input.select },
      )
      const current = await request(
        core.controller,
        core.secret,
        'GET',
        `/proxies/${encodeURIComponent(input.group)}`,
      )
      check(current.now === input.select, 'Trial readback is unconfirmed')
      appliedAt = Date.now()
      state = 'awaiting_confirmation'
    } catch (error) {
      state = attempted ? 'unconfirmed' : 'failed'
      reason = error.message
      if (!attempted) finish()
    }
  })
  writeSync(4, JSON.stringify({ lease, ...snapshot() }))
  closeSync(4)
}
export async function trial(core, input) {
  check(
    process.platform !== 'win32',
    'Windows mutation refused until private ACL/watchdog qualification',
  )
  changeInput(input)
  check(
    input.exclusive === true,
    'Trial requires exclusive:true acknowledgment; rollback is not atomic CAS',
  )
  const prepared = await plan(core, input)
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'network-agent-'))
  await fs.chmod(directory, 0o700)
  const child = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), '_watchdog'],
    { detached: true, stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] },
  )
  child.unref()
  const output = bounded(child.stdio[4], 16 * 1024)
  child.stdio[3].once('error', () => {})
  const failed = new Promise((_, reject) =>
    child.once('error', () =>
      reject(new Error('Watchdog could not be started')),
    ),
  )
  child.stdio[3].end(JSON.stringify({ core, input, prepared }))
  let timer
  const ready = await Promise.race([
    output,
    failed,
    new Promise((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(
              'Watchdog startup unconfirmed; trial may still expire safely',
            ),
          ),
        12_000,
      )
    }),
  ]).finally(() => {
    clearTimeout(timer)
    child.stdio[3].destroy()
    child.stdio[4].destroy()
  })
  const result = decode(ready)
  const leaseFile = path.join(directory, 'lease.json')
  await fs.writeFile(leaseFile, JSON.stringify(result.lease), {
    mode: 0o600,
    flag: 'wx',
  })
  return { ...result, lease: undefined, leaseFile, prepared }
}
export async function leaseCommand(command, leaseFile, payload = {}) {
  check(
    ['status', 'confirm', 'rollback'].includes(command),
    'Unsupported lease command',
  )
  if (command !== 'status')
    check(process.platform !== 'win32', 'Windows mutations are not qualified')
  const lease = decode(await privateFile(leaseFile, 4096))
  check(
    Object.keys(lease).sort().join(',') === 'deadline,endpoint,token,trialId' &&
      /^[a-f0-9]{64}$/.test(lease.token) &&
      /^[a-f0-9]{32}$/.test(lease.trialId) &&
      Number.isSafeInteger(lease.deadline),
    'Malformed private watchdog lease',
  )
  const result = await request(
    lease.endpoint,
    lease.token,
    command === 'status' ? 'GET' : 'POST',
    `/${command}`,
    payload,
  )
  check(result.trialId === lease.trialId, 'Watchdog trial identity mismatch')
  return result
}
async function main() {
  const [command, ...args] = process.argv.slice(2)
  if (command === '_watchdog')
    return watchdog(decode(await bounded(createReadStream(null, { fd: 3 }))))
  if (!command || args.includes('--help') || command === '--help') {
    console.log(HELP)
    return
  }
  check(
    ['status', 'plan', 'trial', 'confirm', 'rollback'].includes(command),
    'Unknown command; use --help',
  )
  const options = {}
  for (let index = 0; index < args.length; index += 2) {
    check(
      ['--controller', '--secret-file', '--input', '--lease'].includes(
        args[index],
      ) &&
        args[index + 1] &&
        !options[args[index]],
      'Invalid/duplicate CLI option',
    )
    options[args[index]] = args[index + 1]
  }
  const input = async () =>
    decode(
      options['--input']
        ? await bounded(createReadStream(options['--input']))
        : await bounded(process.stdin),
    )
  let result
  if (options['--lease'])
    result = await leaseCommand(
      command,
      options['--lease'],
      command === 'confirm' ? await input() : {},
    )
  else {
    check(
      ['status', 'plan', 'trial'].includes(command),
      'This command requires an explicit --lease',
    )
    const controller = endpoint(options['--controller']).origin
    check(options['--secret-file'], 'Explicit --secret-file is required')
    const secret = (await privateFile(options['--secret-file'], 4096)).trim()
    check(
      secret.length > 0 && !/[\r\n]/.test(secret),
      'Secret file must contain one nonempty bearer secret',
    )
    const core = { controller, secret }
    result =
      command === 'status'
        ? await status(core)
        : command === 'plan'
          ? await plan(core, await input())
          : await trial(core, await input())
  }
  console.log(JSON.stringify(result))
  if (!result.ok) process.exitCode = 1
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    console.log(JSON.stringify({ ok: false, error: error.message }))
    process.exitCode = 1
  })
}
