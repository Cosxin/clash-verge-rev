import { describe, expect, test, vi } from 'vitest'

import { useBuildCapabilities } from './use-build-capabilities'

const query = vi.hoisted(() => ({
  data: undefined as
    | {
        flavor: string
        hostNetworkChanges: boolean
        systemProxy: boolean
        tun: boolean
        service: boolean
        autostart: boolean
      }
    | undefined,
  error: undefined as Error | undefined,
}))

vi.mock('@/services/query-client', () => ({ useQuery: () => query }))
vi.mock('@/services/cmds', () => ({ getBuildCapabilities: vi.fn() }))

describe('build-aware host controls', () => {
  test('locks controls before a capability answer and after a failed read', () => {
    query.data = undefined
    query.error = undefined
    expect(useBuildCapabilities()).toMatchObject({
      hostLocked: true,
      unavailable: false,
    })
    query.error = new Error('fixture read failed')
    expect(useBuildCapabilities()).toMatchObject({
      hostLocked: true,
      unavailable: true,
    })
  })

  test('unlocks only explicitly permitted builds', () => {
    query.error = undefined
    query.data = {
      flavor: 'network-dev',
      hostNetworkChanges: false,
      systemProxy: false,
      tun: false,
      service: false,
      autostart: false,
    }
    expect(useBuildCapabilities().hostLocked).toBe(true)
    query.data = {
      flavor: 'network-control',
      hostNetworkChanges: true,
      systemProxy: true,
      tun: false,
      service: false,
      autostart: false,
    }
    expect(useBuildCapabilities()).toMatchObject({
      hostLocked: false,
      tunLocked: true,
      serviceLocked: true,
      autostartLocked: true,
    })
  })
})
