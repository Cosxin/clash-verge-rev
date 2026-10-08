import { isValidElement, useState, type ReactNode } from 'react'
import { createMemoryRouter } from 'react-router'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { navigationItems } from '@/pages/_navigation-meta'
import { router } from '@/pages/_routers'
import HomePage from '@/pages/home'
import ProfilePage from '@/pages/profiles'
import ProxyPage from '@/pages/proxies'

import { ConnectCard } from './connect-card'

const fixture = vi.hoisted(() => ({
  hostLocked: false,
  indicator: false,
  tunRequested: false,
  tunAllowed: true,
  core: { mode: 'rule', mixedPort: 7890 },
  coreError: undefined as Error | undefined,
  selectedUid: 'local-fixture',
  toggle: vi.fn(),
  patchVerge: vi.fn(),
  navigate: undefined as undefined | ((path: string) => Promise<void>),
}))

vi.mock('react', async (original) => ({
  ...(await original<typeof import('react')>()),
  useState: vi.fn((initial) => [initial, vi.fn()]),
}))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))
vi.mock('react-router', async (original) => {
  const actual = await original<typeof import('react-router')>()
  return {
    ...actual,
    createBrowserRouter: (
      routes: Parameters<typeof actual.createMemoryRouter>[0],
    ) => actual.createMemoryRouter(routes),
    useNavigate: () => fixture.navigate,
  }
})
vi.mock('@/pages/_layout', () => ({ default: () => null }))
vi.mock('@/pages/connections', () => ({ default: () => null }))
vi.mock('@/pages/home', () => ({ default: () => null }))
vi.mock('@/pages/logs', () => ({ default: () => null }))
vi.mock('@/pages/network', () => ({ default: () => null }))
vi.mock('@/pages/profiles', () => ({ default: () => null }))
vi.mock('@/pages/proxies', () => ({ default: () => null }))
vi.mock('@/pages/rules', () => ({ default: () => null }))
vi.mock('@/pages/settings', () => ({ default: () => null }))
vi.mock('@/pages/unlock', () => ({ default: () => null }))
vi.mock('ahooks', () => ({ useLockFn: (fn: unknown) => fn }))
vi.mock('@mui/icons-material', () => ({ PowerSettingsNewRounded: 'icon' }))
vi.mock('@mui/material', () => ({
  Alert: 'alert',
  Box: 'box',
  Button: 'button',
  Stack: 'stack',
  Typography: 'text',
}))
vi.mock('@/components/base', () => ({ BaseDialog: 'dialog' }))
vi.mock('@/components/home/enhanced-card', () => ({ EnhancedCard: 'card' }))
vi.mock('@/hooks/use-build-capabilities', () => ({
  useBuildCapabilities: () => ({
    hostLocked: fixture.hostLocked,
    tunLocked: !fixture.tunAllowed,
    unavailable: false,
  }),
}))
vi.mock('@/hooks/use-profiles', () => ({
  useProfiles: () => ({
    current: { uid: 'local-fixture', type: 'local', name: 'Fixture' },
  }),
}))
vi.mock('@/hooks/use-system-proxy-state', () => ({
  useSystemProxyState: () => ({
    indicator: fixture.indicator,
    toggleSystemProxy: fixture.toggle,
  }),
}))
vi.mock('@/hooks/use-system-state', () => ({
  useSystemState: () => ({ runState: { mode: 'Sidecar', opInFlight: false } }),
}))
vi.mock('@/hooks/use-verge', () => ({
  useVerge: () => ({
    verge: { enable_tun_mode: fixture.tunRequested },
    patchVerge: fixture.patchVerge,
  }),
}))
vi.mock('@/hooks/use-visibility', () => ({ useVisibility: () => true }))
vi.mock('tauri-plugin-mihomo-api', () => ({
  getBaseConfig: async () => fixture.core,
}))
vi.mock('@/services/cmds', () => ({
  getBuildCapabilities: async () => ({
    hostNetworkChanges: true,
    systemProxy: true,
    tun: fixture.tunAllowed,
  }),
  getRuntimeState: async () => ({ mode: 'Sidecar', opInFlight: false }),
  getProfiles: async () => ({
    current: fixture.selectedUid,
    items: [{ uid: fixture.selectedUid, type: 'local' }],
  }),
  getSystemProxy: vi.fn(),
  getAutotemProxy: vi.fn(),
}))
vi.mock('@/services/query-client', () => ({
  useQuery: ({ queryKey }: { queryKey: string[] }) =>
    queryKey[0] === 'getClashConfig'
      ? { data: fixture.core, error: fixture.coreError }
      : { data: { enable: fixture.indicator } },
}))

const elements = (
  node: ReactNode,
): { type: unknown; props: Record<string, any> }[] => {
  if (!isValidElement<{ children?: ReactNode }>(node)) return []
  const children = node.props.children
  return [
    node,
    ...(Array.isArray(children) ? children : [children]).flatMap(elements),
  ]
}

beforeEach(() => {
  vi.clearAllMocks()
  fixture.navigate = (path) => router.navigate(path)
  Object.assign(fixture, {
    hostLocked: false,
    indicator: false,
    tunRequested: false,
    tunAllowed: true,
    core: { mode: 'rule', mixedPort: 7890 },
    coreError: undefined,
    selectedUid: 'local-fixture',
  })
})

describe('observed Home connection status', () => {
  test.each([
    {
      label: 'addServers',
      path: navigationItems.profiles.path,
      Component: ProfilePage,
    },
    {
      label: 'chooseServer',
      path: navigationItems.proxies.path,
      Component: ProxyPage,
    },
  ])(
    'routes $label to its registered page without a 404',
    async ({ label, path, Component }) => {
      const button = elements(ConnectCard()).find(
        (node) =>
          node.type === 'button' &&
          node.props.children === `home.components.connect.actions.${label}`,
      )
      expect(button).toBeDefined()
      await button?.props.onClick()
      expect(router.state.location.pathname).toBe(path)
      expect(router.state.errors).toBeNull()
      expect(router.state.matches.at(-1)?.route.element).toMatchObject({
        type: Component,
      })
    },
  )

  test.each(['/profiles', '/proxy', '/unregistered-start-page'])(
    'recovers invalid saved route %s inside the layout',
    async (path) => {
      await router.navigate(path)
      expect(router.state.location.pathname).toBe(navigationItems.home.path)
      expect(router.state.errors).toBeNull()
      expect(router.state.matches.at(-1)?.route.element).toMatchObject({
        type: HomePage,
      })
      expect(router.state.matches[0].route.path).toBe('/')
      expect(router.state.historyAction).toBe('REPLACE')
    },
  )

  test('recovers a bad route on startup before the layout mounts', async () => {
    const restored = createMemoryRouter(router.routes, {
      initialEntries: ['/profiles'],
    })
    try {
      await vi.waitFor(() => expect(restored.state.initialized).toBe(true))
      expect(restored.state.location.pathname).toBe(navigationItems.home.path)
      expect(restored.state.errors).toBeNull()
      expect(restored.state.matches.at(-1)?.route.element).toMatchObject({
        type: HomePage,
      })
    } finally {
      restored.dispose()
    }
  })
  test('does not let an unsupported stale TUN request block proxy cleanup', async () => {
    fixture.tunRequested = true
    fixture.tunAllowed = false
    fixture.indicator = true
    const button = elements(ConnectCard()).find(
      (node) =>
        node.props.children === 'home.components.connect.actions.disconnect' &&
        node.type === 'button',
    )
    await button?.props.onClick()
    expect(fixture.toggle).toHaveBeenCalledWith(false)
    expect(fixture.patchVerge).not.toHaveBeenCalled()
  })
  test('keeps unknown build permissions disabled', () => {
    fixture.hostLocked = true
    const button = elements(ConnectCard()).find(
      (node) =>
        node.props.children === 'home.components.connect.actions.connect',
    )
    expect(button?.props.disabled).toBe(true)
  })

  test('does not label an observed proxy with failed core reads as ready', () => {
    fixture.indicator = true
    fixture.coreError = new Error('synthetic read failure')
    const card = ConnectCard()
    expect(card.props.iconColor).not.toBe('success')
    expect(
      elements(card).some(
        (node) =>
          node.props.children ===
          'home.components.connect.status.coreUnavailable',
      ),
    ).toBe(true)
  })

  test('labels Direct mode without claiming VPN egress', () => {
    fixture.indicator = true
    fixture.core.mode = 'direct'
    const card = ConnectCard()
    expect(card.props.iconColor).not.toBe('success')
    expect(
      elements(card).some(
        (node) =>
          node.props.children === 'home.components.connect.status.direct',
      ),
    ).toBe(true)
  })

  test('does not promote a TUN request to verified activity', () => {
    fixture.tunRequested = true
    const card = ConnectCard()
    expect(card.props.iconColor).not.toBe('success')
    expect(
      elements(card).some(
        (node) =>
          node.props.children === 'home.components.connect.status.disconnected',
      ),
    ).toBe(true)
  })

  test('checks the selected profile before applying a confirmed Connect', async () => {
    fixture.selectedUid = 'other-fixture'
    const dialog = elements(ConnectCard()).find(
      (node) => node.type === 'dialog',
    )
    dialog?.props.onOk()
    await vi.waitFor(() =>
      expect(vi.mocked(useState).mock.results[1].value[1]).toHaveBeenCalledWith(
        true,
      ),
    )
    expect(fixture.toggle).not.toHaveBeenCalled()
  })

  test('only confirmed Connect reaches the system-proxy toggle', async () => {
    const nodes = elements(ConnectCard())
    nodes
      .find(
        (node) =>
          node.props.children === 'home.components.connect.actions.connect' &&
          node.type === 'button',
      )
      ?.props.onClick()
    expect(fixture.toggle).not.toHaveBeenCalled()
    nodes.find((node) => node.type === 'dialog')?.props.onOk()
    await vi.waitFor(() => expect(fixture.toggle).toHaveBeenCalledWith(true))
  })
})
