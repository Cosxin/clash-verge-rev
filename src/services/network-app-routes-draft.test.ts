import { describe, expect, test } from 'vitest'

import type {
  AppRoutingPolicy,
  AppRoutingWorkspace,
} from '@/types/network-app-routes'

import {
  createAppRoutingDraft,
  isAppRoutingApplied,
  missingAppRoutes,
  refreshAppRoutingDraft,
} from './network-app-routes-draft'

const policy: AppRoutingPolicy = {
  schemaVersion: 1,
  generation: 2,
  enabled: true,
  defaultRoute: 'DIRECT',
  routes: [
    {
      processPath: '/Applications/Browser.app/Contents/MacOS/Browser',
      route: 'VPN A',
    },
  ],
}

const workspace: AppRoutingWorkspace = {
  schemaVersion: 1,
  policy,
  profileUid: 'profile-a',
  profileName: 'Two routes',
  appliedGeneration: 2,
  appliedProfileUid: 'profile-a',
  coreMode: 'rule',
  processLookup: 'always',
  status: 'applied',
  reason: '',
  storageWritable: true,
  apps: [],
  routeOptions: [
    { name: 'DIRECT', kind: 'direct', type: 'Direct', available: true },
    { name: 'VPN A', kind: 'group', type: 'Selector', available: true },
  ],
}

describe('application routing edit and apply status', () => {
  test('preserves dirty routing choices and their original CAS generation', () => {
    const draft = createAppRoutingDraft(policy)
    const dirty = { ...draft, policy: { ...policy, defaultRoute: 'VPN A' } }
    const remote = { ...policy, generation: 3 }
    expect(refreshAppRoutingDraft(dirty, remote)).toBe(dirty)
    expect(refreshAppRoutingDraft(draft, remote, true)).toBe(draft)
    expect(refreshAppRoutingDraft(draft, remote).baseline.generation).toBe(3)
    expect(refreshAppRoutingDraft(draft, { ...policy, generation: 1 })).toBe(
      draft,
    )
  })

  test('requires a live acknowledgment for the exact policy and current profile', () => {
    expect(isAppRoutingApplied(workspace)).toBe(true)
    for (const patch of [
      { status: 'saved' as const },
      { appliedGeneration: 1 },
      { profileUid: 'profile-b' },
      { appliedProfileUid: null },
      { coreMode: 'global' },
      { processLookup: 'off' },
      { policy: { ...policy, enabled: false } },
    ]) {
      expect(isAppRoutingApplied({ ...workspace, ...patch })).toBe(false)
    }
  })

  test('keeps missing routes visible rather than falling back to DIRECT', () => {
    const missing = {
      ...workspace,
      routeOptions: workspace.routeOptions.slice(0, 1),
    }
    expect(missingAppRoutes(policy, missing)).toEqual(['VPN A'])
    expect(policy.routes[0].route).toBe('VPN A')
  })
})
