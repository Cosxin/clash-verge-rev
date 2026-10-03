import { describe, expect, test } from 'vitest'

import {
  createNetworkPolicyDraft,
  parseNetworkPolicyDraft,
  refreshNetworkPolicyDraft,
} from './network-policy-draft'

const policy = () => ({
  schemaVersion: 1,
  generation: 0,
  mode: 'observe',
  defaults: { firewall: 'allow', route: { kind: 'direct' } },
  firewallRules: [
    {
      id: 'test-rule',
      name: 'Example',
      enabled: true,
      priority: 0,
      matcher: { host: 'example.com' },
      action: 'block',
    },
  ],
  routeRules: [],
})

describe('advanced network policy draft input', () => {
  test('refreshes a clean draft but preserves local edits and their original save generation', () => {
    const initial = parseNetworkPolicyDraft(JSON.stringify(policy()))!
    const draft = createNetworkPolicyDraft(initial)
    const remote = { ...initial, generation: 1 }
    const dirty = { ...draft, source: '{unfinished local edit' }

    expect(refreshNetworkPolicyDraft(dirty, remote)).toBe(dirty)
    expect(refreshNetworkPolicyDraft(dirty, remote).baseline.generation).toBe(0)
    expect(refreshNetworkPolicyDraft(draft, remote, true)).toBe(draft)

    const refreshed = refreshNetworkPolicyDraft(draft, remote)
    expect(refreshed.baseline.generation).toBe(1)
    expect(refreshed.source).toBe(JSON.stringify(remote, null, 2))
    expect(refreshNetworkPolicyDraft(refreshed, initial)).toBe(refreshed)
  })

  test('normalizes optional matcher fields before rendering', () => {
    const parsed = parseNetworkPolicyDraft(JSON.stringify(policy()))
    expect(parsed?.firewallRules[0].matcher).toEqual({
      host: 'example.com',
      ports: [],
      unknownProcess: false,
      matchAll: false,
    })
  })

  test('rejects malformed nested values without throwing', () => {
    for (const patch of [
      { firewallRules: [null] },
      { defaults: { firewall: 'allow', route: null } },
      {
        routeRules: [{ ...policy().firewallRules[0], action: { kind: 'vpn' } }],
      },
      {
        firewallRules: [
          { ...policy().firewallRules[0], matcher: { ports: '443' } },
        ],
      },
      { generation: Number.MAX_SAFE_INTEGER + 1 },
    ]) {
      expect(
        parseNetworkPolicyDraft(JSON.stringify({ ...policy(), ...patch })),
      ).toBeNull()
    }
    expect(parseNetworkPolicyDraft('{')).toBeNull()
  })

  test('preserves unknown predicates for backend rejection instead of silently dropping them', () => {
    const value = policy()
    const matcher = {
      ...value.firewallRules[0].matcher,
      unsupportedPredicate: 'value',
    }
    value.firewallRules[0].matcher = matcher
    const parsed = parseNetworkPolicyDraft(JSON.stringify(value))
    expect(parsed?.firewallRules[0].matcher).toHaveProperty(
      'unsupportedPredicate',
      'value',
    )
  })
})
