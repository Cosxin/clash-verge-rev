import type {
  FirewallAction,
  NetworkPolicy,
  NetworkRule,
  RouteAction,
  RuleMatcher,
} from '@/types/network-control'

export interface NetworkPolicyDraftState {
  source: string
  baseline: NetworkPolicy
}

export const createNetworkPolicyDraft = (
  policy: NetworkPolicy,
): NetworkPolicyDraftState => ({
  source: JSON.stringify(policy, null, 2),
  baseline: policy,
})

export const isNetworkPolicyDraftDirty = (draft: NetworkPolicyDraftState) =>
  draft.source !== JSON.stringify(draft.baseline, null, 2)

export const refreshNetworkPolicyDraft = (
  draft: NetworkPolicyDraftState,
  policy: NetworkPolicy,
  preserveLocal = false,
): NetworkPolicyDraftState => {
  if (
    policy.generation <= draft.baseline.generation ||
    preserveLocal ||
    isNetworkPolicyDraftDirty(draft)
  ) {
    return draft
  }
  return createNetworkPolicyDraft(policy)
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const isFirewallAction = (value: unknown): value is FirewallAction =>
  value === 'allow' || value === 'block' || value === 'ask'

const isRouteAction = (value: unknown): value is RouteAction =>
  isRecord(value) &&
  (value.kind === 'direct' ||
    (value.kind === 'vpn' && value.required === true) ||
    (value.kind === 'proxy_group' &&
      value.required === true &&
      typeof value.group === 'string'))

const parseMatcher = (value: unknown): RuleMatcher | null => {
  if (!isRecord(value)) return null
  for (const field of ['processPath', 'host', 'hostSuffix', 'ipCidr']) {
    if (value[field] != null && typeof value[field] !== 'string') return null
  }
  if (
    value.network != null &&
    value.network !== 'tcp' &&
    value.network !== 'udp'
  )
    return null
  if (value.unknownProcess != null && typeof value.unknownProcess !== 'boolean')
    return null
  if (value.matchAll != null && typeof value.matchAll !== 'boolean') return null
  if (
    value.ports != null &&
    (!Array.isArray(value.ports) ||
      !value.ports.every(
        (port) => typeof port === 'number' && Number.isInteger(port),
      ))
  )
    return null
  return {
    ...value,
    unknownProcess: value.unknownProcess ?? false,
    matchAll: value.matchAll ?? false,
    ports: value.ports ?? [],
  } as RuleMatcher
}

const parseRule = <Action>(
  value: unknown,
  isAction: (value: unknown) => value is Action,
): NetworkRule<Action> | null => {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.name !== 'string' ||
    typeof value.enabled !== 'boolean' ||
    typeof value.priority !== 'number' ||
    !isAction(value.action)
  )
    return null
  const matcher = parseMatcher(value.matcher)
  return matcher ? ({ ...value, matcher } as NetworkRule<Action>) : null
}

export const parseNetworkPolicyDraft = (
  source: string,
): NetworkPolicy | null => {
  try {
    const value: unknown = JSON.parse(source)
    if (
      !isRecord(value) ||
      value.schemaVersion !== 1 ||
      value.mode !== 'observe' ||
      typeof value.generation !== 'number' ||
      !Number.isSafeInteger(value.generation) ||
      !isRecord(value.defaults) ||
      !isFirewallAction(value.defaults.firewall) ||
      !isRouteAction(value.defaults.route) ||
      !Array.isArray(value.firewallRules) ||
      !Array.isArray(value.routeRules)
    )
      return null
    const firewallRules = value.firewallRules.map((rule) =>
      parseRule(rule, isFirewallAction),
    )
    const routeRules = value.routeRules.map((rule) =>
      parseRule(rule, isRouteAction),
    )
    if (
      firewallRules.some((rule) => rule === null) ||
      routeRules.some((rule) => rule === null)
    )
      return null
    return { ...value, firewallRules, routeRules } as NetworkPolicy
  } catch {
    return null
  }
}
