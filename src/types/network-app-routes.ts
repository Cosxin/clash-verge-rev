import type { IdentityConfidence } from './network-control'

export interface AppRouteRule {
  processPath: string
  route: string
}

export interface AppRoutingPolicy {
  schemaVersion: 1
  generation: number
  enabled: boolean
  defaultRoute: string
  routes: AppRouteRule[]
}

export interface AppRouteCandidate {
  name: string
  processPath: string
  sources: Array<'installed' | 'running' | 'history'>
  identityConfidence: IdentityConfidence
  upload: number
  download: number
  activeConnections: number
}

export interface AppRouteOption {
  name: string
  kind: 'direct' | 'group' | 'node'
  type: string
  selected?: string | null
  available: boolean
}

export interface AppRoutingWorkspace {
  schemaVersion: 1
  policy: AppRoutingPolicy
  profileUid: string | null
  profileName: string | null
  appliedGeneration: number | null
  appliedProfileUid: string | null
  coreMode: string | null
  processLookup: string | null
  status: 'disabled' | 'saved' | 'applied' | 'error'
  applyMode: 'live' | 'setup'
  liveRouteSelections: Record<string, string>
  defaultRoute: string | null
  reason: string
  storageWritable: boolean
  apps: AppRouteCandidate[]
  routeOptions: AppRouteOption[]
}
