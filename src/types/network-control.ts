export type FirewallAction = 'allow' | 'block' | 'ask'
export type Transport = 'tcp' | 'udp'
export type IdentityConfidence = 'exact' | 'inferred' | 'unknown'

export type RouteAction =
  | { kind: 'direct' }
  | { kind: 'proxy_group'; group: string; required: true }
  | { kind: 'vpn'; required: true }

export interface RuleMatcher {
  processPath?: string | null
  unknownProcess: boolean
  host?: string | null
  hostSuffix?: string | null
  ipCidr?: string | null
  ports: number[]
  network?: Transport | null
  matchAll: boolean
}

export interface NetworkRule<Action> {
  id: string
  name: string
  enabled: boolean
  priority: number
  matcher: RuleMatcher
  action: Action
}

export type FirewallRule = NetworkRule<FirewallAction>
export type RouteRule = NetworkRule<RouteAction>

export interface NetworkPolicy {
  schemaVersion: 1
  generation: number
  mode: 'observe'
  defaults: { firewall: FirewallAction; route: RouteAction }
  firewallRules: FirewallRule[]
  routeRules: RouteRule[]
}

export interface PreviewInput {
  processPath?: string | null
  identityConfidence: IdentityConfidence
  host?: string | null
  destinationIp?: string | null
  destinationPort?: number | null
  network?: Transport | null
}

export interface PolicyPreview {
  generation: number
  firewall: FirewallAction
  firewallRuleId: string | null
  route: RouteAction | null
  routeRuleId: string | null
  enforced: false
  identityConfidence: IdentityConfidence
}

export interface NetworkCapabilities {
  nativeMonitor: boolean
  nativeFirewall: boolean
  perAppRouting: boolean
  wholeSystemMonitor: boolean
  killSwitch: boolean
  coreHistory: boolean
}

export interface NetworkWorkspace {
  schemaVersion: 1
  policy: NetworkPolicy
  capabilities: NetworkCapabilities
  effectiveMode: 'observe'
  coverage: 'core_only' | 'native_tcp_udp_and_core'
  adapterReason: string
  os: string
  recordingEnabled: boolean
  retentionDays: number
  maxRecords: number
  lastSampleAt: number | null
  lastError: string | null
  gapCount: number
  droppedRecords: number
  storageWritable: boolean
  sampleIntervalMs: number
}

export interface HistoryRecord {
  id: string
  coreId: string
  epoch: string
  firstSeenAt: number
  lastSeenAt: number
  observedEndedAt: number | null
  state: 'active' | 'ended_incomplete' | 'closed'
  start: string
  process: string
  processPath: string
  identityConfidence: IdentityConfidence
  host: string
  sourceIp: string
  sourcePort: string
  uid: number | null
  hostnameSource: 'engine_inferred' | 'unavailable'
  destinationIp: string
  destinationPort: string
  network: string
  upload: number
  download: number
  observedUpload: number
  observedDownload: number
  counterResets: number
  chains: string[]
  rule: string
  rulePayload: string
  source: 'mihomo' | 'native_macos' | 'native_windows' | 'native_linux'
  completeness: 'sampled_incomplete' | 'native_events_incomplete'
  counterSemantics:
    | 'cumulative_snapshot'
    | 'cumulative'
    | 'delta'
    | 'unavailable'
    | 'observed_ip_packet_bytes'
  pid: number | null
  nativeSequence: number
  policyGeneration: number | null
}

export interface NativeAdapterStatus {
  schemaVersion: 1
  platform: string
  installed: boolean
  active: boolean
  authenticated: boolean
  policyInitialized: boolean
  monitoring: boolean
  generation: number
  processPaths: string[]
  instanceId: string
  existingFlowBehavior: 'unavailable' | 'drop' | 'new_flows_only'
  reason: string
}

export interface HistoryQuery {
  search: string
  source?: HistoryRecord['source'] | null
  offset: number
  limit: number
}

export interface HistoryPage {
  records: HistoryRecord[]
  total: number
  observedUpload: number | null
  observedDownload: number | null
  sourceTotals: {
    source: HistoryRecord['source']
    records: number
    observedUpload: number
    observedDownload: number
  }[]
}

export interface LsDiagnostic {
  sourceIndex: number | null
  ruleId: string | null
  severity: string
  message: string
}

export interface LsRulesImport {
  rules: FirewallRule[]
  sourceCount: number
  acceptedCount: number
  rejectedCount: number
  diagnostics: LsDiagnostic[]
}

export interface LsRulesExport {
  content: string
  exportedCount: number
  rejectedCount: number
  diagnostics: LsDiagnostic[]
}
