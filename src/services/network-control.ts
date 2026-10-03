import { invoke } from '@tauri-apps/api/core'

import type {
  HistoryPage,
  HistoryQuery,
  LsRulesExport,
  LsRulesImport,
  NetworkPolicy,
  NativeAdapterStatus,
  NetworkWorkspace,
  PolicyPreview,
  PreviewInput,
} from '@/types/network-control'

export const getNetworkWorkspace = async () => {
  const workspace = await invoke<NetworkWorkspace>('get_network_workspace')
  if (workspace.schemaVersion !== 1) {
    throw new Error(
      'Unsupported network workspace schema: ' + workspace.schemaVersion,
    )
  }
  return workspace
}

export const saveNetworkPolicy = (
  policy: NetworkPolicy,
  expectedGeneration: number,
) =>
  invoke<NetworkPolicy>('save_network_policy', {
    policy,
    expectedGeneration,
  })

export const previewNetworkPolicy = (input: PreviewInput) =>
  invoke<PolicyPreview>('preview_network_policy', { input })

export const setNetworkHistoryEnabled = (enabled: boolean) =>
  invoke<NetworkWorkspace>('set_network_history_enabled', { enabled })

export const setNetworkHistoryLimits = (
  retentionDays: number,
  maxRecords: number,
) =>
  invoke<NetworkWorkspace>('set_network_history_limits', {
    retentionDays,
    maxRecords,
  })

export const getNetworkHistory = (query: HistoryQuery) =>
  invoke<HistoryPage>('get_network_history', { query })

export const clearNetworkHistory = () => invoke<void>('clear_network_history')

export const exportNetworkHistory = () =>
  invoke<string>('export_network_history')

export const importNetworkLsRules = (content: string) =>
  invoke<LsRulesImport>('import_network_lsrules', { content })

export const exportNetworkLsRules = (policy: NetworkPolicy) =>
  invoke<LsRulesExport>('export_network_lsrules', { policy })

export const getNativeFirewallStatus = () =>
  invoke<NativeAdapterStatus>('get_native_firewall_status')

export const setNativeAppBan = (
  processPath: string,
  blocked: boolean,
  expectedGeneration: number,
  expectedInstanceId: string,
) =>
  invoke<NativeAdapterStatus>('set_native_app_ban', {
    processPath,
    blocked,
    expectedGeneration,
    expectedInstanceId,
  })
