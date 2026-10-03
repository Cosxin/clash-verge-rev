import { invoke } from '@tauri-apps/api/core'

import type {
  AppRouteCandidate,
  AppRoutingPolicy,
  AppRoutingWorkspace,
} from '@/types/network-app-routes'

export const resolveNetworkAppRoutePath = (path: string) =>
  invoke<AppRouteCandidate>('resolve_network_app_route_path', { path })

export const getNetworkAppRoutes = async () => {
  const workspace = await invoke<AppRoutingWorkspace>('get_network_app_routes')
  if (workspace.schemaVersion !== 1) {
    throw new Error(
      'Unsupported app routing schema: ' + workspace.schemaVersion,
    )
  }
  return workspace
}

export const saveNetworkAppRoutes = (
  policy: AppRoutingPolicy,
  expectedGeneration: number,
) =>
  invoke<AppRoutingWorkspace>('save_network_app_routes', {
    policy,
    expectedGeneration,
  })

export const applyNetworkAppRoutes = (
  expectedGeneration: number,
  expectedProfileUid: string,
  expectedApplyMode: 'live' | 'setup',
) =>
  invoke<AppRoutingWorkspace>('apply_network_app_routes', {
    expectedGeneration,
    expectedProfileUid,
    expectedApplyMode,
  })
