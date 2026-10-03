import type {
  AppRoutingPolicy,
  AppRoutingWorkspace,
} from '@/types/network-app-routes'

export interface AppRoutingDraft {
  baseline: AppRoutingPolicy
  policy: AppRoutingPolicy
}

export const createAppRoutingDraft = (
  policy: AppRoutingPolicy,
): AppRoutingDraft => ({
  baseline: policy,
  policy,
})

export const isAppRoutingDraftDirty = (draft: AppRoutingDraft) =>
  JSON.stringify(draft.policy) !== JSON.stringify(draft.baseline)

export const refreshAppRoutingDraft = (
  draft: AppRoutingDraft,
  policy: AppRoutingPolicy,
  preserveLocal = false,
) =>
  policy.generation > draft.baseline.generation &&
  !preserveLocal &&
  !isAppRoutingDraftDirty(draft)
    ? createAppRoutingDraft(policy)
    : draft

export const isAppRoutingApplied = (workspace: AppRoutingWorkspace) =>
  workspace.status === 'applied' &&
  workspace.policy.enabled &&
  workspace.coreMode === 'rule' &&
  workspace.processLookup === 'always' &&
  workspace.profileUid !== null &&
  workspace.appliedProfileUid === workspace.profileUid &&
  workspace.appliedGeneration === workspace.policy.generation

export const missingAppRoutes = (
  policy: AppRoutingPolicy,
  workspace: AppRoutingWorkspace,
) => {
  const available = new Set(
    workspace.routeOptions
      .filter((route) => route.available)
      .map((route) => route.name),
  )
  return [
    ...new Set([
      policy.defaultRoute,
      ...policy.routes.map((rule) => rule.route),
    ]),
  ].filter((route) => !available.has(route))
}
