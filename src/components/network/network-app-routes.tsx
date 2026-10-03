import AddRounded from '@mui/icons-material/AddRounded'
import DeleteOutlineRounded from '@mui/icons-material/DeleteOutlineRounded'
import FolderOpenOutlined from '@mui/icons-material/FolderOpenOutlined'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Chip,
  FormControlLabel,
  IconButton,
  LinearProgress,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material'
import { open } from '@tauri-apps/plugin-dialog'
import { useLockFn } from 'ahooks'
import { useState } from 'react'

import { BaseDialog } from '@/components/base'
import {
  applyNetworkAppRoutes,
  getNetworkAppRoutes,
  resolveNetworkAppRoutePath,
  saveNetworkAppRoutes,
} from '@/services/network-app-routes'
import {
  createAppRoutingDraft,
  isAppRoutingApplied,
  isAppRoutingDraftDirty,
  missingAppRoutes,
  refreshAppRoutingDraft,
} from '@/services/network-app-routes-draft'
import { errorDetail, showNotice } from '@/services/notice-service'
import { setCacheData, useQuery } from '@/services/query-client'
import type {
  AppRouteCandidate,
  AppRoutingPolicy,
  AppRoutingWorkspace,
} from '@/types/network-app-routes'
import parseTraffic from '@/utils/parse-traffic'

const QUERY_KEY = ['getNetworkAppRoutes'] as const
const bytes = (value: number) => parseTraffic(value).join(' ')

interface Props {
  enabled?: boolean
}

const AppRoutesEditor = ({
  workspace,
  refetch,
}: {
  workspace: AppRoutingWorkspace
  refetch: () => Promise<unknown>
}) => {
  const [draft, setDraft] = useState(() =>
    createAppRoutingDraft(workspace.policy),
  )
  const [selection, setSelection] = useState<AppRouteCandidate | string | null>(
    null,
  )
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [discardOpen, setDiscardOpen] = useState(false)
  const [applyTarget, setApplyTarget] = useState<{
    generation: number
    profileUid: string
    profileName: string
    enabled: boolean
  } | null>(null)
  const refreshed = refreshAppRoutingDraft(
    draft,
    workspace.policy,
    busy || applyTarget !== null || input.trim() !== '',
  )
  if (refreshed !== draft) setDraft(refreshed)

  const { policy, baseline } = draft
  const dirty = isAppRoutingDraftDirty(draft)
  const stale = workspace.policy.generation > baseline.generation
  const applied = isAppRoutingApplied(workspace)
  const missing = missingAppRoutes(policy, workspace)
  const editable = !busy && workspace.storageWritable
  const rowStatus = dirty ? 'Draft' : applied ? 'Applied' : 'Saved only'
  const candidates = workspace.apps.filter(
    (app) =>
      !policy.routes.some((rule) => rule.processPath === app.processPath),
  )
  const update = (patch: Partial<AppRoutingPolicy>) =>
    setDraft((current) => ({
      ...current,
      policy: { ...current.policy, ...patch },
    }))
  const receive = async (next: AppRoutingWorkspace) => {
    await setCacheData(QUERY_KEY, next)
    setDraft(createAppRoutingDraft(next.policy))
  }

  const save = useLockFn(async () => {
    setBusy(true)
    setError('')
    try {
      await receive(await saveNetworkAppRoutes(policy, baseline.generation))
      showNotice.success('Routing table saved. Traffic has not been changed.')
    } catch (error) {
      setError(errorDetail(error))
      await refetch()
    } finally {
      setBusy(false)
    }
  })

  const add = useLockFn(async () => {
    const path =
      typeof selection === 'object' && selection !== null
        ? selection.processPath
        : input.trim()
    if (!path) return
    setBusy(true)
    setError('')
    try {
      const app = await resolveNetworkAppRoutePath(path)
      setDraft((current) => ({
        ...current,
        policy: {
          ...current.policy,
          routes: current.policy.routes.some(
            (rule) => rule.processPath === app.processPath,
          )
            ? current.policy.routes
            : [
                ...current.policy.routes,
                {
                  processPath: app.processPath,
                  route: current.policy.defaultRoute,
                },
              ],
        },
      }))
      setSelection(null)
      setInput('')
    } catch (error) {
      setError(errorDetail(error))
    } finally {
      setBusy(false)
    }
  })

  const browse = useLockFn(async () => {
    try {
      const path = await open({
        multiple: false,
        title: 'Choose an application or executable',
      })
      if (typeof path === 'string') {
        setSelection(null)
        setInput(path)
      }
    } catch (error) {
      setError(errorDetail(error))
    }
  })

  const apply = useLockFn(async () => {
    if (!applyTarget) return
    setBusy(true)
    setError('')
    try {
      await receive(
        await applyNetworkAppRoutes(
          applyTarget.generation,
          applyTarget.profileUid,
        ),
      )
      setApplyTarget(null)
      await refetch()
    } catch (error) {
      setError(errorDetail(error))
      setApplyTarget(null)
      await refetch()
    } finally {
      setBusy(false)
    }
  })

  const routeSelect = (
    value: string,
    onChange: (value: string) => void,
    label: string,
  ) => (
    <TextField
      select
      size="small"
      fullWidth
      label={label}
      value={value}
      disabled={!editable}
      onChange={(event) => onChange(event.target.value)}
      sx={{ minWidth: 210 }}
      error={missing.includes(value)}
    >
      {!workspace.routeOptions.some((route) => route.name === value) && (
        <MenuItem value={value} disabled>
          {value} · unavailable
        </MenuItem>
      )}
      {workspace.routeOptions.map((route) => (
        <MenuItem
          key={route.name}
          value={route.name}
          disabled={!route.available}
        >
          {route.name}
          {route.kind === 'group'
            ? ' · group'
            : route.kind === 'node'
              ? ` · ${route.type} server`
              : ''}
          {route.selected ? ` → ${route.selected}` : ''}
        </MenuItem>
      ))}
    </TextField>
  )

  return (
    <Stack spacing={2}>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Stack
            direction="row"
            spacing={1}
            sx={{ alignItems: 'center', flexWrap: 'wrap' }}
          >
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              Application routing
            </Typography>
            <Chip
              size="small"
              color={applied && !dirty ? 'success' : 'default'}
              label={
                dirty
                  ? 'Unsaved edits'
                  : applied
                    ? 'Applied to current profile'
                    : workspace.status === 'error'
                      ? 'Apply failed'
                      : workspace.status === 'disabled'
                        ? 'Disabled in saved table'
                        : 'Saved · apply required'
              }
            />
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Choose a server or proxy/VPN group for each application. Other core
            traffic uses the default route below.
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Profile:{' '}
            {workspace.profileName ||
              workspace.profileUid ||
              'No active profile'}{' '}
            · Saved generation {workspace.policy.generation}
            {' · Core mode: '}
            {workspace.coreMode || 'unavailable'}
            {applied
              ? ` · Verified generation ${workspace.appliedGeneration}`
              : ''}
          </Typography>
          <FormControlLabel
            control={
              <Switch
                checked={policy.enabled}
                disabled={!editable}
                onChange={(_, enabled) => update({ enabled })}
              />
            }
            label="Enable this table when applied"
          />
        </Stack>
      </Paper>
      <Alert severity="info">
        Mihomo routing only: traffic must enter this core, and application
        matching depends on the core finding its executable path. This does not
        capture all system traffic, enable a VPN, or provide a kill switch.
        Existing connections may keep their previous route.
      </Alert>
      {!applied && (
        <Alert severity="info">
          Saving or disabling the table does not change live traffic. The core
          may still use an earlier table until you apply or restore profile
          routing.
        </Alert>
      )}
      {workspace.coreMode !== 'rule' && (
        <Alert severity="warning">
          Applying requires the core to already be in Rule mode. This table will
          not change the mode automatically.
        </Alert>
      )}
      {!workspace.storageWritable && (
        <Alert severity="error">
          The routing store is not writable. Changes cannot be saved or applied.
        </Alert>
      )}
      {workspace.reason && (
        <Alert severity={workspace.status === 'error' ? 'error' : 'info'}>
          {workspace.reason}
        </Alert>
      )}
      {stale && (
        <Alert severity="warning">
          The saved table changed elsewhere. Your edits are preserved; discard
          them to load the newer table before saving or applying.
        </Alert>
      )}
      {missing.length > 0 && (
        <Alert severity="warning">
          Unavailable in the current core: {missing.join(', ')}. Choose
          available routes before applying.
        </Alert>
      )}
      {error && <Alert severity="error">{error}</Alert>}
      {busy && <LinearProgress />}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <Autocomplete
          freeSolo
          fullWidth
          options={candidates}
          value={selection}
          inputValue={input}
          disabled={!editable}
          onChange={(_, value) => setSelection(value)}
          onInputChange={(_, value, reason) => {
            setInput(value)
            if (reason === 'input') setSelection(null)
          }}
          getOptionLabel={(app) =>
            typeof app === 'string'
              ? app
              : `${app.name || app.processPath} — ${app.processPath}`
          }
          getOptionKey={(app) =>
            typeof app === 'string' ? app : app.processPath
          }
          isOptionEqualToValue={(app, value) =>
            typeof value !== 'string' && app.processPath === value.processPath
          }
          renderOption={({ key, ...props }, app) => (
            <Box
              component="li"
              key={key}
              {...props}
              sx={{ display: 'block !important' }}
            >
              <Typography variant="body2">
                {app.name || app.processPath}
              </Typography>
              <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>
                {app.processPath} · {app.sources.join(', ')} ·{' '}
                {app.identityConfidence} identity
              </Typography>
            </Box>
          )}
          renderInput={(params) => (
            <TextField
              {...params}
              size="small"
              label="Choose an app or enter its executable path"
              helperText="Observed apps are suggestions, not verified ownership. Browse also accepts macOS .app bundles."
            />
          )}
        />
        <Button
          startIcon={<FolderOpenOutlined />}
          disabled={!editable}
          onClick={browse}
        >
          Browse
        </Button>
        <Button
          startIcon={<AddRounded />}
          disabled={!editable || !input.trim()}
          onClick={add}
        >
          Add app
        </Button>
      </Stack>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small" aria-label="Application routing table">
          <TableHead>
            <TableRow>
              <TableCell>Application</TableCell>
              <TableCell>Route</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Observed core traffic</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow sx={{ bgcolor: 'action.hover' }}>
              <TableCell>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  Default
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  All other traffic entering this core
                </Typography>
              </TableCell>
              <TableCell>
                {routeSelect(
                  policy.defaultRoute,
                  (defaultRoute) => update({ defaultRoute }),
                  'Default route',
                )}
              </TableCell>
              <TableCell>
                <Chip
                  size="small"
                  variant="outlined"
                  color={applied && !dirty ? 'success' : 'default'}
                  label={rowStatus}
                />
              </TableCell>
              <TableCell colSpan={2}>
                <Typography variant="caption" color="text.secondary">
                  Applies ahead of profile rules when enabled
                </Typography>
              </TableCell>
            </TableRow>
            {policy.routes.map((rule) => {
              const app = workspace.apps.find(
                (app) => app.processPath === rule.processPath,
              )
              return (
                <TableRow key={rule.processPath}>
                  <TableCell sx={{ maxWidth: 320, overflowWrap: 'anywhere' }}>
                    <Typography variant="body2">
                      {app?.name || rule.processPath.split(/[\\/]/).pop()}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {rule.processPath}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {routeSelect(
                      rule.route,
                      (route) =>
                        update({
                          routes: policy.routes.map((entry) =>
                            entry.processPath === rule.processPath
                              ? { ...entry, route }
                              : entry,
                          ),
                        }),
                      `Route for ${app?.name || rule.processPath}`,
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      variant="outlined"
                      color={applied && !dirty ? 'success' : 'default'}
                      label={
                        missing.includes(rule.route) ? 'Unavailable' : rowStatus
                      }
                    />
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {app ? (
                      <>
                        <Typography variant="body2">
                          ↑ {bytes(app.upload)} · ↓ {bytes(app.download)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {app.activeConnections} active ·{' '}
                          {app.identityConfidence} identity
                        </Typography>
                      </>
                    ) : (
                      <Typography variant="caption" color="text.secondary">
                        Not observed
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Remove app override">
                      <span>
                        <IconButton
                          size="small"
                          disabled={!editable}
                          aria-label={`Remove ${app?.name || rule.processPath}`}
                          onClick={() =>
                            update({
                              routes: policy.routes.filter(
                                (entry) =>
                                  entry.processPath !== rule.processPath,
                              ),
                            })
                          }
                        >
                          <DeleteOutlineRounded />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </TableContainer>
      <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
        <Button
          variant="contained"
          disabled={!editable || !dirty || stale}
          onClick={save}
        >
          Save table
        </Button>
        <Button
          variant="outlined"
          disabled={
            !editable ||
            dirty ||
            stale ||
            !workspace.profileUid ||
            workspace.coreMode !== 'rule' ||
            (policy.enabled && missing.length > 0)
          }
          onClick={() => {
            if (workspace.profileUid)
              setApplyTarget({
                generation: baseline.generation,
                profileUid: workspace.profileUid,
                profileName: workspace.profileName || workspace.profileUid,
                enabled: policy.enabled,
              })
          }}
        >
          {policy.enabled
            ? 'Apply to current profile'
            : 'Restore profile routing'}
        </Button>
        <Button
          disabled={busy || (!dirty && !stale && !input)}
          onClick={() => setDiscardOpen(true)}
        >
          Discard edits
        </Button>
      </Stack>
      <BaseDialog
        open={discardOpen}
        title="Discard local routing edits?"
        okBtn="Discard edits"
        cancelBtn="Keep editing"
        onCancel={() => setDiscardOpen(false)}
        onClose={() => setDiscardOpen(false)}
        onOk={() => {
          setDraft(createAppRoutingDraft(workspace.policy))
          setSelection(null)
          setInput('')
          setError('')
          setDiscardOpen(false)
        }}
      >
        The latest saved table will replace your local edits.
      </BaseDialog>
      <BaseDialog
        open={applyTarget !== null}
        title={
          applyTarget?.enabled
            ? 'Apply application routing?'
            : 'Restore profile routing?'
        }
        disableOk={
          busy ||
          dirty ||
          stale ||
          applyTarget?.generation !== workspace.policy.generation ||
          applyTarget?.profileUid !== workspace.profileUid
        }
        okBtn={applyTarget?.enabled ? 'Apply routing' : 'Restore routing'}
        cancelBtn="Cancel"
        disableCancel={busy}
        onCancel={() => {
          if (!busy) setApplyTarget(null)
        }}
        onClose={() => {
          if (!busy) setApplyTarget(null)
        }}
        onOk={apply}
      >
        <Stack spacing={1} sx={{ py: 1 }}>
          <Typography variant="body2">
            Profile: {applyTarget?.profileName}
          </Typography>
          <Typography variant="body2">
            {applyTarget?.enabled
              ? 'This reloads the core with app rules and the default route before the profile’s original rules. Only new connections are reliably affected.'
              : 'This reloads the core without this table’s overrides, restoring the profile’s own routing rules.'}
          </Typography>
          <Typography variant="body2">
            The core must already be in Rule mode. No profile switch,
            system-proxy change, or TUN activation is performed.
          </Typography>
          {applyTarget?.profileUid !== workspace.profileUid && (
            <Alert severity="warning">
              The current profile changed. Close this dialog and review it
              before applying.
            </Alert>
          )}
          {applyTarget?.generation !== workspace.policy.generation && (
            <Alert severity="warning">
              The saved generation changed. Close this dialog and review the
              latest table before applying.
            </Alert>
          )}
        </Stack>
      </BaseDialog>
    </Stack>
  )
}

export const NetworkAppRoutes = ({ enabled = true }: Props) => {
  const { data, error, isFetching, refetch } = useQuery({
    queryKey: QUERY_KEY,
    queryFn: getNetworkAppRoutes,
    enabled,
    refetchInterval: 5000,
    retry: 1,
  })
  return (
    <Stack spacing={2}>
      <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          size="small"
          startIcon={<RefreshRounded />}
          disabled={isFetching}
          onClick={() => void refetch()}
        >
          Refresh apps and routes
        </Button>
      </Box>
      {error && <Alert severity="error">{errorDetail(error)}</Alert>}
      {!data && isFetching && <LinearProgress />}
      {data && <AppRoutesEditor workspace={data} refetch={refetch} />}
    </Stack>
  )
}
