import FolderOpenOutlined from '@mui/icons-material/FolderOpenOutlined'
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Chip,
  List,
  ListItem,
  ListItemText,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { open } from '@tauri-apps/plugin-dialog'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import {
  getNetworkAppRoutes,
  resolveNetworkAppRoutePath,
} from '@/services/network-app-routes'
import {
  getNativeFirewallStatus,
  setNativeAppBan,
} from '@/services/network-control'
import { errorDetail, showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'
import type { AppRouteCandidate } from '@/types/network-app-routes'

export const NetworkAppBans = () => {
  const { t } = useTranslation()
  const [path, setPath] = useState('')
  const [selection, setSelection] = useState<AppRouteCandidate | string | null>(
    null,
  )
  const [pending, setPending] = useState<{
    path: string
    name: string
    blocked: boolean
    generation: number
    instanceId: string
  } | null>(null)
  const [loading, setLoading] = useState(false)
  const {
    data: status,
    error,
    refetch,
  } = useQuery({
    queryKey: ['getNativeFirewallStatus'],
    queryFn: getNativeFirewallStatus,
    refetchInterval: 5000,
    retry: 1,
  })
  const available = Boolean(
    status?.installed &&
      status.active &&
      status.authenticated &&
      status.instanceId,
  )
  const { data: candidates, error: candidatesError } = useQuery({
    queryKey: ['getNetworkAppRoutes'],
    queryFn: getNetworkAppRoutes,
    enabled: available,
    refetchInterval: 5000,
    retry: 1,
  })
  const stale =
    pending !== null &&
    (pending.generation !== status?.generation ||
      pending.instanceId !== status?.instanceId)
  const appLabel = (app: AppRouteCandidate) =>
    `${app.name || app.processPath} — ${app.processPath}`

  const prepare = useLockFn(async (processPath: string, blocked: boolean) => {
    if (!available || !processPath) return
    setLoading(true)
    try {
      const app = blocked ? await resolveNetworkAppRoutePath(processPath) : null
      const { data: current } = await refetch()
      if (
        !current?.installed ||
        !current.active ||
        !current.authenticated ||
        !current.instanceId
      ) {
        throw new Error(
          'The native provider is unavailable. Refresh its status before confirming.',
        )
      }
      setPending({
        path: app?.processPath || processPath,
        name: app?.name || processPath.split(/[\\/]/).pop() || processPath,
        blocked,
        generation: current.generation,
        instanceId: current.instanceId,
      })
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  const browse = useLockFn(async () => {
    setLoading(true)
    try {
      const selected = await open({
        multiple: false,
        title: 'Choose an application or executable',
      })
      if (typeof selected !== 'string') return
      const app = await resolveNetworkAppRoutePath(selected)
      setSelection(app)
      setPath(appLabel(app))
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  const apply = useLockFn(async () => {
    if (!pending || !available || stale) return
    setLoading(true)
    try {
      const { data: current } = await refetch()
      if (
        !current?.installed ||
        !current.active ||
        !current.authenticated ||
        current.generation !== pending.generation ||
        current.instanceId !== pending.instanceId
      ) {
        throw new Error(
          'The native provider or policy changed. Close this confirmation and review the latest status.',
        )
      }
      await setNativeAppBan(
        pending.path,
        pending.blocked,
        pending.generation,
        pending.instanceId,
      )
      await refetch()
      setPending(null)
      setPath('')
      setSelection(null)
      showNotice.success('network.bans.applied')
    } catch (error) {
      showNotice.error(error)
      await refetch()
    } finally {
      setLoading(false)
    }
  })

  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack spacing={2}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
            {t('network.bans.title')}
          </Typography>
          <Chip
            size="small"
            variant="outlined"
            color={
              available && status?.policyInitialized ? 'success' : 'default'
            }
            label={t(
              available && status?.policyInitialized
                ? 'network.bans.active'
                : 'network.status.unavailable',
            )}
          />
        </Stack>
        <Typography variant="body2" color="text.secondary">
          {t('network.bans.description')}
        </Typography>
        {!available && (
          <Alert severity="warning">
            {t('network.bans.unavailable')}
            {status?.reason ? ` ${status.reason}` : ''}
          </Alert>
        )}
        {error && <Alert severity="error">{errorDetail(error)}</Alert>}
        {available && !status?.policyInitialized && (
          <Alert severity="warning">{t('network.bans.uninitialized')}</Alert>
        )}
        {available && status?.existingFlowBehavior === 'new_flows_only' && (
          <Alert severity="warning">{t('network.bans.newFlowsOnly')}</Alert>
        )}
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          <Autocomplete
            freeSolo
            fullWidth
            options={candidates?.apps || []}
            value={selection}
            inputValue={path}
            disabled={loading || !available}
            onChange={(_, value) => setSelection(value)}
            onInputChange={(_, value, reason) => {
              setPath(value)
              if (reason === 'input') setSelection(null)
            }}
            getOptionLabel={(app) =>
              typeof app === 'string' ? app : appLabel(app)
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
                label="Choose an application"
                helperText="Choose a running or observed app, or Browse for an app/executable. An exact path may also be entered."
              />
            )}
          />
          <Button
            startIcon={<FolderOpenOutlined />}
            disabled={loading || !available}
            onClick={browse}
          >
            Browse
          </Button>
          <Button
            color="error"
            variant="outlined"
            disabled={loading || !available || !path.trim()}
            onClick={() =>
              void prepare(
                typeof selection === 'object' && selection !== null
                  ? selection.processPath
                  : path.trim(),
                true,
              )
            }
          >
            {t('network.bans.ban')}
          </Button>
        </Stack>
        {candidatesError && (
          <Alert severity="info">
            App suggestions could not be loaded. Browse remains available.{' '}
            {errorDetail(candidatesError)}
          </Alert>
        )}
        <List disablePadding>
          {status?.processPaths.map((processPath) => (
            <ListItem
              key={processPath}
              disableGutters
              secondaryAction={
                <Button
                  disabled={loading || !available}
                  onClick={() => void prepare(processPath, false)}
                >
                  {t('network.bans.unban')}
                </Button>
              }
            >
              <ListItemText
                primary={processPath}
                secondary={t(
                  available && status.policyInitialized
                    ? 'network.bans.active'
                    : 'network.bans.inactive',
                )}
                sx={{ pr: 8, overflowWrap: 'anywhere' }}
              />
            </ListItem>
          ))}
        </List>
        <BaseDialog
          open={pending !== null}
          title={t(
            pending?.blocked
              ? 'network.bans.confirmBan'
              : 'network.bans.confirmUnban',
          )}
          disableOk={loading || !available || stale}
          okBtn={t(
            pending?.blocked ? 'network.bans.ban' : 'network.bans.unban',
          )}
          cancelBtn={t('shared.actions.cancel')}
          loading={loading}
          disableCancel={loading}
          onCancel={() => {
            if (!loading) setPending(null)
          }}
          onClose={() => {
            if (!loading) setPending(null)
          }}
          onOk={apply}
        >
          <Stack spacing={1} sx={{ py: 1 }}>
            <Typography variant="body2">{pending?.name}</Typography>
            <Typography variant="body2">
              {t('network.bans.confirmDescription')}
            </Typography>
            <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
              {pending?.path}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Confirmed policy generation: {pending?.generation}
            </Typography>
            {stale && (
              <Alert severity="warning">
                The native provider or policy changed. Close this confirmation
                and select the action again; it cannot be applied to the new
                state.
              </Alert>
            )}
          </Stack>
        </BaseDialog>
      </Stack>
    </Paper>
  )
}
