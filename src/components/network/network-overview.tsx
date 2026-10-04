import {
  Alert,
  Box,
  Button,
  Chip,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  Paper,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import {
  setNetworkHistoryEnabled,
  setNetworkHistoryLimits,
} from '@/services/network-control'
import { showNotice } from '@/services/notice-service'
import type {
  NetworkCapabilities,
  NetworkWorkspace,
} from '@/types/network-control'

interface Props {
  workspace: NetworkWorkspace
  onChanged: () => Promise<void>
}

const CAPABILITIES = [
  { id: 'nativeMonitor', label: 'network.capabilities.nativeMonitor' },
  { id: 'nativeFirewall', label: 'network.capabilities.nativeFirewall' },
  { id: 'perAppRouting', label: 'network.capabilities.perAppRouting' },
  {
    id: 'wholeSystemMonitor',
    label: 'network.capabilities.wholeSystemMonitor',
  },
  { id: 'killSwitch', label: 'network.capabilities.killSwitch' },
  { id: 'coreHistory', label: 'network.capabilities.coreHistory' },
] as const satisfies readonly { id: keyof NetworkCapabilities; label: string }[]

export const NetworkOverview = ({ workspace, onChanged }: Props) => {
  const { t } = useTranslation()
  const [retentionDays, setRetentionDays] = useState(
    String(workspace.retentionDays),
  )
  const [maxRecords, setMaxRecords] = useState(String(workspace.maxRecords))
  const [loading, setLoading] = useState(false)
  const [confirmLimits, setConfirmLimits] = useState(false)
  const [checkedAt, setCheckedAt] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setCheckedAt(Date.now()), 5000)
    return () => window.clearInterval(timer)
  }, [])
  const days = Number(retentionDays)
  const records = Number(maxRecords)
  const validLimits =
    Number.isInteger(days) &&
    days >= 1 &&
    days <= 90 &&
    Number.isInteger(records) &&
    records >= 100 &&
    records <= 20000
  const changed =
    days !== workspace.retentionDays || records !== workspace.maxRecords

  const toggleRecording = useLockFn(async (enabled: boolean) => {
    setLoading(true)
    try {
      await setNetworkHistoryEnabled(enabled)
    } catch (error) {
      showNotice.error(error)
    } finally {
      await onChanged().catch((error) => showNotice.error(error))
      setLoading(false)
    }
  })

  const saveLimits = useLockFn(async () => {
    setLoading(true)
    try {
      await setNetworkHistoryLimits(days, records)
      setConfirmLimits(false)
      showNotice.success('network.settings.saved')
    } catch (error) {
      showNotice.error(error)
    } finally {
      await onChanged().catch((error) => showNotice.error(error))
      setLoading(false)
    }
  })

  const staleSample =
    workspace.recordingEnabled &&
    workspace.lastSampleAt !== null &&
    checkedAt - workspace.lastSampleAt >
      Math.max(10000, workspace.sampleIntervalMs * 4)

  return (
    <Stack spacing={2}>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
          {t('network.capabilities.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          {t('network.capabilities.note')}
        </Typography>
        <List disablePadding>
          {CAPABILITIES.map(({ id, label }) => (
            <ListItem
              key={id}
              disableGutters
              secondaryAction={
                <Chip
                  size="small"
                  variant="outlined"
                  color={workspace.capabilities[id] ? 'info' : 'default'}
                  label={t(
                    workspace.capabilities[id]
                      ? 'network.status.available'
                      : 'network.status.unavailable',
                  )}
                />
              }
            >
              <ListItemText primary={t(label)} />
            </ListItem>
          ))}
        </List>
      </Paper>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
            {t('network.settings.title')}
          </Typography>
          <FormControlLabel
            control={
              <Switch
                checked={workspace.recordingEnabled}
                disabled={loading || !workspace.storageWritable}
                onChange={(_, enabled) => toggleRecording(enabled)}
              />
            }
            label={t('network.settings.recording')}
          />
          <Typography variant="body2" color="text.secondary">
            {t('network.settings.recordingDescription')}
          </Typography>
          <Alert severity={workspace.backgroundRecording ? 'success' : 'info'}>
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              {t(
                workspace.backgroundRecording
                  ? 'network.settings.backgroundConfirmed'
                  : 'network.settings.backgroundUnconfirmed',
              )}
            </Typography>
            {workspace.backgroundRecordingReason}
          </Alert>
          {workspace.recordingEnabled &&
            workspace.backgroundRecordingAvailable &&
            !workspace.backgroundRecording && (
              <Button
                variant="outlined"
                loading={loading}
                disabled={!workspace.storageWritable}
                onClick={() => void toggleRecording(true)}
              >
                {t('network.settings.confirmBackground')}
              </Button>
            )}
          <Alert severity="info">{t('network.settings.privacy')}</Alert>
          <Box
            sx={{
              display: 'flex',
              gap: 2,
              alignItems: 'flex-start',
              flexWrap: 'wrap',
            }}
          >
            <TextField
              size="small"
              type="number"
              label={t('network.settings.retentionDays')}
              value={retentionDays}
              disabled={loading || !workspace.storageWritable}
              error={!Number.isInteger(days) || days < 1 || days > 90}
              onChange={(event) => setRetentionDays(event.target.value)}
              sx={{ width: 180 }}
            />
            <TextField
              size="small"
              type="number"
              label={t('network.settings.maxRecords')}
              value={maxRecords}
              disabled={loading || !workspace.storageWritable}
              error={
                !Number.isInteger(records) || records < 100 || records > 20000
              }
              onChange={(event) => setMaxRecords(event.target.value)}
              sx={{ width: 190 }}
            />
            <Button
              variant="outlined"
              loading={loading}
              disabled={!validLimits || !changed || !workspace.storageWritable}
              onClick={() => {
                if (
                  days < workspace.retentionDays ||
                  records < workspace.maxRecords
                ) {
                  setConfirmLimits(true)
                } else {
                  void saveLimits()
                }
              }}
            >
              {t('network.settings.save')}
            </Button>
          </Box>
          {!validLimits && (
            <Alert severity="error">
              {t('network.settings.invalidLimits')}
            </Alert>
          )}
          <Typography variant="caption" color="text.secondary">
            {t('network.status.sampleInterval', {
              seconds: workspace.sampleIntervalMs / 1000,
            })}
            {' · '}
            {t('network.status.lastSample')}:{' '}
            {workspace.lastSampleAt
              ? new Date(workspace.lastSampleAt).toLocaleString()
              : t('network.status.never')}
            {' · '}
            {t('network.status.gaps')}: {workspace.gapCount}
            {' · '}
            {t('network.status.droppedRecords', {
              count: workspace.droppedRecords,
            })}
          </Typography>
          {staleSample && (
            <Alert severity="warning">
              {t('network.status.noRecentSample')}
            </Alert>
          )}
        </Stack>
      </Paper>
      <BaseDialog
        open={confirmLimits}
        title={t('network.settings.save')}
        okBtn={t('shared.actions.save')}
        cancelBtn={t('shared.actions.cancel')}
        loading={loading}
        disableCancel={loading}
        onOk={saveLimits}
        onCancel={() => setConfirmLimits(false)}
        onClose={() => !loading && setConfirmLimits(false)}
      >
        {t('network.settings.limitWarning')}
      </BaseDialog>
    </Stack>
  )
}
