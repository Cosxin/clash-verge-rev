import FileDownloadOutlined from '@mui/icons-material/FileDownloadOutlined'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Box,
  Button,
  Chip,
  IconButton,
  LinearProgress,
  MenuItem,
  Paper,
  Stack,
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
import { save } from '@tauri-apps/plugin-dialog'
import { writeTextFile } from '@tauri-apps/plugin-fs'
import { useDebounce, useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import {
  clearNetworkHistory,
  exportNetworkHistory,
  getNetworkHistory,
} from '@/services/network-control'
import { errorDetail, showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'
import type { HistoryRecord, NetworkWorkspace } from '@/types/network-control'
import parseTraffic from '@/utils/parse-traffic'

interface Props {
  enabled: boolean
  workspace: NetworkWorkspace
  onChanged: () => Promise<void>
}

const PAGE_SIZE = 50
const bytes = (value: number) => parseTraffic(value).join(' ')

export const NetworkHistory = ({ enabled, workspace, onChanged }: Props) => {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [source, setSource] = useState<HistoryRecord['source'] | ''>('')
  const debouncedSearch = useDebounce(search, { wait: 300 })
  const [offset, setOffset] = useState(0)
  const [confirmation, setConfirmation] = useState<'clear' | 'export' | null>(
    null,
  )
  const [loading, setLoading] = useState(false)
  const { data, error, isPending, isFetching, refetch } = useQuery({
    queryKey: ['getNetworkHistory', debouncedSearch, source, offset],
    queryFn: () =>
      getNetworkHistory({
        search: debouncedSearch,
        source: source || null,
        offset,
        limit: PAGE_SIZE,
      }),
    enabled,
    refetchInterval: 5000,
    retry: 1,
  })

  const confirm = useLockFn(async () => {
    setLoading(true)
    try {
      if (confirmation === 'clear') {
        await clearNetworkHistory()
        setOffset(0)
        await Promise.all([refetch(), onChanged()])
        showNotice.success('network.history.cleared')
      } else if (confirmation === 'export') {
        const path = await save({
          defaultPath: 'network-history-redacted.json',
          filters: [{ name: 'JSON', extensions: ['json'] }],
        })
        if (!path) return
        await writeTextFile(path, await exportNetworkHistory())
        showNotice.success('network.history.exported')
      }
      setConfirmation(null)
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  const total = data?.total ?? 0
  const records = data?.records ?? []
  return (
    <Stack spacing={2}>
      <Alert severity="info">
        {t(
          workspace.coverage === 'native_tcp_udp_and_core'
            ? 'network.history.nativeCoverage'
            : 'network.history.coverage',
        )}
      </Alert>
      <Box
        sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}
      >
        <TextField
          size="small"
          label={t('network.history.search')}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value)
            setOffset(0)
          }}
          sx={{ flex: 1, minWidth: 220 }}
        />
        <Tooltip title={t('shared.actions.refresh')}>
          <span>
            <IconButton
              aria-label={t('shared.actions.refresh')}
              disabled={isFetching || loading}
              onClick={() => void refetch()}
            >
              <RefreshRounded />
            </IconButton>
          </span>
        </Tooltip>
        <TextField
          select
          size="small"
          label="Observation source"
          value={source}
          onChange={(event) => {
            setSource(event.target.value as HistoryRecord['source'] | '')
            setOffset(0)
          }}
          sx={{ minWidth: 200 }}
        >
          <MenuItem value="">All sources (separate counters)</MenuItem>
          <MenuItem value="mihomo">Mihomo core</MenuItem>
          <MenuItem value="native_macos">macOS native filter</MenuItem>
          <MenuItem value="native_windows">Windows native filter</MenuItem>
          <MenuItem value="native_linux">Linux native filter</MenuItem>
        </TextField>
        <Button
          startIcon={<FileDownloadOutlined />}
          disabled={loading || total === 0}
          onClick={() => setConfirmation('export')}
        >
          {t('network.history.export')}
        </Button>
        <Button
          color="error"
          disabled={loading || !workspace.storageWritable}
          onClick={() => setConfirmation('clear')}
        >
          {t('network.history.clear')}
        </Button>
      </Box>
      {error && <Alert severity="error">{errorDetail(error)}</Alert>}
      {(isFetching || loading) && <LinearProgress />}
      {data && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="caption" color="text.secondary">
            {t('network.history.sampledTotals')}
          </Typography>
          <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap', mt: 0.5 }}>
            <Typography variant="body2">
              {t('network.history.recordCount', { total })}
            </Typography>
            {(data.sourceTotals ?? []).map((totals) => (
              <Typography variant="body2" key={totals.source}>
                {totals.source}: ↑ {bytes(totals.observedUpload)} · ↓{' '}
                {bytes(totals.observedDownload)}
              </Typography>
            ))}
            {data.sourceTotals === undefined &&
              data.observedUpload !== null &&
              data.observedDownload !== null && (
                <Typography variant="body2">
                  ↑ {bytes(data.observedUpload)} · ↓{' '}
                  {bytes(data.observedDownload)}
                </Typography>
              )}
          </Box>
        </Paper>
      )}
      {records.length > 0 ? (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small" aria-label={t('network.history.title')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('network.history.firstSeen')}</TableCell>
                <TableCell>{t('network.history.application')}</TableCell>
                <TableCell>{t('network.history.source')}</TableCell>
                <TableCell>{t('network.history.destination')}</TableCell>
                <TableCell>{t('network.history.route')}</TableCell>
                <TableCell>{t('network.history.traffic')}</TableCell>
                <TableCell>{t('network.history.state')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {records.map((record) => (
                <TableRow key={record.id}>
                  <TableCell sx={{ minWidth: 128 }}>
                    <Typography variant="body2">
                      {new Date(record.firstSeenAt).toLocaleString()}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {t('network.history.lastSeen')}:{' '}
                      {new Date(record.lastSeenAt).toLocaleTimeString()}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ maxWidth: 210, overflowWrap: 'anywhere' }}>
                    <Tooltip title={record.processPath}>
                      <Typography variant="body2">
                        {record.process ||
                          record.processPath ||
                          t('network.history.unknown')}
                      </Typography>
                    </Tooltip>
                    <Typography variant="caption" color="text.secondary">
                      {t(
                        record.identityConfidence === 'exact'
                          ? 'network.history.nativeIdentity'
                          : record.identityConfidence === 'unknown'
                            ? 'network.history.unknownIdentity'
                            : 'network.history.inferredIdentity',
                      )}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ maxWidth: 180, overflowWrap: 'anywhere' }}>
                    <Typography variant="body2">
                      {record.sourceIp || t('network.history.unknown')}
                      {record.sourcePort ? `:${record.sourcePort}` : ''}
                    </Typography>
                    {(record.uid != null || record.pid != null) && (
                      <Typography variant="caption" color="text.secondary">
                        {record.uid != null ? `UID ${record.uid}` : ''}
                        {record.pid != null ? ` · PID ${record.pid}` : ''}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 230, overflowWrap: 'anywhere' }}>
                    <Typography variant="body2">
                      {record.host ||
                        record.destinationIp ||
                        t('network.history.unknown')}
                      :{record.destinationPort}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {record.network.toUpperCase()}
                      {record.host ? ` · ${record.destinationIp}` : ''}
                    </Typography>
                    {record.host && (
                      <Typography
                        variant="caption"
                        sx={{ display: 'block' }}
                        color="text.secondary"
                      >
                        {t('network.history.engineInferred')}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 180, overflowWrap: 'anywhere' }}>
                    <Typography variant="body2">
                      {record.chains.join(' → ') ||
                        t('network.history.unknown')}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {record.rule}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    <Typography variant="body2">
                      ↑ {bytes(record.observedUpload)}
                    </Typography>
                    <Typography variant="body2">
                      ↓ {bytes(record.observedDownload)}
                    </Typography>
                    {record.counterResets > 0 && (
                      <Typography variant="caption" color="text.secondary">
                        {t('network.history.counterResets', {
                          count: record.counterResets,
                        })}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      variant="outlined"
                      label={t(
                        record.state === 'active'
                          ? 'network.history.active'
                          : record.state === 'closed'
                            ? 'network.history.closed'
                            : 'network.history.ended',
                      )}
                    />
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ mt: 0.5, display: 'block' }}
                    >
                      {record.source} · {record.counterSemantics} ·{' '}
                      {t('network.history.incomplete')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : !isPending && !error ? (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography variant="body2" color="text.secondary">
            {t('network.history.empty')}
          </Typography>
        </Paper>
      ) : null}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          justifyContent: 'flex-end',
        }}
      >
        <Typography variant="caption" color="text.secondary">
          {t('network.history.page', {
            from: records.length ? offset + 1 : 0,
            to: offset + records.length,
            total,
          })}
        </Typography>
        <Button
          disabled={offset === 0 || isFetching}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          {t('shared.actions.previous')}
        </Button>
        <Button
          disabled={offset + PAGE_SIZE >= total || isFetching}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          {t('shared.actions.next')}
        </Button>
      </Box>
      <Typography variant="caption" color="text.secondary">
        {t('network.history.retentionNote')}
      </Typography>
      <BaseDialog
        open={confirmation !== null}
        title={t(
          confirmation === 'clear'
            ? 'network.history.clearTitle'
            : 'network.history.exportTitle',
        )}
        okBtn={t(
          confirmation === 'clear'
            ? 'shared.actions.delete'
            : 'shared.actions.save',
        )}
        cancelBtn={t('shared.actions.cancel')}
        loading={loading}
        disableCancel={loading}
        onOk={confirm}
        onCancel={() => setConfirmation(null)}
        onClose={() => !loading && setConfirmation(null)}
      >
        {t(
          confirmation === 'clear'
            ? 'network.history.clearDescription'
            : 'network.history.exportDescription',
        )}
      </BaseDialog>
    </Stack>
  )
}
