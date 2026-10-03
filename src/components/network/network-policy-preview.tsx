import {
  Alert,
  Box,
  Button,
  Chip,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { previewNetworkPolicy } from '@/services/network-control'
import { errorDetail } from '@/services/notice-service'
import type {
  IdentityConfidence,
  PolicyPreview,
  Transport,
} from '@/types/network-control'

export const NetworkPolicyPreview = ({
  disabled = false,
}: {
  disabled?: boolean
}) => {
  const { t } = useTranslation()
  const [processPath, setProcessPath] = useState('')
  const [host, setHost] = useState('')
  const [destinationIp, setDestinationIp] = useState('')
  const [port, setPort] = useState('443')
  const [network, setNetwork] = useState<Transport>('tcp')
  const [identityConfidence, setIdentityConfidence] =
    useState<IdentityConfidence>('unknown')
  const [result, setResult] = useState<PolicyPreview | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const validPort =
    port.trim() !== '' &&
    Number.isInteger(Number(port)) &&
    Number(port) >= 1 &&
    Number(port) <= 65535

  const evaluate = useLockFn(async () => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      setResult(
        await previewNetworkPolicy({
          processPath: processPath || null,
          identityConfidence,
          host: host || null,
          destinationIp: destinationIp || null,
          destinationPort: Number(port),
          network,
        }),
      )
    } catch (error) {
      setError(errorDetail(error))
    } finally {
      setLoading(false)
    }
  })

  const firewallLabel = result
    ? result.firewall === 'allow'
      ? t('network.policies.allow')
      : result.firewall === 'block'
        ? t('network.policies.block')
        : t('network.policies.ask')
    : ''
  const routeLabel = !result?.route
    ? t('network.preview.routeBlocked')
    : result.route.kind === 'direct'
      ? t('network.policies.direct')
      : result.route.kind === 'vpn'
        ? t('network.policies.vpn')
        : `${t('network.policies.proxy')}: ${result.route.group}`

  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack spacing={2}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
          {t('network.preview.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('network.preview.description')}
        </Typography>
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
            gap: 2,
          }}
        >
          <TextField
            size="small"
            label={t('network.policies.application')}
            value={processPath}
            disabled={disabled || loading}
            onChange={(event) => {
              setProcessPath(event.target.value)
              setResult(null)
            }}
          />
          <TextField
            size="small"
            select
            label={t('network.preview.identityConfidence')}
            value={identityConfidence}
            disabled={disabled || loading}
            onChange={(event) => {
              setIdentityConfidence(event.target.value as IdentityConfidence)
              setResult(null)
            }}
          >
            <MenuItem value="unknown">{t('network.preview.unknown')}</MenuItem>
            <MenuItem value="inferred">
              {t('network.preview.inferred')}
            </MenuItem>
            <MenuItem value="exact">{t('network.preview.exact')}</MenuItem>
          </TextField>
          <TextField
            size="small"
            label={t('network.policies.host')}
            value={host}
            disabled={disabled || loading}
            onChange={(event) => {
              setHost(event.target.value)
              setResult(null)
            }}
          />
          <TextField
            size="small"
            label={t('network.policies.ip')}
            value={destinationIp}
            disabled={disabled || loading}
            onChange={(event) => {
              setDestinationIp(event.target.value)
              setResult(null)
            }}
          />
          <TextField
            size="small"
            type="number"
            label={t('network.policies.port')}
            value={port}
            error={!validPort}
            disabled={disabled || loading}
            helperText={
              !validPort ? t('network.preview.invalidPort') : undefined
            }
            onChange={(event) => {
              setPort(event.target.value)
              setResult(null)
            }}
          />
          <TextField
            size="small"
            select
            label={t('network.policies.network')}
            value={network}
            disabled={disabled || loading}
            onChange={(event) => {
              setNetwork(event.target.value as Transport)
              setResult(null)
            }}
          >
            <MenuItem value="tcp">TCP</MenuItem>
            <MenuItem value="udp">UDP</MenuItem>
          </TextField>
        </Box>
        <Box>
          <Button
            variant="outlined"
            disabled={disabled || !validPort}
            loading={loading}
            onClick={evaluate}
          >
            {t('network.preview.evaluate')}
          </Button>
        </Box>
        {error && <Alert severity="error">{error}</Alert>}
        {result && (
          <Stack spacing={1}>
            <Box>
              <Chip size="small" label={t('network.preview.notEnforced')} />
            </Box>
            <Typography variant="body2">
              {t('network.preview.firewallResult')}: {firewallLabel}
              {' — '}
              {t('network.preview.matchedRule')}:{' '}
              {result.firewallRuleId ?? t('network.preview.defaultRule')}
            </Typography>
            <Typography variant="body2">
              {t('network.preview.routeResult')}: {routeLabel}
              {result.route && (
                <>
                  {' — '}
                  {t('network.preview.matchedRule')}:{' '}
                  {result.routeRuleId ?? t('network.preview.defaultRule')}
                </>
              )}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('network.policies.generation', {
                generation: result.generation,
              })}
            </Typography>
          </Stack>
        )}
      </Stack>
    </Paper>
  )
}
