import {
  Alert,
  Box,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
} from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import type {
  FirewallAction,
  FirewallRule,
  RouteAction,
  RouteRule,
  Transport,
} from '@/types/network-control'

interface Props {
  kind: 'firewall' | 'route'
  rule: FirewallRule | RouteRule | null
  onSave: (rule: FirewallRule | RouteRule) => void
  onClose: () => void
}

export const NetworkRuleEditor = ({ kind, rule, onSave, onClose }: Props) => {
  const { t } = useTranslation()
  const [name, setName] = useState(rule?.name ?? '')
  const [priority, setPriority] = useState(String(rule?.priority ?? 0))
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [processPath, setProcessPath] = useState(
    rule?.matcher.processPath ?? '',
  )
  const [unknownProcess, setUnknownProcess] = useState(
    rule?.matcher.unknownProcess ?? false,
  )
  const [host, setHost] = useState(rule?.matcher.host ?? '')
  const [hostSuffix, setHostSuffix] = useState(rule?.matcher.hostSuffix ?? '')
  const [ipCidr, setIpCidr] = useState(rule?.matcher.ipCidr ?? '')
  const [ports, setPorts] = useState(rule?.matcher.ports.join(', ') ?? '')
  const [network, setNetwork] = useState<Transport | ''>(
    rule?.matcher.network ?? '',
  )
  const [matchAll, setMatchAll] = useState(rule?.matcher.matchAll ?? false)
  const [firewall, setFirewall] = useState<FirewallAction>(
    kind === 'firewall' && rule ? (rule.action as FirewallAction) : 'allow',
  )
  const [route, setRoute] = useState<RouteAction>(
    kind === 'route' && rule
      ? (rule.action as RouteAction)
      : { kind: 'direct' },
  )

  const parsedPorts = ports.trim()
    ? ports.split(',').map((port) => Number(port.trim()))
    : []
  const validPorts =
    parsedPorts.length <= 64 &&
    parsedPorts.every(
      (port) => Number.isInteger(port) && port >= 1 && port <= 65535,
    )
  const parsedPriority = Number(priority)
  const validPriority =
    priority.trim() !== '' &&
    Number.isInteger(parsedPriority) &&
    parsedPriority >= -2147483648 &&
    parsedPriority <= 2147483647
  const hasConditions = Boolean(
    processPath ||
      unknownProcess ||
      host ||
      hostSuffix ||
      ipCidr ||
      ports ||
      network,
  )

  const handleSave = () => {
    const base = {
      id: rule?.id ?? crypto.randomUUID(),
      name: name.trim(),
      enabled,
      priority: parsedPriority,
      matcher: {
        processPath: processPath || null,
        unknownProcess,
        host: host || null,
        hostSuffix: hostSuffix || null,
        ipCidr: ipCidr || null,
        ports: parsedPorts,
        network: network || null,
        matchAll,
      },
    }
    onSave(
      kind === 'firewall'
        ? { ...base, action: firewall }
        : { ...base, action: route },
    )
  }

  return (
    <BaseDialog
      open
      title={t(rule ? 'network.policies.editRule' : 'network.policies.addRule')}
      okBtn={t('shared.actions.save')}
      cancelBtn={t('shared.actions.cancel')}
      disableOk={
        !name.trim() ||
        !validPorts ||
        !validPriority ||
        matchAll === hasConditions ||
        (route.kind === 'proxy_group' && !route.group.trim())
      }
      onOk={handleSave}
      onCancel={onClose}
      onClose={onClose}
      contentSx={{ width: 520, maxWidth: 'calc(100vw - 96px)' }}
    >
      <Stack spacing={2} sx={{ pt: 1 }}>
        <Alert severity="info">{t('network.policies.description')}</Alert>
        <TextField
          size="small"
          label={t('network.policies.ruleName')}
          value={name}
          onChange={(event) => setName(event.target.value)}
          autoFocus
        />
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <TextField
            size="small"
            type="number"
            label={t('network.policies.priority')}
            value={priority}
            error={!validPriority}
            onChange={(event) => setPriority(event.target.value)}
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={enabled}
                onChange={(_, checked) => setEnabled(checked)}
              />
            }
            label={t('network.policies.enabled')}
          />
        </Box>
        <TextField
          size="small"
          label={t('network.policies.application')}
          helperText={t('network.policies.applicationHint')}
          value={processPath}
          disabled={matchAll || unknownProcess}
          onChange={(event) => setProcessPath(event.target.value)}
        />
        <FormControlLabel
          control={
            <Checkbox
              checked={unknownProcess}
              disabled={matchAll || Boolean(processPath)}
              onChange={(_, checked) => setUnknownProcess(checked)}
            />
          }
          label={t('network.policies.unknownProcess')}
        />
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
          <TextField
            size="small"
            label={t('network.policies.host')}
            value={host}
            disabled={matchAll || Boolean(hostSuffix)}
            onChange={(event) => setHost(event.target.value)}
          />
          <TextField
            size="small"
            label={t('network.policies.hostSuffix')}
            value={hostSuffix}
            disabled={matchAll || Boolean(host)}
            onChange={(event) => setHostSuffix(event.target.value)}
          />
          <TextField
            size="small"
            label={t('network.policies.ipCidr')}
            value={ipCidr}
            disabled={matchAll}
            onChange={(event) => setIpCidr(event.target.value)}
          />
          <TextField
            size="small"
            select
            label={t('network.policies.network')}
            value={network}
            disabled={matchAll}
            onChange={(event) =>
              setNetwork(event.target.value as Transport | '')
            }
          >
            <MenuItem value="">{t('network.policies.any')}</MenuItem>
            <MenuItem value="tcp">TCP</MenuItem>
            <MenuItem value="udp">UDP</MenuItem>
          </TextField>
        </Box>
        <TextField
          size="small"
          label={t('network.policies.ports')}
          helperText={t('network.policies.portsHint')}
          value={ports}
          error={!validPorts}
          disabled={matchAll}
          onChange={(event) => setPorts(event.target.value)}
        />
        <FormControlLabel
          control={
            <Checkbox
              checked={matchAll}
              disabled={hasConditions}
              onChange={(_, checked) => setMatchAll(checked)}
            />
          }
          label={t('network.policies.matchAll')}
        />
        {kind === 'firewall' ? (
          <TextField
            size="small"
            select
            label={t('network.policies.action')}
            value={firewall}
            onChange={(event) =>
              setFirewall(event.target.value as FirewallAction)
            }
          >
            <MenuItem value="allow">{t('network.policies.allow')}</MenuItem>
            <MenuItem value="block">{t('network.policies.block')}</MenuItem>
            <MenuItem value="ask">{t('network.policies.ask')}</MenuItem>
          </TextField>
        ) : (
          <>
            <TextField
              size="small"
              select
              label={t('network.policies.route')}
              value={route.kind}
              onChange={(event) => {
                const kind = event.target.value as RouteAction['kind']
                setRoute(
                  kind === 'direct'
                    ? { kind }
                    : kind === 'vpn'
                      ? { kind, required: true }
                      : { kind, group: '', required: true },
                )
              }}
            >
              <MenuItem value="direct">{t('network.policies.direct')}</MenuItem>
              <MenuItem value="proxy_group">
                {t('network.policies.proxy')}
              </MenuItem>
              <MenuItem value="vpn">{t('network.policies.vpn')}</MenuItem>
            </TextField>
            {route.kind === 'proxy_group' && (
              <TextField
                size="small"
                label={t('network.policies.routeTarget')}
                value={route.group}
                onChange={(event) =>
                  setRoute({ ...route, group: event.target.value })
                }
              />
            )}
          </>
        )}
      </Stack>
    </BaseDialog>
  )
}
