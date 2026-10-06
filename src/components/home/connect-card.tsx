import { PowerSettingsNewRounded } from '@mui/icons-material'
import { Alert, Box, Button, Stack, Typography } from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { getBaseConfig } from 'tauri-plugin-mihomo-api'

import { BaseDialog } from '@/components/base'
import { EnhancedCard } from '@/components/home/enhanced-card'
import { useBuildCapabilities } from '@/hooks/use-build-capabilities'
import { useProfiles } from '@/hooks/use-profiles'
import { useSystemProxyState } from '@/hooks/use-system-proxy-state'
import { useSystemState } from '@/hooks/use-system-state'
import { useVerge } from '@/hooks/use-verge'
import { useVisibility } from '@/hooks/use-visibility'
import {
  getAutotemProxy,
  getBuildCapabilities,
  getProfiles,
  getRuntimeState,
  getSystemProxy,
} from '@/services/cmds'
import { useQuery } from '@/services/query-client'

export const ConnectCard = () => {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { verge, patchVerge } = useVerge()
  const { current } = useProfiles()
  const { indicator: systemProxyOn, toggleSystemProxy } = useSystemProxyState()
  const { runState } = useSystemState()
  const { hostLocked, tunLocked, unavailable } = useBuildCapabilities()
  const visible = useVisibility()
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  const [confirmConnect, setConfirmConnect] = useState(false)
  const { data: core, error: coreError } = useQuery({
    queryKey: ['getClashConfig'],
    queryFn: getBaseConfig,
    refetchInterval: visible ? 5000 : false,
    retry: 1,
  })
  const pac = Boolean(verge?.proxy_auto_config)
  const { error: proxyError, data: proxy } = useQuery({
    queryKey: ['getSystemProxy'],
    queryFn: getSystemProxy,
    enabled: !pac,
    refetchInterval: visible ? 5000 : false,
    retry: 1,
  })
  const { error: pacError, data: autoProxy } = useQuery({
    queryKey: ['getAutotemProxy'],
    queryFn: getAutotemProxy,
    enabled: pac,
    refetchInterval: visible ? 5000 : false,
    retry: 1,
  })
  const profileReady = current?.type === 'local' || current?.type === 'remote'
  const coreReady = Boolean(
    core &&
      !coreError &&
      core.mixedPort > 0 &&
      runState.mode !== 'NotRunning' &&
      !runState.opInFlight,
  )
  const proxyKnown = pac
    ? Boolean(autoProxy && !pacError)
    : Boolean(proxy && !proxyError)
  const observedProxy = proxyKnown && systemProxyOn
  const tunRequested = Boolean(verge?.enable_tun_mode)
  const disconnect = observedProxy || (tunRequested && !tunLocked)
  const ready = observedProxy && coreReady
  const direct = core?.mode?.toLowerCase() === 'direct'
  const status = ready
    ? direct
      ? 'home.components.connect.status.direct'
      : 'home.components.connect.status.enabled'
    : observedProxy
      ? 'home.components.connect.status.coreUnavailable'
      : !proxyKnown
        ? 'home.components.connect.status.unknown'
        : 'home.components.connect.status.disconnected'

  const onToggle = useLockFn(async () => {
    if (hostLocked) return
    setPending(true)
    setFailed(false)
    try {
      const capability = await getBuildCapabilities()
      if (!capability.hostNetworkChanges || !capability.systemProxy)
        throw new Error()
      if (disconnect) {
        if (tunRequested && capability.tun)
          await patchVerge({ enable_tun_mode: false })
        await toggleSystemProxy(false)
      } else {
        const [liveCore, liveState, profiles] = await Promise.all([
          getBaseConfig(),
          getRuntimeState(),
          getProfiles(),
        ])
        const selected = profiles.items?.find(
          (item) => item.uid === profiles.current,
        )
        if (
          liveState.mode === 'NotRunning' ||
          liveState.opInFlight ||
          liveCore.mixedPort <= 0 ||
          selected?.uid !== current?.uid ||
          !['local', 'remote'].includes(selected?.type ?? '')
        )
          throw new Error()
        await toggleSystemProxy(true)
      }
    } catch {
      setFailed(true)
    } finally {
      setPending(false)
    }
  })

  return (
    <EnhancedCard
      title={t('home.components.connect.title')}
      icon={<PowerSettingsNewRounded />}
      iconColor={ready && !direct ? 'success' : 'primary'}
      action={null}
    >
      <Stack spacing={1.5}>
        <Stack
          direction="row"
          spacing={2}
          sx={{
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 1,
          }}
        >
          <Box>
            <Typography variant="h6">{t(status)}</Typography>
            <Typography variant="body2" color="text.secondary">
              {current?.name
                ? t('home.components.connect.fields.profile', {
                    name: current.name,
                  })
                : t('home.components.connect.hints.noProfile')}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Button disabled={pending} onClick={() => navigate('/profiles')}>
              {t('home.components.connect.actions.addServers')}
            </Button>
            <Button disabled={pending} onClick={() => navigate('/proxies')}>
              {t('home.components.connect.actions.chooseServer')}
            </Button>
            <Button
              variant="contained"
              loading={pending}
              disabled={
                hostLocked ||
                runState.opInFlight ||
                (!disconnect && (!coreReady || !profileReady || !proxyKnown))
              }
              startIcon={<PowerSettingsNewRounded />}
              onClick={() =>
                disconnect ? onToggle() : setConfirmConnect(true)
              }
            >
              {disconnect
                ? t('home.components.connect.actions.disconnect')
                : t('home.components.connect.actions.connect')}
            </Button>
          </Stack>
        </Stack>
        <Typography variant="caption" color="text.secondary">
          {hostLocked
            ? unavailable
              ? t(
                  'settings.sections.proxyControl.tooltips.capabilitiesUnavailable',
                )
              : t('settings.sections.proxyControl.tooltips.hostChangesDisabled')
            : !coreReady
              ? t('home.components.connect.hints.coreUnavailable')
              : t('home.components.connect.hints.scope')}
        </Typography>
        {tunRequested && (
          <Alert severity="info">
            {tunLocked
              ? t('home.components.connect.hints.tunUnavailable')
              : t('home.components.connect.hints.tun')}
          </Alert>
        )}
        {failed && (
          <Alert severity="error">
            {t('home.components.connect.errors.change')}
          </Alert>
        )}
        <BaseDialog
          open={confirmConnect}
          title={t('home.components.connect.confirm.title')}
          okBtn={t('home.components.connect.actions.connect')}
          cancelBtn={t('shared.actions.cancel')}
          onCancel={() => setConfirmConnect(false)}
          onClose={() => setConfirmConnect(false)}
          onOk={() => {
            setConfirmConnect(false)
            void onToggle()
          }}
        >
          {t('home.components.connect.confirm.description')}
        </BaseDialog>
      </Stack>
    </EnhancedCard>
  )
}
