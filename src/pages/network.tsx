import ExpandMoreRounded from '@mui/icons-material/ExpandMoreRounded'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Chip,
  IconButton,
  LinearProgress,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material'
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BasePage } from '@/components/base'
import { NetworkAppBans } from '@/components/network/network-app-bans'
import { NetworkAppRoutes } from '@/components/network/network-app-routes'
import { NetworkHistory } from '@/components/network/network-history'
import { NetworkOverview } from '@/components/network/network-overview'
import { NetworkPolicyEditor } from '@/components/network/network-policy-editor'
import { useVisibility } from '@/hooks/use-visibility'
import { getNetworkWorkspace } from '@/services/network-control'
import { errorDetail } from '@/services/notice-service'
import { revalidateQuery, useQuery } from '@/services/query-client'

const NetworkPage = () => {
  const { t } = useTranslation()
  const visible = useVisibility()
  const [tab, setTab] = useState<'apps' | 'traffic' | 'settings'>('apps')
  const {
    data: workspace,
    error,
    isFetching,
  } = useQuery({
    queryKey: ['getNetworkWorkspace'],
    queryFn: getNetworkWorkspace,
    enabled: visible,
    refetchInterval: 5000,
    retry: 1,
  })
  const refresh = useCallback(async () => {
    await revalidateQuery(['getNetworkWorkspace'])
  }, [])

  return (
    <BasePage
      title={t('network.page.title')}
      contentStyle={{ height: '100%', overflow: 'auto' }}
      header={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip
            size="small"
            variant="outlined"
            label={t('network.status.separateControls')}
          />
          <Tooltip title={t('shared.actions.refresh')}>
            <span>
              <IconButton
                disabled={isFetching}
                aria-label={t('shared.actions.refresh')}
                onClick={() => void refresh()}
              >
                <RefreshRounded />
              </IconButton>
            </span>
          </Tooltip>
        </Box>
      }
    >
      <Stack spacing={2} sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Routes affect traffic entering Mihomo. App blocking needs an active
          native filter.
        </Typography>
        {error && (
          <Alert severity="error">
            {t('network.status.loadingFailed')}: {errorDetail(error)}
          </Alert>
        )}
        {!workspace && isFetching && <LinearProgress />}
        {workspace && (
          <>
            {!workspace.storageWritable && (
              <Alert severity="error">
                {t('network.status.storageReadOnly')}
              </Alert>
            )}
            {workspace.lastError && (
              <Alert severity="warning">{workspace.lastError}</Alert>
            )}
            <Tabs
              value={tab}
              onChange={(_, value) => setTab(value)}
              variant="scrollable"
              aria-label="Network controls"
            >
              <Tab
                value="apps"
                label="Apps"
                id="network-tab-apps"
                aria-controls="network-panel-apps"
              />
              <Tab
                value="traffic"
                label="Traffic"
                id="network-tab-traffic"
                aria-controls="network-panel-traffic"
              />
              <Tab
                value="settings"
                label="Settings"
                id="network-tab-settings"
                aria-controls="network-panel-settings"
              />
            </Tabs>
            <Box
              role="tabpanel"
              id="network-panel-apps"
              aria-labelledby="network-tab-apps"
              hidden={tab !== 'apps'}
            >
              <Stack spacing={2}>
                <NetworkAppRoutes enabled={visible && tab === 'apps'} />
                <NetworkAppBans />
              </Stack>
            </Box>
            <Box
              role="tabpanel"
              id="network-panel-traffic"
              aria-labelledby="network-tab-traffic"
              hidden={tab !== 'traffic'}
            >
              <NetworkHistory
                workspace={workspace}
                enabled={visible && tab === 'traffic'}
                onChanged={refresh}
              />
            </Box>
            <Box
              role="tabpanel"
              id="network-panel-settings"
              aria-labelledby="network-tab-settings"
              hidden={tab !== 'settings'}
            >
              <Stack spacing={2}>
                <NetworkOverview
                  key={`${workspace.retentionDays}:${workspace.maxRecords}`}
                  workspace={workspace}
                  onChanged={refresh}
                />
                <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                  <AccordionSummary
                    expandIcon={<ExpandMoreRounded />}
                    id="network-advanced-policies-header"
                    aria-controls="network-advanced-policies-content"
                  >
                    <Typography>Advanced draft policies</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <NetworkPolicyEditor
                      policy={workspace.policy}
                      writable={workspace.storageWritable}
                      onChanged={refresh}
                    />
                  </AccordionDetails>
                </Accordion>
              </Stack>
            </Box>
          </>
        )}
      </Stack>
    </BasePage>
  )
}

export default NetworkPage
