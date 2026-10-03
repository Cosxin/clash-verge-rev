import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Box,
  Chip,
  IconButton,
  LinearProgress,
  Stack,
  Tab,
  Tabs,
  Tooltip,
} from '@mui/material'
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BasePage } from '@/components/base'
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
  const [tab, setTab] = useState<
    'overview' | 'routes' | 'policies' | 'history'
  >('overview')
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
        <Alert severity="warning" title={t('network.status.observeTitle')}>
          {t('network.status.observeDescription')}
        </Alert>
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
            >
              <Tab
                value="overview"
                label={t('network.tabs.overview')}
                id="network-tab-overview"
                aria-controls="network-panel-overview"
              />
              <Tab
                value="policies"
                label={t('network.tabs.policies')}
                id="network-tab-policies"
                aria-controls="network-panel-policies"
              />
              <Tab
                value="routes"
                label="App routing"
                id="network-tab-routes"
                aria-controls="network-panel-routes"
              />
              <Tab
                value="history"
                label={t('network.tabs.history')}
                id="network-tab-history"
                aria-controls="network-panel-history"
              />
            </Tabs>
            <Box
              role="tabpanel"
              id="network-panel-overview"
              aria-labelledby="network-tab-overview"
              hidden={tab !== 'overview'}
            >
              <NetworkOverview
                key={`${workspace.retentionDays}:${workspace.maxRecords}`}
                workspace={workspace}
                onChanged={refresh}
              />
            </Box>
            <Box
              role="tabpanel"
              id="network-panel-policies"
              aria-labelledby="network-tab-policies"
              hidden={tab !== 'policies'}
            >
              <NetworkPolicyEditor
                policy={workspace.policy}
                writable={workspace.storageWritable}
                onChanged={refresh}
              />
            </Box>
            <Box
              role="tabpanel"
              id="network-panel-routes"
              aria-labelledby="network-tab-routes"
              hidden={tab !== 'routes'}
            >
              <NetworkAppRoutes enabled={visible && tab === 'routes'} />
            </Box>
            <Box
              role="tabpanel"
              id="network-panel-history"
              aria-labelledby="network-tab-history"
              hidden={tab !== 'history'}
            >
              <NetworkHistory
                workspace={workspace}
                enabled={visible && tab === 'history'}
                onChanged={refresh}
              />
            </Box>
          </>
        )}
      </Stack>
    </BasePage>
  )
}

export default NetworkPage
