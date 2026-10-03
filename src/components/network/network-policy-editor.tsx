import AddRounded from '@mui/icons-material/AddRounded'
import DeleteOutlineRounded from '@mui/icons-material/DeleteOutlineRounded'
import EditOutlined from '@mui/icons-material/EditOutlined'
import ExpandMoreRounded from '@mui/icons-material/ExpandMoreRounded'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Chip,
  IconButton,
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
import { useLockFn } from 'ahooks'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import { saveNetworkPolicy } from '@/services/network-control'
import {
  createNetworkPolicyDraft,
  isNetworkPolicyDraftDirty,
  parseNetworkPolicyDraft,
  refreshNetworkPolicyDraft,
} from '@/services/network-policy-draft'
import { errorDetail, showNotice } from '@/services/notice-service'
import type {
  FirewallAction,
  FirewallRule,
  NetworkPolicy,
  RouteAction,
  RouteRule,
} from '@/types/network-control'

import { NetworkPolicyPreview } from './network-policy-preview'
import { NetworkRuleEditor } from './network-rule-editor'
import { NetworkRuleTransfer } from './network-rule-transfer'

interface Props {
  policy: NetworkPolicy
  writable: boolean
  onChanged: () => Promise<void>
}

type EditorState = {
  kind: 'firewall' | 'route'
  rule: FirewallRule | RouteRule | null
}

const serialize = (policy: NetworkPolicy) => JSON.stringify(policy, null, 2)

export const NetworkPolicyEditor = ({ policy, writable, onChanged }: Props) => {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(() => createNetworkPolicyDraft(policy))
  const [editor, setEditor] = useState<EditorState | null>(null)
  const [discardOpen, setDiscardOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [transferActive, setTransferActive] = useState(false)
  const [error, setError] = useState('')
  const busy = loading || transferActive
  const preserveLocal = busy || editor !== null
  const refreshed = refreshNetworkPolicyDraft(draft, policy, preserveLocal)
  if (refreshed !== draft) setDraft(refreshed)
  const { source, baseline } = draft
  const setSource = (source: string) =>
    setDraft((current) => ({ ...current, source }))
  const parsed = useMemo(() => parseNetworkPolicyDraft(source), [source])
  const changed = isNetworkPolicyDraftDirty(draft)
  const stale =
    policy.generation > baseline.generation && (changed || preserveLocal)

  const save = useLockFn(async () => {
    if (!parsed) return
    setLoading(true)
    setError('')
    try {
      const saved = await saveNetworkPolicy(parsed, baseline.generation)
      setDraft(createNetworkPolicyDraft(saved))
      showNotice.success('network.policies.saved')
      await onChanged()
    } catch (error) {
      setError(errorDetail(error))
    } finally {
      setLoading(false)
    }
  })

  const updateRule = (rule: FirewallRule | RouteRule) => {
    if (!parsed || !editor) return
    if (editor.kind === 'firewall') {
      const next = rule as FirewallRule
      setSource(
        serialize({
          ...parsed,
          firewallRules: editor.rule
            ? parsed.firewallRules.map((item) =>
                item.id === next.id ? next : item,
              )
            : [...parsed.firewallRules, next],
        }),
      )
    } else {
      const next = rule as RouteRule
      setSource(
        serialize({
          ...parsed,
          routeRules: editor.rule
            ? parsed.routeRules.map((item) =>
                item.id === next.id ? next : item,
              )
            : [...parsed.routeRules, next],
        }),
      )
    }
    setEditor(null)
  }

  const actionLabel = (action: FirewallAction | RouteAction) => {
    if (typeof action === 'string') {
      return action === 'allow'
        ? t('network.policies.allow')
        : action === 'block'
          ? t('network.policies.block')
          : t('network.policies.ask')
    }
    return action.kind === 'direct'
      ? t('network.policies.direct')
      : action.kind === 'vpn'
        ? t('network.policies.vpn')
        : `${t('network.policies.proxy')}: ${action.group}`
  }

  const rulesTable = (kind: 'firewall' | 'route') => {
    if (!parsed) return null
    const rules = kind === 'firewall' ? parsed.firewallRules : parsed.routeRules
    return (
      <Paper variant="outlined">
        <Box
          sx={{
            p: 2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
            {t(
              kind === 'firewall'
                ? 'network.policies.firewallRules'
                : 'network.policies.routeRules',
            )}
          </Typography>
          <Button
            startIcon={<AddRounded />}
            disabled={!writable || busy}
            onClick={() => setEditor({ kind, rule: null })}
          >
            {t('network.policies.addRule')}
          </Button>
        </Box>
        {rules.length === 0 ? (
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ p: 2, pt: 0 }}
          >
            {t('network.policies.noRules')}
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{t('network.policies.ruleName')}</TableCell>
                  <TableCell>{t('network.policies.application')}</TableCell>
                  <TableCell>{t('network.policies.destination')}</TableCell>
                  <TableCell>
                    {t(
                      kind === 'firewall'
                        ? 'network.policies.action'
                        : 'network.policies.route',
                    )}
                  </TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow
                    key={rule.id}
                    sx={{ opacity: rule.enabled ? 1 : 0.55 }}
                  >
                    <TableCell>
                      {rule.name}
                      <Typography
                        variant="caption"
                        sx={{ display: 'block' }}
                        color="text.secondary"
                      >
                        {t('network.policies.priority')}: {rule.priority}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ maxWidth: 220, overflowWrap: 'anywhere' }}>
                      {rule.matcher.processPath ||
                        (rule.matcher.unknownProcess
                          ? t('network.policies.unknownProcess')
                          : t('network.policies.allApplications'))}
                    </TableCell>
                    <TableCell sx={{ maxWidth: 220, overflowWrap: 'anywhere' }}>
                      {[
                        rule.matcher.host,
                        rule.matcher.hostSuffix
                          ? `*.${rule.matcher.hostSuffix}`
                          : '',
                        rule.matcher.ipCidr,
                        rule.matcher.ports?.join(', '),
                        rule.matcher.network?.toUpperCase(),
                      ]
                        .filter(Boolean)
                        .join(' · ') || t('network.policies.allDestinations')}
                    </TableCell>
                    <TableCell>{actionLabel(rule.action)}</TableCell>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>
                      <Tooltip title={t('network.policies.editRule')}>
                        <span>
                          <IconButton
                            size="small"
                            aria-label={t('network.policies.editRule')}
                            disabled={!writable || busy}
                            onClick={() => setEditor({ kind, rule })}
                          >
                            <EditOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Tooltip title={t('network.policies.remove')}>
                        <span>
                          <IconButton
                            size="small"
                            aria-label={t('network.policies.remove')}
                            disabled={!writable || busy}
                            onClick={() =>
                              setSource(
                                serialize({
                                  ...parsed,
                                  firewallRules:
                                    kind === 'firewall'
                                      ? parsed.firewallRules.filter(
                                          (item) => item.id !== rule.id,
                                        )
                                      : parsed.firewallRules,
                                  routeRules:
                                    kind === 'route'
                                      ? parsed.routeRules.filter(
                                          (item) => item.id !== rule.id,
                                        )
                                      : parsed.routeRules,
                                }),
                              )
                            }
                          >
                            <DeleteOutlineRounded fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>
    )
  }

  return (
    <Stack spacing={2}>
      <Alert severity="info">{t('network.policies.description')}</Alert>
      <Box
        sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}
      >
        <Chip
          size="small"
          label={t('network.policies.generation', {
            generation: baseline.generation,
          })}
        />
        <Chip
          size="small"
          label={t(
            changed
              ? 'network.policies.unsaved'
              : 'network.policies.savedDraft',
          )}
        />
        <Button
          variant="contained"
          loading={loading}
          disabled={!parsed || !changed || !writable || transferActive}
          onClick={save}
        >
          {t('network.policies.save')}
        </Button>
        <Button
          disabled={(!changed && !stale) || busy}
          onClick={() => setDiscardOpen(true)}
        >
          {t('network.policies.reset')}
        </Button>
      </Box>
      {error && <Alert severity="error">{error}</Alert>}
      {stale && (
        <Alert severity="warning">
          {t('network.policies.staleDraft', {
            generation: baseline.generation,
            latestGeneration: policy.generation,
          })}
        </Alert>
      )}
      {parsed && (
        <>
          <NetworkRuleTransfer
            policy={parsed}
            disabled={!writable || loading}
            onActiveChange={setTransferActive}
            onImport={(rules) =>
              setSource(serialize({ ...parsed, firewallRules: rules }))
            }
          />
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <TextField
              size="small"
              select
              label={t('network.policies.firewallDefault')}
              value={parsed.defaults.firewall}
              disabled={!writable || busy}
              sx={{ minWidth: 190 }}
              onChange={(event) =>
                setSource(
                  serialize({
                    ...parsed,
                    defaults: {
                      ...parsed.defaults,
                      firewall: event.target.value as FirewallAction,
                    },
                  }),
                )
              }
            >
              <MenuItem value="allow">{t('network.policies.allow')}</MenuItem>
              <MenuItem value="block">{t('network.policies.block')}</MenuItem>
              <MenuItem value="ask">{t('network.policies.ask')}</MenuItem>
            </TextField>
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ alignSelf: 'center' }}
            >
              {t('network.policies.routeDefault')}:{' '}
              {actionLabel(parsed.defaults.route)}
            </Typography>
          </Box>
          {rulesTable('firewall')}
          {rulesTable('route')}
        </>
      )}
      <Accordion variant="outlined" disableGutters>
        <AccordionSummary expandIcon={<ExpandMoreRounded />}>
          {t('network.policies.advanced')}
        </AccordionSummary>
        <AccordionDetails>
          <TextField
            fullWidth
            multiline
            minRows={12}
            maxRows={26}
            label={t('network.policies.advanced')}
            value={source}
            disabled={!writable || busy}
            error={!parsed}
            helperText={
              !parsed ? t('network.policies.invalidDraft') : undefined
            }
            onChange={(event) => setSource(event.target.value)}
            slotProps={{
              htmlInput: { style: { fontFamily: 'monospace', fontSize: 12 } },
            }}
          />
        </AccordionDetails>
      </Accordion>
      <NetworkPolicyPreview disabled={busy} />
      {editor && (
        <NetworkRuleEditor
          kind={editor.kind}
          rule={editor.rule}
          onSave={updateRule}
          onClose={() => setEditor(null)}
        />
      )}
      <BaseDialog
        open={discardOpen}
        title={t('network.policies.discardTitle')}
        okBtn={t('shared.actions.confirm')}
        cancelBtn={t('shared.actions.cancel')}
        onOk={() => {
          setDraft(
            createNetworkPolicyDraft(
              policy.generation >= baseline.generation ? policy : baseline,
            ),
          )
          setError('')
          setDiscardOpen(false)
        }}
        onCancel={() => setDiscardOpen(false)}
        onClose={() => setDiscardOpen(false)}
      >
        {t('network.policies.discardDescription')}
      </BaseDialog>
    </Stack>
  )
}
