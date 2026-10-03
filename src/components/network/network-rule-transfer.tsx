import FileDownloadOutlined from '@mui/icons-material/FileDownloadOutlined'
import FileUploadOutlined from '@mui/icons-material/FileUploadOutlined'
import {
  Alert,
  Box,
  Button,
  List,
  ListItem,
  ListItemText,
  Stack,
  Typography,
} from '@mui/material'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readTextFile, stat, writeTextFile } from '@tauri-apps/plugin-fs'
import { useLockFn } from 'ahooks'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import {
  exportNetworkLsRules,
  importNetworkLsRules,
} from '@/services/network-control'
import { showNotice } from '@/services/notice-service'
import type {
  FirewallRule,
  LsRulesExport,
  LsRulesImport,
  NetworkPolicy,
} from '@/types/network-control'

interface Props {
  policy: NetworkPolicy
  disabled: boolean
  onImport: (rules: FirewallRule[]) => void
  onActiveChange: (active: boolean) => void
}

type Transfer =
  | { kind: 'import'; result: LsRulesImport }
  | { kind: 'export'; result: LsRulesExport }

export const NetworkRuleTransfer = ({
  policy,
  disabled,
  onImport,
  onActiveChange,
}: Props) => {
  const { t } = useTranslation()
  const [transfer, setTransfer] = useState<Transfer | null>(null)
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    onActiveChange(loading || transfer !== null)
  }, [loading, transfer, onActiveChange])

  const importRules = useLockFn(async () => {
    setLoading(true)
    try {
      const path = await open({
        multiple: false,
        filters: [{ name: '.lsrules', extensions: ['lsrules'] }],
      })
      if (!path || Array.isArray(path)) return
      if ((await stat(path)).size > 2 * 1024 * 1024) {
        showNotice.error('network.imports.tooLarge')
        return
      }
      const content = await readTextFile(path)
      const result = await importNetworkLsRules(content)
      setTransfer({ kind: 'import', result })
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  const exportRules = useLockFn(async () => {
    setLoading(true)
    try {
      setTransfer({
        kind: 'export',
        result: await exportNetworkLsRules(policy),
      })
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  const confirm = useLockFn(async () => {
    if (!transfer) return
    if (transfer.kind === 'import') {
      onImport(
        transfer.result.rules.map((rule) => ({
          ...rule,
          id: crypto.randomUUID(),
        })),
      )
      setTransfer(null)
      return
    }
    setLoading(true)
    try {
      const path = await save({
        defaultPath: 'network-firewall-draft.lsrules',
        filters: [{ name: '.lsrules', extensions: ['lsrules'] }],
      })
      if (!path) return
      await writeTextFile(path, transfer.result.content)
      setTransfer(null)
      showNotice.success('network.imports.exported')
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  return (
    <>
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
        <Button
          startIcon={<FileUploadOutlined />}
          disabled={disabled || loading}
          onClick={importRules}
        >
          {t('network.imports.importRules')}
        </Button>
        <Button
          startIcon={<FileDownloadOutlined />}
          disabled={disabled || loading}
          onClick={exportRules}
        >
          {t('network.imports.exportRules')}
        </Button>
      </Box>
      {transfer && (
        <BaseDialog
          open
          title={t(
            transfer.kind === 'import'
              ? 'network.imports.review'
              : 'network.imports.exportRules',
          )}
          okBtn={t(
            transfer.kind === 'import'
              ? 'network.imports.apply'
              : 'shared.actions.save',
          )}
          cancelBtn={t('shared.actions.cancel')}
          loading={loading}
          disableCancel={loading}
          disableOk={
            disabled ||
            (transfer.kind === 'import'
              ? transfer.result.acceptedCount === 0
              : transfer.result.exportedCount === 0)
          }
          onOk={confirm}
          onCancel={() => setTransfer(null)}
          onClose={() => !loading && setTransfer(null)}
          contentSx={{ width: 540, maxWidth: 'calc(100vw - 96px)' }}
        >
          <Stack spacing={2}>
            <Alert severity="warning">
              {t(
                transfer.kind === 'import'
                  ? 'network.imports.replaceWarning'
                  : 'network.imports.exportWarning',
              )}
            </Alert>
            <Typography variant="body2">
              {t('network.imports.counts', {
                accepted:
                  transfer.kind === 'import'
                    ? transfer.result.acceptedCount
                    : transfer.result.exportedCount,
                rejected: transfer.result.rejectedCount,
              })}
            </Typography>
            {transfer.result.diagnostics.length > 0 && (
              <Box>
                <Typography variant="subtitle2">
                  {t('network.imports.diagnostics')}
                </Typography>
                <List dense sx={{ maxHeight: 260, overflow: 'auto' }}>
                  {transfer.result.diagnostics.map((diagnostic) => (
                    <ListItem
                      key={`${diagnostic.sourceIndex}:${diagnostic.ruleId}:${diagnostic.severity}:${diagnostic.message}`}
                      disableGutters
                    >
                      <ListItemText
                        primary={diagnostic.message}
                        secondary={diagnostic.ruleId ?? diagnostic.sourceIndex}
                      />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}
          </Stack>
        </BaseDialog>
      )}
    </>
  )
}
