import { Box, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useVerge } from '@/hooks/use-verge'
import { isTVMode } from '@/utils/get-system'

export const TVRemoteBar = () => {
  const { verge } = useVerge()
  const { t } = useTranslation()
  const active = isTVMode(verge?.tv_mode)

  if (!active) return null

  return (
    <Box
      className="tv-remote-bar"
      sx={{
        position: 'fixed',
        bottom: 12,
        right: 24,
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        gap: 2,
        padding: '6px 16px',
        borderRadius: '20px',
        bgcolor: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(8px)',
        border: '1px solid rgba(255, 255, 255, 0.15)',
        color: '#fff',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
        pointerEvents: 'none',
        userSelect: 'none',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, bgcolor: 'rgba(255,255,255,0.2)', px: 0.8, py: 0.2, borderRadius: 1 }}>
          ▲▼◀▶
        </Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.9)' }}>
          {t('tv.bar.move', 'Move')}
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, bgcolor: 'rgba(255,255,255,0.2)', px: 0.8, py: 0.2, borderRadius: 1 }}>
          OK
        </Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.9)' }}>
          {t('tv.bar.select', 'Select')}
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, bgcolor: 'rgba(255,255,255,0.2)', px: 0.8, py: 0.2, borderRadius: 1 }}>
          BACK
        </Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.9)' }}>
          {t('tv.bar.back', 'Back')}
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, bgcolor: 'rgba(255,255,255,0.2)', px: 0.8, py: 0.2, borderRadius: 1 }}>
          ▶||
        </Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.9)' }}>
          {t('tv.bar.proxy', 'Proxy')}
        </Typography>
      </Box>
    </Box>
  )
}
