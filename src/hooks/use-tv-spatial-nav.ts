import { useEffect, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router'
import { isTVMode } from '@/utils/get-system'
import { useVerge } from '@/hooks/use-verge'
import { patchVergeConfig } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

const FOCUSABLE_SELECTOR = [
  'button:not([disabled])',
  '[role="button"]:not([aria-disabled="true"])',
  'a[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"]):not([disabled])',
  '.MuiButtonBase-root:not([disabled])',
  '.MuiListItemButton-root:not([disabled])',
  '.MuiTab-root',
  '.MuiCard-root',
  '[data-tv-focusable="true"]',
].join(', ')

interface Rect {
  left: number
  top: number
  right: number
  bottom: number
  width: number
  height: number
  centerX: number
  centerY: number
}

function getRect(el: HTMLElement): Rect {
  const r = el.getBoundingClientRect()
  return {
    left: r.left,
    top: r.top,
    right: r.right,
    bottom: r.bottom,
    width: r.width,
    height: r.height,
    centerX: r.left + r.width / 2,
    centerY: r.top + r.height / 2,
  }
}

function isVisible(el: HTMLElement): boolean {
  if (el.offsetParent === null && el.tagName !== 'BODY') return false
  const style = window.getComputedStyle(el)
  if (style.visibility === 'hidden' || style.display === 'none' || style.opacity === '0') {
    return false
  }
  const rect = el.getBoundingClientRect()
  return rect.width > 0 && rect.height > 0
}

/**
 * Hook to provide full Android TV remote control (D-pad) spatial navigation
 */
export function useTVSpatialNav() {
  const { verge } = useVerge()
  const navigate = useNavigate()
  const location = useLocation()
  const active = isTVMode(verge?.tv_mode)

  // Toggle tv-mode class on body
  useEffect(() => {
    if (active) {
      document.body.classList.add('tv-mode')
    } else {
      document.body.classList.remove('tv-mode')
    }
    return () => {
      document.body.classList.remove('tv-mode')
    }
  }, [active])

  const findNextElement = useCallback(
    (current: HTMLElement, direction: 'up' | 'down' | 'left' | 'right'): HTMLElement | null => {
      const allElements = Array.from(
        document.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter((el) => isVisible(el) && el !== current && !current.contains(el))

      if (allElements.length === 0) return null

      const curRect = getRect(current)
      let bestMatch: HTMLElement | null = null
      let minDistance = Infinity

      for (const el of allElements) {
        const targetRect = getRect(el)
        let isValid = false
        let primaryDist = 0
        let secondaryDist = 0

        switch (direction) {
          case 'up':
            isValid = targetRect.centerY < curRect.centerY - 4
            primaryDist = Math.abs(curRect.centerY - targetRect.centerY)
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
          case 'down':
            isValid = targetRect.centerY > curRect.centerY + 4
            primaryDist = Math.abs(targetRect.centerY - curRect.centerY)
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
          case 'left':
            isValid = targetRect.centerX < curRect.centerX - 4
            primaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            secondaryDist = Math.abs(curRect.centerY - targetRect.centerY)
            break
          case 'right':
            isValid = targetRect.centerX > curRect.centerX + 4
            primaryDist = Math.abs(targetRect.centerX - curRect.centerX)
            secondaryDist = Math.abs(curRect.centerY - targetRect.centerY)
            break
        }

        if (!isValid) continue

        // Weighted distance calculation: penalize orthogonal movement to prefer same row/column
        const distance = primaryDist + secondaryDist * 2.2
        if (distance < minDistance) {
          minDistance = distance
          bestMatch = el
        }
      }

      return bestMatch
    },
    [],
  )

  useEffect(() => {
    if (!active) return

    const handleKeyDown = (event: KeyboardEvent) => {
      const activeEl = document.activeElement as HTMLElement | null
      const isInput =
        activeEl &&
        ['INPUT', 'TEXTAREA'].includes(activeEl.tagName) &&
        !['button', 'checkbox', 'radio'].includes((activeEl as HTMLInputElement).type)

      // Handle Directional (D-Pad) keys
      if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) {
        if (isInput && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
          // Allow text navigation inside input
          return
        }

        let direction: 'up' | 'down' | 'left' | 'right' = 'down'
        if (event.key === 'ArrowUp') direction = 'up'
        if (event.key === 'ArrowDown') direction = 'down'
        if (event.key === 'ArrowLeft') direction = 'left'
        if (event.key === 'ArrowRight') direction = 'right'

        let current = activeEl
        if (!current || current === document.body || !isVisible(current)) {
          // Find first focusable element
          const first = Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).find(isVisible)
          if (first) {
            event.preventDefault()
            first.focus()
            first.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' })
          }
          return
        }

        const next = findNextElement(current, direction)
        if (next) {
          event.preventDefault()
          next.focus()
          next.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' })
        }
        return
      }

      // Handle Remote OK / Enter / Select
      if (event.key === 'Enter' || event.key === 'Select') {
        if (activeEl && activeEl !== document.body && !isInput) {
          // Trigger click on focused element
          activeEl.click()
        }
        return
      }

      // Handle Remote Back key (Escape / GoBack / Android KEYCODE_BACK)
      if (event.key === 'Escape' || event.key === 'GoBack' || event.key === 'BrowserBack' || event.keyCode === 4) {
        // If modal/dialog is open, let default Escape handle or dismiss
        const dialog = document.querySelector('.MuiDialog-root, .MuiModal-root')
        if (dialog) {
          // Modal will close via its own handler
          return
        }

        // Navigate back if on sub-page
        if (location.pathname !== '/' && location.pathname !== '/home') {
          event.preventDefault()
          navigate('/')
          return
        }

        // If on home and not on sidebar, move focus to sidebar
        const sidebarItem = document.querySelector<HTMLElement>('.the-menu .MuiListItemButton-root')
        if (sidebarItem && activeEl && !sidebarItem.contains(activeEl)) {
          event.preventDefault()
          sidebarItem.focus()
        }
        return
      }

      // Remote Media Play/Pause: toggle proxy
      if (event.key === 'MediaPlayPause' || event.keyCode === 85 || event.keyCode === 179) {
        event.preventDefault()
        const currentProxy = verge?.enable_system_proxy ?? false
        patchVergeConfig({ enable_system_proxy: !currentProxy })
          .then(() => {
            showNotice(
              'info',
              !currentProxy ? 'TV: System Proxy Enabled' : 'TV: System Proxy Disabled',
            )
          })
          .catch((err) => {
            console.error('Failed to toggle proxy via TV remote:', err)
          })
        return
      }

      // Number keys 1-5: quick jump between primary tabs
      if (!isInput && ['1', '2', '3', '4', '5'].includes(event.key)) {
        event.preventDefault()
        const routes = ['/', '/proxies', '/profiles', '/rules', '/settings']
        const targetRoute = routes[parseInt(event.key, 10) - 1]
        if (targetRoute) {
          navigate(targetRoute)
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown, true)
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true)
    }
  }, [active, findNextElement, location.pathname, navigate, verge?.enable_system_proxy])

  return { isTV: active }
}
