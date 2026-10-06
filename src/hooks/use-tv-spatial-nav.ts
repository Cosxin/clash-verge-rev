import { useCallback, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router'

import { useVerge } from '@/hooks/use-verge'
import { patchVergeConfig } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { isTVMode } from '@/utils/get-system'

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
  '.MuiSwitch-switchBase:not([disabled])',
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
  const style = window.getComputedStyle(el)
  if (
    style.visibility === 'hidden' ||
    style.display === 'none' ||
    style.opacity === '0'
  ) {
    return false
  }
  const rect = el.getBoundingClientRect()
  return rect.width > 0 && rect.height > 0
}

const focusElement = (el: HTMLElement) => {
  if (
    el.getAttribute('tabindex') === null &&
    !['BUTTON', 'A', 'INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName)
  ) {
    el.setAttribute('tabindex', '-1')
  }
  document
    .querySelectorAll('.tv-focused')
    .forEach((node) => node.classList.remove('tv-focused'))
  el.classList.add('tv-focused')
  el.focus()
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' })
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

  // Auto-focus initial element in TV mode
  useEffect(() => {
    if (!active) return

    const timer = setTimeout(() => {
      const activeEl = document.activeElement as HTMLElement | null
      if (!activeEl || activeEl === document.body) {
        const first = Array.from(
          document.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
        ).find(isVisible)
        if (first) {
          focusElement(first)
        }
      }
    }, 200)

    return () => clearTimeout(timer)
  }, [active, location.pathname])

  const findNextElement = useCallback(
    (
      current: HTMLElement,
      direction: 'up' | 'down' | 'left' | 'right',
    ): HTMLElement | null => {
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
            isValid =
              targetRect.bottom < curRect.top + 10 ||
              targetRect.centerY < curRect.centerY - 4
            primaryDist =
              Math.max(0, curRect.top - targetRect.bottom) +
              Math.abs(curRect.centerY - targetRect.centerY) * 0.4
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
          case 'down':
            isValid =
              targetRect.top > curRect.bottom - 10 ||
              targetRect.centerY > curRect.centerY + 4
            primaryDist =
              Math.max(0, targetRect.top - curRect.bottom) +
              Math.abs(targetRect.centerY - curRect.centerY) * 0.4
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
          case 'left':
            isValid =
              targetRect.right < curRect.left + 10 ||
              targetRect.centerX < curRect.centerX - 4
            primaryDist =
              Math.max(0, curRect.left - targetRect.right) +
              Math.abs(curRect.centerX - targetRect.centerX) * 0.4
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
          case 'right':
            isValid =
              targetRect.left > curRect.right - 10 ||
              targetRect.centerX > curRect.centerX + 4
            primaryDist =
              Math.max(0, targetRect.left - curRect.right) +
              Math.abs(targetRect.centerX - targetRect.centerX) * 0.4
            secondaryDist = Math.abs(curRect.centerX - targetRect.centerX)
            break
        }

        if (!isValid) continue

        // Weighted distance calculation: penalize orthogonal movement to prefer same row/column
        const distance = primaryDist + secondaryDist * 1.8
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
        !['button', 'checkbox', 'radio'].includes(
          (activeEl as HTMLInputElement).type,
        )

      const isUp =
        event.key === 'ArrowUp' ||
        event.key === 'Up' ||
        event.code === 'ArrowUp' ||
        event.keyCode === 38 ||
        event.keyCode === 19
      const isDown =
        event.key === 'ArrowDown' ||
        event.key === 'Down' ||
        event.code === 'ArrowDown' ||
        event.keyCode === 40 ||
        event.keyCode === 20
      const isLeft =
        event.key === 'ArrowLeft' ||
        event.key === 'Left' ||
        event.code === 'ArrowLeft' ||
        event.keyCode === 37 ||
        event.keyCode === 21
      const isRight =
        event.key === 'ArrowRight' ||
        event.key === 'Right' ||
        event.code === 'ArrowRight' ||
        event.keyCode === 39 ||
        event.keyCode === 22

      // Handle Directional (D-Pad) keys
      if (isUp || isDown || isLeft || isRight) {
        if (isInput && (isLeft || isRight)) {
          // Allow text navigation inside input
          return
        }

        const direction: 'up' | 'down' | 'left' | 'right' = isUp
          ? 'up'
          : isDown
            ? 'down'
            : isLeft
              ? 'left'
              : 'right'

        const current = activeEl
        if (!current || current === document.body || !isVisible(current)) {
          // Find first focusable element
          const first = Array.from(
            document.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
          ).find(isVisible)
          if (first) {
            event.preventDefault()
            focusElement(first)
          }
          return
        }

        const next = findNextElement(current, direction)
        if (next) {
          event.preventDefault()
          focusElement(next)
        }
        return
      }

      // Handle Remote OK / Enter / Select
      if (
        event.key === 'Enter' ||
        event.key === 'Select' ||
        event.keyCode === 13 ||
        event.keyCode === 23
      ) {
        if (activeEl && activeEl !== document.body && !isInput) {
          event.preventDefault()
          activeEl.click()
        }
        return
      }

      // Handle Remote Back key (Escape / GoBack / Android KEYCODE_BACK)
      if (
        event.key === 'Escape' ||
        event.key === 'GoBack' ||
        event.key === 'BrowserBack' ||
        event.keyCode === 4
      ) {
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
        const sidebarItem = document.querySelector<HTMLElement>(
          '.the-menu .MuiListItemButton-root',
        )
        if (sidebarItem && activeEl && !sidebarItem.contains(activeEl)) {
          event.preventDefault()
          sidebarItem.focus()
        }
        return
      }

      // Remote Media Play/Pause: toggle proxy
      if (
        event.key === 'MediaPlayPause' ||
        event.keyCode === 85 ||
        event.keyCode === 179
      ) {
        event.preventDefault()
        const currentProxy = verge?.enable_system_proxy ?? false
        patchVergeConfig({ enable_system_proxy: !currentProxy })
          .then(() => {
            showNotice(
              'info',
              !currentProxy
                ? 'TV: System Proxy Enabled'
                : 'TV: System Proxy Disabled',
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

    const handleFocusIn = (e: FocusEvent) => {
      const target = e.target as HTMLElement | null
      if (target && target !== document.body) {
        document
          .querySelectorAll('.tv-focused')
          .forEach((node) => node.classList.remove('tv-focused'))
        target.classList.add('tv-focused')
      }
    }

    window.addEventListener('keydown', handleKeyDown, true)
    window.addEventListener('focusin', handleFocusIn, true)
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true)
      window.removeEventListener('focusin', handleFocusIn, true)
    }
  }, [
    active,
    findNextElement,
    location.pathname,
    navigate,
    verge?.enable_system_proxy,
  ])

  return { isTV: active }
}
