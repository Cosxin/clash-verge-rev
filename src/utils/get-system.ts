// get the system os
// according to UA
export default function getSystem(): 'macos' | 'windows' | 'android' | 'linux' | 'unknown' {
  const ua = navigator.userAgent
  const platform = OS_PLATFORM

  if (ua.includes('Mac OS X') || platform === 'darwin') return 'macos'

  if (/win64|win32/i.test(ua) || platform === 'win32') return 'windows'

  if (/android/i.test(ua) || platform === 'android') return 'android'

  if (/linux/i.test(ua)) return 'linux'

  return 'unknown'
}

/**
 * Detect whether the current environment is Android TV
 */
export function isAndroidTV(): boolean {
  if (typeof window === 'undefined' || !navigator) return false
  const ua = navigator.userAgent || ''

  // Common user agent indicators for Android TV, Google TV, Fire TV, etc.
  const tvPatterns = [
    /googletv/i,
    /androidtv/i,
    /smart-?tv/i,
    /large screen/i,
    /\b(tv|aft[a-z0-9]+)\b/i,
    /crkey/i, // Chromecast
    /nexus player/i,
    /bravia/i,
    /shield android tv/i,
    /mibox/i,
  ]

  const isAndroid = /android/i.test(ua) || OS_PLATFORM === 'android'
  return isAndroid && tvPatterns.some((pattern) => pattern.test(ua))
}

/**
 * Determine whether TV Mode (remote control spatial navigation & 10ft UI) should be active
 */
export function isTVMode(settingValue?: string | null): boolean {
  if (settingValue === 'always') return true
  if (settingValue === 'off') return false
  return isAndroidTV()
}
