import { describe, expect, test, vi } from 'vitest'

import parseUri from './index'

const reality =
  'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?' +
  'security=reality&sni=example.com&fp=chrome&pbk=fixture-key&sid=0123456789abcdef&flow=xtls-rprx-vision'

describe('protocol share-link compatibility', () => {
  test('keeps malformed JSON fallback warnings free of imported values', () => {
    const marker = 'PRIVATE123'
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const vless = parseUri(
        'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?' +
          `type=ws&obfsParam=${encodeURIComponent(marker)}`,
      ) as IProxyVlessConfig
      expect(vless['ws-opts']?.headers).toEqual({ Host: marker })

      const shadowsocks = parseUri(
        `ss://${btoa('aes-128-gcm:fixture-password')}@192.0.2.1:443?` +
          `v2ray-plugin=${btoa(marker)}`,
      ) as IProxyShadowsocksConfig
      expect(shadowsocks.plugin).toBe('v2ray-plugin')
      expect(shadowsocks['plugin-opts']).toEqual({})

      const vmess = parseUri(
        `vmess://${btoa('auto:00000000-0000-4000-8000-000000000001@192.0.2.1:443')}?` +
          `obfs=websocket&obfsParam=${encodeURIComponent(marker)}&path=%2Ffixture`,
      ) as IProxyVmessConfig
      expect(vmess.server).toBe('192.0.2.1')
      expect(vmess.port).toBe(443)
      expect(vmess['ws-opts']).toEqual({
        headers: { Host: marker },
        path: '/fixture',
      })

      expect(warn.mock.calls).toEqual([
        ['[URI_VLESS] Invalid transport host JSON; using literal host'],
        ['[URI_SS] Invalid plugin JSON; using empty plugin options'],
        ['[URI_VMESS] Non-JSON content; trying Shadowrocket format'],
        ['[URI_VMESS] Invalid transport host JSON; using literal host'],
      ])
      expect(warn.mock.calls.flat().map(String).join(' ')).not.toContain(marker)
    } finally {
      warn.mockRestore()
    }
  })

  test.each(['tls', 'reality'])(
    'keeps ordinary WebSocket aliases distinct from HTTP upgrade with %s',
    (security) => {
      const link =
        'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?' +
        `security=${security}&host=example.com&path=%2Ffixture&type=`
      const ordinaryOptions = {
        headers: { Host: 'example.com' },
        path: '/fixture',
      }
      for (const transport of ['ws', 'websocket']) {
        const proxy = parseUri(link + transport) as IProxyVlessConfig
        expect(proxy.network).toBe('ws')
        expect(proxy['ws-opts']).toEqual(ordinaryOptions)
      }
      const upgrade = parseUri(link + 'httpupgrade') as IProxyVlessConfig
      expect(upgrade.network).toBe('ws')
      expect(upgrade['ws-opts']).toEqual({
        ...ordinaryOptions,
        'v2ray-http-upgrade': true,
        'v2ray-http-upgrade-fast-open': true,
      })
    },
  )

  test('preserves modern Reality handshake and explicit UDP settings', () => {
    const proxy = parseUri(
      reality +
        '&support-x25519mlkem768=1&udp=1&packetEncoding=xudp#Reality%20test',
    ) as IProxyVlessConfig
    expect(proxy.name).toBe('Reality test')
    expect(proxy.tls).toBe(true)
    expect(proxy.servername).toBe('example.com')
    expect(proxy['client-fingerprint']).toBe('chrome')
    expect(proxy.flow).toBe('xtls-rprx-vision')
    expect(proxy.udp).toBe(true)
    expect(proxy['packet-encoding']).toBe('xudp')
    expect(proxy['reality-opts']).toEqual({
      'public-key': 'fixture-key',
      'short-id': '0123456789abcdef',
      'support-x25519mlkem768': true,
    })
  })

  test('does not invent a modern handshake requirement for a legacy link', () => {
    const proxy = parseUri(reality) as IProxyVlessConfig
    expect(proxy['reality-opts']?.['support-x25519mlkem768']).toBeUndefined()
    expect(proxy.udp).toBeUndefined()
    expect(proxy['packet-encoding']).toBeUndefined()
    expect(proxy['skip-cert-verify']).toBeUndefined()
  })

  test('preserves explicit false values and normalized parameter spelling', () => {
    const proxy = parseUri(
      reality +
        '&support_x25519mlkem768=false&udp=0&packet-encoding=packetaddr&allowInsecure=0',
    ) as IProxyVlessConfig
    expect(proxy['reality-opts']?.['support-x25519mlkem768']).toBe(false)
    expect(proxy.udp).toBe(false)
    expect(proxy['packet-encoding']).toBe('packetaddr')
    expect(proxy['skip-cert-verify']).toBe(false)
  })

  test('refuses an unsupported explicit UDP packet encoding', () => {
    expect(() => parseUri(reality + '&packetEncoding=unknown')).toThrow(
      'Unsupported VLESS packet encoding',
    )
  })

  test('preserves Hysteria authentication, TLS pin and certificate-check intent', () => {
    const fingerprint = '12:34:56:78'
    const proxy = parseUri(
      'hy2://encoded%3Apassword%40value@192.0.2.1:8443?' +
        `sni=example.com&insecure=0&pinSHA256=${encodeURIComponent(fingerprint)}#HY2%20test`,
    ) as IProxyHysteria2Config
    expect(proxy.type).toBe('hysteria2')
    expect(proxy.password).toBe('encoded:password@value')
    expect(proxy.sni).toBe('example.com')
    expect(proxy.fingerprint).toBe(fingerprint)
    expect(proxy['skip-cert-verify']).toBe(false)
  })
})
