import { describe, expect, test } from 'vitest'

import parseUri from './index'

const reality =
  'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?' +
  'security=reality&sni=example.com&fp=chrome&pbk=fixture-key&sid=0123456789abcdef&flow=xtls-rprx-vision'

describe('protocol share-link compatibility', () => {
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
