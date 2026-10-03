import { createElement, useState } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { SWRConfig, unstable_serialize } from 'swr'
import { describe, expect, test } from 'vitest'

import { useQuery } from '@/services/query-client'

import { useRetainedNetworkSnapshot } from './use-retained-network-snapshot'

describe('paused network workspace snapshots', () => {
  test('retains acknowledged data when the real disabled SWR key becomes empty', () => {
    const key = ['network-retention-fixture']
    const acknowledged = { generation: 2 }
    const observations: Array<{ incoming: unknown; retained: unknown }> = []
    const Probe = () => {
      const [enabled, setEnabled] = useState(true)
      const { data } = useQuery({
        queryKey: key,
        queryFn: async () => acknowledged,
        enabled,
      })
      const retained = useRetainedNetworkSnapshot(data)
      observations.push({ incoming: data, retained })
      if (enabled) setEnabled(false)
      return retained ? createElement('span', null, 'editor retained') : null
    }
    const result = renderToStaticMarkup(
      createElement(
        SWRConfig,
        { value: { fallback: { [unstable_serialize(key)]: acknowledged } } },
        createElement(Probe),
      ),
    )
    expect(observations[0].incoming).toBe(acknowledged)
    expect(observations.at(-1)?.incoming).toBeUndefined()
    expect(observations.at(-1)?.retained).toBe(acknowledged)
    expect(result).toBe('<span>editor retained</span>')
  })

  test('does not invent initial data and adopts newer acknowledgements on resume', () => {
    const acknowledged = { generation: 2 }
    const latest = { generation: 3 }
    const inputs = [undefined, acknowledged, undefined, latest, undefined]
    const retained: Array<typeof acknowledged | undefined> = []
    const Probe = () => {
      const [step, setStep] = useState(0)
      const snapshot = useRetainedNetworkSnapshot(inputs[step])
      retained.push(snapshot)
      if (step < inputs.length - 1) setStep(step + 1)
      return createElement('span', null, snapshot?.generation)
    }
    expect(renderToStaticMarkup(createElement(Probe))).toBe('<span>3</span>')
    expect(retained[0]).toBeUndefined()
    expect(retained[2]).toBe(acknowledged)
    expect(retained.at(-1)).toBe(latest)
  })
})
