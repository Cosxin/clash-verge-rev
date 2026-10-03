import { useState } from 'react'

export const useRetainedNetworkSnapshot = <T>(incoming: T | undefined) => {
  const [snapshot, setSnapshot] = useState(incoming)
  if (incoming !== undefined && incoming !== snapshot) setSnapshot(incoming)
  return incoming ?? snapshot
}
