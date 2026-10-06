import { getBuildCapabilities } from '@/services/cmds'
import { useQuery } from '@/services/query-client'

export const useBuildCapabilities = () => {
  const { data, error } = useQuery({
    queryKey: ['getBuildCapabilities'],
    queryFn: getBuildCapabilities,
    staleTime: Infinity,
  })

  return {
    flavor: data?.flavor,
    hostLocked: data?.hostNetworkChanges !== true || data.systemProxy !== true,
    tunLocked: data?.tun !== true,
    serviceLocked: data?.service !== true,
    autostartLocked: data?.autostart !== true,
    unavailable: data === undefined && Boolean(error),
  }
}
