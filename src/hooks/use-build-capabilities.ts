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
    hostLocked: data?.hostNetworkChanges !== true,
    unavailable: data === undefined && Boolean(error),
  }
}
