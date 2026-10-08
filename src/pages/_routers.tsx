import { createBrowserRouter, replace, RouteObject } from 'react-router'

import Layout from './_layout'
import { navItems } from './_navigation'
import { navigationItems } from './_navigation-meta'

export const router = createBrowserRouter([
  {
    path: '/',
    Component: Layout,
    children: [
      ...navItems.map(
        (item) =>
          ({
            path: item.path,
            Component: item.Component,
          }) as RouteObject,
      ),
      { path: '*', loader: () => replace(navigationItems.home.path) },
    ],
  },
])
