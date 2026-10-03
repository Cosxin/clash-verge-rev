// SPDX-License-Identifier: GPL-3.0-only
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
if (process.platform !== 'darwin') throw new Error('The macOS provider requires the macOS SDK')
const team = process.env.NETWORK_CONTROL_TEAM_ID ?? ''
const owner = process.env.NETWORK_CONTROL_OWNER_UID ?? '-1'
if (team && !/^[A-Z0-9]{10}$/.test(team)) throw new Error('Team ID must be a real ten-character Apple publisher ID')
if (!/^(?:-1|\d{1,10})$/.test(owner) || Number(owner) > 0xfffffffe) throw new Error('Owner UID is invalid')
const output = join(root, 'build')
const bundle = join(output, 'io.github.cosxin.network-control.filter.systemextension')
mkdirSync(join(bundle, 'Contents', 'MacOS'), { recursive: true })
const args = ['-fobjc-arc', '-mmacosx-version-min=13.0', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-deprecated-declarations',
  `-DNC_TEAM_ID="${team}"`, `-DNC_OWNER_UID=${owner}`, '-framework', 'Foundation', '-framework', 'Security']
execFileSync('xcrun', ['clang', ...args, join(root, 'Native.m'), join(root, 'Provider.m'), '-framework', 'NetworkExtension', '-lbsm',
  '-o', join(bundle, 'Contents', 'MacOS', 'network-control-filter')], { stdio: 'inherit' })
execFileSync('xcrun', ['clang', ...args, join(root, 'Native.m'), join(root, 'Controller.m'), '-o', join(output, 'network-control-native')], { stdio: 'inherit' })
const template = readFileSync(join(root, 'Info.plist'), 'utf8')
writeFileSync(join(bundle, 'Contents', 'Info.plist'), template.replaceAll('__TEAM__', team || 'UNSIGNED'))
console.log(`Compiled ${bundle} and its controller. No signing, installation, provider launch or activation was performed.`)
