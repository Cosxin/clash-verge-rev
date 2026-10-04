// SPDX-License-Identifier: GPL-3.0-only
import { execFileSync } from 'node:child_process'
import { mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

if (process.platform !== 'darwin') throw new Error('Journal fixtures require the macOS SDK')
const root = dirname(fileURLToPath(import.meta.url))
const temporary = realpathSync(mkdtempSync(join(tmpdir(), 'network-control-journal-test-')))
const executable = join(temporary, 'journal-test')
try {
  execFileSync('xcrun', ['clang', '-fobjc-arc', '-mmacosx-version-min=13.0', '-Wall', '-Wextra', '-Werror',
    '-Wno-unused-parameter', '-Wno-deprecated-declarations', '-DNC_JOURNAL_SELF_TEST',
    join(root, 'Native.m'), join(root, 'Journal.m'), join(root, 'JournalTest.m'),
    '-framework', 'Foundation', '-framework', 'Security', '-lsqlite3', '-o', executable], { stdio: 'inherit' })
  execFileSync(executable, [], { stdio: 'inherit' })
} finally {
  rmSync(temporary, { recursive: true })
}
