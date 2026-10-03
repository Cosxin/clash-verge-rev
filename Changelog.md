## v2.5.7

<details>
<summary><strong> 🐞 修复问题 </strong></summary>

- 修复读屏软件将普通模式下的侧边栏导航项播报为不可用的可拖拽控件的问题
- 修复订阅包含自定义 DNS 时，确认开启的 DNS 覆写在重启应用后被自动关闭的问题
- Preserve unsaved Network edits across refreshes, tab changes and window hiding; reject stale saves without losing the draft.
- Reject stale app-ban confirmations before a restarted native provider changes enforcement.
- Show live route choices only while verified routing rules are active.

**🖥️ Windows**

- 修复 Windows 系统盘根目录的删除权限被误判，导致服务模式和 TUN 无法使用的问题

**🍎 macOS**

- macOS 修复启动或重启应用时偶发内核启动失败，并误提示「需要更新系统服务」的问题
- macOS 修复 VPN 接管网络或开机网络未就绪时的问题：服务模式内核无法启动、TUN 不可用、系统代理状态读取报错
- macOS 修复用 `ipconfig set` 手动配置网卡后无法设置系统代理的问题

</details>

<details>
<summary><strong> ✨ 新增功能 </strong></summary>

- Add an observe-only Network workspace for draft firewall/routing rules and decision previews.
- Add opt-in local connection history with retention, incomplete-data labels and redacted export.
- Add reviewed `.lsrules` import/export with unsupported-rule and precedence-conflict diagnostics.
- Add an isolated NetworkControl developer build with a stable-only core and no upstream updater or privileged-service changes.
- Add visual application-to-server/group routing and a default route with explicit, profile-bound core application.
- Add authenticated native ban adapters for macOS, Windows and Linux, with unavailable states until installation and runtime qualification.
- Preserve native source/destination and process evidence in history; keep overlapping native/core traffic counters separate.
- Switch existing app/default routes without a full reload and show their live choices.
- Add JSON agent diagnostics and protected route trials with automatic unconfirmed-trial restoration on macOS/Linux.

</details>

<details>
<summary><strong> 🚀 优化改进 </strong></summary>

- Simplify Network into Apps, Traffic and Settings, keeping advanced drafts out of the primary workflow.

**🖥️ Windows**

- 优化 Windows 服务安全检查未通过时的启动提示：显示具体原因，并提供修复文档链接

</details>
