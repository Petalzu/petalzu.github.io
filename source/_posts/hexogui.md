---
title: HexoGUI：本地 Hexo 的桌面管理器
date: '2026-04-07 18:00:00'
updated: '2026-04-07 18:00:00'
tags:
  - HexoGUI
  - Hexo
  - Electron
  - electron-builder
  - GitHub Actions
categories:
  - 笔记
thumbnail: /images/other/HexoGUI.png
cover: /images/other/HexoGUI.png
toc: true
---
Hexo 很轻量，但一旦把它当作“日常写作环境”，就会频繁遇到一些工程性的小麻烦：多站点切换、反复开关 server、端口占用、预览窗口、以及把这些流程做成一键式。

HexoGUI 就是为了解决这些“碎但高频”的问题：它是一个基于 Electron 的桌面工具，目标是把本地 Hexo 的常用操作收敛到一个界面里，并且能直接打包成便携版可执行文件。

<!-- more -->

## 功能一览

目前 HexoGUI 的定位更像“本地写作与调试工具箱”，核心功能集中在以下几块：

- 选择/记录 Hexo 站点路径，管理文章/页面/图片等内容资产
- 一键启动/停止 Hexo server，并在应用内预览（iframe）
- 主题与语言切换（界面 i18n + 主题循环）
- Windows 下处理端口占用与残留进程，尽量减少“明明关了又提示端口被占用”的情况
- 打包发布：输出便携版 exe；CI 里一键构建 Win/Linux/mac 并自动发布 Release

> 说明：HexoGUI 目前仍以 `localhost:4000` 为默认预览端口，主要通过“退出/停止时清理监听者 + 预览等待就绪”来提升稳定性；动态选端口与全链路端口同步是后续会继续完善的方向（见文末计划）。

## 设计目标与取舍

一开始我给它定的目标很明确：

1. **可用性优先**：不要把 UI 做成复杂 IDE，而是把最高频的操作“做短路径”。
2. **便携优先**：Windows 上更偏好“下载一个 exe 双击就跑”，而不是安装包。
3. **可跨平台构建**：至少能在 CI 上稳定产出 Win/Linux/mac 的发布物。
4. **工程可控**：不引入过多框架；渲染端用原生 HTML/CSS/JS，主进程用 Node 能力解决进程管理问题。

## 项目结构

HexoGUI 的代码结构很典型：

- `main.js`：Electron 主进程；创建窗口、菜单、与 Hexo 子进程生命周期管理
- `preload.js`：在 `contextIsolation` 下向渲染进程暴露安全的 API（IPC 包装）
- `renderer/`：渲染进程 UI（`index.html` / `styles.css` / `app.js`）
- `locales/`：中英文文案（JSON）
- `scripts/`：构建期脚本（例如图标生成）
- `.github/workflows/`：GitHub Actions 矩阵构建与 Release

这种拆分的好处是：UI 层保持“网页”范式，系统能力（spawn/kill/打开外部链接/读写文件等）统一走主进程，边界清晰、调试也更直观。

## 关键实现细节

### 1) 主进程与渲染进程：IPC 作为唯一通道

Electron 的推荐姿势是：渲染进程不要直接拿 Node 权限（尤其是涉及路径、命令执行、进程管理的时候）。所以 HexoGUI 的交互都收敛成 IPC：

- 渲染进程触发：例如“开始调试/停止调试/打开预览”等
- 主进程执行：spawn Hexo、清理端口、打开外部链接
- 状态回传：stdout/stderr 日志、进程退出码、错误原因

这种设计的直接收益是：

- 渲染进程代码更接近纯前端逻辑
- Windows / macOS / Linux 的差异可以集中在主进程处理

### 2) 启动 Hexo server：Windows 的 `spawn` 细节

在 Windows 上，直接 `spawn('hexo', ['server', '-p', '4000'])` 或 `spawn('npm', [...])` 都可能踩到环境与参数解析的坑（尤其在不同 Node/Electron 版本组合下，可能出现 `spawn EINVAL` 这一类错误）。

HexoGUI 的做法偏“稳”：通过 `cmd.exe` 让系统 shell 负责解析命令，并复用站点里的 npm script（例如 `npm run server`）：

```js
// 伪代码示意
spawn('cmd.exe', ['/d', '/s', '/c', `npm run server -- -p ${port}`], {
  cwd: siteDir,
  windowsHide: true,
});
```

在这个层面上，`cwd` 是关键：它决定了 Hexo 读取配置与 `node_modules` 的路径，也决定了“同一个工具能管理多个站点”的可能性。

在非 Windows 平台上则可以直接 spawn `npm`，并用 `detached: true` 让进程组更易于管理与回收。

### 3) 端口占用：停止调试与退出时的清理策略

端口占用（尤其是 4000）是本地 Hexo 最常见的“伪故障”来源：

- 你以为已经停了，但进程没被正确回收
- 你关了 Electron 窗口，但子进程还活着
- 另一个程序恰好占用了 4000

HexoGUI 的策略偏保守：

- **优先杀子进程树**：停止调试时对启动的 Hexo 子进程做“树状清理”（Windows 用 `taskkill /T /F`）
- **额外按端口清理**：在停止调试/退出应用时，查询端口对应 PID，并尝试结束监听者

思路是：如果你明确点了“停止”，那就尽量把与调试相关的监听者清掉，避免下次启动误报。

> 这种做法也意味着：如果你同时在 4000 上跑了别的服务，停止调试可能会影响它。因此更理想的方案还是“自动选空闲端口 + 全链路同步”，后续会做。

### 4) 预览 iframe：等待 server ready 再加载

另一个很常见的体验问题是：

- UI 点击“启动”后，Hexo server 需要几十到几百毫秒初始化
- 但渲染进程的 iframe 立刻去请求 `http://localhost:4000/`
- Electron 控制台就会出现 `ERR_CONNECTION_REFUSED`

HexoGUI 的处理方式是：**先启动 server，再做可达性探测，探测成功后才设置 iframe 的 `src`**。伪代码示意：

```js
async function waitForReady(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await fetch(url, { cache: 'no-store' });
      return true;
    } catch {
      await new Promise(r => setTimeout(r, 250));
    }
  }
  return false;
}
```

这样做的收益是：

- 控制台噪声显著减少
- “启动慢”与“启动失败”更容易区分（至少不会一开始就报错）

### 5) i18n 与主题切换：把高频开关收敛到侧栏底部

UI 层的一个小改动，但对使用手感影响很大：把语言/主题切换放到侧栏左下角，改成 compact 单按钮（语言一键切换、主题按序循环）。

这类控件本质上属于“随时会用但不希望占空间”的类型：

- 放在侧栏底部，符合“设置类入口”直觉
- 单按钮循环减少控件数量，也能避免侧栏过窄时按钮挤压换行

## 打包与发布

### 1) electron-builder：便携版 exe 与跨平台构建

HexoGUI 使用 `electron-builder` 完成打包：

- Windows：输出便携版 `.exe`（portable）
- Linux：输出 AppImage
- macOS：输出 dmg

为了避免 CI 上自动 publish 触发 token 需求，构建脚本显式加了：

```bash
--publish never
```

发布动作交给 GitHub Actions 的 release job 去做，这样权限边界更清晰。

### 2) 图标：从 PNG 生成多尺寸 ico/icns

应用图标在不同平台的格式与尺寸要求不一样：

- Windows 更偏好 `.ico`（内部包含多尺寸）
- macOS 使用 `.icns`

HexoGUI 的做法是：以同一张 `HexoGUI.png` 为源，在构建期生成 `app.ico` 与 `app.icns` 并交给 electron-builder 引用。这样可以保证“图标源一致、平台产物一致”。

### 3) GitHub Actions：三平台矩阵 + 自动 Release

CI 目标是：打 tag 后自动构建三平台并发布 Release。

关键点在于：

- `matrix` 同时跑 Windows/Ubuntu/macOS
- 只上传目标发布物（例如 Windows 只传 `.exe`，macOS 只传 `.dmg`）
- Release 的 title/body 用统一模板生成，避免每次手写

这套流程跑通之后，日常发布基本就变成：

1. 改代码
2. 打 tag
3. 等 Release

## 踩坑记录

- **Port 4000 has been used**：绝大多数时候是残留的 `hexo server` 或者其他程序占用了端口；“杀进程树 + 按端口清理 + 等待 ready 再加载”能明显改善体验。
- **Windows `spawn EINVAL`**：尽量避免直接 spawn 不确定的命令名，使用 `cmd.exe /c` 或 `npx` 这类更稳的入口，并确保 `cwd` 正确。
- **预览偶发拒绝连接**：不是 Hexo 真的坏了，而是 UI 请求太早；加 ready 探测能把噪声压下去。
- **CI 自动 publish 的 token 问题**：构建阶段统一 `--publish never`，发布阶段集中在 release job。
