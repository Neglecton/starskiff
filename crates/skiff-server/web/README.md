# Starskiff Admin Console（前端）

Vue 3 + Vite + Naive UI + vue-i18n 构建的管理控制台，构建产物内嵌进 `starskiff-server` 二进制（rust-embed），离线可用（无 CDN 依赖）。

## 开发

```bash
npm install        # 首次
npm run build      # 产出 dist/（内嵌进服务器；debug 模式 rust-embed 直接读磁盘，改完无需重编 Rust）
npm run dev        # 本地开发服务器（API 需另行指定地址登录）
```

- 产物 `dist/` **不入库**（`.gitignore` 忽略），仅 `dist/index.html` 占位页入库——未构建时 cargo build 依然成功，访问 /admin/ 会显示构建提示。
- **提交前**若构建过前端，用 `git checkout -- crates/skiff-server/web/dist/index.html` 还原占位页（避免把构建产物带进提交）。
- `vite.config.js` 的 `base: './'` 必须保留：管理页挂在服务器的 `/admin/` 子路径（及反代前缀）下，相对路径才能正确加载 assets。
- 服务器对 `assets/`（hash 文件名）返回 `Cache-Control: immutable`，对 `index.html` 返回 `no-cache`——新版本部署后浏览器自动取新壳。

## 结构

```
src/
├── main.js            # createApp + i18n + naive 注册
├── App.vue            # 主题/语言 Provider、登录态切换、header（语言/主题/断开）
├── api.js             # fetch 封装（X-Admin-Token；按 Content-Type 解析，兼容纯文本成功响应）
├── store.js           # reactive store：token/语言/主题（localStorage 持久化）
├── i18n/              # vue-i18n + zh-CN / en-US 语言包（store.lang 驱动，同步 document.lang）
├── styles/global.css  # 全局样式（等宽 .mono、header 等）
└── components/        # LoginPanel / StatCards / NetworksTab / DevicesTab / TokensTab
```

## 约定

- 用户可见文案一律走 i18n（`src/i18n/locales/`），禁止硬编码中英文；Naive UI 组件文案随 `n-config-provider` 的 locale 同步。
- 主题默认浅色，`prefers-color-scheme` 自动初选，手动切换持久化；颜色通过 `themeOverrides`（App.vue）统一管理。
- 表格列的 render 用 `computed` 包裹 `t()`，保证切换语言即时生效。
- 图标用 `@vicons/ionicons5`（内联打包），不用 emoji。
