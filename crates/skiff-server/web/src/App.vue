<script setup>
import { computed, h, provide, ref } from 'vue';
import { NIcon } from 'naive-ui';
import { darkTheme, zhCN, enUS, dateEnUS, dateZhCN } from 'naive-ui';
import {
  CloudOutline,
  DesktopOutline,
  GitNetworkOutline,
  GlobeOutline,
  LinkOutline,
  LogOutOutline,
  MoonOutline,
  PersonCircleOutline,
  ServerOutline,
  SettingsOutline,
  SunnyOutline,
} from '@vicons/ionicons5';
import { store, saveToken, setLang, setTheme, resolvedTheme } from './store';
import LoginPanel from './components/LoginPanel.vue';
import StatCards from './components/StatCards.vue';
import TopologyTab from './components/TopologyTab.vue';
import NetworksTab from './components/NetworksTab.vue';
import DevicesTab from './components/DevicesTab.vue';
import TokensTab from './components/TokensTab.vue';
import SettingsTab from './components/SettingsTab.vue';
import { useI18n } from 'vue-i18n';

const { t } = useI18n();

// Shared data refresh hooks: each tab registers its loader.
const loaders = ref([]);
function registerLoader(fn) {
  loaders.value.push(fn);
}
async function refreshAll() {
  await Promise.allSettled(loaders.value.map((fn) => fn()));
}
provide('refreshAll', refreshAll);
provide('registerLoader', registerLoader);

const naiveLocale = computed(() => (store.lang === 'zh-CN' ? zhCN : enUS));
const naiveDateLocale = computed(() => (store.lang === 'zh-CN' ? dateZhCN : dateEnUS));
const isDark = computed(() => {
  void store.theme;
  void store.systemDark;
  return resolvedTheme() === 'dark';
});
const theme = computed(() => (isDark.value ? darkTheme : null));

const ink = computed(() => (isDark.value ? '#E2E8F0' : '#1E293B'));
const inkHover = computed(() => (isDark.value ? '#F8FAFC' : '#334155'));
const inkPressed = computed(() => (isDark.value ? '#CBD5E1' : '#0F172A'));

const themeOverrides = computed(() => ({
  common: {
    primaryColor: ink.value,
    primaryColorHover: inkHover.value,
    primaryColorPressed: inkPressed.value,
    primaryColorSuppl: ink.value,
    infoColor: '#2563EB',
    successColor: '#059669',
    warningColor: '#D97706',
    errorColor: '#DC2626',
    borderRadius: '10px',
    fontSize: '14px',
  },
}));

const langOptions = computed(() => [
  { label: t('app.langZh'), value: 'zh-CN' },
  { label: t('app.langEn'), value: 'en-US' },
]);

const accountOptions = computed(() => [
  {
    label: t('app.logout'),
    key: 'logout',
    icon: () => h(NIcon, null, { default: () => h(LogOutOutline) }),
  },
]);

function onLogin({ token, base }) {
  saveToken(token);
  store.base = base;
  store.connected = true;
}

function logout() {
  saveToken('');
  store.connected = false;
  loaders.value = [];
}

function onAccountSelect(key) {
  if (key === 'logout') logout();
}

// Auto-login with a persisted token (auth probe inside LoginPanel).
const autoToken = store.token;
</script>

<template>
  <n-config-provider
    :theme="theme"
    :theme-overrides="themeOverrides"
    :locale="naiveLocale"
    :date-locale="naiveDateLocale"
  >
    <n-message-provider placement="top">
      <n-dialog-provider>
        <div class="app-shell" :class="{ 'theme-dark': isDark }">
          <div v-if="!store.connected" class="login-wrap">
            <LoginPanel :auto-token="autoToken" @login="onLogin" />
          </div>
          <template v-else>
            <header class="app-header">
              <div class="brand-lockup">
                <span class="brand-mark" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                    <path d="M12 1.6 14.2 8.4 21.4 9.2 16 14.1 17.6 21.2 12 17.6 6.4 21.2 8 14.1 2.6 9.2 9.8 8.4Z" />
                  </svg>
                </span>
                <h1 class="app-title">Starskiff</h1>
              </div>
              <div class="header-actions">
                <div class="lang-pill">
                  <NIcon class="lang-icon" size="16"><GlobeOutline /></NIcon>
                  <n-select
                    class="lang-select"
                    size="small"
                    :bordered="false"
                    :value="store.lang"
                    :options="langOptions"
                    :consistent-menu-width="false"
                    :aria-label="$t('app.language')"
                    @update:value="setLang"
                  />
                </div>
                <div class="theme-switch" role="group" :aria-label="$t('app.themeSystem')">
                  <button
                    type="button"
                    class="theme-btn"
                    :class="{ active: store.theme === 'light' }"
                    :aria-label="$t('app.themeLight')"
                    :aria-pressed="store.theme === 'light'"
                    @click="setTheme('light')"
                  >
                    <NIcon size="16"><SunnyOutline /></NIcon>
                  </button>
                  <button
                    type="button"
                    class="theme-btn"
                    :class="{ active: store.theme === 'system' }"
                    :aria-label="$t('app.themeSystem')"
                    :aria-pressed="store.theme === 'system'"
                    @click="setTheme('system')"
                  >
                    <NIcon size="16"><DesktopOutline /></NIcon>
                  </button>
                  <button
                    type="button"
                    class="theme-btn"
                    :class="{ active: store.theme === 'dark' }"
                    :aria-label="$t('app.themeDark')"
                    :aria-pressed="store.theme === 'dark'"
                    @click="setTheme('dark')"
                  >
                    <NIcon size="16"><MoonOutline /></NIcon>
                  </button>
                </div>
                <n-dropdown
                  trigger="click"
                  :options="accountOptions"
                  placement="bottom-end"
                  @select="onAccountSelect"
                >
                  <button type="button" class="avatar-btn" :aria-label="$t('app.account')">
                    <NIcon size="22"><PersonCircleOutline /></NIcon>
                  </button>
                </n-dropdown>
              </div>
            </header>
            <main class="page">
              <div class="page-content">
                <StatCards />
                <n-tabs class="console-tabs" type="line" animated>
                  <n-tab-pane name="topology">
                    <template #tab>
                      <span class="tab-label"><NIcon size="16"><GitNetworkOutline /></NIcon>{{ $t('tabs.topology') }}</span>
                    </template>
                    <TopologyTab />
                  </n-tab-pane>
                  <n-tab-pane name="networks">
                    <template #tab>
                      <span class="tab-label"><NIcon size="16"><CloudOutline /></NIcon>{{ $t('tabs.networks') }}</span>
                    </template>
                    <NetworksTab />
                  </n-tab-pane>
                  <n-tab-pane name="devices">
                    <template #tab>
                      <span class="tab-label"><NIcon size="16"><ServerOutline /></NIcon>{{ $t('tabs.devices') }}</span>
                    </template>
                    <DevicesTab />
                  </n-tab-pane>
                  <n-tab-pane name="tokens">
                    <template #tab>
                      <span class="tab-label"><NIcon size="16"><LinkOutline /></NIcon>{{ $t('tabs.tokens') }}</span>
                    </template>
                    <TokensTab />
                  </n-tab-pane>
                  <n-tab-pane name="settings">
                    <template #tab>
                      <span class="tab-label"><NIcon size="16"><SettingsOutline /></NIcon>{{ $t('tabs.settings') }}</span>
                    </template>
                    <SettingsTab />
                  </n-tab-pane>
                </n-tabs>
              </div>
            </main>
          </template>
        </div>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style scoped>
.app-shell {
  min-height: 100vh;
  color: var(--sk-text);
  background: var(--sk-page-bg);
}

.login-wrap {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: clamp(20px, 5vw, 64px) 16px;
  background:
    radial-gradient(circle at 50% 0%, rgba(15, 23, 42, 0.05), transparent 42%),
    var(--sk-page-bg);
}

.brand-lockup {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.brand-mark {
  display: inline-grid;
  place-items: center;
  width: 28px;
  height: 28px;
  flex: none;
  color: var(--sk-ink);
}

.app-title {
  min-width: 0;
}

.lang-pill {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 0 4px 0 10px;
  border: 1px solid var(--sk-border);
  border-radius: 999px;
  background: var(--sk-surface);
  min-height: 32px;
}

.lang-icon {
  color: var(--sk-text-muted);
  flex: none;
}

.lang-select {
  width: 92px;
}

.lang-select :deep(.n-base-selection) {
  --n-border: 0 !important;
  --n-border-hover: 0 !important;
  --n-border-focus: 0 !important;
  --n-border-active: 0 !important;
  background: transparent;
}

.theme-switch {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 3px;
  border: 1px solid var(--sk-border);
  border-radius: 999px;
  background: var(--sk-surface);
}

.theme-btn,
.avatar-btn {
  display: inline-grid;
  place-items: center;
  width: 30px;
  height: 30px;
  padding: 0;
  border: 0;
  border-radius: 999px;
  background: transparent;
  color: var(--sk-text-muted);
  cursor: pointer;
}

.theme-btn.active {
  color: var(--sk-text);
  background: var(--sk-surface-soft);
}

.avatar-btn {
  width: 34px;
  height: 34px;
  color: var(--sk-text-muted);
}

.page {
  min-height: calc(100vh - 64px);
  background: var(--sk-page-bg);
}

.page-content {
  width: min(100%, 1440px);
  margin: 0 auto;
  padding: clamp(18px, 3vw, 32px) clamp(16px, 4vw, 40px) 56px;
}

.console-tabs :deep(.tab-label) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.console-tabs :deep(.n-tabs-bar) {
  height: 3px;
  border-radius: 3px 3px 0 0;
}

@media (max-width: 640px) {
  .app-header {
    align-items: flex-start;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-end;
  }
}
</style>
