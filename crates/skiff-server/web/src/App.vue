<script setup>
import { computed, provide, ref } from 'vue';
import { NIcon } from 'naive-ui';
import { darkTheme, zhCN, enUS, dateEnUS, dateZhCN } from 'naive-ui';
import { MoonOutline, SunnyOutline } from '@vicons/ionicons5';
import { store, saveToken, setLang, toggleTheme } from './store';
import LoginPanel from './components/LoginPanel.vue';
import StatCards from './components/StatCards.vue';
import TopologyTab from './components/TopologyTab.vue';
import NetworksTab from './components/NetworksTab.vue';
import DevicesTab from './components/DevicesTab.vue';
import TokensTab from './components/TokensTab.vue';
import SettingsTab from './components/SettingsTab.vue';

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
const theme = computed(() => (store.theme === 'dark' ? darkTheme : null));
const isDark = computed(() => store.theme === 'dark');

// SaaS trust-blue palette (WCAG-checked); surfaces follow Naive's light/dark bases.
const themeOverrides = {
  common: {
    primaryColor: '#2563EB',
    primaryColorHover: '#3B82F6',
    primaryColorPressed: '#1D4ED8',
    primaryColorSuppl: '#2563EB',
    infoColor: '#2563EB',
    successColor: '#059669',
    warningColor: '#D97706',
    errorColor: '#DC2626',
    borderRadius: '8px',
    fontSize: '14px',
  },
};

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
                <span class="brand-mark" aria-hidden="true">S</span>
                <h1 class="app-title">
                  Starskiff <span class="sub">{{ $t('app.subtitle') }}</span>
                </h1>
              </div>
              <div class="header-actions">
                <n-button
                  quaternary
                  size="small"
                  :aria-label="$t('app.language')"
                  @click="setLang(store.lang === 'zh-CN' ? 'en-US' : 'zh-CN')"
                >
                  {{ store.lang === 'zh-CN' ? 'EN' : '中文' }}
                </n-button>
                <n-button
                  quaternary
                  size="small"
                  :aria-label="$t(isDark ? 'app.themeLight' : 'app.themeDark')"
                  @click="toggleTheme"
                >
                  <template #icon>
                    <NIcon><SunnyOutline v-if="isDark" /><MoonOutline v-else /></NIcon>
                  </template>
                </n-button>
                <n-button secondary size="small" @click="logout">{{ $t('app.logout') }}</n-button>
              </div>
            </header>
            <main class="page">
              <div class="page-content">
                <StatCards />
                <n-tabs type="line" animated>
                  <n-tab-pane name="topology" :tab="$t('tabs.topology')">
                    <TopologyTab />
                  </n-tab-pane>
                  <n-tab-pane name="networks" :tab="$t('tabs.networks')">
                    <NetworksTab />
                  </n-tab-pane>
                  <n-tab-pane name="devices" :tab="$t('tabs.devices')">
                    <DevicesTab />
                  </n-tab-pane>
                  <n-tab-pane name="tokens" :tab="$t('tabs.tokens')">
                    <TokensTab />
                  </n-tab-pane>
                  <n-tab-pane name="settings" :tab="$t('tabs.settings')">
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
    radial-gradient(circle at 50% 0%, rgba(37, 99, 235, 0.08), transparent 42%),
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
  width: 30px;
  height: 30px;
  flex: none;
  border-radius: 9px;
  color: #fff;
  background: linear-gradient(135deg, #2563EB, #4F46E5);
  box-shadow: 0 6px 14px rgba(37, 99, 235, 0.25);
  font-size: 15px;
  font-weight: 800;
}

.app-title {
  min-width: 0;
}

.page {
  min-height: calc(100vh - 65px);
  background: var(--sk-page-bg);
}

.page-content {
  width: min(100%, 1440px);
  margin: 0 auto;
  padding: clamp(18px, 3vw, 32px) clamp(16px, 4vw, 40px) 56px;
}

@media (max-width: 640px) {
  .app-header {
    align-items: flex-start;
  }

  .app-title .sub {
    display: block;
    margin-top: 2px;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-end;
  }
}
</style>
