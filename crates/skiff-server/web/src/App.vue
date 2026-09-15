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
    style="min-height: 100vh"
  >
    <n-message-provider placement="top">
      <n-dialog-provider>
        <div v-if="!store.connected" class="login-wrap" :class="{ dark: isDark }">
          <LoginPanel :auto-token="autoToken" @login="onLogin" />
        </div>
        <template v-else>
          <header
            class="app-header"
            :style="{
              '--sk-border': isDark ? '#2A3348' : '#E2E8F0',
              '--sk-header-bg': isDark ? '#101623' : '#FFFFFF',
              '--sk-header-fg': isDark ? '#F8FAFC' : '#1E293B',
            }"
          >
            <h1 class="app-title">
              Starskiff <span class="sub">{{ $t('app.subtitle') }}</span>
            </h1>
            <div class="header-actions">
              <n-button quaternary size="small" @click="setLang(store.lang === 'zh-CN' ? 'en-US' : 'zh-CN')">
                {{ store.lang === 'zh-CN' ? 'EN' : '中文' }}
              </n-button>
              <n-button quaternary size="small" :aria-label="isDark ? 'light mode' : 'dark mode'" @click="toggleTheme">
                <template #icon>
                  <NIcon><SunnyOutline v-if="isDark" /><MoonOutline v-else /></NIcon>
                </template>
              </n-button>
              <n-button secondary size="small" @click="logout">{{ $t('app.logout') }}</n-button>
            </div>
          </header>
          <main class="page" :style="{ background: isDark ? '#0C111C' : '#F8FAFC', minHeight: 'calc(100vh - 61px)' }">
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
          </main>
        </template>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style scoped>
.login-wrap {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #F8FAFC;
  padding: 16px;
}
.login-wrap.dark {
  background: #0C111C;
}
</style>
