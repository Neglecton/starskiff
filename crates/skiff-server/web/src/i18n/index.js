import { watch } from 'vue';
import { createI18n } from 'vue-i18n';
import { store } from '../store';
import zhCN from './locales/zh-CN';
import enUS from './locales/en-US';

export const i18n = createI18n({
  legacy: false,
  locale: store.lang,
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
    'en-US': enUS,
  },
});

// Language switches flow through the store (persisted); keep vue-i18n in
// sync so $t()/t() re-render alongside the Naive UI locale.
watch(
  () => store.lang,
  (lang) => {
    i18n.global.locale.value = lang;
    document.documentElement.lang = lang;
  },
  { immediate: true },
);
