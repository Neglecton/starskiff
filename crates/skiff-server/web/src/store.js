import { reactive } from 'vue';

const LS_TOKEN = 'starskiff_admin_token';
const LS_LANG = 'starskiff_admin_lang';
const LS_THEME = 'starskiff_admin_theme';

function initialLang() {
  const saved = localStorage.getItem(LS_LANG);
  if (saved === 'zh-CN' || saved === 'en-US') return saved;
  return (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
}

function initialTheme() {
  const saved = localStorage.getItem(LS_THEME);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export const store = reactive({
  token: localStorage.getItem(LS_TOKEN) || '',
  base: '',
  connected: false,
  lang: initialLang(),
  theme: initialTheme(),
});

export function saveToken(token) {
  store.token = token;
  if (token) localStorage.setItem(LS_TOKEN, token);
  else localStorage.removeItem(LS_TOKEN);
}

export function setLang(lang) {
  store.lang = lang;
  localStorage.setItem(LS_LANG, lang);
}

export function toggleTheme() {
  store.theme = store.theme === 'light' ? 'dark' : 'light';
  localStorage.setItem(LS_THEME, store.theme);
}
