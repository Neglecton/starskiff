import { createApp } from 'vue';
import naive from 'naive-ui';
import App from './App.vue';
import { i18n } from './i18n';
import './styles/global.css';

createApp(App).use(i18n).use(naive).mount('#app');
