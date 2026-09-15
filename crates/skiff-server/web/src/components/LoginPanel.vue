<script setup>
import { onMounted, ref } from 'vue';
import { useMessage } from 'naive-ui';
import { api } from '../api';
import { store } from '../store';

const props = defineProps({ autoToken: { type: String, default: '' } });
const emit = defineEmits(['login']);

const message = useMessage();
const serverUrl = ref('');
const token = ref(props.autoToken);
const connecting = ref(false);

async function connect() {
  const t = token.value.trim();
  if (!t || connecting.value) return;
  connecting.value = true;
  // api() reads the shared store; install the candidate credentials to probe.
  store.token = t;
  store.base = serverUrl.value.trim().replace(/\/+$/, '');
  try {
    await api('GET', '/admin/summary');
    emit('login', { token: t, base: store.base });
  } catch (e) {
    message.error(e.message);
  } finally {
    connecting.value = false;
  }
}

onMounted(() => {
  if (props.autoToken) connect();
});
</script>

<template>
  <n-card class="login-card" :bordered="true" style="width: 400px; max-width: 92vw">
    <template #header>{{ $t('login.title') }}</template>
    <n-form label-placement="top" @submit.prevent="connect">
      <n-form-item :label="$t('login.serverUrl')">
        <n-input v-model:value="serverUrl" :placeholder="$t('login.serverUrlPh')" autocomplete="off" />
      </n-form-item>
      <n-form-item :label="$t('login.token')">
        <n-input
          v-model:value="token"
          type="password"
          show-password-on="click"
          :placeholder="$t('login.tokenPh')"
          @keyup.enter="connect"
        />
      </n-form-item>
      <n-button type="primary" block :loading="connecting" :disabled="!token.trim()" @click="connect">
        {{ connecting ? $t('login.connecting') : $t('login.connect') }}
      </n-button>
      <n-p depth="3" style="font-size: 12px; margin: 14px 0 0">
        {{ $t('login.hint') }}
      </n-p>
    </n-form>
  </n-card>
</template>

<style scoped>
.login-card {
  border-radius: 12px;
}
</style>
