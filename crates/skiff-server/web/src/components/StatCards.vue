<script setup>
import { inject, onMounted, ref } from 'vue';
import { useMessage } from 'naive-ui';
import { api } from '../api';

const message = useMessage();
const registerLoader = inject('registerLoader');
const summary = ref(null);

async function load() {
  try {
    summary.value = await api('GET', '/admin/summary');
  } catch (e) {
    message.error(e.message);
  }
}

registerLoader(load);
onMounted(load);
</script>

<template>
  <n-grid v-if="summary" :cols="'1 s:2 m:4'" responsive="screen" :x-gap="14" :y-gap="14" style="margin-bottom: 20px">
    <n-gi>
      <n-card size="small">
        <n-statistic :label="$t('summary.networks')" :value="summary.networks" />
      </n-card>
    </n-gi>
    <n-gi>
      <n-card size="small">
        <n-statistic :label="$t('summary.devices')" :value="summary.devices" />
      </n-card>
    </n-gi>
    <n-gi>
      <n-card size="small">
        <n-statistic :label="$t('summary.online')" :value="summary.online" />
      </n-card>
    </n-gi>
    <n-gi>
      <n-card size="small">
        <n-statistic :label="$t('summary.relay')">
          <span class="mono" style="font-size: 22px; font-weight: 600">
            {{ summary.relayUdpPort }} / {{ summary.relayTcpPort }}
          </span>
        </n-statistic>
      </n-card>
    </n-gi>
  </n-grid>
</template>
