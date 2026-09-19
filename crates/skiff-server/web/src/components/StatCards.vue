<script setup>
import { inject, onMounted, ref } from 'vue';
import { NIcon } from 'naive-ui';
import { Ellipse, GitNetworkOutline, LinkOutline, ServerOutline } from '@vicons/ionicons5';
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
  <n-grid class="summary-grid" :cols="'1 s:2 m:4'" responsive="screen" :x-gap="14" :y-gap="14">
    <n-gi>
      <div class="stat-card">
        <span class="stat-icon"><NIcon size="22"><GitNetworkOutline /></NIcon></span>
        <div class="stat-body">
          <div class="stat-label">{{ $t('summary.networks') }}</div>
          <div class="stat-value">{{ summary ? summary.networks : '—' }}</div>
        </div>
      </div>
    </n-gi>
    <n-gi>
      <div class="stat-card">
        <span class="stat-icon"><NIcon size="22"><ServerOutline /></NIcon></span>
        <div class="stat-body">
          <div class="stat-label">{{ $t('summary.devices') }}</div>
          <div class="stat-value">{{ summary ? summary.devices : '—' }}</div>
        </div>
      </div>
    </n-gi>
    <n-gi>
      <div class="stat-card">
        <span class="stat-icon"><NIcon size="22"><Ellipse /></NIcon></span>
        <div class="stat-body">
          <div class="stat-label">{{ $t('summary.online') }}</div>
          <div class="stat-value">{{ summary ? summary.online : '—' }}</div>
        </div>
      </div>
    </n-gi>
    <n-gi>
      <div class="stat-card">
        <span class="stat-icon"><NIcon size="22"><LinkOutline /></NIcon></span>
        <div class="stat-body">
          <div class="stat-label">{{ $t('summary.relay') }}</div>
          <div v-if="summary" class="relay-row">
            <span class="proto-pill">{{ $t('summary.relayUdp') }}</span>
            <span class="stat-port">{{ summary.relayUdpPort }}</span>
            <span class="proto-pill">{{ $t('summary.relayTcp') }}</span>
            <span class="stat-port">{{ summary.relayTcpPort }}</span>
          </div>
          <div v-else class="stat-value">—</div>
        </div>
      </div>
    </n-gi>
  </n-grid>
</template>

<style scoped>
.summary-grid {
  margin-bottom: 18px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 14px;
  min-height: 88px;
  padding: 16px 18px;
  border: 1px solid var(--sk-border);
  border-radius: var(--sk-radius);
  background: var(--sk-surface);
}

.stat-icon {
  display: inline-grid;
  place-items: center;
  width: 40px;
  height: 40px;
  flex: none;
  color: var(--sk-text);
}

.stat-body {
  min-width: 0;
}

.stat-label {
  color: var(--sk-text-muted);
  font-size: 13px;
  line-height: 1.3;
}

.stat-value {
  margin-top: 2px;
  color: var(--sk-text);
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.15;
}

.relay-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 6px;
}

.stat-port {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.02em;
  font-family: Consolas, 'Cascadia Mono', ui-monospace, 'SF Mono', Menlo, monospace;
}
</style>
