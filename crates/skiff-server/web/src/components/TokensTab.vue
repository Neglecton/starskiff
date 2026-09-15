<script setup>
import { computed, h, inject, onMounted, ref } from 'vue';
import { NButton, NTag, useDialog, useMessage } from 'naive-ui';
import { useI18n } from 'vue-i18n';
import { api, fmtTime } from '../api';

const { t } = useI18n();
const message = useMessage();
const dialog = useDialog();
const registerLoader = inject('registerLoader');

const rows = ref([]);
const networks = ref([]);
const loading = ref(false);
const generating = ref(false);
const form = ref({ network: null, uses: 1, hours: 24, ip: '' });

// Detail modal state for the full (unmasked) token.
const detailToken = ref('');
const showDetail = ref(false);

/// Mask a token for table display: keep the prefix, the fingerprint head and
/// a short tail; the middle collapses to stars so long tokens never stretch
/// the column. e.g. "skk_Ab3…****…9f3c12" — click opens the full value.
function maskToken(token) {
  if (token.length <= 24) return token;
  const head = token.slice(0, 10);
  const tail = token.slice(-8);
  return `${head}****${tail}`;
}

function openDetail(token) {
  detailToken.value = token;
  showDetail.value = true;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    message.success(t('tokens.copied'));
  } catch {
    // Clipboard may be unavailable (insecure context); the modal still
    // shows the full value for manual selection.
  }
}

async function load() {
  loading.value = true;
  try {
    const [toks, nets] = await Promise.all([api('GET', '/admin/tokens'), api('GET', '/admin/networks')]);
    rows.value = toks;
    networks.value = nets.map((n) => ({ label: `${n.name} (${n.cidr})`, value: n.name }));
    if (form.value.network === null && networks.value.length) {
      form.value.network = networks.value[0].value;
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

const columns = computed(() => [
  {
    title: t('tokens.token'),
    key: 'token',
    minWidth: 180,
    render: (r) =>
      h(
        NButton,
        {
          text: true,
          type: 'primary',
          class: 'mono',
          title: t('tokens.showFull'),
          onClick: () => openDetail(r.token),
        },
        { default: () => maskToken(r.token) },
      ),
  },
  { title: t('tokens.network'), key: 'networkName', width: 140 },
  { title: t('tokens.uses'), key: 'usesLeft', width: 100 },
  { title: t('tokens.expires'), key: 'expiresAt', width: 170, render: (r) => fmtTime(r.expiresAt) },
  {
    title: t('tokens.requestedIp'),
    key: 'requestedIp',
    width: 130,
    render: (r) => h(NTag, { size: 'small', bordered: false }, { default: () => r.requestedIp || t('tokens.autoAssign') }),
  },
  {
    title: t('tokens.actions'),
    key: 'actions',
    width: 110,
    render: (r) =>
      h(
        NButton,
        {
          size: 'small',
          type: 'error',
          secondary: true,
          onClick: () => {
            detailToken.value = r.token;
            confirmRevoke(r);
          },
        },
        { default: () => t('tokens.revoke') },
      ),
  },
]);

async function generate() {
  if (!form.value.network || generating.value) return;
  generating.value = true;
  try {
    const created = await api('POST', '/admin/tokens', {
      network: form.value.network,
      uses: form.value.uses,
      expiresInHours: form.value.hours,
      requestedIp: form.value.ip.trim() || null,
    });
    message.success(t('tokens.generated'));
    if (created?.token) openDetail(created.token);
    await load();
  } catch (e) {
    message.error(e.message);
  } finally {
    generating.value = false;
  }
}

function confirmRevoke(row) {
  dialog.warning({
    title: t('tokens.confirmRevokeTitle'),
    content: t('tokens.confirmRevoke'),
    positiveText: t('common.ok'),
    negativeText: t('common.cancel'),
    onPositiveClick: async () => {
      try {
        await api('DELETE', `/admin/tokens/${encodeURIComponent(row.token)}`);
        message.success(t('tokens.revoked'));
        showDetail.value = false;
        await load();
      } catch (e) {
        message.error(e.message);
      }
    },
  });
}

registerLoader(load);
onMounted(load);
</script>

<template>
  <div>
    <n-form inline label-placement="top" style="margin-bottom: 14px" @submit.prevent="generate">
      <n-form-item :label="$t('tabs.networks')">
        <n-select v-model:value="form.network" :options="networks" style="width: 200px" />
      </n-form-item>
      <n-form-item :label="$t('tokens.usesLabel')">
        <n-input-number v-model:value="form.uses" :min="1" :max="1000" style="width: 110px" />
      </n-form-item>
      <n-form-item :label="$t('tokens.hoursLabel')">
        <n-input-number v-model:value="form.hours" :min="1" :max="8760" style="width: 110px" />
      </n-form-item>
      <n-form-item :label="$t('tokens.ipLabel')">
        <n-input v-model:value="form.ip" :placeholder="$t('tokens.ipPh')" style="width: 140px" @keyup.enter="generate" />
      </n-form-item>
      <n-form-item label=" ">
        <n-button type="primary" :loading="generating" :disabled="!form.network" @click="generate">
          {{ generating ? $t('tokens.generating') : $t('tokens.generate') }}
        </n-button>
      </n-form-item>
    </n-form>
    <n-data-table
      :columns="columns"
      :data="rows"
      :loading="loading"
      :row-key="(r) => r.token"
      size="small"
      :bordered="false"
    />

    <n-modal
      v-model:show="showDetail"
      preset="card"
      :title="$t('tokens.token')"
      class="token-modal"
      :bordered="false"
      size="small"
      style="width: 560px; max-width: 92vw"
    >
      <n-p class="mono token-full" style="word-break: break-all; user-select: all; margin: 0 0 14px">
        {{ detailToken }}
      </n-p>
      <n-space>
        <n-button type="primary" size="small" @click="copyText(detailToken)">
          {{ $t('tokens.copy') }}
        </n-button>
        <n-button size="small" quaternary @click="showDetail = false">
          {{ $t('common.cancel') }}
        </n-button>
      </n-space>
    </n-modal>
  </div>
</template>
