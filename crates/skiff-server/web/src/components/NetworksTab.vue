<script setup>
import { computed, h, inject, onMounted, ref } from 'vue';
import { NButton, useDialog, useMessage } from 'naive-ui';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const { t } = useI18n();
const message = useMessage();
const dialog = useDialog();
const registerLoader = inject('registerLoader');
const refreshAll = inject('refreshAll');

const rows = ref([]);
const loading = ref(false);
const creating = ref(false);
const form = ref({ name: '', cidr: '' });

function mono(text) {
  return h('span', { class: 'mono' }, text);
}
function mutedMono(text) {
  return h('span', { class: 'mono', style: 'opacity: .55' }, text);
}

// Computed over t() so headers follow locale switches.
const columns = computed(() => [
  { title: t('networks.name'), key: 'name', minWidth: 120 },
  { title: t('networks.cidr'), key: 'cidr', width: 150, render: (r) => mono(r.cidr) },
  { title: t('networks.deviceCount'), key: 'deviceCount', width: 100 },
  { title: t('networks.id'), key: 'id', minWidth: 240, render: (r) => mutedMono(r.id) },
  {
    title: t('networks.actions'),
    key: 'actions',
    width: 100,
    render: (r) =>
      h(
        NButton,
        { size: 'small', type: 'error', secondary: true, onClick: () => confirmDelete(r) },
        { default: () => t('networks.delete') },
      ),
  },
]);

async function load() {
  loading.value = true;
  try {
    rows.value = await api('GET', '/admin/networks');
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

async function create() {
  if (!form.value.name.trim() || !form.value.cidr.trim() || creating.value) return;
  creating.value = true;
  try {
    await api('POST', '/admin/networks', { name: form.value.name.trim(), cidr: form.value.cidr.trim() });
    message.success(t('networks.created'));
    form.value = { name: '', cidr: '' };
    await refreshAll();
  } catch (e) {
    message.error(e.message);
  } finally {
    creating.value = false;
  }
}

function confirmDelete(row) {
  dialog.warning({
    title: t('networks.confirmDeleteTitle'),
    content: t('networks.confirmDelete'),
    positiveText: t('common.ok'),
    negativeText: t('common.cancel'),
    onPositiveClick: async () => {
      try {
        await api('DELETE', `/admin/networks/${row.id}`);
        message.success(t('networks.deleted'));
        await refreshAll();
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
  <div class="panel-card">
    <n-form class="form-toolbar" label-placement="top" @submit.prevent="create">
      <n-form-item class="form-field" :label="$t('networks.name')">
        <n-input v-model:value="form.name" :placeholder="$t('networks.namePh')" @keyup.enter="create" />
      </n-form-item>
      <n-form-item class="form-field" :label="$t('networks.cidr')">
        <n-input v-model:value="form.cidr" :placeholder="$t('networks.cidrPh')" @keyup.enter="create" />
      </n-form-item>
      <n-form-item class="form-action" label=" ">
        <n-button type="primary" :loading="creating" :disabled="!form.name.trim() || !form.cidr.trim()" @click="create">
          {{ creating ? $t('networks.creating') : $t('networks.create') }}
        </n-button>
      </n-form-item>
    </n-form>
    <n-data-table
      :columns="columns"
      :data="rows"
      :loading="loading"
      :row-key="(r) => r.id"
      size="small"
      :bordered="false"
    >
      <template #empty>
        <div class="table-empty">{{ $t('networks.empty') }}</div>
      </template>
    </n-data-table>
  </div>
</template>

<style scoped>
.form-field {
  width: min(100%, 230px);
}

.form-action {
  margin-left: auto;
}

@media (max-width: 640px) {
  .form-field,
  .form-action {
    width: 100%;
    margin-left: 0;
  }
}
</style>
