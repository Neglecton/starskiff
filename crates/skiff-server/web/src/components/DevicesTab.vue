<script setup>
import { computed, h, inject, onMounted, ref } from 'vue';
import { NButton, NInput, NTag, useDialog, useMessage } from 'naive-ui';
import { useI18n } from 'vue-i18n';
import { api, fmtTime } from '../api';

const { t } = useI18n();
const message = useMessage();
const dialog = useDialog();
const registerLoader = inject('registerLoader');

const rows = ref([]);
const loading = ref(false);
const savingIp = ref(null); // `${devId}:${netId}` while an IP save is in flight

function mono(text) {
  return h('span', { class: 'mono' }, text);
}

function membershipCell(row) {
  if (!row.networks?.length) {
    return h('span', { style: 'opacity: .55' }, t('devices.noNetwork'));
  }
  return row.networks.map((m) =>
    h('div', { class: 'member-cell', key: m.networkId }, [
      h(NTag, { size: 'small', bordered: false, type: 'info' }, { default: () => mono(m.ip) }),
      h('span', { style: 'opacity: .55; font-size: 12px' }, m.networkName),
      h(NInput, {
        size: 'tiny',
        placeholder: t('devices.changeIpPh'),
        style: 'width: 120px',
        defaultValue: m.ip,
        onUpdateValue: (v) => (m._newIp = v),
      }),
      h(
        NButton,
        {
          size: 'tiny',
          tertiary: true,
          type: 'primary',
          loading: savingIp.value === `${row.id}:${m.networkId}`,
          onClick: () => saveIp(row, m),
        },
        { default: () => t('devices.save') },
      ),
    ]),
  );
}

function pathsCell(row, nameById) {
  if (!row.paths?.length) {
    return h('span', { style: 'opacity: .55' }, t('common.dash'));
  }
  return row.paths.map((p) => {
    const direct = p.path.startsWith('Direct');
    return h('div', { class: 'path-cell', key: p.deviceId }, [
      h('span', { class: 'mono' }, nameById.get(p.deviceId) || p.deviceId),
      h('span', { class: ['path-dot', direct ? 'direct' : 'relay'] }),
      h('span', { style: 'opacity: .55; font-size: 12px' }, `${p.path} · ${direct ? t('devices.direct') : t('devices.relay')}`),
    ]);
  });
}

const columns = computed(() => {
  const nameById = new Map(rows.value.map((d) => [d.id, d.name]));
  return [
    {
      title: t('devices.status'),
      key: 'online',
      width: 90,
      render: (r) =>
        h(NTag, { size: 'small', type: r.online ? 'success' : 'default', bordered: false }, {
          default: () => (r.online ? t('devices.online') : t('devices.offline')),
        }),
    },
    { title: t('devices.name'), key: 'name', minWidth: 110 },
    { title: t('devices.id'), key: 'id', width: 150, render: (r) => h('span', { class: 'mono', style: 'opacity: .55' }, String(r.id)) },
    { title: t('devices.virtualIp'), key: 'networks', minWidth: 300, render: (r) => membershipCell(r) },
    {
      title: t('devices.config'),
      key: 'config',
      width: 110,
      render: (r) => {
        if (r.restartPending) {
          return h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => t('settings.restartPending') });
        }
        if (r.settingsRevision == null) return h('span', { style: 'opacity: .55' }, t('common.dash'));
        const applied = r.appliedRevision != null && r.appliedRevision >= r.settingsRevision;
        return h(
          NTag,
          { size: 'small', type: applied ? 'success' : 'info', bordered: false },
          { default: () => (applied ? `r${r.settingsRevision}` : `${r.appliedRevision ?? '—'}/${r.settingsRevision}`) },
        );
      },
    },
    { title: t('devices.paths'), key: 'paths', minWidth: 220, render: (r) => pathsCell(r, nameById) },
    {
      title: t('devices.lastSeen'),
      key: 'lastSeen',
      width: 160,
      render: (r) => h('span', { style: r.lastSeen ? '' : 'opacity: .55; font-size: 13px' }, r.lastSeen ? fmtTime(r.lastSeen) : t('devices.never')),
    },
    {
      title: t('devices.actions'),
      key: 'actions',
      width: 100,
      render: (r) =>
        h(
          NButton,
          { size: 'small', type: 'error', secondary: true, onClick: () => confirmRemove(r) },
          { default: () => t('devices.remove') },
        ),
    },
  ];
});

async function load() {
  loading.value = true;
  try {
    rows.value = await api('GET', '/admin/devices');
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

async function saveIp(row, m) {
  const ip = (m._newIp ?? m.ip).trim();
  savingIp.value = `${row.id}:${m.networkId}`;
  try {
    await api('POST', `/admin/networks/${m.networkId}/devices/${row.id}/ip`, { ip });
    message.success(t('devices.ipUpdated'));
    await load();
  } catch (e) {
    message.error(e.message);
  } finally {
    savingIp.value = null;
  }
}

function confirmRemove(row) {
  dialog.warning({
    title: t('devices.confirmRemoveTitle'),
    content: t('devices.confirmRemove'),
    positiveText: t('common.ok'),
    negativeText: t('common.cancel'),
    onPositiveClick: async () => {
      try {
        await api('DELETE', `/admin/devices/${row.id}`);
        message.success(t('devices.removed'));
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
  <div class="panel-card">
    <n-data-table
      :columns="columns"
      :data="rows"
      :loading="loading"
      :row-key="(r) => r.id"
      size="small"
      :bordered="false"
      :scroll-x="1050"
    >
      <template #empty>
        <div class="table-empty">{{ $t('devices.empty') }}</div>
      </template>
    </n-data-table>
  </div>
</template>
