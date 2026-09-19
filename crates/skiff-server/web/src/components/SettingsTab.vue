<script setup>
import { computed, inject, onMounted, ref, watch } from 'vue';
import { NIcon, useDialog, useMessage } from 'naive-ui';
import {
  ArrowForwardOutline,
  GitNetworkOutline,
  GlobeOutline,
  HardwareChipOutline,
  PowerOutline,
  RefreshOutline,
  SaveOutline,
  SettingsOutline,
  TrashOutline,
  WifiOutline,
} from '@vicons/ionicons5';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const { t } = useI18n();
const message = useMessage();
const dialog = useDialog();
const registerLoader = inject('registerLoader');

const devices = ref([]);
const deviceId = ref(null);
const loading = ref(false);
const saving = ref(false);
const acting = ref(false);
// memberships 的 IP 行内编辑草稿（networkId → 值）。独立于 devices 数据：
// pollStatus/load 重拉设备列表时未提交的输入不丢失。
const ipDrafts = ref({});
const allNetworks = ref([]);
const joinNet = ref(null);
const joinIp = ref('');
const draftListen = ref('udp://0.0.0.0:');
const draftForward = ref({ listen: '127.0.0.1:', proto: 'tcp', destHost: '', destPort: null });

// 全托管：无“是否托管”开关，保存即全量下发。未下发（null）字段在表单
// 中以编译期默认值呈现。
const DEFAULT_LISTEN = ['udp://0.0.0.0:24933', 'tcp://0.0.0.0:24933'];
// 保存确认弹窗：可取消；内嵌“同步对端反向策略”勾选（按对端覆盖入口）。
const showConfirm = ref(false);
const syncReverse = ref(false);
const form = ref({
  pathPolicy: 'auto',
  peerPolicies: [],
  mode: 'proxy',
  listen: [],
  mtu: 1300,
  socksEnabled: true,
  socksHost: '127.0.0.1',
  socksPort: 1080,
  forwardsEnabled: true,
  forwards: [],
  exposes: {},
});

const modeOptions = computed(() => [
  { value: 'proxy', label: t('settings.modeProxy') },
  { value: 'tun', label: t('settings.modeTun') },
]);

const protoOptions = computed(() => [
  { value: 'tcp', label: 'tcp' },
  { value: 'udp', label: 'udp' },
]);

function splitHostPort(raw) {
  const s = String(raw || '').trim();
  if (!s) return { host: '', port: null };
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end > 0) {
      const host = s.slice(0, end + 1);
      const rest = s.slice(end + 1);
      const port = rest.startsWith(':') ? Number(rest.slice(1)) : null;
      return { host, port: Number.isFinite(port) ? port : null };
    }
  }
  const i = s.lastIndexOf(':');
  if (i <= 0) return { host: s, port: null };
  const port = Number(s.slice(i + 1));
  return { host: s.slice(0, i), port: Number.isFinite(port) ? port : null };
}

function joinHostPort(host, port) {
  const h = String(host || '').trim();
  if (port == null || port === '') return h;
  return `${h}:${port}`;
}

const deviceOptions = computed(() =>
  devices.value.map((d) => ({
    value: d.id,
    label: `${d.name} · ${d.online ? t('devices.online') : t('devices.offline')}`,
  })),
);
const current = computed(() => devices.value.find((d) => d.id === deviceId.value));

const statusTag = computed(() => {
  const d = current.value;
  if (!d) return null;
  if (d.settingsError) {
    const rev = d.settingsErrorRevision != null ? ` · r${d.settingsErrorRevision}` : '';
    return { type: 'error', text: `${t('settings.applyFailed')}${rev}：${d.settingsError}` };
  }
  if (d.restartPending) return { type: 'warning', text: t('settings.restartPending') };
  if (d.settingsRevision == null) return { type: 'default', text: t('settings.unmanaged') };
  if (d.appliedRevision == null) return { type: 'info', text: `${t('settings.notReported')} · r${d.settingsRevision}` };
  if (d.appliedRevision < d.settingsRevision)
    return { type: 'info', text: `${t('settings.pending')} · ${d.appliedRevision}/${d.settingsRevision}` };
  return { type: 'success', text: `${t('settings.applied')} · r${d.settingsRevision}` };
});

const networkList = computed(() => current.value?.networks ?? []);
const cidrOf = (networkId) => allNetworks.value.find((n) => n.id === networkId)?.cidr || t('common.dash');

const policyOptions = computed(() =>
  ['auto', 'relayUdp', 'relayTcp', 'directAny', 'directUdp', 'directTcp'].map((v) => ({
    value: v,
    label: t(`settings.policy.${v}`),
  })),
);
const nameOf = (id) => devices.value.find((d) => d.id === id)?.name || String(id);

const joinOptions = computed(() => {
  const mine = new Set(networkList.value.map((n) => n.networkId));
  return allNetworks.value
    .filter((n) => !mine.has(n.id))
    .map((n) => ({ value: n.id, label: `${n.name} (${n.cidr})` }));
});

async function load() {
  loading.value = true;
  try {
    devices.value = await api('GET', '/admin/devices');
    allNetworks.value = await api('GET', '/admin/networks');
    if (deviceId.value && !devices.value.some((d) => d.id === deviceId.value)) {
      deviceId.value = null;
    }
    if (!deviceId.value && devices.value.length) {
      deviceId.value = devices.value[0].id;
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

async function joinNetwork() {
  if (!deviceId.value || !joinNet.value) return;
  acting.value = true;
  try {
    await api('POST', `/admin/devices/${deviceId.value}/networks`, {
      network: joinNet.value,
      requestedIp: joinIp.value.trim() || null,
    });
    message.success(t('settings.joined'));
    joinNet.value = null;
    joinIp.value = '';
    await load();
    pollStatus(2);
  } catch (e) {
    message.error(e.message);
  } finally {
    acting.value = false;
  }
}

function leaveNetwork(net) {
  if (!deviceId.value) return;
  dialog.warning({
    title: t('settings.leaveConfirmTitle'),
    content: t('settings.leaveConfirm', { net: net.networkName }),
    positiveText: t('common.ok'),
    negativeText: t('common.cancel'),
    onPositiveClick: async () => {
      acting.value = true;
      try {
        await api('DELETE', `/admin/devices/${deviceId.value}/networks/${net.networkId}`);
        message.success(t('settings.left'));
        await load();
        pollStatus(2);
      } catch (e) {
        message.error(e.message);
      } finally {
        acting.value = false;
      }
    },
  });
}

/// 修改已加入网络的节点 IP（IP 配置统一在本页；设备页仅展示）。
/// 409 冲突（IP 已被占用）等服务端中文错误经 e.message 直出。
function draftIpOf(net) {
  return (ipDrafts.value[net.networkId] ?? '').trim();
}

async function saveIp(net) {
  if (!deviceId.value || acting.value) return;
  const ip = draftIpOf(net);
  if (!ip || ip === net.ip) return;
  acting.value = true;
  try {
    await api('POST', `/admin/networks/${net.networkId}/devices/${deviceId.value}/ip`, { ip });
    message.success(t('settings.ipUpdated'));
    delete ipDrafts.value[net.networkId];
    await load();
    pollStatus(2);
  } catch (e) {
    message.error(e.message);
  } finally {
    acting.value = false;
  }
}

async function loadSettings() {
  if (!deviceId.value) return;
  loading.value = true;
  try {
    const s = await api('GET', `/admin/devices/${deviceId.value}/settings`);
    const f = {
      pathPolicy: 'auto',
      peerPolicies: [],
      mode: 'proxy',
      listen: [...DEFAULT_LISTEN],
      mtu: 1300,
      socksEnabled: true,
      socksHost: '127.0.0.1',
      socksPort: 1080,
      forwardsEnabled: false,
      forwards: [],
      exposes: {},
    };
    f.mode = s.mode || 'proxy';
    if (s.listen != null && s.listen.length) f.listen = s.listen.map((x) => String(x));
    if (s.pathPolicy != null) f.pathPolicy = s.pathPolicy;
    if (s.peerPolicies != null) f.peerPolicies = s.peerPolicies.map((x) => ({ ...x }));
    if (s.mtu != null) f.mtu = s.mtu;
    if (s.socksListen != null) {
      f.socksEnabled = s.socksListen !== '';
      const parsed = splitHostPort(s.socksListen || '127.0.0.1:1080');
      f.socksHost = parsed.host || '127.0.0.1';
      f.socksPort = parsed.port ?? 1080;
    }
    if (s.forwards != null) {
      f.forwardsEnabled = s.forwards.length > 0;
      f.forwards = s.forwards.map((x) => {
        const dest = splitHostPort(x.dest);
        return {
          listen: String(x.listen || ''),
          proto: x.proto || 'tcp',
          destHost: dest.host,
          destPort: dest.port,
        };
      });
    }
    const exposed = {};
    for (const ne of s.exposes ?? []) exposed[ne.networkId] = ne.rules.map((r) => ({ ...r }));
    for (const net of networkList.value) f.exposes[net.networkId] = exposed[net.networkId] ?? [];
    form.value = f;
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

watch(deviceId, (id) => {
  if (id) loadSettings();
});

function buildBody() {
  // 全托管：PUT 全量替换，恒提交全部字段（表单即真值）。
  return {
    mode: form.value.mode || 'proxy',
    listen: form.value.listen.map((x) => String(x).trim()).filter(Boolean),
    pathPolicy: form.value.pathPolicy || 'auto',
    // 按对端覆盖不在页面常驻：已存在的值原样写回，设置入口在保存弹窗
    // 的“同步对端反向”勾选。
    peerPolicies: form.value.peerPolicies
      .filter((p) => p.deviceId != null)
      .map((p) => ({ deviceId: p.deviceId, policy: p.policy || 'auto' })),
    mtu: Number(form.value.mtu),
    socksListen: form.value.socksEnabled
      ? joinHostPort(form.value.socksHost, form.value.socksPort)
      : '',
    forwards: form.value.forwardsEnabled
      ? form.value.forwards
          .map((x) => ({
            listen: String(x.listen).trim(),
            proto: x.proto || 'tcp',
            dest: joinHostPort(x.destHost, x.destPort),
          }))
          .filter((x) => x.listen && x.dest)
      : [],
    exposes: Object.entries(form.value.exposes).map(([netId]) => ({
      networkId: netId,
      rules: (form.value.exposes[netId] || []).map((r) => ({
        port: Number(r.port),
        proto: r.proto || 'tcp',
        dest: String(r.dest).trim(),
      })),
    })),
  };
}

async function pollStatus(times = 4) {
  for (let i = 0; i < times; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      devices.value = await api('GET', '/admin/devices');
    } catch {
      /* 状态轮询失败不打扰用户 */
    }
  }
}

// 其他设备（对端反向勾选的对象）。
const others = computed(() => devices.value.filter((d) => d.id !== deviceId.value));
const policyLabel = (v) => t(`settings.policy.${v || 'auto'}`);

// 对每个其他设备：把“指向本机”的出口策略覆盖设为 policy（auto = 清除）。
// 对端到其它节点的隧道不受影响（只动指向本机的条目）。
async function applyReverse(policy) {
  const me = deviceId.value;
  for (const d of others.value) {
    const target = await api('GET', `/admin/devices/${d.id}/settings`);
    const { revision: _rev, ...rest } = target;
    const list = (target.peerPolicies || []).filter((x) => x.deviceId !== me);
    if (policy !== 'auto') list.push({ deviceId: me, policy });
    await api('PUT', `/admin/devices/${d.id}/settings`, { ...rest, peerPolicies: list });
  }
}

function save() {
  if (!deviceId.value) return;
  syncReverse.value = false;
  showConfirm.value = true;
}

async function confirmSave() {
  showConfirm.value = false;
  await doSave(syncReverse.value);
}

async function waitApplyOutcome(rev, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1500));
    let d;
    try {
      const list = await api('GET', '/admin/devices');
      devices.value = list;
      d = list.find((x) => x.id === deviceId.value);
    } catch {
      continue;
    }
    if (!d) return { kind: 'timeout' };
    if (d.settingsErrorRevision != null && d.settingsErrorRevision >= rev) {
      return { kind: 'failed', error: d.settingsError || '?' };
    }
    if (d.appliedRevision != null && d.appliedRevision >= rev) {
      return { kind: 'ok', applied: d.appliedRevision };
    }
  }
  return { kind: 'timeout' };
}

async function doSave(syncReversePolicy) {
  saving.value = true;
  try {
    const saved = await api('PUT', `/admin/devices/${deviceId.value}/settings`, buildBody());
    const rev = saved.revision;
    if (syncReversePolicy) {
      await applyReverse(form.value.pathPolicy || 'auto');
    }
    const out = await waitApplyOutcome(rev);
    if (out.kind === 'ok') {
      let msg = t('settings.applyOk') + ` (r${out.applied})`;
      if (syncReversePolicy) msg += `；${t('settings.reverseDone')}`;
      message.success(msg);
    } else if (out.kind === 'failed') {
      message.error(`${t('settings.applyFailed')} (r${rev})：${out.error}`);
    } else {
      message.warning(`${t('settings.applyNoResp')} (r${rev})`);
    }
    pollStatus(2);
  } catch (e) {
    message.error(e.message);
  } finally {
    saving.value = false;
  }
}

async function reconnect() {
  if (!deviceId.value) return;
  acting.value = true;
  try {
    await api('POST', `/admin/devices/${deviceId.value}/reconnect`);
    message.success(t('settings.reconnectDone'));
  } catch (e) {
    message.error(e.message);
  } finally {
    acting.value = false;
  }
}

function restart() {
  if (!deviceId.value) return;
  dialog.warning({
    title: t('settings.restartConfirmTitle'),
    content: t('settings.restartConfirm'),
    positiveText: t('common.ok'),
    negativeText: t('common.cancel'),
    onPositiveClick: async () => {
      acting.value = true;
      try {
        await api('POST', `/admin/devices/${deviceId.value}/restart`);
        message.success(t('settings.restartDone'));
        pollStatus();
      } catch (e) {
        message.error(e.message);
      } finally {
        acting.value = false;
      }
    },
  });
}

function addListen() {
  const url = draftListen.value.trim();
  if (!url) return;
  form.value.listen.push(url);
  draftListen.value = 'udp://0.0.0.0:';
}

function addForward() {
  const d = draftForward.value;
  const dest = joinHostPort(d.destHost, d.destPort);
  if (!String(d.listen).trim() || !dest) return;
  form.value.forwards.push({
    listen: String(d.listen).trim(),
    proto: d.proto || 'tcp',
    destHost: d.destHost,
    destPort: d.destPort,
  });
  draftForward.value = { listen: '127.0.0.1:', proto: 'tcp', destHost: '', destPort: null };
}

function delForward(i) {
  form.value.forwards.splice(i, 1);
}

function refresh() {
  deviceId.value ? loadSettings() : load();
}

registerLoader(load);
onMounted(load);
</script>

<template>
  <div class="settings-tab">
    <div class="page-head">
      <h2 class="page-title">
        <NIcon size="20"><SettingsOutline /></NIcon>
        {{ t('settings.title') }}
      </h2>
      <div class="page-head-actions">
        <span class="current-label">{{ t('settings.currentNode') }}：</span>
        <n-select
          v-model:value="deviceId"
          :options="deviceOptions"
          :placeholder="t('settings.pickDevice')"
          filterable
          size="small"
          class="device-select"
        />
        <n-tag v-if="statusTag" :type="statusTag.type" size="small" :bordered="false">
          {{ statusTag.text }}
        </n-tag>
      </div>
    </div>

    <p v-if="!deviceId" class="empty-hint">{{ t('settings.pickDevice') }}</p>

    <template v-else>
      <section class="sec">
        <div class="sec-head">
          <div class="sec-title">
            <NIcon size="18"><GitNetworkOutline /></NIcon>
            {{ t('settings.memberships') }}
          </div>
        </div>
        <div class="sheet">
          <div class="sheet-head">
            <span>{{ t('settings.netName') }}</span>
            <span>{{ t('settings.netCidr') }}</span>
            <span>{{ t('settings.nodeIp') }}</span>
            <span>{{ t('networks.actions') }}</span>
          </div>
          <div v-for="net in networkList" :key="net.networkId" class="sheet-row">
            <span>{{ net.networkName }}</span>
            <span class="mono">{{ cidrOf(net.networkId) }}</span>
            <n-input
              size="small"
              :value="ipDrafts[net.networkId] ?? net.ip"
              :placeholder="t('settings.changeIpPh')"
              @update:value="(v) => (ipDrafts[net.networkId] = v)"
              @keyup.enter="saveIp(net)"
            />
            <span class="sheet-actions">
              <n-button
                size="tiny"
                tertiary
                type="primary"
                :disabled="!draftIpOf(net) || draftIpOf(net) === net.ip"
                :loading="acting"
                @click="saveIp(net)"
              >
                {{ t('settings.saveIp') }}
              </n-button>
              <n-button size="tiny" secondary :loading="acting" @click="leaveNetwork(net)">
                <template #icon><NIcon><TrashOutline /></NIcon></template>
                {{ t('settings.leave') }}
              </n-button>
            </span>
          </div>
          <div v-if="!networkList.length" class="sheet-empty">{{ t('devices.noNetwork') }}</div>
          <div class="join-row">
            <n-select
              v-model:value="joinNet"
              :options="joinOptions"
              :placeholder="t('settings.pickNet')"
              filterable
              size="small"
            />
            <n-input v-model:value="joinIp" size="small" :placeholder="t('settings.joinIpPh')" />
            <n-button size="small" type="primary" :disabled="!joinNet" :loading="acting" @click="joinNetwork">
              {{ t('settings.join') }}
            </n-button>
          </div>
        </div>
      </section>

      <div class="trio">
        <section class="sec">
          <div class="sec-head">
            <div class="sec-title">
              <NIcon size="18"><ArrowForwardOutline /></NIcon>
              {{ t('settings.egressPolicy') }}
            </div>
          </div>
          <n-select v-model:value="form.pathPolicy" :options="policyOptions" />
        </section>
        <section class="sec">
          <div class="sec-head">
            <div class="sec-title">
              <NIcon size="18"><SettingsOutline /></NIcon>
              {{ t('settings.mode') }}
              <n-tag size="tiny" :bordered="false" type="warning" class="restart-flag">
                {{ t('settings.restartSection') }}
              </n-tag>
            </div>
          </div>
          <n-select v-model:value="form.mode" :options="modeOptions" />
        </section>
        <section class="sec">
          <div class="sec-head">
            <div class="sec-title">
              <NIcon size="18"><HardwareChipOutline /></NIcon>
              {{ t('settings.mtu') }}
              <n-tag size="tiny" :bordered="false" type="warning" class="restart-flag">
                {{ t('settings.restartSection') }}
              </n-tag>
            </div>
          </div>
          <n-input-number v-model:value="form.mtu" :min="576" :max="65500" style="width: 100%" />
          <div class="sec-hint">{{ t('settings.mtuHint') }}</div>
        </section>
      </div>

      <div class="duo">
        <section class="sec">
          <div class="sec-head">
            <div class="sec-title">
              <NIcon size="18"><WifiOutline /></NIcon>
              {{ t('settings.listen') }}
              <n-tag size="tiny" :bordered="false" type="warning" class="restart-flag">
                {{ t('settings.restartSection') }}
              </n-tag>
            </div>
          </div>
          <div class="list-block">
            <div v-for="(u, i) in form.listen" :key="i" class="list-row">
              <n-input v-model:value="form.listen[i]" size="small" :placeholder="t('settings.listenPh')" />
              <n-button size="tiny" secondary @click="form.listen.splice(i, 1)">
                <template #icon><NIcon><TrashOutline /></NIcon></template>
                {{ t('settings.del') }}
              </n-button>
            </div>
            <div class="list-row">
              <n-input
                v-model:value="draftListen"
                size="small"
                :placeholder="t('settings.listenPh')"
                @keyup.enter="addListen"
              />
              <n-button size="small" type="primary" :disabled="!draftListen.trim()" @click="addListen">
                {{ t('settings.add') }}
              </n-button>
            </div>
          </div>
        </section>

        <section class="sec">
          <div class="sec-head">
            <div class="sec-title">
              <NIcon size="18"><GlobeOutline /></NIcon>
              {{ t('settings.socks') }}
              <n-tag size="tiny" :bordered="false" type="warning" class="restart-flag">
                {{ t('settings.restartSection') }}
              </n-tag>
            </div>
            <div class="sec-tools">
              <label class="enable-label">
                {{ t('settings.socksEnabled') }}
                <n-switch size="small" v-model:checked="form.socksEnabled" />
              </label>
            </div>
          </div>
          <div class="socks-grid">
            <div>
              <div class="field-label">{{ t('settings.socksHost') }}</div>
              <n-input v-model:value="form.socksHost" :disabled="!form.socksEnabled" />
            </div>
            <div>
              <div class="field-label">{{ t('settings.socksPort') }}</div>
              <n-input-number
                v-model:value="form.socksPort"
                :min="1"
                :max="65535"
                :disabled="!form.socksEnabled"
                style="width: 100%"
              />
            </div>
          </div>
        </section>
      </div>

      <section class="sec">
        <div class="sec-head">
          <div class="sec-title">
            <NIcon size="18"><GitNetworkOutline /></NIcon>
            {{ t('settings.forwards') }}
            <n-tag size="tiny" :bordered="false" type="warning" class="restart-flag">
              {{ t('settings.restartSection') }}
            </n-tag>
          </div>
          <div class="sec-tools">
            <label class="enable-label">
              {{ t('settings.fwdEnabled') }}
              <n-switch size="small" v-model:checked="form.forwardsEnabled" />
            </label>
          </div>
        </div>
        <div class="sheet fwd-sheet" :class="{ disabled: !form.forwardsEnabled }">
          <div class="sheet-head">
            <span>{{ t('settings.fwdListen') }}</span>
            <span>{{ t('settings.fwdProto') }}</span>
            <span>{{ t('settings.fwdDest') }}</span>
            <span>{{ t('settings.fwdDestPort') }}</span>
            <span>{{ t('networks.actions') }}</span>
          </div>
          <div v-for="(f, i) in form.forwards" :key="i" class="sheet-row">
            <n-input v-model:value="f.listen" size="small" :disabled="!form.forwardsEnabled" />
            <n-select
              v-model:value="f.proto"
              :options="protoOptions"
              size="small"
              :disabled="!form.forwardsEnabled"
            />
            <n-input v-model:value="f.destHost" size="small" :disabled="!form.forwardsEnabled" />
            <n-input-number
              v-model:value="f.destPort"
              size="small"
              :min="1"
              :max="65535"
              :disabled="!form.forwardsEnabled"
              style="width: 100%"
            />
            <span class="sheet-actions">
              <n-button size="tiny" secondary :disabled="!form.forwardsEnabled" @click="delForward(i)">
                <template #icon><NIcon><TrashOutline /></NIcon></template>
                {{ t('settings.del') }}
              </n-button>
            </span>
          </div>
          <div class="sheet-row">
            <n-input
              v-model:value="draftForward.listen"
              size="small"
              :placeholder="t('settings.fwdListen')"
              :disabled="!form.forwardsEnabled"
            />
            <n-select
              v-model:value="draftForward.proto"
              :options="protoOptions"
              size="small"
              :disabled="!form.forwardsEnabled"
            />
            <n-input
              v-model:value="draftForward.destHost"
              size="small"
              :placeholder="t('settings.fwdDestPh')"
              :disabled="!form.forwardsEnabled"
            />
            <n-input-number
              v-model:value="draftForward.destPort"
              size="small"
              :min="1"
              :max="65535"
              :placeholder="t('settings.fwdPortPh')"
              :disabled="!form.forwardsEnabled"
              style="width: 100%"
            />
            <span class="sheet-actions">
              <n-button
                size="small"
                type="primary"
                :disabled="!form.forwardsEnabled"
                @click="addForward"
              >
                {{ t('settings.add') }}
              </n-button>
            </span>
          </div>
        </div>
      </section>

      <div class="foot">
        <div class="foot-actions">
          <n-button type="primary" :loading="saving" @click="save">
            <template #icon><NIcon><SaveOutline /></NIcon></template>
            {{ t('settings.save') }}
          </n-button>
          <n-button secondary :loading="acting" @click="reconnect">
            <template #icon><NIcon><RefreshOutline /></NIcon></template>
            {{ t('settings.reconnect') }}
          </n-button>
          <n-button secondary :loading="acting" @click="restart">
            <template #icon><NIcon><PowerOutline /></NIcon></template>
            {{ t('settings.restart') }}
          </n-button>
          <n-button secondary :loading="loading" @click="refresh">
            <template #icon><NIcon><RefreshOutline /></NIcon></template>
            {{ t('topology.refresh') }}
          </n-button>
        </div>
      </div>
    </template>

    <!-- 保存确认弹窗：可取消；内嵌“同步对端反向”勾选（按对端覆盖的
         唯一入口——小功能不常驻配置页）。 -->
    <n-modal
      v-model:show="showConfirm"
      preset="card"
      :title="t('settings.confirmTitle')"
      :style="{ width: '480px', maxWidth: '92vw' }"
    >
      <p class="confirm-body">{{ t('settings.confirmBody', { device: current?.name ?? '' }) }}</p>
      <n-checkbox v-if="others.length" v-model:checked="syncReverse" class="confirm-check">
        {{ t('settings.syncReverse', { policy: policyLabel(form.pathPolicy) }) }}
      </n-checkbox>
      <template #footer>
        <div class="confirm-actions">
          <n-button size="small" @click="showConfirm = false">{{ t('common.cancel') }}</n-button>
          <n-button size="small" type="primary" :loading="saving" @click="confirmSave">
            {{ t('settings.confirmPush') }}
          </n-button>
        </div>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.restart-flag {
  margin-left: 8px;
}
.confirm-body {
  margin: 0 0 10px;
}
.confirm-check {
  display: flex;
}
.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
.settings-tab {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.page-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.page-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin: 0;
  font-size: 18px;
  font-weight: 700;
}

.page-head-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.current-label {
  color: var(--sk-text-muted);
  font-size: 13px;
}

.device-select {
  width: min(100%, 280px);
}

.empty-hint {
  margin: 8px 0 0;
  color: var(--sk-text-muted);
  font-size: 13px;
}

.sec {
  padding: 16px 18px 18px;
  border: 1px solid var(--sk-border);
  border-radius: var(--sk-radius);
  background: var(--sk-surface);
}

.sec-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.sec-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 700;
}

.sec-tools {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.enable-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--sk-text);
  font-size: 13px;
}

.sec-hint {
  margin-top: 8px;
  color: var(--sk-text-muted);
  font-size: 12px;
}

.trio,
.duo {
  display: grid;
  gap: 14px;
}

.trio {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.duo {
  grid-template-columns: 1.15fr 1fr;
}

.sheet {
  display: flex;
  flex-direction: column;
}

.sheet-head,
.sheet-row {
  display: grid;
  grid-template-columns: 1.2fr 1fr 1fr 150px;
  gap: 12px;
  align-items: center;
}

.fwd-sheet .sheet-head,
.fwd-sheet .sheet-row {
  grid-template-columns: 1.2fr 110px 1fr 110px 120px;
}

.sheet-head {
  padding: 0 4px 10px;
  color: var(--sk-text-muted);
  font-size: 12px;
}

.sheet-row {
  padding: 10px 4px;
  border-top: 1px solid var(--sk-border);
}

.sheet-empty {
  padding: 12px 4px;
  color: var(--sk-text-muted);
  font-size: 13px;
}

.sheet-actions {
  display: flex;
  justify-content: flex-end;
  gap: 6px;
}

.join-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 180px 88px;
  gap: 8px;
  align-items: center;
  padding: 12px 4px 0;
  border-top: 1px solid var(--sk-border);
}

.list-block {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.list-row {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  align-items: center;
}

.socks-grid {
  display: grid;
  grid-template-columns: 1fr 120px;
  gap: 12px;
}

.field-label {
  margin-bottom: 6px;
  color: var(--sk-text-muted);
  font-size: 12px;
}

.disabled {
  opacity: 0.55;
  pointer-events: none;
}

.foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.foot-note {
  margin: 0;
  max-width: 520px;
}

.foot-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-left: auto;
}

@media (max-width: 960px) {
  .trio,
  .duo,
  .socks-grid,
  .sheet-head,
  .sheet-row,
  .fwd-sheet .sheet-head,
  .fwd-sheet .sheet-row,
  .join-row {
    grid-template-columns: 1fr;
  }

  .sheet-head {
    display: none;
  }

  .sheet-actions {
    justify-content: flex-start;
  }
}
</style>
