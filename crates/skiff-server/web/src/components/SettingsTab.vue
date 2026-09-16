<script setup>
import { computed, inject, onMounted, ref, watch } from 'vue';
import { useDialog, useMessage } from 'naive-ui';
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
// 网络成员管理：全部网络（join 下拉）与待提交的 join 参数。
const allNetworks = ref([]);
const joinNet = ref(null);
const joinIp = ref('');

// 托管开关：未勾选 = 该项沿用节点本地配置（PUT 时省略字段）。
const managed = ref({
  pathPolicy: false,
  peerPolicies: false,
  mode: false,
  listen: false,
  mtu: false,
  socks: false,
  forwards: false,
  exposes: {}, // networkId -> bool
});
const form = ref({
  pathPolicy: 'auto',
  peerPolicies: [], // { deviceId, policy }
  mode: 'proxy',
  listen: [], // URL 字符串列表
  mtu: 1300,
  socksEnabled: true,
  socksAddr: '127.0.0.1:1080',
  forwards: [], // { listen, proto, dest }
  exposes: {}, // networkId -> [{ port, proto, dest }]
});

const modeOptions = computed(() => [
  { value: 'proxy', label: t('settings.modeProxy') },
  { value: 'tun', label: t('settings.modeTun') },
]);

function addListen() {
  form.value.listen.push('udp://0.0.0.0:24933');
}

const deviceOptions = computed(() =>
  devices.value.map((d) => ({
    value: d.id,
    label: `${d.name} · ${d.online ? t('devices.online') : t('devices.offline')}`,
  })),
);
const current = computed(() => devices.value.find((d) => d.id === deviceId.value));

// 配置收敛状态：期望 revision（服务端） vs 节点心跳上报的已应用 revision。
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

// 路径策略六档（PathPolicy）与对端设备下拉（排除自己）。
const policyOptions = computed(() =>
  ['auto', 'relayUdp', 'relayTcp', 'directAny', 'directUdp', 'directTcp'].map((v) => ({
    value: v,
    label: t(`settings.policy.${v}`),
  })),
);
const peerDeviceOptions = computed(() =>
  devices.value.filter((d) => d.id !== deviceId.value).map((d) => ({ value: d.id, label: d.name })),
);
const nameOf = (id) => devices.value.find((d) => d.id === id)?.name || String(id);

function addPeerPolicy() {
  form.value.peerPolicies.push({ deviceId: null, policy: 'directTcp' });
}

// 可加入的网络 = 全部网络 - 已加入（按 id）。
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
    if (deviceId.value && !devices.value.some((d) => d.id === deviceId.value)) {
      deviceId.value = null;
    }
    allNetworks.value = await api('GET', '/admin/networks');
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

async function loadSettings() {
  if (!deviceId.value) return;
  loading.value = true;
  try {
    const s = await api('GET', `/admin/devices/${deviceId.value}/settings`);
    const m = {
      pathPolicy: false,
      peerPolicies: false,
      mtu: false,
      socks: false,
      forwards: false,
      exposes: {},
    };
    const f = { ...form.value, exposes: {}, peerPolicies: [], listen: [] };
    if (s.mode != null) {
      m.mode = true;
      f.mode = s.mode;
    }
    if (s.listen != null) {
      m.listen = true;
      f.listen = s.listen.map((x) => String(x));
    }
    if (s.pathPolicy != null) {
      m.pathPolicy = true;
      f.pathPolicy = s.pathPolicy;
    }
    if (s.peerPolicies != null) {
      m.peerPolicies = true;
      f.peerPolicies = s.peerPolicies.map((x) => ({ ...x }));
    }
    if (s.mtu != null) {
      m.mtu = true;
      f.mtu = s.mtu;
    }
    if (s.socksListen != null) {
      m.socks = true;
      f.socksEnabled = s.socksListen !== '';
      f.socksAddr = s.socksListen || '127.0.0.1:1080';
    }
    if (s.forwards != null) {
      m.forwards = true;
      f.forwards = s.forwards.map((x) => ({ ...x }));
    }
    for (const ne of s.exposes ?? []) {
      m.exposes[ne.networkId] = true;
      f.exposes[ne.networkId] = ne.rules.map((r) => ({ ...r }));
    }
    // 设备所属但未托管的网络初始化为空规则集。
    for (const net of networkList.value) {
      if (!(net.networkId in m.exposes)) {
        m.exposes[net.networkId] = false;
        f.exposes[net.networkId] = [];
      }
    }
    managed.value = m;
    form.value = f;
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

watch(deviceId, () => loadSettings());

function buildBody() {
  const body = {};
  if (managed.value.mode) body.mode = form.value.mode || 'proxy';
  if (managed.value.listen) {
    body.listen = form.value.listen.map((x) => String(x).trim()).filter(Boolean);
  }
  if (managed.value.pathPolicy) body.pathPolicy = form.value.pathPolicy || 'auto';
  if (managed.value.peerPolicies) {
    body.peerPolicies = form.value.peerPolicies
      .filter((p) => p.deviceId != null)
      .map((p) => ({ deviceId: p.deviceId, policy: p.policy || 'auto' }));
  }
  if (managed.value.mtu) body.mtu = Number(form.value.mtu);
  if (managed.value.socks) {
    body.socksListen = form.value.socksEnabled ? String(form.value.socksAddr).trim() : '';
  }
  if (managed.value.forwards) {
    body.forwards = form.value.forwards.map((x) => ({
      listen: String(x.listen).trim(),
      proto: x.proto || 'tcp',
      dest: String(x.dest).trim(),
    }));
  }
  const managedNets = Object.entries(managed.value.exposes).filter(([, on]) => on);
  if (managedNets.length) {
    body.exposes = managedNets.map(([netId]) => ({
      networkId: netId,
      rules: (form.value.exposes[netId] || []).map((r) => ({
        port: Number(r.port),
        proto: r.proto || 'tcp',
        dest: String(r.dest).trim(),
      })),
    }));
  }
  return body;
}

// 保存后短暂轮询设备列表，让收敛状态尽快反映出来。
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

// 需要提示对称设置的对端覆盖（非 auto 才有方向意义）。
function overridesNeedingReverse() {
  if (!managed.value.peerPolicies) return [];
  return form.value.peerPolicies.filter((p) => p.deviceId != null && p.policy && p.policy !== 'auto');
}

// 在对端设备上写入反向覆盖（peer → 本机），保留对端其它托管字段。
async function applyReverse(overrides) {
  const me = deviceId.value;
  for (const ov of overrides) {
    const target = await api('GET', `/admin/devices/${ov.deviceId}/settings`);
    const { revision: _rev, ...rest } = target;
    const list = (target.peerPolicies || []).filter((x) => x.deviceId !== me);
    list.push({ deviceId: me, policy: ov.policy });
    await api('PUT', `/admin/devices/${ov.deviceId}/settings`, { ...rest, peerPolicies: list });
  }
}

function save() {
  if (!deviceId.value) return;
  const overrides = overridesNeedingReverse();
  if (overrides.length) {
    dialog.warning({
      title: t('settings.reverseTitle'),
      content: t('settings.reversePrompt', { list: overrides.map((o) => nameOf(o.deviceId)).join(t('devices.separator')) }),
      positiveText: t('settings.reverseYes'),
      negativeText: t('settings.reverseNo'),
      onPositiveClick: () => doSave(overrides),
      onNegativeClick: () => {
        doSave([]);
      },
    });
  } else {
    doSave([]);
  }
}

/// 等待下发闭环：轮询 /admin/devices 直至节点确认（appliedRevision 追平）、
/// 失败（settingsErrorRevision 匹配，已自动回滚）或超时。
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

async function doSave(reverseList) {
  saving.value = true;
  try {
    const saved = await api('PUT', `/admin/devices/${deviceId.value}/settings`, buildBody());
    const rev = saved.revision;
    if (reverseList.length) {
      await applyReverse(reverseList);
    }
    // 下发闭环：等待节点应用确认 / 失败回滚 / 超时。
    const out = await waitApplyOutcome(rev);
    if (out.kind === 'ok') {
      let msg = t('settings.applyOk') + ` (r${out.applied})`;
      if (reverseList.length) msg += `；${t('settings.reverseDone')}`;
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

function addForward() {
  form.value.forwards.push({ listen: '127.0.0.1:0', proto: 'tcp', dest: '' });
}
function delForward(i) {
  form.value.forwards.splice(i, 1);
}
function addExpose(netId) {
  if (!form.value.exposes[netId]) form.value.exposes[netId] = [];
  form.value.exposes[netId].push({ port: null, proto: 'tcp', dest: '127.0.0.1:' });
}
function delExpose(netId, i) {
  form.value.exposes[netId].splice(i, 1);
}

registerLoader(load);
onMounted(load);
</script>

<template>
  <div class="settings-tab">
    <div class="toolbar">
      <n-select
        v-model:value="deviceId"
        :options="deviceOptions"
        :placeholder="t('settings.pickDevice')"
        filterable
        style="width: 280px"
      />
      <n-tag v-if="statusTag" :type="statusTag.type" size="small" :bordered="false">
        {{ statusTag.text }}
      </n-tag>
      <div class="spacer" />
      <n-button size="small" :loading="loading" @click="deviceId ? loadSettings() : load()">
        {{ t('topology.refresh') }}
      </n-button>
    </div>

    <n-alert v-if="deviceId" type="info" :show-icon="false" style="margin: 8px 0">
      {{ t('settings.emptyHint') }}
    </n-alert>

    <template v-if="deviceId">
      <!-- 网络成员管理（服务端权威） -->
      <n-card size="small" :title="t('settings.memberships')" style="margin-bottom: 12px">
        <div v-for="net in networkList" :key="net.networkId" class="field-row">
          <span class="mono">{{ net.networkName }}</span>
          <n-tag size="small" type="info" :bordered="false">{{ net.ip }}</n-tag>
          <div class="spacer" />
          <n-button
            size="tiny"
            quaternary
            type="error"
            :loading="acting"
            @click="leaveNetwork(net)"
          >
            {{ t('settings.leave') }}
          </n-button>
        </div>
        <div class="field-row">
          <n-select
            v-model:value="joinNet"
            :options="joinOptions"
            :placeholder="t('settings.pickNet')"
            filterable
            size="small"
            style="width: 260px"
          />
          <n-input
            v-model:value="joinIp"
            size="small"
            :placeholder="t('settings.joinIpPh')"
            style="width: 170px"
          />
          <n-button
            size="small"
            type="primary"
            secondary
            :disabled="!joinNet"
            :loading="acting"
            @click="joinNetwork"
          >
            {{ t('settings.join') }}
          </n-button>
        </div>
      </n-card>

      <!-- 热生效区 -->
      <n-card size="small" :title="t('settings.hotSection')" style="margin-bottom: 12px">
        <div class="field-row">
          <n-checkbox v-model:checked="managed.pathPolicy" />
          <n-select
            v-model:value="form.pathPolicy"
            :options="policyOptions"
            :disabled="!managed.pathPolicy"
            size="small"
            style="width: 230px"
          />
          <span class="hint">{{ t('settings.policyHint') }}</span>
        </div>
        <div class="field-row">
          <n-checkbox v-model:checked="managed.peerPolicies" />
          <span>{{ t('settings.peerPolicies') }}</span>
        </div>
        <template v-if="managed.peerPolicies">
          <div v-for="(pp, i) in form.peerPolicies" :key="i" class="rule-row">
            <n-select
              v-model:value="pp.deviceId"
              :options="peerDeviceOptions"
              :placeholder="t('settings.pickPeer')"
              filterable
              size="small"
              style="width: 220px"
            />
            <n-select v-model:value="pp.policy" :options="policyOptions" size="small" style="width: 210px" />
            <n-button size="tiny" quaternary type="error" @click="form.peerPolicies.splice(i, 1)">
              {{ t('settings.del') }}
            </n-button>
          </div>
          <n-button size="tiny" dashed @click="addPeerPolicy">{{ t('settings.addPeerPolicy') }}</n-button>
        </template>

        <div class="section-label">{{ t('settings.exposes') }}</div>
        <div v-for="net in networkList" :key="net.networkId" class="net-block">
          <div class="field-row">
            <n-checkbox v-model:checked="managed.exposes[net.networkId]" />
            <span class="mono">{{ t('settings.exposesFor', { net: net.networkName }) }}</span>
          </div>
          <template v-if="managed.exposes[net.networkId]">
            <div v-for="(rule, i) in form.exposes[net.networkId] || []" :key="i" class="rule-row">
              <n-input-number
                v-model:value="rule.port"
                size="tiny"
                :placeholder="t('settings.port')"
                :min="1"
                :max="65535"
                style="width: 110px"
              />
              <n-input v-model:value="rule.proto" size="tiny" style="width: 74px" />
              <n-input
                v-model:value="rule.dest"
                size="tiny"
                :placeholder="t('settings.dest')"
                style="width: 220px"
              />
              <n-button size="tiny" quaternary type="error" @click="delExpose(net.networkId, i)">
                {{ t('settings.del') }}
              </n-button>
            </div>
            <n-button size="tiny" dashed @click="addExpose(net.networkId)">
              {{ t('settings.addRule') }}
            </n-button>
          </template>
        </div>
        <div v-if="!networkList.length" style="opacity: .55">{{ t('devices.noNetwork') }}</div>
      </n-card>

      <!-- 重启生效区 -->
      <n-card size="small" :title="t('settings.restartSection')" style="margin-bottom: 12px">
        <div class="field-row">
          <n-checkbox v-model:checked="managed.mode" />
          <n-select
            v-model:value="form.mode"
            :options="modeOptions"
            :disabled="!managed.mode"
            size="small"
            style="width: 260px"
          />
          <span>{{ t('settings.mode') }}</span>
        </div>
        <div class="field-row">
          <n-checkbox v-model:checked="managed.listen" />
          <span>{{ t('settings.listen') }}</span>
        </div>
        <template v-if="managed.listen">
          <div v-for="(u, i) in form.listen" :key="i" class="rule-row">
            <n-input
              v-model:value="form.listen[i]"
              size="small"
              :placeholder="t('settings.listenPh')"
              style="width: 320px"
            />
            <n-button size="tiny" quaternary type="error" @click="form.listen.splice(i, 1)">
              {{ t('settings.del') }}
            </n-button>
          </div>
          <n-button size="tiny" dashed @click="addListen">{{ t('settings.addListen') }}</n-button>
        </template>
        <div class="field-row" style="margin-top: 8px">
          <span class="hint">{{ t('settings.restartNote') }}</span>
        </div>
        <div class="field-row">
          <n-checkbox v-model:checked="managed.socks" />
          <n-checkbox
            v-model:checked="form.socksEnabled"
            size="small"
            :disabled="!managed.socks"
          >
            {{ t('settings.socksEnabled') }}
          </n-checkbox>
          <span>{{ t('settings.socks') }}</span>
          <n-input
            v-model:value="form.socksAddr"
            size="tiny"
            :disabled="!managed.socks || !form.socksEnabled"
            :placeholder="t('settings.socksAddr')"
            style="width: 200px"
          />
        </div>
        <div class="field-row">
          <n-checkbox v-model:checked="managed.mtu" />
          <n-input-number
            v-model:value="form.mtu"
            size="tiny"
            :min="576"
            :max="65500"
            :disabled="!managed.mtu"
            style="width: 130px"
          />
          <span>{{ t('settings.mtu') }}</span>
        </div>

        <div class="section-label">{{ t('settings.forwards') }}</div>
        <div class="field-row">
          <n-checkbox v-model:checked="managed.forwards" />
        </div>
        <template v-if="managed.forwards">
          <div v-for="(f, i) in form.forwards" :key="i" class="rule-row">
            <n-input
              v-model:value="f.listen"
              size="tiny"
              :placeholder="t('settings.fwdListen')"
              style="width: 180px"
            />
            <n-input v-model:value="f.proto" size="tiny" style="width: 74px" />
            <n-input
              v-model:value="f.dest"
              size="tiny"
              :placeholder="t('settings.fwdDest')"
              style="width: 180px"
            />
            <n-button size="tiny" quaternary type="error" @click="delForward(i)">
              {{ t('settings.del') }}
            </n-button>
          </div>
          <n-button size="tiny" dashed @click="addForward">{{ t('settings.addRule') }}</n-button>
        </template>
      </n-card>

      <div class="toolbar">
        <n-button type="primary" :loading="saving" @click="save">{{ t('settings.save') }}</n-button>
        <n-button :loading="acting" @click="reconnect">{{ t('settings.reconnect') }}</n-button>
        <n-button type="warning" secondary :loading="acting" @click="restart">
          {{ t('settings.restart') }}
        </n-button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.settings-tab {
  width: min(100%, 900px);
}

.settings-tab :deep(.n-card) {
  border-color: var(--sk-border);
  background: var(--sk-surface);
}

.settings-tab .toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}

.toolbar .spacer { flex: 1; }

.field-row,
.rule-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin: 8px 0;
}

.field-row > .hint,
.rule-row > .hint {
  color: var(--sk-text-muted);
  font-size: 12px;
}

.section-label {
  margin: 18px 0 6px;
  color: var(--sk-text);
  font-size: 13px;
  font-weight: 700;
}

.net-block {
  padding: 6px 0 6px 12px;
  border-left: 2px solid var(--sk-border);
  margin: 8px 0;
}

.rule-row :deep(.n-input),
.rule-row :deep(.n-input-number),
.rule-row :deep(.n-select) {
  max-width: 100%;
}

@media (max-width: 640px) {
  .settings-tab .toolbar > :not(.spacer),
  .field-row > :not(.spacer),
  .rule-row > :not(.spacer) {
    max-width: 100%;
  }

  .settings-tab .toolbar > .n-select,
  .field-row > .n-select,
  .field-row > .n-input,
  .field-row > .n-input-number,
  .rule-row > .n-input,
  .rule-row > .n-input-number,
  .rule-row > .n-select {
    width: min(100%, 360px) !important;
  }

  .net-block {
    padding-left: 8px;
  }
}
</style>
