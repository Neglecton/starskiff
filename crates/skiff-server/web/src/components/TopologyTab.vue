<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { NButton, NSwitch, NTag, useMessage } from 'naive-ui';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const { t } = useI18n();
const message = useMessage();

const POLL_MS = 5000;

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const devices = ref([]);
const loading = ref(false);
const autoRefresh = ref(true);
const lastUpdated = ref(null);
let pollTimer = null;

async function load() {
  loading.value = true;
  try {
    devices.value = await api('GET', '/admin/devices');
    lastUpdated.value = new Date();
    rebuildGraph();
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

// ---------------------------------------------------------------------------
// Graph model: nodes (devices + the relay server) and undirected edges
// aggregated from per-device directed path reports.
// ---------------------------------------------------------------------------

const NODE_R = 20;

const simNodes = reactive([]); // { id, name, ip, online, x, y, vx, vy, fixed, isServer }
const edges = ref([]); // { aId, bId, path, rtt, oneSided, aReport, bReport }

const selectedId = ref(null);

function pathRank(p) {
  if (p.startsWith('DirectUdp')) return 0;
  if (p.startsWith('DirectTcp')) return 1;
  if (p.startsWith('RelayTcp')) return 2;
  return 3; // RelayUdp / 其它
}

function edgeStyle(path) {
  if (path.startsWith('DirectUdp')) return { stroke: 'var(--sk-direct-udp)', dash: '' };
  if (path.startsWith('DirectTcp')) return { stroke: 'var(--sk-direct-tcp)', dash: '' };
  if (path.startsWith('RelayTcp')) return { stroke: 'var(--sk-relay-tcp)', dash: '6 4' };
  return { stroke: 'var(--sk-relay-udp)', dash: '6 4' }; // RelayUdp
}

function rebuildGraph() {
  const byId = new Map(devices.value.map((d) => [d.id, d]));
  // Keep existing positions for stable refreshes.
  const prev = new Map(simNodes.map((n) => [n.id, n]));
  simNodes.length = 0;
  simNodes.push({
    id: 'server',
    name: t('topology.server'),
    ip: '',
    online: true,
    isServer: true,
    fixed: true,
    x: prev.get('server')?.x ?? 0,
    y: prev.get('server')?.y ?? 0,
    vx: 0,
    vy: 0,
  });
  for (const d of devices.value) {
    const p = prev.get(d.id);
    const angle = Math.random() * Math.PI * 2;
    simNodes.push({
      id: d.id,
      name: d.name,
      ip: d.networks?.[0]?.ip || '',
      online: d.online,
      isServer: false,
      fixed: false,
      x: p?.x ?? Math.cos(angle) * 160,
      y: p?.y ?? Math.sin(angle) * 160,
      vx: 0,
      vy: 0,
    });
  }

  // Aggregate directed reports into undirected edges keyed by min-max id.
  // Stale reports from OFFLINE devices are skipped (their cached paths no
  // longer describe live traffic), and an edge only exists while BOTH
  // endpoints are online — an offline peer has no live path by definition.
  const map = new Map();
  for (const d of devices.value) {
    if (!d.online) continue;
    for (const rep of d.paths || []) {
      if (!byId.has(rep.deviceId) || rep.deviceId === d.id) continue;
      if (!byId.get(rep.deviceId).online) continue;
      const key = d.id < rep.deviceId ? `${d.id}:${rep.deviceId}` : `${rep.deviceId}:${d.id}`;
      const entry = map.get(key) || { a: null, b: null };
      if (d.id < rep.deviceId) entry.a = rep;
      else entry.b = rep;
      map.set(key, entry);
    }
  }
  const out = [];
  for (const [key, { a, b }] of map) {
    const [aId, bId] = key.split(':');
    const reports = [a, b].filter(Boolean);
    if (!reports.length) continue;
    // Prefer the report with the best (direct-first) path; diverging
    // directions stay visible via tooltip.
    const best = reports.reduce((m, r) => (pathRank(r.path) < pathRank(m.path) ? r : m));
    const relay = !best.path.startsWith('Direct');
    out.push({
      aId,
      bId,
      path: best.path,
      rtt: reports.find((r) => typeof r.rttMs === 'number')?.rttMs ?? null,
      oneSided: !a || !b,
      diverged: a && b && a.path !== b.path,
      aReport: a,
      bReport: b,
      isRelay: relay,
    });
  }
  edges.value = out;
  heat = 160; // re-run the simulation a while after data changes
}

// ---------------------------------------------------------------------------
// Force simulation: server pinned at (0,0); springs along edges; pairwise
// repulsion; light centripetal pull; velocity damping.
// ---------------------------------------------------------------------------

let heat = 0;
let simTimer = null;

function stepSim() {
  if (heat <= 0) return;
  const nodes = simNodes;
  const n = nodes.length;
  // Repulsion (O(n^2), fine for tens of nodes).
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { d2 = 1; dx = 1; }
      const f = 5200 / d2;
      const d = Math.sqrt(d2);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx -= fx; a.vy -= fy;
      b.vx += fx; b.vy += fy;
    }
  }
  // Springs along edges (relay edges pull each reporter towards the server).
  const nodeById = new Map(nodes.map((x) => [x.id, x]));
  const springPairs = [];
  for (const e of edges.value) {
    if (e.isRelay) {
      if (e.aReport) springPairs.push([e.aId, 'server']);
      if (e.bReport) springPairs.push([e.bId, 'server']);
    } else {
      springPairs.push([e.aId, e.bId]);
    }
  }
  for (const [aid, bid] of springPairs) {
    const a = nodeById.get(aid), b = nodeById.get(bid);
    if (!a || !b || a === b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
    const rest = 150;
    const f = (d - rest) * 0.012;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.vx += fx; a.vy += fy;
    b.vx -= fx; b.vy -= fy;
  }
  // Integrate with damping + centripetal pull; skip fixed (server) nodes.
  for (const node of nodes) {
    if (node.fixed) continue;
    node.vx += -node.x * 0.0008;
    node.vy += -node.y * 0.0008;
    node.vx *= 0.85; node.vy *= 0.85;
    node.x += node.vx;
    node.y += node.vy;
  }
  heat -= 1;
}

// ---------------------------------------------------------------------------
// Pan / zoom / drag interactions over the SVG viewport.
// ---------------------------------------------------------------------------

const view = reactive({ x: 0, y: 0, k: 1 });
const svgEl = ref(null);
const W = 900, H = 560;

function svgPoint(evt) {
  const rect = svgEl.value.getBoundingClientRect();
  return {
    x: ((evt.clientX - rect.left) / rect.width) * W,
    y: ((evt.clientY - rect.top) / rect.height) * H,
  };
}

let draggingNode = null;
let panning = null;

function onNodeDown(node, evt) {
  draggingNode = node;
  evt.stopPropagation();
}

function onSvgDown(evt) {
  panning = { sx: evt.clientX, sy: evt.clientY, vx: view.x, vy: view.y };
  selectedId.value = null;
}

function onSvgMove(evt) {
  if (draggingNode) {
    const p = svgPoint(evt);
    draggingNode.x = (p.x - W / 2 - view.x) / view.k;
    draggingNode.y = (p.y - H / 2 - view.y) / view.k;
    draggingNode.vx = 0; draggingNode.vy = 0;
    heat = Math.max(heat, 60);
  } else if (panning) {
    const rect = svgEl.value.getBoundingClientRect();
    view.x = panning.vx + ((evt.clientX - panning.sx) / rect.width) * W;
    view.y = panning.vy + ((evt.clientY - panning.sy) / rect.height) * H;
  }
}

function onSvgUp() {
  draggingNode = null;
  panning = null;
}

function onWheel(evt) {
  const factor = evt.deltaY < 0 ? 1.12 : 0.89;
  const nk = Math.min(3, Math.max(0.35, view.k * factor));
  // Zoom towards the cursor.
  const rect = svgEl.value.getBoundingClientRect();
  const cx = ((evt.clientX - rect.left) / rect.width) * W - W / 2;
  const cy = ((evt.clientY - rect.top) / rect.height) * H - H / 2;
  view.x = cx - ((cx - view.x) * nk) / view.k;
  view.y = cy - ((cy - view.y) * nk) / view.k;
  view.k = nk;
}

function focusNode(id) {
  selectedId.value = selectedId.value === id ? null : id;
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

const nodeById = computed(() => new Map(simNodes.map((n) => [n.id, n])));

const renderEdges = computed(() => {
  const server = nodeById.value.get('server');
  if (!server) return [];
  const out = [];
  for (const e of edges.value) {
    const style = edgeStyle(e.path);
    const common = {
      rtt: e.rtt,
      opacity: 1,
      width: 1.8,
      label: e.rtt !== null ? `${e.rtt}ms` : '',
      tip: edgeTooltip(e),
      ...style,
    };
    if (e.isRelay) {
      // A relayed path means each reporting side talks to the relay: draw
      // one line per online reporter to the server node (the true traffic
      // shape — never a line from a non-reporting/offline endpoint).
      for (const [rep, reporterId] of [
        [e.aReport, e.aId],
        [e.bReport, e.bId],
      ]) {
        if (!rep) continue;
        const n = nodeById.value.get(reporterId);
        if (!n || !n.online) continue;
        applyFocus(out, e, {
          key: `e${e.aId}-${e.bId}-${reporterId}`,
          x1: n.x, y1: n.y, x2: server.x, y2: server.y,
          mx: (n.x + server.x) / 2, my: (n.y + server.y) / 2,
          reporterId,
          ...common,
        });
      }
    } else {
      const a = nodeById.value.get(e.aId);
      const b = nodeById.value.get(e.bId);
      if (!a || !b) continue;
      applyFocus(out, e, {
        key: `e${e.aId}-${e.bId}`,
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
        mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2,
        ...common,
      });
    }
  }
  return out;
});

// Dim non-adjacent edges in focus mode (mutates the render entry in place).
function applyFocus(sink, edge, entry) {
  const adjacent =
    edge.aId === selectedId.value || edge.bId === selectedId.value;
  if (selectedId.value !== null) {
    entry.opacity = adjacent ? 1 : 0.12;
    entry.width = adjacent ? 3 : 1.8;
    if (!adjacent) entry.label = '';
  } else if (edge.oneSided) {
    entry.opacity = 0.45;
  }
  sink.push(entry);
}

function edgeTooltip(e) {
  const nameOf = (id) => nodeById.value.get(id)?.name || id;
  const fmt = (r) =>
    r ? `${r.path}${typeof r.rttMs === 'number' ? ` · ${r.rttMs}ms` : ''}` : t('topology.noReport');
  return `${nameOf(e.aId)} → ${nameOf(e.bId)}: ${fmt(e.aReport)}\n${nameOf(e.bId)} → ${nameOf(e.aId)}: ${fmt(e.bReport)}`;
}

function nodeTooltip(n) {
  return n.isServer ? n.name : `${n.name} · ${n.ip || '?'} · ${n.online ? t('devices.online') : t('devices.offline')}`;
}

// Node focus side panel rows.
const focusRows = computed(() => {
  if (selectedId.value === null) return [];
  const me = nodeById.value.get(selectedId.value);
  const rows = [];
  for (const e of edges.value) {
    if (e.aId !== selectedId.value && e.bId !== selectedId.value) continue;
    const otherId = e.aId === selectedId.value ? e.bId : e.aId;
    const other = nodeById.value.get(otherId);
    rows.push({
      name: other?.name || String(otherId),
      ip: other?.ip || '',
      path: e.path,
      rtt: e.rtt,
      online: other?.online,
    });
  }
  rows.sort((x, y) => (x.rtt ?? 1e9) - (y.rtt ?? 1e9));
  return rows;
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

function restartPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = autoRefresh.value ? setInterval(load, POLL_MS) : null;
}

onMounted(() => {
  load();
  restartPolling();
  simTimer = setInterval(() => {
    stepSim();
  }, 30);
});

onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer);
  if (simTimer) clearInterval(simTimer);
});
</script>

<template>
  <div class="topo">
    <div class="topo-toolbar">
      <span class="muted" style="font-size: 13px">
        {{ lastUpdated ? `${t('topology.lastUpdated')} ${lastUpdated.toLocaleTimeString()}` : '' }}
      </span>
      <div class="topo-legend">
        <span class="lg"><i class="sw direct-udp" />{{ t('topology.directUdp') }}</span>
        <span class="lg"><i class="sw direct-tcp" />{{ t('topology.directTcp') }}</span>
        <span class="lg"><i class="sw relay-udp dashed" />{{ t('topology.relay') }}</span>
        <span class="lg"><i class="sw offline" />{{ t('devices.offline') }}</span>
      </div>
      <div style="display: flex; align-items: center; gap: 10px">
        <label class="muted refresh-control">
          <span>{{ t('topology.autoRefresh') }}</span>
          <n-switch size="small" :value="autoRefresh" @update:value="autoRefresh = $event; restartPolling()" />
        </label>
        <n-button size="small" :loading="loading" @click="load">{{ t('topology.refresh') }}</n-button>
      </div>
    </div>

    <div class="topo-body">
      <svg
        ref="svgEl"
        :viewBox="`0 0 ${W} ${H}`"
        class="topo-svg"
        role="img"
        :aria-label="t('topology.graphLabel')"
        tabindex="0"
        @pointerdown="onSvgDown"
        @pointermove="onSvgMove"
        @pointerup="onSvgUp"
        @pointerleave="onSvgUp"
        @wheel.prevent="onWheel"
      >
        <g :transform="`translate(${W / 2 + view.x} ${H / 2 + view.y}) scale(${view.k})`">
          <!-- edges -->
          <line
            v-for="e in renderEdges"
            :key="e.key"
            :x1="e.x1" :y1="e.y1" :x2="e.x2" :y2="e.y2"
            :stroke="e.stroke"
            :stroke-width="e.width"
            :stroke-dasharray="e.dash"
            :opacity="e.opacity"
          >
            <title>{{ e.tip }}</title>
          </line>
          <!-- edge rtt labels -->
          <text
            v-for="e in renderEdges"
            :key="'l' + e.key"
            :x="e.mx" :y="e.my - 4"
            class="rtt-label"
            :opacity="e.opacity"
          >{{ e.label }}</text>
          <!-- nodes -->
          <g
            v-for="n in simNodes"
            :key="n.id"
            :transform="`translate(${n.x} ${n.y})`"
            class="topo-node"
            :class="{ selected: selectedId === n.id, dimmed: selectedId !== null && selectedId !== n.id }"
            @pointerdown="onNodeDown(n, $event)"
            @click.stop="focusNode(n.id)"
          >
            <title>{{ nodeTooltip(n) }}</title>
            <circle
              :r="n.isServer ? 26 : NODE_R"
              :fill="n.isServer ? 'var(--sk-brand)' : n.online ? 'var(--sk-direct-udp)' : 'var(--sk-offline)'"
              fill-opacity="0.15"
              :stroke="n.isServer ? 'var(--sk-brand)' : n.online ? 'var(--sk-direct-udp)' : 'var(--sk-offline)'"
              stroke-width="2"
            />
            <text class="node-glyph" dy="4" text-anchor="middle">{{ n.isServer ? 'S' : n.name.slice(0, 2).toUpperCase() }}</text>
            <text class="node-name" :y="(n.isServer ? 26 : NODE_R) + 14" text-anchor="middle">{{ n.name }}</text>
          </g>
        </g>
      </svg>

      <!-- focus panel: the selected node's view of the mesh -->
      <div v-if="selectedId !== null" class="topo-panel">
        <div class="topo-panel-title">
          {{ nodeById.get(selectedId)?.name }} — {{ t('topology.focusTitle') }}
        </div>
        <div v-for="(row, i) in focusRows" :key="i" class="topo-panel-row">
          <span class="dot" :class="row.online ? 'on' : 'off'" />
          <span class="mono" style="min-width: 90px">{{ row.name }}</span>
          <span class="mono muted" style="min-width: 90px">{{ row.ip }}</span>
          <n-tag size="small" :bordered="false" :type="row.path.startsWith('Direct') ? 'success' : 'warning'">
            {{ row.path }}
          </n-tag>
          <span class="mono muted" style="margin-left: auto">{{ row.rtt !== null ? row.rtt + 'ms' : '—' }}</span>
        </div>
        <div v-if="!focusRows.length" class="muted" style="padding: 8px 2px">{{ t('topology.noPaths') }}</div>
      </div>
    </div>
    <div class="muted topo-hint">{{ t('topology.hint') }}</div>
  </div>
</template>

<style scoped>
.topo {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.topo-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.topo-toolbar > * {
  min-width: 0;
}

.topo-legend {
  display: flex;
  gap: 14px;
  color: var(--sk-text-muted);
  font-size: 12px;
  flex-wrap: wrap;
}

.topo-legend .lg,
.refresh-control {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.topo-legend .sw {
  display: inline-block;
  width: 18px;
  height: 3px;
  border-radius: 2px;
}

.topo-legend .sw.direct-udp { background: var(--sk-direct-udp); }
.topo-legend .sw.direct-tcp { background: var(--sk-direct-tcp); }
.topo-legend .sw.offline { background: var(--sk-offline); }
.topo-legend .sw.relay-udp {
  background: linear-gradient(90deg, var(--sk-relay-udp) 55%, transparent 45%);
  background-size: 8px 3px;
}

.topo-body {
  position: relative;
  border: 1px solid var(--sk-border);
  border-radius: var(--sk-radius);
  background:
    radial-gradient(circle at 1px 1px, var(--sk-topology-grid) 1px, transparent 0) 0 0 / 22px 22px,
    var(--sk-surface);
  overflow: hidden;
}

.topo-svg {
  width: 100%;
  height: clamp(400px, 58vw, 560px);
  display: block;
  color: var(--sk-text);
  cursor: grab;
  touch-action: none;
  user-select: none;
}

.topo-svg:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: -2px;
}

.topo-svg:active { cursor: grabbing; }

.rtt-label {
  font-size: 10px;
  fill: var(--sk-topology-rtt);
  text-anchor: middle;
  pointer-events: none;
}

.node-glyph {
  font-size: 12px;
  font-weight: 600;
  fill: currentColor;
  pointer-events: none;
}

.node-name {
  font-size: 11px;
  fill: var(--sk-topology-label);
  pointer-events: none;
}

.topo-node {
  cursor: pointer;
  transition: opacity 0.15s ease;
}

.topo-node:focus-visible {
  outline: 2px solid #3b82f6;
}

.topo-node.dimmed { opacity: 0.2; }

.topo-node.selected circle {
  stroke-width: 3.5;
  filter: drop-shadow(0 0 4px rgba(30, 41, 59, 0.35));
}

.topo-panel {
  position: absolute;
  top: 12px;
  right: 12px;
  width: min(320px, calc(100% - 24px));
  max-height: calc(100% - 24px);
  overflow: auto;
  box-sizing: border-box;
  background: color-mix(in srgb, var(--sk-surface) 94%, transparent);
  border: 1px solid var(--sk-border);
  border-radius: 10px;
  padding: 10px 12px;
  box-shadow: var(--sk-shadow);
}

.topo-panel-title {
  font-weight: 600;
  margin-bottom: 8px;
  font-size: 13px;
}

.topo-panel-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px dashed var(--sk-border);
  font-size: 12px;
}

.topo-panel-row:last-child { border-bottom: none; }

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: none;
}

.dot.on { background: var(--sk-direct-udp); }
.dot.off { background: var(--sk-offline); }
.topo-hint { font-size: 12px; }

@media (max-width: 640px) {
  .topo-toolbar > div:last-child {
    width: 100%;
    justify-content: space-between;
  }

  .topo-panel {
    top: auto;
    right: 8px;
    bottom: 8px;
    left: 8px;
    width: auto;
    max-height: 46%;
  }
}
</style>
