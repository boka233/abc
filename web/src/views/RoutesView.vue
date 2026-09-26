<script setup lang="ts">
import { onMounted, ref, watch, computed } from 'vue'
import {
  api,
  TARGET_STRATEGIES,
  type DeviceGroupDto,
  type EndpointDto,
  type RouteDto,
  type RouteLive,
} from '@/api'
import { useTelemetryStore } from '@/stores/telemetry'
import { bytes } from '@/format'

interface RouteRow {
  route: RouteDto
  live: RouteLive | null
}

/**
 * 出口组下拉里代表「不使用隧道」的值。
 *
 * 为什么用这种方式而不是单独的模式选择器：模式与出口组本来就是同一个决定 ——
 * 选了出口组就是隧道模式，不选就是直连。分成两个控件时用户可能选了「隧道」却没选
 * 出口组，或选了出口组又把模式改回直连，都得额外提示。合成一个下拉就不存在这种
 * 矛盾状态。
 */
const NO_TUNNEL = '__direct__'

const telemetry = useTelemetryStore()
const rows = ref<RouteRow[]>([])
const groups = ref<DeviceGroupDto[]>([])
const endpoints = ref<EndpointDto[]>([])
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const showCreate = ref(false)
const showImport = ref(false)
const busy = ref(false)

/** 正在编辑的线路 id；`null` 表示新建。表单本身两种情况共用。 */
const editingId = ref<string | null>(null)

/** 选中的线路 id，批量操作针对它们。 */
const selected = ref(new Set<string>())

const form = ref({
  name: '',
  entry_group_id: '',
  listen_address: '0.0.0.0',
  /** 空字符串表示留空 → 由服务端随机分配。 */
  listen_port: '' as string | number,
  /** `NO_TUNNEL` 表示直连转发。 */
  exit_group_id: NO_TUNNEL,
  /** 多行文本，一行一个 `主机:端口`。 */
  targets: '',
  target_strategy: 'random',
  endpoint_ids: [] as string[],
  tunnel_pool_size: 8,
  load_balance: 'round_robin',
  max_connections: 0,
  egress_source_ip: '',
})

const importForm = ref({
  content: '',
  group_id: '',
  listen_address: '0.0.0.0',
  exit_group_id: NO_TUNNEL,
  endpoint_ids: [] as string[],
  target_strategy: 'random',
  egress_source_ip: '',
})

interface ImportResult {
  total: number
  created: number
  failed: number
  failures: Array<{ line: number; name: string | null; reason: string }>
  proxy_protocol_ignored: number
  notes: string[]
}
const importResult = ref<ImportResult | null>(null)

/** 出口组选了「不使用隧道」时就是直连模式。 */
const isDirect = computed(() => form.value.exit_group_id === NO_TUNNEL)
const importIsDirect = computed(() => importForm.value.exit_group_id === NO_TUNNEL)

/** 表单里解析出的目标列表，用于校验与提示。 */
const parsedTargets = computed(() => parseTargets(form.value.targets))

function parseTargets(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
}

/** 多目标时才需要关心策略 —— 单目标下五种策略结果完全相同。 */
const strategyMatters = computed(() => parsedTargets.value.length > 1)

const inboundGroups = computed(() =>
  groups.value.filter((g) => g.kind === 'inbound' || g.kind === 'both'),
)
const outboundGroups = computed(() =>
  groups.value.filter((g) => g.kind === 'outbound' || g.kind === 'both'),
)

/**
 * 可选的隧道地址：只列出出口组内机器的地址。
 *
 * 出口组有多台机器时，这里会同时列出它们各自的地址 —— 一条线路可以引用多个，
 * 隧道池在其间做负载与故障转移。
 */
const selectableEndpoints = computed(() => endpointsOfGroup(form.value.exit_group_id))
const importSelectableEndpoints = computed(() =>
  endpointsOfGroup(importForm.value.exit_group_id),
)

function endpointsOfGroup(groupId: string): EndpointDto[] {
  if (!groupId || groupId === NO_TUNNEL) return []
  const groupNodeIds = new Set(machinesByGroup.value.get(groupId) ?? [])
  return endpoints.value.filter((e) => groupNodeIds.has(e.node_id))
}

/** 组 id → 该组内机器 id 列表。 */
const machinesByGroup = ref(new Map<string, string[]>())

const allSelected = computed(
  () => rows.value.length > 0 && selected.value.size === rows.value.length,
)

function toggleAll() {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(rows.value.map((r) => r.route.id))
  }
}

function toggleOne(id: string) {
  // 重建 Set 而不是原地增删：Vue 的响应式不会追踪 Set 内部变化。
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

async function load() {
  try {
    const [r, g, e, n] = await Promise.all([
      api.get<{ routes: RouteRow[] }>('/routes'),
      api.get<{ groups: DeviceGroupDto[] }>('/groups'),
      api.get<{ endpoints: EndpointDto[] }>('/endpoints'),
      api.get<{ nodes: Array<{ id: string; group_id: string }> }>('/nodes'),
    ])
    rows.value = r.routes
    groups.value = g.groups
    endpoints.value = e.endpoints

    const map = new Map<string, string[]>()
    for (const node of n.nodes) {
      const list = map.get(node.group_id) ?? []
      list.push(node.id)
      map.set(node.group_id, list)
    }
    machinesByGroup.value = map

    // 已被删除的线路要从选中集合里剔除，否则批量操作会带上不存在的 id。
    const alive = new Set(r.routes.map((row) => row.route.id))
    selected.value = new Set([...selected.value].filter((id) => alive.has(id)))
    error.value = null
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

onMounted(load)
watch(() => telemetry.configGeneration, load)

/** 打开新建弹窗时重置表单，避免上次的内容残留。 */
function openCreate() {
  editingId.value = null
  form.value = {
    name: '',
    entry_group_id: '',
    listen_address: '0.0.0.0',
    listen_port: '',
    exit_group_id: NO_TUNNEL,
    targets: '',
    target_strategy: 'random',
    endpoint_ids: [],
    tunnel_pool_size: 8,
    load_balance: 'round_robin',
    max_connections: 0,
    egress_source_ip: '',
  }
  showCreate.value = true
}

/**
 * 用既有线路填充同一个表单。
 *
 * 复用新建表单而不是另写一套：两者的字段、校验与联动完全一致，分成两份必然会在
 * 某次改动后不一致 —— 比如新建支持了多目标而编辑还是单目标。
 */
function openEdit(route: RouteDto) {
  editingId.value = route.id
  form.value = {
    name: route.name,
    entry_group_id: route.entry_group_id,
    listen_address: route.listen_address,
    listen_port: route.listen_port,
    // 直连线路在库里 exit_group_id 指向入口组，但界面上应显示「不使用隧道」。
    exit_group_id: route.mode === 'direct' ? NO_TUNNEL : route.exit_group_id,
    targets: route.targets.join('\n'),
    target_strategy: route.target_strategy,
    endpoint_ids: route.endpoints.map((e) => e.id),
    tunnel_pool_size: route.tunnel_pool_size,
    load_balance: route.load_balance,
    max_connections: route.max_connections,
    egress_source_ip: route.egress_source_ip ?? '',
  }
  showCreate.value = true
}

const isEditing = computed(() => editingId.value !== null)

async function submitForm() {
  const targets = parsedTargets.value
  if (!targets.length) {
    error.value = '请至少填写一个目标地址'
    return
  }
  const port = String(form.value.listen_port).trim()
  // 两条路径共用同一份载荷：字段含义完全相同，唯一区别是编辑不能换入口组
  // （换组等于换机器，监听端口的唯一性约束是按组算的，应当新建线路）。
  const payload = {
    name: form.value.name,
    mode: isDirect.value ? 'direct' : 'tunnel',
    listen_address: form.value.listen_address,
    // 留空传 null，服务端随机分配一个该入口组未占用的端口。
    listen_port: port === '' ? null : Number(port),
    // 直连模式没有对端出口组，服务端会回落到入口组。
    exit_group_id: isDirect.value ? null : form.value.exit_group_id,
    // target_host/port 由服务端从 targets[0] 取，这里给占位值。
    target_host: '',
    target_port: 0,
    targets,
    target_strategy: form.value.target_strategy,
    endpoint_ids: isDirect.value ? [] : form.value.endpoint_ids,
    tunnel_pool_size: Number(form.value.tunnel_pool_size),
    load_balance: form.value.load_balance,
    max_connections: Number(form.value.max_connections),
    egress_source_ip: form.value.egress_source_ip || null,
  }

  busy.value = true
  try {
    if (editingId.value) {
      await api.patch(`/routes/${editingId.value}`, payload)
      notice.value = `线路「${form.value.name}」已更新，将在 agent 下次配置轮询时生效。`
    } else {
      await api.post('/routes', {
        ...payload,
        entry_group_id: form.value.entry_group_id,
      })
    }
    showCreate.value = false
    editingId.value = null
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

async function toggle(route: RouteDto) {
  try {
    await api.put(`/routes/${route.id}/enabled`, { enabled: !route.enabled })
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function restart(route: RouteDto) {
  try {
    await api.post(`/routes/${route.id}/restart`)
    // 控制面无法直接操作 agent 进程，它只是递增配置版本，agent 下次轮询时重建。
    // 如实说明，而不是暗示这是一个同步动作。
    notice.value = `线路「${route.name}」将在 agent 下次配置轮询时重建。`
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function remove(route: RouteDto) {
  if (!confirm(`删除线路「${route.name}」？其上的活动连接会中断。`)) return
  try {
    await api.delete(`/routes/${route.id}`)
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

// --- 批量操作 ---------------------------------------------------------------

async function bulkDelete() {
  const ids = [...selected.value]
  if (!ids.length) return
  if (!confirm(`删除选中的 ${ids.length} 条线路？其上的活动连接会中断。`)) return
  busy.value = true
  try {
    const r = await api.post<{ succeeded: number; failed: number; errors: string[] }>(
      '/routes/bulk-delete',
      { route_ids: ids },
    )
    notice.value = `已删除 ${r.succeeded} 条${r.failed ? `，${r.failed} 条失败：${r.errors.join('；')}` : ''}。`
    selected.value = new Set()
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

async function bulkEnabled(enabled: boolean) {
  const ids = [...selected.value]
  if (!ids.length) return
  busy.value = true
  try {
    const r = await api.post<{ succeeded: number; failed: number; errors: string[] }>(
      '/routes/bulk-enabled',
      { route_ids: ids, enabled },
    )
    notice.value = `已${enabled ? '启用' : '停用'} ${r.succeeded} 条${
      r.failed ? `，${r.failed} 条失败：${r.errors.join('；')}` : ''
    }。`
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

/** 批量改组弹窗。三项都可留空，只改填了的那些。 */
const showRegroup = ref(false)
const regroupForm = ref({
  /** 空字符串 = 不改。 */
  entry_group_id: '',
  /** 空字符串 = 不改；`NO_TUNNEL` = 改成直连。 */
  exit_group_id: '',
  endpoint_ids: [] as string[],
})

/** 改组时选的出口组决定了模式,与新建表单同一套逻辑。 */
const regroupIsDirect = computed(() => regroupForm.value.exit_group_id === NO_TUNNEL)
const regroupEndpoints = computed(() => endpointsOfGroup(regroupForm.value.exit_group_id))

function openRegroup() {
  regroupForm.value = { entry_group_id: '', exit_group_id: '', endpoint_ids: [] }
  showRegroup.value = true
}

async function runRegroup() {
  const ids = [...selected.value]
  if (!ids.length) return

  const body: Record<string, unknown> = { route_ids: ids }
  if (regroupForm.value.entry_group_id) {
    body.entry_group_id = regroupForm.value.entry_group_id
  }
  if (regroupForm.value.exit_group_id) {
    if (regroupIsDirect.value) {
      // 改成直连：服务端会清空隧道地址并把出口组指向入口组。
      body.mode = 'direct'
    } else {
      body.mode = 'tunnel'
      body.exit_group_id = regroupForm.value.exit_group_id
      body.endpoint_ids = regroupForm.value.endpoint_ids
    }
  }
  if (!body.entry_group_id && !body.mode) {
    error.value = '请至少选择要修改的入口组或出口组'
    return
  }
  if (body.mode === 'tunnel' && !regroupForm.value.endpoint_ids.length) {
    error.value = '改成隧道转发时必须选择隧道地址'
    return
  }

  busy.value = true
  try {
    const r = await api.post<{ succeeded: number; failed: number; errors: string[] }>(
      '/routes/bulk-regroup',
      body,
    )
    notice.value =
      `已修改 ${r.succeeded} 条` +
      (r.failed ? `，${r.failed} 条失败：${r.errors.join('；')}` : '') +
      '。将在 agent 下次配置轮询时生效。'
    showRegroup.value = false
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

/**
 * 导出为 JSON Lines 文件。
 *
 * 用 fetch + Blob 而不是直接开新窗口：导出接口需要 Authorization 头，
 * `window.open` 带不上它。
 */
async function exportRoutes() {
  busy.value = true
  try {
    const r = await api.get<{ content: string; count: number }>('/routes/export')
    const blob = new Blob([r.content], { type: 'application/x-ndjson;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const stamp = new Date().toISOString().slice(0, 10)
    a.download = `routes-${stamp}.jsonl`
    a.click()
    URL.revokeObjectURL(url)
    notice.value = `已导出 ${r.count} 条线路。`
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

function openImport() {
  importResult.value = null
  importForm.value = {
    content: '',
    group_id: '',
    listen_address: '0.0.0.0',
    exit_group_id: NO_TUNNEL,
    endpoint_ids: [],
    target_strategy: 'random',
    egress_source_ip: '',
  }
  showImport.value = true
}

/** 读入本地文件到文本框，省得用户自己复制粘贴 79 行。 */
async function pickFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  importForm.value.content = await file.text()
}

const importLineCount = computed(
  () =>
    importForm.value.content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && !l.startsWith('//')).length,
)

async function runImport() {
  if (!importForm.value.content.trim()) {
    error.value = '请先粘贴或选择要导入的内容'
    return
  }
  busy.value = true
  try {
    importResult.value = await api.post<ImportResult>('/routes/import', {
      content: importForm.value.content,
      group_id: importForm.value.group_id,
      listen_address: importForm.value.listen_address,
      mode: importIsDirect.value ? 'direct' : 'tunnel',
      exit_group_id: importIsDirect.value ? null : importForm.value.exit_group_id,
      endpoint_ids: importIsDirect.value ? [] : importForm.value.endpoint_ids,
      target_strategy: importForm.value.target_strategy,
      egress_source_ip: importForm.value.egress_source_ip || null,
    })
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

/** 某条线路的目标健康状态，按地址查。 */
function healthOf(row: RouteRow, addr: string) {
  return row.live?.targets?.find((t) => t.addr === addr)
}

const currentStrategyHint = computed(
  () => TARGET_STRATEGIES.find((s) => s.value === form.value.target_strategy)?.hint ?? '',
)
</script>

<template>
  <h1>线路</h1>
  <div v-if="error" class="banner banner-bad">
    {{ error }}
    <button class="sm" style="margin-left: 8px" @click="error = null">关闭</button>
  </div>
  <div v-if="notice" class="banner banner-info">
    {{ notice }}
    <button class="sm" style="margin-left: 8px" @click="notice = null">知道了</button>
  </div>

  <div class="banner banner-info">
    <strong>两种转发方式</strong>，在新建线路时由「出口组」一项决定：<br />
    选择一个<strong>出口组</strong> —— 用户 → 入口组 → 加密隧道 → 出口组 → 目标。
    两端各需一台机器，适合跨境；加密的价值在于隐藏已加密流量的形状（防 TLS-in-TLS 指纹）。<br />
    选择<strong>「不使用隧道（直接转发）」</strong> —— 用户 → 单台机器 → 目标。
    只需一台机器，不建隧道、不需要证书。适合一台三网优化机直转落地机，或 IEPL 商家
    只给出口 root 的情形。
  </div>

  <div class="toolbar">
    <button class="primary" :disabled="!groups.length" @click="openCreate">
      新建线路
    </button>
    <button :disabled="!groups.length || busy" @click="openImport">批量导入</button>
    <button :disabled="busy || !rows.length" @click="exportRoutes">批量导出</button>
    <span v-if="!groups.length" class="dim">需要先创建至少一个设备组</span>
    <span class="spacer"></span>
    <button class="sm" @click="load">刷新</button>
  </div>

  <div v-if="selected.size" class="toolbar">
    <span>已选中 <strong>{{ selected.size }}</strong> 条</span>
    <button class="sm" :disabled="busy" @click="openRegroup">批量改组</button>
    <button class="sm" :disabled="busy" @click="bulkEnabled(true)">批量启用</button>
    <button class="sm" :disabled="busy" @click="bulkEnabled(false)">批量停用</button>
    <button class="sm danger" :disabled="busy" @click="bulkDelete">批量删除</button>
    <button class="sm" @click="selected = new Set()">取消选择</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th style="width: 28px">
            <input
              type="checkbox"
              :checked="allSelected"
              :indeterminate="selected.size > 0 && !allSelected"
              title="全选"
              @change="toggleAll"
            />
          </th>
          <th>名称</th><th>方式</th><th>入口组</th><th>监听</th><th>出口组</th>
          <th>目标</th>
          <th class="num">累计流量</th><th>状态</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="row.route.id">
          <td>
            <input
              type="checkbox"
              :checked="selected.has(row.route.id)"
              @change="toggleOne(row.route.id)"
            />
          </td>
          <td>{{ row.route.name }}</td>
          <td>
            <span
              class="pill"
              :class="row.route.mode === 'direct' ? 'pill-warn' : 'pill-ok'"
              :title="
                row.route.mode === 'direct'
                  ? '单机直转，不建隧道、不加密（载荷通常已由上层协议加密）'
                  : '两端各一台机器，中间走 TLS 1.3 加密隧道'
              "
            >{{ row.route.mode_label }}</span>
          </td>
          <td class="dim">
            <RouterLink :to="`/groups/${row.route.entry_group_id}`">
              {{ row.route.entry_group_name ?? '—' }}
            </RouterLink>
          </td>
          <td class="mono">{{ row.route.listen_address }}:{{ row.route.listen_port }}</td>
          <td class="dim">
            <template v-if="row.route.mode === 'direct'">
              <span class="dim">不走隧道</span>
            </template>
            <RouterLink v-else :to="`/groups/${row.route.exit_group_id}`">
              {{ row.route.exit_group_name ?? '—' }}
            </RouterLink>
          </td>
          <td>
            <div v-for="addr in row.route.targets" :key="addr" class="target-line">
              <span class="mono">{{ addr }}</span>
              <span
                v-if="healthOf(row, addr)"
                class="pill"
                :class="
                  healthOf(row, addr)!.tripped
                    ? 'pill-bad'
                    : healthOf(row, addr)!.available
                      ? 'pill-ok'
                      : 'pill-warn'
                "
                :title="
                  `活跃 ${healthOf(row, addr)!.active} 条 · 成功 ${healthOf(row, addr)!.total_ok} · 失败 ${healthOf(row, addr)!.total_failed}` +
                  (healthOf(row, addr)!.tripped
                    ? ` · 已在 ${healthOf(row, addr)!.tripped_on_machines}/${healthOf(row, addr)!.machines} 台机器上熔断，将定期试探恢复`
                    : '')
                "
              >{{ healthOf(row, addr)!.tripped ? '熔断' : healthOf(row, addr)!.active }}</span>
            </div>
            <span
              v-if="row.route.targets.length > 1"
              class="pill pill-info"
              :title="
                TARGET_STRATEGIES.find((s) => s.value === row.route.target_strategy)?.hint
              "
            >{{ row.route.target_strategy_label }}</span>
          </td>
          <td class="num">
            {{ bytes((row.live?.rx_bytes ?? 0) + (row.live?.tx_bytes ?? 0)) }}
          </td>
          <td>
            <span :class="row.route.enabled ? 'pill pill-ok' : 'pill pill-bad'">
              {{ row.route.enabled ? '启用' : '停用' }}
            </span>
          </td>
          <td style="white-space: nowrap">
            <button class="sm" @click="openEdit(row.route)">编辑</button>
            <button class="sm" @click="toggle(row.route)">
              {{ row.route.enabled ? '停用' : '启用' }}
            </button>
            <button class="sm" @click="restart(row.route)">重建</button>
            <button class="sm danger" @click="remove(row.route)">删除</button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td colspan="10" class="empty">
            还没有线路。<br />
            单机直转：建一个设备组，用一键对接把机器加进来，新建线路时出口组选
            「不使用隧道（直接转发）」。<br />
            跨境隧道：还需为出口机器添加隧道地址，新建线路时选择对应的出口组。<br />
            已有别处导出的规则？用「批量导入」一次性导进来。
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- 新建线路 -->
  <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
    <form class="modal" @submit.prevent="submitForm">
      <h2>{{ isEditing ? '编辑线路' : '新建线路' }}</h2>

      <div class="field">
        <label>名称</label>
        <input
          v-model="form.name"
          required
          :placeholder="isDirect ? '香港直转落地' : '上海 → 香港'"
        />
      </div>

      <div class="field-row">
        <div class="field">
          <label>{{ isDirect ? '设备组（转发机所在）' : '入口组' }}</label>
          <select v-model="form.entry_group_id" :disabled="isEditing" required>
            <option value="" disabled>请选择</option>
            <option
              v-for="g in isDirect ? groups : inboundGroups"
              :key="g.id"
              :value="g.id"
            >
              {{ g.name }}（{{ g.nodes_total }} 台）
            </option>
          </select>
          <div v-if="isEditing" class="hint">
            入口组不可更改 —— 换组等于换机器，而监听端口的唯一性是按组计算的。
            要挪到别的组请新建线路。
          </div>
        </div>
        <div class="field">
          <label>出口组</label>
          <select v-model="form.exit_group_id">
            <option :value="NO_TUNNEL">不使用隧道（直接转发）</option>
            <option v-for="g in outboundGroups" :key="g.id" :value="g.id">
              {{ g.name }}（{{ g.nodes_total }} 台）
            </option>
          </select>
          <div v-if="isDirect" class="hint">
            这台机器 accept 后直接 dial 目标，不建隧道、不需要证书。本系统不额外加密
            这条链路 —— 被转发的通常是 VLESS/Trojan 这类自带 TLS 的协议流量，字节本来
            就是密文。
          </div>
          <div v-else class="hint">
            入口与出口之间走 TLS 1.3 加密隧道。需要为出口机器准备证书与隧道地址。
          </div>
        </div>
      </div>

      <div class="field-row">
        <div class="field">
          <label>监听地址</label>
          <input v-model="form.listen_address" required />
        </div>
        <div class="field">
          <label>监听端口（留空则随机分配）</label>
          <input
            v-model="form.listen_port"
            type="number"
            min="1"
            max="65535"
            placeholder="留空 → 随机"
          />
          <div class="hint">
            留空时在 2000-65535 间挑一个本组尚未占用的端口。一台机器上会有多条
            线路，固定 443 会互相冲突。
          </div>
        </div>
      </div>

      <div class="field">
        <label>目标地址（一行一个）</label>
        <textarea
          v-model="form.targets"
          rows="4"
          required
          class="mono"
          :placeholder="
            isDirect
              ? '233.21.21.21:443\n233.21.21.22:443'
              : '127.0.0.1:8443'
          "
        ></textarea>
        <div class="hint">
          {{
            isDirect
              ? '转发机要拨的最终地址，通常就是你的落地机。'
              : '出口机器视角看到的服务；同机时通常是 127.0.0.1。'
          }}
          写成 <span class="mono">主机:端口</span>；IPv6 用
          <span class="mono">[地址]:端口</span>。填多行即多目标。
        </div>
        <div v-if="parsedTargets.length > 1" class="hint">
          已识别 {{ parsedTargets.length }} 个目标，按下面的策略分配新连接。
          某个目标连续失败 3 次会被暂时跳过，之后每 30 秒试探一次，恢复即自动加回。
        </div>
      </div>

      <div class="field">
        <label>
          负载均衡策略
          <span v-if="!strategyMatters" class="dim">（只有多个目标时才起作用）</span>
        </label>
        <select v-model="form.target_strategy">
          <option v-for="s in TARGET_STRATEGIES" :key="s.value" :value="s.value">
            {{ s.label }}
          </option>
        </select>
        <div class="hint">{{ currentStrategyHint }}</div>
      </div>

      <template v-if="!isDirect">
        <div class="field">
          <label>隧道地址（按住 Ctrl 多选；顺序即故障转移顺序）</label>
          <select v-model="form.endpoint_ids" multiple size="5" required>
            <option v-for="ep in selectableEndpoints" :key="ep.id" :value="ep.id">
              {{ ep.node_name ? ep.node_name + ' / ' : '' }}{{ ep.name }} —
              {{ ep.address }}:{{ ep.port }}（{{ ep.kind }}，{{ ep.priority === 'primary' ? '主' : '备' }}）
            </option>
          </select>
          <div class="hint">
            只列出出口组内机器的地址。把 IEPL 放在前、公网放在后即可获得
            「IEPL 优先、公网兜底」的故障转移。
          </div>
          <div
            v-if="!selectableEndpoints.length"
            class="hint"
            style="color: var(--warn)"
          >
            该出口组还没有任何隧道地址。请先到组详情页为机器添加。
          </div>
        </div>

        <div class="field-row">
          <div class="field">
            <label>隧道池大小</label>
            <input v-model.number="form.tunnel_pool_size" type="number" min="1" max="256" required />
            <div class="hint">
              多条 TLS 连接可限制队头阻塞的影响面。默认 8 是个合适的起点。
            </div>
          </div>
          <div class="field">
            <label>隧道选择策略</label>
            <select v-model="form.load_balance">
              <option value="round_robin">轮询</option>
              <option value="least_streams">最少流数</option>
            </select>
            <div class="hint">
              这一项决定连接走隧道池里的哪条隧道，与上面的「负载均衡策略」（决定落到
              哪个目标）互不影响。
            </div>
          </div>
        </div>
      </template>

      <div class="field-row">
        <div class="field">
          <label>最大连接数（0 表示继承全局限制）</label>
          <input v-model.number="form.max_connections" type="number" min="0" />
        </div>
        <div class="field">
          <label>出站源 IP</label>
          <input v-model="form.egress_source_ip" placeholder="203.0.113.9" />
          <div class="hint">
              仅多网卡主机需要指定出站地址时填写。普通直连转发留空，按系统路由连接目标。
          </div>
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" @click="showCreate = false">取消</button>
        <button class="primary" type="submit" :disabled="busy">
          {{ busy ? '提交中…' : isEditing ? '保存' : '创建' }}
        </button>
      </div>
    </form>
  </div>

  <!-- 批量改组 -->
  <div v-if="showRegroup" class="modal-backdrop" @click.self="showRegroup = false">
    <form class="modal" @submit.prevent="runRegroup">
      <h2>批量改组</h2>
      <div class="banner banner-info">
        将修改选中的 <strong>{{ selected.size }}</strong> 条线路。
        留空的项不做改动 —— 只想换入口组就只选入口组。
      </div>

      <div class="field">
        <label>入口组</label>
        <select v-model="regroupForm.entry_group_id">
          <option value="">不修改</option>
          <option v-for="g in groups" :key="g.id" :value="g.id">
            {{ g.name }}（{{ g.nodes_total }} 台）
          </option>
        </select>
        <div class="hint">
          监听端口的唯一性按组计算：若目标组里已有线路占着同一个端口，那一条会报冲突
          并保持原样，其余的照常改。
        </div>
      </div>

      <div class="field">
        <label>出口组 / 转发方式</label>
        <select v-model="regroupForm.exit_group_id">
          <option value="">不修改</option>
          <option :value="NO_TUNNEL">不使用隧道（直接转发）</option>
          <option v-for="g in outboundGroups" :key="g.id" :value="g.id">
            {{ g.name }}（{{ g.nodes_total }} 台）
          </option>
        </select>
        <div v-if="regroupIsDirect" class="hint">
          改成直连转发：会清空这些线路的隧道地址，出口组指向入口组。
        </div>
      </div>

      <div v-if="regroupForm.exit_group_id && !regroupIsDirect" class="field">
        <label>隧道地址（按住 Ctrl 多选；整批共用）</label>
        <select v-model="regroupForm.endpoint_ids" multiple size="5" required>
          <option v-for="ep in regroupEndpoints" :key="ep.id" :value="ep.id">
            {{ ep.node_name ? ep.node_name + ' / ' : '' }}{{ ep.name }} —
            {{ ep.address }}:{{ ep.port }}（{{ ep.kind }}）
          </option>
        </select>
        <div class="hint">
          换出口组必须重新指定隧道地址 —— 原来的那些属于旧组，留着会让入口拨向没有
          运行该线路出口的机器。
        </div>
        <div v-if="!regroupEndpoints.length" class="hint" style="color: var(--warn)">
          该出口组还没有任何隧道地址。请先到组详情页为机器添加。
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" @click="showRegroup = false">取消</button>
        <button class="primary" type="submit" :disabled="busy">
          {{ busy ? '提交中…' : '应用' }}
        </button>
      </div>
    </form>
  </div>

  <!-- 批量导入 -->
  <div v-if="showImport" class="modal-backdrop" @click.self="showImport = false">
    <form class="modal" @submit.prevent="runImport">
      <h2>批量导入线路</h2>

      <div class="banner banner-info">
        每行一个 JSON 对象（JSON Lines），与常见中转面板的导出格式兼容：
        <div class="mono" style="margin-top: 6px">
          {"dest":["1.2.3.4:443"],"listen_port":17976,"name":"台湾01"}
        </div>
        <div style="margin-top: 6px">
          <span class="mono">dest</span> 有多项时即多目标，按下面的策略分配。
          <span class="mono">listen_port</span> 可以省略，由系统在 2000-65535 间自动挑一个未占用的端口。
          逐条处理：某一条失败不影响其余，结果里会列出失败的行号与原因。
        </div>
      </div>

      <div class="field">
        <label>内容</label>
        <input type="file" accept=".jsonl,.json,.txt,text/plain" @change="pickFile" />
        <textarea
          v-model="importForm.content"
          rows="8"
          class="mono"
          placeholder='{"dest":["1.2.3.4:443"],"listen_port":17976,"name":"台湾01"}'
          style="margin-top: 6px"
        ></textarea>
        <div class="hint">
          可选择文件，也可直接粘贴。当前识别到 {{ importLineCount }} 条有效行
          （空行与 <span class="mono">#</span>、<span class="mono">//</span> 开头的行会被跳过）。
        </div>
      </div>

      <div class="field-row">
        <div class="field">
          <label>导入到设备组</label>
          <select v-model="importForm.group_id" required>
            <option value="" disabled>请选择</option>
            <option v-for="g in groups" :key="g.id" :value="g.id">
              {{ g.name }}（{{ g.nodes_total }} 台）
            </option>
          </select>
        </div>
        <div class="field">
          <label>出口组</label>
          <select v-model="importForm.exit_group_id">
            <option :value="NO_TUNNEL">不使用隧道（直接转发）</option>
            <option v-for="g in outboundGroups" :key="g.id" :value="g.id">
              {{ g.name }}（{{ g.nodes_total }} 台）
            </option>
          </select>
          <div class="hint">
            导入格式里没有隧道信息，所以默认直接转发。选了出口组则全部按隧道模式导入。
          </div>
        </div>
      </div>

      <div class="field-row">
        <div class="field">
          <label>监听地址</label>
          <input v-model="importForm.listen_address" required />
        </div>
        <div class="field">
          <label>负载均衡策略（多目标时生效）</label>
          <select v-model="importForm.target_strategy">
            <option v-for="s in TARGET_STRATEGIES" :key="s.value" :value="s.value">
              {{ s.label }}
            </option>
          </select>
          <div class="hint">
            某一行自带 <span class="mono">target_strategy</span> 时以该行为准。
          </div>
        </div>
      </div>

      <div v-if="!importIsDirect" class="field">
        <label>隧道地址（按住 Ctrl 多选）</label>
        <select v-model="importForm.endpoint_ids" multiple size="4" required>
          <option v-for="ep in importSelectableEndpoints" :key="ep.id" :value="ep.id">
            {{ ep.node_name ? ep.node_name + ' / ' : '' }}{{ ep.name }} —
            {{ ep.address }}:{{ ep.port }}
          </option>
        </select>
      </div>

      <div class="field">
        <label>出站源 IP（所有导入线路共用，可留空）</label>
        <input v-model="importForm.egress_source_ip" placeholder="203.0.113.9" />
      </div>

      <div v-if="importResult" class="banner" :class="importResult.failed ? 'banner-warn' : 'banner-info'">
        <strong>
          共 {{ importResult.total }} 条，成功 {{ importResult.created }} 条，
          失败 {{ importResult.failed }} 条。
        </strong>
        <ul v-if="importResult.notes.length" style="margin: 6px 0 0; padding-left: 18px">
          <li v-for="(n, i) in importResult.notes" :key="i">{{ n }}</li>
        </ul>
        <div v-if="importResult.failures.length" style="margin-top: 6px">
          失败明细：
          <ul style="margin: 4px 0 0; padding-left: 18px">
            <li v-for="f in importResult.failures" :key="f.line">
              第 {{ f.line }} 行{{ f.name ? `（${f.name}）` : '' }}：{{ f.reason }}
            </li>
          </ul>
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" @click="showImport = false">
          {{ importResult ? '关闭' : '取消' }}
        </button>
        <button class="primary" type="submit" :disabled="busy">
          {{ busy ? '导入中…' : '开始导入' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.target-line {
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
textarea {
  width: 100%;
  resize: vertical;
}
</style>
