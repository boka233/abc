<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  api,
  type DeviceGroupDto,
  type EndpointDto,
  type InstallCommandDto,
  type NodeDto,
  type RouteDto,
} from '@/api'
import { useTelemetryStore } from '@/stores/telemetry'
import { bitrate, bytes, duration, percent, rtt, statusClass, ago } from '@/format'
import InstallCommandModal from '@/components/InstallCommandModal.vue'

interface Detail {
  group: DeviceGroupDto
  machines: NodeDto[]
  routes: RouteDto[]
}

const route = useRoute()
const telemetry = useTelemetryStore()
const detail = ref<Detail | null>(null)
const error = ref<string | null>(null)
const install = ref<InstallCommandDto | null>(null)

const groupId = computed(() => String(route.params.id))

// 添加隧道地址的表单，针对某一台机器。
const epForm = ref({
  node_id: '',
  node_name: '',
  name: '',
  address: '',
  port: 5000,
  kind: 'iepl',
  priority: 'primary',
  interface: '',
  source_ip: '',
  tls_server_name: '',
})
const showEndpointForm = ref(false)

async function load() {
  try {
    detail.value = await api.get<Detail>(`/groups/${groupId.value}`)
    error.value = null
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

let refreshTimer: number | undefined
onMounted(() => {
  void load()
  refreshTimer = window.setInterval(() => { void load() }, 10_000)
})
onUnmounted(() => window.clearInterval(refreshTimer))
watch(() => telemetry.configGeneration, load)
watch(groupId, load)

/** 用实时遥测覆盖机器状态：心跳落库有延迟。 */
const machines = computed(() => {
  if (!detail.value) return []
  return detail.value.machines.map((m) => {
    const live = telemetry.nodeReports[m.id]
    if (!live) return m
    return {
      ...m,
      status: 'online',
      connections: live.connections,
      rx_bps: live.rx_bps,
      tx_bps: live.tx_bps,
      rx_bytes: live.rx_bytes,
      tx_bytes: live.tx_bytes,
      cpu_percent: live.host.cpu_percent,
      memory_used_bytes: live.host.memory_used_bytes,
      memory_total_bytes: live.host.memory_total_bytes,
      uptime_secs: live.host.uptime_secs,
      host_uptime_secs: live.host.host_uptime_secs,
      disk_used_bytes: live.host.disk_used_bytes,
      disk_total_bytes: live.host.disk_total_bytes,
      agent_version: live.agent_version,
      tunnels: live.tunnels,
      interfaces: live.interfaces ?? m.interfaces,
    }
  })
})

function ipv4Octets(address: string): number[] | null {
  const parts = address.split('.')
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null
  const octets = parts.map(Number)
  return octets.every((octet) => octet <= 255) ? octets : null
}

function isPublicIpv4(address: string): boolean {
  const octets = ipv4Octets(address)
  if (!octets) return false
  const [a, b] = octets
  return a !== 0 && a !== 10 && a !== 127 && a < 224 &&
    !(a === 100 && b >= 64 && b <= 127) &&
    !(a === 169 && b === 254) &&
    !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168)
}

function isPublicIpv6(address: string): boolean {
  const normalized = address.toLowerCase().split('%')[0]
  return normalized.includes(':') && normalized !== '::1' && normalized !== '::' &&
    !normalized.startsWith('fe80:') && !normalized.startsWith('fc') &&
    !normalized.startsWith('fd') && !normalized.startsWith('ff')
}

function publicIps(machine: NodeDto): { v4?: string; v6?: string } {
  const addresses = [machine.observed_ip, machine.public_address, machine.management_address]
    .filter((address): address is string => Boolean(address))
    .concat((machine.interfaces ?? [])
    .filter((iface) => !iface.is_loopback)
    .flatMap((iface) => iface.addresses))
  return {
    v4: addresses.find(isPublicIpv4),
    v6: addresses.find(isPublicIpv6),
  }
}

function machineIp(machine: NodeDto): string {
  const ips = publicIps(machine)
  return ips.v4 ?? ips.v6 ?? machine.observed_ip ?? '—'
}

const geoRegions = ref<Record<string, string>>({})
const geoRequested = new Set<string>()

// Only look up each public IP once per page visit. A failed lookup leaves the
// country unknown, without blocking telemetry or route management.
watch(machines, (members) => {
  for (const machine of members) {
    for (const ip of Object.values(publicIps(machine))) {
      if (!ip || geoRequested.has(ip)) continue
      geoRequested.add(ip)
      const controller = new AbortController()
      const timeout = window.setTimeout(() => controller.abort(), 5000)
      fetch(`https://api.country.is/${encodeURIComponent(ip)}`, { signal: controller.signal })
        .then((response) => response.ok ? response.json() : null)
        .then((data: { country?: string } | null) => {
          const code = data?.country?.toUpperCase()
          const localized = code && /^[A-Z]{2}$/.test(code)
            ? new Intl.DisplayNames(['zh-CN'], { type: 'region' }).of(code)
            : undefined
          geoRegions.value = {
            ...geoRegions.value,
            [ip]: localized ?? '—',
          }
        })
        .catch(() => {
          geoRegions.value = { ...geoRegions.value, [ip]: '—' }
        })
        .finally(() => window.clearTimeout(timeout))
    }
  }
}, { immediate: true })

function regionFor(machine: NodeDto, family: 'v4' | 'v6'): string {
  const ip = publicIps(machine)[family]
  return ip ? (geoRegions.value[ip] ?? '识别中') : '—'
}

function usage(used: number, total: number): number {
  return total > 0 ? Math.min(100, Math.max(0, used / total * 100)) : 0
}

const showTunnelDetails = computed(() => Boolean(detail.value && (
  detail.value.group.kind === 'outbound' ||
  detail.value.routes.some((route) => route.mode !== 'direct')
)))

async function showInstall() {
  if (!detail.value) return
  try {
    install.value = await api.post<InstallCommandDto>(
      `/groups/${groupId.value}/install-command`,
      {},
    )
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function openEndpointForm(machine: NodeDto) {
  epForm.value = {
    node_id: machine.id,
    node_name: machine.name,
    name: '',
    address: '',
    port: 5000,
    kind: 'iepl',
    priority: 'primary',
    interface: '',
    source_ip: '',
    tls_server_name: '',
  }
  showEndpointForm.value = true
}

async function createEndpoint() {
  try {
    await api.post('/endpoints', {
      node_id: epForm.value.node_id,
      name: epForm.value.name,
      address: epForm.value.address,
      port: Number(epForm.value.port),
      kind: epForm.value.kind,
      priority: epForm.value.priority,
      interface: epForm.value.interface || null,
      source_ip: epForm.value.source_ip || null,
      tls_server_name: epForm.value.tls_server_name || null,
    })
    showEndpointForm.value = false
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function removeEndpoint(ep: EndpointDto) {
  if (!confirm(`删除隧道地址「${ep.name}」？引用它的线路需要先移除该地址。`)) return
  try {
    await api.delete(`/endpoints/${ep.id}`)
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function removeMachine(machine: NodeDto) {
  if (
    !confirm(
      `从组内移除机器「${machine.name}」？它的隧道地址会一并删除，` +
        `但组内其余机器会继续承载相关线路。`,
    )
  )
    return
  try {
    await api.delete(`/groups/${groupId.value}/machines/${machine.id}`)
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function kindClass(kind: string): string {
  if (kind === 'iepl') return 'pill pill-ok'
  if (kind === 'private') return 'pill pill-info'
  return 'pill pill-warn'
}
</script>

<template>
  <div v-if="error" class="banner banner-bad">{{ error }}</div>

  <template v-if="detail">
    <h1>
      {{ detail.group.name }}
      <span class="pill pill-info" style="margin-left: 8px">
        {{ detail.group.kind_label }}
      </span>
      <span
        v-if="!detail.group.enabled"
        class="pill pill-bad"
        style="margin-left: 4px"
        >已停用</span
      >
    </h1>

    <div class="toolbar">
      <button class="primary" @click="showInstall">一键对接（添加机器）</button>
      <span class="spacer"></span>
      <button class="sm" @click="load">刷新</button>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-label">在线机器</div>
        <div class="card-value">
          {{ machines.filter((m) => m.status === 'online').length }} /
          {{ machines.length }}
        </div>
      </div>
      <div class="card">
        <div class="card-label">连接数</div>
        <div class="card-value">
          {{ machines.reduce((s, m) => s + (m.connections ?? 0), 0) }}
        </div>
      </div>
      <div class="card">
        <div class="card-label">当前速率</div>
        <div class="compact-lines mono">
          <div>↑ {{ bitrate(machines.reduce((s, m) => s + (m.rx_bps ?? 0), 0)) }}</div>
          <div>↓ {{ bitrate(machines.reduce((s, m) => s + (m.tx_bps ?? 0), 0)) }}</div>
        </div>
      </div>
      <div class="card">
        <div class="card-label">累计流量</div>
        <div class="compact-lines mono">
          <div>↑ {{ bytes(machines.reduce((s, m) => s + (m.total_rx_bytes ?? 0), 0)) }}</div>
          <div>↓ {{ bytes(machines.reduce((s, m) => s + (m.total_tx_bytes ?? 0), 0)) }}</div>
        </div>
      </div>
      <div class="card">
        <div class="card-label">配置版本</div>
        <div class="card-value" style="font-size: 16px">
          {{ detail.group.config_revision }}
        </div>
        <div class="card-sub">组内机器共享</div>
      </div>
    </div>

    <h2>组内机器</h2>
    <p class="dim small">v4/v6 地区按节点公网 IP 自动识别。多网卡主机的实际目标出口以系统路由和线路源 IP 为准。</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>机器</th><th>状态</th>
            <th title="根据节点公网 IPv4 自动识别国家或地区">v4 地区</th>
            <th title="根据节点公网 IPv6 自动识别国家或地区；没有 IPv6 时显示空缺">v6 地区</th>
            <th title="面板看到的节点地址；多网卡机器的实际目标出口可能不同">节点 IP</th>
            <th>速率</th><th>开机时长</th><th>累计流量</th>
            <th>CPU</th><th>RAM</th><th>存储</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in machines" :key="m.id">
            <td>{{ m.name }}<div class="dim small">{{ m.role }} · {{ m.connections }} 连接 · v{{ m.agent_version ?? '—' }}</div></td>
            <td><span :class="statusClass(m.status)">{{ m.status === 'online' ? '在线' : '离线' }}</span></td>
            <td>{{ regionFor(m, 'v4') }}</td>
            <td>{{ regionFor(m, 'v6') }}</td>
            <td class="mono">{{ machineIp(m) }}</td>
            <td class="mono compact-lines"><div>↑ {{ bitrate(m.rx_bps) }}</div><div>↓ {{ bitrate(m.tx_bps) }}</div></td>
            <td>{{ duration(m.host_uptime_secs || m.uptime_secs) }}</td>
            <td class="mono compact-lines"><div>↑ {{ bytes(m.total_rx_bytes ?? 0) }}</div><div>↓ {{ bytes(m.total_tx_bytes ?? 0) }}</div></td>
            <td><div class="usage-meter"><div :style="{ width: `${usage(m.cpu_percent, 100)}%` }"></div><span>{{ percent(m.cpu_percent) }}</span></div></td>
            <td><div class="usage-meter"><div :style="{ width: `${usage(m.memory_used_bytes, m.memory_total_bytes)}%` }"></div><span>{{ m.memory_total_bytes ? percent(usage(m.memory_used_bytes, m.memory_total_bytes)) : '—' }}</span></div></td>
            <td><div class="usage-meter"><div :style="{ width: `${usage(m.disk_used_bytes, m.disk_total_bytes)}%` }"></div><span>{{ m.disk_total_bytes ? percent(usage(m.disk_used_bytes, m.disk_total_bytes)) : '—' }}</span></div></td>
            <td style="white-space: nowrap">
              <button v-if="showTunnelDetails" class="sm" @click="openEndpointForm(m)">加隧道地址</button>
              <button class="sm danger" @click="removeMachine(m)">移除</button>
              <div class="dim small">心跳 {{ ago(m.last_heartbeat_at) }}</div>
            </td>
          </tr>
          <tr v-if="!machines.length">
            <td colspan="12" class="empty">
              组内还没有机器。点上方「一键对接」取得安装命令，在目标服务器上执行即可。
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <template v-if="showTunnelDetails">
    <h2>隧道地址</h2>
    <div class="banner banner-info">
      仅软件隧道线路需要添加出口地址。直连转发直接连接线路目标，无需配置此处。
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>所属机器</th><th>名称</th><th>地址</th><th class="num">端口</th>
            <th>类型</th><th>优先级</th><th>网卡</th><th>源 IP</th>
            <th>TLS 名称</th><th>启用</th><th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="m in machines" :key="`eps-${m.id}`">
            <tr v-for="ep in m.endpoints ?? []" :key="ep.id">
              <td class="dim">{{ m.name }}</td>
              <td>{{ ep.name }}</td>
              <td class="mono">{{ ep.address }}</td>
              <td class="num">{{ ep.port }}</td>
              <td><span :class="kindClass(ep.kind)">{{ ep.kind }}</span></td>
              <td>{{ ep.priority === 'primary' ? '主' : '备' }}</td>
              <td class="mono dim">{{ ep.interface ?? '—' }}</td>
              <td class="mono">{{ ep.source_ip ?? '—' }}</td>
              <td class="mono dim">{{ ep.tls_server_name ?? '—' }}</td>
              <td>
                <span :class="ep.enabled ? 'pill pill-ok' : 'pill pill-bad'">
                  {{ ep.enabled ? '是' : '否' }}
                </span>
              </td>
              <td><button class="sm danger" @click="removeEndpoint(ep)">删除</button></td>
            </tr>
          </template>
          <tr v-if="!machines.some((m) => (m.endpoints ?? []).length)">
            <td colspan="11" class="empty">
              还没有隧道地址。出口组必须为每台机器至少配置一个，入口才知道拨向哪里。
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2>隧道状态</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>机器</th><th>隧道</th><th>端点</th><th>状态</th>
            <th class="num">流数</th><th class="num">RTT</th>
            <th class="num">接收</th><th class="num">发送</th>
            <th class="num">已连接</th><th class="num">重连次数</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="m in machines" :key="`tun-${m.id}`">
            <tr v-for="t in m.tunnels ?? []" :key="`${m.id}-${t.tunnel_id}`">
              <td class="dim">{{ m.name }}</td>
              <td class="mono">#{{ t.tunnel_id }}</td>
              <td>{{ t.endpoint_name }}</td>
              <td><span :class="statusClass(t.state)">{{ t.state }}</span></td>
              <td class="num">{{ t.streams }}</td>
              <td class="num">{{ rtt(t.rtt_ms) }}</td>
              <td class="num">{{ bytes(t.rx_bytes) }}</td>
              <td class="num">{{ bytes(t.tx_bytes) }}</td>
              <td class="num">{{ duration(t.established_secs) }}</td>
              <td class="num">{{ t.reconnects }}</td>
            </tr>
          </template>
          <tr v-if="!machines.some((m) => (m.tunnels ?? []).length)">
            <td colspan="10" class="empty">暂无隧道上报。</td>
          </tr>
        </tbody>
      </table>
    </div>

    </template>

    <h2>网卡</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>机器</th><th>网卡</th><th>地址</th><th>标记</th></tr></thead>
        <tbody>
          <template v-for="m in machines" :key="`if-${m.id}`">
            <tr v-for="i in m.interfaces ?? []" :key="`${m.id}-${i.name}`">
              <td class="dim">{{ m.name }}</td>
              <td class="mono">{{ i.name }}</td>
              <td class="mono">{{ i.addresses.join(', ') }}</td>
              <td class="dim">{{ i.is_loopback ? '回环' : '' }}</td>
            </tr>
          </template>
          <tr v-if="!machines.some((m) => (m.interfaces ?? []).length)">
            <td colspan="4" class="empty">暂无上报。</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="dim" style="font-size: 12px">网卡信息只读。IEPL 机器可像普通节点一样使用直连转发，目标地址由线路配置决定。</p>

    <h2>相关线路</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>名称</th><th>本组角色</th><th>监听</th><th>目标</th><th>状态</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in detail.routes" :key="r.id">
            <td><RouterLink :to="{ name: 'routes' }">{{ r.name }}</RouterLink></td>
            <td>
              <span class="pill pill-info">
                {{ r.entry_group_id === groupId ? '入口' : '出口' }}
              </span>
            </td>
            <td class="mono">{{ r.listen_address }}:{{ r.listen_port }}</td>
            <td class="mono">{{ r.target_host }}:{{ r.target_port }}</td>
            <td>
              <span :class="r.enabled ? 'pill pill-ok' : 'pill pill-bad'">
                {{ r.enabled ? '启用' : '停用' }}
              </span>
            </td>
          </tr>
          <tr v-if="!detail.routes.length">
            <td colspan="5" class="empty">该组还没有被任何线路引用。</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>

  <!-- 添加隧道地址 -->
  <div
    v-if="showEndpointForm"
    class="modal-backdrop"
    @click.self="showEndpointForm = false"
  >
    <form class="modal" @submit.prevent="createEndpoint">
      <h2>为「{{ epForm.node_name }}」添加隧道地址</h2>
      <div class="field">
        <label>名称</label>
        <input v-model="epForm.name" required placeholder="hk-iepl" />
      </div>
      <div class="field-row">
        <div class="field">
          <label>地址（入口拨向这里）</label>
          <input v-model="epForm.address" required placeholder="10.20.0.2" />
        </div>
        <div class="field">
          <label>端口</label>
          <input v-model.number="epForm.port" type="number" min="1" max="65535" required />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label>类型</label>
          <select v-model="epForm.kind">
            <option value="iepl">IEPL 专线</option>
            <option value="private">内网</option>
            <option value="public">公网</option>
          </select>
        </div>
        <div class="field">
          <label>优先级</label>
          <select v-model="epForm.priority">
            <option value="primary">主</option>
            <option value="backup">备</option>
          </select>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label>网卡（仅备注用）</label>
          <input v-model="epForm.interface" placeholder="eth1" />
        </div>
        <div class="field">
          <label>源 IP</label>
          <input v-model="epForm.source_ip" placeholder="10.20.0.1" />
          <div class="hint">由入口绑定，用于强制隧道走指定网卡。</div>
        </div>
      </div>
      <div class="field">
        <label>TLS 服务器名</label>
        <input v-model="epForm.tls_server_name" placeholder="exit.internal" />
        <div class="hint">
          一键对接的出口会自动使用签发的 TLS 名称。手动部署证书时，请填写证书中的名称。
        </div>
      </div>
      <div class="modal-actions">
        <button type="button" @click="showEndpointForm = false">取消</button>
        <button class="primary" type="submit">添加</button>
      </div>
    </form>
  </div>

  <InstallCommandModal
    v-if="install && detail"
    :data="install"
    :group-name="detail.group.name"
    @close="install = null"
  />
</template>

<style scoped>
.small { font-size: 11px; margin-top: 3px; }
.compact-lines { white-space: nowrap; line-height: 1.6; }
.usage-meter { position: relative; min-width: 92px; height: 24px; border-radius: 7px; background: var(--surface-3, #343944); overflow: hidden; }
.usage-meter > div { height: 100%; background: #7061bc; opacity: .75; }
.usage-meter > span { position: absolute; left: 8px; top: 2px; font-size: 12px; }
</style>
