<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { api, type DailyTrafficDto, type NodeDto, type TrafficPoint } from '@/api'
import SparkChart from '@/components/SparkChart.vue'
import { bitrate, bytes, timestamp } from '@/format'

const points = ref<TrafficPoint[]>([])
const nodes = ref<NodeDto[]>([])
const minutes = ref(60)
const nodeId = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const today = new Date()
const dailyDate = ref(
  `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`,
)
const daily = ref<DailyTrafficDto | null>(null)
const dailyError = ref<string | null>(null)
const dailyBusy = ref(false)

async function loadDaily() {
  dailyBusy.value = true
  try {
    const params = new URLSearchParams({
      date: dailyDate.value,
      utc_offset_minutes: String(-new Date().getTimezoneOffset()),
    })
    daily.value = await api.get<DailyTrafficDto>(`/traffic/daily?${params}`)
    dailyError.value = null
  } catch (e) {
    daily.value = null
    dailyError.value = e instanceof Error ? e.message : String(e)
  } finally {
    dailyBusy.value = false
  }
}

async function load() {
  busy.value = true
  try {
    const params = new URLSearchParams({ minutes: String(minutes.value) })
    if (nodeId.value) params.set('node_id', nodeId.value)
    const result = await api.get<{ series: TrafficPoint[] }>(`/traffic?${params}`)
    points.value = result.series
    error.value = null
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

onMounted(async () => {
  void loadDaily()
  const n = await api.get<{ nodes: NodeDto[] }>('/nodes')
  nodes.value = n.nodes
  await load()
})

// 把历史行映射成图表组件的数据形状，复用仪表盘的曲线实现。
const series = computed(() =>
  points.value.map((p) => ({
    t: new Date(p.bucket_at).getTime(),
    rx: p.rx_bps,
    tx: p.tx_bps,
    connections: p.connections,
  })),
)

const latest = computed(() => points.value[points.value.length - 1] ?? null)
</script>

<template>
  <h1>流量</h1>
  <div v-if="error" class="banner banner-bad">{{ error }}</div>

  <h2>每日线路流量</h2>
  <div v-if="dailyError" class="banner banner-bad">{{ dailyError }}</div>
  <div class="toolbar">
    <label for="daily-traffic-date">日期</label>
    <input
      id="daily-traffic-date"
      v-model="dailyDate"
      type="date"
      style="max-width: 180px"
      @change="loadDaily"
    />
    <button class="sm" :disabled="dailyBusy" @click="loadDaily">刷新</button>
    <span class="spacer"></span>
    <span class="dim">按浏览器本地时区统计</span>
  </div>
  <div v-if="daily" class="grid" style="margin-bottom: 16px">
    <div class="card">
      <div class="card-label">当天总流量</div>
      <div class="card-value">{{ bytes(daily.total_bytes) }}</div>
      <div class="card-sub">接收 + 发送，{{ daily.routes.length }} 条线路有流量</div>
    </div>
    <div class="card">
      <div class="card-label">当天接收</div>
      <div class="card-value">{{ bytes(daily.rx_bytes) }}</div>
    </div>
    <div class="card">
      <div class="card-label">当天发送</div>
      <div class="card-value">{{ bytes(daily.tx_bytes) }}</div>
    </div>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>线路</th><th class="num">接收</th><th class="num">发送</th><th class="num">总流量</th></tr>
      </thead>
      <tbody>
        <tr v-for="route in daily?.routes ?? []" :key="route.route_id">
          <td>{{ route.route_name }}</td>
          <td class="num">{{ bytes(route.rx_bytes) }}</td>
          <td class="num">{{ bytes(route.tx_bytes) }}</td>
          <td class="num">{{ bytes(route.rx_bytes + route.tx_bytes) }}</td>
        </tr>
        <tr v-if="daily && !daily.routes.length">
          <td colspan="4" class="empty">当天暂无已采样的转发流量。</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="dim" style="font-size: 12px">
    每天的流量由入口线路累计计数器的相邻采样增量计算。首次采样仅作基线；重启或采样中断期间的流量可能无法完整还原。历史保留期限由「设置」决定。
  </p>

  <div class="toolbar">
    <select v-model="nodeId" style="max-width: 200px" @change="load">
      <option value="">全部机器</option>
      <option v-for="n in nodes" :key="n.id" :value="n.id">
        {{ n.group_name ? n.group_name + ' / ' : '' }}{{ n.name }}
      </option>
    </select>
    <select v-model.number="minutes" style="max-width: 160px" @change="load">
      <option :value="15">最近 15 分钟</option>
      <option :value="60">最近 1 小时</option>
      <option :value="360">最近 6 小时</option>
      <option :value="1440">最近 24 小时</option>
      <option :value="10080">最近 7 天</option>
    </select>
    <button class="sm" :disabled="busy" @click="load">刷新</button>
    <span class="spacer"></span>
    <span class="dim">{{ points.length }} 个采样点</span>
  </div>

  <div v-if="latest" class="grid" style="margin-bottom: 16px">
    <div class="card">
      <div class="card-label">最新接收</div>
      <div class="card-value">{{ bitrate(latest.rx_bps) }}</div>
    </div>
    <div class="card">
      <div class="card-label">最新发送</div>
      <div class="card-value">{{ bitrate(latest.tx_bps) }}</div>
    </div>
    <div class="card">
      <div class="card-label">累计接收</div>
      <div class="card-value">{{ bytes(latest.rx_bytes) }}</div>
    </div>
    <div class="card">
      <div class="card-label">累计发送</div>
      <div class="card-value">{{ bytes(latest.tx_bytes) }}</div>
    </div>
  </div>

  <h2>吞吐</h2>
  <div class="card">
    <SparkChart :points="series" mode="rate" />
    <div v-if="latest" class="dim" style="font-size: 12px; margin-top: 8px">
      最新采样时间：{{ timestamp(latest.bucket_at) }}
    </div>
  </div>

  <h2>连接数</h2>
  <div class="card">
    <SparkChart :points="series" mode="count" />
  </div>

  <p class="dim" style="font-size: 12px; margin-top: 14px">
    采样由控制面按固定间隔聚合写入 —— 数据面只在内存里累加计数器，转发路径上从不
    写数据库。接收、发送是转发的应用数据方向，不是 VPS 网卡总流量。
  </p>
</template>
