<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { api, type NodeDto, type TrafficPoint } from '@/api'
import SparkChart from '@/components/SparkChart.vue'
import { bitrate, bytes, timestamp } from '@/format'

const points = ref<TrafficPoint[]>([])
const nodes = ref<NodeDto[]>([])
const minutes = ref(60)
const nodeId = ref('')
const error = ref<string | null>(null)
const busy = ref(false)


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
      <div class="card-label">最新下行</div>
      <div class="card-value">{{ bitrate(latest.rx_bps) }}</div>
    </div>
    <div class="card">
      <div class="card-label">最新上行</div>
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
    写数据库。
  </p>
</template>
