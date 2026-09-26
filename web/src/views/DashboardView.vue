<script setup lang="ts">
import { onMounted, onUnmounted, ref, computed } from 'vue'
import { api, type DashboardDto } from '@/api'
import { useTelemetryStore } from '@/stores/telemetry'
import SparkChart from '@/components/SparkChart.vue'
import { bitrate, bytes, duration } from '@/format'

const telemetry = useTelemetryStore()
const stats = ref<DashboardDto | null>(null)
const error = ref<string | null>(null)

async function load() {
  try {
    stats.value = await api.get<DashboardDto>('/dashboard')
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

// WebSocket 推来的汇总比 REST 快照新几秒，且无需再发一次请求，所以优先用它。
const live = computed(() => telemetry.summary)

const nodesOnline = computed(() => live.value?.nodes_online ?? stats.value?.nodes_online ?? 0)
const nodesOffline = computed(() => stats.value?.nodes_offline ?? 0)
const tunnelsOnline = computed(() => live.value?.tunnels_online ?? stats.value?.tunnels_online ?? 0)
const tunnelsTotal = computed(() => live.value?.tunnels_total ?? stats.value?.tunnels_total ?? 0)
const connections = computed(() => live.value?.connections ?? stats.value?.connections ?? 0)
const rxBps = computed(() => live.value?.rx_bps ?? stats.value?.rx_bps ?? 0)
const txBps = computed(() => live.value?.tx_bps ?? stats.value?.tx_bps ?? 0)
</script>

<template>
  <h1>仪表盘</h1>

  <div v-if="error" class="banner banner-bad">{{ error }}</div>

  <div v-if="stats && stats.tunnel_routes_enabled > 0 && !stats.psk_configured" class="banner banner-warn">
    未配置隧道 PSK，隧道目前仅依赖 TLS 认证。建议在控制面配置中设置
    <code>tunnel_psk</code> 作为纵深防御 —— 证书签错或实验环境误开
    <code>insecure_skip_verify</code> 时，它仍能挡住未授权对端。
  </div>
  <div v-if="stats && !stats.production" class="banner banner-info">
    当前为开发模式。设置 <code>production = true</code> 可强制要求强密钥与私有 CA。
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">在线机器</div>
      <div class="card-value">{{ nodesOnline }}</div>
      <div class="card-sub">{{ nodesOffline }} 台离线</div>
    </div>
    <div v-if="stats?.tunnel_routes_enabled" class="card">
      <div class="card-label">健康隧道</div>
      <div class="card-value">{{ tunnelsOnline }} / {{ tunnelsTotal }}</div>
      <div class="card-sub">全集群</div>
    </div>
    <div class="card">
      <div class="card-label">启用线路</div>
      <div class="card-value">{{ stats?.routes_enabled ?? 0 }}</div>
      <div class="card-sub">共配置 {{ stats?.routes_total ?? 0 }} 条</div>
    </div>
    <div class="card">
      <div class="card-label">TCP 连接数</div>
      <div class="card-value">{{ connections }}</div>
      <div class="card-sub">正在转发</div>
    </div>
    <div class="card">
      <div class="card-label">接收</div>
      <div class="card-value">{{ bitrate(rxBps) }}</div>
      <div class="card-sub">累计 {{ bytes(stats?.total_rx_bytes ?? 0) }}</div>
    </div>
    <div class="card">
      <div class="card-label">发送</div>
      <div class="card-value">{{ bitrate(txBps) }}</div>
      <div class="card-sub">累计 {{ bytes(stats?.total_tx_bytes ?? 0) }}</div>
    </div>
  </div>

  <h2>吞吐</h2>
  <div class="card">
    <SparkChart :points="telemetry.series" mode="rate" />
  </div>

  <h2>连接数</h2>
  <div class="card">
    <SparkChart :points="telemetry.series" mode="count" />
  </div>

  <p class="dim" style="margin-top: 16px; font-size: 12px">
    控制面已运行 {{ duration(stats?.uptime_secs ?? 0) }} ·
    {{ telemetry.connected ? '实时数据流已连接' : '实时数据流正在重连' }}
  </p>
</template>
