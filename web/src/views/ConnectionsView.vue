<script setup lang="ts">
import { computed, ref } from 'vue'
import { useTelemetryStore } from '@/stores/telemetry'
import { bytes, duration } from '@/format'

const telemetry = useTelemetryStore()
const filter = ref('')

/**
 * agent 上报的是活动连接的**采样**，不是完整表。1 万并发时完整列表意味着每几秒
 * 一个几 MB 的上报，而且没人会去读 1 万行。
 */
const rows = computed(() => {
  const q = filter.value.trim().toLowerCase()
  const all = telemetry.connections
  if (!q) return all
  return all.filter(
    (c) =>
      c.route_name.toLowerCase().includes(q) ||
      c.client_addr.toLowerCase().includes(q) ||
      c.target.toLowerCase().includes(q),
  )
})
</script>

<template>
  <h1>连接</h1>

  <div class="banner banner-info">
    这是各 agent 上报的采样，不是完整连接表 —— 高并发下完整列表既读不完也不划算传输。
  </div>

  <div class="toolbar">
    <input v-model="filter" placeholder="按线路、客户端或目标过滤" style="max-width: 320px" />
    <span class="spacer"></span>
    <span class="dim">显示 {{ rows.length }} 条</span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>线路</th><th>客户端</th><th>目标</th>
          <th class="num">隧道</th><th class="num">流 ID</th>
          <th class="num">接收</th><th class="num">发送</th>
          <th class="num">存活</th><th class="num">空闲</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="c in rows" :key="`${c.tunnel_id}-${c.id}`">
          <td>{{ c.route_name }}</td>
          <td class="mono">{{ c.client_addr }}</td>
          <td class="mono">{{ c.target }}</td>
          <td class="num mono">#{{ c.tunnel_id }}</td>
          <td class="num mono">{{ c.stream_id }}</td>
          <td class="num">{{ bytes(c.rx_bytes) }}</td>
          <td class="num">{{ bytes(c.tx_bytes) }}</td>
          <td class="num">{{ duration(c.age_secs) }}</td>
          <td class="num">{{ duration(c.idle_secs) }}</td>
        </tr>
        <tr v-if="!rows.length">
          <td colspan="9" class="empty">暂无连接上报。</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
