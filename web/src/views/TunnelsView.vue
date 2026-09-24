<script setup lang="ts">
import { computed } from 'vue'
import { useTelemetryStore } from '@/stores/telemetry'
import { bytes, duration, rtt, statusClass } from '@/format'

// 全部数据来自实时流：隧道状态本身是瞬时的，从不落库，所以没有可拉取的历史。
const telemetry = useTelemetryStore()

const rows = computed(() =>
  telemetry.tunnels.map((t) => ({
    ...t,
    node_name: t.node_id ? (telemetry.nodeNames[t.node_id] ?? t.node_id) : '—',
  })),
)

function stateLabel(state: string): string {
  switch (state) {
    case 'online':
      return '在线'
    case 'connecting':
      return '连接中'
    case 'degraded':
      return '降级'
    default:
      return '离线'
  }
}
</script>

<template>
  <h1>隧道</h1>

  <div v-if="!telemetry.connected" class="banner banner-warn">
    实时数据流正在重连。隧道状态不落库，因此在恢复前本表为空。
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>隧道</th><th>机器</th><th>端点</th><th>类型</th><th>状态</th>
          <th class="num">流数</th><th class="num">RTT</th>
          <th class="num">接收</th><th class="num">发送</th>
          <th class="num">已连接</th><th class="num">重连次数</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in rows" :key="`${t.node_id}-${t.tunnel_id}`">
          <td class="mono">#{{ t.tunnel_id }}</td>
          <td class="dim">{{ t.node_name }}</td>
          <td>{{ t.endpoint_name }}</td>
          <td><span class="pill pill-info">{{ t.endpoint_kind }}</span></td>
          <td><span :class="statusClass(t.state)">{{ stateLabel(t.state) }}</span></td>
          <td class="num">{{ t.streams }}</td>
          <td class="num">{{ rtt(t.rtt_ms) }}</td>
          <td class="num">{{ bytes(t.rx_bytes) }}</td>
          <td class="num">{{ bytes(t.tx_bytes) }}</td>
          <td class="num">{{ duration(t.established_secs) }}</td>
          <td class="num">{{ t.reconnects }}</td>
        </tr>
        <tr v-if="!rows.length">
          <td colspan="11" class="empty">暂无隧道上报。</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
