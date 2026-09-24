<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type AuditRow } from '@/api'
import { timestamp } from '@/format'

const entries = ref<AuditRow[]>([])
const actionFilter = ref('')
const error = ref<string | null>(null)

async function load() {
  try {
    const params = new URLSearchParams({ limit: '200' })
    if (actionFilter.value) params.set('action', actionFilter.value)
    const result = await api.get<{ entries: AuditRow[] }>(`/logs/audit?${params}`)
    entries.value = result.entries
    error.value = null
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

onMounted(load)
</script>

<template>
  <h1>审计日志</h1>
  <div v-if="error" class="banner banner-bad">{{ error }}</div>

  <div class="banner banner-info">
    仅追加，不可编辑。详情字段在落库前按字段名清洗，令牌与 PSK 不会进入本表。
  </div>

  <div class="toolbar">
    <select v-model="actionFilter" style="max-width: 200px" @change="load">
      <option value="">全部操作</option>
      <option value="auth">登录认证</option>
      <option value="group">设备组</option>
      <option value="node">机器</option>
      <option value="endpoint">隧道地址</option>
      <option value="route">线路</option>
      <option value="agent">agent 注册</option>
      <option value="user">用户</option>
      <option value="settings">设置</option>
    </select>
    <button class="sm" @click="load">刷新</button>
    <span class="spacer"></span>
    <span class="dim">{{ entries.length }} 条</span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>时间</th><th>操作者</th><th>操作</th><th>对象</th>
          <th>来源 IP</th><th>结果</th><th>详情</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in entries" :key="e.id">
          <td class="dim">{{ timestamp(e.at) }}</td>
          <td>{{ e.username ?? 'agent' }}</td>
          <td class="mono">{{ e.action }}</td>
          <td>
            <span v-if="e.target_name">{{ e.target_name }}</span>
            <span v-else class="dim">—</span>
            <span v-if="e.target_type" class="dim">（{{ e.target_type }}）</span>
          </td>
          <td class="mono dim">{{ e.source_ip ?? '—' }}</td>
          <td>
            <span :class="e.success ? 'pill pill-ok' : 'pill pill-bad'">
              {{ e.success ? '成功' : '失败' }}
            </span>
          </td>
          <td class="mono dim" style="max-width: 280px; overflow: hidden; text-overflow: ellipsis">
            {{ e.detail_json ?? '' }}
          </td>
        </tr>
        <tr v-if="!entries.length">
          <td colspan="7" class="empty">暂无审计记录。</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
