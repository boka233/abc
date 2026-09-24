<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'

interface EffectiveSettings {
  node_stale_secs: number
  traffic_retention_days: number
  audit_retention_days: number
  stats_interval_secs: number
}

interface Deployment {
  listen: string
  production: boolean
  psk_configured: boolean
  agent_heartbeat_secs: number
  stale_after_secs: number
  tls_ca_configured: boolean
  mtls_required: boolean
}

const auth = useAuthStore()
const settings = ref<EffectiveSettings | null>(null)
const deployment = ref<Deployment | null>(null)
const error = ref<string | null>(null)
const saved = ref(false)

const pw = ref({ current: '', next: '', confirm: '' })
const pwError = ref<string | null>(null)
const pwSaved = ref(false)

async function load() {
  try {
    const result = await api.get<{ settings: EffectiveSettings; deployment: Deployment }>('/settings')
    settings.value = result.settings
    deployment.value = result.deployment
    error.value = null
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

onMounted(load)

async function save() {
  if (!settings.value) return
  saved.value = false
  try {
    await api.patch('/settings', settings.value)
    saved.value = true
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function changePassword() {
  pwError.value = null
  pwSaved.value = false
  if (pw.value.next !== pw.value.confirm) {
    pwError.value = '两次输入的新密码不一致'
    return
  }
  try {
    await auth.changePassword(pw.value.current, pw.value.next)
    pw.value = { current: '', next: '', confirm: '' }
    pwSaved.value = true
  } catch (e) {
    pwError.value = e instanceof Error ? e.message : String(e)
  }
}
</script>

<template>
  <h1>设置</h1>
  <div v-if="error" class="banner banner-bad">{{ error }}</div>
  <div v-if="saved" class="banner banner-info">设置已保存。</div>

  <h2>修改密码</h2>
  <div class="card" style="max-width: 420px">
    <div v-if="pwError" class="banner banner-bad">{{ pwError }}</div>
    <div v-if="pwSaved" class="banner banner-info">密码已修改。</div>
    <form @submit.prevent="changePassword">
      <div class="field">
        <label>当前密码</label>
        <input v-model="pw.current" type="password" autocomplete="current-password" required />
      </div>
      <div class="field">
        <label>新密码</label>
        <input v-model="pw.next" type="password" autocomplete="new-password" required minlength="12" />
        <div class="hint">至少 12 个字符。</div>
      </div>
      <div class="field">
        <label>确认新密码</label>
        <input v-model="pw.confirm" type="password" autocomplete="new-password" required />
      </div>
      <button class="primary" type="submit">修改密码</button>
    </form>
  </div>

  <h2>运行时设置</h2>
  <div v-if="settings" class="card" style="max-width: 560px">
    <div class="field-row">
      <div class="field">
        <label>机器离线判定阈值（秒）</label>
        <input v-model.number="settings.node_stale_secs" type="number" min="10" max="3600" />
        <div class="hint">必须大于心跳间隔的两倍，否则机器状态会反复跳变。</div>
      </div>
      <div class="field">
        <label>流量聚合间隔（秒）</label>
        <input v-model.number="settings.stats_interval_secs" type="number" min="1" max="300" />
      </div>
    </div>
    <div class="field-row">
      <div class="field">
        <label>流量数据保留（天）</label>
        <input v-model.number="settings.traffic_retention_days" type="number" min="1" max="3650" />
      </div>
      <div class="field">
        <label>审计日志保留（天）</label>
        <input v-model.number="settings.audit_retention_days" type="number" min="1" max="3650" />
      </div>
    </div>
    <button class="primary" @click="save">保存</button>
  </div>

  <h2>部署信息</h2>
  <div v-if="deployment" class="card" style="max-width: 560px">
    <p class="dim" style="margin-top: 0; font-size: 12px">
      只读。这些值来自控制面的配置文件 —— 可能把管理员锁在面板外的设置，不应该能从
      面板里改。
    </p>
    <table>
      <tbody>
        <tr><td>监听地址</td><td class="mono">{{ deployment.listen }}</td></tr>
        <tr>
          <td>运行模式</td>
          <td>
            <span :class="deployment.production ? 'pill pill-ok' : 'pill pill-warn'">
              {{ deployment.production ? '生产' : '开发' }}
            </span>
          </td>
        </tr>
        <tr>
          <td>隧道 PSK</td>
          <td>
            <span :class="deployment.psk_configured ? 'pill pill-ok' : 'pill pill-warn'">
              {{ deployment.psk_configured ? '已配置' : '未设置' }}
            </span>
          </td>
        </tr>
        <tr>
          <td>私有 CA</td>
          <td>
            <span :class="deployment.tls_ca_configured ? 'pill pill-ok' : 'pill pill-warn'">
              {{ deployment.tls_ca_configured ? '已配置' : '使用系统信任库' }}
            </span>
          </td>
        </tr>
        <tr>
          <td>双向认证 mTLS</td>
          <td>
            <span :class="deployment.mtls_required ? 'pill pill-ok' : 'pill pill-info'">
              {{ deployment.mtls_required ? '要求' : '不要求' }}
            </span>
          </td>
        </tr>
        <tr><td>agent 心跳间隔</td><td>{{ deployment.agent_heartbeat_secs }} 秒</td></tr>
      </tbody>
    </table>
  </div>
</template>
