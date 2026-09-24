<script setup lang="ts">
import { onMounted, computed, watch } from 'vue'
import { RouterView, useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useTelemetryStore } from '@/stores/telemetry'

const auth = useAuthStore()
const telemetry = useTelemetryStore()
const route = useRoute()
const router = useRouter()

const isLogin = computed(() => route.name === 'login')

const nav = [
  { name: 'dashboard', label: '仪表盘', path: '/dashboard' },
  { name: 'groups', label: '设备组', path: '/groups' },
  { name: 'routes', label: '线路', path: '/routes' },
  { name: 'tunnels', label: '隧道', path: '/tunnels' },
  { name: 'connections', label: '连接', path: '/connections' },
  { name: 'traffic', label: '流量', path: '/traffic' },
  { name: 'logs', label: '日志', path: '/logs' },
  { name: 'settings', label: '设置', path: '/settings' },
]

onMounted(async () => {
  const ok = await auth.restore()
  if (ok) telemetry.connect()
})

// Open the telemetry stream once authenticated, close it on logout.
watch(
  () => auth.username,
  (value) => {
    if (value) telemetry.connect()
    else telemetry.disconnect()
  },
)

function logout() {
  telemetry.disconnect()
  auth.logout()
  void router.push({ name: 'login' })
}
</script>

<template>
  <RouterView v-if="isLogin" />

  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">隧道中转管理</div>
      <nav class="nav">
        <RouterLink
          v-for="item in nav"
          :key="item.name"
          :to="{ name: item.name }"
          :class="{ active: route.path.startsWith(item.path) }"
        >
          {{ item.label }}
        </RouterLink>
      </nav>
      <div class="sidebar-footer">
        <div>
          <span class="dot" :class="telemetry.connected ? 'dot-ok' : 'dot-bad'"></span>
          {{ telemetry.connected ? '实时连接正常' : '正在重连' }}
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="dim">{{ auth.role === 'admin' ? '管理员' : (auth.role ?? '') }}</div>
        <div class="toolbar" style="margin: 0">
          <span class="dim">{{ auth.username ?? '' }}</span>
          <button class="sm" @click="logout">退出登录</button>
        </div>
      </header>

      <main class="content">
        <!-- 未改密前服务端会拒绝所有写操作，这里直接说明，避免用户撞上无解释的 403。 -->
        <div v-if="auth.mustChangePassword" class="banner banner-warn">
          当前账号仍在使用初始密码，请前往
          <RouterLink :to="{ name: 'settings' }">设置</RouterLink>
          修改 —— 在此之前所有配置变更都会被拒绝。
        </div>
        <RouterView />
      </main>
    </div>
  </div>
</template>
