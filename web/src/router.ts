import { createRouter, createWebHistory } from 'vue-router'
import { getToken, setUnauthorizedHandler } from '@/api'

/**
 * 视图按需加载，登录页不会把整个面板的代码一起拉下来。
 *
 * 导航层级刻意只有两级实体：**设备组**（机器的集合）与**线路**（转发规则）。
 * 隧道地址收在设备组详情页里 —— 它是出口机器的属性，不是和这两者平级的概念。
 */
export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { public: true } },
    { path: '/', redirect: '/dashboard' },
    { path: '/dashboard', name: 'dashboard', component: () => import('@/views/DashboardView.vue') },
    { path: '/groups', name: 'groups', component: () => import('@/views/GroupsView.vue') },
    { path: '/groups/:id', name: 'group-detail', component: () => import('@/views/GroupDetailView.vue') },
    { path: '/routes', name: 'routes', component: () => import('@/views/RoutesView.vue') },
    { path: '/tunnels', name: 'tunnels', component: () => import('@/views/TunnelsView.vue') },
    { path: '/connections', name: 'connections', component: () => import('@/views/ConnectionsView.vue') },
    { path: '/traffic', name: 'traffic', component: () => import('@/views/TrafficView.vue') },
    { path: '/logs', name: 'logs', component: () => import('@/views/LogsView.vue') },
    { path: '/settings', name: 'settings', component: () => import('@/views/SettingsView.vue') },
    // 旧路径重定向，避免书签失效。
    { path: '/nodes', redirect: '/groups' },
    { path: '/endpoints', redirect: '/groups' },
    // 未知的客户端路径回到仪表盘，而不是白屏。
    { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
  ],
})

router.beforeEach((to) => {
  const authenticated = getToken() !== null
  if (!to.meta.public && !authenticated) {
    // 记住原本要去的位置，登录后送回去。
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.name === 'login' && authenticated) {
    return { name: 'dashboard' }
  }
  return true
})

// 任何请求返回 401 都会走到这里，避免会话过期后页面还显示着旧数据。
setUnauthorizedHandler(() => {
  if (router.currentRoute.value.name !== 'login') {
    void router.push({ name: 'login' })
  }
})
