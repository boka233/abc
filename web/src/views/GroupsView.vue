<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, type DeviceGroupDto, type InstallCommandDto } from '@/api'
import { useTelemetryStore } from '@/stores/telemetry'
import { bitrate } from '@/format'
import InstallCommandModal from '@/components/InstallCommandModal.vue'

const telemetry = useTelemetryStore()
const groups = ref<DeviceGroupDto[]>([])
const error = ref<string | null>(null)
const showCreate = ref(false)
const install = ref<InstallCommandDto | null>(null)
const installGroupName = ref('')

const form = ref({
  name: '',
  region: '',
  kind: 'outbound',
  note: '',
})

async function load() {
  try {
    const result = await api.get<{ groups: DeviceGroupDto[] }>('/groups')
    groups.value = result.groups
    error.value = null
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

onMounted(load)
// 服务端广播配置变更时重新拉取。
watch(() => telemetry.configGeneration, load)

async function create() {
  try {
    const result = await api.post<{
      group: DeviceGroupDto
      install_command: string
      enroll_token: string
    }>('/groups', {
      name: form.value.name,
      region: form.value.region,
      kind: form.value.kind,
      note: form.value.note || null,
    })
    showCreate.value = false
    installGroupName.value = result.group.name
    // 建组后直接把一键对接命令弹出来 —— 这是用户接下来必然要做的事。
    install.value = {
      command: result.install_command,
      panel_url: '',
      warning: null,
    }
    form.value = { name: '', region: '', kind: 'outbound', note: '' }
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function showInstall(group: DeviceGroupDto) {
  try {
    install.value = await api.get<InstallCommandDto>(
      `/groups/${group.id}/install-command`,
    )
    installGroupName.value = group.name
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function toggle(group: DeviceGroupDto) {
  try {
    await api.patch(`/groups/${group.id}`, { enabled: !group.enabled })
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function remove(group: DeviceGroupDto) {
  if (
    !confirm(
      `删除设备组「${group.name}」？组内 ${group.nodes_total} 台机器的记录会一并删除。`,
    )
  )
    return
  try {
    await api.delete(`/groups/${group.id}`)
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function kindClass(kind: string): string {
  if (kind === 'inbound') return 'pill pill-info'
  if (kind === 'outbound') return 'pill pill-ok'
  return 'pill pill-warn'
}
</script>

<template>
  <h1>设备组</h1>
  <div v-if="error" class="banner banner-bad">{{ error }}</div>

  <div class="banner banner-info">
    设备组是入口或出口机器的集合。<strong>注册令牌挂在组上</strong>，所以同一条
    「一键对接」命令可以在多台机器上执行，它们会自动加入同一个组并领到相同的线路
    配置。换机器、加机器都不需要改动线路。
  </div>

  <div class="toolbar">
    <button class="primary" @click="showCreate = true">新建设备组</button>
    <span class="spacer"></span>
    <button class="sm" @click="load">刷新</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>名称</th><th>类型</th><th>地区</th>
          <th class="num">机器</th><th class="num">连接数</th>
          <th class="num">下行</th><th class="num">上行</th>
          <th>状态</th><th>备注</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="g in groups" :key="g.id">
          <td><RouterLink :to="`/groups/${g.id}`">{{ g.name }}</RouterLink></td>
          <td><span :class="kindClass(g.kind)">{{ g.kind_label }}</span></td>
          <td class="dim">{{ g.region || '—' }}</td>
          <td class="num">
            <span :class="g.nodes_online > 0 ? 'pill pill-ok' : 'pill pill-bad'">
              {{ g.nodes_online }}/{{ g.nodes_total }}
            </span>
          </td>
          <td class="num">{{ g.connections ?? 0 }}</td>
          <td class="num">{{ bitrate(g.rx_bps ?? 0) }}</td>
          <td class="num">{{ bitrate(g.tx_bps ?? 0) }}</td>
          <td>
            <span :class="g.enabled ? 'pill pill-ok' : 'pill pill-bad'">
              {{ g.enabled ? '启用' : '停用' }}
            </span>
          </td>
          <td class="dim">{{ g.note || '—' }}</td>
          <td style="white-space: nowrap">
            <button class="sm" @click="showInstall(g)">一键对接</button>
            <button class="sm" @click="toggle(g)">{{ g.enabled ? '停用' : '启用' }}</button>
            <button class="sm danger" @click="remove(g)">删除</button>
          </td>
        </tr>
        <tr v-if="!groups.length">
          <td colspan="10" class="empty">
            还没有设备组。先建一个入口组和一个出口组，再用「一键对接」把机器加进来。
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- 新建设备组 -->
  <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
    <form class="modal" @submit.prevent="create">
      <h2>新建设备组</h2>
      <div class="field">
        <label>名称</label>
        <input v-model="form.name" required placeholder="香港出口" />
      </div>
      <div class="field-row">
        <div class="field">
          <label>类型</label>
          <select v-model="form.kind">
            <option value="inbound">入口 —— 接受用户连接并拨隧道</option>
            <option value="outbound">出口 —— 终结隧道并拨目标</option>
            <option value="both">入口+出口 —— 两者兼任</option>
          </select>
          <div class="hint">
            类型决定组内机器的角色。已被线路引用的组不能再改类型。
          </div>
        </div>
        <div class="field">
          <label>地区</label>
          <input v-model="form.region" placeholder="hk" />
        </div>
      </div>
      <div class="field">
        <label>备注</label>
        <input v-model="form.note" placeholder="可选" />
      </div>
      <div class="modal-actions">
        <button type="button" @click="showCreate = false">取消</button>
        <button class="primary" type="submit">创建</button>
      </div>
    </form>
  </div>

  <InstallCommandModal
    v-if="install"
    :data="install"
    :group-name="installGroupName"
    @close="install = null"
  />
</template>
