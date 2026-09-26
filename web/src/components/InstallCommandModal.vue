<script setup lang="ts">
/**
 * 一键对接命令弹窗。
 *
 * 每条新命令带一个新令牌。明文只在签发时返回，原有机器的令牌继续有效。
 */
import { ref } from 'vue'
import type { InstallCommandDto } from '@/api'

const props = defineProps<{
  data: InstallCommandDto
  groupName: string
}>()
defineEmits<{ close: [] }>()

const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.data.command)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    // 非 HTTPS 下 clipboard API 不可用，退回手工选中。
    copied.value = false
  }
}
</script>

<template>
  <div class="modal-backdrop" @click.self="$emit('close')">
    <div class="modal">
      <h2>一键对接 —— {{ groupName }}</h2>

      <div class="banner banner-warn">
        <strong>命令中包含注册令牌，请立即复制。</strong>
        库中只存哈希，无法再次查看。每次打开本弹窗都会签发新令牌；
        已对接机器的令牌继续有效，不会因添加机器而断线。
      </div>

      <div v-if="data.warning" class="banner banner-bad">{{ data.warning }}</div>

      <div class="field">
        <label>在目标服务器上以 root 执行</label>
        <textarea
          readonly
          rows="4"
          class="mono"
          style="resize: vertical"
          :value="data.command"
          @click="($event.target as HTMLTextAreaElement).select()"
        ></textarea>
      </div>

      <div class="toolbar">
        <button class="primary" @click="copy">
          {{ copied ? '已复制' : '复制命令' }}
        </button>
        <span v-if="data.panel_url" class="dim" style="font-size: 12px">
          面板地址：{{ data.panel_url }}
        </span>
      </div>

      <h2 style="font-size: 14px; margin-top: 18px">执行后会做什么</h2>
      <ul class="dim" style="font-size: 12px; line-height: 1.8; padding-left: 20px">
        <li>下载并安装 tunnel-agent，写出 <code>/etc/tunnel-agent/config.toml</code>（权限 0600）</li>
        <li>安装并启动 systemd 服务，agent 自行向本组注册</li>
        <li>
          询问是否应用网络优化。<strong>改动前会逐项打印当前值与目标值</strong>，
          且只会修改低风险项（somaxconn / BBR / fq / LimitNOFILE）；
          <code>tcp_rmem</code> 这类按连接数放大的参数仅提示不改
        </li>
      </ul>

      <div class="banner banner-info" style="margin-top: 14px">
        出口机器还需要放置 TLS 证书到 <code>/etc/tunnel/</code>，并在本组详情页为该
        机器添加「隧道地址」，入口才知道该拨向哪里。<br />
        <strong>IEPL 双网卡主机</strong>请先按 <code>docs/networking-iepl.md</code>
        配置策略路由与 rp_filter —— 未配置时的故障表现是「连接建立不起来且日志无异常」。
      </div>

      <div class="modal-actions">
        <button @click="$emit('close')">关闭</button>
      </div>
    </div>
  </div>
</template>
