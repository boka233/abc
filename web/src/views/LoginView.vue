<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/api'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const username = ref('')
const password = ref('')
const error = ref<string | null>(null)
const busy = ref(false)

async function submit() {
  error.value = null
  busy.value = true
  try {
    await auth.login(username.value, password.value)
    const target = (route.query.redirect as string) || '/dashboard'
    await router.push(target)
  } catch (e) {
    // 服务端不区分「用户不存在」与「密码错误」，这里的提示也不区分。
    error.value = e instanceof ApiError ? e.message : '无法连接控制面'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <form class="card login-card" @submit.prevent="submit">
      <h1 style="margin-bottom: 18px">隧道中转管理</h1>

      <div v-if="error" class="banner banner-bad">{{ error }}</div>

      <div class="field">
        <label for="u">用户名</label>
        <input id="u" v-model="username" autocomplete="username" autofocus required />
      </div>
      <div class="field">
        <label for="p">密码</label>
        <input
          id="p"
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
        />
      </div>

      <button class="primary" type="submit" :disabled="busy" style="width: 100%">
        {{ busy ? '登录中…' : '登录' }}
      </button>
    </form>
  </div>
</template>
