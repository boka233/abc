/** Session store. */

import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, getToken, setToken } from '@/api'

interface LoginResponse {
  token: string
  expires_in_secs: number
  username: string
  role: string
  must_change_password: boolean
}

interface MeResponse {
  user_id: string
  username: string
  role: string
  must_change_password: boolean
}

export const useAuthStore = defineStore('auth', () => {
  const username = ref<string | null>(null)
  const role = ref<string | null>(null)
  /**
   * Set when the account still carries its generated first-run password. The
   * server refuses mutating requests until it is rotated, so the UI surfaces a
   * banner rather than letting the user hit unexplained 403s.
   */
  const mustChangePassword = ref(false)
  const ready = ref(false)

  function isAuthenticated(): boolean {
    return getToken() !== null
  }

  async function login(user: string, password: string): Promise<void> {
    const result = await api.post<LoginResponse>('/auth/login', {
      username: user,
      password,
    })
    setToken(result.token)
    username.value = result.username
    role.value = result.role
    mustChangePassword.value = result.must_change_password
  }

  /** Validate an existing token on page load. */
  async function restore(): Promise<boolean> {
    if (!getToken()) {
      ready.value = true
      return false
    }
    try {
      const me = await api.get<MeResponse>('/auth/me')
      username.value = me.username
      role.value = me.role
      mustChangePassword.value = me.must_change_password
      return true
    } catch {
      // Expired or revoked; api.ts has already cleared the token.
      username.value = null
      role.value = null
      return false
    } finally {
      ready.value = true
    }
  }

  async function changePassword(current: string, next: string): Promise<void> {
    await api.post('/auth/password', {
      current_password: current,
      new_password: next,
    })
    mustChangePassword.value = false
  }

  function logout(): void {
    setToken(null)
    username.value = null
    role.value = null
    mustChangePassword.value = false
  }

  return {
    username,
    role,
    mustChangePassword,
    ready,
    isAuthenticated,
    login,
    restore,
    changePassword,
    logout,
  }
})
