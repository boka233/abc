/**
 * Live telemetry store, fed by the WebSocket.
 *
 * Incremental by design: a node report replaces only that node's entry. The
 * requirement is explicit about this — no full-page refresh on a timer, because
 * re-rendering the whole fleet every second is both wasteful and visibly janky.
 *
 * Reconnection uses exponential backoff with jitter, for the same reason the
 * agent does: when the control plane restarts, every open tab tries to reconnect
 * at once.
 */

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { getToken, type ConnectionDto, type TunnelDto } from '@/api'

export interface FleetSummary {
  nodes_online: number
  nodes_offline: number
  nodes_degraded: number
  routes_total: number
  routes_enabled: number
  tunnels_online: number
  tunnels_total: number
  connections: number
  rx_bps: number
  tx_bps: number
  total_rx_bytes: number
  total_tx_bytes: number
}

export interface NodeReport {
  node_id: string
  agent_version: string
  config_revision: number
  connections: number
  rx_bps: number
  tx_bps: number
  rx_bytes: number
  tx_bytes: number
  host: {
    cpu_percent: number
    memory_used_bytes: number
    memory_total_bytes: number
    uptime_secs: number
    host_uptime_secs: number
    disk_used_bytes: number
    disk_total_bytes: number
  }
  interfaces: Array<{ name: string; addresses: string[]; is_loopback: boolean }>
  tunnels: TunnelDto[]
  connection_samples: ConnectionDto[]
  routes: Array<{
    route_id: string
    connections: number
    rx_bps: number
    tx_bps: number
    tunnels_online: number
    tunnels_total: number
  }>
}

/** Points retained per series. At a 2s summary cadence this is ~10 minutes. */
const MAX_SERIES_POINTS = 300

export interface SeriesPoint {
  t: number
  rx: number
  tx: number
  connections: number
}

export const useTelemetryStore = defineStore('telemetry', () => {
  const connected = ref(false)
  const summary = ref<FleetSummary | null>(null)
  const nodeReports = ref<Record<string, NodeReport>>({})
  const nodeNames = ref<Record<string, string>>({})
  const series = ref<SeriesPoint[]>([])
  /** Incremented when the server says configuration changed, so views refetch. */
  const configGeneration = ref(0)
  const lastError = ref<string | null>(null)

  let socket: WebSocket | null = null
  let reconnectTimer: number | null = null
  let attempt = 0
  let closing = false

  const tunnels = computed<TunnelDto[]>(() =>
    Object.values(nodeReports.value).flatMap((report) =>
      report.tunnels.map((t) => ({ ...t, node_id: report.node_id })),
    ),
  )

  const connections = computed<ConnectionDto[]>(() =>
    Object.values(nodeReports.value)
      .flatMap((r) => r.connection_samples ?? [])
      .sort((a, b) => b.age_secs - a.age_secs),
  )

  function pushSeries(s: FleetSummary): void {
    series.value.push({
      t: Date.now(),
      rx: s.rx_bps,
      tx: s.tx_bps,
      connections: s.connections,
    })
    // Bounded: an always-open dashboard tab would otherwise grow without limit.
    if (series.value.length > MAX_SERIES_POINTS) {
      series.value.splice(0, series.value.length - MAX_SERIES_POINTS)
    }
  }

  function handleMessage(raw: string): void {
    let event: Record<string, unknown>
    try {
      event = JSON.parse(raw)
    } catch {
      return
    }

    switch (event.type) {
      case 'summary': {
        // The server sends Summary(Box<FleetSummary>), which flattens the fields
        // alongside `type`.
        const { type: _t, ...fields } = event
        const s = fields as unknown as FleetSummary
        summary.value = s
        pushSeries(s)
        break
      }
      case 'node_report': {
        const id = event.node_id as string
        const name = event.node_name as string
        if (id) {
          // Replace only this node: that is what makes the update incremental.
          nodeReports.value = {
            ...nodeReports.value,
            [id]: event.report as unknown as NodeReport,
          }
          if (name) nodeNames.value[id] = name
        }
        break
      }
      case 'node_offline': {
        const id = event.node_id as string
        if (id && nodeReports.value[id]) {
          const next = { ...nodeReports.value }
          delete next[id]
          nodeReports.value = next
        }
        break
      }
      case 'config_changed':
        configGeneration.value += 1
        break
      case 'lagged':
        // This tab fell behind and lost events. Force a refetch rather than
        // showing data we know is incomplete.
        configGeneration.value += 1
        break
    }
  }

  function scheduleReconnect(): void {
    if (closing || reconnectTimer !== null) return
    // Exponential backoff with full jitter: when the control plane restarts,
    // every open tab would otherwise reconnect in lockstep.
    const base = Math.min(1000 * 2 ** Math.min(attempt, 5), 30_000)
    const delay = Math.random() * base
    attempt += 1
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null
      connect()
    }, delay)
  }

  function connect(): void {
    const token = getToken()
    if (!token) return

    closing = false
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    // The browser WebSocket API cannot set headers, so the token goes in the
    // query string. The server validates it before upgrading.
    const url = `${scheme}://${window.location.host}/ws?token=${encodeURIComponent(token)}`

    try {
      socket = new WebSocket(url)
    } catch (e) {
      lastError.value = String(e)
      scheduleReconnect()
      return
    }

    socket.onopen = () => {
      connected.value = true
      lastError.value = null
      attempt = 0
    }
    socket.onmessage = (ev) => handleMessage(String(ev.data))
    socket.onerror = () => {
      lastError.value = 'telemetry stream error'
    }
    socket.onclose = () => {
      connected.value = false
      socket = null
      scheduleReconnect()
    }
  }

  function disconnect(): void {
    closing = true
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    socket?.close()
    socket = null
    connected.value = false
    nodeReports.value = {}
    summary.value = null
    series.value = []
  }

  return {
    connected,
    summary,
    nodeReports,
    nodeNames,
    series,
    tunnels,
    connections,
    configGeneration,
    lastError,
    connect,
    disconnect,
  }
})
