/**
 * API client.
 *
 * Every request carries the session token. A 401 clears the session and sends
 * the user to the login screen — handled centrally here rather than in each
 * component, so an expired token cannot leave a view silently showing stale data.
 */

export interface ApiErrorBody {
  error: string
  code: string
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

const TOKEN_KEY = 'tunnel.token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

/** Called on 401 so the app can redirect. Set by the router. */
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 401) {
    setToken(null)
    onUnauthorized?.()
    throw new ApiError(401, 'unauthorized', 'Session expired, please sign in again')
  }

  if (!response.ok) {
    let detail: ApiErrorBody | null = null
    try {
      detail = (await response.json()) as ApiErrorBody
    } catch {
      // Non-JSON error body (a proxy error page, for instance).
    }
    throw new ApiError(
      response.status,
      detail?.code ?? 'error',
      detail?.error ?? `Request failed with status ${response.status}`,
    )
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
}

// --- 共享类型 --------------------------------------------------------------

/** 设备组：入口或出口机器的集合，令牌挂在组上。 */
export interface DeviceGroupDto {
  id: string
  name: string
  region: string
  kind: string
  kind_label: string
  note: string | null
  enabled: boolean
  config_revision: number
  created_at: string
  nodes_total: number
  nodes_online: number
  /** 以下为控制面叠加的实时汇总。 */
  rx_bps?: number
  tx_bps?: number
  connections?: number
}

export interface NodeDto {
  id: string
  group_id: string
  group_name: string | null
  name: string
  hostname: string | null
  region: string
  role: string
  public_address: string | null
  management_address: string | null
  observed_ip: string | null
  agent_version: string | null
  enabled: boolean
  config_revision: number
  status: string
  cpu_percent: number
  memory_used_bytes: number
  memory_total_bytes: number
  uptime_secs: number
  host_uptime_secs: number
  disk_used_bytes: number
  disk_total_bytes: number
  connections: number
  rx_bytes: number
  tx_bytes: number
  total_rx_bytes?: number
  total_tx_bytes?: number
  rx_bps: number
  tx_bps: number
  tunnels_online: number
  tunnels_total: number
  interfaces: Array<{ name: string; addresses: string[]; is_loopback: boolean }>
  last_heartbeat_at: string | null
  /** 组详情页里每台机器携带自己的隧道地址与隧道状态。 */
  endpoints?: EndpointDto[]
  tunnels?: TunnelDto[]
  report_age_secs?: number
  /**
   * 服务端选出的公网地址与对应地区（ISO 国家代码，如 `HK`）。
   *
   * 只由组详情接口下发。地址的选取规则只在服务端保留一份，面板直接显示，
   * 不再自己重算 —— 两边各有一份规则时，查的与显示的迟早会不是同一个 IP。
   * 地区为 null 表示还在查询中或查询失败。
   */
  public_v4?: string | null
  public_v6?: string | null
  v4_region?: string | null
  v6_region?: string | null
}

export interface InstallCommandDto {
  command: string
  panel_url: string
  warning: string | null
}

export interface EndpointDto {
  id: string
  node_id: string
  node_name: string | null
  name: string
  address: string
  port: number
  kind: string
  priority: string
  interface: string | null
  source_ip: string | null
  tls_server_name: string | null
  enabled: boolean
}

export interface RouteDto {
  id: string
  name: string
  /** `tunnel` 或 `direct`。 */
  mode: string
  mode_label: string
  entry_group_id: string
  entry_group_name: string | null
  listen_address: string
  listen_port: number
  exit_group_id: string
  exit_group_name: string | null
  target_host: string
  target_port: number
  /** 全部目标地址。单目标时只有一项。 */
  targets: string[]
  /** `random`/`round_robin`/`ip_hash`/`least_conn`/`failover`。 */
  target_strategy: string
  /** 策略的中文名，后端给出，前端不再自己维护映射。 */
  target_strategy_label: string
  endpoints: EndpointDto[]
  tunnel_pool_size: number
  load_balance: string
  max_connections: number
  egress_source_ip: string | null
  egress_interface: string | null
  enabled: boolean
}

/**
 * 一个转发目标的健康状态，在入口组内所有机器上汇总后给出。
 *
 * 组内每台机器各自维护熔断状态，所以 `tripped` 表示「至少有一台熔断了它」，
 * `available` 表示「至少有一台还在用它」—— 两者可以同时为真，
 * `tripped_on_machines / machines` 给出具体比例。
 */
export interface TargetHealth {
  addr: string
  available: boolean
  tripped: boolean
  /** 有几台机器熔断了它。 */
  tripped_on_machines: number
  /** 有几台机器上报了它，作为上面那个数的分母。 */
  machines: number
  active: number
  consecutive_failures: number
  total_ok: number
  total_failed: number
}

/** 负载均衡策略选项，与后端 TargetStrategy 一一对应。 */
export const TARGET_STRATEGIES: Array<{ value: string; label: string; hint: string }> = [
  { value: 'random', label: '随机', hint: '默认。并发下天然均匀，多台入口机之间不会产生同步的分配节奏。' },
  { value: 'round_robin', label: '轮询', hint: '按顺序轮流。目标性能一致、连接寿命相近时最均匀。' },
  { value: 'ip_hash', label: 'IP 哈希', hint: '同一客户端固定落到同一目标。目标侧有会话状态（登录态、本地缓存）时用它。' },
  { value: 'least_conn', label: '最少连接数', hint: '挑当前活跃连接最少的。连接寿命差异大时比轮询更均衡。' },
  { value: 'failover', label: '故障转移', hint: '主备关系：只用最靠前的可用目标，备用机平时不承载流量。' },
]

export interface RouteLive {
  route_id: string
  tunnels_online: number
  tunnels_total: number
  connections: number
  rx_bps: number
  tx_bps: number
  rx_bytes: number
  tx_bytes: number
  accepted_total: number
  rejected_total: number
  failed_total: number
  active_endpoint_id: string | null
  /** 有几台机器在实际承载这条线路。 */
  reporting_machines?: number
  /** 各目标的健康状态。直连线路才有；隧道线路由出口拨号，入口无从得知。 */
  targets?: TargetHealth[]
}

export interface TunnelDto {
  tunnel_id: number
  node_id?: string
  node_name?: string
  route_id: string
  endpoint_name: string
  endpoint_kind: string
  state: string
  streams: number
  rx_bytes: number
  tx_bytes: number
  rtt_ms: number | null
  established_secs: number
  reconnects: number
}

export interface ConnectionDto {
  id: number
  route_name: string
  tunnel_id: number
  stream_id: number
  client_addr: string
  target: string
  rx_bytes: number
  tx_bytes: number
  age_secs: number
  idle_secs: number
}

export interface DashboardDto {
  nodes_total: number
  nodes_online: number
  nodes_offline: number
  nodes_degraded: number
  routes_total: number
  routes_enabled: number
  tunnel_routes_enabled: number
  tunnels_online: number
  tunnels_total: number
  connections: number
  rx_bps: number
  tx_bps: number
  total_rx_bytes: number
  total_tx_bytes: number
  uptime_secs: number
  psk_configured: boolean
  production: boolean
}

export interface TrafficPoint {
  bucket_at: string
  rx_bytes: number
  tx_bytes: number
  rx_bps: number
  tx_bps: number
  connections: number
}

export interface DailyRouteTraffic {
  route_id: string
  route_name: string
  rx_bytes: number
  tx_bytes: number
}

export interface DailyTrafficDto {
  date: string
  utc_offset_minutes: number
  rx_bytes: number
  tx_bytes: number
  total_bytes: number
  routes: DailyRouteTraffic[]
}

export interface AuditRow {
  id: number
  at: string
  username: string | null
  action: string
  target_type: string | null
  target_name: string | null
  source_ip: string | null
  detail_json: string | null
  success: number
}
