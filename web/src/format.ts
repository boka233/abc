/** Display formatting helpers. */

/** Bytes as a binary-prefixed string. */
export function bytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let v = value
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return i === 0 ? `${value} B` : `${v.toFixed(2)} ${units[i]}`
}

/**
 * Bits per second in decimal units.
 *
 * Deliberately decimal (kbps = 1000) rather than binary: network rates are
 * quoted decimally everywhere, and showing 1 Gbps as 0.93 Gbps because of a
 * 1024 divisor invites "the graph is wrong" tickets.
 */
export function bitrate(bps: number): string {
  if (!Number.isFinite(bps) || bps < 0) return '—'
  const units = ['bps', 'kbps', 'Mbps', 'Gbps', 'Tbps']
  let v = bps
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i += 1
  }
  return i === 0 ? `${Math.round(v)} ${units[i]}` : `${v.toFixed(2)} ${units[i]}`
}

/** Compact duration: `3d 4h`, `5m 20s`. */
export function duration(secs: number): string {
  if (!Number.isFinite(secs) || secs < 0) return '—'
  const s = Math.floor(secs)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`
}

export function percent(value: number): string {
  if (!Number.isFinite(value)) return '—'
  return `${value.toFixed(1)}%`
}

export function rtt(ms: number | null): string {
  return ms === null || ms === undefined ? '—' : `${ms} ms`
}

export function timestamp(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** Relative age, for "last seen" columns. */
export function ago(iso: string | null): string {
  if (!iso) return 'never'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const secs = (Date.now() - d.getTime()) / 1000
  return secs < 2 ? 'just now' : `${duration(secs)} ago`
}

/** Colour class for a status pill. */
export function statusClass(status: string): string {
  switch (status) {
    case 'online':
      return 'pill pill-ok'
    case 'degraded':
    case 'connecting':
      return 'pill pill-warn'
    default:
      return 'pill pill-bad'
  }
}
