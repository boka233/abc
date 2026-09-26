<script setup lang="ts">
/**
 * Inline SVG line chart.
 *
 * Hand-rolled rather than pulling in a charting library: this draws two series
 * from an in-memory array that is already bounded, and a library would add
 * hundreds of kilobytes plus its own reactivity model for that. Re-renders come
 * from Vue's reactivity on the `points` prop, so the WebSocket updates flow
 * straight into the path without a redraw loop.
 */
import { computed } from 'vue'
import type { SeriesPoint } from '@/stores/telemetry'
import { bitrate } from '@/format'

const props = defineProps<{
  points: SeriesPoint[]
  /** `rate` draws rx/tx in bits per second; `count` draws the connection count. */
  mode?: 'rate' | 'count'
}>()

const W = 800
const H = 180
const PAD = 4

const mode = computed(() => props.mode ?? 'rate')

const series = computed(() => {
  const pts = props.points
  if (pts.length < 2) return null

  const rx = pts.map((p) => (mode.value === 'rate' ? p.rx : p.connections))
  const tx = pts.map((p) => (mode.value === 'rate' ? p.tx : 0))

  // Scale to the visible maximum, with a floor so a flat zero line does not
  // divide by zero or jump wildly on the first non-zero sample.
  const peak = Math.max(1, ...rx, ...tx)

  const toPath = (values: number[]) =>
    values
      .map((v, i) => {
        const x = PAD + (i / (values.length - 1)) * (W - PAD * 2)
        const y = H - PAD - (v / peak) * (H - PAD * 2)
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
      })
      .join(' ')

  return {
    rxPath: toPath(rx),
    txPath: mode.value === 'rate' ? toPath(tx) : null,
    peak,
    latestRx: rx[rx.length - 1],
    latestTx: tx[tx.length - 1],
  }
})

function label(value: number): string {
  return mode.value === 'rate' ? bitrate(value) : String(value)
}
</script>

<template>
  <div>
    <svg v-if="series" class="chart" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none">
      <line
        v-for="f in [0.25, 0.5, 0.75]"
        :key="f"
        :x1="PAD"
        :x2="W - PAD"
        :y1="PAD + f * (H - PAD * 2)"
        :y2="PAD + f * (H - PAD * 2)"
        stroke="var(--border)"
        stroke-width="1"
      />
      <path :d="series.rxPath" fill="none" stroke="var(--accent)" stroke-width="2" />
      <path
        v-if="series.txPath"
        :d="series.txPath"
        fill="none"
        stroke="var(--ok)"
        stroke-width="2"
      />
    </svg>
    <div v-else class="empty" style="height: 180px; display: grid; place-items: center">
      Collecting data…
    </div>

    <div v-if="series" class="legend">
      <span class="legend-item">
        <span class="legend-swatch" style="background: var(--accent)"></span>
        {{ mode === 'rate' ? '接收' : '连接数' }}
        <strong>{{ label(series.latestRx) }}</strong>
      </span>
      <span v-if="series.txPath" class="legend-item">
        <span class="legend-swatch" style="background: var(--ok)"></span>
        发送 <strong>{{ label(series.latestTx) }}</strong>
      </span>
      <span class="legend-item dim">peak {{ label(series.peak) }}</span>
    </div>
  </div>
</template>
