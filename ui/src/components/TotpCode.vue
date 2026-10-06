<script setup lang="ts">
// The current one-time code of a secret: shown on demand (fetching it is
// audited like a reveal), counted down with a bar over the code's period
// and fetched again when it rolls over; copyable without showing it.
// Shared by the secret's view and edit drawers.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { UiButton } from '@go-tangra/ui'
import { describe } from '@/api/client'
import { useSecrets } from '@/stores/secrets'

const props = defineProps<{ secretId: string }>()
const emit = defineEmits<{ error: [message: string] }>()
const secrets = useSecrets()
const code = ref<{ code: string; period: number; expires_in: number } | null>(null)
const copied = ref(false)
let timer: ReturnType<typeof setInterval> | undefined
let copiedTimer: ReturnType<typeof setTimeout> | undefined

// Share of the code's period still left (the countdown bar); low near the end.
const remaining = computed(() => (code.value && code.value.period > 0 ? Math.max(0, Math.min(1, code.value.expires_in / code.value.period)) : 0))
const expiring = computed(() => !!code.value && code.value.expires_in <= 5)

async function load(): Promise<void> {
  try {
    code.value = await secrets.totp(props.secretId)
    stop()
    timer = setInterval(() => {
      if (!code.value) return
      code.value.expires_in -= 1
      if (code.value.expires_in <= 0) void load()
    }, 1000)
  } catch (e) {
    emit('error', describe(e))
  }
}
async function copy(): Promise<void> {
  try {
    if (!code.value) await load()
    if (!code.value) return
    await navigator.clipboard.writeText(code.value.code)
    copied.value = true
    if (copiedTimer) clearTimeout(copiedTimer)
    copiedTimer = setTimeout(() => { copied.value = false }, 1500)
  } catch (e) {
    emit('error', describe(e))
  }
}
function stop(): void {
  if (timer) clearInterval(timer)
  timer = undefined
}
watch(() => props.secretId, () => { stop(); code.value = null })
onBeforeUnmount(() => { stop(); if (copiedTimer) clearTimeout(copiedTimer) })
</script>

<template>
  <div class="flex flex-wrap items-start gap-2" data-test="totp-row">
    <!-- The countdown bar sits under the digits, as wide as the code. -->
    <span class="inline-flex flex-col gap-1" data-test="totp-display">
      <output class="font-mono text-2xl font-semibold tracking-widest text-primary" data-test="totp-code">{{ code?.code ?? '------' }}</output>
      <span v-if="code" class="flex items-center gap-1.5" data-test="totp-countdown">
        <progress class="progress h-1.5 min-w-0 flex-1" :class="expiring ? 'progress-warning' : 'progress-primary'" :value="remaining * 100" max="100" :aria-label="'One-time code expires in ' + code.expires_in + ' seconds'" data-test="totp-progress" />
        <span class="w-7 text-end text-xs tabular-nums" :class="expiring ? 'text-warning' : 'text-base-content/70'" data-test="totp-expires">{{ code.expires_in }}s</span>
      </span>
    </span>
    <UiButton v-if="!code" variant="soft" size="xs" data-test="totp-load" @click="load">Show code</UiButton>
    <UiButton variant="text" size="xs" :icon="copied ? 'mdi-check' : 'mdi-content-copy'" icon-only :label="copied ? 'Copied' : 'Copy one-time code'" data-test="copy-totp" @click="copy" />
  </div>
</template>
