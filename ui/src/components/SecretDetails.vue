<script setup lang="ts">
// The vault-specific part of a secret: reveal/copy the current password
// (audited, never persisted), rotate it, one-time codes and email shares.
// Module-unique; rendered under the kit's record form in the secret drawer.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { UiAlert, UiButton, UiSecretField, UiCopyButton, UiForm, UiInput, UiTextarea, UiSelect, UiNumberInput, UiSection, UiDataTable, UiStatusChip, UiDrawer, useConfirm, type Column, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { describe } from '@/api/client'
import type { Secret } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { useShares, type Share } from '@/stores/shares'
import { changePasswordSchema, totpSchema, shareSchema, SHARE_VALIDITY } from '@/schemas'

const props = defineProps<{ secret: Secret }>()
const emit = defineEmits<{ saved: [s: Secret]; versions: [s: Secret] }>()
const secrets = useSecrets()
const shares = useShares()
const confirm = useConfirm()
const error = ref('')
// The revealed value lives only in component state and is dropped when the secret changes or the drawer closes.
const revealed = ref('')
const code = ref<{ code: string; period: number; expires_in: number } | null>(null)
let timer: ReturnType<typeof setInterval> | undefined
const canWrite = computed(() => props.secret.permissions.write)
const canShare = computed(() => props.secret.permissions.share)

function reset(): void {
  stopTimer()
  revealed.value = ''
  code.value = null
  error.value = ''
  passwordForm.reset({ password: '', comment: '' })
  totpForm.reset({ seed: '' })
}
onBeforeUnmount(() => { stopTimer(); revealed.value = '' })

async function reveal(): Promise<void> {
  error.value = ''
  try {
    revealed.value = (await secrets.reveal(props.secret.id)).password
  } catch (e) {
    error.value = describe(e)
  }
}
const passwordForm = useZodForm(changePasswordSchema, {
  initial: { password: '', comment: '' },
  onSubmit: (v) => secrets.changePassword(props.secret.id, v.password, v.comment ?? ''),
  onSuccess: async () => {
    passwordForm.reset({ password: '', comment: '' })
    revealed.value = ''
    emit('saved', await secrets.get(props.secret.id))
  },
})
async function loadCode(): Promise<void> {
  try {
    code.value = await secrets.totp(props.secret.id)
    stopTimer()
    timer = setInterval(() => {
      if (!code.value) return
      code.value.expires_in -= 1
      if (code.value.expires_in <= 0) void loadCode()
    }, 1000)
  } catch (e) {
    error.value = describe(e)
  }
}
function stopTimer(): void {
  if (timer) clearInterval(timer)
  timer = undefined
}
const totpForm = useZodForm(totpSchema, {
  initial: { seed: '' },
  onSubmit: (v) => secrets.setTotp(props.secret.id, v.seed),
  onSuccess: async () => {
    totpForm.reset({ seed: '' })
    emit('saved', await secrets.get(props.secret.id))
  },
})
async function dropTotp(): Promise<void> {
  if (!(await confirm.ask({ title: 'Remove the one-time code?', danger: true, confirmLabel: 'Remove' }))) return
  try {
    await secrets.removeTotp(props.secret.id)
    code.value = null
    stopTimer()
    emit('saved', await secrets.get(props.secret.id))
  } catch (e) {
    error.value = describe(e)
  }
}

watch(() => props.secret.id, () => { reset(); if (canShare.value) void shares.list(props.secret.id) }, { immediate: true })

// --- email shares ---
const shareOpen = ref(false)
const shareDone = ref('')
const validityOptions: SelectOption[] = [{ title: '1 hour', value: '1h' }, { title: '1 day', value: '1d' }, { title: '7 days', value: '7d' }]
const shareForm = useZodForm(shareSchema, {
  initial: { recipient_email: '', message: '', validity: '1h', max_opens: 1, cidr: '' },
  onSubmit: (v) => shares.create(props.secret.id, { recipient_email: v.recipient_email, message: v.message, validity_seconds: SHARE_VALIDITY[v.validity], max_opens: v.max_opens, cidr: v.cidr }),
  onSuccess: () => { shareDone.value = String(shareForm.values.recipient_email) },
})
function openShare(): void {
  shareDone.value = ''
  shareForm.reset({ recipient_email: '', message: '', validity: '1h', max_opens: 1, cidr: '' })
  shareOpen.value = true
}
async function cancelShare(s: Share): Promise<void> {
  error.value = ''
  try {
    await shares.cancel(props.secret.id, s.id)
  } catch (e) {
    error.value = describe(e)
  }
}
const shareColumns: Column<Share>[] = [
  { key: 'recipient_email', label: 'Recipient' },
  { key: 'state', label: 'State', width: 'sm' },
  { key: 'opens', label: 'Reveals', format: (s) => `${s.opens}/${s.max_opens}`, hideOnStack: true },
  { key: 'expires_at', label: 'Until', format: (s) => new Date(s.expires_at).toLocaleString() + (s.cidr ? ' · ' + s.cidr : '') },
]
</script>

<template>
  <div class="mt-4 flex flex-col gap-4">
    <UiAlert v-if="error" kind="error" data-test="drawer-error">{{ error }}</UiAlert>
    <UiSection title="Password" :description="'Version ' + secret.current_version + '. Revealing is recorded in the audit trail.'">
      <div class="flex flex-wrap items-end gap-2">
        <UiSecretField id="revealed-password" :model-value="revealed || '••••••••'" label="Password" readonly :revealable="!!revealed" class="grow" data-test="revealed-password" />
        <UiButton variant="soft" data-test="reveal" @click="reveal">Reveal</UiButton>
        <UiCopyButton v-if="revealed" :value="revealed" label="Copy password" />
      </div>
      <UiButton variant="text" size="sm" class="mt-2" data-test="open-versions" @click="emit('versions', secret)">Version history</UiButton>
      <UiForm v-if="canWrite" :form="passwordForm" class="mt-3">
        <div class="flex flex-col gap-2">
          <UiSecretField v-bind="passwordForm.field('password')" label="New password" autocomplete="new-password" required data-test="new-password" />
          <UiInput v-bind="passwordForm.field('comment')" label="Comment" data-test="password-comment" />
          <div><UiButton type="submit" variant="soft" size="sm" :loading="passwordForm.submitting.value" data-test="change-password">Change password</UiButton></div>
        </div>
      </UiForm>
    </UiSection>
    <UiSection title="One-time code">
      <template v-if="secret.has_totp">
        <div class="flex flex-wrap items-center gap-2">
          <output class="font-mono text-2xl tracking-widest" data-test="totp-code">{{ code?.code ?? '------' }}</output>
          <span v-if="code" class="text-xs text-base-content/70" data-test="totp-expires">{{ code.expires_in }}s</span>
          <UiButton variant="soft" size="sm" data-test="totp-load" @click="loadCode">{{ code ? 'Refresh' : 'Show code' }}</UiButton>
          <UiButton v-if="canWrite" variant="text" size="sm" color="error" data-test="totp-remove" @click="dropTotp">Remove</UiButton>
        </div>
      </template>
      <UiForm v-else-if="canWrite" :form="totpForm">
        <div class="flex flex-wrap items-end gap-2">
          <UiSecretField v-bind="totpForm.field('seed')" label="TOTP seed" class="grow" data-test="totp-seed" />
          <UiButton type="submit" variant="soft" size="sm" :loading="totpForm.submitting.value" data-test="totp-save">Save seed</UiButton>
        </div>
      </UiForm>
      <p v-else class="text-xs text-base-content/70">No one-time code configured.</p>
    </UiSection>
    <UiSection v-if="canShare" title="Shared links" data-test="shares-panel">
      <UiAlert v-if="shares.error" kind="error" class="mb-2" data-test="shares-error">{{ shares.error }}</UiAlert>
      <UiDataTable :items="shares.items" :columns="shareColumns" caption="Shared links" empty-title="No links yet" :row-attrs="(s) => ({ 'data-test': 'share-' + s.id })">
        <template #cell-state="{ row }"><UiStatusChip :status="row.state" :colors="{ consumed: 'neutral', expired: 'neutral', cancelled: 'neutral' }" :data-test="'share-state-' + row.id" /></template>
        <template #actions="{ row }"><UiButton v-if="row.state === 'active'" size="xs" variant="text" color="error" :data-test="'share-cancel-' + row.id" @click="cancelShare(row)">Cancel</UiButton></template>
      </UiDataTable>
      <UiButton size="sm" variant="soft" class="mt-2" icon="mdi-email-fast-outline" data-test="share-new" @click="openShare">Share by email</UiButton>
    </UiSection>
    <UiDrawer v-model="shareOpen" :title="'Share “' + secret.name + '” by email'" size="md" data-test="share-dialog">
      <UiAlert v-if="shareDone" kind="success" data-test="share-done">A link was mailed to {{ shareDone }}. It reveals the current password and is never shown here.</UiAlert>
      <UiForm v-else :form="shareForm">
        <div class="flex flex-col gap-3">
          <UiInput v-bind="shareForm.field('recipient_email')" label="Recipient email" type="email" required data-test="share-email" />
          <UiTextarea v-bind="shareForm.field('message')" label="Message (optional)" :rows="2" data-test="share-message" />
          <div class="grid grid-cols-2 gap-2">
            <UiSelect v-bind="shareForm.field('validity')" label="Valid for" :options="validityOptions" :clearable="false" data-test="share-validity" />
            <UiNumberInput v-bind="shareForm.field('max_opens')" label="Reveals allowed" :min="1" :max="10" data-test="share-opens" />
          </div>
          <UiInput v-bind="shareForm.field('cidr')" label="Allowed network (CIDR, optional)" placeholder="203.0.113.0/24" data-test="share-cidr" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" data-test="share-close" @click="shareOpen = false">{{ shareDone ? 'Close' : 'Cancel' }}</UiButton>
        <UiButton v-if="!shareDone" :loading="shareForm.submitting.value" data-test="share-send" @click="shareForm.submit()">Send link</UiButton>
      </template>
    </UiDrawer>
  </div>
</template>
