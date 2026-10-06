<script setup lang="ts">
// Read-only view of a secret (the v3 layout): its fields as a label/value
// list with the password (reveal/copy, audited, never persisted) and the
// one-time code inline, then the timestamps, then the email shares. Editing
// lives in the separate edit drawer.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { UiAlert, UiButton, UiForm, UiInput, UiTextarea, UiSelect, UiNumberInput, UiSection, UiDataTable, UiStatusChip, UiDrawer, UiKeyValueTable, type Column, type SelectOption } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { describe } from '@/api/client'
import type { Secret } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { useShares, type Share } from '@/stores/shares'
import { SHARE_LIST } from '@/stores/paged'
import { shareSchema, SHARE_VALIDITY } from '@/schemas'
import TotpCode from '@/components/TotpCode.vue'

const props = defineProps<{ secret: Secret }>()
const secrets = useSecrets()
const shares = useShares()
const error = ref('')
// The revealed value lives only in component state and is dropped when the secret changes or the drawer closes.
const revealed = ref('')
const shown = ref(false)
const canShare = computed(() => props.secret.permissions.share)
const when = (s?: string) => (s ? new Date(s).toLocaleString() : '')

// Rows of the label/value list; the slots below render rows 2 (password), 3 (one-time code) and 4 (host).
const fields = computed(() => [
  { label: 'Name', value: props.secret.name },
  { label: 'Username', value: props.secret.username, copyable: true },
  { label: 'Password' },
  { label: '2FA / TOTP' },
  { label: 'Host URL', value: props.secret.host_url },
  { label: 'Folder', value: props.secret.folder_path || '/' },
  { label: 'Version', value: 'v' + props.secret.current_version },
  { label: 'Description', value: props.secret.description },
])
const timestamps = computed(() => [
  { label: 'Created', value: when(props.secret.created_at) },
  { label: 'Updated', value: when(props.secret.updated_at) },
])
// Only http(s) links are clickable; anything else stays text.
const hostHref = computed(() => (/^https?:\/\//i.test(props.secret.host_url) ? props.secret.host_url : ''))

async function toggle(): Promise<void> {
  error.value = ''
  if (shown.value) {
    shown.value = false
    return
  }
  try {
    if (!revealed.value) revealed.value = (await secrets.reveal(props.secret.id)).password
    shown.value = true
  } catch (e) {
    error.value = describe(e)
  }
}
// Copy without showing: fetch the current value (audited like a reveal)
// straight into the clipboard; nothing is kept in component state.
const copied = ref(false)
let copiedTimer: ReturnType<typeof setTimeout> | undefined
async function copyPassword(): Promise<void> {
  error.value = ''
  try {
    const value = revealed.value || (await secrets.reveal(props.secret.id)).password
    await navigator.clipboard.writeText(value)
    copied.value = true
    if (copiedTimer) clearTimeout(copiedTimer)
    copiedTimer = setTimeout(() => { copied.value = false }, 1500)
  } catch (e) {
    error.value = describe(e)
  }
}
function reset(): void {
  revealed.value = ''
  shown.value = false
  error.value = ''
}
onBeforeUnmount(() => { if (copiedTimer) clearTimeout(copiedTimer); revealed.value = '' })
// A new version (or another secret) drops whatever was revealed.
watch(() => [props.secret.id, props.secret.current_version], reset)
watch(() => props.secret.id, () => { if (canShare.value) void shares.list(props.secret.id, SHARE_LIST.first) }, { immediate: true })

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
// Server paging and sorting of the caller's shares (newest first); kept in
// component state, not the URL (the panel lives in a drawer).
const shareSort = computed(() => ({ key: shares.params.sort, dir: shares.params.order }))
const sharePage = (page: number) => void shares.list(props.secret.id, { ...shares.params, page })
const shareSize = (size: number) => void shares.list(props.secret.id, { ...shares.params, page: 1, page_size: size })
const shareSortBy = (s: { key: string; dir: 'asc' | 'desc' }) => void shares.list(props.secret.id, { ...shares.params, page: 1, sort: s.key, order: s.dir })
const shareColumns: Column<Share>[] = [
  { key: 'recipient_email', label: 'Recipient' },
  { key: 'state', label: 'State', width: 'sm' },
  { key: 'opens', label: 'Reveals', format: (s) => `${s.opens}/${s.max_opens}`, hideOnStack: true },
  { key: 'expires_at', label: 'Until', sortable: true, format: (s) => new Date(s.expires_at).toLocaleString() + (s.cidr ? ' · ' + s.cidr : '') },
  { key: 'created_at', label: 'Created', sortable: true, defaultDir: 'desc', hideOnStack: true, format: (s) => new Date(s.created_at).toLocaleString() },
]
</script>

<template>
  <div class="flex flex-col gap-4" data-test="secret-view">
    <UiAlert v-if="error" kind="error" data-test="drawer-error">{{ error }}</UiAlert>
    <UiKeyValueTable :items="fields" data-test="secret-fields">
      <template #value-2>
        <span class="flex flex-wrap items-center gap-1">
          <span class="font-mono" :class="shown ? 'break-all' : 'tracking-widest'" data-test="revealed-password">{{ shown ? revealed : '••••••••••••' }}</span>
          <UiButton variant="text" size="xs" :icon="shown ? 'mdi-eye-off-outline' : 'mdi-eye-outline'" icon-only :label="shown ? 'Hide password' : 'Reveal password'" data-test="reveal" @click="toggle" />
          <UiButton variant="text" size="xs" :icon="copied ? 'mdi-check' : 'mdi-content-copy'" icon-only :label="copied ? 'Copied' : 'Copy password'" data-test="copy-password" @click="copyPassword" />
        </span>
      </template>
      <template #value-3>
        <TotpCode v-if="secret.has_totp" :secret-id="secret.id" @error="error = $event" />
        <span v-else class="text-base-content/70" data-test="totp-none">—</span>
      </template>
      <template #value-4>
        <a v-if="hostHref" :href="hostHref" target="_blank" rel="noopener noreferrer" class="link link-primary break-all" data-test="host-link">{{ secret.host_url }}</a>
        <span v-else>{{ secret.host_url || '—' }}</span>
      </template>
    </UiKeyValueTable>
    <p class="text-xs text-base-content/70">Revealing or copying the password or the one-time code is recorded in the audit trail.</p>
    <UiSection title="Timestamps" data-test="secret-timestamps">
      <UiKeyValueTable :items="timestamps" :columns="2" />
    </UiSection>
    <UiSection v-if="canShare" title="Shared links" data-test="shares-panel">
      <UiAlert v-if="shares.error" kind="error" class="mb-2" data-test="shares-error">{{ shares.error }}</UiAlert>
      <UiDataTable :items="shares.items" :columns="shareColumns" :loading="shares.loading" :total="shares.total" :page="shares.params.page" :page-size="shares.params.page_size" :page-sizes="[10, 25, 50]" :sort="shareSort" caption="Shared links" empty-title="No links yet" :row-attrs="(s) => ({ 'data-test': 'share-' + s.id })" @update:page="sharePage" @update:page-size="shareSize" @update:sort="shareSortBy">
        <template #cell-state="{ row }"><UiStatusChip :status="row.state" :colors="{ consumed: 'neutral', expired: 'neutral', cancelled: 'neutral' }" :data-test="'share-state-' + row.id" /></template>
        <template #actions="{ row }"><UiButton v-if="row.state === 'active'" size="xs" variant="text" color="error" :data-test="'share-cancel-' + row.id" @click="cancelShare(row)">Cancel</UiButton></template>
      </UiDataTable>
      <UiButton size="sm" variant="soft" class="mt-2" icon="mdi-email-outline" data-test="share-new" @click="openShare">Share by email</UiButton>
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
