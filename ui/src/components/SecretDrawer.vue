<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { describe } from '@/api/client'
import type { Secret, SecretInput } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { useFolders } from '@/stores/folders'
import SharesPanel from '@/components/SharesPanel.vue'

const props = defineProps<{ modelValue: boolean; secret: Secret | null; folderId: string | null }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; saved: [s: Secret]; deleted: [id: string]; versions: [s: Secret]; share: [s: Secret] }>()
const secrets = useSecrets()
const folders = useFolders()

const form = ref<SecretInput & { folder_id: string | null }>({ folder_id: null, name: '', username: '', host_url: '', description: '', password: '', totp: '' })
const metadataText = ref('{}')
const error = ref('')
const busy = ref(false)
const revealed = ref('')
const revealedVersion = ref(0)
const copied = ref(false)
const newPassword = ref('')
const comment = ref('')
const totpSeed = ref('')
const code = ref<{ code: string; period: number; expires_in: number } | null>(null)
let timer: ReturnType<typeof setInterval> | undefined

const editing = computed(() => props.secret !== null)
const canWrite = computed(() => !props.secret || props.secret.permissions.write)
const canDelete = computed(() => !!props.secret && props.secret.permissions.delete)
const canShare = computed(() => !!props.secret && props.secret.permissions.share)
const nameError = computed(() => (form.value.name.trim() ? '' : 'Name is required'))
const passwordError = computed(() => (!editing.value && !form.value.password ? 'A password is required' : ''))
const metadataError = computed(() => {
  try {
    const v = JSON.parse(metadataText.value || '{}')
    return v && typeof v === 'object' && !Array.isArray(v) ? '' : 'Metadata must be a JSON object'
  } catch {
    return 'Metadata must be valid JSON'
  }
})
const folderOptions = computed(() => [{ title: 'Root', value: null as string | null }, ...folders.flat().map((f) => ({ title: ' '.repeat(f.depth * 2) + f.folder.path, value: f.folder.id as string | null }))])

watch(
  () => [props.modelValue, props.secret] as const,
  ([open, s]) => {
    if (!open) return
    stopTimer()
    revealed.value = ''
    copied.value = false
    error.value = ''
    newPassword.value = ''
    comment.value = ''
    totpSeed.value = ''
    code.value = null
    if (s) {
      form.value = { folder_id: s.folder_id, name: s.name, username: s.username, host_url: s.host_url, description: s.description, password: '', totp: '' }
      metadataText.value = JSON.stringify(s.metadata ?? {}, null, 2)
    } else {
      form.value = { folder_id: props.folderId, name: '', username: '', host_url: '', description: '', password: '', totp: '' }
      metadataText.value = '{}'
    }
  },
  { immediate: true },
)

function close(): void {
  stopTimer()
  emit('update:modelValue', false)
}

async function save(): Promise<void> {
  if (nameError.value || passwordError.value || metadataError.value) return
  busy.value = true
  error.value = ''
  try {
    const metadata = JSON.parse(metadataText.value || '{}') as Record<string, unknown>
    if (props.secret) {
      const s = await secrets.update(props.secret.id, { name: form.value.name.trim(), username: form.value.username, host_url: form.value.host_url, description: form.value.description, metadata })
      if (form.value.folder_id !== props.secret.folder_id) await secrets.move(props.secret.id, form.value.folder_id ?? null)
      emit('saved', s)
    } else {
      const input: SecretInput = { ...form.value, name: form.value.name.trim(), metadata }
      if (!input.totp) delete input.totp
      const s = await secrets.create(input)
      emit('saved', s)
    }
    close()
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function reveal(): Promise<void> {
  if (!props.secret) return
  error.value = ''
  try {
    const m = await secrets.reveal(props.secret.id)
    revealed.value = m.password
    revealedVersion.value = m.version
  } catch (e) {
    error.value = describe(e)
  }
}

async function copy(): Promise<void> {
  if (!revealed.value) return
  try {
    await navigator.clipboard.writeText(revealed.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    error.value = 'Copy is not available in this browser.'
  }
}

async function changePassword(): Promise<void> {
  if (!props.secret || !newPassword.value) return
  busy.value = true
  error.value = ''
  try {
    await secrets.changePassword(props.secret.id, newPassword.value, comment.value)
    newPassword.value = ''
    comment.value = ''
    revealed.value = ''
    const fresh = await secrets.get(props.secret.id)
    emit('saved', fresh)
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function loadCode(): Promise<void> {
  if (!props.secret) return
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

async function saveTotp(): Promise<void> {
  if (!props.secret || !totpSeed.value) return
  busy.value = true
  error.value = ''
  try {
    await secrets.setTotp(props.secret.id, totpSeed.value)
    totpSeed.value = ''
    emit('saved', await secrets.get(props.secret.id))
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function dropTotp(): Promise<void> {
  if (!props.secret) return
  busy.value = true
  try {
    await secrets.removeTotp(props.secret.id)
    code.value = null
    stopTimer()
    emit('saved', await secrets.get(props.secret.id))
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

const confirmDelete = ref(false)
async function remove(): Promise<void> {
  if (!props.secret) return
  busy.value = true
  try {
    await secrets.remove(props.secret.id)
    emit('deleted', props.secret.id)
    close()
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
    confirmDelete.value = false
  }
}

onBeforeUnmount(stopTimer)
</script>

<template>
  <v-navigation-drawer :model-value="modelValue" location="right" temporary width="520" data-test="secret-drawer" @update:model-value="emit('update:modelValue', $event)">
    <v-toolbar density="compact" color="transparent">
      <v-toolbar-title>{{ editing ? secret?.name : 'New secret' }}</v-toolbar-title>
      <v-btn icon="mdi-close" aria-label="Close" variant="text" data-test="drawer-close" @click="close" />
    </v-toolbar>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mx-4" data-test="drawer-error">{{ error }}</v-alert>
    <v-form class="pa-4" @submit.prevent="save">
      <v-select v-model="form.folder_id" :items="folderOptions" label="Folder" :disabled="!canWrite" data-test="secret-folder" />
      <v-text-field v-model="form.name" label="Name" :error-messages="nameError" :disabled="!canWrite" required data-test="secret-name" />
      <v-text-field v-model="form.username" label="Username" :disabled="!canWrite" data-test="secret-username" />
      <v-text-field v-model="form.host_url" label="Host URL" :disabled="!canWrite" data-test="secret-host" />
      <v-textarea v-model="form.description" label="Description" rows="2" :disabled="!canWrite" data-test="secret-description" />
      <v-textarea v-model="metadataText" label="Metadata (JSON)" rows="3" :error-messages="metadataError" :disabled="!canWrite" data-test="secret-metadata" />
      <template v-if="!editing">
        <v-text-field v-model="form.password" label="Password" type="password" autocomplete="new-password" :error-messages="passwordError" required data-test="secret-password" />
        <v-text-field v-model="form.totp" label="TOTP seed (optional)" placeholder="otpauth://… or base32" data-test="secret-totp" />
      </template>
      <div class="d-flex ga-2">
        <v-btn v-if="canWrite" type="submit" color="primary" :loading="busy" data-test="secret-save">{{ editing ? 'Save' : 'Create' }}</v-btn>
        <v-btn v-if="canShare" variant="text" data-test="secret-share" @click="secret && emit('share', secret)">Share access</v-btn>
        <v-spacer />
        <v-btn v-if="canDelete" color="error" variant="text" data-test="secret-delete" @click="confirmDelete = true">Delete</v-btn>
      </div>
    </v-form>
    <template v-if="editing && secret">
      <v-divider />
      <section class="pa-4" aria-labelledby="material-heading">
        <h3 id="material-heading" class="text-subtitle-1 mb-2">Password (version {{ secret.current_version }})</h3>
        <p class="text-caption text-medium-emphasis">Revealing is recorded in the audit trail.</p>
        <div class="d-flex align-center ga-2">
          <v-text-field :model-value="revealed || '••••••••'" readonly :type="revealed ? 'text' : 'password'" label="Password" hide-details density="compact" data-test="revealed-password" />
          <v-btn variant="tonal" data-test="reveal" @click="reveal">Reveal</v-btn>
          <v-btn variant="tonal" :disabled="!revealed" data-test="copy" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</v-btn>
        </div>
        <v-btn variant="text" class="mt-2" data-test="open-versions" @click="emit('versions', secret)">Version history</v-btn>
        <template v-if="secret.permissions.write">
          <v-text-field v-model="newPassword" label="New password" type="password" autocomplete="new-password" class="mt-4" data-test="new-password" />
          <v-text-field v-model="comment" label="Comment" data-test="password-comment" />
          <v-btn variant="tonal" :disabled="!newPassword" :loading="busy" data-test="change-password" @click="changePassword">Change password</v-btn>
        </template>
      </section>
      <v-divider />
      <section class="pa-4" aria-labelledby="totp-heading">
        <h3 id="totp-heading" class="text-subtitle-1 mb-2">One-time code</h3>
        <template v-if="secret.has_totp">
          <div class="d-flex align-center ga-2">
            <output class="text-h5" data-test="totp-code">{{ code?.code ?? '------' }}</output>
            <span v-if="code" class="text-caption" data-test="totp-expires">{{ code.expires_in }}s</span>
            <v-btn variant="tonal" data-test="totp-load" @click="loadCode">{{ code ? 'Refresh' : 'Show code' }}</v-btn>
            <v-btn v-if="secret.permissions.write" variant="text" color="error" data-test="totp-remove" @click="dropTotp">Remove</v-btn>
          </div>
        </template>
        <template v-else-if="secret.permissions.write">
          <v-text-field v-model="totpSeed" label="TOTP seed" placeholder="otpauth://… or base32" data-test="totp-seed" />
          <v-btn variant="tonal" :disabled="!totpSeed" data-test="totp-save" @click="saveTotp">Save seed</v-btn>
        </template>
        <p v-else class="text-caption text-medium-emphasis">No one-time code configured.</p>
      </section>
    </template>
    <template v-if="editing && secret && canShare">
      <v-divider />
      <SharesPanel :secret-id="secret.id" :secret-name="secret.name" />
    </template>
    <v-dialog v-model="confirmDelete" max-width="420">
      <v-card data-test="confirm-delete">
        <v-card-title>Delete secret?</v-card-title>
        <v-card-text>Every version is destroyed in the vault. This cannot be undone.</v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="confirmDelete = false">Cancel</v-btn>
          <v-btn color="error" :loading="busy" data-test="confirm-delete-yes" @click="remove">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-navigation-drawer>
</template>
