<script setup lang="ts">
import { ref, watch } from 'vue'
import { describe } from '@/api/client'
import type { Secret, SecretVersion } from '@/api/types'
import { useSecrets } from '@/stores/secrets'

const props = defineProps<{ modelValue: boolean; secret: Secret | null }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; restored: [version: number] }>()
const secrets = useSecrets()
const items = ref<SecretVersion[]>([])
const error = ref('')
const busy = ref(false)
const shown = ref<Record<number, string>>({})
const restoring = ref<SecretVersion | null>(null)
const comment = ref('')

watch(
  () => [props.modelValue, props.secret] as const,
  async ([open, s]) => {
    if (!open || !s) return
    shown.value = {}
    error.value = ''
    try {
      items.value = await secrets.versions(s.id)
    } catch (e) {
      error.value = describe(e)
    }
  },
  { immediate: true },
)

async function show(v: SecretVersion): Promise<void> {
  if (!props.secret) return
  try {
    const m = await secrets.reveal(props.secret.id, v.version)
    shown.value = { ...shown.value, [v.version]: m.password }
  } catch (e) {
    error.value = describe(e)
  }
}

async function restore(): Promise<void> {
  if (!props.secret || !restoring.value) return
  busy.value = true
  error.value = ''
  try {
    const nv = await secrets.restore(props.secret.id, restoring.value.version, comment.value)
    items.value = await secrets.versions(props.secret.id)
    emit('restored', nv)
    restoring.value = null
    comment.value = ''
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-navigation-drawer :model-value="modelValue" location="right" temporary width="480" data-test="version-drawer" @update:model-value="emit('update:modelValue', $event)">
    <v-toolbar density="compact" color="transparent">
      <v-toolbar-title>Versions of {{ secret?.name }}</v-toolbar-title>
      <v-btn icon="mdi-close" aria-label="Close" variant="text" data-test="versions-close" @click="emit('update:modelValue', false)" />
    </v-toolbar>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mx-4" data-test="versions-error">{{ error }}</v-alert>
    <v-list lines="two" aria-label="Versions">
      <v-list-item v-for="v in items" :key="v.version" :data-test="'version-' + v.version">
        <v-list-item-title>
          Version {{ v.version }}
          <v-chip v-if="v.current" size="x-small" color="primary" class="ml-1" data-test="version-current">current</v-chip>
          <v-chip v-if="v.material_missing" size="x-small" color="warning" class="ml-1">material missing</v-chip>
        </v-list-item-title>
        <v-list-item-subtitle>{{ v.comment || v.source }} · {{ new Date(v.created_at).toLocaleString() }}</v-list-item-subtitle>
        <div class="d-flex align-center ga-2 mt-1">
          <code v-if="shown[v.version]" :data-test="'version-password-' + v.version">{{ shown[v.version] }}</code>
          <v-btn v-else size="small" variant="text" :data-test="'version-show-' + v.version" @click="show(v)">Show</v-btn>
          <v-btn v-if="!v.current && secret?.permissions.write" size="small" variant="tonal" :data-test="'version-restore-' + v.version" @click="restoring = v">Restore</v-btn>
        </div>
      </v-list-item>
    </v-list>
    <v-dialog :model-value="restoring !== null" max-width="440" @update:model-value="restoring = null">
      <v-card data-test="confirm-restore">
        <v-card-title>Restore version {{ restoring?.version }}?</v-card-title>
        <v-card-text>
          The password of version {{ restoring?.version }} becomes a new current version; history is kept.
          <v-text-field v-model="comment" label="Comment" class="mt-2" data-test="restore-comment" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="restoring = null">Cancel</v-btn>
          <v-btn color="primary" :loading="busy" data-test="confirm-restore-yes" @click="restore">Restore</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-navigation-drawer>
</template>
