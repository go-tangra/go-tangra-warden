<script setup lang="ts">
// Version history of one secret with per-version reveal and restore.
// Module-unique (vault versioning), built on kit primitives.
import { ref, watch } from 'vue'
import { UiDrawer, UiAlert, UiButton, UiBadge, UiForm, UiInput, UiDialog, UiEmptyState } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { describe } from '@/api/client'
import type { Secret, SecretVersion } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { restoreSchema } from '@/schemas'

const props = defineProps<{ modelValue: boolean; secret: Secret | null }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; restored: [version: number] }>()
const secrets = useSecrets()
const items = ref<SecretVersion[]>([])
const error = ref('')
const shown = ref<Record<number, string>>({})
const restoring = ref<SecretVersion | null>(null)
watch(() => [props.modelValue, props.secret] as const, async ([open, s]) => {
  if (!open || !s) return
  shown.value = {}
  error.value = ''
  try {
    items.value = await secrets.versions(s.id)
  } catch (e) {
    error.value = describe(e)
  }
}, { immediate: true })
async function show(v: SecretVersion): Promise<void> {
  if (!props.secret) return
  try {
    shown.value = { ...shown.value, [v.version]: (await secrets.reveal(props.secret.id, v.version)).password }
  } catch (e) {
    error.value = describe(e)
  }
}
const restoreForm = useZodForm(restoreSchema, {
  initial: { comment: '' },
  onSubmit: async (v) => {
    const nv = await secrets.restore(props.secret!.id, restoring.value!.version, v.comment ?? '')
    items.value = await secrets.versions(props.secret!.id)
    emit('restored', nv)
  },
  onSuccess: () => {
    restoring.value = null
    restoreForm.reset({ comment: '' })
  },
})
</script>

<template>
  <UiDrawer :model-value="modelValue" :title="'Versions of ' + (secret?.name ?? '')" size="md" data-test="version-drawer" @update:model-value="emit('update:modelValue', $event)">
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="versions-error">{{ error }}</UiAlert>
    <UiEmptyState v-if="!items.length" title="No versions" />
    <ul v-else class="divide-y divide-base-300" aria-label="Versions">
      <li v-for="v in items" :key="v.version" class="py-3" :data-test="'version-' + v.version">
        <div class="flex flex-wrap items-center gap-1">
          <span class="font-medium">Version {{ v.version }}</span>
          <UiBadge v-if="v.current" color="primary" data-test="version-current">current</UiBadge>
          <UiBadge v-if="v.material_missing" color="warning">material missing</UiBadge>
        </div>
        <div class="text-xs text-base-content/70">{{ v.comment || v.source }} · {{ new Date(v.created_at).toLocaleString() }}</div>
        <div class="mt-1 flex flex-wrap items-center gap-2">
          <code v-if="shown[v.version]" class="rounded-field bg-base-200 px-2 py-0.5 text-sm" :data-test="'version-password-' + v.version">{{ shown[v.version] }}</code>
          <UiButton v-else size="xs" variant="text" :data-test="'version-show-' + v.version" @click="show(v)">Show</UiButton>
          <UiButton v-if="!v.current && secret?.permissions.write" size="xs" variant="soft" :data-test="'version-restore-' + v.version" @click="restoring = v">Restore</UiButton>
        </div>
      </li>
    </ul>
    <UiDialog :model-value="restoring !== null" :title="'Restore version ' + (restoring?.version ?? '') + '?'" size="sm" data-test="confirm-restore" @update:model-value="restoring = null">
      <p class="mb-2 text-sm">The password of version {{ restoring?.version }} becomes a new current version; history is kept.</p>
      <UiForm :form="restoreForm"><UiInput v-bind="restoreForm.field('comment')" label="Comment" data-test="restore-comment" /></UiForm>
      <template #actions>
        <UiButton variant="text" @click="restoring = null">Cancel</UiButton>
        <UiButton :loading="restoreForm.submitting.value" data-test="confirm-restore-yes" @click="restoreForm.submit()">Restore</UiButton>
      </template>
    </UiDialog>
  </UiDrawer>
</template>
