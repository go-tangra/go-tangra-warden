<script setup lang="ts">
// Three-step Bitwarden import (pick → validate → import). Module-unique: the
// document is shape-checked by a Zod schema before any request; nothing is
// written until the operator confirms.
import { computed, ref, watch } from 'vue'
import { UiAlert, UiButton, UiForm, UiFilePicker, UiSelect, UiKeyValueTable, UiDrawer, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'

import { readFile } from '@/api/download'
import { useFolders } from '@/stores/folders'
import { useTransfer, type TransferReport } from '@/stores/transfer'
import { bitwardenDocument, importPickSchema, importStrategySchema, IMPORT_STRATEGIES, MAX_IMPORT_BYTES } from '@/schemas'

const props = defineProps<{ modelValue: boolean; folderId: string | null }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; imported: [report: TransferReport] }>()
const folders = useFolders()
const transfer = useTransfer()
const step = ref<'pick' | 'validated' | 'done'>('pick')
const document = ref('')
const fileName = ref('')
const target = ref<string | null>(null)
const report = ref<TransferReport | null>(null)
const error = ref('')
const folderOptions = computed<SelectOption[]>(() => folders.flat().map((f) => ({ title: f.folder.path, value: f.folder.id })))

const pick = useZodForm(importPickSchema, {
  onSubmit: async (v) => {
    const parsed = bitwardenDocument.safeParse(await readFile(v.file))
    if (!parsed.success) {
      pick.setFieldError('file', parsed.error.issues[0]?.message ?? 'Invalid export.')
      throw new Error('invalid export')
    }
    document.value = parsed.data
    fileName.value = v.file.name
    target.value = v.target ?? null
    report.value = await transfer.validate(document.value, target.value)
    step.value = 'validated'
  },
})
const strategy = useZodForm(importStrategySchema, {
  initial: { strategy: 'rename' },
  onSubmit: async (v) => {
    report.value = await transfer.importBitwarden(document.value, target.value, v.strategy)
    step.value = 'done'
    emit('imported', report.value)
  },
})
const canImport = computed(() => step.value === 'validated' && !!report.value && report.value.items > 0)
watch(() => props.modelValue, (open) => {
  if (!open) return
  step.value = 'pick'
  document.value = ''
  fileName.value = ''
  report.value = null
  error.value = ''
  pick.reset({ target: props.folderId ?? '' })
  strategy.reset({ strategy: 'rename' })
}, { immediate: true })
const summary = computed(() => (report.value ? [{ label: 'File', value: fileName.value }, { label: 'Folders', value: report.value.folders }, { label: 'Logins', value: report.value.items }, { label: 'Name collisions', value: report.value.collisions.length }, { label: 'Problems', value: report.value.problems.length }, ...(step.value === 'done' ? [{ label: 'Result', value: `${report.value.created} created, ${report.value.renamed} renamed, ${report.value.skipped} skipped, ${report.value.overwritten} overwritten, ${report.value.failed} failed` }] : [])] : []))
const strategyOptions: SelectOption[] = IMPORT_STRATEGIES.map((s) => ({ title: s === 'overwrite' ? 'Overwrite (new version)' : s.charAt(0).toUpperCase() + s.slice(1), value: s }))
const serverError = computed(() => error.value || pick.serverError.value || strategy.serverError.value)
</script>

<template>
  <UiDrawer :model-value="modelValue" title="Import from Bitwarden" size="lg" data-test="import-dialog" @update:model-value="emit('update:modelValue', $event)">
    <UiAlert v-if="serverError" kind="error" class="mb-3" data-test="import-error">{{ serverError }}</UiAlert>
    <UiForm v-if="step === 'pick'" :form="pick">
      <p class="mb-3 text-sm">Pick an unencrypted Bitwarden JSON export (up to 16 MiB). Nothing is written until you confirm the import.</p>
      <div class="flex flex-col gap-3">
        <UiFilePicker v-bind="pick.field('file')" label="Export file" accept="application/json,.json" :max-bytes="MAX_IMPORT_BYTES" required data-test="import-file" />
        <UiSelect v-bind="pick.field('target')" label="Import into" :options="folderOptions" placeholder="Root" data-test="import-target" />
      </div>
    </UiForm>
    <template v-else-if="report">
      <UiKeyValueTable :items="summary" data-test="import-summary" />
      <ul v-if="report.collisions.length" class="mt-2 list-disc ps-5 text-xs" data-test="collision-list"><li v-for="(c, i) in report.collisions.slice(0, 20)" :key="i">{{ c.folder }}/{{ c.name }}</li></ul>
      <ul v-if="report.problems.length" class="mt-2 list-disc ps-5 text-xs text-error" data-test="problem-list"><li v-for="p in report.problems.slice(0, 20)" :key="p.index">item {{ p.index }}: {{ p.reason }}</li></ul>
      <ul v-if="report.warnings.length" class="mt-2 list-disc ps-5 text-xs text-base-content/70"><li v-for="(w, i) in report.warnings.slice(0, 10)" :key="i">{{ w }}</li></ul>
      <UiForm v-if="step === 'validated'" :form="strategy" class="mt-3">
        <UiSelect v-bind="strategy.field('strategy')" label="When a name already exists in the folder" :options="strategyOptions" :clearable="false" data-test="strategy" />
      </UiForm>
    </template>
    <template #actions>
      <UiButton variant="text" data-test="import-close" @click="emit('update:modelValue', false)">{{ step === 'done' ? 'Close' : 'Cancel' }}</UiButton>
      <UiButton v-if="step === 'pick'" :loading="pick.submitting.value || transfer.busy" data-test="import-validate" @click="pick.submit()">Validate</UiButton>
      <UiButton v-if="step === 'validated'" :disabled="!canImport" :loading="strategy.submitting.value || transfer.busy" data-test="import-go" @click="strategy.submit()">Import</UiButton>
    </template>
  </UiDrawer>
</template>
