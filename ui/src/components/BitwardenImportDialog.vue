<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, describe } from '@/api/client'
import { readFile } from '@/api/download'
import { useFolders } from '@/stores/folders'
import { useTransfer, type Strategy, type TransferReport } from '@/stores/transfer'

const props = defineProps<{ modelValue: boolean; folderId: string | null }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; imported: [report: TransferReport] }>()
const folders = useFolders()
const transfer = useTransfer()

const step = ref<'pick' | 'validated' | 'done'>('pick')
const document = ref('')
const fileName = ref('')
const target = ref<string | null>(props.folderId)
const strategy = ref<Strategy>('rename')
const report = ref<TransferReport | null>(null)
const error = ref('')

const folderOptions = computed(() => [{ title: 'Root', value: null as string | null }, ...folders.flat().map((f) => ({ title: f.folder.path, value: f.folder.id as string | null }))])
const canImport = computed(() => step.value === 'validated' && !!report.value && report.value.items > 0)

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    step.value = 'pick'
    document.value = ''
    fileName.value = ''
    report.value = null
    error.value = ''
    target.value = props.folderId
  },
)

async function picked(files: File | File[] | null): Promise<void> {
  const file = Array.isArray(files) ? files[0] : files
  if (!file) return
  error.value = ''
  try {
    document.value = await readFile(file)
    fileName.value = file.name
    JSON.parse(document.value)
  } catch (err) {
    document.value = ''
    error.value = err instanceof ApiError ? describe(err) : 'The file is not valid JSON.'
  }
}

async function validate(): Promise<void> {
  if (!document.value) return
  error.value = ''
  try {
    report.value = await transfer.validate(document.value, target.value)
    step.value = 'validated'
  } catch (err) {
    error.value = describe(err)
  }
}

async function doImport(): Promise<void> {
  if (!document.value) return
  error.value = ''
  try {
    report.value = await transfer.importBitwarden(document.value, target.value, strategy.value)
    step.value = 'done'
    emit('imported', report.value)
  } catch (err) {
    error.value = describe(err)
  }
}
</script>

<template>
  <v-dialog :model-value="modelValue" max-width="640" @update:model-value="emit('update:modelValue', $event)">
    <v-card data-test="import-dialog">
      <v-card-title>Import from Bitwarden</v-card-title>
      <v-card-text>
        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3" data-test="import-error">{{ error }}</v-alert>
        <template v-if="step === 'pick'">
          <p class="text-body-2 mb-3">Pick an unencrypted Bitwarden JSON export (up to 16 MiB). Nothing is written until you confirm the import.</p>
          <v-file-input label="Export file" accept="application/json,.json" prepend-icon="mdi-file-upload-outline" data-test="import-file" @update:model-value="picked" />
          <v-select v-model="target" :items="folderOptions" label="Import into" data-test="import-target" />
        </template>
        <template v-else-if="report">
          <v-table density="compact" aria-label="Import summary" data-test="import-summary">
            <tbody>
              <tr><th scope="row">File</th><td>{{ fileName }}</td></tr>
              <tr><th scope="row">Folders</th><td data-test="count-folders">{{ report.folders }}</td></tr>
              <tr><th scope="row">Logins</th><td data-test="count-items">{{ report.items }}</td></tr>
              <tr><th scope="row">Name collisions</th><td data-test="count-collisions">{{ report.collisions.length }}</td></tr>
              <tr><th scope="row">Problems</th><td data-test="count-problems">{{ report.problems.length }}</td></tr>
              <tr v-if="step === 'done'"><th scope="row">Result</th><td data-test="import-result">{{ report.created }} created, {{ report.renamed }} renamed, {{ report.skipped }} skipped, {{ report.overwritten }} overwritten, {{ report.failed }} failed</td></tr>
            </tbody>
          </v-table>
          <ul v-if="report.collisions.length" class="text-caption mt-2 pl-4" data-test="collision-list">
            <li v-for="(c, i) in report.collisions.slice(0, 20)" :key="i">{{ c.folder }}/{{ c.name }}</li>
          </ul>
          <ul v-if="report.problems.length" class="text-caption mt-2 pl-4 text-error" data-test="problem-list">
            <li v-for="p in report.problems.slice(0, 20)" :key="p.index">item {{ p.index }}: {{ p.reason }}</li>
          </ul>
          <ul v-if="report.warnings.length" class="text-caption mt-2 pl-4 text-medium-emphasis">
            <li v-for="(w, i) in report.warnings.slice(0, 10)" :key="i">{{ w }}</li>
          </ul>
          <v-radio-group v-if="step === 'validated'" v-model="strategy" label="When a name already exists in the folder" inline class="mt-3" data-test="strategy">
            <v-radio label="Skip" value="skip" data-test="strategy-skip" />
            <v-radio label="Rename" value="rename" data-test="strategy-rename" />
            <v-radio label="Overwrite (new version)" value="overwrite" data-test="strategy-overwrite" />
          </v-radio-group>
        </template>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" data-test="import-close" @click="emit('update:modelValue', false)">{{ step === 'done' ? 'Close' : 'Cancel' }}</v-btn>
        <v-btn v-if="step === 'pick'" color="primary" :disabled="!document" :loading="transfer.busy" data-test="import-validate" @click="validate">Validate</v-btn>
        <v-btn v-if="step === 'validated'" color="primary" :disabled="!canImport" :loading="transfer.busy" data-test="import-go" @click="doImport">Import</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
