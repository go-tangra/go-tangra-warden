<script setup lang="ts">
// Folder management for the explorer's left pane: new / rename / move / delete
// on the selected folder, each through a small dialog. Needs `manage Folder`.
// Module-unique (folder tree semantics of the vault), built on kit primitives.
import { computed, ref } from 'vue'
import { useAbility } from '@casl/vue'
import { UiButton, UiDialog, UiForm, UiInput, UiSelect, UiCheckbox, UiDrawer, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { describe } from '@/api/client'
import { useFolders } from '@/stores/folders'
import { folderNameSchema, folderMoveSchema, folderDeleteSchema } from '@/schemas'

const props = defineProps<{ selected: string | null }>()
const emit = defineEmits<{ notice: [text: string]; error: [text: string]; select: [id: string | null] }>()
const folders = useFolders()
const ability = useAbility()
const canManage = computed(() => ability.can('manage', 'Folder'))
const current = computed(() => (props.selected ? folders.find(props.selected)?.folder : undefined))
// Creating needs write on the parent; the root is writable for anyone who may manage folders.
const canCreate = computed(() => canManage.value && (!props.selected || !!current.value?.permissions.write))
const canWrite = computed(() => canManage.value && !!current.value?.permissions.write)
const canDelete = computed(() => canManage.value && !!current.value?.permissions.delete)
// A folder cannot move into itself or its own subtree.
const moveOptions = computed<SelectOption[]>(() => folders.flat().filter((f) => f.folder.id !== props.selected && !f.folder.path.startsWith((current.value?.path ?? '') + '/')).map((f) => ({ title: f.folder.path, value: f.folder.id })))

type Dialog = 'new' | 'rename' | 'move' | 'delete'
const dialog = ref<Dialog | null>(null)
async function run(fn: () => Promise<void>, ok: string): Promise<void> {
  try {
    await fn()
    dialog.value = null
    emit('notice', ok)
  } catch (e) {
    emit('error', describe(e))
    throw e
  }
}
const createForm = useZodForm(folderNameSchema, { initial: { name: '' }, onSubmit: (v) => run(async () => emit('select', (await folders.create(props.selected, v.name)).id), 'Folder created.') })
const renameForm = useZodForm(folderNameSchema, { initial: { name: '' }, onSubmit: (v) => run(async () => { if (props.selected) await folders.rename(props.selected, v.name) }, 'Folder renamed.') })
const moveForm = useZodForm(folderMoveSchema, { initial: { parent_id: '' }, onSubmit: (v) => run(async () => { if (props.selected) await folders.move(props.selected, v.parent_id ?? null) }, 'Folder moved.') })
const deleteForm = useZodForm(folderDeleteSchema, {
  initial: { recursive: false },
  onSubmit: (v) => run(async () => {
    const parent = current.value?.parent_id ?? null
    if (props.selected) await folders.remove(props.selected, v.recursive)
    emit('select', parent)
  }, 'Folder deleted.'),
})
function openDialog(kind: Dialog): void {
  createForm.reset({ name: '' })
  renameForm.reset({ name: current.value?.name ?? '' })
  moveForm.reset({ parent_id: current.value?.parent_id ?? '' })
  deleteForm.reset({ recursive: false })
  dialog.value = kind
}
</script>

<template>
  <div v-if="canManage" class="flex items-center gap-0.5" data-test="folder-actions">
    <UiButton size="xs" variant="text" icon="mdi-folder-plus-outline" icon-only :disabled="!canCreate" :label="current ? 'New folder in ' + current.name : 'New folder'" data-test="folder-new" @click="openDialog('new')" />
    <UiButton size="xs" variant="text" icon="mdi-pencil-outline" icon-only :disabled="!canWrite" label="Rename folder" data-test="folder-rename" @click="openDialog('rename')" />
    <UiButton size="xs" variant="text" icon="mdi-folder-move-outline" icon-only :disabled="!canWrite" label="Move folder" data-test="folder-move" @click="openDialog('move')" />
    <UiButton size="xs" variant="text" color="error" icon="mdi-delete-outline" icon-only :disabled="!canDelete" label="Delete folder" data-test="folder-delete" @click="openDialog('delete')" />
    <UiDrawer :model-value="dialog === 'new'" :title="'New folder ' + (current ? 'in ' + current.path : 'at the root')" size="md" data-test="folder-new-dialog" @update:model-value="dialog = null">
      <UiForm :form="createForm"><UiInput v-bind="createForm.field('name')" label="Name" required data-test="folder-name" /></UiForm>
      <template #actions><UiButton variant="text" @click="dialog = null">Cancel</UiButton><UiButton :loading="createForm.submitting.value" data-test="folder-create" @click="createForm.submit()">Create</UiButton></template>
    </UiDrawer>
    <UiDrawer :model-value="dialog === 'rename'" :title="'Rename ' + (current?.name ?? '')" size="md" data-test="folder-rename-dialog" @update:model-value="dialog = null">
      <UiForm :form="renameForm"><UiInput v-bind="renameForm.field('name')" label="Name" required data-test="folder-rename-name" /></UiForm>
      <template #actions><UiButton variant="text" @click="dialog = null">Cancel</UiButton><UiButton :loading="renameForm.submitting.value" data-test="folder-rename-go" @click="renameForm.submit()">Rename</UiButton></template>
    </UiDrawer>
    <UiDrawer :model-value="dialog === 'move'" :title="'Move ' + (current?.name ?? '')" size="md" data-test="folder-move-dialog" @update:model-value="dialog = null">
      <UiForm :form="moveForm"><UiSelect v-bind="moveForm.field('parent_id')" label="Move to" :options="moveOptions" placeholder="Root" data-test="folder-move-target" /></UiForm>
      <template #actions><UiButton variant="text" @click="dialog = null">Cancel</UiButton><UiButton :loading="moveForm.submitting.value" data-test="folder-move-go" @click="moveForm.submit()">Move</UiButton></template>
    </UiDrawer>
    <UiDialog :model-value="dialog === 'delete'" :title="'Delete ' + (current?.path ?? '') + '?'" size="sm" data-test="confirm-folder-delete" @update:model-value="dialog = null">
      <p v-if="current?.secret_count" class="mb-2 text-sm">{{ current.secret_count }} secret(s) sit directly inside.</p>
      <UiForm :form="deleteForm"><UiCheckbox v-bind="deleteForm.field('recursive')" label="Also delete every subfolder and secret inside (material destroyed in the vault)" data-test="folder-recursive" /></UiForm>
      <template #actions><UiButton variant="text" @click="dialog = null">Cancel</UiButton><UiButton color="error" :loading="deleteForm.submitting.value" data-test="confirm-folder-delete-yes" @click="deleteForm.submit()">Delete</UiButton></template>
    </UiDialog>
  </div>
</template>
