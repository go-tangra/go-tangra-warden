<script setup lang="ts">
// Folder management for the explorer's left pane: new / rename / move / delete
// on the selected folder, each through a small dialog. Needs `manage Folder`.
import { computed, ref } from 'vue'
import { useAbility } from '@casl/vue'
import { describe } from '@/api/client'
import { useFolders } from '@/stores/folders'

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
const moveOptions = computed(() => [
  { title: 'Root', value: null as string | null },
  ...folders
    .flat()
    .filter((f) => f.folder.id !== props.selected && !f.folder.path.startsWith((current.value?.path ?? '') + '/'))
    .map((f) => ({ title: f.folder.path, value: f.folder.id as string | null })),
])

type Dialog = 'new' | 'rename' | 'move' | 'delete'
const dialog = ref<Dialog | null>(null)
const name = ref('')
const moveTo = ref<string | null>(null)
const recursive = ref(false)
const busy = ref(false)

function openDialog(kind: Dialog): void {
  name.value = kind === 'rename' ? (current.value?.name ?? '') : ''
  moveTo.value = current.value?.parent_id ?? null
  recursive.value = false
  dialog.value = kind
}

async function run(fn: () => Promise<void>, ok: string): Promise<void> {
  busy.value = true
  try {
    await fn()
    dialog.value = null
    emit('notice', ok)
  } catch (e) {
    emit('error', describe(e))
  } finally {
    busy.value = false
  }
}

const create = () =>
  run(async () => {
    const f = await folders.create(props.selected, name.value.trim())
    emit('select', f.id)
  }, 'Folder created.')
const rename = () =>
  run(async () => {
    if (props.selected) await folders.rename(props.selected, name.value.trim())
  }, 'Folder renamed.')
const move = () =>
  run(async () => {
    if (props.selected) await folders.move(props.selected, moveTo.value)
  }, 'Folder moved.')
const remove = () =>
  run(async () => {
    const parent = current.value?.parent_id ?? null
    if (props.selected) await folders.remove(props.selected, recursive.value)
    emit('select', parent)
  }, 'Folder deleted.')
</script>

<template>
  <div v-if="canManage" class="d-flex align-center" data-test="folder-actions">
    <v-btn icon="mdi-folder-plus-outline" size="small" variant="text" :disabled="!canCreate" :aria-label="current ? 'New folder in ' + current.name : 'New folder'" data-test="folder-new" @click="openDialog('new')" />
    <v-btn icon="mdi-pencil-outline" size="small" variant="text" :disabled="!canWrite" aria-label="Rename folder" data-test="folder-rename" @click="openDialog('rename')" />
    <v-btn icon="mdi-folder-move-outline" size="small" variant="text" :disabled="!canWrite" aria-label="Move folder" data-test="folder-move" @click="openDialog('move')" />
    <v-btn icon="mdi-delete-outline" size="small" variant="text" color="error" :disabled="!canDelete" aria-label="Delete folder" data-test="folder-delete" @click="openDialog('delete')" />

    <v-dialog :model-value="dialog === 'new'" max-width="440" @update:model-value="dialog = null">
      <v-card data-test="folder-new-dialog">
        <v-card-title>New folder {{ current ? 'in ' + current.path : 'at the root' }}</v-card-title>
        <v-card-text>
          <v-form id="folder-new-form" @submit.prevent="create">
            <v-text-field v-model="name" label="Name" autofocus data-test="folder-name" />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = null">Cancel</v-btn>
          <v-btn type="submit" form="folder-new-form" color="primary" :disabled="!name.trim()" :loading="busy" data-test="folder-create">Create</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog :model-value="dialog === 'rename'" max-width="440" @update:model-value="dialog = null">
      <v-card data-test="folder-rename-dialog">
        <v-card-title>Rename {{ current?.name }}</v-card-title>
        <v-card-text>
          <v-form id="folder-rename-form" @submit.prevent="rename">
            <v-text-field v-model="name" label="Name" autofocus data-test="folder-rename-name" />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = null">Cancel</v-btn>
          <v-btn type="submit" form="folder-rename-form" color="primary" :disabled="!name.trim()" :loading="busy" data-test="folder-rename-go">Rename</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog :model-value="dialog === 'move'" max-width="440" @update:model-value="dialog = null">
      <v-card data-test="folder-move-dialog">
        <v-card-title>Move {{ current?.name }}</v-card-title>
        <v-card-text>
          <v-select v-model="moveTo" :items="moveOptions" label="Move to" data-test="folder-move-target" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = null">Cancel</v-btn>
          <v-btn color="primary" :loading="busy" data-test="folder-move-go" @click="move">Move</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog :model-value="dialog === 'delete'" max-width="440" @update:model-value="dialog = null">
      <v-card data-test="confirm-folder-delete">
        <v-card-title>Delete {{ current?.path }}?</v-card-title>
        <v-card-text>
          <p v-if="current?.secret_count" class="mb-2">{{ current.secret_count }} secret(s) sit directly inside.</p>
          <v-checkbox v-model="recursive" label="Also delete every subfolder and secret inside (material destroyed in the vault)" hide-details data-test="folder-recursive" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = null">Cancel</v-btn>
          <v-btn color="error" :loading="busy" data-test="confirm-folder-delete-yes" @click="remove">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>
