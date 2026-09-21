<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFolders } from '@/stores/folders'
import { useSecrets } from '@/stores/secrets'
import type { Secret } from '@/api/types'
import FolderTree from '@/components/FolderTree.vue'
import PermissionDrawer from '@/components/PermissionDrawer.vue'

const folders = useFolders()
const secrets = useSecrets()
const selected = ref<string | null>(null)
const drawer = ref(false)
const target = ref<{ type: 'folder' | 'secret'; id: string; name: string } | null>(null)
const current = computed(() => (selected.value ? folders.find(selected.value)?.folder : undefined))

onMounted(async () => {
  await Promise.all([folders.load(), secrets.list(null)])
})

async function select(id: string | null): Promise<void> {
  selected.value = id
  await secrets.list(id)
}

function openFolder(): void {
  if (!current.value) return
  target.value = { type: 'folder', id: current.value.id, name: current.value.path }
  drawer.value = true
}

function openSecret(s: Secret): void {
  target.value = { type: 'secret', id: s.id, name: s.name }
  drawer.value = true
}
</script>

<template>
  <v-container fluid data-test="warden-permissions">
    <v-row>
      <v-col cols="12" md="4">
        <v-card variant="outlined">
          <v-card-title class="text-subtitle-1">Pick a resource</v-card-title>
          <v-card-text>
            <FolderTree :nodes="folders.tree" :selected="selected" @select="select" />
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="8">
        <div class="d-flex align-center mb-3">
          <span class="text-subtitle-1" data-test="picked-path">{{ current?.path ?? '/' }}</span>
          <v-spacer />
          <v-btn v-if="current" variant="tonal" data-test="manage-folder" @click="openFolder">Manage folder access</v-btn>
        </div>
        <v-table density="comfortable" aria-label="Secrets in the folder">
          <thead>
            <tr>
              <th scope="col">Secret</th>
              <th scope="col">Your permissions</th>
              <th scope="col"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in secrets.items" :key="s.id" :data-test="'perm-row-' + s.id">
              <td>{{ s.name }}</td>
              <td>
                <span v-for="(v, k) in s.permissions" :key="k" class="mr-2"><v-icon :icon="v ? 'mdi-check' : 'mdi-close'" size="x-small" /> {{ k }}</span>
              </td>
              <td><v-btn size="small" variant="text" :data-test="'manage-secret-' + s.id" @click="openSecret(s)">Manage</v-btn></td>
            </tr>
            <tr v-if="!secrets.items.length">
              <td colspan="3" class="text-medium-emphasis">No secrets here.</td>
            </tr>
          </tbody>
        </v-table>
      </v-col>
    </v-row>
    <PermissionDrawer v-if="target" v-model="drawer" :resource-type="target.type" :resource-id="target.id" :resource-name="target.name" @changed="secrets.refresh()" />
  </v-container>
</template>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
}
</style>
