<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiTree, UiDataTable, UiButton, UiIcon, UiPermissionDrawer, usePermissionGrants, type Column, type TreeNode } from '@freya/ui'
import { useFolders } from '@/stores/folders'
import { useSecrets } from '@/stores/secrets'
import { useDirectory } from '@/stores/directory'
import { grantable, usePermissions, type Relation, type ResourceType, type SubjectType } from '@/stores/permissions'
import type { FolderNode, Secret } from '@/api/types'

const folders = useFolders()
const secrets = useSecrets()
const perms = usePermissions()
const dir = useDirectory()
const selected = ref<string | null>(null)
const drawer = ref(false)
const target = ref<{ type: ResourceType; id: string; name: string } | null>(null)
const current = computed(() => (selected.value ? folders.find(selected.value)?.folder : undefined))
const ROOT = '__root__'
const toNode = (n: FolderNode): TreeNode => ({ id: n.folder.id, label: n.folder.name, icon: 'mdi-folder-outline', children: n.children.map(toNode) })
const tree = computed<TreeNode[]>(() => [{ id: ROOT, label: 'Root', icon: 'mdi-home-outline', children: folders.tree.map(toNode) }])
const treeSelected = computed({ get: () => selected.value ?? ROOT, set: (id: string) => void select(id === ROOT ? null : id) })
onMounted(async () => {
  await Promise.all([folders.load(), secrets.list(null), dir.loadRoles()])
})
async function select(id: string | null): Promise<void> {
  selected.value = id
  await secrets.list(id)
}
const access = usePermissionGrants({
  grants: () => perms.grants,
  effective: () => ({ relation: perms.effective?.relation, canShare: !!perms.effective?.permissions.share }),
  grant: (r) => perms.grant({ resource_type: target.value!.type, resource_id: target.value!.id, subject_type: r.subject_type as SubjectType, subject_id: r.subject_id, relation: r.relation as Relation, expires_at: r.expires_at ?? null }),
  revoke: async (id) => { const g = perms.grants.find((x) => x.id === id); if (g) await perms.revoke(g, target.value!.type, target.value!.id) },
  directory: { roles: () => Object.values(dir.roles), searchUsers: perms.searchUsers, resolveUsers: dir.resolveUsers, userName: dir.userName, roleName: dir.roleName },
  grantable,
})
async function open(type: ResourceType, id: string, name: string): Promise<void> {
  target.value = { type, id, name }
  drawer.value = true
  await perms.load(type, id)
  await access.resolve()
}
async function closed(v: boolean): Promise<void> {
  drawer.value = v
  if (!v) await secrets.refresh()
}
const columns: Column<Secret>[] = [
  { key: 'name', label: 'Secret' },
  { key: 'permissions', label: 'Your permissions', format: (s) => Object.entries(s.permissions).filter(([, v]) => v).map(([k]) => k).join(', ') },
]
</script>

<template>
  <UiPage title="Permissions" subtitle="Who can read, edit, share or own each folder and secret" data-test="warden-permissions">
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <UiCard class="lg:col-span-4" title="Pick a resource"><UiTree v-model:selected="treeSelected" :items="tree" /></UiCard>
      <UiCard class="lg:col-span-8" :padded="false">
        <div class="flex flex-wrap items-center gap-2 border-b border-base-300 px-4 py-2">
          <span class="font-medium" data-test="picked-path">{{ current?.path ?? '/' }}</span>
          <span class="grow" />
          <UiButton v-if="current" size="sm" variant="soft" data-test="manage-folder" @click="open('folder', current.id, current.path)">Manage folder access</UiButton>
        </div>
        <UiDataTable :items="secrets.items" :columns="columns" :loading="secrets.loading" caption="Secrets in the folder" empty-title="No secrets here" :row-attrs="(s) => ({ 'data-test': 'perm-row-' + s.id })">
          <template #cell-permissions="{ row }">
            <span v-for="(v, k) in row.permissions" :key="k" class="me-2 inline-flex items-center gap-0.5 text-xs"><UiIcon :name="v ? 'mdi-check' : 'mdi-close'" size="xs" :class="v ? 'text-success' : 'text-base-content/70'" />{{ k }}</span>
          </template>
          <template #actions="{ row }"><UiButton size="xs" variant="text" :data-test="'manage-secret-' + row.id" @click="open('secret', row.id, row.name)">Manage</UiButton></template>
        </UiDataTable>
      </UiCard>
    </div>
    <UiPermissionDrawer :model-value="drawer" :title="'Access to ' + (target?.name ?? '')" :grants="access.grants.value" :subjects="access.subjects.value" :levels="access.levels.value" :can-manage="access.canShare.value" expires :editable-level="false" :hint="access.hint.value" :error="access.error.value" :busy="access.busy.value" data-test="permission-drawer" @update:model-value="closed" @search="access.search" @grant="access.onGrant" @revoke="access.onRevoke" @change-level="access.onChangeLevel" />
  </UiPage>
</template>
