<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useAbility } from '@casl/vue'
import { UiPage, UiAlert, UiCard, UiButton, UiTree, UiDataTable, UiInput, UiForm, UiIcon, UiDropdownMenu, UiRecordDrawer, UiStatGrid, UiStatTile, UiKeyValueTable, UiPermissionDrawer, usePermissionGrants, useToast, useConfirm, type Column, type MenuItem, type TreeNode } from '@freya/ui'
import { useZodForm, zodToFields } from '@freya/ui/forms'
import { describe } from '@/api/client'
import type { Folder, FolderNode, Secret } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { useFolders } from '@/stores/folders'
import { useOps } from '@/stores/ops'
import { useDirectory } from '@/stores/directory'
import { grantable, usePermissions, type Relation, type SubjectType } from '@/stores/permissions'
import FolderActions from '@/components/FolderActions.vue'
import SecretDetails from '@/components/SecretDetails.vue'
import VersionDrawer from '@/components/VersionDrawer.vue'
import BitwardenImportDialog from '@/components/BitwardenImportDialog.vue'
import { downloadJSON } from '@/api/download'
import type { TransferReport } from '@/stores/transfer'
import { secretCreateSchema, secretUpdateSchema, searchSchema, auditFilterSchema } from '@/schemas'

const secrets = useSecrets()
const folders = useFolders()
const ops = useOps()
const dir = useDirectory()
const perms = usePermissions()
const ability = useAbility()
const toast = useToast()
const confirm = useConfirm()
const selected = ref<string | null>(null)
const drawer = ref(false)
const versions = ref(false)
const sharing = ref(false)
const current = ref<Secret | null>(null)
const importing = ref(false)
const showAudit = ref(false)
const folderError = ref('')
const canCreate = computed(() => ability.can('create', 'Secret'))
const canImport = computed(() => ability.can('import', 'Transfer'))
const canExport = computed(() => ability.can('export', 'Transfer'))
const canBackup = computed(() => ability.can('manage', 'Backup'))
const canStats = computed(() => ability.can('read', 'Stats'))
const currentFolder = computed(() => (selected.value ? folders.find(selected.value)?.folder : undefined))
const canCreateHere = computed(() => canCreate.value && (!selected.value || !!currentFolder.value?.permissions.write))
// Explorer pane: the subfolders of the current folder are listed before its secrets.
const childFolders = computed(() => (selected.value ? (folders.find(selected.value)?.children ?? []) : folders.tree).map((n) => n.folder))
const crumbs = computed(() => {
  const out: Array<{ id: string; name: string }> = []
  for (let f = currentFolder.value; f; f = f.parent_id ? folders.find(f.parent_id)?.folder : undefined) out.unshift({ id: f.id, name: f.name })
  return out
})
onMounted(async () => {
  await Promise.all([folders.load(), secrets.list(null)])
  if (canStats.value) void ops.loadStats()
})

// --- folder tree: a synthetic root node above the vault folders ---
const ROOT = '__root__'
const toNode = (n: FolderNode): TreeNode => ({ id: n.folder.id, label: n.folder.name, icon: 'mdi-folder-outline', badge: n.folder.secret_count ? String(n.folder.secret_count) : '', children: n.children.map(toNode) })
const tree = computed<TreeNode[]>(() => [{ id: ROOT, label: 'Root', icon: 'mdi-home-outline', children: folders.tree.map(toNode) }])
const treeSelected = computed({ get: () => selected.value ?? ROOT, set: (id: string) => void select(id === ROOT ? null : id) })
async function select(id: string | null): Promise<void> {
  selected.value = id
  search.reset({ q: '' })
  folderError.value = ''
  await secrets.list(id)
}
async function folderChanged(text: string): Promise<void> {
  toast.success(text)
  folderError.value = ''
  await Promise.all([folders.load(), secrets.list(selected.value)])
}
const search = useZodForm(searchSchema, { initial: { q: '' }, onSubmit: (v) => (v.q ? secrets.search(v.q) : secrets.list(selected.value)) })

// --- rows: folders first, then secrets (one table, stacked cards below md) ---
type Row = Record<string, unknown> & { id: string; kind: 'folder' | 'secret'; name: string; username: string; host_url: string; folder_path: string; version: string; folder?: Folder; secret?: Secret }
const rows = computed<Row[]>(() => [
  ...(secrets.query ? [] : childFolders.value.map((f): Row => ({ id: 'f:' + f.id, kind: 'folder', name: f.name, username: f.secret_count + ' secret(s)', host_url: '', folder_path: '', version: '', folder: f }))),
  ...secrets.items.map((s): Row => ({ id: s.id, kind: 'secret', name: s.name, username: s.username, host_url: s.host_url, folder_path: s.folder_path || '/', version: String(s.current_version), secret: s })),
])
const columns: Column<Row>[] = [
  { key: 'name', label: 'Name' },
  { key: 'username', label: 'Username' },
  { key: 'host_url', label: 'Host', hideOnStack: true },
  { key: 'folder_path', label: 'Folder', hideOnStack: true },
  { key: 'version', label: 'Version', width: 'sm', align: 'end' },
]
function onRow(r: Row): void {
  if (r.kind === 'folder' && r.folder) void select(r.folder.id)
  else if (r.secret) open(r.secret)
}

// --- secret drawer: kit record form (create vs edit schema) + vault details ---
const folderOptions = computed(() => folders.flat().map((f) => ({ title: f.folder.path, value: f.folder.id })))
const schema = computed(() => (current.value ? secretUpdateSchema : secretCreateSchema))
const fields = computed(() => zodToFields(schema.value, { folder_id: { type: 'select', options: folderOptions.value, placeholder: 'Root' }, host_url: { label: 'Host URL' }, description: { type: 'textarea', cols: 12 }, metadata: { label: 'Metadata (JSON)', type: 'textarea', cols: 12 }, password: { type: 'secret' }, totp: { label: 'TOTP seed (optional)', type: 'secret' } }))
const initial = computed(() => (current.value ? { folder_id: current.value.folder_id ?? '', name: current.value.name, username: current.value.username, host_url: current.value.host_url, description: current.value.description, metadata: JSON.stringify(current.value.metadata ?? {}, null, 2) } : { folder_id: selected.value ?? '', metadata: '{}' }))
async function submit(v: Record<string, unknown>): Promise<Secret> {
  const folder_id = (v.folder_id as string | undefined) ?? null
  if (current.value) {
    const s = await secrets.update(current.value.id, { name: v.name as string, username: v.username as string, host_url: v.host_url as string, description: v.description as string, metadata: v.metadata as Record<string, unknown> })
    return folder_id !== current.value.folder_id ? secrets.move(current.value.id, folder_id) : s
  }
  return secrets.create({ folder_id, name: v.name as string, username: v.username as string, host_url: v.host_url as string, description: v.description as string, metadata: v.metadata as Record<string, unknown>, password: v.password as string, totp: v.totp as string | undefined })
}
function open(s: Secret | null): void {
  current.value = s
  drawer.value = true
}
function saved(v: unknown): void {
  const s = v as Secret
  current.value = s
  toast.success('Saved ' + s.name + '.')
  void secrets.refresh()
}
// Secondary drawers replace the secret drawer; closing them brings it back.
function openVersions(s: Secret): void {
  current.value = s
  drawer.value = false
  versions.value = true
}
function closeSecondary(): void {
  versions.value = false
  sharing.value = false
  drawer.value = true
}
async function restored(v: number): Promise<void> {
  toast.success('Restored as version ' + v + '.')
  if (current.value) current.value = await secrets.get(current.value.id)
}
async function removeSecret(): Promise<void> {
  if (!current.value || !(await confirm.ask({ title: 'Delete secret?', text: 'Every version is destroyed in the vault. This cannot be undone.', danger: true, confirmLabel: 'Delete' }))) return
  try {
    await secrets.remove(current.value.id)
    drawer.value = false
    toast.success('Secret deleted.')
  } catch (e) {
    secrets.error = (e as Error).message
  }
}
// --- access grants on the current secret (share permission) ---
const access = usePermissionGrants({
  grants: () => perms.grants,
  effective: () => ({ relation: perms.effective?.relation, canShare: !!perms.effective?.permissions.share }),
  grant: (r) => perms.grant({ resource_type: 'secret', resource_id: current.value!.id, subject_type: r.subject_type as SubjectType, subject_id: r.subject_id, relation: r.relation as Relation, expires_at: r.expires_at ?? null }),
  revoke: async (id) => { const g = perms.grants.find((x) => x.id === id); if (g) await perms.revoke(g, 'secret', current.value!.id) },
  directory: { roles: () => Object.values(dir.roles), searchUsers: perms.searchUsers, resolveUsers: dir.resolveUsers, userName: dir.userName, roleName: dir.roleName },
  grantable,
})
async function openShare(): Promise<void> {
  if (!current.value) return
  drawer.value = false
  sharing.value = true
  await Promise.all([perms.load('secret', current.value.id), dir.loadRoles()])
  await access.resolve()
}

// --- more actions: import / export / backup ---
const moreItems = computed<MenuItem[]>(() => [
  ...(canImport.value ? [{ key: 'import', label: 'Import from Bitwarden', icon: 'mdi-import' }] : []),
  ...(canExport.value ? [{ key: 'export', label: 'Export to Bitwarden', icon: 'mdi-export' }] : []),
  ...(canBackup.value ? [{ key: 'backup', label: 'Backup (no material)', icon: 'mdi-database-arrow-down-outline' }, { key: 'backup-material', label: 'Backup with material', icon: 'mdi-database-lock-outline', danger: true }] : []),
])
async function onMore(key: string): Promise<void> {
  try {
    if (key === 'import') importing.value = true
    else if (key === 'export') {
      await downloadJSON('/api/warden/v1/transfer/bitwarden/export' + (selected.value ? '?folder_id=' + selected.value : ''), 'warden-bitwarden-export.json')
      toast.warning('Export downloaded', 'It contains passwords: handle it as a secret.')
    } else if (key === 'backup' || key === 'backup-material') {
      const withMaterial = key === 'backup-material'
      await downloadJSON('/api/warden/v1/backup/export' + (withMaterial ? '?include_material=true' : ''), withMaterial ? 'warden-backup-with-material.json' : 'warden-backup.json')
      toast.success(withMaterial ? 'Backup with material downloaded: handle it as a secret.' : 'Backup downloaded (no material).')
    }
  } catch (e) {
    secrets.error = (e as Error).message
  }
}
async function imported(r: TransferReport): Promise<void> {
  toast.success('Imported', `${r.created} created, ${r.renamed} renamed, ${r.skipped} skipped, ${r.overwritten} overwritten.`)
  await Promise.all([folders.load(), secrets.refresh()])
}
const errorText = computed(() => (secrets.error ? describe(new Error(secrets.error)) : ''))

// --- statistics + audit (Stats ability) ---
const auditFilter = useZodForm(auditFilterSchema, {
  initial: { event_type: '', actor_id: '', from: '', to: '' },
  onSubmit: async (f) => {
    await ops.loadAudit({ event_type: f.event_type || undefined, actor_id: f.actor_id || undefined, from: f.from, to: f.to })
    await dir.resolveUsers(ops.audit.filter((e) => e.actor_kind === 'user').map((e) => e.actor_id))
  },
})
async function toggleAudit(): Promise<void> {
  showAudit.value = !showAudit.value
  if (showAudit.value) await auditFilter.submit()
}
const auditRows = computed(() => ops.audit.map((e, n) => ({ ...e, id: e.ts + ':' + n })))
const auditColumns: Column<(typeof auditRows.value)[number]>[] = [
  { key: 'ts', label: 'When', format: (e) => new Date(e.ts).toLocaleString() },
  { key: 'event_type', label: 'Event' },
  { key: 'actor', label: 'Actor', format: (e) => (e.actor_kind === 'user' ? dir.userName(e.actor_id) : e.actor_kind === 'system' ? 'system' : e.actor_kind + (e.actor_id ? ' ' + e.actor_id : '')) },
  { key: 'subject', label: 'Subject', format: (e) => (e.subject_kind ? e.subject_kind + (e.subject_name ? ' ' + e.subject_name : e.subject_id ? ' ' + e.subject_id : '') : ''), hideOnStack: true },
  { key: 'outcome', label: 'Outcome', width: 'sm', format: (e) => e.outcome + (e.reason ? ' (' + e.reason + ')' : '') },
]
const moreAudit = async () => {
  const f = auditFilter.validate()
  if (!f) return
  await ops.loadAudit({ event_type: f.event_type || undefined, actor_id: f.actor_id || undefined, from: f.from, to: f.to }, ops.next)
  await dir.resolveUsers(ops.audit.filter((e) => e.actor_kind === 'user').map((e) => e.actor_id))
}
const statItems = computed(() => (ops.stats ? [{ label: 'Grants', value: Object.entries(ops.stats.grants ?? {}).map(([k, v]) => k + ' ' + v).join(', ') || 'none' }, { label: 'Shares', value: Object.entries(ops.stats.shares ?? {}).map(([k, v]) => k + ' ' + v).join(', ') || 'none' }] : []))
</script>

<template>
  <UiPage title="Secrets" data-test="warden-secrets">
    <template #actions>
      <UiButton v-if="canCreateHere" icon="mdi-plus" data-test="new-secret" @click="open(null)">New secret</UiButton>
      <UiDropdownMenu v-if="moreItems.length" :items="moreItems" label="More actions" data-test="more-actions" @select="onMore" />
    </template>
    <UiAlert v-if="secrets.error" kind="error" class="mb-3" data-test="list-error">{{ errorText }}</UiAlert>
    <UiAlert v-if="folderError" kind="error" class="mb-3" data-test="folder-error">{{ folderError }}</UiAlert>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <UiCard class="lg:col-span-4" title="Folders">
        <template #header><div class="flex grow justify-end"><FolderActions :selected="selected" @notice="folderChanged" @error="folderError = $event" @select="select" /></div></template>
        <UiTree v-model:selected="treeSelected" :items="tree" />
      </UiCard>
      <UiCard class="lg:col-span-8" :padded="false">
        <div class="flex flex-wrap items-center gap-2 border-b border-base-300 px-4 py-2">
          <nav class="flex min-w-0 items-center gap-1 text-sm" aria-label="Current folder" data-test="current-path">
            <button type="button" class="btn btn-text btn-xs" aria-label="Root" @click="select(null)"><UiIcon name="mdi-home-outline" size="sm" /></button>
            <template v-for="(c, i) in crumbs" :key="c.id">
              <span class="opacity-50" aria-hidden="true">/</span>
              <span v-if="i === crumbs.length - 1" class="truncate font-medium" aria-current="page">{{ c.name }}</span>
              <button v-else type="button" class="btn btn-text btn-xs" :aria-label="'Go up to ' + c.name" @click="select(c.id)">{{ c.name }}</button>
            </template>
          </nav>
          <span class="grow" />
          <UiForm :form="search" class="flex items-end gap-2">
            <UiInput v-bind="search.field('q')" label="Search secrets" sr-only-label placeholder="Search secrets" type="search" size="sm" data-test="search" @enter="search.submit()" />
            <UiButton type="submit" size="sm" variant="soft" data-test="search-go">Search</UiButton>
          </UiForm>
        </div>
        <p v-if="secrets.query" class="px-4 pt-3 text-xs text-base-content/70" data-test="search-results">Results for “{{ secrets.query }}”</p>
        <UiDataTable :items="rows" :columns="columns" :loading="secrets.loading || folders.loading" caption="Folder contents" :empty-title="secrets.query ? 'No secrets match' : 'This folder is empty'" clickable :has-more="!!secrets.next" :row-attrs="(r) => ({ 'data-test': r.kind === 'folder' ? 'folder-row' : 'secret-row' })" @row-click="onRow" @load-more="secrets.more()">
          <template #cell-name="{ row }">
            <span class="inline-flex items-center gap-1">
              <UiIcon :name="row.kind === 'folder' ? 'mdi-folder' : 'mdi-key-variant'" size="sm" :class="row.kind === 'folder' ? 'text-warning' : 'text-primary'" />
              <span :data-test="row.kind === 'secret' ? 'secret-open-' + row.id : undefined">{{ row.name }}</span>
              <UiIcon v-if="row.secret?.has_totp" name="mdi-clock-outline" size="xs" label="Has one-time code" />
            </span>
          </template>
        </UiDataTable>
      </UiCard>
    </div>
    <template v-if="canStats">
      <UiStatGrid v-if="ops.stats" class="mt-6" :cols="4" data-test="stats-card">
        <UiStatTile title="Secrets" :value="ops.stats.secrets" icon="mdi-key-variant" color="primary" data-test="stat-secrets" />
        <UiStatTile title="With one-time code" :value="ops.stats.secrets_with_totp" icon="mdi-clock-outline" data-test="stat-totp" />
        <UiStatTile title="Folders" :value="ops.stats.folders" icon="mdi-folder-outline" data-test="stat-folders" />
        <UiStatTile title="Versions" :value="ops.stats.versions" icon="mdi-history" data-test="stat-versions" />
        <UiStatTile title="Operations (24 h)" :value="ops.stats.operations_24h" icon="mdi-pulse" data-test="stat-ops" />
      </UiStatGrid>
      <UiKeyValueTable v-if="ops.stats" class="mt-2" :items="statItems" :columns="2" />
      <p v-else class="mt-6 text-sm text-base-content/70" data-test="stats-empty">{{ ops.error ? 'Statistics unavailable.' : 'Loading…' }}</p>
      <UiButton variant="text" class="mt-2" data-test="toggle-audit" @click="toggleAudit">{{ showAudit ? 'Hide audit trail' : 'Show audit trail' }}</UiButton>
      <UiCard v-if="showAudit" class="mt-2" title="Audit trail" data-test="audit-table">
        <UiForm :form="auditFilter" class="mb-3">
          <div class="grid grid-cols-2 gap-2 md:grid-cols-12 md:items-end">
            <div class="md:col-span-3"><UiInput v-bind="auditFilter.field('event_type')" label="Event type" size="sm" data-test="audit-type" @enter="auditFilter.submit()" /></div>
            <div class="md:col-span-3"><UiInput v-bind="auditFilter.field('actor_id')" label="Actor" size="sm" data-test="audit-actor" @enter="auditFilter.submit()" /></div>
            <div class="md:col-span-2"><UiInput v-bind="auditFilter.field('from')" label="From" type="date" size="sm" /></div>
            <div class="md:col-span-2"><UiInput v-bind="auditFilter.field('to')" label="To" type="date" size="sm" /></div>
            <div class="col-span-2 md:col-span-2"><UiButton type="submit" block size="sm" data-test="audit-apply">Apply</UiButton></div>
          </div>
        </UiForm>
        <UiDataTable :items="auditRows" :columns="auditColumns" caption="Audit events" empty-title="No events" :has-more="!!ops.next" :row-attrs="() => ({ 'data-test': 'audit-row' })" @load-more="moreAudit" />
      </UiCard>
    </template>

    <UiRecordDrawer v-model="drawer" :title="current ? current.name : 'New secret'" :schema="schema" :fields="fields" :initial="initial" :submit="submit" size="lg" :save-label="current ? 'Save' : 'Create'" :readonly="!!current && !current.permissions.write" data-test="secret-drawer" @saved="saved">
      <template #after>
        <SecretDetails v-if="current" :secret="current" @saved="saved" @versions="openVersions" />
        <div v-if="current" class="mt-4 flex flex-wrap gap-2">
          <UiButton v-if="current.permissions.share" variant="soft" size="sm" icon="mdi-shield-account-outline" data-test="secret-share" @click="openShare">Share access</UiButton>
          <span class="grow" />
          <UiButton v-if="current.permissions.delete" variant="text" size="sm" color="error" data-test="secret-delete" @click="removeSecret">Delete</UiButton>
        </div>
      </template>
    </UiRecordDrawer>
    <VersionDrawer :model-value="versions" :secret="current" @update:model-value="closeSecondary" @restored="restored" />
    <UiPermissionDrawer :model-value="sharing" :title="'Access to ' + (current?.name ?? '')" :grants="access.grants.value" :subjects="access.subjects.value" :levels="access.levels.value" :can-manage="access.canShare.value" expires :editable-level="false" :hint="access.hint.value" :error="access.error.value" :busy="access.busy.value" data-test="permission-drawer" @update:model-value="closeSecondary" @search="access.search" @grant="access.onGrant" @revoke="access.onRevoke" @change-level="access.onChangeLevel" />
    <BitwardenImportDialog v-model="importing" :folder-id="selected" @imported="imported" />
  </UiPage>
</template>
