<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useAbility } from '@casl/vue'
import { describe } from '@/api/client'
import type { Secret } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { useFolders } from '@/stores/folders'
import FolderTree from '@/components/FolderTree.vue'
import FolderActions from '@/components/FolderActions.vue'
import SecretDrawer from '@/components/SecretDrawer.vue'
import VersionDrawer from '@/components/VersionDrawer.vue'
import PermissionDrawer from '@/components/PermissionDrawer.vue'
import BitwardenImportDialog from '@/components/BitwardenImportDialog.vue'
import StatsCard from '@/components/StatsCard.vue'
import AuditTable from '@/components/AuditTable.vue'
import { downloadJSON } from '@/api/download'
import type { TransferReport } from '@/stores/transfer'

const secrets = useSecrets()
const folders = useFolders()
const ability = useAbility()
const selected = ref<string | null>(null)
const q = ref('')
const drawer = ref(false)
const versions = ref(false)
const sharing = ref(false)
const current = ref<Secret | null>(null)
const notice = ref('')
const canCreate = computed(() => ability.can('create', 'Secret'))
const canImport = computed(() => ability.can('import', 'Transfer'))
const canExport = computed(() => ability.can('export', 'Transfer'))
const canBackup = computed(() => ability.can('manage', 'Backup'))
const canStats = computed(() => ability.can('read', 'Stats'))
const showAudit = ref(false)
const importing = ref(false)
const currentFolder = computed(() => (selected.value ? folders.find(selected.value)?.folder : undefined))
const canCreateHere = computed(() => canCreate.value && (!selected.value || !!currentFolder.value?.permissions.write))
// Explorer pane: the subfolders of the current folder are listed before its secrets.
const childFolders = computed(() => (selected.value ? (folders.find(selected.value)?.children ?? []) : folders.tree).map((n) => n.folder))
// Breadcrumb from the root to the current folder.
const crumbs = computed(() => {
  const out: Array<{ id: string; name: string }> = []
  for (let f = currentFolder.value; f; f = f.parent_id ? folders.find(f.parent_id)?.folder : undefined) out.unshift({ id: f.id, name: f.name })
  return out
})
const folderError = ref('')

onMounted(async () => {
  await Promise.all([folders.load(), secrets.list(null)])
})

async function select(id: string | null): Promise<void> {
  selected.value = id
  q.value = ''
  folderError.value = ''
  await secrets.list(id)
}

async function folderChanged(text: string): Promise<void> {
  notice.value = text
  folderError.value = ''
  await secrets.list(selected.value)
}

async function search(): Promise<void> {
  await secrets.search(q.value)
}

function open(s: Secret | null): void {
  current.value = s
  drawer.value = true
}

// Secondary drawers replace the secret drawer (two temporary drawers on the
// same side would overlap); closing them brings the secret drawer back.
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

function openShare(s: Secret): void {
  current.value = s
  drawer.value = false
  sharing.value = true
}

function saved(s: Secret): void {
  current.value = s
  notice.value = 'Saved ' + s.name + '.'
}

async function restored(v: number): Promise<void> {
  notice.value = 'Restored as version ' + v + '.'
  if (current.value) current.value = await secrets.get(current.value.id)
}

const errorText = computed(() => (secrets.error ? describe(new Error(secrets.error)) : ''))

async function imported(r: TransferReport): Promise<void> {
  notice.value = 'Imported: ' + r.created + ' created, ' + r.renamed + ' renamed, ' + r.skipped + ' skipped, ' + r.overwritten + ' overwritten.'
  await Promise.all([folders.load(), secrets.refresh()])
}

async function exportBitwarden(): Promise<void> {
  try {
    const q = selected.value ? '?folder_id=' + selected.value : ''
    await downloadJSON('/api/warden/v1/transfer/bitwarden/export' + q, 'warden-bitwarden-export.json')
    notice.value = 'Export downloaded. It contains passwords: handle it as a secret.'
  } catch (e) {
    secrets.error = (e as Error).message
  }
}

async function backup(withMaterial: boolean): Promise<void> {
  try {
    await downloadJSON('/api/warden/v1/backup/export' + (withMaterial ? '?include_material=true' : ''), withMaterial ? 'warden-backup-with-material.json' : 'warden-backup.json')
    notice.value = withMaterial ? 'Backup with material downloaded: handle it as a secret.' : 'Backup downloaded (no material).'
  } catch (e) {
    secrets.error = (e as Error).message
  }
}
</script>

<template>
  <div data-test="warden-secrets">
    <v-alert v-if="secrets.error" type="error" variant="tonal" density="compact" class="mb-3" data-test="list-error">{{ errorText }}</v-alert>
    <v-alert v-if="folderError" type="error" variant="tonal" density="compact" class="mb-3" data-test="folder-error">{{ folderError }}</v-alert>
    <v-alert v-if="notice" type="success" variant="tonal" density="compact" closable class="mb-3" data-test="notice" @click:close="notice = ''">{{ notice }}</v-alert>
    <v-card class="explorer">
      <!-- Left pane: the folder tree and its management. -->
      <aside class="explorer__folders" aria-label="Folders">
        <div class="explorer__pane-header">
          <span class="text-subtitle-1 font-weight-medium">Folders</span>
          <v-spacer />
          <FolderActions :selected="selected" @notice="folderChanged" @error="folderError = $event" @select="select" />
        </div>
        <v-progress-linear v-if="folders.loading" indeterminate aria-label="Loading folders" />
        <div class="explorer__tree">
          <FolderTree :nodes="folders.tree" :selected="selected" @select="select" />
        </div>
      </aside>
      <!-- Right pane: what the current folder holds. -->
      <section class="explorer__content">
        <div class="explorer__pane-header explorer__toolbar">
          <nav class="explorer__crumbs" aria-label="Current folder" data-test="current-path">
            <button type="button" class="explorer__crumb" :class="{ 'explorer__crumb--current': !crumbs.length }" aria-label="Root" @click="select(null)"><v-icon icon="mdi-home-outline" size="small" /></button>
            <template v-for="(c, i) in crumbs" :key="c.id">
              <span class="explorer__crumb-sep" aria-hidden="true">/</span>
              <span v-if="i === crumbs.length - 1" class="explorer__crumb explorer__crumb--current" aria-current="page">{{ c.name }}</span>
              <button v-else type="button" class="explorer__crumb" :aria-label="'Go up to ' + c.name" @click="select(c.id)">{{ c.name }}</button>
            </template>
          </nav>
          <v-spacer />
          <v-text-field v-model="q" placeholder="Search secrets" prepend-inner-icon="mdi-magnify" hide-details density="compact" clearable class="explorer__search" aria-label="Search secrets" data-test="search" @keyup.enter="search" @click:clear="select(selected)" />
          <v-btn variant="tonal" data-test="search-go" @click="search">Search</v-btn>
          <v-btn v-if="canCreateHere" color="primary" prepend-icon="mdi-plus" data-test="new-secret" @click="open(null)">New secret</v-btn>
          <v-menu v-if="canImport || canExport || canBackup">
            <template #activator="{ props: menu }">
              <v-btn v-bind="menu" variant="text" icon="mdi-dots-vertical" aria-label="More actions" data-test="more-actions" />
            </template>
            <v-list density="compact">
              <v-list-item v-if="canImport" title="Import from Bitwarden" data-test="action-import" @click="importing = true" />
              <v-list-item v-if="canExport" title="Export to Bitwarden" data-test="action-export" @click="exportBitwarden" />
              <v-list-item v-if="canBackup" title="Backup (no material)" data-test="action-backup" @click="backup(false)" />
              <v-list-item v-if="canBackup" title="Backup with material" data-test="action-backup-material" @click="backup(true)" />
            </v-list>
          </v-menu>
        </div>
        <p v-if="secrets.query" class="text-caption px-4 pt-3" data-test="search-results">Results for “{{ secrets.query }}”</p>
        <v-progress-linear v-if="secrets.loading" indeterminate aria-label="Loading secrets" />
        <v-table density="comfortable" aria-label="Folder contents">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Username</th>
              <th scope="col">Host</th>
              <th scope="col">Folder</th>
              <th scope="col">Version</th>
            </tr>
          </thead>
          <tbody>
            <template v-if="!secrets.query">
              <tr v-for="f in childFolders" :key="f.id" class="explorer__row" data-test="folder-row" @click="select(f.id)">
                <td class="explorer__name"><v-icon icon="mdi-folder" color="warning" size="small" class="mr-2" />{{ f.name }}</td>
                <td class="text-medium-emphasis" colspan="3">{{ f.secret_count }} secret(s)</td>
                <td class="text-medium-emphasis">—</td>
              </tr>
            </template>
            <tr v-for="s in secrets.items" :key="s.id" class="explorer__row" data-test="secret-row" @click="open(s)">
              <td class="explorer__name">
                <v-icon icon="mdi-key-variant" color="primary" size="small" class="mr-2" />
                <button type="button" class="explorer__link" :data-test="'secret-open-' + s.id">{{ s.name }}</button>
                <v-icon v-if="s.has_totp" icon="mdi-clock-outline" size="x-small" class="ml-1" aria-label="Has one-time code" />
              </td>
              <td>{{ s.username }}</td>
              <td class="text-truncate" style="max-width: 220px">{{ s.host_url }}</td>
              <td>{{ s.folder_path || '/' }}</td>
              <td>{{ s.current_version }}</td>
            </tr>
            <tr v-if="!secrets.loading && secrets.items.length === 0 && (secrets.query || childFolders.length === 0)">
              <td colspan="5" class="text-medium-emphasis" data-test="empty">{{ secrets.query ? 'No secrets match.' : 'This folder is empty.' }}</td>
            </tr>
          </tbody>
        </v-table>
        <div v-if="secrets.next" class="px-4 py-2">
          <v-btn variant="text" data-test="load-more" @click="secrets.more()">Load more</v-btn>
        </div>
      </section>
    </v-card>
    <template v-if="canStats">
      <StatsCard class="mt-6" />
      <v-btn variant="text" class="mt-2" data-test="toggle-audit" @click="showAudit = !showAudit">{{ showAudit ? 'Hide audit trail' : 'Show audit trail' }}</v-btn>
      <AuditTable v-if="showAudit" class="mt-2" />
    </template>
    <SecretDrawer v-model="drawer" :secret="current" :folder-id="selected" @saved="saved" @deleted="notice = 'Secret deleted.'" @versions="openVersions" @share="openShare" />
    <VersionDrawer :model-value="versions" :secret="current" @update:model-value="closeSecondary" @restored="restored" />
    <PermissionDrawer v-if="current" :model-value="sharing" resource-type="secret" :resource-id="current.id" :resource-name="current.name" @update:model-value="closeSecondary" @changed="secrets.refresh()" />
    <BitwardenImportDialog v-model="importing" :folder-id="selected" @imported="imported" />
  </div>
</template>

<style scoped>
/* Two panes like a file manager: folders on the left, contents on the right. */
.explorer {
  display: flex;
  min-height: 480px;
}
.explorer__folders {
  flex: 0 0 280px;
  border-inline-end: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
  display: flex;
  flex-direction: column;
}
.explorer__content {
  flex: 1 1 auto;
  min-width: 0;
}
.explorer__pane-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-height: 56px;
  padding: 0.5rem 1rem;
  border-block-end: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
}
.explorer__toolbar {
  flex-wrap: wrap;
}
.explorer__search {
  flex: 0 1 260px;
}
.explorer__tree {
  padding: 0.5rem;
  overflow: auto;
}
.explorer__crumbs {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  min-width: 0;
  white-space: nowrap;
}
.explorer__crumb {
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  padding: 0.125rem 0.25rem;
  border-radius: 4px;
  cursor: pointer;
}
.explorer__crumb--current {
  cursor: default;
  font-weight: 500;
}
.explorer__crumb-sep {
  opacity: 0.5;
}
.explorer__row {
  cursor: pointer;
}
.explorer__name {
  white-space: nowrap;
}
.explorer__link {
  border: 0;
  background: transparent;
  color: rgb(var(--v-theme-primary));
  font: inherit;
  padding: 0;
  cursor: pointer;
}
@media (max-width: 959px) {
  .explorer {
    flex-direction: column;
  }
  .explorer__folders {
    flex-basis: auto;
    border-inline-end: 0;
    border-block-end: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
  }
}
</style>
