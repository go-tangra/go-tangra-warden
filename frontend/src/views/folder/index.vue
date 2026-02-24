<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, ref, computed, onMounted } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import {
  LucideEye,
  LucideTrash,
  LucidePencil,
  LucideCopy,
  LucideLock,
  LucideFolder,
  LucideFolderOpen,
  LucideHistory,
  LucideKey,
  LucideUpload,
  LucideDownload,
  LucideShare2,
  LucidePlus,
  LucideX,
} from 'shell/vben/icons';

import {
  notification,
  Tree,
  Dropdown,
  Menu,
  MenuItem,
  Space,
  Button,
  Modal,
  Select,
  SelectOption,
  Divider,
} from 'ant-design-vue';
import type { Key } from 'ant-design-vue/es/_util/type';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import {
  type Secret,
  type FolderTreeNode,
  type ExportToBitwardenResponse,
} from '../../api/services';
import { $t } from 'shell/locales';
import type { CreateSharePolicyInput, SharePolicyType, SharePolicyMethod } from '../../types';
import { useWardenFolderStore } from '../../stores/warden-folder.state';
import { useWardenSecretStore } from '../../stores/warden-secret.state';
import { useAccessStore } from 'shell/vben/stores';

import FolderDrawer from './folder-drawer.vue';
import SecretDrawer from '../secret/secret-drawer.vue';
import VersionDrawer from '../secret/version-drawer.vue';
import PermissionDrawer from '../permission/permission-drawer.vue';
import BitwardenImportModal from '../secret/bitwarden-import-modal.vue';

const folderStore = useWardenFolderStore();
const secretStore = useWardenSecretStore();

// Direct API call to sharing service (sharing store is in a separate MF module)
async function createShare(data: Record<string, unknown>) {
  const token = (useAccessStore() as any).accessToken;
  const res = await fetch('/admin/v1/modules/sharing/v1/shares', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `HTTP ${res.status}`);
  }
  return res.json();
}

// Folder tree state
const folderTree = ref<FolderTreeNode[]>([]);
const selectedFolderId = ref<string | undefined>(undefined);
const expandedKeys = ref<string[]>([]);
const loadingTree = ref(false);


// Convert folder tree to ant-design tree data format
interface TreeNode {
  key: string;
  title: string;
  children?: TreeNode[];
  isLeaf?: boolean;
  raw: FolderTreeNode;
}

function convertToTreeData(nodes: FolderTreeNode[]): TreeNode[] {
  return nodes.map((node) => ({
    key: node.folder?.id ?? '',
    title: node.folder?.name ?? '',
    children: node.children ? convertToTreeData(node.children) : undefined,
    isLeaf: !node.children || node.children.length === 0,
    raw: node,
  }));
}

const treeData = computed(() => convertToTreeData(folderTree.value));

// Load folder tree
async function loadFolderTree() {
  loadingTree.value = true;
  try {
    const resp = await folderStore.getFolderTree(undefined, undefined, true);
    folderTree.value = (resp.roots ?? []) as FolderTreeNode[];
  } catch {
    notification.error({ message: $t('ui.notification.load_failed') });
  } finally {
    loadingTree.value = false;
  }
}

onMounted(() => {
  loadFolderTree();
});

// Handle folder selection
function handleFolderSelect(keys: Key[]) {
  if (keys.length > 0) {
    selectedFolderId.value = String(keys[0]);
    gridApi.reload();
  } else {
    selectedFolderId.value = undefined;
    gridApi.reload();
  }
}

// Secret list
const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Input',
      fieldName: 'nameFilter',
      label: $t('warden.page.secret.name'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
  ],
};

const gridOptions: VxeGridProps<Secret> = {
  height: 'auto',
  stripe: false,
  toolbarConfig: {
    custom: true,
    export: true,
    import: false,
    refresh: true,
    zoom: true,
  },
  exportConfig: {},
  rowConfig: {
    isHover: true,
  },
  pagerConfig: {
    enabled: true,
    pageSize: 20,
    pageSizes: [10, 20, 50, 100],
  },

  proxyConfig: {
    ajax: {
      query: async ({ page }, formValues) => {
        const resp = await secretStore.listSecrets(
          { page: page.currentPage, pageSize: page.pageSize },
          {
            folderId: selectedFolderId.value,
            nameFilter: formValues?.nameFilter,
          },
        );
        return {
          items: resp.secrets ?? [],
          total: resp.total ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    {
      title: $t('warden.page.secret.name'),
      field: 'name',
      minWidth: 150,
      slots: { default: 'name' },
    },
    { title: $t('warden.page.secret.username'), field: 'username', width: 150 },
    { title: $t('warden.page.secret.hostUrl'), field: 'hostUrl', minWidth: 200 },
    {
      title: $t('warden.page.secret.currentVersion'),
      field: 'currentVersion',
      width: 100,
    },
    {
      title: $t('ui.table.createdAt'),
      field: 'createTime',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 180,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

// Drawer states
const drawerMode = ref<'create' | 'edit' | 'view'>('view');
const folderDrawerMode = ref<'create' | 'edit'>('create');

const [SecretDrawerComponent, secretDrawerApi] = useVbenDrawer({
  connectedComponent: SecretDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

const [FolderDrawerComponent, folderDrawerApi] = useVbenDrawer({
  connectedComponent: FolderDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      loadFolderTree();
    }
  },
});

const [VersionDrawerComponent, versionDrawerApi] = useVbenDrawer({
  connectedComponent: VersionDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

const [PermissionDrawerComponent, permissionDrawerApi] = useVbenDrawer({
  connectedComponent: PermissionDrawer,
});

// Bitwarden Import Modal ref
const bitwardenImportModalRef = ref<InstanceType<typeof BitwardenImportModal> | null>(null);

// Secret operations
function openSecretDrawer(
  row: Secret,
  mode: 'create' | 'edit' | 'view',
) {
  drawerMode.value = mode;
  secretDrawerApi.setData({ row, mode, folderId: selectedFolderId.value });
  secretDrawerApi.open();
}

function handleViewSecret(row: Secret) {
  openSecretDrawer(row, 'view');
}

function handleEditSecret(row: Secret) {
  openSecretDrawer(row, 'edit');
}

function handleCreateSecret() {
  openSecretDrawer({} as Secret, 'create');
}

async function handleDeleteSecret(row: Secret) {
  if (!row.id) return;
  try {
    await secretStore.deleteSecret(row.id);
    notification.success({ message: $t('warden.page.secret.deleteSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}

async function handleCopyPassword(row: Secret) {
  if (!row.id) return;
  try {
    const resp = await secretStore.getSecretPassword(row.id);
    await navigator.clipboard.writeText(resp.password ?? '');
    notification.success({ message: $t('warden.page.secret.passwordCopied') });
  } catch {
    notification.error({ message: $t('ui.notification.operation_failed') });
  }
}

function handleViewVersions(row: Secret) {
  versionDrawerApi.setData({ secret: row });
  versionDrawerApi.open();
}

function handleViewPermissions(row: Secret) {
  permissionDrawerApi.setData({
    resourceType: 'RESOURCE_TYPE_SECRET',
    resourceId: row.id,
    resourceName: row.name,
  });
  permissionDrawerApi.open();
}

// Share secret
const shareModalVisible = ref(false);
const shareSecretRow = ref<Secret | null>(null);
const shareEmail = ref('');
const shareMessage = ref('');
const shareLoading = ref(false);
const sharePolicies = ref<CreateSharePolicyInput[]>([]);
const showPolicyForm = ref(false);
const policyType = ref<SharePolicyType>('SHARE_POLICY_TYPE_WHITELIST');
const policyMethod = ref<SharePolicyMethod>('SHARE_POLICY_METHOD_IP');
const policyValue = ref('');
const policyReason = ref('');

const policyMethodOptions: { value: SharePolicyMethod; label: string; placeholder: string }[] = [
  { value: 'SHARE_POLICY_METHOD_IP', label: 'IP Address', placeholder: 'e.g. 192.168.1.1' },
  { value: 'SHARE_POLICY_METHOD_NETWORK', label: 'Network (CIDR)', placeholder: 'e.g. 10.1.111.0/24' },
  { value: 'SHARE_POLICY_METHOD_MAC', label: 'MAC Address', placeholder: 'e.g. AA:BB:CC:DD:EE:FF' },
  { value: 'SHARE_POLICY_METHOD_REGION', label: 'Region', placeholder: 'e.g. US, DE, BG' },
  { value: 'SHARE_POLICY_METHOD_TIME', label: 'Time Window', placeholder: 'e.g. 09:00-17:00' },
  { value: 'SHARE_POLICY_METHOD_DEVICE', label: 'Device', placeholder: 'e.g. mobile, desktop' },
];

const currentPlaceholder = computed(() => {
  return policyMethodOptions.find(o => o.value === policyMethod.value)?.placeholder || '';
});

function handleShareSecret(row: Secret) {
  shareSecretRow.value = row;
  shareEmail.value = '';
  shareMessage.value = '';
  sharePolicies.value = [];
  showPolicyForm.value = false;
  shareModalVisible.value = true;
}

function handleAddPolicy() {
  if (!policyValue.value) return;
  sharePolicies.value.push({
    type: policyType.value,
    method: policyMethod.value,
    value: policyValue.value,
    reason: policyReason.value || undefined,
  });
  policyValue.value = '';
  policyReason.value = '';
  showPolicyForm.value = false;
}

function handleRemovePolicy(index: number) {
  sharePolicies.value.splice(index, 1);
}

function getPolicyTypeLabel(type: SharePolicyType) {
  return type === 'SHARE_POLICY_TYPE_WHITELIST' ? 'Allow' : 'Deny';
}

function getPolicyMethodLabel(method: SharePolicyMethod) {
  return policyMethodOptions.find(o => o.value === method)?.label || method;
}

async function handleShareSubmit() {
  if (!shareSecretRow.value?.id || !shareEmail.value) return;
  shareLoading.value = true;
  try {
    await createShare({
      resourceType: 'RESOURCE_TYPE_SECRET',
      resourceId: shareSecretRow.value.id,
      recipientEmail: shareEmail.value,
      message: shareMessage.value || undefined,
      policies: sharePolicies.value.length > 0 ? sharePolicies.value : undefined,
    });
    notification.success({ message: 'Share link created and email sent' });
    shareModalVisible.value = false;
  } catch {
    notification.error({ message: 'Failed to create share' });
  } finally {
    shareLoading.value = false;
  }
}

// Folder operations
function handleCreateFolder(parentId?: string) {
  folderDrawerMode.value = 'create';
  folderDrawerApi.setData({ mode: 'create', parentId });
  folderDrawerApi.open();
}

function handleEditFolder(node: TreeNode) {
  folderDrawerMode.value = 'edit';
  folderDrawerApi.setData({ mode: 'edit', folder: node.raw.folder });
  folderDrawerApi.open();
}

async function handleDeleteFolder(node: TreeNode) {
  const folder = node.raw.folder;
  if (!folder?.id) return;

  const hasChildren =
    (folder.secretCount ?? 0) > 0 || (folder.subfolderCount ?? 0) > 0;

  Modal.confirm({
    title: $t('warden.page.folder.delete'),
    content: hasChildren
      ? $t('warden.page.folder.confirmDeleteForce')
      : $t('warden.page.folder.confirmDelete'),
    okText: $t('ui.button.ok'),
    cancelText: $t('ui.button.cancel'),
    onOk: async () => {
      try {
        await folderStore.deleteFolder(folder.id!, hasChildren);
        notification.success({
          message: $t('warden.page.folder.deleteSuccess'),
        });
        if (selectedFolderId.value === folder.id) {
          selectedFolderId.value = undefined;
        }
        await loadFolderTree();
        await gridApi.query();
      } catch {
        notification.error({ message: $t('ui.notification.delete_failed') });
      }
    },
  });
}

function handleViewFolderPermissions(node: TreeNode) {
  permissionDrawerApi.setData({
    resourceType: 'RESOURCE_TYPE_FOLDER',
    resourceId: node.raw.folder?.id,
    resourceName: node.raw.folder?.name,
  });
  permissionDrawerApi.open();
}

// Bitwarden Import/Export
function handleOpenImportModal() {
  bitwardenImportModalRef.value?.open();
}

async function handleExport() {
  try {
    const result = await secretStore.exportToBitwarden({
      folderId: selectedFolderId.value,
      includeSubfolders: true,
    }) as ExportToBitwardenResponse;

    // Create and download the file
    const blob = new Blob([result.jsonData ?? ''], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = result.suggestedFilename ?? 'warden-export.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    notification.success({
      message: $t('warden.page.bitwarden.exportSuccess'),
      description: `${result.itemsExported} ${$t('warden.page.bitwarden.itemsExported')}`,
    });
  } catch (error: any) {
    notification.error({
      message: $t('warden.page.bitwarden.exportFailed'),
      description: error.message,
    });
  }
}

function handleImportSuccess() {
  loadFolderTree();
  gridApi.query();
}

// Get selected folder name
const selectedFolderName = computed(() => {
  if (!selectedFolderId.value) return $t('warden.page.folder.rootFolder');
  const findFolder = (
    nodes: FolderTreeNode[],
  ): string | undefined => {
    for (const node of nodes) {
      if (node.folder?.id === selectedFolderId.value) {
        return node.folder?.name;
      }
      if (node.children) {
        const found = findFolder(node.children);
        if (found) return found;
      }
    }
    return undefined;
  };
  return findFolder(folderTree.value) ?? $t('warden.page.folder.rootFolder');
});
</script>

<template>
  <Page auto-content-height>
    <div class="flex h-full gap-4">
      <!-- Folder Tree Panel -->
      <div class="w-64 shrink-0 overflow-auto rounded border bg-card p-4">
        <div class="mb-4 flex items-center justify-between">
          <span class="font-semibold">{{ $t('warden.page.folder.title') }}</span>
          <Button
            type="primary"
            size="small"
            @click="handleCreateFolder(selectedFolderId)"
          >
            {{ $t('ui.button.create', { moduleName: '' }) }}
          </Button>
        </div>

        <!-- Root folder item -->
        <div
          class="mb-2 flex cursor-pointer items-center gap-2 rounded p-2 hover:bg-accent"
          :class="{ 'bg-accent': !selectedFolderId }"
          @click="
            selectedFolderId = undefined;
            gridApi.reload();
          "
        >
          <component :is="LucideFolderOpen" class="size-4" />
          <span>{{ $t('warden.page.folder.rootFolder') }}</span>
        </div>

        <Tree
          v-if="treeData.length > 0"
          v-model:expanded-keys="expandedKeys"
          :tree-data="treeData"
          :selectable="true"
          :selected-keys="selectedFolderId ? [selectedFolderId] : []"
          block-node
          @select="handleFolderSelect"
        >
          <template #title="{ title, key, raw }">
            <Dropdown :trigger="['contextmenu']">
              <div class="flex items-center gap-2">
                <component
                  :is="expandedKeys.includes(key) ? LucideFolderOpen : LucideFolder"
                  class="size-4"
                />
                <span>{{ title }}</span>
                <span v-if="raw?.folder?.secretCount" class="text-muted-foreground text-xs">
                  ({{ raw.folder.secretCount }})
                </span>
              </div>
              <template #overlay>
                <Menu>
                  <MenuItem key="create" @click="handleCreateFolder(key)">
                    {{ $t('warden.page.folder.create') }}
                  </MenuItem>
                  <MenuItem key="edit" @click="handleEditFolder({ key, title, raw })">
                    {{ $t('warden.page.folder.edit') }}
                  </MenuItem>
                  <MenuItem
                    key="permissions"
                    @click="handleViewFolderPermissions({ key, title, raw })"
                  >
                    {{ $t('warden.page.permission.title') }}
                  </MenuItem>
                  <MenuItem
                    key="delete"
                    danger
                    @click="handleDeleteFolder({ key, title, raw })"
                  >
                    {{ $t('warden.page.folder.delete') }}
                  </MenuItem>
                </Menu>
              </template>
            </Dropdown>
          </template>
        </Tree>

        <div v-else-if="!loadingTree" class="text-muted-foreground text-center text-sm">
          {{ $t('ui.text.no_data') }}
        </div>
      </div>

      <!-- Secret List Panel -->
      <div class="flex-1 overflow-hidden">
        <Grid :table-title="`${$t('warden.page.secret.title')} - ${selectedFolderName}`">
          <template #toolbar-tools>
            <Space>
              <Button @click="handleOpenImportModal">
                <template #icon>
                  <LucideUpload class="size-4" />
                </template>
                {{ $t('warden.page.bitwarden.import') }}
              </Button>
              <Button @click="handleExport">
                <template #icon>
                  <LucideDownload class="size-4" />
                </template>
                {{ $t('warden.page.bitwarden.export') }}
              </Button>
              <Button type="primary" @click="handleCreateSecret">
                {{ $t('warden.page.secret.create') }}
              </Button>
            </Space>
          </template>
          <template #name="{ row }">
            <div class="flex items-center gap-2">
              <component :is="LucideLock" class="size-4" />
              <span>{{ row.name }}</span>
            </div>
          </template>
          <template #action="{ row }">
            <Space>
              <Button
                type="link"
                size="small"
                :icon="h(LucideEye)"
                :title="$t('ui.button.view')"
                @click.stop="handleViewSecret(row)"
              />
              <Button
                type="link"
                size="small"
                :icon="h(LucideCopy)"
                :title="$t('warden.page.secret.copyPassword')"
                @click.stop="handleCopyPassword(row)"
              />
              <Button
                type="link"
                size="small"
                :icon="h(LucideHistory)"
                :title="$t('warden.page.secret.versionHistory')"
                @click.stop="handleViewVersions(row)"
              />
              <Button
                type="link"
                size="small"
                :icon="h(LucidePencil)"
                :title="$t('ui.button.edit')"
                @click.stop="handleEditSecret(row)"
              />
              <Button
                type="link"
                size="small"
                :icon="h(LucideShare2)"
                title="Share"
                @click.stop="handleShareSecret(row)"
              />
              <Button
                type="link"
                size="small"
                :icon="h(LucideKey)"
                :title="$t('warden.page.permission.title')"
                @click.stop="handleViewPermissions(row)"
              />
              <a-popconfirm
                :cancel-text="$t('ui.button.cancel')"
                :ok-text="$t('ui.button.ok')"
                :title="$t('warden.page.secret.confirmDelete')"
                @confirm="handleDeleteSecret(row)"
              >
                <Button
                  danger
                  type="link"
                  size="small"
                  :icon="h(LucideTrash)"
                  :title="$t('ui.button.delete', { moduleName: '' })"
                />
              </a-popconfirm>
            </Space>
          </template>
        </Grid>
      </div>
    </div>

    <SecretDrawerComponent />
    <FolderDrawerComponent />
    <VersionDrawerComponent />
    <PermissionDrawerComponent />
    <BitwardenImportModal
      ref="bitwardenImportModalRef"
      :folder-id="selectedFolderId"
      @success="handleImportSuccess"
    />

    <!-- Share Secret Modal -->
    <Modal
      v-model:open="shareModalVisible"
      title="Share Secret"
      :confirm-loading="shareLoading"
      :width="560"
      @ok="handleShareSubmit"
    >
      <div v-if="shareSecretRow" style="margin-bottom: 16px">
        Sharing: <strong>{{ shareSecretRow.name }}</strong>
      </div>
      <div style="margin-bottom: 12px">
        <label style="display: block; margin-bottom: 4px; font-weight: 500">Recipient Email *</label>
        <a-input
          v-model:value="shareEmail"
          placeholder="Enter recipient email"
          type="email"
        />
      </div>
      <div style="margin-bottom: 12px">
        <label style="display: block; margin-bottom: 4px; font-weight: 500">Message (optional)</label>
        <a-textarea
          v-model:value="shareMessage"
          :rows="2"
          placeholder="Optional message to include in the email"
        />
      </div>

      <Divider style="margin: 12px 0 8px">Access Restrictions</Divider>

      <!-- Existing policies list -->
      <div v-if="sharePolicies.length > 0" style="margin-bottom: 8px">
        <div
          v-for="(policy, idx) in sharePolicies"
          :key="idx"
          style="display: flex; align-items: center; gap: 8px; padding: 6px 8px; background: #f5f5f5; border-radius: 4px; margin-bottom: 4px; font-size: 13px"
        >
          <a-tag :color="policy.type === 'SHARE_POLICY_TYPE_WHITELIST' ? 'green' : 'red'" style="margin: 0">
            {{ getPolicyTypeLabel(policy.type) }}
          </a-tag>
          <span style="font-weight: 500">{{ getPolicyMethodLabel(policy.method) }}</span>
          <span style="flex: 1; color: #666">{{ policy.value }}</span>
          <span v-if="policy.reason" style="color: #999; font-size: 12px">({{ policy.reason }})</span>
          <Button type="text" size="small" danger :icon="h(LucideX)" @click="handleRemovePolicy(idx)" />
        </div>
      </div>

      <!-- Add policy form -->
      <div v-if="showPolicyForm" style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin-bottom: 8px">
        <div style="display: flex; gap: 8px; margin-bottom: 8px">
          <Select v-model:value="policyType" style="width: 130px" size="small">
            <SelectOption value="SHARE_POLICY_TYPE_WHITELIST">Allow</SelectOption>
            <SelectOption value="SHARE_POLICY_TYPE_BLACKLIST">Deny</SelectOption>
          </Select>
          <Select v-model:value="policyMethod" style="width: 160px" size="small">
            <SelectOption
              v-for="opt in policyMethodOptions"
              :key="opt.value"
              :value="opt.value"
            >{{ opt.label }}</SelectOption>
          </Select>
        </div>
        <div style="display: flex; gap: 8px; margin-bottom: 8px">
          <a-input
            v-model:value="policyValue"
            size="small"
            :placeholder="currentPlaceholder"
            style="flex: 1"
            @press-enter="handleAddPolicy"
          />
          <a-input
            v-model:value="policyReason"
            size="small"
            placeholder="Reason (optional)"
            style="flex: 1"
          />
        </div>
        <div style="display: flex; gap: 8px; justify-content: flex-end">
          <Button size="small" @click="showPolicyForm = false">Cancel</Button>
          <Button size="small" type="primary" :disabled="!policyValue" @click="handleAddPolicy">Add</Button>
        </div>
      </div>

      <Button
        v-if="!showPolicyForm"
        type="dashed"
        size="small"
        block
        :icon="h(LucidePlus)"
        @click="showPolicyForm = true"
      >
        Add Restriction
      </Button>
    </Modal>
  </Page>
</template>
