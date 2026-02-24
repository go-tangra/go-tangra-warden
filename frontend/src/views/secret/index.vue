<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, ref } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import {
  LucideEye,
  LucideTrash,
  LucidePencil,
  LucideCopy,
  LucideLock,
  LucideHistory,
  LucideKey,
} from 'shell/vben/icons';

import { notification, Space, Button } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type Secret } from '../../api/services';
import { $t } from 'shell/locales';
import { useWardenSecretStore } from '../../stores/warden-secret.state';

import SecretDrawer from './secret-drawer.vue';
import VersionDrawer from './version-drawer.vue';
import PermissionDrawer from '../permission/permission-drawer.vue';

const secretStore = useWardenSecretStore();

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
          { nameFilter: formValues?.nameFilter },
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

const drawerMode = ref<'create' | 'edit' | 'view'>('view');

const [SecretDrawerComponent, secretDrawerApi] = useVbenDrawer({
  connectedComponent: SecretDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
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

function openSecretDrawer(
  row: Secret,
  mode: 'create' | 'edit' | 'view',
) {
  drawerMode.value = mode;
  secretDrawerApi.setData({ row, mode });
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
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('warden.page.secret.title')">
      <template #toolbar-tools>
        <Button class="mr-2" type="primary" @click="handleCreateSecret">
          {{ $t('warden.page.secret.create') }}
        </Button>
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

    <SecretDrawerComponent />
    <VersionDrawerComponent />
    <PermissionDrawerComponent />
  </Page>
</template>
