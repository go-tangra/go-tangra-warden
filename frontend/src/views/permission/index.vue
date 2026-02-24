<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, ref } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideTrash, LucidePencil, LucideUsers } from 'shell/vben/icons';

import { notification, Space, Button, Tag } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type PermissionTuple } from '../../api/services';
import { $t } from 'shell/locales';
import { useWardenPermissionStore } from '../../stores/warden-permission.state';

import PermissionDrawer from './permission-drawer.vue';

const permissionStore = useWardenPermissionStore();

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Select',
      fieldName: 'resourceType',
      label: $t('warden.page.permission.resourceType'),
      componentProps: {
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
        options: [
          { label: $t('warden.page.permission.resourceTypeFolder'), value: 'RESOURCE_TYPE_FOLDER' },
          { label: $t('warden.page.permission.resourceTypeSecret'), value: 'RESOURCE_TYPE_SECRET' },
        ],
      },
    },
  ],
};

const gridOptions: VxeGridProps<PermissionTuple> = {
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
        const resp = await permissionStore.listPermissions(
          { page: page.currentPage, pageSize: page.pageSize },
          { resourceType: formValues?.resourceType },
        );
        return {
          items: resp.permissions ?? [],
          total: resp.total ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    {
      title: $t('warden.page.permission.resourceType'),
      field: 'resourceType',
      width: 120,
      slots: { default: 'resourceType' },
    },
    {
      title: $t('warden.page.permission.resourceId'),
      field: 'resourceId',
      width: 200,
    },
    {
      title: $t('warden.page.permission.subjectType'),
      field: 'subjectType',
      width: 100,
      slots: { default: 'subjectType' },
    },
    {
      title: $t('warden.page.permission.subjectId'),
      field: 'subjectId',
      width: 150,
    },
    {
      title: $t('warden.page.permission.relation'),
      field: 'relation',
      width: 120,
      slots: { default: 'relation' },
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
      width: 120,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const drawerMode = ref<'create' | 'edit'>('create');

const [PermissionDrawerComponent, permissionDrawerApi] = useVbenDrawer({
  connectedComponent: PermissionDrawer,
  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function handleCreatePermission() {
  drawerMode.value = 'create';
  permissionDrawerApi.setData({ mode: 'create' });
  permissionDrawerApi.open();
}

function handleEditPermission(row: any) {
  drawerMode.value = 'edit';
  permissionDrawerApi.setData({
    mode: 'edit',
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    permission: row,
  });
  permissionDrawerApi.open();
}

async function handleDeletePermission(row: any) {
  if (!row.id) return;
  try {
    await permissionStore.revokeAccess({
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      subjectType: row.subjectType,
      subjectId: row.subjectId,
      relation: row.relation,
    });
    notification.success({ message: $t('ui.notification.delete_success') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}

function getResourceTypeLabel(type: string) {
  switch (type) {
    case 'RESOURCE_TYPE_FOLDER':
      return $t('warden.page.permission.resourceTypeFolder');
    case 'RESOURCE_TYPE_SECRET':
      return $t('warden.page.permission.resourceTypeSecret');
    default:
      return type;
  }
}

function getSubjectTypeLabel(type: string) {
  switch (type) {
    case 'SUBJECT_TYPE_USER':
      return $t('warden.page.permission.user');
    case 'SUBJECT_TYPE_ROLE':
      return $t('warden.page.permission.role');
    case 'SUBJECT_TYPE_TENANT':
      return $t('warden.page.permission.tenant');
    default:
      return type;
  }
}

function getRelationLabel(relation: string) {
  switch (relation) {
    case 'RELATION_OWNER':
      return $t('warden.page.permission.owner');
    case 'RELATION_EDITOR':
      return $t('warden.page.permission.editor');
    case 'RELATION_VIEWER':
      return $t('warden.page.permission.viewer');
    case 'RELATION_SHARER':
      return $t('warden.page.permission.sharer');
    default:
      return relation;
  }
}

function getRelationColor(relation: string) {
  switch (relation) {
    case 'RELATION_OWNER':
      return 'red';
    case 'RELATION_EDITOR':
      return 'orange';
    case 'RELATION_VIEWER':
      return 'blue';
    case 'RELATION_SHARER':
      return 'purple';
    default:
      return 'default';
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('warden.page.permission.title')">
      <template #toolbar-tools>
        <Button class="mr-2" type="primary" @click="handleCreatePermission">
          {{ $t('warden.page.permission.grant') }}
        </Button>
      </template>
      <template #resourceType="{ row }">
        <Tag>{{ getResourceTypeLabel(row.resourceType) }}</Tag>
      </template>
      <template #subjectType="{ row }">
        <div class="flex items-center gap-1">
          <component :is="LucideUsers" class="size-4" />
          <span>{{ getSubjectTypeLabel(row.subjectType) }}</span>
        </div>
      </template>
      <template #relation="{ row }">
        <Tag :color="getRelationColor(row.relation)">
          {{ getRelationLabel(row.relation) }}
        </Tag>
      </template>
      <template #action="{ row }">
        <Space>
          <Button
            type="link"
            size="small"
            :icon="h(LucidePencil)"
            :title="$t('ui.button.edit')"
            @click.stop="handleEditPermission(row)"
          />
          <a-popconfirm
            :cancel-text="$t('ui.button.cancel')"
            :ok-text="$t('ui.button.ok')"
            :title="$t('warden.page.permission.confirmRevoke')"
            @confirm="handleDeletePermission(row)"
          >
            <Button
              danger
              type="link"
              size="small"
              :icon="h(LucideTrash)"
              :title="$t('warden.page.permission.revoke')"
            />
          </a-popconfirm>
        </Space>
      </template>
    </Grid>

    <PermissionDrawerComponent />
  </Page>
</template>
