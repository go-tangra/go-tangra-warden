<script lang="ts" setup>
import { ref, computed, h, watch } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';
import { LucideTrash, LucidePlus } from 'shell/vben/icons';

import {
  Table,
  Button,
  notification,
  Modal,
  Space,
  Tag,
  Spin,
  Form,
  FormItem,
  Select,
  Divider,
  DatePicker,
} from 'ant-design-vue';
import type { ColumnsType } from 'ant-design-vue/es/table';

import { type PermissionTuple } from '../../api/services';
import type { AdminUser, AdminRole } from '../../types';
import { $t } from 'shell/locales';
import { useWardenPermissionStore } from '../../stores/warden-permission.state';
import { listUsers, listRoles } from '../../api/admin-api';

const permissionStore = useWardenPermissionStore();

const data = ref<{
  resourceType: 'RESOURCE_TYPE_FOLDER' | 'RESOURCE_TYPE_SECRET';
  resourceId: string;
  resourceName?: string;
}>();
const loading = ref(false);
const permissions = ref<PermissionTuple[]>([]);
const showGrantForm = ref(false);
const granting = ref(false);

// Users and roles for dropdown
const users = ref<AdminUser[]>([]);
const roles = ref<AdminRole[]>([]);
const loadingSubjects = ref(false);

const grantForm = ref<{
  subjectType: 'SUBJECT_TYPE_USER' | 'SUBJECT_TYPE_ROLE';
  subjectId: string;
  relation: 'RELATION_OWNER' | 'RELATION_EDITOR' | 'RELATION_VIEWER' | 'RELATION_SHARER';
  expiresAt?: string;
}>({
  subjectType: 'SUBJECT_TYPE_USER',
  subjectId: '',
  relation: 'RELATION_VIEWER',
  expiresAt: undefined,
});

// Watch subject type changes to clear subjectId
watch(() => grantForm.value.subjectType, () => {
  grantForm.value.subjectId = '';
});

// Computed options for subject dropdown based on type
const subjectOptions = computed(() => {
  if (grantForm.value.subjectType === 'SUBJECT_TYPE_USER') {
    return users.value.map((user) => ({
      value: String(user.id),
      label: `${user.realname || user.username} (${user.username})`,
    }));
  } else {
    return roles.value.map((role) => ({
      value: role.code ?? '',
      label: role.name ?? '',
    }));
  }
});

// Load users and roles
async function loadSubjects() {
  loadingSubjects.value = true;

  // Load users and roles separately to handle individual failures
  try {
    const usersResp = await listUsers({ status: 'NORMAL' });
    users.value = usersResp.items ?? [];
  } catch (e) {
    console.error('Failed to load users:', e);
    users.value = [];
  }

  try {
    const rolesResp = await listRoles();
    roles.value = rolesResp.items ?? [];
  } catch (e) {
    console.error('Failed to load roles:', e);
    roles.value = [];
  }

  loadingSubjects.value = false;
}

const title = computed(() => $t('warden.page.permission.title'));

const subjectTypeOptions = computed(() => [
  { value: 'SUBJECT_TYPE_USER', label: $t('warden.page.permission.user') },
  { value: 'SUBJECT_TYPE_ROLE', label: $t('warden.page.permission.role') },
]);

const relationOptions = computed(() => [
  { value: 'RELATION_OWNER', label: $t('warden.page.permission.owner') },
  { value: 'RELATION_EDITOR', label: $t('warden.page.permission.editor') },
  { value: 'RELATION_VIEWER', label: $t('warden.page.permission.viewer') },
  { value: 'RELATION_SHARER', label: $t('warden.page.permission.sharer') },
]);

function subjectTypeToName(type: string | undefined) {
  switch (type) {
    case 'SUBJECT_TYPE_USER':
      return $t('warden.page.permission.user');
    case 'SUBJECT_TYPE_ROLE':
      return $t('warden.page.permission.role');
    case 'SUBJECT_TYPE_TENANT':
      return $t('warden.page.permission.tenant');
    default:
      return type ?? '';
  }
}

function relationToName(relation: string | undefined) {
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
      return relation ?? '';
  }
}

function relationToColor(relation: string | undefined) {
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

function formatDateTime(value: string | undefined) {
  if (!value) return $t('warden.page.permission.noExpiry');
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function resolveSubjectName(subjectType: string | undefined, subjectId: string | undefined): string {
  if (!subjectId) return '';

  if (subjectType === 'SUBJECT_TYPE_USER') {
    const user = users.value.find((u) => String(u.id) === subjectId);
    if (user) {
      return `${user.realname || user.username} (${user.username})`;
    }
  } else if (subjectType === 'SUBJECT_TYPE_ROLE') {
    const role = roles.value.find((r) => r.code === subjectId);
    if (role) {
      return role.name ?? subjectId;
    }
  }

  return subjectId;
}

async function loadPermissions() {
  if (!data.value?.resourceId || !data.value?.resourceType) return;
  loading.value = true;
  try {
    const resp = await permissionStore.listPermissions(undefined, {
      resourceType: data.value.resourceType,
      resourceId: data.value.resourceId,
    });
    permissions.value = (resp.permissions ?? []) as PermissionTuple[];
  } catch (e) {
    console.error('Failed to load permissions:', e);
    notification.error({ message: $t('ui.notification.load_failed') });
  } finally {
    loading.value = false;
  }
}

async function handleGrant() {
  if (!data.value?.resourceId || !data.value?.resourceType) return;

  granting.value = true;
  try {
    await permissionStore.grantAccess({
      resourceType: data.value.resourceType,
      resourceId: data.value.resourceId,
      subjectType: grantForm.value.subjectType,
      subjectId: grantForm.value.subjectId,
      relation: grantForm.value.relation,
      expiresAt: grantForm.value.expiresAt,
    });
    notification.success({
      message: $t('warden.page.permission.grantSuccess'),
    });
    showGrantForm.value = false;
    resetGrantForm();
    await loadPermissions();
  } catch (e) {
    console.error('Failed to grant access:', e);
    notification.error({ message: $t('ui.notification.operation_failed') });
  } finally {
    granting.value = false;
  }
}

async function handleRevoke(permission: any) {
  if (!data.value?.resourceId || !data.value?.resourceType) return;

  Modal.confirm({
    title: $t('warden.page.permission.revokeAccess'),
    content: $t('warden.page.permission.revokeConfirm'),
    okText: $t('ui.button.ok'),
    cancelText: $t('ui.button.cancel'),
    onOk: async () => {
      try {
        await permissionStore.revokeAccess({
          resourceType: data.value!.resourceType,
          resourceId: data.value!.resourceId,
          subjectType: permission.subjectType,
          subjectId: permission.subjectId ?? '',
          relation: permission.relation,
        });
        notification.success({
          message: $t('warden.page.permission.revokeSuccess'),
        });
        await loadPermissions();
      } catch (e) {
        console.error('Failed to revoke access:', e);
        notification.error({ message: $t('ui.notification.operation_failed') });
      }
    },
  });
}

function resetGrantForm() {
  grantForm.value = {
    subjectType: 'SUBJECT_TYPE_USER',
    subjectId: '',
    relation: 'RELATION_VIEWER',
    expiresAt: undefined,
  };
}

const columns: ColumnsType<any> = [
  {
    title: $t('warden.page.permission.subjectType'),
    dataIndex: 'subjectType',
    key: 'subjectType',
    width: 100,
    customRender: ({ text }) => subjectTypeToName(text),
  },
  {
    title: $t('warden.page.permission.subject'),
    dataIndex: 'subjectId',
    key: 'subjectId',
    width: 200,
    ellipsis: true,
    customRender: ({ record }) => resolveSubjectName(record.subjectType, record.subjectId),
  },
  {
    title: $t('warden.page.permission.relation'),
    dataIndex: 'relation',
    key: 'relation',
    width: 100,
    customRender: ({ text }) =>
      h(Tag, { color: relationToColor(text) }, () => relationToName(text)),
  },
  {
    title: $t('warden.page.permission.expiresAt'),
    dataIndex: 'expiresAt',
    key: 'expiresAt',
    width: 180,
    customRender: ({ text }) => formatDateTime(text),
  },
  {
    title: $t('ui.table.action'),
    key: 'action',
    width: 80,
    fixed: 'right',
  },
];

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        resourceType: 'RESOURCE_TYPE_FOLDER' | 'RESOURCE_TYPE_SECRET';
        resourceId: string;
        resourceName?: string;
      };
      permissions.value = [];
      showGrantForm.value = false;
      resetGrantForm();
      await Promise.all([loadPermissions(), loadSubjects()]);
    }
  },
});

const resourceTypeName = computed(() => {
  switch (data.value?.resourceType) {
    case 'RESOURCE_TYPE_FOLDER':
      return $t('warden.page.permission.folder');
    case 'RESOURCE_TYPE_SECRET':
      return $t('warden.page.permission.secret');
    default:
      return '';
  }
});
</script>

<template>
  <Drawer :title="title" :footer="false" width="700px">
    <template v-if="data">
      <div class="mb-4 flex items-center justify-between">
        <div>
          <span class="text-muted-foreground">{{ resourceTypeName }}:</span>
          <span class="ml-2 font-semibold">{{
            data.resourceName || data.resourceId
          }}</span>
        </div>
        <Button
          type="primary"
          :icon="h(LucidePlus)"
          @click="showGrantForm = !showGrantForm"
        >
          {{ $t('warden.page.permission.grantAccess') }}
        </Button>
      </div>

      <!-- Grant Form -->
      <div v-if="showGrantForm" class="bg-muted mb-4 rounded p-4">
        <Form layout="vertical" :model="grantForm" @finish="handleGrant">
          <div class="grid grid-cols-2 gap-4">
            <FormItem
              :label="$t('warden.page.permission.subjectType')"
              name="subjectType"
              :rules="[{ required: true }]"
            >
              <Select
                v-model:value="grantForm.subjectType"
                :options="subjectTypeOptions"
              />
            </FormItem>

            <FormItem
              :label="grantForm.subjectType === 'SUBJECT_TYPE_USER' ? $t('warden.page.permission.user') : $t('warden.page.permission.role')"
              name="subjectId"
              :rules="[{ required: true }]"
            >
              <Select
                v-model:value="grantForm.subjectId"
                :options="subjectOptions"
                :loading="loadingSubjects"
                :placeholder="$t('ui.placeholder.select')"
                show-search
                :filter-option="(input: string, option: any) =>
                  option.label.toLowerCase().includes(input.toLowerCase())"
              />
            </FormItem>

            <FormItem
              :label="$t('warden.page.permission.relation')"
              name="relation"
              :rules="[{ required: true }]"
            >
              <Select
                v-model:value="grantForm.relation"
                :options="relationOptions"
              />
            </FormItem>

            <FormItem
              :label="$t('warden.page.permission.expiresAt')"
              name="expiresAt"
            >
              <DatePicker
                v-model:value="grantForm.expiresAt"
                show-time
                :placeholder="$t('warden.page.permission.noExpiry')"
                class="w-full"
              />
            </FormItem>
          </div>

          <FormItem class="mb-0">
            <Space>
              <Button type="primary" html-type="submit" :loading="granting">
                {{ $t('warden.page.permission.grantAccess') }}
              </Button>
              <Button @click="showGrantForm = false; resetGrantForm()">
                {{ $t('ui.button.cancel') }}
              </Button>
            </Space>
          </FormItem>
        </Form>
      </div>

      <Divider v-if="showGrantForm" />

      <Spin :spinning="loading">
        <Table
          :columns="columns"
          :data-source="permissions"
          :pagination="false"
          :scroll="{ y: 400 }"
          row-key="id"
          size="small"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'">
              <Button
                danger
                type="text"
                size="small"
                :icon="h(LucideTrash)"
                :title="$t('warden.page.permission.revokeAccess')"
                @click="handleRevoke(record as PermissionTuple)"
              />
            </template>
          </template>

          <template #emptyText>
            <div class="py-8 text-center">
              <span class="text-muted-foreground">{{
                $t('ui.text.no_data')
              }}</span>
            </div>
          </template>
        </Table>
      </Spin>
    </template>
  </Drawer>
</template>
