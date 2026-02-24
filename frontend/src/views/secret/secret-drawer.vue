<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';
import { LucideEye, LucideEyeOff, LucideCopy, LucidePlus, LucideTrash } from 'shell/vben/icons';

import {
  Form,
  FormItem,
  Input,
  Button,
  notification,
  Textarea,
  TreeSelect,
  Descriptions,
  DescriptionsItem,
  Divider,
  Tag,
  Space,
  Select,
} from 'ant-design-vue';

import {
  type Secret,
  type FolderTreeNode,
} from '../../api/services';
import type { AdminUser, AdminRole } from '../../types';
import { $t } from 'shell/locales';
import { useWardenFolderStore } from '../../stores/warden-folder.state';
import { useWardenSecretStore } from '../../stores/warden-secret.state';
import { listUsers, listRoles } from '../../api/admin-api';

const folderStore = useWardenFolderStore();
const secretStore = useWardenSecretStore();

const data = ref<{
  mode: 'create' | 'edit' | 'view';
  row: Secret;
  folderId?: string;
}>();
const loading = ref(false);
const folderTree = ref<FolderTreeNode[]>([]);
const showPassword = ref(false);
const currentPassword = ref('');
const loadingPassword = ref(false);

const formState = ref<{
  name: string;
  username: string;
  password: string;
  hostUrl: string;
  description: string;
  folderId?: string;
  versionComment: string;
}>({
  name: '',
  username: '',
  password: '',
  hostUrl: '',
  description: '',
  folderId: undefined,
  versionComment: '',
});

// Password update form (separate from main form in edit mode)
const passwordForm = ref<{
  newPassword: string;
  comment: string;
}>({
  newPassword: '',
  comment: '',
});
const updatingPassword = ref(false);

// Initial permissions for create mode
const initialPermissions = ref<Array<{
  subjectType: 'SUBJECT_TYPE_USER' | 'SUBJECT_TYPE_ROLE';
  subjectId: string;
  relation: 'RELATION_OWNER' | 'RELATION_EDITOR' | 'RELATION_VIEWER' | 'RELATION_SHARER';
}>>([]);
const users = ref<AdminUser[]>([]);
const roles = ref<AdminRole[]>([]);
const loadingSubjects = ref(false);

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

function getSubjectOptions(subjectType: string) {
  if (subjectType === 'SUBJECT_TYPE_USER') {
    return users.value.map((user) => ({
      value: String(user.id),
      label: `${user.realname || user.username} (${user.username})`,
    }));
  }
  return roles.value.map((role) => ({
    value: role.code ?? '',
    label: role.name ?? '',
  }));
}

function addPermissionRow() {
  initialPermissions.value.push({
    subjectType: 'SUBJECT_TYPE_USER',
    subjectId: '',
    relation: 'RELATION_VIEWER',
  });
}

function removePermissionRow(index: number) {
  initialPermissions.value.splice(index, 1);
}

async function loadSubjects() {
  loadingSubjects.value = true;
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

const title = computed(() => {
  switch (data.value?.mode) {
    case 'create':
      return $t('warden.page.secret.create');
    case 'edit':
      return $t('warden.page.secret.edit');
    default:
      return $t('warden.page.secret.title');
  }
});

const isViewMode = computed(() => data.value?.mode === 'view');
const isCreateMode = computed(() => data.value?.mode === 'create');
const isEditMode = computed(() => data.value?.mode === 'edit');

// Convert folder tree to TreeSelect format
interface TreeSelectNode {
  value: string;
  title: string;
  children?: TreeSelectNode[];
}

function convertToTreeSelectData(
  nodes: FolderTreeNode[],
): TreeSelectNode[] {
  return nodes.map((node) => ({
    value: node.folder?.id ?? '',
    title: node.folder?.name ?? '',
    children: node.children
      ? convertToTreeSelectData(node.children)
      : undefined,
  }));
}

const treeSelectData = computed(() => convertToTreeSelectData(folderTree.value));

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'SECRET_STATUS_ACTIVE':
      return '#52C41A';
    case 'SECRET_STATUS_ARCHIVED':
      return '#8C8C8C';
    case 'SECRET_STATUS_DELETED':
      return '#FF4D4F';
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  switch (status) {
    case 'SECRET_STATUS_ACTIVE':
      return $t('warden.page.secret.statusActive');
    case 'SECRET_STATUS_ARCHIVED':
      return $t('warden.page.secret.statusArchived');
    case 'SECRET_STATUS_DELETED':
      return $t('warden.page.secret.statusDeleted');
    default:
      return status ?? '';
  }
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function loadFolderTree() {
  try {
    const resp = await folderStore.getFolderTree();
    folderTree.value = (resp.roots ?? []) as FolderTreeNode[];
  } catch (e) {
    console.error('Failed to load folder tree:', e);
  }
}

async function loadPassword() {
  if (!data.value?.row?.id) return;
  loadingPassword.value = true;
  try {
    const resp = await secretStore.getSecretPassword(data.value.row.id);
    currentPassword.value = resp.password ?? '';
  } catch (e) {
    console.error('Failed to load password:', e);
    notification.error({ message: $t('ui.notification.load_failed') });
  } finally {
    loadingPassword.value = false;
  }
}

async function handleCopyPassword() {
  if (!currentPassword.value) {
    await loadPassword();
  }
  try {
    await navigator.clipboard.writeText(currentPassword.value);
    notification.success({ message: $t('warden.page.secret.passwordCopied') });
  } catch {
    notification.error({ message: $t('ui.notification.operation_failed') });
  }
}

async function handleTogglePassword() {
  if (!showPassword.value && !currentPassword.value) {
    await loadPassword();
  }
  showPassword.value = !showPassword.value;
}

async function handleSubmit() {
  loading.value = true;
  try {
    if (isCreateMode.value) {
      // Filter out incomplete permission rows
      const validPermissions = initialPermissions.value.filter(
        (p) => p.subjectId && p.subjectType && p.relation,
      );
      await secretStore.createSecret({
        name: formState.value.name,
        username: formState.value.username,
        password: formState.value.password,
        hostUrl: formState.value.hostUrl,
        description: formState.value.description,
        folderId: formState.value.folderId,
        versionComment: formState.value.versionComment,
        metadata: {},
        ...(validPermissions.length > 0 ? { initialPermissions: validPermissions } : {}),
      });
      notification.success({
        message: $t('warden.page.secret.createSuccess'),
      });
    } else if (isEditMode.value && data.value?.row?.id) {
      await secretStore.updateSecret(data.value.row.id, {
        name: formState.value.name,
        username: formState.value.username,
        hostUrl: formState.value.hostUrl,
        description: formState.value.description,
      });
      notification.success({
        message: $t('warden.page.secret.updateSuccess'),
      });
    }
    drawerApi.close();
  } catch (e) {
    console.error('Failed to save secret:', e);
    notification.error({
      message: isCreateMode.value
        ? $t('ui.notification.create_failed')
        : $t('ui.notification.update_failed'),
    });
  } finally {
    loading.value = false;
  }
}

async function handleUpdatePassword() {
  if (!data.value?.row?.id || !passwordForm.value.newPassword) return;

  updatingPassword.value = true;
  try {
    await secretStore.updateSecretPassword(
      data.value.row.id,
      passwordForm.value.newPassword,
      passwordForm.value.comment,
    );
    notification.success({
      message: $t('warden.page.secret.passwordUpdateSuccess'),
    });
    // Reset form and reload secret data
    passwordForm.value = { newPassword: '', comment: '' };
    currentPassword.value = '';
    showPassword.value = false;
    // Reload secret to get new version
    const resp = await secretStore.getSecret(data.value.row.id);
    if (resp.secret) {
      data.value.row = resp.secret as Secret;
    }
  } catch (e) {
    console.error('Failed to update password:', e);
    notification.error({ message: $t('ui.notification.update_failed') });
  } finally {
    updatingPassword.value = false;
  }
}

function resetForm() {
  formState.value = {
    name: '',
    username: '',
    password: '',
    hostUrl: '',
    description: '',
    folderId: undefined,
    versionComment: '',
  };
  passwordForm.value = { newPassword: '', comment: '' };
  currentPassword.value = '';
  showPassword.value = false;
  initialPermissions.value = [];
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        mode: 'create' | 'edit' | 'view';
        row: Secret;
        folderId?: string;
      };

      await loadFolderTree();

      if (data.value?.mode === 'create') {
        resetForm();
        formState.value.folderId = data.value.folderId;
        loadSubjects();
      } else if (data.value?.row) {
        formState.value = {
          name: data.value.row.name ?? '',
          username: data.value.row.username ?? '',
          password: '',
          hostUrl: data.value.row.hostUrl ?? '',
          description: data.value.row.description ?? '',
          folderId: data.value.row.folderId,
          versionComment: '',
        };
        currentPassword.value = '';
        showPassword.value = false;
      }
    }
  },
});

const secret = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <!-- View Mode -->
    <template v-if="secret && isViewMode">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('warden.page.secret.name')">
          {{ secret.name }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.username')">
          {{ secret.username || '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.password')">
          <Space>
            <span>{{
              showPassword ? currentPassword : '••••••••••••'
            }}</span>
            <Button
              type="text"
              size="small"
              :icon="showPassword ? h(LucideEyeOff) : h(LucideEye)"
              :loading="loadingPassword"
              @click="handleTogglePassword"
            />
            <Button
              type="text"
              size="small"
              :icon="h(LucideCopy)"
              @click="handleCopyPassword"
            />
          </Space>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.hostUrl')">
          <a v-if="secret.hostUrl" :href="secret.hostUrl" target="_blank">
            {{ secret.hostUrl }}
          </a>
          <span v-else>-</span>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.folderPath')">
          {{ secret.folderPath || '/' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.currentVersion')">
          v{{ secret.currentVersion }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.status')">
          <Tag :color="statusToColor(secret.status)">
            {{ statusToName(secret.status) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('warden.page.secret.description')">
          {{ secret.description || '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('ui.table.timestamps') || 'Timestamps' }}</Divider>
      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(secret.createTime) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.updatedAt')">
          {{ formatDateTime(secret.updateTime) }}
        </DescriptionsItem>
      </Descriptions>
    </template>

    <!-- Create Mode -->
    <template v-else-if="isCreateMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <FormItem
          :label="$t('warden.page.secret.name')"
          name="name"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.name"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.secret.username')" name="username">
          <Input
            v-model:value="formState.username"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem
          :label="$t('warden.page.secret.password')"
          name="password"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input.Password
            v-model:value="formState.password"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.secret.hostUrl')" name="hostUrl">
          <Input
            v-model:value="formState.hostUrl"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="2048"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.secret.folder')" name="folderId">
          <TreeSelect
            v-model:value="formState.folderId"
            :tree-data="treeSelectData"
            :placeholder="$t('warden.page.folder.rootFolder')"
            allow-clear
            tree-default-expand-all
          />
        </FormItem>

        <FormItem
          :label="$t('warden.page.secret.description')"
          name="description"
        >
          <Textarea
            v-model:value="formState.description"
            :rows="3"
            :maxlength="4096"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <FormItem
          :label="$t('warden.page.secret.versionComment')"
          name="versionComment"
        >
          <Input
            v-model:value="formState.versionComment"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="1024"
          />
        </FormItem>

        <Divider>{{ $t('warden.page.permission.title') }}</Divider>

        <div
          v-for="(perm, idx) in initialPermissions"
          :key="idx"
          class="mb-3 flex items-center gap-2"
        >
          <Select
            v-model:value="perm.subjectType"
            :options="subjectTypeOptions"
            style="width: 110px"
            @change="perm.subjectId = ''"
          />
          <Select
            v-model:value="perm.subjectId"
            :options="getSubjectOptions(perm.subjectType)"
            :loading="loadingSubjects"
            :placeholder="$t('ui.placeholder.select')"
            show-search
            :filter-option="(input: string, option: any) =>
              option.label.toLowerCase().includes(input.toLowerCase())"
            style="flex: 1"
          />
          <Select
            v-model:value="perm.relation"
            :options="relationOptions"
            style="width: 110px"
          />
          <Button
            danger
            type="text"
            size="small"
            @click="removePermissionRow(idx)"
          >
            <LucideTrash class="size-4" />
          </Button>
        </div>

        <div class="mb-4">
          <Button size="small" type="dashed" block @click="addPermissionRow">
            <LucidePlus class="mr-1 size-4" />
            {{ $t('warden.page.permission.grantAccess') }}
          </Button>
        </div>

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ $t('ui.button.create', { moduleName: '' }) }}
          </Button>
        </FormItem>
      </Form>
    </template>

    <!-- Edit Mode -->
    <template v-else-if="isEditMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <FormItem
          :label="$t('warden.page.secret.name')"
          name="name"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input
            v-model:value="formState.name"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.secret.username')" name="username">
          <Input
            v-model:value="formState.username"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="255"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.secret.hostUrl')" name="hostUrl">
          <Input
            v-model:value="formState.hostUrl"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="2048"
          />
        </FormItem>

        <FormItem
          :label="$t('warden.page.secret.description')"
          name="description"
        >
          <Textarea
            v-model:value="formState.description"
            :rows="3"
            :maxlength="4096"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ $t('ui.button.save') }}
          </Button>
        </FormItem>
      </Form>

      <Divider>{{ $t('warden.page.secret.updatePassword') }}</Divider>
      <Form layout="vertical" :model="passwordForm" @finish="handleUpdatePassword">
        <FormItem
          :label="$t('warden.page.secret.password')"
          name="newPassword"
          :rules="[{ required: true, message: $t('ui.formRules.required') }]"
        >
          <Input.Password
            v-model:value="passwordForm.newPassword"
            :placeholder="$t('ui.placeholder.input')"
          />
        </FormItem>

        <FormItem :label="$t('warden.page.version.comment')" name="comment">
          <Input
            v-model:value="passwordForm.comment"
            :placeholder="$t('ui.placeholder.input')"
            :maxlength="1024"
          />
        </FormItem>

        <FormItem>
          <Button
            type="default"
            html-type="submit"
            :loading="updatingPassword"
            :disabled="!passwordForm.newPassword"
            block
          >
            {{ $t('warden.page.secret.updatePassword') }}
          </Button>
        </FormItem>
      </Form>
    </template>
  </Drawer>
</template>

<script lang="ts">
import { h } from 'vue';
</script>
