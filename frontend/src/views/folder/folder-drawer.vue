<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';
import { LucidePlus, LucideTrash } from 'shell/vben/icons';

import {
  Form,
  FormItem,
  Input,
  Button,
  notification,
  Textarea,
  TreeSelect,
  Divider,
  Select,
} from 'ant-design-vue';

import {
  type Folder,
  type FolderTreeNode,
} from '../../api/services';
import type { AdminUser, AdminRole } from '../../types';
import { $t } from 'shell/locales';
import { useWardenFolderStore } from '../../stores/warden-folder.state';
import { listUsers, listRoles } from '../../api/admin-api';

const folderStore = useWardenFolderStore();

const data = ref<{
  mode: 'create' | 'edit';
  parentId?: string;
  folder?: Folder;
}>();
const loading = ref(false);
const folderTree = ref<FolderTreeNode[]>([]);

const formState = ref<{
  name: string;
  description: string;
  parentId?: string;
}>({
  name: '',
  description: '',
  parentId: undefined,
});

// Additional permissions to grant alongside the implicit OWNER that the
// backend always assigns to the creator. Mirrors secret-drawer.vue.
const initialPermissions = ref<
  Array<{
    subjectType: 'SUBJECT_TYPE_USER' | 'SUBJECT_TYPE_ROLE';
    subjectId: string;
    relation:
      | 'RELATION_OWNER'
      | 'RELATION_EDITOR'
      | 'RELATION_VIEWER'
      | 'RELATION_SHARER';
  }>
>([]);
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
  if (data.value?.mode === 'create') {
    return $t('warden.page.folder.create');
  }
  return $t('warden.page.folder.edit');
});

const isCreateMode = computed(() => data.value?.mode === 'create');
const isEditMode = computed(() => data.value?.mode === 'edit');

// Convert folder tree to TreeSelect format
interface TreeSelectNode {
  value: string;
  title: string;
  children?: TreeSelectNode[];
  disabled?: boolean;
}

function convertToTreeSelectData(
  nodes: FolderTreeNode[],
  excludeId?: string,
): TreeSelectNode[] {
  return nodes
    .filter((node) => node.folder?.id !== excludeId)
    .map((node) => ({
      value: node.folder?.id ?? '',
      title: node.folder?.name ?? '',
      children: node.children
        ? convertToTreeSelectData(node.children, excludeId)
        : undefined,
    }));
}

const treeSelectData = computed(() => {
  const excludeId = isEditMode.value ? data.value?.folder?.id : undefined;
  return convertToTreeSelectData(folderTree.value, excludeId);
});

async function loadFolderTree() {
  try {
    const resp = await folderStore.getFolderTree();
    folderTree.value = (resp.roots ?? []) as FolderTreeNode[];
  } catch (e) {
    console.error('Failed to load folder tree:', e);
  }
}

async function handleSubmit() {
  loading.value = true;
  try {
    if (isCreateMode.value) {
      // Drop half-filled permission rows before sending.
      const validPermissions = initialPermissions.value.filter(
        (p) => p.subjectId && p.subjectType && p.relation,
      );
      await folderStore.createFolder({
        name: formState.value.name,
        description: formState.value.description,
        parentId: formState.value.parentId,
        ...(validPermissions.length > 0
          ? { initialPermissions: validPermissions }
          : {}),
      } as any);
      notification.success({
        message: $t('warden.page.folder.createSuccess'),
      });
    } else if (isEditMode.value && data.value?.folder?.id) {
      await folderStore.updateFolder(data.value.folder.id, {
        name: formState.value.name,
        description: formState.value.description,
      });
      notification.success({
        message: $t('warden.page.folder.updateSuccess'),
      });
    }
    drawerApi.close();
  } catch (e) {
    console.error('Failed to save folder:', e);
    notification.error({
      message: isCreateMode.value
        ? $t('ui.notification.create_failed')
        : $t('ui.notification.update_failed'),
    });
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  formState.value = {
    name: '',
    description: '',
    parentId: undefined,
  };
  initialPermissions.value = [];
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        mode: 'create' | 'edit';
        parentId?: string;
        folder?: Folder;
      };

      await loadFolderTree();

      if (data.value?.mode === 'create') {
        resetForm();
        formState.value.parentId = data.value.parentId;
        // Lazy-load subjects only when creating; edit mode doesn't need them.
        loadSubjects();
      } else if (data.value?.mode === 'edit' && data.value.folder) {
        formState.value = {
          name: data.value.folder.name ?? '',
          description: data.value.folder.description ?? '',
          parentId: data.value.folder.parentId,
        };
      }
    }
  },
});
</script>

<template>
  <Drawer :title="title" :footer="false">
    <Form layout="vertical" :model="formState" @finish="handleSubmit">
      <FormItem
        :label="$t('warden.page.folder.name')"
        name="name"
        :rules="[{ required: true, message: $t('ui.formRules.required') }]"
      >
        <Input
          v-model:value="formState.name"
          :placeholder="$t('ui.placeholder.input')"
          :maxlength="255"
        />
      </FormItem>

      <FormItem
        v-if="isCreateMode"
        :label="$t('warden.page.folder.parent')"
        name="parentId"
      >
        <TreeSelect
          v-model:value="formState.parentId"
          :tree-data="treeSelectData"
          :placeholder="$t('warden.page.folder.rootFolder')"
          allow-clear
          tree-default-expand-all
        />
      </FormItem>

      <FormItem :label="$t('warden.page.folder.description')" name="description">
        <Textarea
          v-model:value="formState.description"
          :rows="3"
          :maxlength="1024"
          :placeholder="$t('ui.placeholder.input')"
        />
      </FormItem>

      <template v-if="isCreateMode">
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
      </template>

      <FormItem>
        <Button type="primary" html-type="submit" :loading="loading" block>
          {{ isCreateMode ? $t('ui.button.create', { moduleName: '' }) : $t('ui.button.save') }}
        </Button>
      </FormItem>
    </Form>
  </Drawer>
</template>
