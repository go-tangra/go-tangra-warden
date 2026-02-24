<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Form,
  FormItem,
  Input,
  Button,
  notification,
  Textarea,
  TreeSelect,
} from 'ant-design-vue';

import {
  type Folder,
  type FolderTreeNode,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useWardenFolderStore } from '../../stores/warden-folder.state';

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
      await folderStore.createFolder({
        name: formState.value.name,
        description: formState.value.description,
        parentId: formState.value.parentId,
      });
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

      <FormItem>
        <Button type="primary" html-type="submit" :loading="loading" block>
          {{ isCreateMode ? $t('ui.button.create', { moduleName: '' }) : $t('ui.button.save') }}
        </Button>
      </FormItem>
    </Form>
  </Drawer>
</template>
