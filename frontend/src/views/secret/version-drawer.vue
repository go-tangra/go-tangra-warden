<script lang="ts" setup>
import { ref, computed, h } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';
import { LucideEye, LucideEyeOff, LucideRotateCcw } from 'shell/vben/icons';

import {
  Table,
  Button,
  notification,
  Modal,
  Space,
  Tag,
  Spin,
} from 'ant-design-vue';
import type { ColumnsType } from 'ant-design-vue/es/table';

import {
  type Secret,
  type SecretVersion,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useWardenSecretStore } from '../../stores/warden-secret.state';

const secretStore = useWardenSecretStore();

const data = ref<{
  secret: Secret;
}>();
const loading = ref(false);
const versions = ref<SecretVersion[]>([]);
const showingPasswordVersion = ref<number | null>(null);
const versionPasswords = ref<Record<number, string>>({});
const loadingPassword = ref(false);
const restoringVersion = ref<number | null>(null);

const title = computed(() => $t('warden.page.version.title'));

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function loadVersions() {
  if (!data.value?.secret?.id) return;
  loading.value = true;
  try {
    const resp = await secretStore.listVersions(data.value.secret.id);
    versions.value = (resp.versions ?? []) as SecretVersion[];
  } catch (e) {
    console.error('Failed to load versions:', e);
    notification.error({ message: $t('ui.notification.load_failed') });
  } finally {
    loading.value = false;
  }
}

async function handleTogglePassword(version: SecretVersion) {
  const versionNum = version.versionNumber ?? 0;

  if (showingPasswordVersion.value === versionNum) {
    showingPasswordVersion.value = null;
    return;
  }

  if (!versionPasswords.value[versionNum] && data.value?.secret?.id) {
    loadingPassword.value = true;
    try {
      const resp = await secretStore.getVersion(
        data.value.secret.id,
        versionNum,
        true,
      );
      versionPasswords.value[versionNum] = resp.password ?? '';
    } catch (e) {
      console.error('Failed to load password:', e);
      notification.error({ message: $t('ui.notification.load_failed') });
      loadingPassword.value = false;
      return;
    } finally {
      loadingPassword.value = false;
    }
  }

  showingPasswordVersion.value = versionNum;
}

async function handleRestore(version: SecretVersion) {
  if (!data.value?.secret?.id || !version.versionNumber) return;

  Modal.confirm({
    title: $t('warden.page.version.restore'),
    content: $t('warden.page.version.restoreConfirm'),
    okText: $t('ui.button.ok'),
    cancelText: $t('ui.button.cancel'),
    onOk: async () => {
      const versionNum = version.versionNumber!;
      restoringVersion.value = versionNum;
      try {
        await secretStore.restoreVersion(
          data.value!.secret.id!,
          versionNum,
          `Restored from version ${versionNum}`,
        );
        notification.success({
          message: $t('warden.page.version.restoreSuccess'),
        });
        await loadVersions();
      } catch (e) {
        console.error('Failed to restore version:', e);
        notification.error({ message: $t('ui.notification.operation_failed') });
      } finally {
        restoringVersion.value = null;
      }
    },
  });
}

const columns: ColumnsType<SecretVersion> = [
  {
    title: $t('warden.page.version.versionNumber'),
    dataIndex: 'versionNumber',
    key: 'versionNumber',
    width: 100,
    customRender: ({ record }) => {
      const isCurrent =
        record.versionNumber === data.value?.secret?.currentVersion;
      return h(Space, {}, () => [
        h('span', {}, `v${record.versionNumber}`),
        isCurrent
          ? h(Tag, { color: 'green' }, () => 'Current')
          : null,
      ]);
    },
  },
  {
    title: $t('warden.page.version.createdAt'),
    dataIndex: 'createTime',
    key: 'createTime',
    width: 180,
    customRender: ({ text }) => formatDateTime(text),
  },
  {
    title: $t('warden.page.version.comment'),
    dataIndex: 'comment',
    key: 'comment',
    ellipsis: true,
    customRender: ({ text }) => text || '-',
  },
  {
    title: $t('ui.table.action'),
    key: 'action',
    width: 140,
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
        secret: Secret;
      };
      versions.value = [];
      versionPasswords.value = {};
      showingPasswordVersion.value = null;
      await loadVersions();
    }
  },
});

const secret = computed(() => data.value?.secret);
</script>

<template>
  <Drawer :title="title" :footer="false" width="700px">
    <template v-if="secret">
      <div class="mb-4">
        <span class="font-semibold">{{ secret.name }}</span>
        <span class="text-muted-foreground ml-2">
          ({{ $t('warden.page.secret.currentVersion') }}: v{{
            secret.currentVersion
          }})
        </span>
      </div>

      <Spin :spinning="loading">
        <Table
          :columns="columns"
          :data-source="versions"
          :pagination="false"
          :scroll="{ y: 500 }"
          row-key="id"
          size="small"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'">
              <Space>
                <Button
                  type="text"
                  size="small"
                  :icon="
                    showingPasswordVersion === record.versionNumber
                      ? h(LucideEyeOff)
                      : h(LucideEye)
                  "
                  :loading="loadingPassword && showingPasswordVersion === null"
                  :title="$t('warden.page.version.viewPassword')"
                  @click="handleTogglePassword(record as SecretVersion)"
                />
                <Button
                  v-if="record.versionNumber !== secret.currentVersion"
                  type="text"
                  size="small"
                  :icon="h(LucideRotateCcw)"
                  :loading="restoringVersion === record.versionNumber"
                  :title="$t('warden.page.version.restore')"
                  @click="handleRestore(record as SecretVersion)"
                />
              </Space>
            </template>
          </template>

          <template #expandedRowRender="{ record }">
            <div
              v-if="showingPasswordVersion === record.versionNumber"
              class="bg-muted rounded p-4"
            >
              <div class="text-sm font-semibold">
                {{ $t('warden.page.secret.password') }}:
              </div>
              <code class="mt-1 block">{{
                versionPasswords[record.versionNumber] || '...'
              }}</code>
            </div>
          </template>
        </Table>
      </Spin>
    </template>
  </Drawer>
</template>
