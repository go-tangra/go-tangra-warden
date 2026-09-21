<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { describe } from '@/api/client'
import { useShares } from '@/stores/shares'
import ShareDialog from '@/components/ShareDialog.vue'

const props = defineProps<{ secretId: string; secretName: string }>()
const shares = useShares()
const dialog = ref(false)
const error = ref('')

onMounted(() => shares.list(props.secretId))
watch(() => props.secretId, (id) => shares.list(id))

async function cancel(id: string): Promise<void> {
  error.value = ''
  try {
    await shares.cancel(props.secretId, id)
  } catch (e) {
    error.value = describe(e)
  }
}
</script>

<template>
  <section class="pa-4" aria-labelledby="shares-heading" data-test="shares-panel">
    <div class="d-flex align-center mb-2">
      <h3 id="shares-heading" class="text-subtitle-1">Shared links</h3>
      <v-spacer />
      <v-btn size="small" variant="tonal" data-test="share-new" @click="dialog = true">Share by email</v-btn>
    </div>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="shares-error">{{ error }}</v-alert>
    <v-list v-if="shares.items.length" density="compact" lines="two" aria-label="Shared links">
      <v-list-item v-for="s in shares.items" :key="s.id" :data-test="'share-' + s.id">
        <v-list-item-title>{{ s.recipient_email }} <v-chip size="x-small" class="ml-1" :data-test="'share-state-' + s.id">{{ s.state }}</v-chip></v-list-item-title>
        <v-list-item-subtitle>{{ s.opens }}/{{ s.max_opens }} reveals · until {{ new Date(s.expires_at).toLocaleString() }}{{ s.cidr ? ' · ' + s.cidr : '' }}</v-list-item-subtitle>
        <template #append>
          <v-btn v-if="s.state === 'active'" size="small" variant="text" color="error" :data-test="'share-cancel-' + s.id" @click="cancel(s.id)">Cancel</v-btn>
        </template>
      </v-list-item>
    </v-list>
    <p v-else class="text-caption text-medium-emphasis" data-test="shares-empty">No links yet.</p>
    <ShareDialog v-model="dialog" :secret-id="secretId" :secret-name="secretName" />
  </section>
</template>
