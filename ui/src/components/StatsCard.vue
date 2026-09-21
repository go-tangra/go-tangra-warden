<script setup lang="ts">
import { onMounted } from 'vue'
import { useOps } from '@/stores/ops'

const ops = useOps()
onMounted(ops.loadStats)
</script>

<template>
  <v-card variant="outlined" data-test="stats-card">
    <v-card-title class="text-subtitle-1">Statistics</v-card-title>
    <v-card-text v-if="ops.stats">
      <dl class="stats-grid">
        <dt>Secrets</dt>
        <dd data-test="stat-secrets">{{ ops.stats.secrets }}</dd>
        <dt>With one-time code</dt>
        <dd data-test="stat-totp">{{ ops.stats.secrets_with_totp }}</dd>
        <dt>Folders</dt>
        <dd data-test="stat-folders">{{ ops.stats.folders }}</dd>
        <dt>Versions</dt>
        <dd data-test="stat-versions">{{ ops.stats.versions }}</dd>
        <dt>Grants</dt>
        <dd data-test="stat-grants">{{ Object.entries(ops.stats.grants).map(([k, v]) => k + ' ' + v).join(', ') || 'none' }}</dd>
        <dt>Shares</dt>
        <dd data-test="stat-shares">{{ Object.entries(ops.stats.shares).map(([k, v]) => k + ' ' + v).join(', ') || 'none' }}</dd>
        <dt>Operations (24 h)</dt>
        <dd data-test="stat-ops">{{ ops.stats.operations_24h }}</dd>
      </dl>
    </v-card-text>
    <v-card-text v-else class="text-medium-emphasis" data-test="stats-empty">{{ ops.error ? 'Statistics unavailable.' : 'Loading…' }}</v-card-text>
  </v-card>
</template>

<style scoped>
.stats-grid {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 4px 16px;
}
.stats-grid dt {
  color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity));
}
</style>
