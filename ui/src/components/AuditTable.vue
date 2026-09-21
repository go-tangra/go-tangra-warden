<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useOps, type AuditFilter, type AuditItem } from '@/stores/ops'
import { useDirectory } from '@/stores/directory'

const ops = useOps()
const dir = useDirectory()
const filter = ref<AuditFilter>({})
const eventType = ref('')
const actor = ref('')

async function apply(): Promise<void> {
  filter.value = { event_type: eventType.value || undefined, actor_id: actor.value || undefined }
  await ops.loadAudit(filter.value)
}

// Actors are user ids from the auth module; the subject name comes with the event.
watch(
  () => ops.audit,
  (items) => void dir.resolveUsers(items.filter((e) => e.actor_kind === 'user').map((e) => e.actor_id)),
)

function actorLabel(e: AuditItem): string {
  switch (e.actor_kind) {
    case 'user':
      return dir.userName(e.actor_id)
    case 'system':
      return 'system'
    default:
      return e.actor_kind + (e.actor_id ? ' ' + e.actor_id : '')
  }
}

function subjectLabel(e: AuditItem): string {
  if (!e.subject_kind) return ''
  return e.subject_kind + (e.subject_name ? ' ' + e.subject_name : e.subject_id ? ' ' + e.subject_id : '')
}

onMounted(apply)
</script>

<template>
  <v-card variant="outlined" data-test="audit-table">
    <v-card-title class="text-subtitle-1">Audit trail</v-card-title>
    <v-card-text>
      <v-form class="d-flex ga-2 mb-2" @submit.prevent="apply">
        <v-text-field v-model="eventType" label="Event type" density="compact" hide-details data-test="audit-type" />
        <v-text-field v-model="actor" label="Actor id" density="compact" hide-details data-test="audit-actor" />
        <v-btn type="submit" variant="tonal" data-test="audit-apply">Filter</v-btn>
      </v-form>
      <v-alert v-if="ops.error" type="error" variant="tonal" density="compact" data-test="audit-error">Audit unavailable ({{ ops.error }}).</v-alert>
      <v-table density="compact" aria-label="Audit events">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Event</th>
            <th scope="col">Actor</th>
            <th scope="col">Subject</th>
            <th scope="col">Outcome</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in ops.audit" :key="i" data-test="audit-row">
            <td>{{ new Date(e.ts).toLocaleString() }}</td>
            <td>{{ e.event_type }}</td>
            <td :title="e.actor_id" data-test="audit-actor-cell">{{ actorLabel(e) }}</td>
            <td :title="e.subject_id" data-test="audit-subject-cell">{{ subjectLabel(e) }}</td>
            <td>{{ e.outcome }}{{ e.reason ? ' (' + e.reason + ')' : '' }}</td>
          </tr>
          <tr v-if="!ops.audit.length">
            <td colspan="5" class="text-medium-emphasis" data-test="audit-empty">No events.</td>
          </tr>
        </tbody>
      </v-table>
      <v-btn v-if="ops.next" variant="text" data-test="audit-more" @click="ops.loadAudit(filter, ops.next)">Load more</v-btn>
    </v-card-text>
  </v-card>
</template>
