<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { describe } from '@/api/client'
import { grantable, usePermissions, type Grant, type Relation, type ResourceType, type RoleHit, type SubjectType, type UserHit } from '@/stores/permissions'
import { useDirectory } from '@/stores/directory'

const props = defineProps<{ modelValue: boolean; resourceType: ResourceType; resourceId: string; resourceName: string }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; changed: [] }>()
const perms = usePermissions()
const dir = useDirectory()

const subjectType = ref<SubjectType>('user')
const userQuery = ref('')
const userHits = ref<UserHit[]>([])
const user = ref<UserHit | null>(null)
const roleHits = ref<RoleHit[]>([])
const role = ref<string | null>(null)
const relation = ref<Relation>('viewer')
const expires = ref('')
const error = ref('')
const busy = ref(false)
let searchTimer: ReturnType<typeof setTimeout> | undefined

const held = computed(() => perms.effective?.relation ?? '')
const canShare = computed(() => !!perms.effective?.permissions.share)
const options = computed(() => grantable(held.value))
const subjectId = computed(() => (subjectType.value === 'user' ? user.value?.id : subjectType.value === 'role' ? role.value : ''))
const subjectError = computed(() => (subjectType.value === 'tenant' || subjectId.value ? '' : 'Pick a subject'))
const expiresError = computed(() => (expires.value && new Date(expires.value).getTime() <= Date.now() ? 'Expiry must be in the future' : ''))

watch(
  () => [props.modelValue, props.resourceId] as const,
  async ([open]) => {
    if (!open) return
    error.value = ''
    user.value = null
    role.value = null
    userQuery.value = ''
    expires.value = ''
    await perms.load(props.resourceType, props.resourceId)
    if (!options.value.includes(relation.value)) relation.value = options.value[0] ?? 'viewer'
    try {
      roleHits.value = await perms.roles()
    } catch {
      roleHits.value = []
    }
  },
  { immediate: true },
)

watch(userQuery, (q) => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(async () => {
    try {
      userHits.value = await perms.searchUsers(q)
    } catch {
      userHits.value = []
    }
  }, 150)
})

async function submit(): Promise<void> {
  if (subjectError.value || expiresError.value) return
  busy.value = true
  error.value = ''
  try {
    await perms.grant({
      resource_type: props.resourceType,
      resource_id: props.resourceId,
      subject_type: subjectType.value,
      subject_id: subjectType.value === 'tenant' ? undefined : (subjectId.value ?? undefined),
      relation: relation.value,
      expires_at: expires.value ? new Date(expires.value).toISOString() : null,
    })
    emit('changed')
    user.value = null
    role.value = null
    userQuery.value = ''
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function revoke(g: Grant): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    await perms.revoke(g, props.resourceType, props.resourceId)
    emit('changed')
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

function subjectLabel(g: { subject_type: SubjectType; subject_id?: string }): string {
  if (g.subject_type === 'tenant') return 'Everyone in the tenant'
  return g.subject_type === 'role' ? 'Role ' + dir.roleName(g.subject_id) : 'User ' + dir.userName(g.subject_id)
}

// Grants name users by id and roles by slug; resolve both whenever the lists change.
watch(
  () => [perms.grants, perms.effective?.grants ?? []] as const,
  ([grants, sources]) => {
    const all = [...grants, ...sources]
    void dir.resolveUsers(all.filter((g) => g.subject_type === 'user').map((g) => g.subject_id))
    if (all.some((g) => g.subject_type === 'role')) void dir.loadRoles()
  },
  { immediate: true },
)
</script>

<template>
  <v-navigation-drawer :model-value="modelValue" location="right" temporary width="560" data-test="permission-drawer" @update:model-value="emit('update:modelValue', $event)">
    <v-toolbar density="compact" color="transparent">
      <v-toolbar-title>Access to {{ resourceName }}</v-toolbar-title>
      <v-btn icon="mdi-close" aria-label="Close" variant="text" data-test="permissions-close" @click="emit('update:modelValue', false)" />
    </v-toolbar>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mx-4" data-test="permissions-error">{{ error }}</v-alert>
    <section class="pa-4" aria-labelledby="effective-heading">
      <h3 id="effective-heading" class="text-subtitle-1 mb-1">Your access</h3>
      <p class="text-body-2" data-test="effective-summary">
        <template v-if="perms.effective">
          {{ perms.effective.relation ? 'Strongest relation: ' + perms.effective.relation : 'No access' }} ·
          <span v-for="(v, k) in perms.effective.permissions" :key="k" class="mr-2"><v-icon :icon="v ? 'mdi-check' : 'mdi-close'" size="x-small" /> {{ k }}</span>
        </template>
      </p>
      <ul v-if="perms.effective?.grants.length" class="text-caption text-medium-emphasis pl-4" data-test="effective-sources">
        <li v-for="s in perms.effective.grants" :key="s.grant_id">{{ s.relation }} as {{ subjectLabel(s) }}{{ s.inherited ? ' (inherited from a folder)' : '' }}</li>
      </ul>
    </section>
    <v-divider />
    <section v-if="canShare" class="pa-4" aria-labelledby="grant-heading">
      <h3 id="grant-heading" class="text-subtitle-1 mb-2">Grant access</h3>
      <v-form @submit.prevent="submit">
        <v-btn-toggle v-model="subjectType" mandatory density="comfortable" class="mb-3" aria-label="Subject type" data-test="subject-type">
          <v-btn value="user" data-test="subject-user">User</v-btn>
          <v-btn value="role" data-test="subject-role">Role</v-btn>
          <v-btn value="tenant" data-test="subject-tenant">Everyone</v-btn>
        </v-btn-toggle>
        <template v-if="subjectType === 'user'">
          <v-text-field v-model="userQuery" label="Find a member (name or email)" density="compact" data-test="user-query" />
          <v-list v-if="userHits.length && !user" density="compact" aria-label="Matching members" data-test="user-hits">
            <v-list-item v-for="u in userHits" :key="u.id" :title="u.display_name" :subtitle="u.email ?? ''" :data-test="'user-hit-' + u.id" @click="user = u" />
          </v-list>
          <v-chip v-if="user" closable class="mb-3" data-test="user-picked" @click:close="user = null">{{ user.display_name }}</v-chip>
        </template>
        <v-select v-else-if="subjectType === 'role'" v-model="role" :items="roleHits" item-title="display_name" item-value="slug" label="Role" density="compact" data-test="role-select" />
        <p v-else class="text-body-2 mb-3">Every member of the tenant.</p>
        <v-select v-model="relation" :items="options" label="Relation" density="compact" data-test="relation-select" />
        <v-text-field v-model="expires" label="Expires (optional)" type="datetime-local" density="compact" :error-messages="expiresError" data-test="expires" />
        <v-btn type="submit" color="primary" :disabled="!!subjectError || !!expiresError" :loading="busy" data-test="grant-save">Grant</v-btn>
        <span v-if="subjectError" class="text-caption text-medium-emphasis ml-2">{{ subjectError }}</span>
      </v-form>
    </section>
    <p v-else class="pa-4 text-body-2 text-medium-emphasis" data-test="no-share">You cannot share this {{ resourceType }}.</p>
    <v-divider />
    <section class="pa-4" aria-labelledby="grants-heading">
      <h3 id="grants-heading" class="text-subtitle-1 mb-2">Grants</h3>
      <v-table density="compact" aria-label="Grants">
        <thead>
          <tr>
            <th scope="col">Subject</th>
            <th scope="col">Relation</th>
            <th scope="col">Source</th>
            <th scope="col">Expires</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="g in perms.grants" :key="g.id" :data-test="'grant-' + g.id" :class="{ 'text-medium-emphasis': g.expired }">
            <td>{{ subjectLabel(g) }}</td>
            <td>{{ g.relation }}</td>
            <td>{{ g.inherited ? 'inherited' : 'direct' }}</td>
            <td>{{ g.expires_at ? new Date(g.expires_at).toLocaleString() + (g.expired ? ' (expired)' : '') : 'never' }}</td>
            <td><v-btn v-if="canShare" size="small" variant="text" color="error" :data-test="'revoke-' + g.id" @click="revoke(g)">Revoke</v-btn></td>
          </tr>
          <tr v-if="!perms.grants.length">
            <td colspan="5" class="text-medium-emphasis" data-test="no-grants">No grants visible.</td>
          </tr>
        </tbody>
      </v-table>
    </section>
  </v-navigation-drawer>
</template>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
}
</style>
