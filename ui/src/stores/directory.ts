import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { RoleHit, UserHit } from '@/stores/permissions'

// Names for the ids the warden API hands back: user ids resolve through the
// auth module's batch lookup (public profiles of the caller's tenant; unknown
// or foreign ids come back absent and stay as ids), role slugs through the
// role list. Both are cached for the session.
export const useDirectory = defineStore('warden-directory', () => {
  const users = ref<Record<string, UserHit | null>>({})
  const roles = ref<Record<string, RoleHit>>({})
  let rolesLoaded: Promise<void> | null = null
  const pending = new Map<string, Promise<void>>()

  /** Resolves the given user ids (deduplicated, batches of 100); failures leave ids unresolved. */
  async function resolveUsers(ids: Array<string | undefined | null>): Promise<void> {
    const want = [...new Set(ids.filter((id): id is string => !!id && !(id in users.value) && !pending.has(id)))]
    const waits: Promise<void>[] = ids.filter((id): id is string => !!id && pending.has(id)).map((id) => pending.get(id)!)
    for (let i = 0; i < want.length; i += 100) {
      const chunk = want.slice(i, i + 100)
      const p = api<{ items: UserHit[] }>('POST', '/api/v1/users/lookup', { ids: chunk })
        .then((out) => {
          const found = new Map(out.items.map((u) => [u.id, u]))
          for (const id of chunk) users.value[id] = found.get(id) ?? null
        })
        .catch(() => {
          // Leave them unknown so a later call retries.
        })
        .finally(() => chunk.forEach((id) => pending.delete(id)))
      chunk.forEach((id) => pending.set(id, p))
      waits.push(p)
    }
    await Promise.all(waits)
  }

  async function loadRoles(): Promise<void> {
    rolesLoaded ??= api<RoleHit[]>('GET', '/api/v1/roles')
      .then((list) => {
        for (const r of list) roles.value[r.slug] = r
      })
      .catch(() => {
        rolesLoaded = null
      })
    await rolesLoaded
  }

  /** Display name of a user, or the id while unresolved. */
  function userName(id: string | undefined | null): string {
    if (!id) return ''
    return users.value[id]?.display_name ?? id
  }

  /** Display name of a role, or the slug while unresolved. */
  function roleName(slug: string | undefined | null): string {
    if (!slug) return ''
    return roles.value[slug]?.display_name ?? slug
  }

  return { users, roles, resolveUsers, loadRoles, userName, roleName }
})
