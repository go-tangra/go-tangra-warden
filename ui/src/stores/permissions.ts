import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Permissions } from '@/api/types'

export type ResourceType = 'folder' | 'secret'
export type SubjectType = 'user' | 'role' | 'tenant'
export type Relation = 'owner' | 'editor' | 'viewer' | 'sharer'

export interface Grant {
  id: string
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string
  relation: Relation
  granted_by?: string
  granted_at: string
  expires_at?: string
  inherited: boolean
  expired: boolean
}

export interface Source {
  grant_id: string
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string
  relation: Relation
  expires_at?: string
  inherited: boolean
}

export interface Effective {
  permissions: Permissions
  relation: string
  grants: Source[]
}

export interface GrantInput {
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string | undefined
  relation: Relation
  expires_at?: string | null | undefined
}

export interface UserHit {
  id: string
  display_name: string
  avatar_url?: string
  email?: string
}

export interface RoleHit {
  slug: string
  display_name: string
}

/** Relations a granter holding `held` may hand out (never above their own). */
export function grantable(held: string): Relation[] {
  const order: Relation[] = ['viewer', 'sharer', 'editor', 'owner']
  const rank = order.indexOf(held as Relation)
  return rank < 0 ? [] : order.slice(0, rank + 1)
}

export const usePermissions = defineStore('warden-permissions', () => {
  const grants = ref<Grant[]>([])
  const effective = ref<Effective | null>(null)
  const loading = ref(false)
  const error = ref('')

  async function load(resourceType: ResourceType, resourceId: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [g, e] = await Promise.all([
        api<{ items: Grant[] }>('GET', 'grants', undefined, { query: { resource_type: resourceType, resource_id: resourceId } }).catch((err) => {
          if ((err as { reason?: string }).reason === 'forbidden') return { items: [] as Grant[] }
          throw err
        }),
        api<Effective>('GET', 'access/effective', undefined, { query: { resource_type: resourceType, resource_id: resourceId } }),
      ])
      grants.value = g.items
      effective.value = e
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function grant(input: GrantInput): Promise<Grant> {
    const g = await api<Grant>('POST', 'grants', input)
    await load(input.resource_type, input.resource_id)
    return g
  }

  async function revoke(g: Grant, resourceType: ResourceType, resourceId: string): Promise<void> {
    await api('POST', 'grants/' + g.id + '/revoke')
    await load(resourceType, resourceId)
  }

  async function searchUsers(q: string): Promise<UserHit[]> {
    if (q.trim().length < 2) return []
    const out = await api<{ items: UserHit[] }>('GET', '/api/v1/users', undefined, { query: { q: q.trim() } })
    return out.items
  }

  async function roles(): Promise<RoleHit[]> {
    return api<RoleHit[]>('GET', '/api/v1/roles')
  }

  return { grants, effective, loading, error, load, grant, revoke, searchUsers, roles }
})
