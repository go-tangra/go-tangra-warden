import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Folder, FolderNode } from '@/api/types'

export const useFolders = defineStore('warden-folders', () => {
  const tree = ref<FolderNode[]>([])
  const loading = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const out = await api<{ items: FolderNode[] }>('GET', 'folders/tree')
      tree.value = out.items
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  function find(id: string | null, nodes: FolderNode[] = tree.value): FolderNode | undefined {
    for (const n of nodes) {
      if (n.folder.id === id) return n
      const hit = find(id, n.children)
      if (hit) return hit
    }
    return undefined
  }

  async function create(parentId: string | null, name: string): Promise<Folder> {
    const f = await api<Folder>('POST', 'folders', { parent_id: parentId, name })
    await load()
    return f
  }

  async function rename(id: string, name: string): Promise<Folder> {
    const f = await api<Folder>('PUT', 'folders/' + id, { name })
    await load()
    return f
  }

  async function move(id: string, parentId: string | null): Promise<Folder> {
    const f = await api<Folder>('POST', 'folders/' + id + '/move', { parent_id: parentId })
    await load()
    return f
  }

  async function remove(id: string, recursive: boolean): Promise<void> {
    await api('POST', 'folders/' + id + '/remove', { recursive })
    await load()
  }

  /** Flattens the tree depth-first for pickers. */
  function flat(nodes: FolderNode[] = tree.value, depth = 0): Array<{ folder: Folder; depth: number }> {
    const out: Array<{ folder: Folder; depth: number }> = []
    for (const n of nodes) {
      out.push({ folder: n.folder, depth })
      out.push(...flat(n.children, depth + 1))
    }
    return out
  }

  return { tree, loading, error, load, find, create, rename, move, remove, flat }
})
