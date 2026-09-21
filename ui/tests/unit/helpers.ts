import { vi } from 'vitest'
import { defineComponent, h, type Plugin } from 'vue'
import { mount } from '@vue/test-utils'
import { VLayout } from 'vuetify/components'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'
import type { Folder, FolderNode, Secret } from '@/api/types'

export type Reply = { status: number; body: unknown }

/** Stubs fetch with a request handler and records calls. */
export function stubFetch(handler: (url: string, init?: RequestInit) => Reply) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(input), init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

export function plugins(rules: Array<{ action: string; subject: string }> = [{ action: 'manage', subject: 'all' }]): Array<Plugin | [Plugin, ...unknown[]]> {
  return [createVuetify({ components, directives }), [abilitiesPlugin as Plugin, createMongoAbility(rules), { useGlobalProperties: true }]]
}

export const perms = { read: true, write: true, delete: true, share: true }
export const viewer = { read: true, write: false, delete: false, share: false }

export function folder(id: string, name: string, path: string, parent: string | null = null, p = perms): Folder {
  return { id, parent_id: parent, name, path, secret_count: 0, created_at: '2026-09-16T00:00:00Z', updated_at: '2026-09-16T00:00:00Z', permissions: p }
}

export function node(f: Folder, children: FolderNode[] = []): FolderNode {
  return { folder: f, children }
}

export function secret(id: string, name: string, extra: Partial<Secret> = {}): Secret {
  return {
    id,
    folder_id: null,
    folder_path: '',
    name,
    username: 'root',
    host_url: 'https://h',
    description: '',
    metadata: {},
    current_version: 1,
    has_totp: false,
    created_at: '2026-09-16T00:00:00Z',
    updated_at: '2026-09-16T00:00:00Z',
    permissions: perms,
    ...extra,
  }
}

/** Sets a text input's value and emits input. */
export function type(root: ParentNode, selector: string, value: string): void {
  const el = root.querySelector(selector + ' input, ' + selector + ' textarea') as HTMLInputElement | null
  if (!el) throw new Error('no input for ' + selector)
  el.value = value
  el.dispatchEvent(new Event('input'))
}

export function click(root: ParentNode, selector: string): void {
  const el = root.querySelector(selector) as HTMLElement | null
  if (!el) throw new Error('no element for ' + selector)
  el.click()
}

/**
 * Mounts a component that needs Vuetify's layout (navigation drawers) inside
 * a v-layout, as the platform shell's v-app provides in production. Listeners
 * go in `attrs` as onX functions.
 */
export function mountInLayout(comp: unknown, attrs: Record<string, unknown>, rules?: Array<{ action: string; subject: string }>) {
  const Wrapper = defineComponent({ render: () => h(VLayout, null, () => [h(comp as never, attrs)]) })
  return mount(Wrapper, { global: { plugins: plugins(rules) }, attachTo: document.body })
}
