import type { RouteRecordRaw } from 'vue-router'
import '@/main.css'

// Routes mounted by the platform shell under their own error boundary.
export const routes: RouteRecordRaw[] = [
  { path: '/warden', name: 'warden-secrets', component: () => import('@/views/secrets/index.vue'), meta: { module: 'warden' } },
  // Folders are managed inside the explorer; old links keep working.
  { path: '/warden/folders', redirect: '/warden' },
  { path: '/warden/permissions', name: 'warden-permissions', component: () => import('@/views/permissions/index.vue'), meta: { module: 'warden' } },
  { path: '/warden/generator', name: 'warden-generator', component: () => import('@/views/generator/index.vue'), meta: { module: 'warden' } },
]
export default routes
