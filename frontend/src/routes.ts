import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/warden',
    name: 'Warden',
    component: () => import('shell/vben/layouts').then((m) => m.BasicLayout),
    redirect: '/warden/folder',
    meta: {
      order: 2010,
      icon: 'lucide:key-round',
      title: 'warden.menu.warden',
      keepAlive: true,
      authority: ['platform:admin', 'tenant:manager'],
    },
    children: [
      {
        path: 'folder',
        name: 'WardenFolders',
        meta: {
          icon: 'lucide:folder-tree',
          title: 'warden.menu.secrets',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/folder/index.vue'),
      },
      {
        path: 'permission',
        name: 'WardenPermissions',
        meta: {
          icon: 'lucide:shield',
          title: 'warden.menu.permissions',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/permission/index.vue'),
      },
    ],
  },
];

export default routes;
