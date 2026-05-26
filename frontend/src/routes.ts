import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/warden',
    name: 'Warden',
    component: () => import('shell/app-layout'),
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
      {
        path: 'generator',
        name: 'WardenGenerator',
        meta: {
          icon: 'lucide:dices',
          title: 'warden.menu.generator',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/generator/index.vue'),
      },
    ],
  },
];

export default routes;
