import { useAccessStore } from 'shell/vben/stores';

import { wardenApi } from './client';

export async function listUsers(): Promise<{ items: any[] }> {
  return wardenApi.get('/users?noPaging=true');
}

async function adminGet(path: string): Promise<any> {
  const token = (useAccessStore() as any).accessToken;
  const res = await fetch(path, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function listRoles(): Promise<{ items: any[] }> {
  return adminGet('/admin/admin/v1/roles?noPaging=true');
}
