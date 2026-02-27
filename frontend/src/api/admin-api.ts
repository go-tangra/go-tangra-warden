import { useAccessStore } from 'shell/vben/stores';

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

export async function listUsers(
  query?: Record<string, string>,
): Promise<{ items: any[] }> {
  const params = new URLSearchParams({ noPaging: 'true' });
  if (query && Object.keys(query).length > 0) {
    params.set('query', JSON.stringify(query));
  }
  return adminGet(`/admin/admin/v1/users?${params}`);
}

export async function listRoles(): Promise<{ items: any[] }> {
  return adminGet('/admin/admin/v1/roles?noPaging=true');
}
