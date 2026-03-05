import { wardenApi } from './client';

export async function listUsers(): Promise<{ items: any[] }> {
  return wardenApi.get('/users?noPaging=true');
}

export async function listRoles(): Promise<{ items: any[] }> {
  return wardenApi.get('/roles?noPaging=true');
}
