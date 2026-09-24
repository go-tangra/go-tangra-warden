import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

export interface TransferReport {
  folders: number
  items: number
  created: number
  renamed: number
  skipped: number
  overwritten: number
  failed: number
  collisions: Array<{ name: string; folder: string }>
  problems: Array<{ index: number; reason: string }>
  warnings: string[]
}

export interface BackupReport {
  folders: Counts
  secrets: Counts
  versions: Counts
  grants: Counts
  warnings: string[]
}

export interface Counts {
  created: number
  skipped: number
  failed: number
}

export type Strategy = 'skip' | 'rename' | 'overwrite'

export const useTransfer = defineStore('warden-transfer', () => {
  const busy = ref(false)

  async function validate(document: string, folderId: string | null): Promise<TransferReport> {
    busy.value = true
    try {
      return await api<TransferReport>('POST', 'transfer/bitwarden/validate', JSON.parse(document), { query: { folder_id: folderId ?? undefined } })
    } finally {
      busy.value = false
    }
  }

  async function importBitwarden(document: string, folderId: string | null, duplicates: Strategy): Promise<TransferReport> {
    busy.value = true
    try {
      return await api<TransferReport>('POST', 'transfer/bitwarden/import', JSON.parse(document), { query: { folder_id: folderId ?? undefined, duplicates } })
    } finally {
      busy.value = false
    }
  }

  async function importBackup(document: string): Promise<BackupReport> {
    busy.value = true
    try {
      return await api<BackupReport>('POST', 'backup/import', JSON.parse(document))
    } finally {
      busy.value = false
    }
  }

  return { busy, validate, importBitwarden, importBackup }
})
