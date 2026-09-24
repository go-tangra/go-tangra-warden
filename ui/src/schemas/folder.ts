import { z } from 'zod'
import { nonEmpty, optionalString } from '@go-tangra/ui/forms'

export const folderNameSchema = z.object({
  name: nonEmpty(120).refine((s) => !s.includes('/'), 'Folder names cannot contain "/".'),
})
export const folderMoveSchema = z.object({ parent_id: optionalString(64) })
export const folderDeleteSchema = z.object({ recursive: z.boolean().optional().transform((v) => v ?? false) })
