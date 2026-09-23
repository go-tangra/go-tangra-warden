import { z } from 'zod'
import { isoDate } from '@freya/ui/forms'

export const auditFilterSchema = z.object({
  event_type: z.string().trim().max(100).optional(),
  actor_id: z.string().trim().max(200).optional(),
  from: isoDate,
  to: isoDate,
})
export const searchSchema = z.object({ q: z.string().trim().max(200) })
