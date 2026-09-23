import { z } from 'zod'
import { email, optionalString, cidr } from '@freya/ui/forms'

export const SHARE_VALIDITY = { '1h': 3600, '1d': 86400, '7d': 604800 } as const

/** One-time email share of the current password. */
export const shareSchema = z.object({
  recipient_email: email,
  message: optionalString(1000),
  validity: z.enum(['1h', '1d', '7d']),
  max_opens: z.coerce.number().int().min(1, 'At least one reveal.').max(10, 'At most ten reveals.'),
  cidr: optionalString(64).pipe(cidr.optional()),
})
export type ShareFormOutput = z.output<typeof shareSchema>
