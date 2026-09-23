import { z } from 'zod'
import { optionalString } from '@freya/ui/forms'

export const IMPORT_STRATEGIES = ['skip', 'rename', 'overwrite'] as const
export const MAX_IMPORT_BYTES = 16 * 1024 * 1024

/** Bitwarden unencrypted JSON export: shape-checked here before any request. */
export const bitwardenDocument = z
  .string()
  .transform((text, ctx) => {
    let doc: unknown
    try {
      doc = JSON.parse(text)
    } catch {
      ctx.addIssue({ code: 'custom', message: 'The file is not valid JSON.' })
      return z.NEVER
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
      ctx.addIssue({ code: 'custom', message: 'The file is not a Bitwarden export.' })
      return z.NEVER
    }
    const d = doc as Record<string, unknown>
    if (d.encrypted === true) {
      ctx.addIssue({ code: 'custom', message: 'Encrypted exports are not supported; export without a password.' })
      return z.NEVER
    }
    if (!Array.isArray(d.items)) {
      ctx.addIssue({ code: 'custom', message: 'The export has no "items" list.' })
      return z.NEVER
    }
    return text
  })

export const importPickSchema = z.object({
  file: z.instanceof(File, { message: 'Choose an export file.' }).refine((f) => f.size <= MAX_IMPORT_BYTES, 'The file is larger than 16 MiB.'),
  target: optionalString(64),
})
export const importStrategySchema = z.object({ strategy: z.enum(IMPORT_STRATEGIES) })
