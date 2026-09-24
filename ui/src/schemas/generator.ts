import { z } from 'zod'

export const generatorSchema = z
  .object({
    length: z.coerce.number().int().min(8, 'At least 8 characters.').max(128, 'At most 128 characters.'),
    lower: z.boolean().optional().transform((v) => v ?? false),
    upper: z.boolean().optional().transform((v) => v ?? false),
    digits: z.boolean().optional().transform((v) => v ?? false),
    symbols: z.boolean().optional().transform((v) => v ?? false),
    source: z.enum(['server', 'local']),
  })
  .refine((o) => o.lower || o.upper || o.digits || o.symbols, { path: ['lower'], message: 'Pick at least one character class.' })
export type GeneratorFormOutput = z.output<typeof generatorSchema>
