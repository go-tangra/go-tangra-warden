import { z } from 'zod'
import { nonEmpty, optionalString, jsonObject } from '@freya/ui/forms'

/** otpauth:// URI or a base32 seed (the service normalises either). */
export const totpSeed = z.string().trim().max(2048).regex(/^(otpauth:\/\/totp\/.+|[A-Z2-7]+=*)$/i, 'Paste an otpauth:// URI or a base32 seed.')

const base = {
  folder_id: optionalString(64),
  name: nonEmpty(200),
  username: optionalString(200),
  host_url: optionalString(2048),
  description: optionalString(2000),
  metadata: jsonObject,
}

/** New secret: the password is required once and travels write-only. */
export const secretCreateSchema = z.object({
  ...base,
  password: z.string().min(1, 'A password is required.').max(4096),
  totp: optionalString(2048).pipe(totpSeed.optional()),
})
/** Editing metadata only; password and TOTP change through their own actions. */
export const secretUpdateSchema = z.object(base)
export type SecretCreateOutput = z.output<typeof secretCreateSchema>
export type SecretUpdateOutput = z.output<typeof secretUpdateSchema>

export const changePasswordSchema = z.object({
  password: z.string().min(1, 'Enter the new password.').max(4096),
  comment: optionalString(500),
})
export const totpSchema = z.object({ seed: totpSeed })
export const restoreSchema = z.object({ comment: optionalString(500) })
