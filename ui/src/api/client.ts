// The warden API through the gateway: the kit client bound to this module's base.
import { createApi, ApiError, csrfToken, describe, type Method, type RequestOptions } from '@freya/ui/api'
import { registerReasons } from '@freya/ui/forms'
import type { paths } from './schema.d'

export { ApiError, csrfToken, describe }
export type { Method, RequestOptions }

// Path names are checked against the OpenAPI contract at compile time.
export type ApiPath = keyof paths
export const BASE = '/api/warden/v1'

// Vault-specific refusal reasons (closed vocabulary, api/openapi/warden.yaml).
registerReasons({
  conflict: 'A sibling with that name already exists, or the move is not possible.',
  vault_unavailable: 'The vault is unavailable; metadata stays readable, material does not.',
  region_unavailable: 'That region is not available for sharing.',
  share_consumed: 'This link has already been used.',
  share_expired: 'This link has expired.',
})

export const api = createApi({ base: BASE })
export const upload = api.upload
export const fileUrl = api.fileUrl
