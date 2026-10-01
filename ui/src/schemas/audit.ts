import { z } from 'zod'
import { isoDate } from '@go-tangra/ui/forms'

/** The server refuses an audit window wider than this (to defaults to now). */
export const MAX_AUDIT_SPAN_DAYS = 90
export const AUDIT_SPAN_MESSAGE = `The date range is limited to ${MAX_AUDIT_SPAN_DAYS} days.`

export const auditFilterSchema = z
  .object({
    event_type: z.string().trim().max(100).optional(),
    actor_id: z.string().trim().max(200).optional(),
    from: isoDate,
    to: isoDate,
  })
  .superRefine((f, ctx) => {
    if (!f.from) return
    const from = Date.parse(f.from)
    const to = f.to ? Date.parse(f.to) : Date.now()
    if (to < from) ctx.addIssue({ code: 'custom', path: ['to'], message: 'Must not be before the start date.' })
    else if (to - from > MAX_AUDIT_SPAN_DAYS * 24 * 3600 * 1000) ctx.addIssue({ code: 'custom', path: ['from'], message: AUDIT_SPAN_MESSAGE })
  })
export const searchSchema = z.object({ q: z.string().trim().max(200) })
