<script setup lang="ts">
// The vault-specific part of the secret's edit drawer (the v3 layout), under
// the details form: change the password (a new version), then the one-time
// code — show and remove it, or set a seed. Writers only.
import { ref, watch } from 'vue'
import { UiAlert, UiButton, UiSecretField, UiForm, UiInput, UiSection, useConfirm } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { describe } from '@/api/client'
import type { Secret } from '@/api/types'
import { useSecrets } from '@/stores/secrets'
import { changePasswordSchema, totpSchema } from '@/schemas'
import TotpCode from '@/components/TotpCode.vue'

const props = defineProps<{ secret: Secret }>()
const emit = defineEmits<{ saved: [s: Secret] }>()
const secrets = useSecrets()
const confirm = useConfirm()
const error = ref('')

const passwordForm = useZodForm(changePasswordSchema, {
  initial: { password: '', comment: '' },
  onSubmit: (v) => secrets.changePassword(props.secret.id, v.password, v.comment ?? ''),
  onSuccess: async () => {
    passwordForm.reset({ password: '', comment: '' })
    emit('saved', await secrets.get(props.secret.id))
  },
})
const totpForm = useZodForm(totpSchema, {
  initial: { seed: '' },
  onSubmit: (v) => secrets.setTotp(props.secret.id, v.seed),
  onSuccess: async () => {
    totpForm.reset({ seed: '' })
    emit('saved', await secrets.get(props.secret.id))
  },
})
async function dropTotp(): Promise<void> {
  if (!(await confirm.ask({ title: 'Remove the one-time code?', danger: true, confirmLabel: 'Remove' }))) return
  error.value = ''
  try {
    await secrets.removeTotp(props.secret.id)
    emit('saved', await secrets.get(props.secret.id))
  } catch (e) {
    error.value = describe(e)
  }
}
watch(() => props.secret.id, () => {
  error.value = ''
  passwordForm.reset({ password: '', comment: '' })
  totpForm.reset({ seed: '' })
})
</script>

<template>
  <div class="mt-4 flex flex-col gap-4" data-test="secret-edit-sections">
    <UiAlert v-if="error" kind="error" data-test="drawer-error">{{ error }}</UiAlert>
    <UiSection title="Update password" :description="'Password (version ' + secret.current_version + '). Saving a new password creates a new version.'" data-test="password-section">
      <UiForm :form="passwordForm">
        <div class="flex flex-col gap-2">
          <UiSecretField v-bind="passwordForm.field('password')" label="New password" autocomplete="new-password" required data-test="new-password" />
          <UiInput v-bind="passwordForm.field('comment')" label="Comment" data-test="password-comment" />
          <div><UiButton type="submit" variant="soft" size="sm" :loading="passwordForm.submitting.value" data-test="change-password">Update password</UiButton></div>
        </div>
      </UiForm>
    </UiSection>
    <UiSection title="2FA / TOTP" data-test="totp-section">
      <div v-if="secret.has_totp" class="flex flex-wrap items-center gap-2">
        <TotpCode :secret-id="secret.id" @error="error = $event" />
        <UiButton variant="text" size="sm" color="error" data-test="totp-remove" @click="dropTotp">Remove</UiButton>
      </div>
      <UiForm v-else :form="totpForm">
        <div class="flex flex-wrap items-end gap-2">
          <UiSecretField v-bind="totpForm.field('seed')" label="TOTP seed" placeholder="otpauth:// URI or base32 seed" class="grow" data-test="totp-seed" />
          <UiButton type="submit" variant="soft" size="sm" :loading="totpForm.submitting.value" data-test="totp-save">Set TOTP</UiButton>
        </div>
      </UiForm>
    </UiSection>
  </div>
</template>
