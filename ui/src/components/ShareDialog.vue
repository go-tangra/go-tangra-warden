<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { describe } from '@/api/client'
import { useShares } from '@/stores/shares'

const props = defineProps<{ modelValue: boolean; secretId: string; secretName: string }>()
const emit = defineEmits<{ 'update:modelValue': [v: boolean]; created: [] }>()
const shares = useShares()

const email = ref('')
const message = ref('')
const validity = ref<'1h' | '1d' | '7d'>('1h')
const opens = ref(1)
const cidr = ref('')
const error = ref('')
const busy = ref(false)
const done = ref(false)

const emailError = computed(() => (/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email.value.trim()) ? '' : 'Enter the recipient email'))
const cidrError = computed(() => (!cidr.value || /^[0-9a-fA-F.:]+\/\d{1,3}$/.test(cidr.value.trim()) ? '' : 'Use CIDR notation, e.g. 203.0.113.0/24'))
const seconds: Record<typeof validity.value, number> = { '1h': 3600, '1d': 86400, '7d': 604800 }

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    email.value = ''
    message.value = ''
    validity.value = '1h'
    opens.value = 1
    cidr.value = ''
    error.value = ''
    done.value = false
  },
)

async function submit(): Promise<void> {
  if (emailError.value || cidrError.value) return
  busy.value = true
  error.value = ''
  try {
    await shares.create(props.secretId, { recipient_email: email.value.trim(), message: message.value || undefined, validity_seconds: seconds[validity.value], max_opens: opens.value, cidr: cidr.value.trim() || undefined })
    done.value = true
    emit('created')
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-dialog :model-value="modelValue" max-width="560" @update:model-value="emit('update:modelValue', $event)">
    <v-card data-test="share-dialog">
      <v-card-title>Share “{{ secretName }}” by email</v-card-title>
      <v-card-text>
        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3" data-test="share-error">{{ error }}</v-alert>
        <template v-if="done">
          <v-alert type="success" variant="tonal" data-test="share-done">A link was mailed to {{ email }}. It reveals the current password and is never shown here.</v-alert>
        </template>
        <v-form v-else @submit.prevent="submit">
          <v-text-field v-model="email" label="Recipient email" type="email" :error-messages="email ? emailError : ''" data-test="share-email" />
          <v-textarea v-model="message" label="Message (optional)" rows="2" counter="1000" maxlength="1000" data-test="share-message" />
          <v-select v-model="validity" :items="[{ title: '1 hour', value: '1h' }, { title: '1 day', value: '1d' }, { title: '7 days', value: '7d' }]" label="Valid for" data-test="share-validity" />
          <v-slider v-model="opens" label="Reveals allowed" :min="1" :max="10" :step="1" thumb-label data-test="share-opens" />
          <v-text-field v-model="cidr" label="Allowed network (CIDR, optional)" :error-messages="cidrError" data-test="share-cidr" />
        </v-form>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" data-test="share-close" @click="emit('update:modelValue', false)">{{ done ? 'Close' : 'Cancel' }}</v-btn>
        <v-btn v-if="!done" color="primary" :disabled="!!emailError || !!cidrError" :loading="busy" data-test="share-send" @click="submit">Send link</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
