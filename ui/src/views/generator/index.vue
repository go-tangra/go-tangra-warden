<script setup lang="ts">
import { computed, ref } from 'vue'
import { describe } from '@/api/client'
import { generateLocal, useOps, type GeneratorOptions } from '@/stores/ops'

const ops = useOps()
const options = ref<GeneratorOptions>({ length: 20, lower: true, upper: true, digits: true, symbols: true })
const password = ref('')
const source = ref<'server' | 'local'>('server')
const error = ref('')
const copied = ref(false)
const valid = computed(() => options.value.length >= 8 && options.value.length <= 128 && (options.value.lower || options.value.upper || options.value.digits || options.value.symbols))

async function generate(): Promise<void> {
  error.value = ''
  copied.value = false
  if (!valid.value) {
    error.value = 'Pick a length between 8 and 128 and at least one character class.'
    return
  }
  try {
    if (source.value === 'server') password.value = await ops.generate(options.value)
    else password.value = generateLocal(options.value)
  } catch (e) {
    error.value = describe(e)
  }
}

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(password.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    error.value = 'Copy is not available in this browser.'
  }
}
</script>

<template>
  <v-container data-test="warden-generator" max-width="720">
    <h1 class="text-h5 mb-4">Password generator</h1>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3" data-test="generator-error">{{ error }}</v-alert>
    <v-card variant="outlined">
      <v-card-text>
        <v-slider v-model="options.length" label="Length" :min="8" :max="128" :step="1" thumb-label data-test="gen-length" />
        <div class="d-flex flex-wrap ga-4">
          <v-checkbox v-model="options.lower" label="Lowercase" hide-details data-test="gen-lower" />
          <v-checkbox v-model="options.upper" label="Uppercase" hide-details data-test="gen-upper" />
          <v-checkbox v-model="options.digits" label="Digits" hide-details data-test="gen-digits" />
          <v-checkbox v-model="options.symbols" label="Symbols" hide-details data-test="gen-symbols" />
        </div>
        <v-radio-group v-model="source" inline label="Source" class="mt-2" data-test="gen-source">
          <v-radio label="Service (audited as nothing; never logged)" value="server" data-test="gen-server" />
          <v-radio label="This browser" value="local" data-test="gen-local" />
        </v-radio-group>
        <div class="d-flex align-center ga-2">
          <v-text-field :model-value="password" readonly label="Password" hide-details density="compact" class="font-monospace" data-test="gen-output" />
          <v-btn color="primary" data-test="gen-go" @click="generate">Generate</v-btn>
          <v-btn variant="tonal" :disabled="!password" data-test="gen-copy" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</v-btn>
        </div>
      </v-card-text>
    </v-card>
  </v-container>
</template>
