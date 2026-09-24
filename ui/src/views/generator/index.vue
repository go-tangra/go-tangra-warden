<script setup lang="ts">
import { ref } from 'vue'
import { UiPage, UiCard, UiForm, UiNumberInput, UiCheckbox, UiSelect, UiButton, UiSecretField, UiCopyButton, type SelectOption } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { generateLocal, useOps } from '@/stores/ops'
import { generatorSchema } from '@/schemas'

const ops = useOps()
const password = ref('')
const sourceOptions: SelectOption[] = [{ title: 'Service (never logged)', value: 'server' }, { title: 'This browser', value: 'local' }]
const form = useZodForm(generatorSchema, {
  initial: { length: 20, lower: true, upper: true, digits: true, symbols: true, source: 'server' },
  onSubmit: async (o) => {
    password.value = o.source === 'server' ? await ops.generate(o) : generateLocal(o)
  },
})
</script>

<template>
  <UiPage title="Password generator" data-test="warden-generator">
    <UiCard class="max-w-2xl">
      <UiForm :form="form">
        <div class="flex flex-col gap-3">
          <UiNumberInput v-bind="form.field('length')" label="Length" :min="8" :max="128" required data-test="gen-length" />
          <div class="flex flex-wrap gap-4">
            <UiCheckbox v-bind="form.field('lower')" label="Lowercase" data-test="gen-lower" />
            <UiCheckbox v-bind="form.field('upper')" label="Uppercase" data-test="gen-upper" />
            <UiCheckbox v-bind="form.field('digits')" label="Digits" data-test="gen-digits" />
            <UiCheckbox v-bind="form.field('symbols')" label="Symbols" data-test="gen-symbols" />
          </div>
          <UiSelect v-bind="form.field('source')" label="Source" :options="sourceOptions" :clearable="false" data-test="gen-source" />
          <div class="flex flex-wrap items-end gap-2">
            <UiSecretField id="gen-output" :model-value="password" label="Password" readonly class="grow" data-test="gen-output" />
            <UiButton type="submit" :loading="form.submitting.value" data-test="gen-go">Generate</UiButton>
            <UiCopyButton v-if="password" :value="password" label="Copy password" data-test="gen-copy" />
          </div>
        </div>
      </UiForm>
    </UiCard>
  </UiPage>
</template>
