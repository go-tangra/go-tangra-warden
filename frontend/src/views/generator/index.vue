<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';

import { Page } from 'shell/vben/common-ui';
import { LucideCopy, LucideRefreshCw } from 'shell/vben/icons';
import { $t } from 'shell/locales';

import {
  Button,
  Card,
  Checkbox,
  InputNumber,
  notification,
  Progress,
  Slider,
  Tag,
} from 'ant-design-vue';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?';
const AMBIGUOUS = 'il1Lo0O';

const MIN_LENGTH = 4;
const MAX_LENGTH = 128;

interface GeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

const options = reactive<GeneratorOptions>({
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeAmbiguous: false,
});

const password = ref('');

/**
 * Returns a uniformly distributed integer in [0, max) using the Web Crypto
 * API. Rejection sampling removes the modulo bias of a naive `value % max`.
 */
function secureRandomInt(max: number): number {
  const range = 2 ** 32;
  const limit = range - (range % max);
  const buffer = new Uint32Array(1);
  let value: number;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0]!;
  } while (value >= limit);
  return value % max;
}

function filterAmbiguous(set: string): string {
  if (!options.excludeAmbiguous) return set;
  return [...set].filter((char) => !AMBIGUOUS.includes(char)).join('');
}

function activeSets(): string[] {
  const sets: string[] = [];
  if (options.lowercase) sets.push(filterAmbiguous(LOWERCASE));
  if (options.uppercase) sets.push(filterAmbiguous(UPPERCASE));
  if (options.numbers) sets.push(filterAmbiguous(NUMBERS));
  if (options.symbols) sets.push(filterAmbiguous(SYMBOLS));
  return sets.filter((set) => set.length > 0);
}

/** Fisher-Yates shuffle using cryptographically secure randomness. */
function shuffle(chars: string[]): string[] {
  const result = [...chars];
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = secureRandomInt(i + 1);
    [result[i], result[j]] = [result[j]!, result[i]!];
  }
  return result;
}

function pickFrom(set: string): string {
  return set.charAt(secureRandomInt(set.length));
}

function generate(): void {
  const sets = activeSets();
  if (sets.length === 0) {
    password.value = '';
    return;
  }

  const pool = sets.join('');
  const chars: string[] = [];

  // Guarantee at least one character from each selected set when length allows.
  if (options.length >= sets.length) {
    sets.forEach((set) => chars.push(pickFrom(set)));
  }

  while (chars.length < options.length) {
    chars.push(pickFrom(pool));
  }

  password.value = shuffle(chars).join('');
}

const poolSize = computed(() =>
  activeSets().reduce((total, set) => total + set.length, 0),
);

/** Shannon entropy in bits: length * log2(poolSize). */
const entropyBits = computed(() => {
  if (poolSize.value === 0 || password.value.length === 0) return 0;
  return Math.round(password.value.length * Math.log2(poolSize.value));
});

const strength = computed(() => {
  const bits = entropyBits.value;
  if (bits < 40) {
    return { label: $t('warden.page.generator.weak'), color: '#ff4d4f', percent: 25 };
  }
  if (bits < 60) {
    return { label: $t('warden.page.generator.fair'), color: '#faad14', percent: 50 };
  }
  if (bits < 80) {
    return { label: $t('warden.page.generator.strong'), color: '#52c41a', percent: 75 };
  }
  return { label: $t('warden.page.generator.veryStrong'), color: '#237804', percent: 100 };
});

const noSetSelected = computed(() => activeSets().length === 0);

async function handleCopy(): Promise<void> {
  if (!password.value) return;
  try {
    await navigator.clipboard.writeText(password.value);
    notification.success({ message: $t('warden.page.generator.copied') });
  } catch (error: unknown) {
    console.error('Failed to copy password:', error);
    notification.error({ message: $t('warden.page.generator.copyFailed') });
  }
}

onMounted(() => generate());
</script>

<template>
  <Page auto-content-height>
    <Card :title="$t('warden.page.generator.title')" class="mx-auto max-w-2xl">
      <div class="flex flex-col gap-6">
        <!-- Generated password output -->
        <div class="flex items-center gap-2">
          <div
            class="flex-1 break-all rounded-md border border-solid border-gray-200 bg-gray-50 px-4 py-3 font-mono text-lg dark:border-gray-700 dark:bg-gray-800"
          >
            <span v-if="password">{{ password }}</span>
            <span v-else class="text-gray-400">
              {{ $t('warden.page.generator.selectAtLeastOne') }}
            </span>
          </div>
          <Button
            type="text"
            :title="$t('warden.page.generator.regenerate')"
            :disabled="noSetSelected"
            @click="generate"
          >
            <component :is="LucideRefreshCw" class="size-5" />
          </Button>
          <Button
            type="text"
            :title="$t('warden.page.generator.copy')"
            :disabled="!password"
            @click="handleCopy"
          >
            <component :is="LucideCopy" class="size-5" />
          </Button>
        </div>

        <!-- Strength indicator -->
        <div v-if="password" class="flex items-center gap-3">
          <Progress
            :percent="strength.percent"
            :stroke-color="strength.color"
            :show-info="false"
            class="flex-1"
          />
          <Tag :color="strength.color">{{ strength.label }}</Tag>
          <span class="whitespace-nowrap text-sm text-gray-500">
            {{ entropyBits }} {{ $t('warden.page.generator.bits') }}
          </span>
        </div>

        <!-- Length control -->
        <div>
          <div class="mb-2 flex items-center justify-between">
            <span class="font-medium">{{ $t('warden.page.generator.length') }}</span>
            <InputNumber
              v-model:value="options.length"
              :min="MIN_LENGTH"
              :max="MAX_LENGTH"
              @change="generate"
            />
          </div>
          <Slider
            v-model:value="options.length"
            :min="MIN_LENGTH"
            :max="MAX_LENGTH"
            @change="generate"
          />
        </div>

        <!-- Character set options -->
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Checkbox v-model:checked="options.uppercase" @change="generate">
            {{ $t('warden.page.generator.uppercase') }} (A-Z)
          </Checkbox>
          <Checkbox v-model:checked="options.lowercase" @change="generate">
            {{ $t('warden.page.generator.lowercase') }} (a-z)
          </Checkbox>
          <Checkbox v-model:checked="options.numbers" @change="generate">
            {{ $t('warden.page.generator.numbers') }} (0-9)
          </Checkbox>
          <Checkbox v-model:checked="options.symbols" @change="generate">
            {{ $t('warden.page.generator.symbols') }} (!@#$...)
          </Checkbox>
          <Checkbox v-model:checked="options.excludeAmbiguous" @change="generate">
            {{ $t('warden.page.generator.excludeAmbiguous') }} (il1Lo0O)
          </Checkbox>
        </div>
      </div>
    </Card>
  </Page>
</template>
