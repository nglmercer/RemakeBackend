<template>
  <AppCard :label="t('releases.submitTitle')">
    <div class="flex flex-col gap-3">
      <AppSelect v-model="publisherId" :label="t('releases.selectPublisher')">
        <option value="" disabled>{{ t('releases.selectPublisher') }}</option>
        <option v-for="p in eligiblePublishers" :key="p.id" :value="p.id">{{ p.namespace }}</option>
      </AppSelect>
      <p v-if="publisherId" class="text-xs text-slate-500 dark:text-slate-400">{{ t('releases.selectPublisherHint') }}</p>

      <StateBlock :loading="keysPending" :error="!!keysError" :retry="true" @retry="refetchKeys">
        <AppSelect v-model="keyId" :label="t('releases.selectKey')">
          <option value="" disabled>{{ t('releases.selectKey') }}</option>
          <option v-for="k in approvedKeys" :key="k.id" :value="k.id">{{ k.keyId }}</option>
        </AppSelect>
      </StateBlock>
      <p v-if="publisherId && !keysPending" class="text-xs text-slate-500 dark:text-slate-400">{{ t('releases.selectKeyHint') }}</p>

      <label class="flex min-w-0 flex-col gap-1 text-sm">
        <span class="font-medium text-slate-700 dark:text-slate-300">{{ t('releases.selectFile') }}</span>
        <input
          type="file"
          accept=".plugin,application/octet-stream"
          class="text-sm text-slate-700 file:mr-3 file:rounded-md file:border file:border-slate-300 file:bg-white file:px-3 file:py-2 file:text-sm file:font-medium file:text-slate-700 hover:file:bg-slate-100 dark:text-slate-300 dark:file:border-slate-600 dark:file:bg-slate-800 dark:file:text-slate-200 dark:hover:file:bg-slate-700"
          @change="onFile"
        />
        <span class="text-xs text-slate-500 dark:text-slate-400">{{ t('releases.fileHint') }}</span>
      </label>
      <dl v-if="fileInfo" class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs">
        <dt class="font-sans text-slate-500 dark:text-slate-400">{{ t('releases.checksum') }}</dt>
        <dd class="break-all">{{ fileInfo.sha256 }}</dd>
        <dt class="font-sans text-slate-500 dark:text-slate-400">{{ t('releases.size') }}</dt>
        <dd class="tabular-nums">{{ fileInfo.size }}</dd>
      </dl>

      <AppInput v-model="pluginId" :label="t('releases.pluginId')" required :maxlength="256" />
      <p v-if="publisherId" class="text-xs text-slate-500 dark:text-slate-400">{{ t('releases.pluginIdHint', { namespace: namespaceOf(publisherId) }) }}</p>
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <AppInput v-model="version" :label="t('releases.version')" required :maxlength="128" />
        <AppInput v-model="target" :label="t('releases.target')" required :maxlength="128" />
      </div>
      <p class="text-xs text-slate-500 dark:text-slate-400">{{ t('releases.versionHint') }} {{ t('releases.targetHint') }}</p>

      <p v-if="error" role="alert" class="flex items-start gap-2 text-sm text-red-700 dark:text-red-300">
        <AppIcon name="alert" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
        {{ error }}
      </p>
      <p v-if="notice" role="status" class="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-300">
        <AppIcon name="checkCircle" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
        {{ notice }}
      </p>

      <div class="flex flex-wrap gap-2">
        <AppButton size="sm" variant="primary" :loading="phase !== 'idle' && phase !== 'done'" :disabled="!canStart || phase === 'done'" @click="run">
          {{ phase === 'done' ? t('releases.submitted') : t('releases.submit') }}
        </AppButton>
        <AppButton v-if="phase === 'done'" size="sm" variant="secondary" @click="reset">
          {{ t('states.retry') }}
        </AppButton>
      </div>
      <ol v-if="phase !== 'idle'" class="flex flex-col gap-1 text-xs text-slate-600 dark:text-slate-400">
        <li v-for="s in steps" :key="s.key" class="flex items-center gap-2">
          <AppIcon :name="s.done ? 'checkCircle' : s.active ? 'refresh' : 'clock'" :size="14" aria-hidden="true" />
          {{ s.label }}
        </li>
      </ol>
    </div>
  </AppCard>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useQuery } from '@tanstack/vue-query'
import { ApiError, api } from '../../api/client'
import { canPublish } from '../../api/types'
import type { MyPublisher } from '../../api/types'
import StateBlock from '../StateBlock.vue'
import AppIcon from '../icons/AppIcon.vue'
import AppButton from '../ui/AppButton.vue'
import AppCard from '../ui/AppCard.vue'
import AppInput from '../ui/AppInput.vue'
import AppSelect from '../ui/AppSelect.vue'

const props = defineProps<{ publishers: MyPublisher[] }>()
const emit = defineEmits<{ submitted: [] }>()

const { t } = useI18n()

const MAX_SIZE = 128 * 1024 * 1024
const eligiblePublishers = computed(() => props.publishers.filter((p) => p.status === 'approved' && canPublish(p.role)))

const publisherId = ref('')
const keyId = ref('')
const file = ref<File | null>(null)
const fileInfo = ref<{ sha256: string; size: number } | null>(null)
const pluginId = ref('')
const version = ref('')
const target = ref('any')
const phase = ref<'idle' | 'reserving' | 'uploading' | 'completing' | 'submitting' | 'done'>('idle')
const error = ref('')
const notice = ref('')

function namespaceOf(id: string): string {
  return props.publishers.find((p) => p.id === id)?.namespace ?? ''
}

const { data: keys, isPending: keysPending, error: keysError, refetch: refetchKeys } = useQuery({
  queryKey: ['portal', 'wizard-keys', publisherId],
  queryFn: () => api.publisherKeys(publisherId.value),
  enabled: computed(() => publisherId.value !== ''),
})
const approvedKeys = computed(() => (keys.value ?? []).filter((k) => k.status === 'approved'))
watch(publisherId, () => {
  keyId.value = ''
})

const canStart = computed(
  () => publisherId.value !== '' && keyId.value !== '' && file.value !== null && pluginId.value.trim() !== '' && version.value.trim() !== '' && target.value.trim() !== '',
)

const steps = computed(() => {
  const order = ['reserving', 'uploading', 'completing', 'submitting'] as const
  const labels: Record<string, string> = {
    reserving: t('releases.reserve'),
    uploading: t('releases.upload'),
    completing: t('releases.complete'),
    submitting: t('releases.submit'),
  }
  const activeIndex = phase.value === 'idle' || phase.value === 'done' ? order.length : order.indexOf(phase.value)
  return order.map((key, i) => ({ key, label: labels[key]!, done: i < activeIndex || phase.value === 'done', active: phase.value === key }))
})

function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  file.value = input.files?.[0] ?? null
  fileInfo.value = null
}

function validVersion(v: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(v)
  if (!m) return false
  for (const part of [m[1]!, m[2]!, m[3]!]) {
    if (part.length > 1 && part.startsWith('0')) return false
  }
  return true
}

function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
  return `portal-${Date.now()}-${Math.floor(Math.random() * 1e9)}`
}

async function hashFile(f: File): Promise<string> {
  const subtle = typeof crypto !== 'undefined' ? crypto.subtle : undefined
  if (!subtle) throw new Error('no-subtle')
  const digest = await subtle.digest('SHA-256', await f.arrayBuffer())
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function validateLocal(f: File): Promise<string> {
  if (f.size < 1 || f.size > MAX_SIZE) throw new Error('size')
  const head = new Uint8Array(await f.slice(0, 4).arrayBuffer())
  if (!(head[0] === 0x50 && head[1] === 0x4b && (head[2] === 0x03 || head[2] === 0x05 || head[2] === 0x07) && (head[3] === 0x04 || head[3] === 0x06 || head[3] === 0x08))) {
    throw new Error('magic')
  }
  return hashFile(f)
}

function failExpired(status: number): boolean {
  return status === 403 || status === 410 || status === 404
}

async function run() {
  if (!canStart.value || phase.value === 'done' || !file.value) {
    error.value = t('releases.invalidFile')
    return
  }
  error.value = ''
  notice.value = ''
  const namespace = namespaceOf(publisherId.value)
  if (!pluginId.value.startsWith(`${namespace}.`)) {
    error.value = t('releases.pluginIdMismatch', { namespace })
    return
  }
  if (!validVersion(version.value.trim())) {
    error.value = t('releases.versionInvalid')
    return
  }
  const currentFile = file.value
  // 1-2: file validation is local; the server revalidates everything.
  let sha256: string
  try {
    sha256 = await validateLocal(currentFile)
  } catch (e) {
    error.value =
      e instanceof Error && e.message === 'size'
        ? t('releases.tooLarge')
        : e instanceof Error && e.message === 'magic'
          ? t('releases.badMagic')
          : t('releases.noSha')
    return
  }
  fileInfo.value = { sha256, size: currentFile.size }
  // 3-6: reserve, upload, complete, submit. Each step is retried explicitly by
  // re-running; reservations are idempotent per key and expire in 5 minutes.
  try {
    phase.value = 'reserving'
    const reservation = await api.reserveUpload(publisherId.value, currentFile.size, sha256, newIdempotencyKey())
    notice.value = t('releases.reserved')
    phase.value = 'uploading'
    const put = await fetch(reservation.url, {
      method: 'PUT',
      headers: reservation.headers,
      body: currentFile,
      credentials: 'omit',
    })
    if (!put.ok) {
      error.value = failExpired(put.status) ? t('releases.expiredUpload') : t('releases.uploadFailed')
      phase.value = 'idle'
      return
    }
    phase.value = 'completing'
    const completed = await api.completeUpload(reservation.id)
    if (completed.status !== 'quarantined') {
      error.value = t('releases.uploadFailed')
      phase.value = 'idle'
      return
    }
    notice.value = t('releases.uploaded')
    phase.value = 'submitting'
    const release = await api.submitRelease({
      uploadId: reservation.id,
      publisherKeyId: keyId.value,
      pluginId: pluginId.value.trim(),
      version: version.value.trim(),
      target: target.value.trim(),
    })
    phase.value = 'done'
    notice.value = `${t('releases.submitted')} (${release.id})`
    emit('submitted')
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 401) error.value = t('errors.expired')
      else if (e.status === 403 || e.status === 410) error.value = t('releases.expiredUpload')
      else if (e.status === 404 || e.status === 409) error.value = t('releases.submitFailed')
      else error.value = t('errors.actionFailed')
    } else {
      error.value = t('errors.actionFailed')
    }
    phase.value = 'idle'
  }
}

function reset() {
  phase.value = 'idle'
  error.value = ''
  notice.value = ''
  file.value = null
  fileInfo.value = null
  pluginId.value = ''
  version.value = ''
  target.value = 'any'
  keyId.value = ''
}

defineExpose({ phase: computed(() => phase.value), error: computed(() => error.value) })
</script>
