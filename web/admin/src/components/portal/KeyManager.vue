<template>
  <div class="flex flex-col gap-2">
    <StateBlock :loading="isPending" :error="!!error" :retry="true" @retry="refetch">
      <ul v-if="keys.length > 0" class="divide-y divide-slate-100 rounded-md border border-slate-200 text-sm dark:divide-slate-800 dark:border-slate-700">
        <li v-for="k in keys" :key="k.id" class="flex flex-wrap items-center gap-2 px-3 py-1.5">
          <span class="min-w-0 flex-1 truncate font-mono text-xs" :title="k.fingerprint">{{ k.keyId }}</span>
          <span class="hidden font-mono text-[11px] text-slate-500 lg:inline dark:text-slate-400">{{ short(k.fingerprint) }}</span>
          <AppBadge :tone="k.status === 'approved' ? 'success' : k.status === 'pending' ? 'warn' : 'neutral'">
            {{ keyStatus(k.status) }}
          </AppBadge>
          <AppButton
            v-if="canManage && k.status !== 'revoked'"
            size="sm"
            variant="danger"
            :disabled="busy !== null"
            @click="askRevoke(k.id)"
          >
            {{ t('portal.revoke') }}
          </AppButton>
        </li>
      </ul>
      <EmptyState v-else :title="t('portal.noKeys')" icon="key" />
    </StateBlock>
    <div v-if="canManage" class="flex flex-col gap-2">
      <AppButton size="sm" variant="ghost" icon="key" @click="openEnroll">
        {{ t('portal.enrollKey') }}
      </AppButton>
      <div v-if="enroll.active" class="flex flex-col gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm dark:border-slate-700 dark:bg-slate-800">
        <p class="text-slate-600 dark:text-slate-400">{{ t('portal.enrollIntro') }}</p>
        <template v-if="enroll.challenge">
          <p class="text-slate-600 dark:text-slate-400">{{ t('portal.challengeReady') }}</p>
          <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs">
            <dt class="font-sans text-slate-500 dark:text-slate-400">{{ t('portal.challengeId') }}</dt>
            <dd class="break-all">{{ enroll.challenge.challengeId }}</dd>
            <dt class="font-sans text-slate-500 dark:text-slate-400">{{ t('portal.nonce') }}</dt>
            <dd class="break-all">{{ enroll.challenge.nonce }}</dd>
          </dl>
          <p class="font-mono text-xs text-slate-500 dark:text-slate-400">{{ t('portal.cliHint') }}</p>
          <form class="flex flex-col gap-2" @submit.prevent="submitKey">
            <AppInput v-model="enroll.keyId" :label="t('portal.keyId')" required />
            <AppInput v-model="enroll.publicKey" :label="t('portal.publicKey')" required />
            <AppInput v-model="enroll.signature" :label="t('portal.signature')" required />
            <p v-if="enroll.error" role="alert" class="flex items-start gap-2 text-red-700 dark:text-red-300">
              <AppIcon name="alert" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
              {{ enroll.error }}
            </p>
            <AppButton type="submit" size="sm" variant="primary" :loading="enroll.busy" :disabled="enroll.busy">
              {{ t('portal.submitKey') }}
            </AppButton>
          </form>
        </template>
      </div>
    </div>
    <p v-else class="text-xs text-slate-500 dark:text-slate-400">{{ t('portal.approvalsNote') }}</p>
    <ConfirmDialog :danger="true" :open="revokeId !== null" :title="t('portal.revoke')" :body="t('portal.revokeConfirm')" :busy="busy !== null" @confirm="doRevoke" @cancel="revokeId = null" />
    <StepUpDialog
      :open="dialogOpen"
      action="publisher.key.enroll"
      :action-label="t('portal.enrollKey')"
      :publisher-id="publisherId"
      :return-to="dialogReturnTo"
      @granted="onGranted"
      @cancelled="dialogOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ApiError, api } from '../../api/client'
import { parseStepUpQuery } from '../../api/auth'
import { useUiStore } from '../../stores/ui'
import { canManageKeys } from '../../api/types'
import type { KeyChallenge } from '../../api/types'
import StateBlock from '../StateBlock.vue'
import StepUpDialog from '../StepUpDialog.vue'
import ConfirmDialog from '../ConfirmDialog.vue'
import AppIcon from '../icons/AppIcon.vue'
import AppBadge from '../ui/AppBadge.vue'
import AppButton from '../ui/AppButton.vue'
import AppInput from '../ui/AppInput.vue'
import EmptyState from '../ui/EmptyState.vue'

const props = defineProps<{ publisherId: string; role: string; status: string }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const ui = useUiStore()
const route = useRoute()
const router = useRouter()
const client = useQueryClient()
const canManage = computed(() => props.status === 'approved' && canManageKeys(props.role))

const { data, isPending, error, refetch } = useQuery({
  queryKey: ['portal', 'keys', props.publisherId],
  queryFn: () => api.publisherKeys(props.publisherId),
})
const keys = computed(() => data.value ?? [])

function short(fingerprint: string): string {
  return fingerprint.length > 16 ? `${fingerprint.slice(0, 8)}…${fingerprint.slice(-6)}` : fingerprint
}

function keyStatus(status: string): string {
  if (status === 'pending') return t('portal.keyPending')
  if (status === 'approved') return t('portal.keyApproved')
  if (status === 'revoked') return t('portal.keyRevoked')
  return status
}

// Single active enrollment: the dialog mints a session-bound grant, the
// challenge validates it, and registration spends it. Everything lives in
// component state; nothing touches web storage.
const enroll = reactive({
  active: false,
  grantId: null as string | null,
  challenge: null as KeyChallenge | null,
  keyId: '',
  publicKey: '',
  signature: '',
  busy: false,
  error: '',
})
const dialogOpen = ref(false)
const dialogReturnTo = ref(`/app/portal?stepUp=enroll&publisher=${props.publisherId}`)
const busy = ref<string | null>(null)
const revokeId = ref<string | null>(null)

function openEnroll() {
  enroll.active = true
  enroll.grantId = null
  enroll.challenge = null
  enroll.keyId = ''
  enroll.publicKey = ''
  enroll.signature = ''
  enroll.busy = false
  enroll.error = ''
  dialogReturnTo.value = `/app/portal?stepUp=enroll&publisher=${props.publisherId}`
  dialogOpen.value = true
}

function stepUpFailed(status: number, code?: string): string {
  if (status === 401) {
    void router.replace({ path: '/login', query: { next: '/app/portal' } })
    return t('errors.expired')
  }
  if (status === 403 && code === 'step_up_expired') return t('stepUp.expired')
  return t('errors.actionFailed')
}

async function fetchChallenge(grantId: string) {
  enroll.busy = true
  enroll.error = ''
  try {
    enroll.challenge = await api.publisherKeyChallenge(props.publisherId, grantId)
  } catch (e) {
    if (e instanceof ApiError) {
      enroll.error = stepUpFailed(e.status, e.code)
      if (e.status === 403 && e.code === 'step_up_expired') {
        dialogReturnTo.value = `/app/portal?stepUp=enroll&publisher=${props.publisherId}`
        dialogOpen.value = true
      }
    } else {
      enroll.error = t('errors.actionFailed')
    }
  } finally {
    enroll.busy = false
  }
}

async function onGranted(grantId: string) {
  dialogOpen.value = false
  enroll.grantId = grantId
  await fetchChallenge(grantId)
}

async function submitKey() {
  if (!enroll.grantId || !enroll.challenge || enroll.busy) return
  enroll.busy = true
  enroll.error = ''
  try {
    await api.requestPublisherKey(
      props.publisherId,
      {
        challengeId: enroll.challenge.challengeId,
        keyId: enroll.keyId.trim(),
        publicKey: enroll.publicKey.trim(),
        signature: enroll.signature.trim(),
      },
      enroll.grantId,
    )
    ui.toast(t('portal.enrolled'), 'ok')
    enroll.active = false
    enroll.grantId = null
    enroll.challenge = null
    await client.invalidateQueries({ queryKey: ['portal', 'keys', props.publisherId] })
    emit('changed')
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
      enroll.error = stepUpFailed(e.status, e.code)
    } else {
      enroll.error = t('errors.actionFailed')
    }
  } finally {
    enroll.busy = false
  }
}

function askRevoke(id: string) {
  revokeId.value = id
}

async function doRevoke() {
  const id = revokeId.value
  if (!id || busy.value) return
  busy.value = id
  try {
    await api.revokePublisherKey(props.publisherId, id)
    revokeId.value = null
    ui.toast(t('portal.revoked'), 'ok')
    await client.invalidateQueries({ queryKey: ['portal', 'keys', props.publisherId] })
    emit('changed')
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      void router.replace({ path: '/login', query: { next: '/app/portal' } })
      ui.toast(t('errors.expired'), 'err')
    } else {
      ui.toast(t('errors.actionFailed'), 'err')
    }
  } finally {
    busy.value = null
  }
}

// Google round-trip: the callback redirects here with the one-time grant (or
// an opaque error) in the query. The grant is consumed into memory and the
// query is stripped immediately.
const resumed = ref(false)
async function resumeFromQuery() {
  if (resumed.value) return
  const pending = route.query['stepUp'] === 'enroll' ? route.query['publisher'] : undefined
  if (pending !== props.publisherId || !canManage.value) return
  resumed.value = true
  const outcome = parseStepUpQuery(route.query as Record<string, unknown>)
  const clean = { ...route.query }
  delete clean['stepUp']
  delete clean['publisher']
  delete clean['stepUpGrant']
  delete clean['stepUpError']
  await router.replace({ path: route.path, query: clean })
  if (outcome && 'grantId' in outcome) {
    enroll.active = true
    dialogReturnTo.value = `/app/portal?stepUp=enroll&publisher=${props.publisherId}`
    await onGranted(outcome.grantId)
  } else if (outcome && 'error' in outcome) {
    ui.toast(t('stepUp.failed'), 'err')
  }
}

onMounted(() => {
  void resumeFromQuery()
})
watch(canManage, () => {
  void resumeFromQuery()
})
</script>
