<template>
  <div class="flex flex-col gap-2 text-sm">
    <StateBlock :loading="isPending" :error="!!failed" :retry="true" @retry="refetch">
      <template v-if="transfer">
        <p v-if="isRecipient" class="text-slate-700 dark:text-slate-300">
          {{ t('portal.offerFrom', { user: transfer.offeredBy }) }}
        </p>
        <p v-else class="font-mono text-xs text-slate-600 dark:text-slate-400">
          {{ transfer.recipientUserId }}
        </p>
        <div class="mt-2 flex flex-wrap gap-2">
          <AppButton v-if="isRecipient" size="sm" variant="primary" :loading="busy === 'accept'" :disabled="busy !== null" @click="doAccept">
            {{ t('portal.accept') }}
          </AppButton>
          <AppButton v-if="isOwner" size="sm" variant="secondary" :disabled="busy !== null" @click="confirmCancel = true">
            {{ t('portal.cancel') }}
          </AppButton>
        </div>
      </template>
      <p v-else class="text-slate-500 dark:text-slate-400">{{ t('portal.noTransfer') }}</p>
    </StateBlock>
    <form v-if="isOwner && !transfer" class="flex flex-col gap-2" @submit.prevent="doOffer">
      <AppInput v-model="recipient" :label="t('portal.offerTo')" required :maxlength="256" />
      <p v-if="error" role="alert" class="flex items-start gap-2 text-red-700 dark:text-red-300">
        <AppIcon name="alert" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
        {{ error }}
      </p>
      <AppButton type="submit" size="sm" variant="secondary" :loading="busy === 'offer'" :disabled="busy !== null || !recipient.trim()">
        {{ t('portal.offerButton') }}
      </AppButton>
    </form>
    <ConfirmDialog :danger="false" :open="confirmCancel" :title="t('portal.cancel')" :body="t('portal.cancelConfirm')" :busy="busy !== null" @confirm="doCancel" @cancel="confirmCancel = false" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ApiError, api } from '../../api/client'
import { useUiStore } from '../../stores/ui'
import { useSession } from '../../queries/session'
import StateBlock from '../StateBlock.vue'
import ConfirmDialog from '../ConfirmDialog.vue'
import AppIcon from '../icons/AppIcon.vue'
import AppButton from '../ui/AppButton.vue'
import AppInput from '../ui/AppInput.vue'

const props = defineProps<{ publisherId: string; role: string }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const ui = useUiStore()
const client = useQueryClient()
const session = useSession()
const isOwner = computed(() => props.role === 'owner')

const { data, isPending, error: loadError, refetch } = useQuery({
  queryKey: ['portal', 'transfer', props.publisherId],
  queryFn: async () => {
    try {
      return await api.currentTransfer(props.publisherId)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },
  retry: false,
})
const transfer = computed(() => data.value ?? null)
const failed = computed(() => loadError.value != null && !(loadError.value instanceof ApiError && loadError.value.status === 404))
const isRecipient = computed(() => transfer.value != null && transfer.value.recipientUserId === session.data.value?.id)

const recipient = ref('')
const busy = ref<string | null>(null)
const error = ref('')
const confirmCancel = ref(false)

function key(): string[] {
  return ['portal', 'transfer', props.publisherId]
}

async function refresh() {
  await client.invalidateQueries({ queryKey: key() })
  emit('changed')
}

async function doOffer() {
  if (busy.value || !recipient.value.trim()) return
  busy.value = 'offer'
  error.value = ''
  try {
    await api.offerTransfer(props.publisherId, recipient.value.trim())
    recipient.value = ''
    ui.toast(t('portal.offered'), 'ok')
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError && e.status === 401 ? t('errors.expired') : t('errors.actionFailed')
  } finally {
    busy.value = null
  }
}

async function doAccept() {
  if (busy.value || !transfer.value) return
  busy.value = 'accept'
  error.value = ''
  try {
    await api.acceptTransfer(props.publisherId, transfer.value.id)
    ui.toast(t('portal.accepted'), 'ok')
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError && e.status === 401 ? t('errors.expired') : t('errors.actionFailed')
  } finally {
    busy.value = null
  }
}

async function doCancel() {
  if (busy.value) return
  busy.value = 'cancel'
  error.value = ''
  try {
    await api.cancelTransfer(props.publisherId)
    confirmCancel.value = false
    ui.toast(t('portal.cancelled'), 'ok')
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError && e.status === 401 ? t('errors.expired') : t('errors.actionFailed')
  } finally {
    busy.value = null
  }
}
</script>
