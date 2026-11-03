<template>
  <div class="flex flex-col gap-4">
    <PageHeader :title="t('portal.title')" :description="t('portal.releases')" icon="portal" />

    <AppCard :label="t('portal.requestTitle')">
      <form class="flex flex-col gap-2" @submit.prevent="requestNamespace">
        <AppInput v-model="namespace" :label="t('portal.namespace')" required :maxlength="63" />
        <p class="text-xs text-slate-500 dark:text-slate-400">{{ t('portal.namespaceHint') }}</p>
        <p v-if="requestError" role="alert" class="flex items-start gap-2 text-sm text-red-700 dark:text-red-300">
          <AppIcon name="alert" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
          {{ requestError }}
        </p>
        <div>
          <AppButton type="submit" size="sm" variant="primary" :loading="requesting" :disabled="requesting || !validNamespace">
            {{ t('portal.requestButton') }}
          </AppButton>
        </div>
      </form>
    </AppCard>

    <StateBlock :loading="isPending" :error="!!error" :retry="true" @retry="refetch">
      <ul class="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <li v-for="p in publishers" :key="p.id">
          <AppCard :label="p.namespace">
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span class="break-all font-mono text-sm font-semibold">{{ p.namespace }}</span>
              <AppBadge :tone="p.status === 'approved' ? 'success' : p.status === 'pending' ? 'warn' : 'neutral'">
                {{ statusLabel(p.status) }}
              </AppBadge>
              <AppBadge tone="info" icon="account">{{ p.role }}</AppBadge>
            </div>
            <div class="mt-3 flex flex-col gap-2">
              <AppButton size="sm" variant="ghost" icon="portal" @click="toggle(p.id, 'members')">
                {{ t('portal.members') }}
              </AppButton>
              <MemberManager v-if="open[p.id] === 'members'" :publisher-id="p.id" :role="p.role" @changed="refetch" />

              <AppButton size="sm" variant="ghost" icon="key" @click="toggle(p.id, 'keys')">
                {{ t('portal.keys') }}
              </AppButton>
              <KeyManager v-if="open[p.id] === 'keys'" :publisher-id="p.id" :role="p.role" :status="p.status" @changed="refetch" />

              <AppButton size="sm" variant="ghost" icon="arrowRight" @click="toggle(p.id, 'transfer')">
                {{ t('portal.transfer') }}
              </AppButton>
              <TransferPanel v-if="open[p.id] === 'transfer'" :publisher-id="p.id" :role="p.role" @changed="refetch" />

              <AppButton size="sm" variant="ghost" icon="package" @click="toggle(p.id, 'releases')">
                {{ t('releases.title') }}
              </AppButton>
              <ReleaseList v-if="open[p.id] === 'releases'" :publisher-id="p.id" :refresh-key="releaseRefresh" />
            </div>
            <p class="mt-3 text-xs text-slate-500 dark:text-slate-400">{{ t('portal.notOwnerAdmin') }}</p>
          </AppCard>
        </li>
      </ul>
      <EmptyState v-if="publishers.length === 0" :title="t('states.empty')" icon="portal" />
    </StateBlock>

    <ReleaseWizard v-if="publishers.length > 0" :publishers="publishers" @submitted="releaseRefresh++" />
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useQuery } from '@tanstack/vue-query'
import { ApiError, api } from '../api/client'
import { useUiStore } from '../stores/ui'
import StateBlock from '../components/StateBlock.vue'
import AppIcon from '../components/icons/AppIcon.vue'
import AppBadge from '../components/ui/AppBadge.vue'
import AppButton from '../components/ui/AppButton.vue'
import AppCard from '../components/ui/AppCard.vue'
import AppInput from '../components/ui/AppInput.vue'
import EmptyState from '../components/ui/EmptyState.vue'
import PageHeader from '../components/ui/PageHeader.vue'
import MemberManager from '../components/portal/MemberManager.vue'
import KeyManager from '../components/portal/KeyManager.vue'
import TransferPanel from '../components/portal/TransferPanel.vue'
import ReleaseList from '../components/portal/ReleaseList.vue'
import ReleaseWizard from '../components/portal/ReleaseWizard.vue'

const { t } = useI18n()
const ui = useUiStore()
const route = useRoute()

const { data, isPending, error, refetch } = useQuery({
  queryKey: ['portal', 'publishers'],
  queryFn: api.myPublishers,
})
const publishers = computed(() => data.value ?? [])
const open = reactive<Record<string, string>>({})
const releaseRefresh = ref(0)

// Google round-trip lands back here with ?stepUp=enroll&publisher=ID: open the
// keys section so KeyManager can consume the one-time grant into memory.
watch(publishers, (list) => {
  const pending = route.query['stepUp'] === 'enroll' ? route.query['publisher'] : undefined
  if (typeof pending === 'string' && list.some((p) => p.id === pending) && !open[pending]) {
    open[pending] = 'keys'
  }
}, { immediate: true })

function toggle(id: string, section: string) {
  if (open[id] === section) delete open[id]
  else open[id] = section
}

function statusLabel(status: string): string {
  if (status === 'pending') return t('portal.statusPending')
  if (status === 'approved') return t('portal.statusApproved')
  if (status === 'suspended') return t('portal.statusSuspended')
  return status
}

const namespace = ref('')
const requesting = ref(false)
const requestError = ref('')
const validNamespace = computed(() => /^[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(namespace.value.trim()))

async function requestNamespace() {
  if (requesting.value || !validNamespace.value) return
  requesting.value = true
  requestError.value = ''
  try {
    await api.createPublisher(namespace.value.trim())
    namespace.value = ''
    ui.toast(t('portal.requested'), 'ok')
    await refetch()
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 401) requestError.value = t('errors.expired')
      else if (e.status === 409) requestError.value = t('errors.actionFailed')
      else if (e.status === 429) requestError.value = t('stepUp.rateLimited')
      else requestError.value = t('errors.actionFailed')
    } else {
      requestError.value = t('errors.actionFailed')
    }
  } finally {
    requesting.value = false
  }
}
</script>
