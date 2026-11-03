<template>
  <div class="flex flex-col gap-2">
    <div class="flex items-center justify-between gap-2">
      <h4 class="text-sm font-semibold text-slate-900 dark:text-white">{{ t('releases.title') }}</h4>
      <AppButton size="sm" variant="ghost" icon="refresh" icon-only :label="t('states.refresh')" :title="t('states.refresh')" @click="refetch" />
    </div>
    <StateBlock :loading="isPending" :error="!!error" :retry="true" @retry="refetch">
      <ul v-if="items.length > 0" class="flex flex-col gap-2">
        <li v-for="r in items" :key="r.id">
          <AppCard :label="`${r.pluginId} ${r.version}`">
            <button type="button" class="flex w-full flex-wrap items-center gap-x-3 gap-y-1 text-left" @click="toggle(r.id)">
              <span class="break-all font-mono text-sm font-semibold">{{ r.pluginId }} {{ r.version }}</span>
              <AppBadge tone="info">{{ r.target }}</AppBadge>
              <AppBadge :tone="r.status === 'review_approved' ? 'success' : r.status === 'review_rejected' || r.status === 'rejected' ? 'danger' : 'warn'">
                {{ r.status }}
              </AppBadge>
              <AppBadge v-if="r.yanked" tone="danger">{{ t('releases.yanked') }}</AppBadge>
            </button>
            <div v-if="openId === r.id" class="mt-2 flex flex-col gap-1.5 border-t border-slate-100 pt-2 text-sm dark:border-slate-800">
              <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.checksum') }}</dt>
                <dd class="break-all font-mono">{{ r.sha256 }}</dd>
                <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.size') }}</dt>
                <dd class="font-mono tabular-nums">{{ r.size }}</dd>
                <dt class="text-slate-500 dark:text-slate-400">{{ t('portal.keyId') }}</dt>
                <dd class="break-all font-mono">{{ r.keyId }}</dd>
                <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.verification') }}</dt>
                <dd>{{ r.verification ? `${r.verification.status}${r.verification.resultClass ? ` (${r.verification.resultClass})` : ''}` : '—' }}</dd>
                <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.moderation') }}</dt>
                <dd>{{ r.moderation ? `${r.moderation.decision} (${r.moderation.reasonCode})` : '—' }}</dd>
                <template v-if="r.yanked">
                  <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.yankReason') }}</dt>
                  <dd>{{ r.yankReason }}</dd>
                </template>
                <template v-if="r.advisory">
                  <dt class="text-slate-500 dark:text-slate-400">{{ t('releases.advisory') }}</dt>
                  <dd>{{ r.advisory.severity }}: {{ r.advisory.message }}</dd>
                </template>
              </dl>
            </div>
          </AppCard>
        </li>
      </ul>
      <EmptyState v-else :title="t('releases.noReleases')" icon="package" />
      <div v-if="nextCursor" class="mt-2 flex justify-center">
        <AppButton size="sm" variant="secondary" icon="chevronDown" @click="loadMore">
          {{ t('states.next') }}
        </AppButton>
      </div>
    </StateBlock>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useQuery } from '@tanstack/vue-query'
import { api } from '../../api/client'
import type { PublisherRelease } from '../../api/types'
import StateBlock from '../StateBlock.vue'
import AppBadge from '../ui/AppBadge.vue'
import AppButton from '../ui/AppButton.vue'
import AppCard from '../ui/AppCard.vue'
import EmptyState from '../ui/EmptyState.vue'

const props = defineProps<{ publisherId: string; refreshKey?: number }>()

const { t } = useI18n()
const cursor = ref<string | undefined>(undefined)
const accumulated = ref<PublisherRelease[]>([])
const openId = ref<string | null>(null)

const { data, isPending, error, refetch } = useQuery({
  queryKey: ['portal', 'releases', props.publisherId, cursor],
  queryFn: () => api.publisherReleases(props.publisherId, { cursor: cursor.value, limit: 20 }),
})

watch(data, (page) => {
  if (!page) return
  accumulated.value = cursor.value
    ? [...accumulated.value, ...page.items]
    : [...page.items]
})
watch(() => props.publisherId, () => {
  cursor.value = undefined
  accumulated.value = []
  openId.value = null
})
watch(() => props.refreshKey, () => {
  cursor.value = undefined
  void refetch()
})

const items = computed(() => accumulated.value)
const nextCursor = computed(() => data.value?.nextCursor ?? null)

function loadMore() {
  if (data.value?.nextCursor) cursor.value = data.value.nextCursor
}

function toggle(id: string) {
  openId.value = openId.value === id ? null : id
}
</script>
