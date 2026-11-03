<template>
  <div class="flex flex-col gap-2">
    <StateBlock :loading="isPending" :error="!!error" :retry="true" @retry="refetch">
      <ul v-if="members.length > 0" class="divide-y divide-slate-100 rounded-md border border-slate-200 text-sm dark:divide-slate-800 dark:border-slate-700">
        <li v-for="m in members" :key="m.user_id" class="flex flex-wrap items-center gap-2 px-3 py-1.5">
          <span class="min-w-0 flex-1 truncate font-mono text-xs">{{ m.user_id }}</span>
          <AppBadge tone="neutral">{{ m.role }}</AppBadge>
          <template v-if="isOwner && m.role !== 'owner'">
            <AppSelect :model-value="roles[m.user_id] ?? m.role" class="w-32" :label="t('portal.setRole')" @update:model-value="(v) => (roles[m.user_id] = v)">
              <option value="admin">admin</option>
              <option value="publisher">publisher</option>
              <option value="viewer">viewer</option>
            </AppSelect>
            <AppButton size="sm" variant="secondary" :loading="busy === m.user_id" :disabled="busy !== null" @click="saveRole(m.user_id)">
              {{ t('states.confirm') }}
            </AppButton>
            <AppButton size="sm" variant="danger" :disabled="busy !== null" @click="askRemove(m.user_id)">
              {{ t('portal.remove') }}
            </AppButton>
          </template>
        </li>
      </ul>
      <EmptyState v-else :title="t('states.empty')" icon="portal" />
    </StateBlock>
    <div v-if="!isOwner && role !== 'owner'" class="flex flex-wrap items-center gap-2">
      <AppButton size="sm" variant="danger" :loading="busy === 'leave'" :disabled="busy !== null" @click="confirmLeave = true">
        {{ t('portal.leave') }}
      </AppButton>
    </div>
    <p v-if="actionError" role="alert" class="flex items-start gap-2 text-sm text-red-700 dark:text-red-300">
      <AppIcon name="alert" :size="16" class="mt-0.5 shrink-0" aria-hidden="true" />
      {{ actionError }}
    </p>
    <ConfirmDialog :danger="true" :open="removeId !== null" :title="t('portal.remove')" :body="t('portal.removeConfirm')" :busy="busy !== null" @confirm="doRemove" @cancel="removeId = null" />
    <ConfirmDialog :danger="true" :open="confirmLeave" :title="t('portal.leave')" :body="t('portal.leaveConfirm')" :busy="busy !== null" @confirm="doLeave" @cancel="confirmLeave = false" />
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ApiError, api } from '../../api/client'
import { useUiStore } from '../../stores/ui'
import type { PublisherMember } from '../../api/types'
import StateBlock from '../StateBlock.vue'
import ConfirmDialog from '../ConfirmDialog.vue'
import AppIcon from '../icons/AppIcon.vue'
import AppBadge from '../ui/AppBadge.vue'
import AppButton from '../ui/AppButton.vue'
import AppSelect from '../ui/AppSelect.vue'
import EmptyState from '../ui/EmptyState.vue'

const props = defineProps<{ publisherId: string; role: string }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const ui = useUiStore()
const client = useQueryClient()
const isOwner = computed(() => props.role === 'owner')

const { data, isPending, error, refetch } = useQuery({
  queryKey: ['portal', 'members', props.publisherId],
  queryFn: () => api.publisherMembers(props.publisherId),
})
const members = computed(() => data.value ?? [])
const roles = reactive<Record<string, string>>({})
watch(members, (list) => {
  for (const m of list) roles[m.user_id] = m.role
}, { immediate: true })

const busy = ref<string | null>(null)
const removeId = ref<string | null>(null)
const confirmLeave = ref(false)
const actionError = ref('')

function failed(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return t('errors.expired')
    if (e.status === 403) return t('errors.forbidden')
    if (e.status === 404) return t('errors.loadFailed')
  }
  return t('errors.actionFailed')
}

async function saveRole(userId: string) {
  if (busy.value) return
  const role = roles[userId] ?? members.value.find((m) => m.user_id === userId)?.role ?? 'viewer'
  busy.value = userId
  actionError.value = ''
  try {
    await api.setMemberRole(props.publisherId, userId, role)
    ui.toast(t('portal.roleUpdated'), 'ok')
    await client.invalidateQueries({ queryKey: ['portal', 'members', props.publisherId] })
    emit('changed')
  } catch (e) {
    actionError.value = failed(e)
  } finally {
    busy.value = null
  }
}

function askRemove(userId: string) {
  removeId.value = userId
}

async function doRemove() {
  const userId = removeId.value
  if (!userId || busy.value) return
  busy.value = userId
  actionError.value = ''
  try {
    await api.removeMember(props.publisherId, userId)
    removeId.value = null
    ui.toast(t('portal.removed'), 'ok')
    await client.invalidateQueries({ queryKey: ['portal', 'members', props.publisherId] })
    emit('changed')
  } catch (e) {
    actionError.value = failed(e)
  } finally {
    busy.value = null
  }
}

async function doLeave() {
  if (busy.value) return
  busy.value = 'leave'
  actionError.value = ''
  try {
    await api.leavePublisher(props.publisherId)
    confirmLeave.value = false
    ui.toast(t('portal.left'), 'ok')
    emit('changed')
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      actionError.value = t('portal.cannotLeaveOwner')
    } else {
      actionError.value = failed(e)
    }
  } finally {
    busy.value = null
  }
}

defineExpose({ members: computed(() => members.value as PublisherMember[]) })
</script>
