import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createPinia, setActivePinia } from 'pinia'
import { VueQueryPlugin, QueryClient } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import Portal from '../src/views/Portal.vue'
import { en } from '../src/i18n/en'
import { es } from '../src/i18n/es'

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

async function harness(path = '/app/portal') {
  setActivePinia(createPinia())
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/app/portal', component: { template: '<div />' } },
      { path: '/login', component: { template: '<div />' } },
    ],
  })
  await router.push(path)
  return router
}

function mountPortal(router: Router, fetchImpl: (url: string, init?: RequestInit) => Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(fetchImpl))
  return mount(Portal, {
    global: {
      plugins: [
        createI18n({ legacy: false, locale: 'en', messages: { en, es } }),
        [VueQueryPlugin, { queryClient: new QueryClient() }],
        router,
      ],
    },
  })
}

describe('publisher portal step-up enrollment', () => {
  it('loads publishers without calling key endpoints upfront', async () => {
    const seen: string[] = []
    const router = await harness()
    const wrapper = mountPortal(router, async (url: string) => {
      seen.push(url)
      if (url === '/api/v1/publishers') {
        return json([{ id: 'p1', namespace: 'acme', status: 'approved', role: 'owner' }])
      }
      if (url === '/api/v1/publishers/p1/keys') return json([])
      return json({ items: [], nextCursor: null })
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('acme'))
    // Key endpoints stay untouched until the member opens the keys section.
    expect(seen.some((u) => u.includes('/keys/'))).toBe(false)
    const keysToggle = wrapper.findAll('button').find((b) => b.text().includes('Signing keys'))
    expect(keysToggle).toBeDefined()
    await keysToggle!.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toMatch(/Enroll signing key|Inscribir clave/))
    expect(seen.some((u) => u.includes('/keys'))).toBe(true)
    vi.unstubAllGlobals()
  })

  it('resumes the pending enrollment after the Google round-trip', async () => {
    const seen: string[] = []
    const router = await harness('/app/portal?stepUp=enroll&publisher=p1&stepUpGrant=g1')
    const wrapper = mountPortal(router, async (url: string) => {
      seen.push(url)
      if (url === '/api/v1/publishers') {
        return json([{ id: 'p1', namespace: 'acme', status: 'approved', role: 'owner' }])
      }
      if (url === '/api/v1/publishers/p1/keys') return json([])
      if (url === '/api/v1/publishers/p1/keys/challenges') {
        return json({ challengeId: 'c1', nonce: 'n'.repeat(64), expiresIn: 300 })
      }
      return json({ items: [], nextCursor: null })
    })
    await vi.waitFor(() => expect(seen).toContain('/api/v1/publishers/p1/keys/challenges'))
    expect(wrapper.text()).toContain('c1')
    // The one-time grant is stripped from the URL once consumed.
    expect(router.currentRoute.value.query['stepUpGrant']).toBeUndefined()
    vi.unstubAllGlobals()
  })
})
