import { afterEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createPinia, setActivePinia } from 'pinia'
import { VueQueryPlugin, QueryClient } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import Portal from '../src/views/Portal.vue'
import MemberManager from '../src/components/portal/MemberManager.vue'
import KeyManager from '../src/components/portal/KeyManager.vue'
import ReleaseList from '../src/components/portal/ReleaseList.vue'
import ReleaseWizard from '../src/components/portal/ReleaseWizard.vue'
import { en } from '../src/i18n/en'
import { es } from '../src/i18n/es'

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function plugins(router: Router) {
  return [
    createI18n({ legacy: false, locale: 'en', messages: { en, es } }),
    [VueQueryPlugin, { queryClient: new QueryClient({ defaultOptions: { queries: { retry: false } } }) }],
    router,
  ] as never[]
}

function harness() {
  setActivePinia(createPinia())
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/app/portal', component: { template: '<div />' } },
      { path: '/login', component: { template: '<div />' } },
    ],
  })
}

// ConfirmDialog teleports into document.body, outside the mounted wrapper.
function bodyText(): string {
  return document.body.textContent ?? ''
}

function clickBodyButton(label: string) {
  const btn = [...document.body.querySelectorAll('button')].find(
    (b) => b.textContent?.trim() === label,
  )
  expect(btn).toBeDefined()
  btn!.click()
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('namespace requests', () => {
  it('rejects invalid namespaces locally and posts valid ones', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url === '/api/v1/publishers' && !init?.method) return json([])
      if (url === '/api/v1/publishers' && init?.method === 'POST') {
        return json({ id: 'p9', namespace: 'acme', status: 'pending', role: 'owner' }, 201)
      }
      return json({ items: [], nextCursor: null })
    }))
    const router = harness()
    await router.push('/app/portal')
    const wrapper = mount(Portal, { global: { plugins: plugins(router) } })
    await vi.waitFor(() => expect(wrapper.text()).toContain('Request namespace'))
    const input = wrapper.find('input')
    const buttons = wrapper.findAll('button')
    const request = buttons.find((b) => b.text().includes('Request namespace'))!
    await input.setValue('A')
    expect((request.element as HTMLButtonElement).disabled).toBe(true)
    await input.setValue('acme')
    await wrapper.find('form').trigger('submit')
    await vi.waitFor(() => {
      expect(calls.filter((c) => c.url === '/api/v1/publishers' && !c.init?.method).length).toBeGreaterThanOrEqual(2)
    })
    const post = calls.find((c) => c.init?.method === 'POST')
    expect(post?.url).toBe('/api/v1/publishers')
    expect(post?.init?.body).toBe(JSON.stringify({ namespace: 'acme' }))
  })
})

describe('member management', () => {
  const members = [
    { user_id: 'owner-1', role: 'owner' },
    { user_id: 'member-2', role: 'viewer' },
  ]
  function mountMembers(role: string, fetchImpl: (url: string, init?: RequestInit) => Promise<Response>) {
    vi.stubGlobal('fetch', vi.fn(fetchImpl))
    const router = harness()
    return mount(MemberManager, {
      props: { publisherId: 'p1', role },
      global: { plugins: plugins(router) },
    })
  }

  it('lets owners change roles and remove members', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const wrapper = mountMembers('owner', async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return json(members)
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('member-2'))
    // Owners cannot leave (the backend answers 409); they manage instead.
    expect(wrapper.text()).not.toContain('Leave publisher')
    const selects = wrapper.findAll('select')
    expect(selects.length).toBe(1)
    await selects[0]!.setValue('publisher')
    const save = wrapper.findAll('button').find((b) => b.text() === 'Confirm')!
    await save.trigger('click')
    await vi.waitFor(() => {
      const put = calls.find((c) => c.init?.method === 'PUT')
      expect(put?.url).toBe('/api/v1/publishers/p1/members/member-2')
      expect(put?.init?.body).toBe(JSON.stringify({ role: 'publisher' }))
    })
    // The save awaits a membership refetch before clearing its busy flag.
    await vi.waitFor(() => {
      const gets = calls.filter((c) => c.url === '/api/v1/publishers/p1/members' && !c.init?.method)
      expect(gets.length).toBeGreaterThanOrEqual(2)
    })
    const remove = wrapper.findAll('button').find((b) => b.text() === 'Remove')!
    await remove.trigger('click')
    await vi.waitFor(() => expect(bodyText()).toContain('Remove this member?'))
    clickBodyButton('Confirm')
    await vi.waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/publishers/p1/members/member-2' && c.init?.method === 'DELETE')).toBe(true)
    })
  })

  it('hides management controls from non-owners and offers leave', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const wrapper = mountMembers('viewer', async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return json(members)
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('member-2'))
    expect(wrapper.findAll('select').length).toBe(0)
    expect(wrapper.text()).toContain('Leave publisher')
    const leave = wrapper.findAll('button').find((b) => b.text() === 'Leave publisher')!
    await leave.trigger('click')
    await vi.waitFor(() => expect(bodyText()).toContain('Leave this publisher?'))
    clickBodyButton('Confirm')
    await vi.waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/publishers/p1/membership' && c.init?.method === 'DELETE')).toBe(true)
    })
  })
})

describe('signing key list and revocation', () => {
  const keys = [
    { id: 'k1', keyId: 'key-one', publicKey: 'eA==', fingerprint: 'ab'.repeat(32), status: 'approved' },
    { id: 'k2', keyId: 'key-two', publicKey: 'eQ==', fingerprint: 'cd'.repeat(32), status: 'pending' },
  ]
  it('renders fingerprints and revokes with confirmation', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return json(keys)
    }))
    const router = harness()
    await router.push('/app/portal')
    const wrapper = mount(KeyManager, {
      props: { publisherId: 'p1', role: 'owner', status: 'approved' },
      global: { plugins: plugins(router) },
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('key-one'))
    expect(wrapper.text()).toContain('Approved')
    expect(wrapper.text()).toContain('Pending')
    const revoke = wrapper.findAll('button').find((b) => b.text() === 'Revoke')!
    await revoke.trigger('click')
    await vi.waitFor(() => expect(bodyText()).toContain('Revoke this signing key?'))
    clickBodyButton('Confirm')
    await vi.waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/publishers/p1/keys/k1/revoke' && c.init?.method === 'POST')).toBe(true)
    })
  })

  it('hides enrollment and revocation from viewers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json([])))
    const router = harness()
    await router.push('/app/portal')
    const wrapper = mount(KeyManager, {
      props: { publisherId: 'p1', role: 'viewer', status: 'approved' },
      global: { plugins: plugins(router) },
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('No signing keys yet.'))
    expect(wrapper.text()).not.toContain('Enroll signing key')
    expect(wrapper.text()).not.toContain('Revoke')
  })
})

describe('publisher release list', () => {
  const page1 = {
    items: [
      {
        id: 'r1', publisherId: 'p1', uploadId: 'u1', publisherKeyId: 'k1',
        pluginId: 'acme.plugin', version: '1.0.0', target: 'any', status: 'review_approved',
        sha256: 'a'.repeat(64), size: 42, keyId: 'key-one', keyFingerprint: 'f'.repeat(64),
        yanked: false, yankReason: null, advisory: null,
        moderation: { decision: 'approve', reasonCode: 'policy_reviewed' },
        verification: { status: 'antivirus_passed', resultClass: 'antivirus_passed' },
      },
    ],
    nextCursor: 'r1',
  }
  const page2 = {
    items: [
      {
        id: 'r2', publisherId: 'p1', uploadId: 'u2', publisherKeyId: 'k1',
        pluginId: 'acme.plugin', version: '0.9.0', target: 'any', status: 'awaiting_verification',
        sha256: 'b'.repeat(64), size: 10, keyId: 'key-one', keyFingerprint: 'f'.repeat(64),
        yanked: true, yankReason: 'bad', advisory: { severity: 'high', message: 'upgrade', url: null },
        moderation: null, verification: null,
      },
    ],
    nextCursor: null,
  }
  it('renders statuses and expands details with pagination', async () => {
    const seen: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      seen.push(url)
      if (url.includes('cursor=')) return json(page2)
      return json(page1)
    }))
    const router = harness()
    const wrapper = mount(ReleaseList, {
      props: { publisherId: 'p1' },
      global: { plugins: plugins(router) },
    })
    await vi.waitFor(() => expect(wrapper.text()).toContain('1.0.0'))
    expect(wrapper.text()).toContain('review_approved')
    const toggle = wrapper.find('li button')
    await toggle.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('a'.repeat(64)))
    expect(wrapper.text()).toContain('antivirus_passed')
    expect(wrapper.text()).toContain('policy_reviewed')
    const next = wrapper.findAll('button').find((b) => b.text().includes('Next'))!
    await next.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('0.9.0'))
    expect(seen.some((u) => u.includes('cursor=r1'))).toBe(true)
    expect(wrapper.text()).toContain('Yanked')
  })
})

describe('release submission wizard', () => {
  const publishers = [{ id: 'p1', namespace: 'acme', status: 'approved', role: 'owner' }]
  const keys = [{ id: 'k1', keyId: 'key-one', publicKey: 'eA==', fingerprint: 'f'.repeat(64), status: 'approved' }]

  function packageFile() {
    const bytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4])
    return new File([bytes], 'acme.plugin', { type: 'application/octet-stream' })
  }

  function stubCrypto() {
    vi.stubGlobal('crypto', {
      randomUUID: () => 'idem-1',
      subtle: { digest: async () => new Uint8Array(32).fill(7).buffer as ArrayBuffer },
    })
  }

  function mountWizard(fetchImpl: (url: string, init?: RequestInit) => Promise<Response>) {
    vi.stubGlobal('fetch', vi.fn(fetchImpl))
    const router = harness()
    return mount(ReleaseWizard, {
      props: { publishers },
      global: { plugins: plugins(router) },
    })
  }

  async function fillValid(wrapper: ReturnType<typeof mount>) {
    await wrapper.findAll('select')[0]!.setValue('p1')
    await vi.waitFor(() => expect(wrapper.text()).toContain('key-one'))
    await wrapper.findAll('select')[1]!.setValue('k1')
    const input = wrapper.find('input[type="file"]')
    const f = packageFile()
    Object.defineProperty(input.element, 'files', { value: [f], configurable: true })
    await input.trigger('change')
    const texts = wrapper.findAll('input[type="text"]')
    await texts[0]!.setValue('acme.plugin')
    await texts[1]!.setValue('1.2.3')
    await texts[2]!.setValue('any')
  }

  it('validates plugin identity and version locally', async () => {
    stubCrypto()
    const wrapper = mountWizard(async (url: string) => {
      if (url === '/api/v1/publishers/p1/keys') return json(keys)
      return json({})
    })
    await fillValid(wrapper)
    const texts = wrapper.findAll('input[type="text"]')
    await texts[0]!.setValue('other.plugin')
    const submit = wrapper.findAll('button').find((b) => b.text() === 'Submit release')!
    await submit.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('must start with'))
    await texts[0]!.setValue('acme.plugin')
    await texts[1]!.setValue('01.2.3')
    await submit.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('normalized semantic version'))
  })

  it('runs reserve, upload, complete, and submit in order', async () => {
    stubCrypto()
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const wrapper = mountWizard(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url === '/api/v1/publishers/p1/keys') return json(keys)
      if (url === '/api/v1/plugins/uploads' && init?.method === 'POST') {
        expect(init.headers).toMatchObject({ 'Idempotency-Key': 'idem-1' })
        const body = JSON.parse(init.body as string)
        expect(body.publisherId).toBe('p1')
        expect(body.sha256).toBe('07'.repeat(32))
        return json({ id: 'up1', url: 'https://storage.test/put', headers: { 'x-amz-checksum-sha256': 'x' }, expiresIn: 299 })
      }
      if (url === 'https://storage.test/put') {
        expect(init?.method).toBe('PUT')
        expect(init?.credentials).toBe('omit')
        return new Response('', { status: 200 })
      }
      if (url === '/api/v1/plugins/uploads/up1/complete') return json({ id: 'up1', status: 'quarantined' })
      if (url === '/api/v1/plugins/releases') {
        const body = JSON.parse(init?.body as string)
        expect(body).toMatchObject({ uploadId: 'up1', publisherKeyId: 'k1', pluginId: 'acme.plugin', version: '1.2.3', target: 'any' })
        return json({ id: 'r1', status: 'awaiting_verification' }, 201)
      }
      return json({})
    })
    await fillValid(wrapper)
    const submit = wrapper.findAll('button').find((b) => b.text() === 'Submit release')!
    await submit.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('r1'))
    expect(wrapper.emitted('submitted')).toBeDefined()
    const order = calls.map((c) => c.url)
    expect(order.indexOf('/api/v1/plugins/uploads')).toBeLessThan(order.indexOf('https://storage.test/put'))
    expect(order.indexOf('https://storage.test/put')).toBeLessThan(order.indexOf('/api/v1/plugins/uploads/up1/complete'))
  })

  it('reports expired upload URLs and stays retryable', async () => {
    stubCrypto()
    const wrapper = mountWizard(async (url: string, init?: RequestInit) => {
      if (url === '/api/v1/publishers/p1/keys') return json(keys)
      if (url === '/api/v1/plugins/uploads') {
        return json({ id: 'up1', url: 'https://storage.test/put', headers: {}, expiresIn: 1 })
      }
      if (url === 'https://storage.test/put') return new Response('', { status: 403 })
      return json({})
    })
    await fillValid(wrapper)
    const submit = wrapper.findAll('button').find((b) => b.text() === 'Submit release')!
    await submit.trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('expired'))
    // The wizard returns to idle so the publisher can reserve a fresh URL.
    await vi.waitFor(() => expect(wrapper.findAll('button').some((b) => b.text() === 'Submit release')).toBe(true))
  })
})
