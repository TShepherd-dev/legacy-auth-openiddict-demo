<template>
  <div>
    <div v-if="!user" class="card">
      <h3>Not signed in</h3>
      <p>
        Sign in via the authorization code flow (PKCE) against the OpenIddict server.
        Seeded demo users: <strong>alice</strong> (full permissions) and
        <strong>bob</strong> (view only) — password <code>Passw0rd!</code>.
      </p>
      <button @click="login">Sign in</button>
    </div>

    <template v-else>
      <div class="card">
        <h3>API calls</h3>
        <p>
          The access token is an opaque <em>reference token</em>; the server validates it,
          then re-hydrates your permission claims server-side from the user cache —
          exactly like the legacy platform pipeline. Watch what alice vs bob can do.
        </p>
        <button @click="callPublic" :disabled="busy">GET /api/demo (public)</button>
        <button @click="callViewData" :disabled="busy">GET /api/demo/view-data</button>
        <button @click="callManageData" :disabled="busy">POST /api/demo/manage-data</button>
        <button @click="callMe" :disabled="busy">GET /api/demo/me</button>
      </div>

      <div class="card" v-for="r in results" :key="r.id">
        <h3>
          {{ r.label }}
          <span :class="statusClass(r)" class="badge">{{ r.status }}</span>
        </h3>
        <p v-if="r.error" class="error-text">{{ r.error }}</p>
        <pre>{{ r.body }}</pre>
      </div>

      <div class="card">
        <h3>ID token claims (JWT)</h3>
        <p>The access token is opaque; this is the decoded id_token.</p>
        <pre>{{ idTokenClaims }}</pre>
      </div>

      <div class="card">
        <h3>Userinfo claims</h3>
        <pre>{{ userinfoClaims }}</pre>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { getUser, login, decodeJwt, ApiClient } from '../auth'

const emit = defineEmits(['auth-changed'])

const user = ref(null)
const busy = ref(false)
const results = ref([])
const userinfoClaims = ref('not fetched yet')
let nextId = 0

const api = new ApiClient()

const idTokenClaims = computed(() =>
  user.value ? JSON.stringify(decodeJwt(user.value.id_token), null, 2) : 'n/a',
)

function statusClass(r) {
  if (r.status === 403) return 'forbidden'
  if (r.status >= 200 && r.status < 300) return 'ok-badge'
  return 'error-text'
}

async function run(label, fn) {
  busy.value = true
  try {
    const res = await fn()
    results.value.unshift({
      id: ++nextId,
      label,
      status: res.status,
      body: JSON.stringify(res.body, null, 2),
      error: null,
    })
  } catch (e) {
    results.value.unshift({
      id: ++nextId,
      label,
      status: '-',
      body: null,
      error: e.message,
    })
  } finally {
    busy.value = false
  }
}

const callPublic = () => run('GET /api/demo (public)', () => fetch('https://localhost:5001/api/demo').then(async (r) => ({ status: r.status, body: await r.json() })))
const callViewData = () => run('GET /api/demo/view-data', () => api.fetch('/api/demo/view-data'))
const callMe = () => {
  const p = api.fetch('/api/demo/me').then(async (res) => {
    if (res.status === 200 && res.body?.claims) {
      userinfoClaims.value = JSON.stringify(res.body.claims.find((c) => c.type === 'ap_permissions') ?? {}, null, 2)
    }
    return res
  })
  return run('GET /api/demo/me', () => p)
}
const callManageData = () =>
  run('POST /api/demo/manage-data', () =>
    api.fetch('/api/demo/manage-data', { method: 'POST', body: JSON.stringify({ action: 'create' }) }),
  )

onMounted(async () => {
  user.value = await getUser()
})

watch(user, () => emit('auth-changed'))
</script>
