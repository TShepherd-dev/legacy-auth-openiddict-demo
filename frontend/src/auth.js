import { UserManager, WebStorageStateStore } from 'oidc-client-ts'

// Mirrors the "the platform BFF SPA client" client seeded by the legacy client seeding service
// in the legacy codebase: public SPA, authorization_code + refresh_token, PKCE required.
const config = {
  authority: 'https://localhost:5001',
  client_id: 'LegacyAuthDemo.Spa',
  redirect_uri: 'http://localhost:8080/auth-callback',
  post_logout_redirect_uri: 'http://localhost:8080/auth-logout',
  response_type: 'code',
  scope: 'openid email profile roles offline_access',
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  // Reference tokens are opaque, so no resource indicator / JWT assumptions needed.
}

export const userManager = new UserManager(config)

export async function getUser() {
  return await userManager.getUser()
}

export function login() {
  return userManager.signinRedirect()
}

export async function logout() {
  const user = await userManager.getUser()
  if (user) {
    await userManager.signoutRedirect()
  }
}

// The access token is an opaque REFERENCE token (UseReferenceAccessTokens in the
// server startup), so we can't decode it client-side. The id_token IS a JWT and
// the userinfo endpoint returns the hydrated ap_permissions claims.
export function decodeJwt(token) {
  try {
    const payload = token.split('.')[1]
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

export class ApiClient {
  constructor(baseUrl = 'https://localhost:5001') {
    this.baseUrl = baseUrl
  }

  async fetch(path, options = {}, retried = false) {
    const user = await getUser()
    if (!user || user.expired) {
      throw new Error('Not signed in')
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${user.access_token}`,
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
    })

    // Access token expired or revoked -> one silent renewal attempt, then retry.
    if (response.status === 401 && !retried) {
      try {
        await userManager.signinSilent()
        return this.fetch(path, options, true)
      } catch (e) {
        await userManager.removeUser()
        throw new Error('Session expired - please sign in again')
      }
    }

    if (!response.ok && response.status !== 403) {
      throw new Error(`HTTP ${response.status}`)
    }

    if (response.status === 204) return null
    return { status: response.status, body: await response.json().catch(() => null) }
  }
}
