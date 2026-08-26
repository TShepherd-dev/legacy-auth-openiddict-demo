# Legacy Auth Demo — OpenIddict fitted into a legacy-style codebase

A miniature, runnable reproduction of how **OpenIddict** was fitted into a large
legacy .NET platform that does **not** use ASP.NET Identity's native user/role/claims
model — it has its own users, multi-tenancy (`ClientId`/`SiteId`), resources and
permissions stored in its own tables and caches.

The interesting part is not the OAuth flows themselves (OpenIddict provides those) —
it is the **seams**: custom Identity stores over the legacy DAL, tokens that carry
almost nothing, server-side permission re-hydration after token validation, and
authorization policies driven by legacy permissions instead of ASP.NET roles.

## What makes this approach distinctive

1. **Tokens carry minimal claims.** Only `sub`, `ap_clientId`, `ap_siteId`,
   `ap_schema` (+ `ap_tokentype` for PATs). No roles, no permissions, no PII.
   If the permission model changes, existing tokens stay valid.
2. **Rich permissions never leave the server.** They live in process-wide
   in-memory caches (`ApplicationCaches`) in front of the "legacy" database.
3. **Post-validation hydration event.** A custom OpenIddict *validation* event
   handler (`LegacyOpenIdDictEventHandler`) runs immediately after token validation,
   loads the caller's permission set from the cache (mutex-guarded DB repopulation on
   miss) and attaches them to the principal as a **second ClaimsIdentity**
   (`ap_permissions` claims). Controllers never see raw identity plumbing.
4. **Personal Access Tokens (PATs).** Third-party tokens map their `scope` claim to
   permissions (`api.users.manage` → `route.users.manage`) *without* consulting — or
   polluting — the owner's cached permissions. A scoped PAT can never inherit its
   owner's full powers.
5. **Dynamic policy provider instead of `[Authorize(Roles=...)]`.**
   `LegacyRoutePermissionAuthorizationPolicyProvider` turns
   `[Authorize(Policy = "PERMISSION_route.demo.view")]` into a policy whose
   requirement checks the hydrated `ap_permissions` claims. The requirement class is
   its own handler (legacy-style: no ASP.NET policies existed before).
6. **Reference tokens + BFF-friendly surface.** `UseReferenceAccessTokens()` /
   `UseReferenceRefreshTokens()` — opaque tokens revocable server-side; the SPA never
   sees a readable JWT access token.
7. **Session niceties fitted as pipeline events:** `session_state` claim injection
   (custom sign-in event ordered right after code-principal preparation) and
   `check_session_iframe` discovery metadata (custom discovery event), both mirroring
   the legacy integration for msal.js-style session monitoring.

## Solution layout

```
Auth_OpenIdDict/
├── LegacyAuthDemo.sln
├── src/
│   ├── LegacyAuthDemo.Domain/            # the "legacy" world
│   │   ├── Authentication/
│   │   │   ├── LegacyUserIdentity.cs     # POCO mimicking IdentityUser, NOT an IdentityUser
│   │   │   ├── LegacyRole.cs             # : IdentityRole<int> mapped onto tblRole-style table
│   │   │   ├── UserContext.cs            # per-request context: user + permission claims
│   │   │   └── LegacyAuthConstants.cs    # policy prefix, claim types, error keys, client ids
│   │   ├── Caching/ApplicationCaches.cs  # static AuthUserCache / UserCache (the heart of it)
│   │   └── Legacy/LegacyUserDal.cs       # fake DAL standing in for the real database
│   ├── LegacyAuthDemo.Authorization/     # the bridge layer
│   │   ├── Data/
│   │   │   ├── LegacyDbContext.cs        # ONLY for OpenIddict entities (UseOpenIddict<int>())
│   │   │   ├── ClientAppRegistration.cs  # dev client seeding (IHostedService)
│   │   │   └── TokenCleanupHostedService.cs # prunes expired tokens (Quartz replacement)
│   │   ├── Stores/LegacyUserStore.cs     # ASP.NET Identity store OVER the legacy DAL
│   │   ├── Stores/LegacyRoleStore.cs
│   │   ├── Repositories/                 # LegacyUserManager / LegacySignInManager
│   │   ├── Sessions/                     # IAuthUserSession: ap_session cookie ↔ session_state
│   │   ├── Authorization/
│   │   │   ├── LegacyOpenIdDictEventHandler.cs   # ★ post-validation permission hydration
│   │   │   ├── LegacyRoutePermissionAuthorizationPolicyProvider.cs
│   │   │   └── LegacyRoutePermissionRequirement.cs # requirement + self-handler
│   │   └── Startup/LegacyOAuthOpenIdStartup.cs   # ★ all AddOpenIddict wiring in one place
│   └── LegacyAuthDemo.WebApi/            # the host
│       ├── Controllers/AuthorizationController.cs # authorize/token/logout/userinfo/PAT/session-check
│       ├── Controllers/DemoController.cs          # protected endpoints using PERMISSION_ policies
│       ├── Pages/Account/Login|Logout.cshtml      # Razor login page (identity cookie)
│       └── Program.cs
└── frontend/                             # Vue 3 + Vite + oidc-client-ts (PKCE auth-code flow)
```

## Mapping from the original legacy codebase

| Legacy (original platform) | This demo |
|---|---|
| `the legacy RunAuthStartup` | `LegacyOAuthOpenIdStartup.RunAuthStartup` |
| `the legacy DbContext` + SQL Server, `UseOpenIddict<int>()` | `LegacyDbContext` + SQLite, same `ReplaceDefaultEntities<int>()` |
| `AuthenticationUserIdentity` (backed by `tblUser` via UDFs) | `LegacyUserIdentity` (backed by fake `LegacyUserDal`) |
| `the legacy user store` / `the legacy user manager` / `the legacy sign-in manager` | `LegacyUserStore` / `LegacyUserManager` / `LegacySignInManager` |
| `ApplicationCaches.UserCache/AuthUserCache` | same pattern, simplified |
| `the legacy OpenIddict validation handler` | `LegacyOpenIdDictEventHandler.AddApPermissionsToRequestIdentity` |
| `the legacy route-permission policy provider` + Requirement | same names, trimmed |
| Quartz.NET token pruning job | `TokenCleanupHostedService` (plain hosted service) |
| `the legacy client seeding service` (#if DEBUG seeding) | `ClientAppRegistration` |
| X509 certs from config (prod) / ephemeral keys (dev) | ephemeral keys only (dev demo) |
| `the platform BFF SPA client` SPA client | `LegacyAuthDemo.Spa` |

Deliberate simplifications: single tenant pinned (Client 1/Site 1), two seeded users,
no consent UI, no PAT revocation rows, `EnsureCreated()` instead of migrations.

## Running it

Prereqs: .NET 10 SDK, Node 18+, trusted dev cert:

```powershell
dotnet dev-certs https --trust
```

Terminal 1 — API (https://localhost:5001):

```powershell
dotnet run --project src/LegacyAuthDemo.WebApi
```

Terminal 2 — SPA (http://localhost:8080):

```powershell
cd frontend
npm install
npm run dev
```

Seeded users: **alice** (`route.demo.view`, `route.demo.manage`, `route.users.manage`)
and **bob** (`route.demo.view` only) — password `Passw0rd!`.

## Demo script

**Password grant (machine-to-machine style):**

```powershell
curl.exe -k -X POST https://localhost:5001/api/user/authenticate `
  -H "Content-Type: application/x-www-form-urlencoded" `
  -d "grant_type=password&client_id=LegacyAuthDemo.Test&username=bob&password=Passw0rd!&scope=offline_access"
```

Note the opaque reference access token (~43 chars, not a JWT).

```powershell
curl.exe -k https://localhost:5001/api/demo/me -H "Authorization: Bearer <token>"
```

Two identities: the minimal token claims + the hydrated `ap_permissions` — added by
the validation event handler *after* OpenIddict validated the reference token.

**Authorization-code + PKCE via the SPA:** open http://localhost:8080, sign in on the
Razor login page, inspect `/api/demo/me`, then hit `manage-data` as bob → 403 with
`route.demo.manage` required; as alice → 202.

**PAT (third-party scoped access):**

```powershell
$tok = (password grant for alice).access_token
curl.exe -k -X POST https://localhost:5001/ap-auth-server/connect/getPatToken `
  -H "Authorization: Bearer $tok" -H "Content-Type: application/json" `
  -d '{"partnerName":"AcmeCorp","scopes":["api.users.manage"]}'
```

The returned JWT carries `ap_tokentype=ApPat`. Using it against
`/api/demo/view-data` yields **403** even though alice herself may view data — the
PAT only maps `api.users.manage` → `route.users.manage`.
