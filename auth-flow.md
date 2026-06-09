# Auth Server — Login / Logout Flow

## Overview

`auth.smartcampus.com` is the sole owner of login state. Tenant apps (lms, portal, admin) **consume** authentication results — they do not own sessions.

| Principle | Detail |
|-----------|--------|
| One active `CentralUserSession` per (user, tenant) | New login from any device revokes all others |
| One active Passport token per (user, client, app) | SSO to the same app displaces the prior token; LMS ↔ Portal tokens are independent |
| No per-request `/api/user` polling | Tenant apps validate JWTs locally via JWKS; revocations are pushed via signed webhooks |
| `device_uuid` is audit metadata | Tracks which browser triggered the login; not a scoping key |
| Handoffs stored in Redis, not DB | `oauth_handoffs` table is superseded; `HandoffStore` writes to Redis with a 5-minute TTL |

---

## Database: Console Migrations

> **Console (`smartcampus-console`) owns all landlord migrations. Never run these from auth-server.**

### New: `central_user_sessions`

```php
Schema::create('central_user_sessions', function (Blueprint $table) {
    $table->uuid('id')->primary();
    $table->foreignUuid('tenant_id')->constrained('tenants');
    $table->uuid('user_id');                            // tenant-side UUID
    $table->uuid('session_uuid')->unique();
    $table->string('device_uuid', 64)->nullable();      // from device_id query param (audit only)
    $table->string('access_token_id', 100)->nullable()->index(); // first issued token's jti
    $table->string('refresh_token_id', 80)->nullable();
    $table->string('ip_address', 45)->nullable();
    $table->text('user_agent')->nullable();
    $table->timestamp('last_activity_at')->nullable();
    $table->timestamp('revoked_at')->nullable();
    $table->timestamps();

    $table->index(['tenant_id', 'user_id', 'revoked_at']);
});
```

### Alter: `oauth_access_tokens`

```php
$table->dropColumn('device_type'); // no longer used
```

### Alter: `oauth_clients`

```php
$table->string('revocation_webhook_url')->nullable();
$table->string('revocation_webhook_secret', 64)->nullable();
```

### Drop: `oauth_handoffs` (follow-up migration after Phase 2 deploy)

Handoffs are now stored in Redis. Once `HandoffStore` is deployed and the existing table is
empty, run this migration from the console app:

```php
// console migration — run after auth-server HandoffStore is deployed
Schema::dropIfExists('oauth_handoffs');
```

---

## Storage & Pruning

Revoked tokens, expired auth codes, and old sessions are **not deleted immediately** — they
accumulate unless explicitly pruned. The scheduler handles this.

### What gets pruned and when

| Table | Command | Cadence | Retention |
|-------|---------|---------|-----------|
| `oauth_handoffs` | `oauth:prune-handoffs` | Hourly | None — any row past `expires_at` is worthless |
| `oauth_auth_codes` | `passport:purge --revoked --hours=720` | Daily 02:00 | 30-day window |
| `oauth_access_tokens` | same | Daily 02:00 | 30-day window for revoked rows |
| `oauth_refresh_tokens` | same (cascade) | Daily 02:00 | Cascade from access token deletion |
| `central_user_sessions` | `oauth:prune-sessions` | Daily 03:00 | 90-day window for revoked rows |

`oauth_handoffs` pruning is only needed as a fallback while any un-redeemed/expired rows
remain from before the Redis migration. Once the table is dropped, remove this command.

### Scheduler registration (`routes/console.php`)

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('passport:purge --revoked --hours=720')->daily()->at('02:00');
Schedule::command('oauth:prune-handoffs')->hourly();
Schedule::command('oauth:prune-sessions')->daily()->at('03:00');
```

### Server cron entry (required once per server)

```
* * * * * php /path/to/auth-server/artisan schedule:run >> /dev/null 2>&1
```

---

## Login Flow

```
Browser → LMS
  LMS → GET /oauth/authorize?client_id={id}&device_id={uuid}&scope=lms:*
  ResolveTenantForOAuth:
    - Resolves tenant from client_id
    - Stores oauth_tenant_id, oauth_client_id in PHP session
    - Stores device_id in PHP session as oauth_device_id
  No active PHP session → /login form shown

Browser submits credentials (Inertia XHR)
  LoginController::store():
    - Auth::guard('tenant_web')->attempt() → success
    - session()->regenerate()
    - CentralSessionService::createSession(user, tenantId, request):
        [DB transaction on landlord]
        1. Revoke all prior CentralUserSession records for (user, tenant)
        2. Collect all active oauth_access_tokens for (user, tenant)
        3. Revoke those tokens + their refresh tokens
        4. Fire AccessTokenRevoked event for each → DispatchRevocationWebhook queued
        5. Create new CentralUserSession (device_uuid, ip_address, user_agent stored)
    - Store session_uuid in PHP session as oauth_central_session_uuid
    - Return Inertia::location() → browser does full-page navigation to /oauth/authorize

Passport auto-approves (first-party client, skipsAuthorization = true)
  → Auth code issued
  → Browser → GET /oauth/callback?code=...&state=...

OAuthCallbackController::__invoke():
  - In-process token exchange (PsrServerRequest → AuthorizationServer)
  - TenantAwareAccessTokenRepository::persistNewAccessToken():
      1. Derive app_id from scope prefix (e.g. "lms:*" → App where slug="lms")
      2. Displace prior (user, client, app_id=lms) token if any
      3. Persist new token (tenant_id, app_id stored; no device_type)
  - Parse JWT jti from access token
  - Update CentralUserSession (session_uuid match, access_token_id is null):
      SET access_token_id = jti, refresh_token_id = oauth_refresh_tokens.id
  - Clear oauth_central_session_uuid from PHP session
  - HandoffStore::store(token, payload):
      Encrypted JSON written to Redis key "handoff:{token}" with 300s TTL
      (oauth_handoffs DB table is NOT written to)
  - Browser → LMS /auth/complete?token={handoff}

LMS server-side:
  - GET /api/oauth/handoff/{token} → HandoffStore::redeem(token)
      Atomic getdel from Redis — returns null if expired or already redeemed
  - Returns { access_token, refresh_token, user_data }
  - Store token; user authenticated in LMS
```

---

## SSO Flow (Portal after LMS login)

```
Browser → Portal
  Portal → GET /oauth/authorize?client_id={same}&scope=portal:*
  ResolveTenantForOAuth: tenant resolved from client_id
  PHP session is active → user already authenticated
  Passport auto-approves

OAuthCallbackController::__invoke():
  - Token exchange as above
  - TenantAwareAccessTokenRepository: displaces prior portal token (if any);
    LMS token is untouched (different app_id)
  - oauth_central_session_uuid is NOT in session → CentralUserSession NOT updated
    (only LoginController sets a new central session)
  - HandoffStore::store(token, payload) → Redis (same as login flow above)
  - Portal receives token via /api/oauth/handoff/{token}
```

---

## JWT Claims

```json
{
  "jti": "<token-uuid>",
  "iss": "https://auth.smartcampus.com",
  "aud": "<client-id>",
  "sub": "<tenant-user-uuid>",
  "iat": 1700000000,
  "nbf": 1700000000,
  "exp": 1700003600,
  "tenant_id": "<tenant-uuid>",
  "scopes": ["lms:*"]
}
```

`device_type` is **not** a JWT claim. Device info is stored as audit metadata in `central_user_sessions.device_uuid`.

---

## Logout Flow

```
User clicks Logout in LMS
  → Browser redirect: GET /logout?app_slug=lms&redirect={lms_base_url}

LogoutController::destroy():
  1. Read oauth_app_base_urls and oauth_tenant_id from session (before invalidation)
  2. Revoke CentralUserSession(s) for (user, tenant) → revoked_at = now()
  3. RevokeUserTokensAction: all active tokens for user → revoked = true
     Each token fires AccessTokenRevoked event
  4. Auth::guard('tenant_web')->logout()
  5. session()->invalidate() + regenerateToken()
  6. Redirect: ?redirect= param (if allowed host) → app base URL → tenant.login

Async (queued):
  DispatchRevocationWebhook listener (per AccessTokenRevoked event):
    - Look up token → client_id, user_id, tenant_id
    - Look up oauth_clients.revocation_webhook_url
    - If set → dispatch SendRevocationWebhookJob

  SendRevocationWebhookJob (3 retries, 10s backoff):
    POST {webhook_url}
    Headers:
      X-Webhook-Signature: sha256=<HMAC-SHA256(body, revocation_webhook_secret)>
      Content-Type: application/json
    Body:
      {
        "event": "token.revoked",
        "token_ids": ["<jti>"],
        "user_id": "<uuid>",
        "tenant_id": "<uuid>",
        "timestamp": "2026-01-01T00:00:00+00:00"
      }
```

### Why the browser redirect is required for logout

The auth-server PHP session cookie is `HttpOnly` scoped to `auth.smartcampus.com`. An API call from the tenant app's server cannot clear it — only a same-origin browser request can. `POST /api/logout` exists for programmatic token revocation only (e.g. mobile apps or background processes that manage their own tokens).

---

## Tenant App: `/auth/complete` Handler

Every tenant app must expose a route at `/auth/complete` that the browser lands on after the
auth-server finishes the OAuth flow. This is a **server-rendered route** (not a client-side
redirect) so the handoff redemption happens server-to-server before the browser gets a response.

```
Browser → GET /auth/complete?token={handoff_token}

Server-side handler:
  1. Read `token` from query string
  2. Call auth-server: GET https://auth.smartcampus.com/api/oauth/handoff/{token}
       - Must be server-to-server (not from the browser)
       - Must be called within 5 minutes of the browser landing here
  3. On 200 OK → store access_token + refresh_token (see response schema below)
       - Mark the user as authenticated in the local session
       - Redirect browser to `final_url` (from the handoff response)
  4. On 410 Gone → token expired, already redeemed, or invalid
       - Redirect user back to login (restart the OAuth flow)
```

### Handoff API — Response Schema

`GET /api/oauth/handoff/{token}` returns:

```json
{
  "access_token":  "<signed JWT>",
  "refresh_token": "<opaque token>",
  "expires_in":    3600,
  "user_data": {
    "id":    "<tenant-user-uuid>",
    "name":  "Jane Smith",
    "email": "jane@school.edu"
  },
  "nonce":     "<echoed from original authorize state>",
  "final_url": "https://lms.school.edu/dashboard"
}
```

| Field | Usage |
|-------|-------|
| `access_token` | Store server-side; attach as `Authorization: Bearer {token}` on API calls |
| `refresh_token` | Store server-side; use to obtain a new access token when the current one expires |
| `expires_in` | Seconds until `access_token` expires; schedule refresh before this elapses |
| `user_data` | Bootstrap the local user session (name, email, id) |
| `nonce` | Optional: verify it matches the value you put into the `state` parameter to confirm round-trip integrity |
| `final_url` | Redirect the browser here after storing the tokens |

### Handoff API — Error Responses

| Status | Meaning | Action |
|--------|---------|--------|
| `410 Gone` | Token expired (> 5 min), already redeemed, or never existed | Restart login flow |
| `429 Too Many Requests` | Throttle limit hit (20 req/min per IP) | Retry with backoff |

---

## oauth-client Package — Required Changes

The oauth-client package is the shared library consumed by all tenant apps. It wraps the
OAuth initiation, token storage, local JWT validation, and webhook handling.

### Initiate login

Append `device_id` to the authorize redirect URL:

```js
const deviceId = localStorage.getItem('sc_device_id')
  ?? (() => { const id = crypto.randomUUID(); localStorage.setItem('sc_device_id', id); return id; })();

const url = new URL('https://auth.smartcampus.com/oauth/authorize');
url.searchParams.set('client_id', CLIENT_ID);
url.searchParams.set('scope', SCOPE);
url.searchParams.set('device_id', deviceId);
url.searchParams.set('response_type', 'code');
url.searchParams.set('state', buildState({ nonce, final_url: window.location.href }));

window.location.href = url.toString();
```

`state` must be a base64url-encoded JSON object: `{ "nonce": "<random>", "final_url": "<url>" }`.

### Logout

Always a browser redirect — never an API call — so the auth-server can clear its own session cookie:

```js
const params = new URLSearchParams({
  app_slug: APP_SLUG,
  redirect: window.location.origin,
});
window.location.href = `https://auth.smartcampus.com/logout?${params}`;
```

### Local JWT validation

Validate the access token signature on every request using the JWKS endpoint. Cache the
keyset (TTL ~1 h) to avoid fetching on every request.

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://auth.smartcampus.com/oauth/jwks'));

async function validateToken(jwt) {
  const { payload } = await jwtVerify(jwt, JWKS, {
    issuer:   'https://auth.smartcampus.com',
    audience: CLIENT_ID,
  });
  // Also check jti against revoked token cache (see below)
  if (isRevoked(payload.jti)) throw new Error('Token revoked');
  return payload;
}
```

### Revoked token cache

Maintain a short-lived in-process or Redis set of revoked `jti` values. Populate it from
the webhook (below). Evict entries after their JWT `exp` passes — they can't be used after
that regardless.

```js
const revokedJtis = new Map(); // jti → expiry timestamp

function isRevoked(jti) {
  const exp = revokedJtis.get(jti);
  if (!exp) return false;
  if (Date.now() / 1000 > exp) { revokedJtis.delete(jti); return false; }
  return true;
}

function revokeJti(jti, exp) {
  revokedJtis.set(jti, exp);
}
```

### Webhook endpoint — `POST /api/auth/webhook/revoke`

Register this route in each tenant app. The auth-server calls it when a user's token is
revoked (on login from another device, or logout).

```js
app.post('/api/auth/webhook/revoke', express.raw({ type: 'application/json' }), (req, res) => {
  if (!verifyWebhook(req.body, req.headers['x-webhook-signature'], WEBHOOK_SECRET)) {
    return res.sendStatus(401);
  }

  const { token_ids, user_id } = JSON.parse(req.body);

  for (const jti of token_ids) {
    revokeJti(jti, /* look up exp from your token store or decode JWT */);
  }

  // If the currently authenticated user's token is in token_ids, invalidate their session
  invalidateLocalSessionsForUser(user_id, token_ids);

  res.sendStatus(204);
});
```

### Webhook HMAC Verification

```js
const crypto = require('crypto');

function verifyWebhook(rawBody, signatureHeader, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader));
}
```

---

## Tenant App Integration Contract

Summary of every touch point between a tenant app and the auth-server:

| Action | Endpoint / Mechanism | Notes |
|--------|----------------------|-------|
| Initiate login | `GET /oauth/authorize?client_id=...&scope=...&device_id={uuid}&state=...` | Via oauth-client package |
| Receive auth result | `GET /auth/complete?token={handoff}` — your route, calls handoff API | Server-side; must redeem within 5 min |
| Redeem handoff | `GET /api/oauth/handoff/{token}` (server-to-server) | Returns tokens + user_data; 410 = restart login |
| Logout | Browser redirect `GET /logout?app_slug={slug}&redirect={encoded_url}` | Must be browser-initiated |
| Token validation | Local JWT verify (JWKS) + `jti` revoked-cache check | No per-request call to auth-server |
| Receive revocations | `POST /api/auth/webhook/revoke` on your server | Verify HMAC; update revoked cache; invalidate local session |
| Webhook payload | `{ event, token_ids, user_id, tenant_id, timestamp }` | Signed with `X-Webhook-Signature: sha256=...` |

---

## Verification Checklist

1. **Session revocation on login** — Log in on Browser A → log in on Browser B → verify Browser A's `CentralUserSession.revoked_at` is set and its tokens have `revoked = true`.
2. **Cross-app SSO independence** — After LMS login, open Portal via SSO → two rows in `oauth_access_tokens` with different `app_id`, neither revoked.
3. **Same-app token displacement** — SSO to Portal twice → only one Portal token active; prior Portal token `revoked = true`.
4. **CentralUserSession linked** — After first login, `central_user_sessions.access_token_id` matches the issued token's `id`.
5. **Webhook delivery** — After logout, tenant app webhook receives a POST with valid HMAC and the correct `token_ids`.
6. **Full logout** — Browser redirect to `/logout` → all tokens revoked, `CentralUserSession.revoked_at` set, PHP session destroyed, browser landed on correct app.
7. **JWT claims** — Decode issued JWT: `jti`, `tenant_id`, and `scopes` present. Confirm `device_type` is absent.
8. **Redis handoff — key lifecycle** — After login, run `redis-cli keys "handoff:*"` to confirm the key exists. After the tenant app redeems it, confirm the key is gone (atomic `getdel`).
9. **Redis handoff — duplicate redemption** — Attempt `GET /api/oauth/handoff/{token}` a second time → must return `404`.
10. **Redis handoff — no DB writes** — Confirm `oauth_handoffs` table receives no new rows after HandoffStore is deployed.
11. **Pruning — handoffs** — Run `php artisan oauth:prune-handoffs` and verify expired rows are deleted from `oauth_handoffs`.
12. **Pruning — sessions** — Run `php artisan oauth:prune-sessions` and verify old revoked sessions are deleted from `central_user_sessions`.
13. **Pruning — tokens** — Run `php artisan passport:purge --revoked --hours=720` and verify row counts drop in `oauth_access_tokens` and `oauth_auth_codes`.
14. **Scheduler** — Run `php artisan schedule:list` and confirm all three prune jobs appear with correct cadence.
15. **Tests** — `php artisan test --compact`
