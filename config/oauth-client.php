<?php

return [

    /*
     * The app slug that identifies this tenant app (e.g. portal, admin, lms).
     * Must match the slug registered in the console. Used for logging and
     * diagnostics; client credentials are now read from config('services.auth.*').
     */
    'app_slug' => env('OAUTH_APP_SLUG', ''),

    /*
     * Route name of the host app's login action (OAuthController::redirect).
     * The middleware redirects unauthenticated requests here.
     */
    'login_route' => 'auth.redirect',

    /*
     * Full URL of the auth server's handoff redemption API endpoint (no trailing slash).
     * Example: https://auth.example.com/api/oauth/handoff
     */
    'handoff_endpoint' => env('OAUTH_HANDOFF_ENDPOINT', ''),

    /*
     * Route names used by the package OAuth controller after callback/logout.
     */
    'after_login_route' => 'dashboard',
    'after_logout_route' => 'home',
    'error_route' => 'home',

    /*
     * Session key under which the token data (access_token, refresh_token,
     * expires_at) is stored.
     */
    'token_session_key' => 'oauth_token',

    /*
     * Seconds before expiry to treat the token as expired and attempt a refresh.
     * A 60-second buffer avoids edge cases where the token expires mid-request.
     */
    'refresh_buffer_seconds' => 60,

    /*
     * How often (in seconds) the middleware verifies the access token against
     * the auth server's /api/user endpoint. This detects server-side revocation
     * (e.g. logout from another app) between refresh cycles.
     * Set to 0 to verify on every request (more secure, more traffic).
     */
    'server_verify_interval_seconds' => env('OAUTH_SERVER_VERIFY_INTERVAL', 300),

    /*
     * Shared secret used to verify HMAC-SHA256 signatures on incoming webhook
     * payloads from the auth server. Set OAUTH_WEBHOOK_SECRET in the host app.
     */
    'webhook_secret' => env('OAUTH_WEBHOOK_SECRET', ''),

    /*
     * How long (in seconds) to cache the JWKS public-key set fetched from the
     * auth server's /oauth/jwks endpoint. Default: 1 hour.
     */
    'jwks_cache_ttl' => env('OAUTH_JWKS_CACHE_TTL', 3600),

    /*
     * How long (in seconds) to keep a revoked token JTI in the cache after a
     * revocation webhook is received. Should be >= the longest token lifetime.
     * Default: 24 hours.
     */
    'revoked_token_ttl' => env('OAUTH_REVOKED_TOKEN_TTL', 86400),

];
