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
     * Session key under which the token data (access_token, refresh_token,
     * expires_at) is stored.
     */
    'token_session_key' => 'oauth_token',

    /*
     * Session key under which the synced user profile (id, name, roles,
     * permissions) is stored by RolePermissionSyncService.
     */
    'user_session_key' => 'oauth_user',

    /*
     * Seconds before expiry to treat the token as expired and attempt a refresh.
     * A 60-second buffer avoids edge cases where the token expires mid-request.
     */
    'refresh_buffer_seconds' => 60,

];
