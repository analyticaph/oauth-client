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
     * Route name of the host app's OAuth callback.
     */
    'callback_route' => 'oauth.callback',

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

];
