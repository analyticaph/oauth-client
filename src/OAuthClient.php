<?php

namespace Analyticaph\OAuthClient;

class OAuthClient
{
    /**
     * Register the browser login/finalize/logout/profile routes. Call from the
     * host app's routes/web.php so they run inside the `web` middleware group.
     *
     * Pass `profile: false` in apps that handle account settings natively and
     * have retired the `auth.profile` redirect to the auth server.
     */
    public static function routes(bool $profile = true): void
    {
        require __DIR__.'/../routes/web.php';
    }
}
