<?php

namespace Analyticaph\OAuthClient;

class OAuthClient
{
    /**
     * Register the browser login/finalize/logout/profile routes. Call from the
     * host app's routes/web.php so they run inside the `web` middleware group.
     */
    public static function routes(): void
    {
        require __DIR__.'/../routes/web.php';
    }
}
