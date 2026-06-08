<?php

namespace Analyticaph\OAuthClient;

use Illuminate\Support\ServiceProvider;
use Analyticaph\OAuthClient\Http\Middleware\ValidateOAuthToken;
use Analyticaph\OAuthClient\Services\OAuthService;

class OAuthClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oauth-client.php', 'oauth-client');

        $this->app->singleton(OAuthService::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/oauth-client.php' => config_path('oauth-client.php'),
            ], 'oauth-client-config');
        }

        $this->app['router']->aliasMiddleware('oauth.validate', ValidateOAuthToken::class);

        $this->loadRoutesFrom(__DIR__.'/../routes/webhook.php');
    }
}
