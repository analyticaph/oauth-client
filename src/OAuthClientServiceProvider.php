<?php

namespace Analyticaph\OAuthClient;

use Analyticaph\OAuthClient\Contracts\OAuthUserResolver;
use Analyticaph\OAuthClient\Http\Middleware\EnsureOAuthSessionActive;
use Analyticaph\OAuthClient\Http\Middleware\EnsureValidApiBearerToken;
use Analyticaph\OAuthClient\Http\Middleware\ValidateOAuthToken;
use Analyticaph\OAuthClient\Resolvers\FindUserByIdResolver;
use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Support\ServiceProvider;

class OAuthClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oauth-client.php', 'oauth-client');

        $this->app->singleton(OAuthService::class);

        // Host apps may still bind their own resolver; this is only the fallback.
        $this->app->bindIf(OAuthUserResolver::class, FindUserByIdResolver::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/oauth-client.php' => config_path('oauth-client.php'),
            ], 'oauth-client-config');
        }

        $router = $this->app['router'];
        $router->aliasMiddleware('oauth.validate', ValidateOAuthToken::class);
        $router->aliasMiddleware('oauth.session', EnsureOAuthSessionActive::class);
        $router->aliasMiddleware('oauth.bearer', EnsureValidApiBearerToken::class);

        $this->loadRoutesFrom(__DIR__.'/../routes/webhook.php');
    }
}
