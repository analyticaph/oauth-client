<?php

namespace SmartCampus\OAuthClient;

use Illuminate\Support\ServiceProvider;
use SmartCampus\OAuthClient\Http\Middleware\ValidateOAuthToken;
use SmartCampus\OAuthClient\Services\OAuthService;
use SmartCampus\OAuthClient\Services\RolePermissionSyncService;

class OAuthClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/oauth-client.php', 'oauth-client');

        $this->app->singleton(OAuthService::class);
        $this->app->singleton(RolePermissionSyncService::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/oauth-client.php' => config_path('oauth-client.php'),
            ], 'oauth-client-config');
        }

        $this->app['router']->aliasMiddleware('oauth.validate', ValidateOAuthToken::class);
    }
}
