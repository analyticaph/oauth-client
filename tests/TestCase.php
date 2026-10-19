<?php

namespace Analyticaph\OAuthClient\Tests;

use Analyticaph\OAuthClient\OAuthClient;
use Analyticaph\OAuthClient\OAuthClientServiceProvider;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [OAuthClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('oauth-client.handoff_endpoint', 'https://auth.test/api/oauth/handoff');
        $app['config']->set('services.auth.server', 'https://auth.test');
    }

    protected function defineRoutes($router): void
    {
        Route::middleware('web')->group(function () {
            OAuthClient::routes();

            Route::get('dashboard', fn () => 'dashboard')->name('dashboard');
            Route::get('/', fn () => 'home')->name('home');
        });
    }
}
