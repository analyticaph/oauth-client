<?php

use Analyticaph\OAuthClient\OAuthClient;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Route;

it('registers the auth.profile redirect by default', function () {
    expect(Route::has('auth.profile'))->toBeTrue();

    $this->get('auth/profile')->assertRedirect('/login');
});

it('can skip the auth.profile route', function () {
    Route::setRoutes(new RouteCollection);

    OAuthClient::routes(profile: false);
    Route::getRoutes()->refreshNameLookups();

    expect(Route::has('login'))->toBeTrue()
        ->and(Route::has('oauth.finalize'))->toBeTrue()
        ->and(Route::has('logout'))->toBeTrue()
        ->and(Route::has('auth.profile'))->toBeFalse();
});
