<?php

use Analyticaph\OAuthClient\Services\OAuthService;
use Analyticaph\OAuthClient\Support\ExpiredSessionResponse;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::middleware(['web', 'oauth.session'])->get('protected', fn () => 'ok');
});

function fakeOAuthService(?array $claims, bool $revoked = false): OAuthService
{
    $oauth = Mockery::mock(OAuthService::class)->makePartial();
    $oauth->shouldReceive('isExpired')->andReturnFalse();
    $oauth->shouldReceive('validateJwtLocally')->andReturn($claims);
    $oauth->shouldReceive('isRevoked')->andReturn($revoked);

    return $oauth;
}

it('lets guests through untouched', function () {
    $this->get('protected')->assertOk();
});

it('lets an authenticated user with a valid token through', function () {
    $this->app->instance(OAuthService::class, fakeOAuthService(['jti' => 'abc']));

    $this->actingAs(new GenericUser(['id' => 'user-1', 'remember_token' => null]))
        ->get('protected')
        ->assertOk();
});

it('logs out a user whose token fails verification', function () {
    $this->app->instance(OAuthService::class, fakeOAuthService(null));

    $this->actingAs(new GenericUser(['id' => 'user-1', 'remember_token' => null]))
        ->get('protected')
        ->assertRedirect(route('login'));
});

it('tells JSON clients when the session was revoked by another sign-in', function () {
    $this->app->instance(OAuthService::class, fakeOAuthService(['jti' => 'abc'], revoked: true));

    $this->actingAs(new GenericUser(['id' => 'user-1', 'remember_token' => null]))
        ->getJson('protected')
        ->assertUnauthorized()
        ->assertExactJson(['message' => ExpiredSessionResponse::REVOKED_MESSAGE]);
});
