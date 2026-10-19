<?php

use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::middleware('oauth.bearer')->get('api/me', fn (Request $request) => $request->attributes->get('oauth_claims'));
});

function fakeBearerService(?array $claims, bool $revoked = false): OAuthService
{
    $oauth = Mockery::mock(OAuthService::class)->makePartial();
    $oauth->shouldReceive('verifyBearerToken')->andReturn($claims);
    $oauth->shouldReceive('isRevoked')->andReturn($revoked);

    return $oauth;
}

it('rejects requests without a bearer token', function () {
    $this->getJson('api/me')->assertUnauthorized();
});

it('rejects tokens that fail verification', function () {
    $this->app->instance(OAuthService::class, fakeBearerService(null));

    $this->getJson('api/me', ['Authorization' => 'Bearer bad'])->assertUnauthorized();
});

it('rejects revoked tokens', function () {
    $this->app->instance(OAuthService::class, fakeBearerService(['jti' => 'abc'], revoked: true));

    $this->getJson('api/me', ['Authorization' => 'Bearer good'])->assertUnauthorized();
});

it('exposes verified claims to the request', function () {
    $this->app->instance(OAuthService::class, fakeBearerService(['jti' => 'abc', 'sub' => 'user-1']));

    $this->getJson('api/me', ['Authorization' => 'Bearer good'])
        ->assertOk()
        ->assertJson(['sub' => 'user-1']);
});
