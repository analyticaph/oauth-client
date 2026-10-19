<?php

use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Support\Facades\Cache;

beforeEach(function () {
    config([
        'cache.default' => 'array',
        'cache.stores.oauth' => ['driver' => 'array'],
    ]);
});

it('keeps revocations in the configured store', function () {
    config(['oauth-client.cache_store' => 'oauth']);

    $oauth = app(OAuthService::class);
    $oauth->revokeToken('jti-1');

    expect($oauth->isRevoked('jti-1'))->toBeTrue()
        ->and(Cache::store('oauth')->has('oauth:revoked:jti-1'))->toBeTrue()
        ->and(Cache::store('array')->has('oauth:revoked:jti-1'))->toBeFalse();
});

it('falls back to the default store when none is configured', function () {
    config(['oauth-client.cache_store' => null]);

    app(OAuthService::class)->revokeToken('jti-2');

    expect(Cache::store('array')->has('oauth:revoked:jti-2'))->toBeTrue();
});
