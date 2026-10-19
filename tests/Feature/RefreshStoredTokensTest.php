<?php

use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    config(['cache.default' => 'array']);
});

it('exchanges a refresh token only once and reuses the result', function () {
    Http::fake([
        'auth.test/oauth/token' => Http::response([
            'access_token' => 'new-access',
            'refresh_token' => 'new-refresh',
            'expires_in' => 3600,
        ]),
    ]);

    $oauth = app(OAuthService::class);

    $first = $oauth->refreshStoredTokens('old-refresh');
    $second = $oauth->refreshStoredTokens('old-refresh');

    expect($first['access_token'])->toBe('new-access')
        ->and($second)->toBe($first);

    Http::assertSentCount(1);
});

it('exchanges different refresh tokens independently', function () {
    Http::fake([
        'auth.test/oauth/token' => Http::response(['access_token' => 'new-access', 'expires_in' => 3600]),
    ]);

    $oauth = app(OAuthService::class);

    $oauth->refreshStoredTokens('refresh-a');
    $oauth->refreshStoredTokens('refresh-b');

    Http::assertSentCount(2);
});

it('propagates a connection failure without caching it', function () {
    $calls = 0;

    Http::fake([
        'auth.test/oauth/token' => function () use (&$calls) {
            if (++$calls === 1) {
                throw new ConnectionException('unreachable');
            }

            return Http::response(['access_token' => 'new-access', 'expires_in' => 3600]);
        },
    ]);

    $oauth = app(OAuthService::class);

    expect(fn () => $oauth->refreshStoredTokens('old-refresh'))->toThrow(ConnectionException::class)
        ->and($oauth->refreshStoredTokens('old-refresh')['access_token'])->toBe('new-access')
        ->and($calls)->toBe(2);
});
