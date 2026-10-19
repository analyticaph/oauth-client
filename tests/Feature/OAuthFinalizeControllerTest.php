<?php

use Analyticaph\OAuthClient\Contracts\OAuthUserResolver;
use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->app->instance(OAuthUserResolver::class, new class implements OAuthUserResolver
    {
        public function resolve(array $userData): Authenticatable
        {
            return new GenericUser(['id' => $userData['id'], 'password' => '', 'remember_token' => null]);
        }
    });
});

it('logs the user in and regenerates the session after a successful handoff', function () {
    Http::fake(['auth.test/*' => Http::response([
        'nonce' => 'expected-nonce',
        'access_token' => 'access',
        'refresh_token' => 'refresh',
        'expires_in' => 3600,
        'user_data' => ['id' => 'user-1'],
        'final_url' => 'https://tenant.test/dashboard',
    ])]);

    $this->withSession(['oauth_nonce' => 'expected-nonce']);
    $sessionIdBefore = session()->getId();

    $this->get('auth/complete?token=abc')
        ->assertRedirect('https://tenant.test/dashboard');

    expect(Auth::id())->toBe('user-1')
        ->and(session()->getId())->not->toBe($sessionIdBefore)
        ->and(app(OAuthService::class)->getAccessToken())->toBe('access');
});

it('rejects a handoff whose nonce does not match the session', function () {
    Http::fake(['auth.test/*' => Http::response([
        'nonce' => 'attacker-nonce',
        'access_token' => 'access',
        'refresh_token' => 'refresh',
        'expires_in' => 3600,
        'user_data' => ['id' => 'user-1'],
        'final_url' => 'https://tenant.test/dashboard',
    ])]);

    $this->withSession(['oauth_nonce' => 'expected-nonce'])
        ->get('auth/complete?token=abc')
        ->assertForbidden();

    expect(Auth::check())->toBeFalse();
});

it('restarts login when the handoff token is expired or already redeemed', function () {
    Http::fake(['auth.test/*' => Http::response(['message' => 'Not found.'], 404)]);

    $this->get('auth/complete?token=stale')
        ->assertRedirect(route('login'));
});

it('restarts login instead of erroring when the auth server is unreachable', function () {
    Http::fake(fn () => throw new ConnectionException('Connection refused'));

    $this->get('auth/complete?token=abc')
        ->assertRedirect(route('login'));

    expect(Auth::check())->toBeFalse();
});

it('skips redemption when the user is already authenticated', function () {
    Http::fake();

    $this->actingAs(new GenericUser(['id' => 'user-1', 'remember_token' => null]))
        ->get('auth/complete?token=abc')
        ->assertRedirect(route('dashboard'));

    Http::assertNothingSent();
});
