<?php

namespace Analyticaph\OAuthClient\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OAuthService
{
    private const JWKS_CACHE_KEY = 'oauth:jwks';
    private const JWKS_LAST_GOOD_CACHE_KEY = 'oauth:jwks:last_good';
    private const JWKS_BACKOFF_CACHE_KEY = 'oauth:jwks:backoff';
    private const JWKS_BACKOFF_SECONDS = 60;
    private const JWKS_REFRESH_LOCK_KEY = 'oauth:jwks:refresh';
    private const JWKS_REFRESH_LOCK_SECONDS = 10;
    private const TOKEN_REFRESH_LOCK_SECONDS = 15;
    private const TOKEN_REFRESH_WAIT_SECONDS = 6;
    private const TOKEN_REFRESH_RESULT_SECONDS = 30;

    public function authorizationUrl(string $finalUrl): string
    {
        $nonce = Str::random(40);
        session(['oauth_nonce' => $nonce]);

        $state = rtrim(strtr(base64_encode(json_encode([
            'nonce'     => $nonce,
            'final_url' => $finalUrl,
        ])), '+/', '-_'), '=');

        $deviceType = $this->detectDeviceType((string) (request()->userAgent() ?? ''));

        $redirectUri = rtrim((string) config('services.auth.server'), '/') . '/oauth/callback';

        $query = http_build_query(array_filter([
            'client_id'     => config('services.auth.client_id'),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'scope'         => implode(' ', (array) config('services.auth.scopes')),
            'state'         => $state,
            'device_hint'   => $deviceType,
            'device_id'     => request()->cookie('sc_device_id') ?? request()->query('device_id'),
        ], fn($v) => $v !== null && $v !== ''));

        return rtrim((string) config('services.auth.server'), '/') . '/oauth/authorize?' . $query;
    }

    public function refreshToken(string $refreshToken): array
    {
        return $this->authServer()->post(
            rtrim((string) config('services.auth.server'), '/') . '/oauth/token',
            [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id'     => config('services.auth.client_id'),
                'client_secret' => config('services.auth.client_secret'),
            ]
        )->throw()->json();
    }

    /**
     * Refresh tokens at most once per refresh token, however many requests ask.
     *
     * Concurrent requests from one session (autosave + page load) all carry the
     * same refresh token once the access token nears expiry. With refresh-token
     * rotation only the first exchange succeeds, so the rest would fail and log
     * the user out. The first caller takes a lock and exchanges; the others wait
     * for it and reuse the result, which is kept briefly for stragglers.
     *
     * The wait outlasts the auth-server timeout (5s), so a waiter only gives up
     * when the lock holder itself died.
     *
     * @throws \Illuminate\Http\Client\ConnectionException
     * @throws \Illuminate\Contracts\Cache\LockTimeoutException
     */
    public function refreshStoredTokens(string $refreshToken): array
    {
        $key = 'oauth:refresh:' . hash('sha256', $refreshToken);

        if (is_array($tokens = $this->cache()->get("{$key}:result"))) {
            return $tokens;
        }

        return $this->cache()->lock("{$key}:lock", self::TOKEN_REFRESH_LOCK_SECONDS)
            ->block(self::TOKEN_REFRESH_WAIT_SECONDS, function () use ($key, $refreshToken) {
                if (is_array($tokens = $this->cache()->get("{$key}:result"))) {
                    return $tokens;
                }

                $tokens = $this->refreshToken($refreshToken);
                $this->cache()->put("{$key}:result", $tokens, self::TOKEN_REFRESH_RESULT_SECONDS);

                return $tokens;
            });
    }

    public function storeTokens(array $tokenData): void
    {
        $expiresAt = isset($tokenData['expires_at'])
            ? (int) $tokenData['expires_at']
            : now()->addSeconds((int) ($tokenData['expires_in'] ?? 3600))->timestamp;

        session([
            (string) config('oauth-client.token_session_key') => [
                'access_token'  => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'] ?? null,
                'expires_at'    => $expiresAt,
            ],
        ]);
    }

    public function getAccessToken(): ?string
    {
        return $this->stored()['access_token'] ?? null;
    }

    public function getRefreshToken(): ?string
    {
        return $this->stored()['refresh_token'] ?? null;
    }

    public function isExpired(): bool
    {
        $expiresAt = $this->stored()['expires_at'] ?? null;

        if ($expiresAt === null) {
            return true;
        }

        return now()->timestamp >= ($expiresAt - (int) config('oauth-client.refresh_buffer_seconds'));
    }

    public function clearTokens(): void
    {
        session()->forget((string) config('oauth-client.token_session_key'));
    }

    /**
     * Verify the stored access token's signature locally using the JWKS public-key
     * set. Returns the decoded claims on success, or null on any failure.
     *
     * @return array<string, mixed>|null
     */
    public function validateJwtLocally(): ?array
    {
        $token = $this->getAccessToken();

        return $token ? $this->verifyBearerToken($token) : null;
    }

    /**
     * Verify an arbitrary bearer token string (not session-bound) locally using the
     * JWKS public-key set. For stateless API consumers with no HTTP session.
     * Returns the decoded claims on success, or null on any failure (invalid
     * signature, malformed token, or expiry — JWT::decode() throws on an expired
     * `exp` claim, caught below).
     *
     * @return array<string, mixed>|null
     */
    public function verifyBearerToken(string $token): ?array
    {
        $jwks = $this->fetchJwks();
        if (! $jwks) {
            return null;
        }

        try {
            $keySet = JWK::parseKeySet($jwks, 'RS256');

            return (array) JWT::decode($token, $keySet);
        } catch (\Throwable) {
            return null;
        }
    }

    public function isRevoked(string $jti): bool
    {
        return $this->cache()->has($this->revokedCacheKey($jti));
    }

    public function revokeToken(string $jti): void
    {
        $this->cache()->put(
            $this->revokedCacheKey($jti),
            true,
            (int) config('oauth-client.revoked_token_ttl', 86400)
        );
    }

    /**
     * Fetch the JWKS, cached for jwks_cache_ttl (stale-while-revalidate).
     *
     * When the cached set has expired but a last-good copy exists, that copy is
     * returned immediately. The one request that wins the refresh lock schedules a
     * refetch to run after its response is sent, so no request waits on the auth
     * server. terminating() is used rather than defer() because Laravel 10 is
     * still supported.
     *
     * With no last-good copy (cold start or cache flush), the fetch happens
     * synchronously. A failed fetch skips refetching for JWKS_BACKOFF_SECONDS, so
     * an unreachable auth server doesn't cost a timeout on every request.
     */
    private function fetchJwks(): ?array
    {
        $cached = $this->cache()->get(self::JWKS_CACHE_KEY);
        if ($cached !== null) {
            return $cached;
        }

        $lastGood = $this->cache()->get(self::JWKS_LAST_GOOD_CACHE_KEY);
        if ($lastGood !== null) {
            if (! $this->cache()->has(self::JWKS_BACKOFF_CACHE_KEY)) {
                $lock = $this->cache()->lock(self::JWKS_REFRESH_LOCK_KEY, self::JWKS_REFRESH_LOCK_SECONDS);

                if ($lock->get()) {
                    app()->terminating(function () use ($lock) {
                        try {
                            $this->refreshJwks();
                        } finally {
                            $lock->release();
                        }
                    });
                }
            }

            return $lastGood;
        }

        if ($this->cache()->has(self::JWKS_BACKOFF_CACHE_KEY)) {
            return null;
        }

        return $this->refreshJwks();
    }

    /**
     * Fetch the JWKS from the auth server and store it as both the fresh and the
     * last-good copy. On failure, set the backoff flag and return null.
     */
    private function refreshJwks(): ?array
    {
        try {
            $response = $this->authServer()->get(rtrim((string) config('services.auth.server'), '/') . '/oauth/jwks');
            $jwks = $response->successful() ? $response->json() : null;
        } catch (ConnectionException) {
            $jwks = null;
        }

        if (! is_array($jwks)) {
            $this->cache()->put(self::JWKS_BACKOFF_CACHE_KEY, true, self::JWKS_BACKOFF_SECONDS);

            return null;
        }

        $this->cache()->put(self::JWKS_CACHE_KEY, $jwks, (int) config('oauth-client.jwks_cache_ttl', 86400));
        $this->cache()->forever(self::JWKS_LAST_GOOD_CACHE_KEY, $jwks);

        return $jwks;
    }

    /**
     * Store for revocations, the JWKS and refresh locks. These must read and
     * write the same keys whatever tenant is current: the revoke webhook runs
     * without a tenant, while web requests check revocations after tenancy has
     * re-prefixed the default store. A store with its own `prefix` keeps one
     * keyspace. Null falls back to the default store.
     */
    private function cache(): Repository
    {
        return Cache::store(config('oauth-client.cache_store'));
    }

    private function authServer(): PendingRequest
    {
        return Http::connectTimeout(2)->timeout(5);
    }

    private function revokedCacheKey(string $jti): string
    {
        return 'oauth:revoked:' . $jti;
    }

    private function detectDeviceType(string $userAgent): string
    {
        return preg_match('/Mobile|Android|iPhone|iPad|iPod|BlackBerry|Windows Phone/i', $userAgent)
            ? 'mobile'
            : 'desktop';
    }

    private function stored(): array
    {
        /** @var array<string, mixed> */
        return session((string) config('oauth-client.token_session_key'), []);
    }
}
