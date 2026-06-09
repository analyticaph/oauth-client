<?php

namespace Analyticaph\OAuthClient\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OAuthService
{
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
        return Http::post(
            rtrim((string) config('services.auth.server'), '/') . '/oauth/token',
            [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id'     => config('services.auth.client_id'),
                'client_secret' => config('services.auth.client_secret'),
            ]
        )->throw()->json();
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
        if (! $token) {
            return null;
        }

        $jwks = $this->fetchJwks();
        if (! $jwks) {
            return null;
        }

        try {
            $keySet = JWK::parseKeySet($jwks, 'RS256');
            $claims = (array) JWT::decode($token, $keySet);

            return $claims;
        } catch (\Throwable) {
            return null;
        }
    }

    public function isRevoked(string $jti): bool
    {
        return Cache::has($this->revokedCacheKey($jti));
    }

    public function revokeToken(string $jti): void
    {
        Cache::put(
            $this->revokedCacheKey($jti),
            true,
            (int) config('oauth-client.revoked_token_ttl', 86400)
        );
    }

    private function fetchJwks(): ?array
    {
        $cached = Cache::get('oauth:jwks');
        if ($cached !== null) {
            return $cached;
        }

        $response = Http::get(rtrim((string) config('services.auth.server'), '/') . '/oauth/jwks');
        if (! $response->successful()) {
            return null;
        }

        $jwks = $response->json();
        Cache::put('oauth:jwks', $jwks, (int) config('oauth-client.jwks_cache_ttl', 3600));

        return $jwks;
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
