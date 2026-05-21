<?php

namespace Analyticaph\OAuthClient\Services;

use Illuminate\Support\Facades\Http;

class OAuthService
{
    public function authorizationUrl(string $redirectUri, ?string $state = null): string
    {
        $query = http_build_query(array_filter([
            'client_id'     => config('services.auth.client_id'),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'scope'         => implode(' ', (array) config('services.auth.scopes')),
            'state'         => $state,
        ], fn ($value) => $value !== null && $value !== ''));

        return rtrim((string) config('services.auth.server'), '/') . '/oauth/authorize?' . $query;
    }

    public function exchangeCode(string $code, string $redirectUri): array
    {
        return Http::post(
            rtrim((string) config('services.auth.server'), '/') . '/oauth/token',
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => config('services.auth.client_id'),
                'client_secret' => config('services.auth.client_secret'),
                'redirect_uri'  => $redirectUri,
                'code'          => $code,
            ]
        )->throw()->json();
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

    public function fetchUser(string $accessToken): array
    {
        return Http::withToken($accessToken)
            ->get(rtrim((string) config('services.auth.server'), '/') . '/api/user')
            ->throw()
            ->json();
    }

    public function storeTokens(array $tokenData): void
    {
        session([
            (string) config('oauth-client.token_session_key') => [
                'access_token'  => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'] ?? null,
                'expires_at'    => now()->addSeconds($tokenData['expires_in'] ?? 3600)->timestamp,
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

    private function stored(): array
    {
        /** @var array<string, mixed> */
        return session((string) config('oauth-client.token_session_key'), []);
    }
}
