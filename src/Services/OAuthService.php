<?php

namespace Analyticaph\OAuthClient\Services;

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

        $query = http_build_query([
            'client_id'     => config('services.auth.client_id'),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'scope'         => implode(' ', (array) config('services.auth.scopes')),
            'state'         => $state,
            'device_hint'   => $deviceType,
        ]);

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
