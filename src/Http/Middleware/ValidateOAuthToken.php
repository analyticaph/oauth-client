<?php

namespace Analyticaph\OAuthClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Analyticaph\OAuthClient\Services\OAuthService;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class ValidateOAuthToken
{
    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $accessToken = $this->oauth->getAccessToken();

        if (! $accessToken) {
            return $this->redirectToLogin($request);
        }

        if ($this->oauth->isExpired()) {
            $refreshToken = $this->oauth->getRefreshToken();

            if (! $refreshToken) {
                $this->clearAndForget();

                return $this->redirectToLogin($request);
            }

            if (! $this->attemptRefresh($refreshToken)) {
                $this->clearAndForget();

                return $this->redirectToLogin($request);
            }
        }

        $claims = $this->oauth->validateJwtLocally();

        if ($claims === null) {
            $this->clearAndForget();

            return $this->redirectToLogin($request);
        }

        $jti = $claims['jti'] ?? null;
        if ($jti !== null && $this->oauth->isRevoked((string) $jti)) {
            $this->clearAndForget();

            return $this->redirectToLogin($request);
        }

        if (! $this->oauth->isTokenValidOnServer()) {
            $this->clearAndForget();

            return $this->redirectToLogin($request);
        }

        return $next($request);
    }

    private function attemptRefresh(string $refreshToken): bool
    {
        try {
            $tokens = $this->oauth->refreshToken($refreshToken);

            $this->oauth->storeTokens($tokens);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    private function clearAndForget(): void
    {
        $this->oauth->clearTokens();
    }

    private function redirectToLogin(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return redirect()->route(config('oauth-client.login_route'));
    }
}
