<?php

namespace Analyticaph\OAuthClient\Http\Middleware;

use Analyticaph\OAuthClient\Services\OAuthService;
use Analyticaph\OAuthClient\Support\ExpiredSessionResponse;
use Closure;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Web-group guard: force-logs-out a locally authenticated user whose OAuth
 * session is expired (and unrefreshable), fails JWKS verification, or was
 * revoked by the auth server's webhook. Guests pass straight through.
 *
 * Register it before ValidateCsrfToken where the app rebuilds its web group,
 * so a revoked session is reported as such instead of surfacing as a 419.
 */
class EnsureOAuthSessionActive
{
    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! Auth::check()) {
            return $next($request);
        }

        if ($this->oauth->isExpired() && ! $this->attemptRefresh()) {
            return $this->invalidate($request);
        }

        $claims = $this->oauth->validateJwtLocally();

        if ($claims === null) {
            return $this->invalidate($request);
        }

        $jti = $claims['jti'] ?? null;
        if ($jti !== null && $this->oauth->isRevoked((string) $jti)) {
            return $this->invalidate($request, ExpiredSessionResponse::REVOKED_MESSAGE);
        }

        return $next($request);
    }

    private function attemptRefresh(): bool
    {
        $refreshToken = $this->oauth->getRefreshToken();

        if (! $refreshToken) {
            return false;
        }

        try {
            $tokens = $this->oauth->refreshToken($refreshToken);
            $this->oauth->storeTokens($tokens);

            return true;
        } catch (ConnectionException) {
            // Auth server unreachable — keep the session rather than logging
            // everyone out during an outage; the JWT check below still applies.
            return true;
        } catch (Throwable) {
            return false;
        }
    }

    private function invalidate(Request $request, string $message = ExpiredSessionResponse::EXPIRED_MESSAGE): Response
    {
        $this->oauth->clearTokens();

        return ExpiredSessionResponse::respond($request, $message);
    }
}
