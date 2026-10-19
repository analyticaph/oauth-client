<?php

namespace Analyticaph\OAuthClient\Http\Middleware;

use Analyticaph\OAuthClient\Services\OAuthService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Stateless API guard (`oauth.bearer`): verifies the request's bearer token
 * locally against the JWKS and the revocation list, then exposes the decoded
 * claims as the `oauth_claims` request attribute. Switching to the token's
 * tenant and binding a local user stay with the host app.
 */
class EnsureValidApiBearerToken
{
    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $accessToken = $request->bearerToken();

        if (blank($accessToken)) {
            return $this->unauthorized();
        }

        $claims = $this->oauth->verifyBearerToken($accessToken);

        if ($claims === null) {
            return $this->unauthorized();
        }

        $jti = $claims['jti'] ?? null;
        if ($jti !== null && $this->oauth->isRevoked((string) $jti)) {
            return $this->unauthorized();
        }

        $request->attributes->set('oauth_claims', $claims);

        return $next($request);
    }

    private function unauthorized(): Response
    {
        return response()->json([
            'status' => 'error',
            'message' => 'Invalid or expired bearer token.',
        ], 401);
    }
}
