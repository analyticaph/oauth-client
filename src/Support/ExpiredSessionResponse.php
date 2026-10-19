<?php

namespace Analyticaph\OAuthClient\Support;

use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Shared "the session is no longer valid" response, used by
 * EnsureOAuthSessionActive (OAuth token expired/revoked) and by the host
 * app's 419 handler (CSRF/session mismatch or ordinary idle expiry):
 *
 *     $exceptions->render(ExpiredSessionResponse::renderTokenMismatch(...));
 *
 * Logs the user out and resets the local session, then degrades gracefully
 * per request type instead of dead-ending on a raw error page.
 */
class ExpiredSessionResponse
{
    public const EXPIRED_MESSAGE = 'Session expired.';

    public const REVOKED_MESSAGE = 'You were signed out because your account was signed in from another device.';

    public static function respond(Request $request, string $message = self::EXPIRED_MESSAGE): Response
    {
        Auth::logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        $loginUrl = route((string) config('oauth-client.login_route'));

        // Inertia XHR requests satisfy expectsJson() but cannot follow a JSON
        // 401 — they need a full browser redirect via X-Inertia-Location (409).
        if ($request->headers->has('X-Inertia')) {
            return response('', 409)->header('X-Inertia-Location', $loginUrl);
        }

        if ($request->expectsJson() || $request->headers->get('X-Requested-With') === 'XMLHttpRequest') {
            return response()->json(['message' => $message], 401);
        }

        return redirect($loginUrl);
    }

    /**
     * Render callback for the host app's exception handler. Laravel converts
     * TokenMismatchException into a 419 HttpException before render callbacks
     * run, so a callback type-hinted on TokenMismatchException never fires —
     * this one matches the converted exception instead.
     */
    public static function renderTokenMismatch(HttpException $e, Request $request): ?Response
    {
        if (! $e->getPrevious() instanceof TokenMismatchException) {
            return null;
        }

        return self::respond($request);
    }
}
