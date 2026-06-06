<?php

namespace Analyticaph\OAuthClient\Http\Controllers;

use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class OAuthController
{
    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function redirect(Request $request): Response
    {
        $this->oauth->clearTokens();

        $finalUrl = (string) ($request->session()->pull('url.intended')
            ?: route((string) config('oauth-client.after_login_route')));

        return $this->externalRedirect($request, $this->oauth->authorizationUrl($finalUrl));
    }

    public function logout(Request $request): RedirectResponse
    {
        $this->oauth->clearTokens();

        Auth::logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $afterLogout = urlencode(route((string) config('oauth-client.after_logout_route')));
        $authLogoutUrl = rtrim((string) config('services.auth.server'), '/').'/logout?redirect='.$afterLogout;

        return redirect()->away($authLogoutUrl);
    }

    private function externalRedirect(Request $request, string $url): Response
    {
        if ($request->headers->has('X-Inertia')) {
            return response('', 409)->header('X-Inertia-Location', $url);
        }

        return redirect()->away($url);
    }
}
