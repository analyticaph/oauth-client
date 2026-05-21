<?php

namespace SmartCampus\OAuthClient\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use SmartCampus\OAuthClient\Contracts\OAuthUserResolver;
use SmartCampus\OAuthClient\Services\OAuthService;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class OAuthController
{
    private const STATE_SESSION_KEY = 'oauth_state';

    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function redirect(Request $request): Response
    {
        $this->oauth->clearTokens();

        $state = Str::random(40);
        $request->session()->put(self::STATE_SESSION_KEY, $state);

        return $this->externalRedirect(
            $request,
            $this->oauth->authorizationUrl($this->redirectUri(), $state)
        );
    }

    public function callback(Request $request): RedirectResponse
    {
        try {
            if ($request->has('error')) {
                return $this->redirectWithError(
                    'OAuth error: '.$request->input('error_description', 'Unknown error')
                );
            }

            if (! $this->hasValidState($request)) {
                return $this->redirectWithError('OAuth state validation failed.');
            }

            $code = $request->input('code');
            if (! $code) {
                return $this->redirectWithError('Authorization code missing.');
            }

            $tokenData = $this->oauth->exchangeCode((string) $code, $this->redirectUri());
            $this->oauth->storeTokens($tokenData);

            $userData = $this->oauth->fetchUser($tokenData['access_token']);
            $user = app(OAuthUserResolver::class)->resolve($userData);

            Auth::login($user);

            return redirect()->intended(route((string) config('oauth-client.after_login_route')));
        } catch (Throwable $e) {
            $this->oauth->clearTokens();

            Log::error('oauth-client.callback.failed', [
                'session_id' => $request->session()->getId(),
                'message' => $e->getMessage(),
            ]);

            return $this->redirectWithError('Authentication failed: '.$e->getMessage());
        }
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

    private function redirectUri(): string
    {
        return (string) (config('services.auth.redirect_uri')
            ?: route((string) config('oauth-client.callback_route')));
    }

    private function hasValidState(Request $request): bool
    {
        $expected = (string) $request->session()->pull(self::STATE_SESSION_KEY, '');
        $actual = (string) $request->input('state', '');

        return $expected !== '' && $actual !== '' && hash_equals($expected, $actual);
    }

    private function externalRedirect(Request $request, string $url): Response
    {
        if ($request->headers->has('X-Inertia')) {
            return response('', 409)->header('X-Inertia-Location', $url);
        }

        return redirect()->away($url);
    }

    private function redirectWithError(string $message): RedirectResponse
    {
        return redirect()
            ->route((string) config('oauth-client.error_route'))
            ->with('error', $message);
    }
}
