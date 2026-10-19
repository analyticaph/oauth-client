<?php

namespace Analyticaph\OAuthClient\Http\Controllers;

use Analyticaph\OAuthClient\Contracts\OAuthUserResolver;
use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

/**
 * Handoff-token callback (`auth/complete`): redeems the one-time token the
 * auth server redirected back with, stores the OAuth tokens, and logs the
 * resolved local user in.
 */
class OAuthFinalizeController
{
    public function __invoke(Request $request, OAuthService $oauth, OAuthUserResolver $resolver): RedirectResponse
    {
        // Back/forward navigation: user is already authenticated, no need to redeem again.
        if (Auth::check()) {
            return redirect()->intended(route((string) config('oauth-client.after_login_route')));
        }

        try {
            $response = Http::connectTimeout(5)
                ->timeout(10)
                ->get(config('oauth-client.handoff_endpoint').'/'.$request->query('token'));
        } catch (ConnectionException $e) {
            // Auth server unreachable — log it and restart login instead of a 500.
            report($e);

            return redirect()->route((string) config('oauth-client.login_route'));
        }

        // Token expired, already redeemed, or missing — restart login gracefully.
        if ($response->failed()) {
            return redirect()->route((string) config('oauth-client.login_route'));
        }

        $data = $response->json();

        abort_unless(hash_equals((string) $request->session()->pull('oauth_nonce', ''), (string) ($data['nonce'] ?? '')), 403);

        $oauth->storeTokens([
            'access_token' => $data['access_token'],
            'refresh_token' => $data['refresh_token'],
            'expires_in' => $data['expires_in'],
        ]);

        Auth::login($resolver->resolve($data['user_data']));
        $request->session()->regenerate();

        return redirect()->to($data['final_url']);
    }
}
