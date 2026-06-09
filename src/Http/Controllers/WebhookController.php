<?php

namespace Analyticaph\OAuthClient\Http\Controllers;

use Analyticaph\OAuthClient\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class WebhookController
{
    public function __construct(
        private readonly OAuthService $oauth,
    ) {}

    public function revoke(Request $request): JsonResponse
    {
        $secret = (string) config('oauth-client.webhook_secret');
        $signature = (string) $request->header('X-Webhook-Signature', '');

        if (! $this->verifySignature($request->getContent(), $signature, $secret)) {
            return response()->json(['message' => 'Unauthorized.'], 401);
        }

        foreach ((array) $request->input('token_ids', []) as $jti) {
            if (is_string($jti) && $jti !== '') {
                $this->oauth->revokeToken($jti);
            }
        }

        return response()->json(['message' => 'OK.']);
    }

    private function verifySignature(string $rawBody, string $signatureHeader, string $secret): bool
    {
        if ($secret === '' || $signatureHeader === '') {
            return false;
        }

        $expected = 'sha256=' . hash_hmac('sha256', $rawBody, $secret);

        return hash_equals($expected, $signatureHeader);
    }
}
