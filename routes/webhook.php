<?php

use Analyticaph\OAuthClient\Http\Controllers\WebhookController;
use Illuminate\Support\Facades\Route;

Route::post('/api/auth/webhook/revoke', [WebhookController::class, 'revoke'])
    ->name('oauth.webhook.revoke');
