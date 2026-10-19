<?php

use Analyticaph\OAuthClient\Http\Controllers\OAuthController;
use Analyticaph\OAuthClient\Http\Controllers\OAuthFinalizeController;
use Illuminate\Support\Facades\Route;

/*
 * Opt-in browser routes. Not auto-loaded — call OAuthClient::routes() from the
 * host app's routes/web.php so apps that still define their own login/logout
 * routes don't collide with these names.
 */

Route::middleware('guest')->group(function () {
    Route::get('login', [OAuthController::class, 'redirect'])
        ->name('login');
});

Route::get('auth/complete', OAuthFinalizeController::class)
    ->name('oauth.finalize');

Route::middleware('auth')->group(function () {
    Route::post('logout', [OAuthController::class, 'logout'])
        ->name('logout');

    Route::get('auth/profile', function () {
        return redirect()->away(rtrim((string) config('services.auth.server'), '/').'/settings');
    })->name('auth.profile');
});
