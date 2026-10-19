<?php

use Analyticaph\OAuthClient\Support\ExpiredSessionResponse;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::middleware('web')->get('expire', function (Request $request) {
        return ExpiredSessionResponse::respond($request);
    });
});

it('logs the user out and redirects browser requests to login', function () {
    $this->actingAs(new GenericUser(['id' => 'user-1', 'remember_token' => null]))
        ->get('expire')
        ->assertRedirect(route('login'));

    expect(Auth::check())->toBeFalse();
});

it('sends Inertia requests a full-page location visit', function () {
    $this->get('expire', ['X-Inertia' => 'true'])
        ->assertStatus(409)
        ->assertHeader('X-Inertia-Location', route('login'));
});

it('answers JSON requests with a 401 and the given message', function () {
    $this->getJson('expire')
        ->assertUnauthorized()
        ->assertExactJson(['message' => ExpiredSessionResponse::EXPIRED_MESSAGE]);
});

it('can render a TokenMismatchException as an expired session', function () {
    Route::middleware('web')->post('mutate', fn () => throw new TokenMismatchException);

    $this->app->make(ExceptionHandler::class)
        ->renderable(ExpiredSessionResponse::renderTokenMismatch(...));

    $this->post('mutate')->assertRedirect(route('login'));
});

it('leaves other HTTP exceptions to the default handler', function () {
    Route::middleware('web')->get('missing', fn () => abort(404));

    $this->app->make(ExceptionHandler::class)
        ->renderable(ExpiredSessionResponse::renderTokenMismatch(...));

    $this->get('missing')->assertNotFound();
});
