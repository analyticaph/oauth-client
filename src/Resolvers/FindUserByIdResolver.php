<?php

namespace Analyticaph\OAuthClient\Resolvers;

use Analyticaph\OAuthClient\Contracts\OAuthUserResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Default OAuthUserResolver: the auth server's user id is the tenant-side
 * user UUID, so the local user is a direct lookup on the auth provider's
 * model. Roles and permissions are not synced here — they live in the
 * tenant DB (written by the console) and are resolved per request.
 *
 * Host apps that need more can bind their own OAuthUserResolver.
 */
class FindUserByIdResolver implements OAuthUserResolver
{
    /**
     * @param  array<string, mixed>  $userData
     */
    public function resolve(array $userData): Authenticatable
    {
        /** @var class-string<Model&Authenticatable> $model */
        $model = config('auth.providers.users.model');

        return $model::query()->findOrFail($userData['id']);
    }
}
