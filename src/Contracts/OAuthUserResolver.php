<?php

namespace SmartCampus\OAuthClient\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface OAuthUserResolver
{
    /**
     * Resolve the host application's authenticatable user from auth-server data.
     *
     * @param  array<string, mixed>  $userData
     */
    public function resolve(array $userData): Authenticatable;
}
