<?php

namespace SmartCampus\OAuthClient\Services;

class RolePermissionSyncService
{
    /**
     * Persist the roles and permissions from the /api/user response into the
     * session so they are available without an API call on every request.
     */
    public function sync(array $user): void
    {
        session([
            config('oauth-client.user_session_key') => [
                'id'          => $user['id'],
                'name'        => $user['name'],
                'email'       => $user['email'] ?? null,
                'roles'       => $user['roles'] ?? [],
                'permissions' => $user['permissions'] ?? [],
            ],
        ]);
    }

    public function clear(): void
    {
        session()->forget(config('oauth-client.user_session_key'));
    }

    public function hasRole(string|array $roles): bool
    {
        $stored = $this->getRoles();

        foreach ((array) $roles as $role) {
            if (in_array($role, $stored, true)) {
                return true;
            }
        }

        return false;
    }

    public function hasPermission(string|array $permissions): bool
    {
        $stored = $this->getPermissions();

        foreach ((array) $permissions as $permission) {
            if (in_array($permission, $stored, true)) {
                return true;
            }
        }

        return false;
    }

    public function getRoles(): array
    {
        return $this->stored()['roles'] ?? [];
    }

    public function getPermissions(): array
    {
        return $this->stored()['permissions'] ?? [];
    }

    public function user(): array
    {
        return $this->stored();
    }

    private function stored(): array
    {
        return session(config('oauth-client.user_session_key'), []);
    }
}
