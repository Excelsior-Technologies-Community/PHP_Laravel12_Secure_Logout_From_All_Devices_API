<?php

namespace App\Models;

use Laravel\Sanctum\PersonalAccessToken as SanctumPersonalAccessToken;

class PersonalAccessToken extends SanctumPersonalAccessToken
{
    protected $fillable = [
        'name',
        'token',
        'abilities',
        'expires_at',
        'device_type',
        'browser',
        'os',
        'ip_address',
        'city',
        'country',
        'country_code',
        'is_suspicious',
        'last_active_at',
    ];

    protected function casts(): array
    {
        return array_merge(parent::casts(), [
            'is_suspicious' => 'boolean',
            'last_active_at' => 'datetime',
        ]);
    }
}
