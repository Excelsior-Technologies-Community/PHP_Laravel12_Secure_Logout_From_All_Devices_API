<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Laravel\Sanctum\PersonalAccessToken;

class AuthActivity extends Model
{
    protected $fillable = [
        'user_id',
        'token_id',
        'action',
        'ip_address',
        'user_agent',
        'device_type',
        'browser',
        'os',
        'city',
        'country',
        'country_code',
        'is_suspicious',
        'risk_score',
        'risk_reason',
    ];

    protected function casts(): array
    {
        return [
            'is_suspicious' => 'boolean',
            'risk_score' => 'integer',
        ];
    }

    /**
     * Activity belongs to a user.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Activity belongs to a Sanctum token.
     */
    public function token(): BelongsTo
    {
        return $this->belongsTo(
            PersonalAccessToken::class,
            'token_id'
        );
    }
}