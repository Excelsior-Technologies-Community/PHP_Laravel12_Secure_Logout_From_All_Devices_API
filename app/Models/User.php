<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Str;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
        'is_frozen',
        'frozen_at',
        'freeze_reason',
        'freeze_token',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'freeze_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'is_frozen' => 'boolean',
            'frozen_at' => 'datetime',
        ];
    }

    /**
     * Authentication activity history.
     */
    public function authActivities(): HasMany
    {
        return $this->hasMany(AuthActivity::class);
    }

    /**
     * Instantly freeze account and revoke all sessions (Kill Switch).
     */
    public function freeze(string $reason = 'Emergency account freeze requested'): string
    {
        $token = Str::random(40);

        $this->update([
            'is_frozen' => true,
            'frozen_at' => now(),
            'freeze_reason' => $reason,
            'freeze_token' => $token,
        ]);

        // Revoke all tokens across all devices
        $this->tokens()->delete();

        return $token;
    }

    /**
     * Unfreeze account.
     */
    public function unfreeze(): void
    {
        $this->update([
            'is_frozen' => false,
            'frozen_at' => null,
            'freeze_reason' => null,
            'freeze_token' => null,
        ]);
    }
}