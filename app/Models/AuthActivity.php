<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuthActivity extends Model
{
    protected $fillable = [
        'user_id',
        'token_id',
        'action',
        'ip_address',
        'user_agent',
    ];

    /**
     * Activity belongs to a user.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}