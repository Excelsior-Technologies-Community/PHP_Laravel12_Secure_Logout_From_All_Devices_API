<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\AuthActivity;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Register a new user.
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6',
            'device_name' => 'nullable|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $deviceName = $request->device_name ?? 'Unknown Device';

        $accessToken = $user->createToken($deviceName);

        $this->recordActivity(
            $user,
            $accessToken->accessToken->id,
            'REGISTER',
            $request
        );

        return response()->json([
            'status' => true,
            'message' => 'User registered successfully',
            'token' => $accessToken->plainTextToken,
            'token_id' => $accessToken->accessToken->id,
            'device_name' => $deviceName,
            'user' => $user,
        ], 201);
    }

    /**
     * Login user and create a new device session.
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
            'device_name' => 'required|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid credentials',
            ], 401);
        }

        $accessToken = $user->createToken($request->device_name);

        $this->recordActivity(
            $user,
            $accessToken->accessToken->id,
            'LOGIN',
            $request
        );

        return response()->json([
            'status' => true,
            'message' => 'Login successful',
            'token' => $accessToken->plainTextToken,
            'token_id' => $accessToken->accessToken->id,
            'device_name' => $request->device_name,
            'user' => $user,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 1. Current User Profile
    |--------------------------------------------------------------------------
    */

    /**
     * Get currently authenticated user.
     */
    public function me(Request $request)
    {
        $user = $request->user();

        return response()->json([
            'status' => true,
            'message' => 'Authenticated user retrieved successfully',
            'user' => $user,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Existing Logout APIs
    |--------------------------------------------------------------------------
    */

    /**
     * Logout current device.
     */
    public function logout(Request $request)
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        $tokenId = $currentToken?->id;

        $this->recordActivity(
            $user,
            $tokenId,
            'LOGOUT',
            $request
        );

        if ($currentToken) {
            $currentToken->delete();
        }

        return response()->json([
            'status' => true,
            'message' => 'Logged out from current device',
        ]);
    }

    /**
     * Logout from all devices.
     */
    public function logoutAll(Request $request)
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        $currentTokenId = $currentToken?->id;

        $this->recordActivity(
            $user,
            $currentTokenId,
            'LOGOUT_ALL_DEVICES',
            $request
        );

        $user->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Logged out from all devices',
        ]);
    }

    /**
     * Logout from all other devices except current device.
     */
    public function logoutOthers(Request $request)
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        if (!$currentToken) {
            return response()->json([
                'status' => false,
                'message' => 'Current authentication token not found',
            ], 401);
        }

        $currentTokenId = $currentToken->id;

        $otherTokens = $user->tokens()
            ->where('id', '!=', $currentTokenId)
            ->get();

        foreach ($otherTokens as $token) {
            $this->recordActivity(
                $user,
                $token->id,
                'LOGOUT_OTHER_DEVICES',
                $request
            );
        }

        $user->tokens()
            ->where('id', '!=', $currentTokenId)
            ->delete();

        return response()->json([
            'status' => true,
            'message' => 'Logged out from other devices',
            'current_token_id' => $currentTokenId,
            'revoked_sessions' => $otherTokens->count(),
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Existing Device Management
    |--------------------------------------------------------------------------
    */

    /**
     * Get all currently active device sessions.
     */
    public function activeDevices(Request $request)
    {
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated',
            ], 401);
        }

        $currentToken = $user->currentAccessToken();
        $currentTokenId = $currentToken?->id;

        $tokens = $user->tokens()
            ->orderByDesc('last_used_at')
            ->get();

        $devices = $tokens->map(function ($token) use ($currentTokenId) {
            return [
                'token_id' => $token->id,
                'device_name' => $token->name,
                'abilities' => $token->abilities,
                'last_used_at' => $token->last_used_at,
                'created_at' => $token->created_at,
                'expires_at' => $token->expires_at,
                'is_current_device' => (int) $token->id === (int) $currentTokenId,
            ];
        })->values();

        return response()->json([
            'status' => true,
            'message' => 'Active device sessions retrieved successfully',
            'total_devices' => $devices->count(),
            'devices' => $devices,
        ]);
    }
    /**
     * Revoke a specific device session.
     */
    public function revokeDevice(Request $request, int $tokenId)
    {
        $user = $request->user();

        $token = $user->tokens()
            ->where('id', $tokenId)
            ->first();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Device session not found',
            ], 404);
        }

        $isCurrentDevice =
            $user->currentAccessToken()?->id === $token->id;

        $this->recordActivity(
            $user,
            $token->id,
            'DEVICE_REVOKED',
            $request
        );

        $deviceName = $token->name;

        $token->delete();

        return response()->json([
            'status' => true,
            'message' => 'Device session revoked successfully',
            'token_id' => $tokenId,
            'device_name' => $deviceName,
            'was_current_device' => $isCurrentDevice,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 2. Change Password
    |--------------------------------------------------------------------------
    */

    /**
     * Change password and revoke all existing sessions.
     */
    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = $request->user();

        if (!Hash::check(
            $request->current_password,
            $user->password
        )) {
            return response()->json([
                'status' => false,
                'message' => 'Current password is incorrect',
            ], 422);
        }

        if (Hash::check(
            $request->new_password,
            $user->password
        )) {
            return response()->json([
                'status' => false,
                'message' => 'New password must be different from current password',
            ], 422);
        }

        $user->password = Hash::make($request->new_password);
        $user->save();

        $currentTokenId = $user->currentAccessToken()?->id;

        $this->recordActivity(
            $user,
            $currentTokenId,
            'PASSWORD_CHANGED',
            $request
        );

        $user->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Password changed successfully. All devices have been logged out.',
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 3. Change Email
    |--------------------------------------------------------------------------
    */

    /**
     * Change authenticated user's email.
     */
    public function changeEmail(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'new_email' => 'required|email|unique:users,email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = $request->user();

        if (!Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => false,
                'message' => 'Password is incorrect',
            ], 422);
        }

        $oldEmail = $user->email;

        $user->email = $request->new_email;
        $user->save();

        $this->recordActivity(
            $user,
            $user->currentAccessToken()?->id,
            'EMAIL_CHANGED',
            $request
        );

        return response()->json([
            'status' => true,
            'message' => 'Email address changed successfully',
            'old_email' => $oldEmail,
            'new_email' => $user->email,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 4. Revoke Current Device
    |--------------------------------------------------------------------------
    */

    /**
     * Revoke only the current device.
     */
    public function revokeCurrentDevice(Request $request)
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        if (!$currentToken) {
            return response()->json([
                'status' => false,
                'message' => 'Current authentication token not found',
            ], 401);
        }

        $tokenId = $currentToken->id;
        $deviceName = $currentToken->name;

        $this->recordActivity(
            $user,
            $tokenId,
            'CURRENT_DEVICE_REVOKED',
            $request
        );

        $currentToken->delete();

        return response()->json([
            'status' => true,
            'message' => 'Current device revoked successfully',
            'token_id' => $tokenId,
            'device_name' => $deviceName,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 5. Revoke All Other Devices
    |--------------------------------------------------------------------------
    */

    /**
     * Revoke all other device sessions.
     */
    public function revokeAllOtherDevices(Request $request)
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        if (!$currentToken) {
            return response()->json([
                'status' => false,
                'message' => 'Current authentication token not found',
            ], 401);
        }

        $currentTokenId = $currentToken->id;

        $otherTokens = $user->tokens()
            ->where('id', '!=', $currentTokenId)
            ->get();

        foreach ($otherTokens as $token) {
            $this->recordActivity(
                $user,
                $token->id,
                'DEVICE_REVOKED',
                $request
            );
        }

        $count = $otherTokens->count();

        $user->tokens()
            ->where('id', '!=', $currentTokenId)
            ->delete();

        return response()->json([
            'status' => true,
            'message' => 'All other devices revoked successfully',
            'current_token_id' => $currentTokenId,
            'revoked_devices' => $count,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 6. Device Statistics
    |--------------------------------------------------------------------------
    */

    /**
     * Get device/session statistics.
     */
    public function deviceStatistics(Request $request)
    {
        $user = $request->user();

        $tokens = $user->tokens()->get();

        $currentTokenId = $user->currentAccessToken()?->id;

        $currentDevice = $tokens->first(
            fn($token) => $token->id === $currentTokenId
        );

        return response()->json([
            'status' => true,
            'message' => 'Device statistics retrieved successfully',
            'statistics' => [
                'total_devices' => $tokens->count(),
                'current_device' => $currentDevice?->name,
                'current_token_id' => $currentTokenId,
                'oldest_device' => $tokens->sortBy('created_at')->first()?->name,
                'latest_device' => $tokens->sortByDesc('created_at')->first()?->name,
                'last_activity' => $tokens
                    ->sortByDesc('last_used_at')
                    ->first()?->last_used_at,
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 7. Authentication Activity Search / Filter
    |--------------------------------------------------------------------------
    */

    /**
     * Search and filter authentication activities.
     */
    public function searchActivities(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'action' => 'nullable|string|max:100',
            'ip_address' => 'nullable|string|max:100',
            'from_date' => 'nullable|date',
            'to_date' => 'nullable|date|after_or_equal:from_date',
            'per_page' => 'nullable|integer|min:1|max:100',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $query = $request->user()
            ->authActivities()
            ->latest();

        if ($request->filled('action')) {
            $query->where('action', $request->action);
        }

        if ($request->filled('ip_address')) {
            $query->where(
                'ip_address',
                'like',
                '%' . $request->ip_address . '%'
            );
        }

        if ($request->filled('from_date')) {
            $query->whereDate(
                'created_at',
                '>=',
                $request->from_date
            );
        }

        if ($request->filled('to_date')) {
            $query->whereDate(
                'created_at',
                '<=',
                $request->to_date
            );
        }

        $activities = $query->paginate(
            $request->integer('per_page', 10)
        );

        return response()->json([
            'status' => true,
            'message' => 'Authentication activities retrieved successfully',
            'filters' => [
                'action' => $request->action,
                'ip_address' => $request->ip_address,
                'from_date' => $request->from_date,
                'to_date' => $request->to_date,
            ],
            'activities' => $activities,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 8. Clear Authentication Activities
    |--------------------------------------------------------------------------
    */

    /**
     * Delete authentication activity history.
     */
    public function clearActivities(Request $request)
    {
        $user = $request->user();

        $count = $user->authActivities()->count();

        $user->authActivities()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Authentication activity history cleared successfully',
            'deleted_records' => $count,
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | 9. Login Security Summary
    |--------------------------------------------------------------------------
    */

    /**
     * Get authentication security summary.
     */
    public function securitySummary(Request $request)
    {
        $user = $request->user();

        $activities = $user->authActivities();

        $totalActivities = $activities->count();

        $loginCount = (clone $activities)
            ->where('action', 'LOGIN')
            ->count();

        $logoutCount = (clone $activities)
            ->where('action', 'LOGOUT')
            ->count();

        $deviceRevokedCount = (clone $activities)
            ->whereIn('action', [
                'DEVICE_REVOKED',
                'CURRENT_DEVICE_REVOKED',
            ])
            ->count();

        $passwordChangedCount = (clone $activities)
            ->where('action', 'PASSWORD_CHANGED')
            ->count();

        $emailChangedCount = (clone $activities)
            ->where('action', 'EMAIL_CHANGED')
            ->count();

        $lastLogin = (clone $activities)
            ->where('action', 'LOGIN')
            ->latest()
            ->first();

        return response()->json([
            'status' => true,
            'message' => 'Security summary retrieved successfully',
            'summary' => [
                'total_activities' => $totalActivities,
                'total_logins' => $loginCount,
                'total_logouts' => $logoutCount,
                'devices_revoked' => $deviceRevokedCount,
                'password_changes' => $passwordChangedCount,
                'email_changes' => $emailChangedCount,
                'active_devices' => $user->tokens()->count(),
                'last_login' => $lastLogin ? [
                    'ip_address' => $lastLogin->ip_address,
                    'user_agent' => $lastLogin->user_agent,
                    'logged_at' => $lastLogin->created_at,
                ] : null,
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Existing Authentication Activity
    |--------------------------------------------------------------------------
    */

    /**
     * Get authentication activity history.
     */
    public function activityHistory(Request $request)
    {
        $activities = $request->user()
            ->authActivities()
            ->latest()
            ->paginate(
                $request->integer('per_page', 10)
            );

        return response()->json([
            'status' => true,
            'message' => 'Authentication activity retrieved successfully',
            'activities' => $activities,
        ]);
    }

    /**
     * Store authentication activity.
     */
    private function recordActivity(
        User $user,
        ?int $tokenId,
        string $action,
        Request $request
    ): void {
        AuthActivity::create([
            'user_id' => $user->id,
            'token_id' => $tokenId,
            'action' => $action,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);
    }
}
