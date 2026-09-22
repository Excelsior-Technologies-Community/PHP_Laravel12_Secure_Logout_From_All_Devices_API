<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\AuthActivity;
use App\Models\User;
use App\Services\DeviceFingerprintService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    protected DeviceFingerprintService $fingerprintService;

    public function __construct(DeviceFingerprintService $fingerprintService)
    {
        $this->fingerprintService = $fingerprintService;
    }

    /**
     * Register a new user with device fingerprinting.
     */
    public function register(Request $request): JsonResponse
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

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $deviceName = $request->device_name ?: $fingerprint['client_name'];

        $accessToken = $user->createToken($deviceName);
        $tokenModel = $accessToken->accessToken;

        // Store device fingerprint in token record
        $tokenModel->update([
            'device_type' => $fingerprint['device_type'],
            'browser' => $fingerprint['browser'],
            'os' => $fingerprint['os'],
            'ip_address' => $fingerprint['ip_address'],
            'city' => $fingerprint['city'],
            'country' => $fingerprint['country'],
            'country_code' => $fingerprint['country_code'],
            'is_suspicious' => false,
            'last_active_at' => now(),
        ]);

        $this->recordActivity($user, $tokenModel->id, 'REGISTER', $request, $fingerprint);

        return response()->json([
            'status' => true,
            'message' => 'User registered successfully with device fingerprint! 🛡️',
            'token' => $accessToken->plainTextToken,
            'token_id' => $tokenModel->id,
            'device_name' => $deviceName,
            'fingerprint' => $fingerprint,
            'user' => $user,
        ], 201);
    }

    /**
     * Login user, analyze risk, and create a fingerprinted session.
     */
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
            'device_name' => 'nullable|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        // Brute-force shield rate limiting
        $throttleKey = Str::transliterate(Str::lower($request->email) . '|' . $request->ip());
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = RateLimiter::availableIn($throttleKey);
            return response()->json([
                'status' => false,
                'message' => "Too many failed login attempts. Account temporarily locked for {$seconds} seconds.",
                'locked_seconds' => $seconds,
            ], 429);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            RateLimiter::hit($throttleKey, 300); // 5 min lock on 5 failures
            return response()->json([
                'status' => false,
                'message' => 'Invalid email or password credentials.',
            ], 401);
        }

        // Account Freeze Check
        if ($user->is_frozen) {
            return response()->json([
                'status' => false,
                'message' => '⚠️ Account is currently FROZEN due to a security freeze: ' . ($user->freeze_reason ?? 'Security lock active'),
                'is_frozen' => true,
                'frozen_at' => $user->frozen_at,
            ], 403);
        }

        RateLimiter::clear($throttleKey);

        // Generate Deep Device Fingerprint & Suspicious Login Detection
        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $deviceName = $request->device_name ?: $fingerprint['client_name'];

        $accessToken = $user->createToken($deviceName);
        $tokenModel = $accessToken->accessToken;

        $tokenModel->update([
            'device_type' => $fingerprint['device_type'],
            'browser' => $fingerprint['browser'],
            'os' => $fingerprint['os'],
            'ip_address' => $fingerprint['ip_address'],
            'city' => $fingerprint['city'],
            'country' => $fingerprint['country'],
            'country_code' => $fingerprint['country_code'],
            'is_suspicious' => $fingerprint['is_suspicious'],
            'last_active_at' => now(),
        ]);

        $this->recordActivity($user, $tokenModel->id, 'LOGIN', $request, $fingerprint);

        return response()->json([
            'status' => true,
            'message' => $fingerprint['is_suspicious']
                ? '⚠️ Login successful, but suspicious activity detected!'
                : 'Login successful! Active device session registered.',
            'token' => $accessToken->plainTextToken,
            'token_id' => $tokenModel->id,
            'device_name' => $deviceName,
            'fingerprint' => $fingerprint,
            'is_suspicious' => $fingerprint['is_suspicious'],
            'risk_score' => $fingerprint['risk_score'],
            'risk_reason' => $fingerprint['risk_reason'],
            'user' => $user,
        ]);
    }

    /**
     * Current authenticated user.
     */
    public function me(Request $request): JsonResponse
    {
        $user = $request->user();
        return response()->json([
            'status' => true,
            'message' => 'Authenticated user retrieved successfully',
            'user' => $user,
            'active_devices_count' => $user->tokens()->count(),
            'is_frozen' => (bool) $user->is_frozen,
        ]);
    }

    /**
     * Active Devices Command Center List
     */
    public function activeDevices(Request $request): JsonResponse
    {
        $user = $request->user();
        $currentTokenId = $user->currentAccessToken()?->id;

        $devices = $user->tokens()->latest('created_at')->get()->map(function ($token) use ($currentTokenId) {
            $flag = (new DeviceFingerprintService())->getCountryFlag($token->country_code);

            return [
                'id' => $token->id,
                'device_name' => $token->name,
                'device_type' => $token->device_type ?: 'Desktop',
                'device_icon' => $token->device_type === 'Mobile' ? '📱' : ($token->device_type === 'Tablet' ? '📱' : '💻'),
                'browser' => $token->browser ?: 'Web Browser',
                'os' => $token->os ?: 'Unknown OS',
                'ip_address' => $token->ip_address ?: '127.0.0.1',
                'city' => $token->city ?: 'Local',
                'country' => $token->country ?: 'Network',
                'country_code' => $token->country_code ?: 'IN',
                'country_flag' => $flag,
                'is_current' => $token->id === $currentTokenId,
                'is_suspicious' => (bool) $token->is_suspicious,
                'last_active_at' => $token->last_active_at ?? $token->last_used_at ?? $token->created_at,
                'created_at' => $token->created_at,
            ];
        });

        return response()->json([
            'status' => true,
            'message' => 'Active devices retrieved successfully',
            'total_devices' => $devices->count(),
            'current_token_id' => $currentTokenId,
            'devices' => $devices,
        ]);
    }

    /**
     * Revoke single specific device session.
     */
    public function revokeDevice(Request $request, int|string $tokenId): JsonResponse
    {
        $user = $request->user();
        $token = $user->tokens()->where('id', $tokenId)->first();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Device session not found or already revoked.',
            ], 404);
        }

        $deviceName = $token->name;
        $isCurrent = $token->id === $user->currentAccessToken()?->id;

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, $token->id, $isCurrent ? 'LOGOUT' : 'DEVICE_REVOKED', $request, $fingerprint, "Revoked device: {$deviceName}");

        $token->delete();

        return response()->json([
            'status' => true,
            'message' => "Device '{$deviceName}' revoked successfully.",
            'is_current' => $isCurrent,
        ]);
    }

    /**
     * Revoke current active device session (Logout).
     */
    public function logout(Request $request): JsonResponse
    {
        return $this->revokeCurrentDevice($request);
    }

    public function revokeCurrentDevice(Request $request): JsonResponse
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        if ($currentToken) {
            $fingerprint = $this->fingerprintService->inspect($request, $user);
            $this->recordActivity($user, $currentToken->id, 'LOGOUT', $request, $fingerprint);
            $currentToken->delete();
        }

        return response()->json([
            'status' => true,
            'message' => 'Current device session logged out successfully.',
        ]);
    }

    /**
     * Revoke all other devices except current device.
     */
    public function logoutOthers(Request $request): JsonResponse
    {
        return $this->revokeAllOtherDevices($request);
    }

    public function revokeAllOtherDevices(Request $request): JsonResponse
    {
        $user = $request->user();
        $currentTokenId = $user->currentAccessToken()?->id;

        $otherTokens = $user->tokens()->where('id', '!=', $currentTokenId);
        $count = $otherTokens->count();

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, $currentTokenId, 'OTHER_DEVICES_REVOKED', $request, $fingerprint, "Revoked {$count} other device sessions.");

        $otherTokens->delete();

        return response()->json([
            'status' => true,
            'message' => "Successfully logged out {$count} other device session(s).",
            'revoked_count' => $count,
        ]);
    }

    /**
     * Logout from ALL devices (including current).
     */
    public function logoutAll(Request $request): JsonResponse
    {
        $user = $request->user();
        $count = $user->tokens()->count();

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, null, 'ALL_DEVICES_LOGGED_OUT', $request, $fingerprint, "All {$count} device sessions terminated.");

        $user->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => "Successfully logged out from all {$count} devices.",
            'revoked_count' => $count,
        ]);
    }

    /**
     * Emergency Kill Switch: Freeze account and instantly terminate all sessions.
     */
    public function emergencyFreeze(Request $request): JsonResponse
    {
        $user = $request->user();
        $reason = $request->input('reason', 'Emergency Kill Switch triggered by user due to security concern.');

        $unlockToken = $user->freeze($reason);

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, null, 'EMERGENCY_ACCOUNT_FROZEN', $request, $fingerprint, "Emergency freeze active. All sessions killed.");

        return response()->json([
            'status' => true,
            'message' => '🚨 Emergency Kill Switch activated! All device sessions terminated and account is FROZEN.',
            'is_frozen' => true,
            'frozen_at' => $user->frozen_at,
            'unlock_token' => $unlockToken,
        ]);
    }

    /**
     * Unfreeze account using email, password, and unlock token.
     */
    public function unfreezeAccount(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
            'unlock_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['status' => false, 'errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['status' => false, 'message' => 'Invalid email or password.'], 401);
        }

        if (!$user->is_frozen) {
            return response()->json(['status' => true, 'message' => 'Account is not currently frozen.']);
        }

        if ($user->freeze_token !== $request->unlock_token) {
            return response()->json(['status' => false, 'message' => 'Invalid unlock token.'], 403);
        }

        $user->unfreeze();

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, null, 'ACCOUNT_UNFROZEN', $request, $fingerprint, "Account restored.");

        return response()->json([
            'status' => true,
            'message' => '✅ Account un-frozen successfully! You can now log in securely.',
        ]);
    }

    /**
     * Suspicious Login Alerts List
     */
    public function suspiciousAlerts(Request $request): JsonResponse
    {
        $user = $request->user();
        $alerts = $user->authActivities()
            ->where('is_suspicious', true)
            ->orWhere('risk_score', '>=', 60)
            ->latest('created_at')
            ->limit(20)
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Suspicious security alerts retrieved.',
            'alerts_count' => $alerts->count(),
            'alerts' => $alerts,
        ]);
    }

    /**
     * Device statistics.
     */
    public function deviceStatistics(Request $request): JsonResponse
    {
        $user = $request->user();
        $tokens = $user->tokens()->get();

        $desktopCount = $tokens->where('device_type', 'Desktop')->count();
        $mobileCount = $tokens->where('device_type', 'Mobile')->count();
        $tabletCount = $tokens->where('device_type', 'Tablet')->count();
        $suspiciousCount = $tokens->where('is_suspicious', true)->count();

        $uniqueCountries = $tokens->pluck('country')->filter()->unique()->values();

        return response()->json([
            'status' => true,
            'statistics' => [
                'total_active_devices' => $tokens->count(),
                'desktop_devices' => $desktopCount,
                'mobile_devices' => $mobileCount,
                'tablet_devices' => $tabletCount,
                'suspicious_devices' => $suspiciousCount,
                'active_countries' => $uniqueCountries,
                'is_frozen' => (bool) $user->is_frozen,
            ],
        ]);
    }

    /**
     * Security & Activity Summary.
     */
    public function securitySummary(Request $request): JsonResponse
    {
        $user = $request->user();
        $activities = $user->authActivities();

        $totalActivities = $activities->count();
        $loginCount = (clone $activities)->where('action', 'LOGIN')->count();
        $logoutCount = (clone $activities)->where('action', 'LOGOUT')->count();
        $revokedCount = (clone $activities)->whereIn('action', ['DEVICE_REVOKED', 'OTHER_DEVICES_REVOKED', 'ALL_DEVICES_LOGGED_OUT'])->count();
        $suspiciousCount = (clone $activities)->where('is_suspicious', true)->count();

        $lastLogin = (clone $activities)->where('action', 'LOGIN')->latest('created_at')->first();

        return response()->json([
            'status' => true,
            'summary' => [
                'total_activities' => $totalActivities,
                'total_logins' => $loginCount,
                'total_logouts' => $logoutCount,
                'devices_revoked' => $revokedCount,
                'suspicious_logins' => $suspiciousCount,
                'active_devices' => $user->tokens()->count(),
                'is_frozen' => (bool) $user->is_frozen,
                'last_login' => $lastLogin ? [
                    'ip_address' => $lastLogin->ip_address,
                    'device_name' => "{$lastLogin->browser} on {$lastLogin->os}",
                    'location' => "{$lastLogin->city}, {$lastLogin->country}",
                    'country_code' => $lastLogin->country_code,
                    'logged_at' => $lastLogin->created_at,
                    'is_suspicious' => $lastLogin->is_suspicious,
                ] : null,
            ],
        ]);
    }

    /**
     * Authentication Activity History with Search & Filters
     */
    public function activityHistory(Request $request): JsonResponse
    {
        $activities = $request->user()->authActivities()->latest('created_at')->paginate($request->integer('per_page', 15));
        return response()->json(['status' => true, 'activities' => $activities]);
    }

    public function searchActivities(Request $request): JsonResponse
    {
        $query = $request->user()->authActivities()->latest('created_at');

        if ($request->filled('action')) {
            $query->where('action', $request->action);
        }
        if ($request->filled('ip_address')) {
            $query->where('ip_address', 'like', "%{$request->ip_address}%");
        }
        if ($request->boolean('suspicious_only')) {
            $query->where('is_suspicious', true);
        }

        $activities = $query->paginate($request->integer('per_page', 15));
        return response()->json(['status' => true, 'activities' => $activities]);
    }

    public function clearActivities(Request $request): JsonResponse
    {
        $user = $request->user();
        $count = $user->authActivities()->count();
        $user->authActivities()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Authentication activity history cleared.',
            'deleted_records' => $count,
        ]);
    }

    /**
     * Change Password
     */
    public function changePassword(Request $request): JsonResponse
    {
        $request->validate([
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:6|confirmed',
        ]);

        $user = $request->user();

        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json(['status' => false, 'message' => 'Current password does not match.'], 400);
        }

        $user->update(['password' => Hash::make($request->new_password)]);

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, $user->currentAccessToken()?->id, 'PASSWORD_CHANGED', $request, $fingerprint);

        return response()->json(['status' => true, 'message' => 'Password updated successfully!']);
    }

    /**
     * Change Email
     */
    public function changeEmail(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email|unique:users,email,' . $request->user()->id,
            'password' => 'required|string',
        ]);

        $user = $request->user();

        if (!Hash::check($request->password, $user->password)) {
            return response()->json(['status' => false, 'message' => 'Password verification failed.'], 400);
        }

        $user->update(['email' => $request->email]);

        $fingerprint = $this->fingerprintService->inspect($request, $user);
        $this->recordActivity($user, $user->currentAccessToken()?->id, 'EMAIL_CHANGED', $request, $fingerprint);

        return response()->json(['status' => true, 'message' => 'Email updated successfully!']);
    }

    /**
     * Internal helper to record activity log.
     */
    private function recordActivity(
        User $user,
        ?int $tokenId,
        string $action,
        Request $request,
        array $fingerprint = [],
        ?string $reason = null
    ): void {
        AuthActivity::create([
            'user_id' => $user->id,
            'token_id' => $tokenId,
            'action' => $action,
            'ip_address' => $fingerprint['ip_address'] ?? $request->ip(),
            'user_agent' => $fingerprint['user_agent'] ?? $request->userAgent(),
            'device_type' => $fingerprint['device_type'] ?? 'Desktop',
            'browser' => $fingerprint['browser'] ?? 'Web Browser',
            'os' => $fingerprint['os'] ?? 'Unknown OS',
            'city' => $fingerprint['city'] ?? 'Local',
            'country' => $fingerprint['country'] ?? 'Network',
            'country_code' => $fingerprint['country_code'] ?? 'IN',
            'is_suspicious' => $fingerprint['is_suspicious'] ?? false,
            'risk_score' => $fingerprint['risk_score'] ?? 0,
            'risk_reason' => $reason ?: ($fingerprint['risk_reason'] ?? null),
        ]);
    }
}
