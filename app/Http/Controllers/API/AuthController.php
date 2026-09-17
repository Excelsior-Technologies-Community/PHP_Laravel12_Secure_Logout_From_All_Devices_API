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

        /*
         * Device name allows us to identify the session later.
         */
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

    /**
     * Get all currently active device sessions.
     */
    public function activeDevices(Request $request)
    {
        $user = $request->user();
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
                'is_current_device' => $token->id === $currentTokenId,
            ];
        });

        return response()->json([
            'status' => true,
            'message' => 'Active device sessions retrieved successfully',
            'total_devices' => $devices->count(),
            'devices' => $devices->values(),
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

    /**
     * Get authentication activity history.
     */
    public function activityHistory(Request $request)
    {
        $activities = $request->user()
            ->authActivities()
            ->latest()
            ->paginate(10);

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