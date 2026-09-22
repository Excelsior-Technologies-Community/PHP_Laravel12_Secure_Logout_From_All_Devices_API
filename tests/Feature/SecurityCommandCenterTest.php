<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class SecurityCommandCenterTest extends TestCase
{
    use RefreshDatabase;

    /**
     * 1. Test registration generates device fingerprint and stores in token & activity.
     */
    public function test_registration_records_device_fingerprint_and_activity(): void
    {
        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'X-Forwarded-For' => '49.37.12.98',
            'X-Simulate-City' => 'Mumbai',
            'X-Simulate-Country' => 'India',
            'X-Simulate-Country-Code' => 'IN',
        ])->postJson('/api/register', [
            'name' => 'Security Admin',
            'email' => 'admin@security.io',
            'password' => 'password123',
            'device_name' => 'MacBook Pro 16',
        ]);

        $response->assertStatus(201)
            ->assertJson([
                'status' => true,
            ])
            ->assertJsonStructure([
                'token',
                'token_id',
                'device_name',
                'fingerprint' => [
                    'browser',
                    'os',
                    'device_type',
                    'city',
                    'country',
                    'country_flag',
                ],
            ]);

        $this->assertDatabaseHas('personal_access_tokens', [
            'name' => 'MacBook Pro 16',
            'os' => 'macOS',
            'city' => 'Mumbai',
            'country' => 'India',
        ]);

        $this->assertDatabaseHas('auth_activities', [
            'action' => 'REGISTER',
            'city' => 'Mumbai',
            'country' => 'India',
        ]);
    }

    /**
     * 2. Test multi-device listing and remote revocation of other devices.
     */
    public function test_active_devices_and_revoke_others(): void
    {
        $user = User::create([
            'name' => 'John Doe',
            'email' => 'john@security.io',
            'password' => Hash::make('password123'),
        ]);

        // Device 1 (Current)
        $token1 = $user->createToken('Desktop PC');
        $token1->accessToken->update(['os' => 'Windows 11/10', 'city' => 'Mumbai', 'country_code' => 'IN']);

        // Device 2 (Phone)
        $token2 = $user->createToken('iPhone 15');
        $token2->accessToken->update(['os' => 'iOS (iPhone)', 'city' => 'Mumbai', 'country_code' => 'IN']);

        // Device 3 (Work Laptop)
        $token3 = $user->createToken('MacBook Air');
        $token3->accessToken->update(['os' => 'macOS', 'city' => 'Bengaluru', 'country_code' => 'IN']);

        // Authenticate with token 1
        $response = $this->withToken($token1->plainTextToken)->getJson('/api/devices');

        $response->assertStatus(200)
            ->assertJson([
                'status' => true,
                'total_devices' => 3,
                'current_token_id' => $token1->accessToken->id,
            ]);

        // Revoke all other devices (token2 and token3)
        $revokeResponse = $this->withToken($token1->plainTextToken)->postJson('/api/devices/revoke-others');
        $revokeResponse->assertStatus(200)
            ->assertJson([
                'status' => true,
                'revoked_count' => 2,
            ]);

        $this->assertDatabaseHas('personal_access_tokens', ['id' => $token1->accessToken->id]);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $token2->accessToken->id]);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $token3->accessToken->id]);
    }

    /**
     * 3. Test impossible travel anomaly triggers suspicious login alert.
     */
    public function test_impossible_travel_triggers_suspicious_login_alert(): void
    {
        $user = User::create([
            'name' => 'Alice Security',
            'email' => 'alice@security.io',
            'password' => Hash::make('password123'),
        ]);

        // 1st Login from India
        $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'X-Simulate-City' => 'Mumbai',
            'X-Simulate-Country' => 'India',
            'X-Simulate-Country-Code' => 'IN',
        ])->postJson('/api/login', [
            'email' => 'alice@security.io',
            'password' => 'password123',
        ]);

        // 2nd Login from USA 5 minutes later (Impossible Travel!)
        $response2 = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
            'X-Simulate-City' => 'New York',
            'X-Simulate-Country' => 'United States',
            'X-Simulate-Country-Code' => 'US',
        ])->postJson('/api/login', [
            'email' => 'alice@security.io',
            'password' => 'password123',
        ]);

        $response2->assertStatus(200)
            ->assertJson([
                'status' => true,
                'is_suspicious' => true,
            ]);

        $this->assertGreaterThanOrEqual(60, $response2->json('risk_score'));
        $this->assertStringContainsString('Impossible Travel', $response2->json('risk_reason'));

        // Check suspicious alerts endpoint
        $alertsResponse = $this->withToken($response2->json('token'))->getJson('/api/security/suspicious-alerts');
        $alertsResponse->assertStatus(200);
        $this->assertGreaterThanOrEqual(1, $alertsResponse->json('alerts_count'));
    }

    /**
     * 4. Test Emergency Kill Switch freezes account and terminates all sessions.
     */
    public function test_emergency_kill_switch_and_unfreeze_flow(): void
    {
        $user = User::create([
            'name' => 'Emergency User',
            'email' => 'emergency@security.io',
            'password' => Hash::make('password123'),
        ]);

        $token = $user->createToken('Current Device');

        // Activate Emergency Freeze
        $freezeResponse = $this->withToken($token->plainTextToken)->postJson('/api/security/emergency-freeze', [
            'reason' => 'Suspected account compromise',
        ]);

        $freezeResponse->assertStatus(200)
            ->assertJson([
                'status' => true,
                'is_frozen' => true,
            ])
            ->assertJsonStructure([
                'unlock_token',
            ]);

        $unlockToken = $freezeResponse->json('unlock_token');

        // All tokens must be deleted
        $this->assertDatabaseCount('personal_access_tokens', 0);

        // Subsequent login attempt must be rejected with 403 Frozen
        $loginAttempt = $this->postJson('/api/login', [
            'email' => 'emergency@security.io',
            'password' => 'password123',
        ]);

        $loginAttempt->assertStatus(403)
            ->assertJson([
                'status' => false,
                'is_frozen' => true,
            ]);

        // Unfreeze account
        $unfreezeResponse = $this->postJson('/api/security/unfreeze', [
            'email' => 'emergency@security.io',
            'password' => 'password123',
            'unlock_token' => $unlockToken,
        ]);

        $unfreezeResponse->assertStatus(200)
            ->assertJson([
                'status' => true,
            ]);

        // User can now log in again
        $finalLogin = $this->postJson('/api/login', [
            'email' => 'emergency@security.io',
            'password' => 'password123',
        ]);

        $finalLogin->assertStatus(200)->assertJson(['status' => true]);
    }
}
