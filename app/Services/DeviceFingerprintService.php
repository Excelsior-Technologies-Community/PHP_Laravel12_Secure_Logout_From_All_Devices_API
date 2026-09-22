<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

class DeviceFingerprintService
{
    /**
     * Inspect request and generate complete device fingerprint & location metadata.
     */
    public function inspect(Request $request, ?User $user = null): array
    {
        $userAgent = $request->header('User-Agent', $request->userAgent() ?? '');
        $ip = $this->getClientIp($request);

        $parsedAgent = $this->parseUserAgent($userAgent);
        $location = $this->resolveLocation($ip, $request);

        $riskAnalysis = [
            'is_suspicious' => false,
            'risk_score' => 0,
            'risk_reason' => null,
        ];

        if ($user) {
            $riskAnalysis = $this->analyzeRisk($user, $parsedAgent, $location, $ip);
        }

        return array_merge($parsedAgent, $location, $riskAnalysis, [
            'ip_address' => $ip,
            'user_agent' => $userAgent,
            'inspected_at' => now()->toIso8601String(),
        ]);
    }

    /**
     * Get real client IP address.
     */
    public function getClientIp(Request $request): string
    {
        $ip = $request->header('CF-Connecting-IP')
            ?? $request->header('X-Forwarded-For')
            ?? $request->ip()
            ?? '127.0.0.1';

        if (str_contains($ip, ',')) {
            $ip = trim(explode(',', $ip)[0]);
        }

        return $ip;
    }

    /**
     * Deep User-Agent & Device Type Parser
     */
    public function parseUserAgent(?string $ua): array
    {
        $ua = $ua ?: '';
        $browser = 'Unknown Browser';
        $os = 'Unknown OS';
        $deviceType = 'Desktop';
        $deviceIcon = '🖥️';

        // 1. Device Type Detection
        if (preg_match('/(tablet|ipad|playbook|silk)|(android(?!.*mobile))/i', $ua)) {
            $deviceType = 'Tablet';
            $deviceIcon = '📱';
        } elseif (preg_match('/(mobile|iphone|ipod|blackberry|opera mini|iemobile|wpdesktop|windows phone)/i', $ua)) {
            $deviceType = 'Mobile';
            $deviceIcon = '📱';
        } else {
            $deviceType = 'Desktop';
            $deviceIcon = '💻';
        }

        // 2. OS Detection
        if (preg_match('/windows nt 10\.0/i', $ua)) {
            $os = 'Windows 11/10';
        } elseif (preg_match('/windows nt 6\.3/i', $ua)) {
            $os = 'Windows 8.1';
        } elseif (preg_match('/windows nt 6\.1/i', $ua)) {
            $os = 'Windows 7';
        } elseif (preg_match('/macintosh|mac os x/i', $ua)) {
            $os = 'macOS';
            $deviceIcon = '💻';
        } elseif (preg_match('/iphone/i', $ua)) {
            $os = 'iOS (iPhone)';
            $deviceIcon = '📱';
        } elseif (preg_match('/ipad/i', $ua)) {
            $os = 'iPadOS (iPad)';
            $deviceIcon = '📱';
        } elseif (preg_match('/android/i', $ua)) {
            $os = 'Android';
            $deviceIcon = '📱';
        } elseif (preg_match('/cros/i', $ua)) {
            $os = 'ChromeOS';
        } elseif (preg_match('/linux/i', $ua)) {
            $os = 'Linux';
        }

        // 3. Browser Detection
        if (preg_match('/edg\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Microsoft Edge ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/opr\/([\d\.]+)|opera/i', $ua, $matches)) {
            $browser = 'Opera ' . (isset($matches[1]) ? explode('.', $matches[1])[0] : '');
        } elseif (preg_match('/samsungbrowser\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Samsung Internet ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/chrome\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Google Chrome ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/crios\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Chrome iOS ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/fxios\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Firefox iOS ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/firefox\/([\d\.]+)/i', $ua, $matches)) {
            $browser = 'Mozilla Firefox ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/version\/([\d\.]+).*safari/i', $ua, $matches)) {
            $browser = 'Apple Safari ' . explode('.', $matches[1])[0];
        } elseif (preg_match('/safari/i', $ua)) {
            $browser = 'Apple Safari';
        }

        return [
            'device_type' => $deviceType,
            'device_icon' => $deviceIcon,
            'browser' => trim($browser),
            'os' => $os,
            'client_name' => "{$browser} on {$os}",
        ];
    }

    /**
     * GeoIP Location Resolver with local fallback and simulated header overrides
     */
    public function resolveLocation(string $ip, ?Request $request = null): array
    {
        // Check for test / simulated headers if provided in dashboard/requests
        if ($request && $request->hasHeader('X-Simulate-City')) {
            return [
                'city' => $request->header('X-Simulate-City', 'New York'),
                'country' => $request->header('X-Simulate-Country', 'United States'),
                'country_code' => $request->header('X-Simulate-Country-Code', 'US'),
                'country_flag' => $this->getCountryFlag($request->header('X-Simulate-Country-Code', 'US')),
            ];
        }

        // Local & Private IPs
        if ($ip === '127.0.0.1' || $ip === '::1' || str_starts_with($ip, '192.168.') || str_starts_with($ip, '10.')) {
            return [
                'city' => 'Localhost / Dev Station',
                'country' => 'Local Network',
                'country_code' => 'IN',
                'country_flag' => '🇮🇳',
            ];
        }

        // Deterministic simulation mapping for demo & testing
        $hash = crc32($ip);
        $locations = [
            ['city' => 'Mumbai', 'country' => 'India', 'country_code' => 'IN', 'country_flag' => '🇮🇳'],
            ['city' => 'Bengaluru', 'country' => 'India', 'country_code' => 'IN', 'country_flag' => '🇮🇳'],
            ['city' => 'New York', 'country' => 'United States', 'country_code' => 'US', 'country_flag' => '🇺🇸'],
            ['city' => 'San Francisco', 'country' => 'United States', 'country_code' => 'US', 'country_flag' => '🇺🇸'],
            ['city' => 'London', 'country' => 'United Kingdom', 'country_code' => 'GB', 'country_flag' => '🇬🇧'],
            ['city' => 'Frankfurt', 'country' => 'Germany', 'country_code' => 'DE', 'country_flag' => '🇩🇪'],
            ['city' => 'Singapore', 'country' => 'Singapore', 'country_code' => 'SG', 'country_flag' => '🇸🇬'],
            ['city' => 'Tokyo', 'country' => 'Japan', 'country_code' => 'JP', 'country_flag' => '🇯🇵'],
            ['city' => 'Sydney', 'country' => 'Australia', 'country_code' => 'AU', 'country_flag' => '🇦🇺'],
        ];

        return $locations[abs($hash) % count($locations)];
    }

    /**
     * Convert Country Code to Unicode Flag Emoji
     */
    public function getCountryFlag(?string $code): string
    {
        if (!$code || strlen($code) !== 2) return '🌐';
        $code = strtoupper($code);
        $firstChar = ord($code[0]) - 65 + 0x1F1E6;
        $secondChar = ord($code[1]) - 65 + 0x1F1E6;
        return mb_chr($firstChar, 'UTF-8') . mb_chr($secondChar, 'UTF-8');
    }

    /**
     * Analyze Risk, Impossible Travel & Suspicious Anomalies
     */
    public function analyzeRisk(User $user, array $parsedAgent, array $location, string $ip): array
    {
        $lastActivity = $user->authActivities()
            ->where('action', 'LOGIN')
            ->latest('created_at')
            ->first();

        $isSuspicious = false;
        $riskScore = 0;
        $riskReasons = [];

        if ($lastActivity) {
            // 1. Impossible Travel Anomaly Check
            $lastCountry = $lastActivity->country_code ?? 'IN';
            $currentCountry = $location['country_code'] ?? 'IN';
            $timeDiffMinutes = Carbon::parse($lastActivity->created_at)->diffInMinutes(now());

            if ($lastCountry !== $currentCountry && $timeDiffMinutes < 90) {
                $isSuspicious = true;
                $riskScore += 80;
                $riskReasons[] = "Impossible Travel: Login from {$location['country']} only {$timeDiffMinutes} mins after {$lastActivity->country}";
            }

            // 2. New Device & IP Check
            $knownIps = $user->authActivities()
                ->whereNotNull('ip_address')
                ->distinct()
                ->pluck('ip_address')
                ->toArray();

            if (!in_array($ip, $knownIps) && count($knownIps) > 0) {
                $riskScore += 25;
                $riskReasons[] = "Login from unrecognized IP address ({$ip})";
            }

            $knownBrowsers = $user->authActivities()
                ->whereNotNull('browser')
                ->distinct()
                ->pluck('browser')
                ->toArray();

            if (!in_array($parsedAgent['browser'], $knownBrowsers) && count($knownBrowsers) > 0) {
                $riskScore += 20;
                $riskReasons[] = "First time using {$parsedAgent['browser']}";
            }
        }

        if ($riskScore >= 60) {
            $isSuspicious = true;
        }

        return [
            'is_suspicious' => $isSuspicious,
            'risk_score' => min($riskScore, 100),
            'risk_reason' => !empty($riskReasons) ? implode('; ', $riskReasons) : null,
        ];
    }
}
