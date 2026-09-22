<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Secure Logout & Device Security Command Center</title>

    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>

    <!-- Alpine.js -->
    <script src="https://unpkg.com/alpinejs" defer></script>

    <style>
        [x-cloak] { display: none !important; }
        .pulse-live {
            animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes pulse-ring {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.15); }
        }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased font-sans p-3 sm:p-6 lg:p-8 selection:bg-indigo-500 selection:text-white">

<div class="max-w-7xl mx-auto" x-data="securityApp()" x-init="init()" x-cloak>

    <!-- =====================================================
         1. TOP NAVIGATION & SECURITY HEADER
    ====================================================== -->
    <header class="bg-slate-900/80 backdrop-blur-md rounded-2xl border border-slate-800 p-5 mb-6 shadow-2xl">
        <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            
            <div class="flex items-center gap-3.5">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center text-2xl shadow-lg shadow-indigo-500/20">
                    🛡️
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <h1 class="text-xl font-black text-white tracking-tight">Security Command Center</h1>
                        <span class="inline-flex items-center gap-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold px-2 py-0.5 rounded-full">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-live"></span>
                            ACTIVE SHIELD
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-0.5">Multi-Device Session Manager • GeoIP Fingerprinting • Emergency Kill Switch</p>
                </div>
            </div>

            <!-- Header Controls & Auth State -->
            <div class="flex items-center gap-2.5 flex-wrap">
                <template x-if="isAuthenticated">
                    <div class="flex items-center gap-2">
                        <!-- User Badge -->
                        <div class="bg-slate-800/80 border border-slate-700 px-3 py-1.5 rounded-xl text-xs flex items-center gap-2">
                            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                            <span class="font-bold text-slate-200" x-text="currentUser.email"></span>
                        </div>

                        <!-- Emergency Kill Switch Button -->
                        <button
                            @click="triggerEmergencyFreeze()"
                            class="inline-flex items-center gap-1.5 bg-rose-600/20 hover:bg-rose-600 border border-rose-500/40 hover:border-rose-600 text-rose-300 hover:text-white font-bold text-xs px-3.5 py-2 rounded-xl transition shadow-lg shadow-rose-950">
                            <span>🚨</span> Emergency Kill Switch
                        </button>

                        <!-- Logout Current -->
                        <button
                            @click="logoutCurrent()"
                            class="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 font-semibold text-xs px-3.5 py-2 rounded-xl transition">
                            <span>🚪</span> Logout
                        </button>
                    </div>
                </template>

                <template x-if="!isAuthenticated">
                    <div class="flex items-center gap-2">
                        <button
                            @click="authModalMode = 'login'; showAuthModal = true;"
                            class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl shadow-lg shadow-indigo-600/20 transition">
                            Sign In / Register
                        </button>
                    </div>
                </template>
            </div>
        </div>
    </header>

    <!-- Global Toast Alert -->
    <div
        x-show="message"
        x-transition
        :class="messageType === 'success' ? 'bg-emerald-950/90 border-emerald-700 text-emerald-200' : 'bg-rose-950/90 border-rose-700 text-rose-200'"
        class="mb-6 p-4 rounded-xl border flex items-center justify-between text-xs font-semibold shadow-xl">
        <div class="flex items-center gap-2">
            <span x-text="messageType === 'success' ? '✅' : '⚠️'"></span>
            <span x-text="message"></span>
        </div>
        <button @click="message = ''" class="text-slate-400 hover:text-white text-base">✕</button>
    </div>

    <!-- Emergency Frozen Account Alert Banner -->
    <template x-if="isAccountFrozen">
        <div class="bg-gradient-to-r from-rose-950 to-red-900 border-2 border-rose-500 p-5 rounded-2xl mb-6 shadow-2xl flex flex-col sm:flex-row items-center justify-between gap-4">
            <div class="flex items-center gap-3">
                <span class="text-3xl animate-bounce">🚨</span>
                <div>
                    <h3 class="text-sm font-extrabold text-white uppercase tracking-wider">ACCOUNT IS CURRENTLY FROZEN</h3>
                    <p class="text-xs text-rose-200 mt-0.5">All active sessions were killed. You must enter your unlock recovery token to restore access.</p>
                </div>
            </div>
            <button
                @click="showUnfreezeModal = true"
                class="bg-white text-rose-950 font-black text-xs px-5 py-2.5 rounded-xl hover:bg-rose-100 transition shadow-lg whitespace-nowrap">
                🔓 Unlock Account
            </button>
        </div>
    </template>

    <!-- Main Content Grid -->
    <template x-if="isAuthenticated">
        <div class="space-y-6">

            <!-- =====================================================
                 2. SECURITY TELEMETRY KPI TILES
            ====================================================== -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4.5">
                    <div class="flex justify-between items-start">
                        <span class="text-[11px] font-bold text-slate-400 uppercase">Active Devices</span>
                        <span class="text-base">📱</span>
                    </div>
                    <p class="text-2xl font-black text-white mt-1" x-text="devices.length"></p>
                </div>

                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4.5">
                    <div class="flex justify-between items-start">
                        <span class="text-[11px] font-bold text-emerald-400 uppercase">Total Logins</span>
                        <span class="text-base">🔑</span>
                    </div>
                    <p class="text-2xl font-black text-emerald-400 mt-1" x-text="securitySummaryData.total_logins || 0"></p>
                </div>

                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4.5">
                    <div class="flex justify-between items-start">
                        <span class="text-[11px] font-bold text-amber-400 uppercase">Revoked Sessions</span>
                        <span class="text-base">🛑</span>
                    </div>
                    <p class="text-2xl font-black text-amber-400 mt-1" x-text="securitySummaryData.devices_revoked || 0"></p>
                </div>

                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4.5">
                    <div class="flex justify-between items-start">
                        <span class="text-[11px] font-bold text-rose-400 uppercase">Suspicious Alerts</span>
                        <span class="text-base">⚠️</span>
                    </div>
                    <p class="text-2xl font-black text-rose-400 mt-1" x-text="suspiciousAlertsList.length"></p>
                </div>
            </div>

            <!-- =====================================================
                 3. ACTIVE DEVICES & REMOTE LOGOUT COMMAND CENTER (FEATURE 1)
            ====================================================== -->
            <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6 pb-4 border-b border-slate-800">
                    <div>
                        <h2 class="text-base font-bold text-white flex items-center gap-2">
                            <span>💻</span> Active Device Sessions (<span x-text="devices.length"></span>)
                        </h2>
                        <p class="text-xs text-slate-400 mt-0.5">Manage and remotely revoke active Sanctum tokens from other laptops, phones and locations</p>
                    </div>

                    <div class="flex items-center gap-2">
                        <button
                            @click="revokeAllOtherDevices()"
                            :disabled="devices.length <= 1"
                            class="bg-amber-600/20 hover:bg-amber-600 border border-amber-500/40 text-amber-300 hover:text-white disabled:opacity-30 font-bold text-xs px-3.5 py-2 rounded-xl transition">
                            🛑 Revoke All Other Devices (<span x-text="Math.max(0, devices.length - 1)"></span>)
                        </button>
                        <button
                            @click="logoutAllDevices()"
                            class="bg-rose-600/20 hover:bg-rose-600 border border-rose-500/40 text-rose-300 hover:text-white font-bold text-xs px-3.5 py-2 rounded-xl transition">
                            🔥 Logout Everywhere
                        </button>
                    </div>
                </div>

                <!-- Device Cards Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <template x-for="device in devices" :key="device.id">
                        <div
                            :class="device.is_current ? 'border-indigo-500/80 bg-indigo-950/20 ring-1 ring-indigo-500/40' : (device.is_suspicious ? 'border-rose-500/80 bg-rose-950/20' : 'border-slate-800 bg-slate-950/50')"
                            class="border rounded-2xl p-4.5 flex flex-col justify-between transition hover:border-slate-700 shadow-md">
                            
                            <div>
                                <!-- Device Header with Icon & Current Badge -->
                                <div class="flex items-start justify-between gap-2 mb-3">
                                    <div class="flex items-center gap-2.5">
                                        <span class="text-2xl p-2 rounded-xl bg-slate-800/80 border border-slate-700" x-text="device.device_icon"></span>
                                        <div>
                                            <h4 class="font-bold text-xs text-white" x-text="device.device_name"></h4>
                                            <p class="text-[11px] text-slate-400" x-text="`${device.browser} • ${device.os}`"></p>
                                        </div>
                                    </div>

                                    <template x-if="device.is_current">
                                        <span class="bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-[10px] font-extrabold px-2 py-0.5 rounded-full">
                                            THIS DEVICE
                                        </span>
                                    </template>

                                    <template x-if="device.is_suspicious && !device.is_current">
                                        <span class="bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[10px] font-extrabold px-2 py-0.5 rounded-full">
                                            ⚠️ SUSPICIOUS
                                        </span>
                                    </template>
                                </div>

                                <!-- Metadata info -->
                                <div class="space-y-1 text-[11px] text-slate-400 bg-slate-900/50 p-2.5 rounded-xl border border-slate-800/60 mb-3">
                                    <div class="flex items-center justify-between">
                                        <span>📍 Location:</span>
                                        <span class="font-bold text-slate-200" x-text="`${device.country_flag} ${device.city}, ${device.country}`"></span>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <span>🌐 IP Address:</span>
                                        <span class="font-mono text-slate-300" x-text="device.ip_address"></span>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <span>⏱️ Last Active:</span>
                                        <span class="text-slate-300" x-text="formatDate(device.last_active_at)"></span>
                                    </div>
                                </div>
                            </div>

                            <!-- Action -->
                            <div class="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                                <span class="text-[10px] text-slate-500" x-text="`Token ID: #${device.id}`"></span>
                                <button
                                    @click="revokeSingleDevice(device.id, device.device_name)"
                                    :class="device.is_current ? 'text-slate-400 hover:text-rose-400' : 'text-rose-400 hover:text-rose-300 font-bold'"
                                    class="text-xs transition">
                                    <span x-text="device.is_current ? 'Logout This Device' : '🛑 Revoke Access'"></span>
                                </button>
                            </div>
                        </div>
                    </template>
                </div>
            </div>

            <!-- =====================================================
                 4. GEOIP FINGERPRINTING & IMPOSSIBLE TRAVEL SIMULATOR (FEATURE 2)
            ====================================================== -->
            <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="mb-4">
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <span>🌍</span> Multi-Device & Impossible Travel Anomaly Simulator
                    </h3>
                    <p class="text-xs text-slate-400 mt-0.5">Test how the fingerprinting engine detects logins from different devices and flags impossible geographical travel anomalies</p>
                </div>

                <div class="bg-slate-950/60 border border-slate-800 p-4 rounded-xl">
                    <div class="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-3">
                        <div>
                            <label class="block text-[11px] font-bold text-slate-400 uppercase mb-1">Simulate Device</label>
                            <select x-model="simDevice" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs font-semibold text-white focus:outline-none focus:ring-1 focus:ring-indigo-500">
                                <option value="Apple iPhone 15 Pro (Safari iOS 17)">📱 iPhone 15 Pro (Safari)</option>
                                <option value="Samsung Galaxy S24 Ultra (Android 14)">📱 Samsung Galaxy S24 (Chrome)</option>
                                <option value="MacBook Pro 16 M3 (macOS Sonoma)">💻 MacBook Pro (Safari)</option>
                                <option value="Windows 11 Workstation (Edge)">🖥️ Windows 11 PC (Edge)</option>
                                <option value="Ubuntu Linux Dev Server (Firefox)">🐧 Linux Workstation (Firefox)</option>
                            </select>
                        </div>

                        <div>
                            <label class="block text-[11px] font-bold text-slate-400 uppercase mb-1">Simulate Location</label>
                            <select x-model="simCity" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs font-semibold text-white focus:outline-none focus:ring-1 focus:ring-indigo-500">
                                <option value="Mumbai|India|IN">🇮🇳 Mumbai, India</option>
                                <option value="Bengaluru|India|IN">🇮🇳 Bengaluru, India</option>
                                <option value="New York|United States|US">🇺🇸 New York, USA</option>
                                <option value="San Francisco|United States|US">🇺🇸 San Francisco, USA</option>
                                <option value="London|United Kingdom|GB">🇬🇧 London, UK</option>
                                <option value="Tokyo|Japan|JP">🇯🇵 Tokyo, Japan</option>
                                <option value="Frankfurt|Germany|DE">🇩🇪 Frankfurt, Germany</option>
                            </select>
                        </div>

                        <div>
                            <label class="block text-[11px] font-bold text-slate-400 uppercase mb-1">Simulate IP</label>
                            <input type="text" x-model="simIp" placeholder="104.28.19.45" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:ring-1 focus:ring-indigo-500">
                        </div>

                        <div class="flex items-end">
                            <button
                                @click="createSimulatedDeviceSession()"
                                class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs py-2.5 rounded-xl shadow transition">
                                🚀 Create Device Session
                            </button>
                        </div>
                    </div>
                    <p class="text-[11px] text-slate-500">💡 <strong>Tip:</strong> If you simulate a login from 🇮🇳 Mumbai and immediately after from 🇺🇸 New York, the Impossible Travel defense engine will calculate high risk (80+) and flag it as a suspicious login.</p>
                </div>
            </div>

            <!-- =====================================================
                 5. SUSPICIOUS ALERTS & AUDIT TRAIL (FEATURE 3)
            ====================================================== -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                <!-- Suspicious Alerts Drawer (1 col) -->
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-sm font-bold text-white flex items-center gap-2">
                            <span>🚨</span> Security Anomaly Alerts (<span x-text="suspiciousAlertsList.length"></span>)
                        </h3>
                    </div>

                    <div class="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                        <template x-for="alert in suspiciousAlertsList" :key="alert.id">
                            <div class="bg-rose-950/30 border border-rose-800/60 p-3 rounded-xl">
                                <div class="flex items-start justify-between">
                                    <span class="bg-rose-500/20 text-rose-300 font-black text-[10px] px-1.5 py-0.5 rounded">
                                        RISK SCORE: <span x-text="alert.risk_score"></span>/100
                                    </span>
                                    <small class="text-[10px] text-slate-400" x-text="formatDate(alert.created_at)"></small>
                                </div>
                                <p class="text-xs font-bold text-white mt-1.5" x-text="alert.risk_reason || 'Suspicious Login Anomaly'"></p>
                                <p class="text-[11px] text-slate-400 mt-0.5" x-text="`IP: ${alert.ip_address} • ${alert.city}, ${alert.country}`"></p>
                            </div>
                        </template>
                        <template x-if="suspiciousAlertsList.length === 0">
                            <div class="text-center py-8 text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/40">
                                <span>✨</span> No security breaches or anomalies detected!
                            </div>
                        </template>
                    </div>
                </div>

                <!-- Authentication Activity Audit Trail (2 cols) -->
                <div class="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                        <h3 class="text-sm font-bold text-white flex items-center gap-2">
                            <span>📜</span> Authentication Audit Trail
                        </h3>
                        <div class="flex items-center gap-2">
                            <button @click="clearActivityHistory()" class="text-xs text-slate-400 hover:text-rose-400 font-semibold">Clear Log</button>
                            <button @click="fetchActivities()" class="text-xs text-indigo-400 hover:text-indigo-300 font-semibold">Refresh</button>
                        </div>
                    </div>

                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs border-collapse">
                            <thead>
                                <tr class="text-slate-400 uppercase text-[10px] border-b border-slate-800">
                                    <th class="py-2.5 px-3">Event</th>
                                    <th class="py-2.5 px-3">Device / Platform</th>
                                    <th class="py-2.5 px-3">Location & IP</th>
                                    <th class="py-2.5 px-3 text-right">Timestamp</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/60">
                                <template x-for="act in activities" :key="act.id">
                                    <tr class="hover:bg-slate-800/30">
                                        <td class="py-2.5 px-3">
                                            <span
                                                :class="{
                                                    'bg-emerald-500/20 text-emerald-300 border-emerald-500/30': act.action === 'LOGIN' || act.action === 'REGISTER',
                                                    'bg-rose-500/20 text-rose-300 border-rose-500/30': act.action.includes('REVOKED') || act.action.includes('LOGOUT') || act.action.includes('FROZEN'),
                                                    'bg-indigo-500/20 text-indigo-300 border-indigo-500/30': act.action.includes('CHANGED')
                                                }"
                                                class="border px-2 py-0.5 rounded text-[10px] font-bold"
                                                x-text="act.action"></span>
                                        </td>
                                        <td class="py-2.5 px-3 text-slate-200">
                                            <span x-text="`${act.browser || 'Browser'} on ${act.os || 'OS'}`"></span>
                                        </td>
                                        <td class="py-2.5 px-3 text-slate-300">
                                            <span x-text="`${act.city || 'Local'}, ${act.country || 'Network'} (${act.ip_address})`"></span>
                                        </td>
                                        <td class="py-2.5 px-3 text-right text-slate-400" x-text="formatDate(act.created_at)"></td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>

        </div>
    </template>

    <!-- Guest / Sign In Screen -->
    <template x-if="!isAuthenticated">
        <div class="max-w-md mx-auto my-12 bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl">
            <div class="text-center mb-6">
                <div class="w-14 h-14 mx-auto rounded-2xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-3xl mb-3">
                    🔐
                </div>
                <h2 class="text-xl font-black text-white" x-text="authModalMode === 'login' ? 'Sign In to Security Center' : 'Create Protected Account'"></h2>
                <p class="text-xs text-slate-400 mt-1">Full multi-device Sanctum authentication with live fingerprinting</p>
            </div>

            <form @submit.prevent="authModalMode === 'login' ? submitLogin() : submitRegister()" class="space-y-4 text-xs font-semibold">
                <template x-if="authModalMode === 'register'">
                    <div>
                        <label class="block text-slate-400 uppercase mb-1">Full Name</label>
                        <input type="text" x-model="authForm.name" required class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:ring-1 focus:ring-indigo-500">
                    </div>
                </template>

                <div>
                    <label class="block text-slate-400 uppercase mb-1">Email Address</label>
                    <input type="email" x-model="authForm.email" required class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:ring-1 focus:ring-indigo-500">
                </div>

                <div>
                    <label class="block text-slate-400 uppercase mb-1">Password</label>
                    <input type="password" x-model="authForm.password" required class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:ring-1 focus:ring-indigo-500">
                </div>

                <div>
                    <label class="block text-slate-400 uppercase mb-1">Device Name (Optional)</label>
                    <input type="text" x-model="authForm.device_name" placeholder="e.g. My MacBook Pro" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:ring-1 focus:ring-indigo-500">
                </div>

                <button
                    type="submit"
                    class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs py-3 rounded-xl shadow-lg transition">
                    <span x-text="authModalMode === 'login' ? 'Sign In & Connect Device' : 'Create Account & Start Session'"></span>
                </button>
            </form>

            <div class="mt-5 pt-4 border-t border-slate-800 text-center text-xs text-slate-400">
                <button
                    @click="authModalMode = authModalMode === 'login' ? 'register' : 'login'"
                    class="text-indigo-400 hover:text-indigo-300 font-bold">
                    <span x-text="authModalMode === 'login' ? 'Need an account? Register here' : 'Already have an account? Sign In'"></span>
                </button>
            </div>
        </div>
    </template>

    <!-- =====================================================
         MODAL: UNLOCK / UNFREEZE ACCOUNT
    ====================================================== -->
    <div
        x-show="showUnfreezeModal"
        class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md"
        x-transition>
        <div
            @click.away="showUnfreezeModal = false"
            class="bg-slate-900 w-full max-w-md rounded-2xl border border-slate-800 p-6 shadow-2xl">
            <h3 class="text-lg font-black text-white mb-1">🔓 Unlock & Restore Account</h3>
            <p class="text-xs text-slate-400 mb-4">Enter your recovery token to unfreeze your account and resume access.</p>

            <form @submit.prevent="submitUnfreeze()" class="space-y-3.5 text-xs font-semibold">
                <div>
                    <label class="block text-slate-400 uppercase mb-1">Email</label>
                    <input type="email" x-model="unfreezeForm.email" required class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-sm text-white">
                </div>
                <div>
                    <label class="block text-slate-400 uppercase mb-1">Password</label>
                    <input type="password" x-model="unfreezeForm.password" required class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-sm text-white">
                </div>
                <div>
                    <label class="block text-slate-400 uppercase mb-1">Unlock Recovery Token</label>
                    <input type="text" x-model="unfreezeForm.unlock_token" required placeholder="Enter token received during freeze" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-sm font-mono text-indigo-300">
                </div>

                <div class="flex gap-2 pt-2">
                    <button type="button" @click="showUnfreezeModal = false" class="w-1/2 py-2.5 text-slate-400 hover:text-white">Cancel</button>
                    <button type="submit" class="w-1/2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2.5 rounded-xl">Restore Access</button>
                </div>
            </form>
        </div>
    </div>

</div>

<!-- =====================================================
     ALPINE.JS SECURITY CONSOLE CONTROLLER
====================================================== -->
<script>
function securityApp() {
    return {
        token: localStorage.getItem('auth_token') || '',
        currentUser: {},
        isAuthenticated: false,
        isAccountFrozen: false,
        message: '',
        messageType: 'success',

        devices: [],
        activities: [],
        suspiciousAlertsList: [],
        securitySummaryData: {},

        // Auth Form
        authModalMode: 'login', // 'login' | 'register'
        showAuthModal: false,
        authForm: { name: '', email: 'admin@security.io', password: 'password123', device_name: '' },

        // Simulation Tool
        simDevice: 'Apple iPhone 15 Pro (Safari iOS 17)',
        simCity: 'New York|United States|US',
        simIp: '198.51.100.42',

        // Unfreeze
        showUnfreezeModal: false,
        unfreezeForm: { email: '', password: '', unlock_token: '' },

        init() {
            if (this.token) {
                this.fetchMe();
            }
        },

        showMessage(msg, type = 'success') {
            this.message = msg;
            this.messageType = type;
            setTimeout(() => { this.message = ''; }, 6000);
        },

        fetchMe() {
            fetch('/api/me', {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(res => {
                if (!res.ok) throw new Error('Unauthenticated');
                return res.json();
            })
            .then(data => {
                this.currentUser = data.user;
                this.isAuthenticated = true;
                this.isAccountFrozen = Boolean(data.is_frozen);
                this.fetchDevices();
                this.fetchActivities();
                this.fetchSuspiciousAlerts();
                this.fetchSummary();
            })
            .catch(() => {
                this.token = '';
                localStorage.removeItem('auth_token');
                this.isAuthenticated = false;
            });
        },

        fetchDevices() {
            fetch('/api/devices', {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.devices = data.devices || [];
            });
        },

        fetchActivities() {
            fetch('/api/auth-activities', {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.activities = data.activities?.data || [];
            });
        },

        fetchSuspiciousAlerts() {
            fetch('/api/security/suspicious-alerts', {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.suspiciousAlertsList = data.alerts || [];
            });
        },

        fetchSummary() {
            fetch('/api/security-summary', {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.securitySummaryData = data.summary || {};
            });
        },

        submitLogin() {
            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(this.authForm)
            })
            .then(async res => {
                const data = await res.json();
                if (!res.ok) throw new Error(data.message || 'Login failed');
                return data;
            })
            .then(data => {
                this.token = data.token;
                localStorage.setItem('auth_token', data.token);
                this.currentUser = data.user;
                this.isAuthenticated = true;
                this.showMessage(data.message);
                this.fetchDevices();
                this.fetchActivities();
                this.fetchSuspiciousAlerts();
                this.fetchSummary();
            })
            .catch(err => this.showMessage(err.message, 'error'));
        },

        submitRegister() {
            fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(this.authForm)
            })
            .then(async res => {
                const data = await res.json();
                if (!res.ok) throw new Error(data.message || 'Registration failed');
                return data;
            })
            .then(data => {
                this.token = data.token;
                localStorage.setItem('auth_token', data.token);
                this.currentUser = data.user;
                this.isAuthenticated = true;
                this.showMessage(data.message);
                this.fetchDevices();
                this.fetchActivities();
                this.fetchSuspiciousAlerts();
                this.fetchSummary();
            })
            .catch(err => this.showMessage(err.message, 'error'));
        },

        revokeSingleDevice(tokenId, name) {
            if (!confirm(`Revoke session token for '${name}'?`)) return;

            fetch(`/api/devices/${tokenId}`, {
                method: 'DELETE',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.showMessage(data.message);
                if (data.is_current) {
                    this.logoutCurrent();
                } else {
                    this.fetchDevices();
                    this.fetchActivities();
                    this.fetchSummary();
                }
            });
        },

        revokeAllOtherDevices() {
            if (!confirm('Revoke all other device sessions?')) return;

            fetch('/api/devices/revoke-others', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(r => r.json())
            .then(data => {
                this.showMessage(data.message);
                this.fetchDevices();
                this.fetchActivities();
                this.fetchSummary();
            });
        },

        logoutCurrent() {
            fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .finally(() => {
                this.token = '';
                localStorage.removeItem('auth_token');
                this.isAuthenticated = false;
                this.showMessage('Logged out successfully.');
            });
        },

        logoutAllDevices() {
            if (!confirm('Logout from ALL active devices? You will be signed out.')) return;

            fetch('/api/logout-all', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .finally(() => {
                this.token = '';
                localStorage.removeItem('auth_token');
                this.isAuthenticated = false;
                this.showMessage('All device sessions terminated.');
            });
        },

        triggerEmergencyFreeze() {
            const reason = prompt('Specify reason for emergency account freeze:', 'Suspicious activity detected on account');
            if (!reason) return;

            fetch('/api/security/emergency-freeze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({ reason: reason })
            })
            .then(r => r.json())
            .then(data => {
                prompt('🚨 ACCOUNT FROZEN! Copy your emergency UNLOCK TOKEN:', data.unlock_token);
                this.token = '';
                localStorage.removeItem('auth_token');
                this.isAuthenticated = false;
                this.isAccountFrozen = true;
                this.unfreezeForm.unlock_token = data.unlock_token;
                this.showUnfreezeModal = true;
            });
        },

        submitUnfreeze() {
            fetch('/api/security/unfreeze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(this.unfreezeForm)
            })
            .then(async res => {
                const data = await res.json();
                if (!res.ok) throw new Error(data.message || 'Unfreeze failed');
                return data;
            })
            .then(data => {
                this.showUnfreezeModal = false;
                this.isAccountFrozen = false;
                this.showMessage(data.message);
            })
            .catch(err => this.showMessage(err.message, 'error'));
        },

        createSimulatedDeviceSession() {
            const [city, country, code] = this.simCity.split('|');

            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'User-Agent': this.simDevice,
                    'X-Forwarded-For': this.simIp,
                    'X-Simulate-City': city,
                    'X-Simulate-Country': country,
                    'X-Simulate-Country-Code': code
                },
                body: JSON.stringify({
                    email: this.currentUser.email || this.authForm.email,
                    password: 'password123',
                    device_name: `${this.simDevice} (${city})`
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.is_suspicious) {
                    this.showMessage(`⚠️ Simulated Login flagged as SUSPICIOUS! Reason: ${data.risk_reason}`, 'error');
                } else {
                    this.showMessage(`Simulated device connected: ${data.device_name}`);
                }
                this.fetchDevices();
                this.fetchActivities();
                this.fetchSuspiciousAlerts();
                this.fetchSummary();
            });
        },

        clearActivityHistory() {
            if (!confirm('Clear activity logs?')) return;
            fetch('/api/auth-activities', {
                method: 'DELETE',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(() => {
                this.fetchActivities();
                this.showMessage('Activity history cleared.');
            });
        },

        formatDate(dateStr) {
            if (!dateStr) return '-';
            const d = new Date(dateStr);
            return isNaN(d.getTime()) ? dateStr : d.toLocaleString();
        }
    };
}
</script>

</body>
</html>
