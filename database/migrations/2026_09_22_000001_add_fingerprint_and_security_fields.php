<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // 1. Enhance personal_access_tokens table
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->string('device_type')->nullable()->after('name'); // Desktop, Mobile, Tablet
            $table->string('browser')->nullable()->after('device_type'); // Chrome, Safari, Firefox
            $table->string('os')->nullable()->after('browser'); // Windows, macOS, Android, iOS
            $table->string('ip_address')->nullable()->after('os');
            $table->string('city')->nullable()->after('ip_address');
            $table->string('country')->nullable()->after('city');
            $table->string('country_code', 5)->nullable()->after('country');
            $table->boolean('is_suspicious')->default(false)->after('country_code');
            $table->timestamp('last_active_at')->nullable()->after('last_used_at');
        });

        // 2. Enhance auth_activities table
        Schema::table('auth_activities', function (Blueprint $table) {
            $table->string('device_type')->nullable()->after('user_agent');
            $table->string('browser')->nullable()->after('device_type');
            $table->string('os')->nullable()->after('browser');
            $table->string('city')->nullable()->after('os');
            $table->string('country')->nullable()->after('city');
            $table->string('country_code', 5)->nullable()->after('country');
            $table->boolean('is_suspicious')->default(false)->after('country_code');
            $table->unsignedSmallInteger('risk_score')->default(0)->after('is_suspicious'); // 0-100
            $table->string('risk_reason')->nullable()->after('risk_score');
        });

        // 3. Enhance users table with Emergency Kill Switch & Account Freeze
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('is_frozen')->default(false)->after('password');
            $table->timestamp('frozen_at')->nullable()->after('is_frozen');
            $table->string('freeze_reason')->nullable()->after('frozen_at');
            $table->string('freeze_token', 64)->nullable()->after('freeze_reason');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->dropColumn([
                'device_type', 'browser', 'os', 'ip_address', 'city', 'country', 'country_code', 'is_suspicious', 'last_active_at'
            ]);
        });

        Schema::table('auth_activities', function (Blueprint $table) {
            $table->dropColumn([
                'device_type', 'browser', 'os', 'city', 'country', 'country_code', 'is_suspicious', 'risk_score', 'risk_reason'
            ]);
        });

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['is_frozen', 'frozen_at', 'freeze_reason', 'freeze_token']);
        });
    }
};
