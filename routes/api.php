<?php

use App\Http\Controllers\API\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Public Authentication Routes
|--------------------------------------------------------------------------
*/
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/security/unfreeze', [AuthController::class, 'unfreezeAccount']);

/*
|--------------------------------------------------------------------------
| Protected Authentication Routes
|--------------------------------------------------------------------------
*/
Route::middleware('auth:sanctum')->group(function () {

    /*
    |--------------------------------------------------------------------------
    | User Profile
    |--------------------------------------------------------------------------
    */
    Route::get('/me', [AuthController::class, 'me']);

    /*
    |--------------------------------------------------------------------------
    | Logout APIs
    |--------------------------------------------------------------------------
    */
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/logout-all', [AuthController::class, 'logoutAll']);
    Route::post('/logout-others', [AuthController::class, 'logoutOthers']);

    /*
    |--------------------------------------------------------------------------
    | Device Management & Command Center
    |--------------------------------------------------------------------------
    */
    Route::get('/devices', [AuthController::class, 'activeDevices']);
    Route::delete('/devices/{tokenId}', [AuthController::class, 'revokeDevice']);
    Route::post('/devices/revoke-current', [AuthController::class, 'revokeCurrentDevice']);
    Route::post('/devices/revoke-others', [AuthController::class, 'revokeAllOtherDevices']);
    Route::get('/devices/statistics', [AuthController::class, 'deviceStatistics']);

    /*
    |--------------------------------------------------------------------------
    | Account Security & Emergency Kill Switch
    |--------------------------------------------------------------------------
    */
    Route::post('/change-password', [AuthController::class, 'changePassword']);
    Route::post('/change-email', [AuthController::class, 'changeEmail']);
    Route::post('/security/emergency-freeze', [AuthController::class, 'emergencyFreeze']);
    Route::get('/security/suspicious-alerts', [AuthController::class, 'suspiciousAlerts']);

    /*
    |--------------------------------------------------------------------------
    | Authentication Activity & Security Logs
    |--------------------------------------------------------------------------
    */
    Route::get('/auth-activities', [AuthController::class, 'activityHistory']);
    Route::get('/auth-activities/search', [AuthController::class, 'searchActivities']);
    Route::delete('/auth-activities', [AuthController::class, 'clearActivities']);
    Route::get('/security-summary', [AuthController::class, 'securitySummary']);
});