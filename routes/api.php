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


/*
|--------------------------------------------------------------------------
| Protected Authentication Routes
|--------------------------------------------------------------------------
*/

Route::middleware('auth:sanctum')->group(function () {

    /*
    |--------------------------------------------------------------------------
    | User
    |--------------------------------------------------------------------------
    */

    // 1. Current authenticated user
    Route::get('/me', [AuthController::class, 'me']);


    /*
    |--------------------------------------------------------------------------
    | Logout
    |--------------------------------------------------------------------------
    */

    Route::post('/logout', [AuthController::class, 'logout']);

    Route::post('/logout-all', [AuthController::class, 'logoutAll']);

    Route::post('/logout-others', [AuthController::class, 'logoutOthers']);


    /*
    |--------------------------------------------------------------------------
    | Device Management
    |--------------------------------------------------------------------------
    */

    // Existing: active devices
    Route::get('/devices', [AuthController::class, 'activeDevices']);

    // Existing: revoke specific device
    Route::delete(
        '/devices/{tokenId}',
        [AuthController::class, 'revokeDevice']
    );

    // 4. Revoke current device
    Route::post(
        '/devices/revoke-current',
        [AuthController::class, 'revokeCurrentDevice']
    );

    // 5. Revoke all other devices
    Route::post(
        '/devices/revoke-others',
        [AuthController::class, 'revokeAllOtherDevices']
    );

    // 6. Device statistics
    Route::get(
        '/devices/statistics',
        [AuthController::class, 'deviceStatistics']
    );


    /*
    |--------------------------------------------------------------------------
    | Account Security
    |--------------------------------------------------------------------------
    */

    // 2. Change password
    Route::post(
        '/change-password',
        [AuthController::class, 'changePassword']
    );

    // 3. Change email
    Route::post(
        '/change-email',
        [AuthController::class, 'changeEmail']
    );


    /*
    |--------------------------------------------------------------------------
    | Authentication Activity
    |--------------------------------------------------------------------------
    */

    // Existing activity history
    Route::get(
        '/auth-activities',
        [AuthController::class, 'activityHistory']
    );

    // 7. Search/filter activity
    Route::get(
        '/auth-activities/search',
        [AuthController::class, 'searchActivities']
    );

    // 8. Clear activity history
    Route::delete(
        '/auth-activities',
        [AuthController::class, 'clearActivities']
    );

    // 9. Security summary
    Route::get(
        '/security-summary',
        [AuthController::class, 'securitySummary']
    );
});