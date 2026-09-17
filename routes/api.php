<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;

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

    // Existing secure logout APIs
    Route::post('/logout', [AuthController::class, 'logout']);

    Route::post('/logout-all', [AuthController::class, 'logoutAll']);

    Route::post('/logout-others', [AuthController::class, 'logoutOthers']);


    // New device/session management APIs
    Route::get('/devices', [AuthController::class, 'activeDevices']);

    Route::delete(
        '/devices/{tokenId}',
        [AuthController::class, 'revokeDevice']
    );


    // New authentication activity history API
    Route::get(
        '/auth-activities',
        [AuthController::class, 'activityHistory']
    );
});