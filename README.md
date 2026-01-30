# 🚀 PHP_Laravel12_Secure_Logout_From_All_Devices_API

![Laravel](https://img.shields.io/badge/Laravel-12-red)
![Sanctum](https://img.shields.io/badge/Auth-Sanctum-blue)
![API](https://img.shields.io/badge/API-REST-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

##  Overview

This step-by-step guide walks you through building a Laravel 12 API authentication system using Laravel Sanctum, including:

* User Registration
* User Login
* Logout from Current Device
* Logout from Other Devices
* Logout from All Devices

---

##  1. Install Laravel 12 Project

```bash
composer create-project laravel/laravel secureapi
```

Start the development server:

```bash
php artisan serve
```

---

##  2. Configure Database

Update your `.env` file:

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=secureapi
DB_USERNAME=root
DB_PASSWORD=
```

Run migrations:

```bash
php artisan migrate
```

---

##  3. Install Laravel Sanctum

```bash
composer require laravel/sanctum

php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"

php artisan migrate
```

---

##  4. Update User Model

**File:** `app/Models/User.php`

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];
}
```

---

##  5. Configure Middleware (Laravel 12)

**File:** `bootstrap/app.php`

```php
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {

        // Sanctum SPA / API token support
        $middleware->statefulApi();

    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
```

---

##  6. Create Auth Controller

```bash
php artisan make:controller API/AuthController
```

**File:** `app/Http/Controllers/API/AuthController.php`

```php
<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // Register
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6'
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'token' => $token,
            'user' => $user
        ]);
    }

    // Login
    public function login(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'token' => $token,
            'user' => $user
        ]);
    }

    // Logout current device
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Logged out from current device'
        ]);
    }

    // Logout ALL devices
    public function logoutAll(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => 'Logged out from all devices'
        ]);
    }

    // Logout other devices only
    public function logoutOthers(Request $request)
    {
        $currentTokenId = $request->user()->currentAccessToken()->id;

        $request->user()->tokens()
            ->where('id', '!=', $currentTokenId)
            ->delete();

        return response()->json([
            'status' => true,
            'message' => 'Logged out from other devices'
        ]);
    }
}
```

---

##  7. Define API Routes

**File:** `routes/api.php`

```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/logout-all', [AuthController::class, 'logoutAll']);
    Route::post('/logout-others', [AuthController::class, 'logoutOthers']);
});
```

---

##  8. API Request & Response Examples (Full Outputs)

### Register User

**POST** `http://127.0.0.1:8000/api/register`

```json
{
  "name": "Harry",
  "email": "harry@test.com",
  "password": "123456"
}
```

**Response**

```json
{
  "status": true,
  "token": "1|XyZabc123TOKENVALUE",
  "user": {
    "id": 1,
    "name": "Harry",
    "email": "harry@test.com",
    "created_at": "2026-01-30T10:57:26.000000Z",
    "updated_at": "2026-01-30T10:57:26.000000Z"
  }
}
```
<img width="1800" height="993" alt="Screenshot 2026-01-30 162745" src="https://github.com/user-attachments/assets/e35ba239-97a1-42c2-8ac2-50b7dde7dc3a" />

---

### Login User

**POST** `http://127.0.0.1:8000/api/login`

```json
{
  "email": "harry@test.com",
  "password": "123456"
}
```

**Response**

```json
{
  "status": true,
  "token": "2|AnotherTOKENvalue456",
  "user": {
    "id": 1,
    "name": "Harry",
    "email": "harry@test.com",
    "created_at": "2026-01-30T10:57:26.000000Z",
    "updated_at": "2026-01-30T10:57:26.000000Z"
  }
}
```
<img width="1794" height="891" alt="Screenshot 2026-01-30 163030" src="https://github.com/user-attachments/assets/a1309727-adfb-40fe-b6b6-b35da1f06dc1" />

---

### Logout Current Device

**POST** `/api/logout`

```
Authorization: Bearer 2|AnotherTOKENvalue456
Accept: application/json
```

```json
{
  "status": true,
  "message": "Logged out from current device"
}
```
<img width="1792" height="713" alt="Screenshot 2026-01-30 163316" src="https://github.com/user-attachments/assets/f9b59af9-7caf-491e-9b1b-04c697ec1b3b" />

---

### Logout Other Devices

**POST** `/api/logout-others`

```
Authorization: Bearer CURRENT_DEVICE_TOKEN
Accept: application/json
```

```json
{
  "status": true,
  "message": "Logged out from other devices"
}
```
<img width="1804" height="730" alt="Screenshot 2026-01-30 163533" src="https://github.com/user-attachments/assets/09fd9b31-4ceb-4014-98f6-cb2ccb5a1807" />

---

### Logout From All Devices

**POST** `/api/logout-all`

```
Authorization: Bearer TOKEN_A
Accept: application/json
```

```json
{
  "status": true,
  "message": "Logged out from all devices"
}
```
<img width="1802" height="785" alt="Screenshot 2026-01-30 163900" src="https://github.com/user-attachments/assets/cbdadfa1-f4d0-47db-9639-b6f0a907c9f6" />

---

##  Final Result

✔ Token-based authentication
✔ Secure logout (current device)
✔ Logout other sessions
✔ Logout from all devices
✔ Unauthorized protection after logout
