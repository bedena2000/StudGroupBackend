<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::middleware('auth.sanctum')->post('/logout', [AuthController::class, 'logout']);

Route::post('/test', function () {
    return "hello world";
})->middleware('auth:sanctum');