<?php

namespace App\Http\Controllers;

use App\Models\User;
use Auth;
use Hash;
use Illuminate\Http\Request;
use Password;
use Validator;

class AuthController extends Controller
{
    
    public function register(Request $request) {

        $validatedCredentials = Validator::make($request->all(), [
            'username' => 'required|unique:users|min:4|max:26',
            'password' => 'required|min:4|max:26',
        ]);

        if($validatedCredentials->fails()) {
            return response()->json([
                'message' => $validatedCredentials->errors(),
            ]);
        };
        
        $user = User::create([
            'username' => $request->username,
            'password' => Hash::make($request->password)
        ]);

        return response()->json([
            'message' => 'User registered successfully'
        ]);
    }

    public function login(Request $request) {

        $user = User::where('username', $request->username)->first();

        if(!$user) {
            return response()->json([
                'message' => 'User has not found'
            ]);
        }

        if(!Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Wrong password'
            ]);
        };

        Auth::login($user);

        // Return info
        return response()->json([
            'message' => 'welcome'
        ]);
    }

    public function logout(Request $request) {
        

        return response()->json([
            'message' => 'Logged out successfully'
        ]);
    }

}
