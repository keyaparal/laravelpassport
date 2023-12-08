<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

class AuthController extends Controller
{
    public function register(Request $request)
    {
    //    try{
        // echo "jseag";
        // die;
        // dump($request->all());
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            // 'password' => bcrypt($request->password),
            'password' => Hash::make($request->password),
        ]);
        //dd( $user);
        $token = $user->createToken('app')->accessToken;
        return response()->json(['token' => $token,'user' =>$user,'message' => 'Success'], 200);

    //    }catch(\Throwable $th){
    //     return response()->json(['message' => $th->getMessage()]);
    //    }

    }
    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);
        try {
            if(Auth::attempt($loginData)){
                $user= Auth::user();
                
                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    // 'password' => bcrypt($request->password),
                    'password' => Hash::make($request->password),
                ]);
                $token = $user->createToken('app')->accessToken;
                // $accessToken = auth()->user()->createToken('authToken')->accessToken;
                // return response()->json(['user' => auth()->user(), 'access_token' => $accessToken]);
            }
            // if (!auth()->attempt($loginData)) {
            //     return response()->json(['message' => 'Invalid Credentials']);
            // }
            // $accessToken = auth()->user()->createToken('authToken')->accessToken;
            // return response()->json(['user' => auth()->user(), 'access_token' => $accessToken]);
        } catch (\Throwable $th) {
            return response()->json(['message' => 'Invalid Credentials']);
        }
    }
    public function logout(Request $request)
    {
        // Auth::logout();
        auth()->logout();
        return response()->json(['message' => 'User logged out successfully']);
    }
    public function user(Request $request)
    {
        return response()->json($request->user());
    }
}
