<?php

namespace CellcubeActiveMiddleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class ActiveMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->cookie('access_token') ?? $request->header('Authorization');
        if ($token) {
            try {
                $user = JWTAuth::setToken($token)->authenticate();
                if ($user->is_active != 1) {
                    return responseError(__("Exception"), ['message' => 'Your account has been inactive', 'code' => 403], 403);
                }
            } catch (\Exception $e) {
                return responseError(__("Exception"), ['message' => 'Unauthorized', 'code' => 401], 401);
            }
        }
        
        return $next($request);
    }
}
