<?php

namespace CellcubeActiveMiddleware;

use Closure;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class ActiveMiddleware
{
    /**
    * Routes that skip the revocation check.
    */
    protected array $except = [
        'auth/login',
        'login/microsoft',
        'login/callback',
    ];

    public function handle(Request $request, Closure $next)
    {
        if ($request->is(...$this->except)) return $next($request);
        $token = $request->cookie('access_token') ?? $request->header('Authorization');
        if ($token) {
            try {
                $user = JWTAuth::setToken($token)->authenticate();
                if ($user->is_active != 1) {
                    return responseError(__("Exception"), ['message' => 'Your account has been inactive', 'code' => 403], 403);
                }

                // Cross-projects token revocation check
                if ($user->session_revoke) {
                    $payload   = JWTAuth::setToken($token)->getPayload();
                    $issuedAt  = $payload->get('iat');
                    $revokedAt = Carbon::parse($user->session_revoke)->timestamp;

                    if ($issuedAt !== null && $issuedAt < $revokedAt) {
                        return responseError(__("Exception"), ['message' => 'Session has been revoked. Please log in again.'], 401);
                    }
                }
            } catch (\Exception $e) {
                return responseError(__("Exception"), ['message' => 'Unauthorized', 'code' => 401], 401);
            }
        }

        return $next($request);
    }
}
