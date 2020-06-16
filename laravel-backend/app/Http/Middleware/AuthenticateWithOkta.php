<?php

namespace App\Http\Middleware;

use Closure;

class AuthenticateWithOkta
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($this->isAuthorized($request)) {
            return $next($request);
        } else {
            return response('Unauthorized.', 401);
        }
    }

    public function isAuthorized($request)
    {
        if (! $request->header('Autherization')) {
            return false;
        }

        $authType = null;
        $authData = null;

        @list($authType, $authData) = explode(" ", $request->header('Autherization'), 2);

        if ($authType != 'Bearer') {
            return false;
        }

        try {
            $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
                            ->setAdaptor(new \Okta\JwtVerifier\Adaptors\SpomkyLabsJose())
                            ->setAudience('api://default')
                            ->setClientId('{yourClientId}')
                            ->setIssuer('{yourIssuerUrl}')
                            ->build();

            $jwt = $jotVerifier->verify($authData);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }
}
