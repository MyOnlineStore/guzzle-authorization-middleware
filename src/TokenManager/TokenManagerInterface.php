<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;

interface TokenManagerInterface
{
    public function getToken(): Token;
}
