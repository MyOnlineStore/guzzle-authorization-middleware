<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;

interface TokenManagerInterface
{
    /**
     * @throws FailedToRetrieveToken
     */
    public function getToken(): Token;
}
