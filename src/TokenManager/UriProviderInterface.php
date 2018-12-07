<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use Psr\Http\Message\UriInterface;

interface UriProviderInterface
{
    public function getTokenUri(): UriInterface;
}
