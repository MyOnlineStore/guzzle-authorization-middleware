<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveTokenUri;
use Psr\Http\Message\UriInterface;

interface UriProviderInterface
{
    /**
     * @throws FailedToRetrieveTokenUri
     */
    public function getTokenUri(): UriInterface;
}
