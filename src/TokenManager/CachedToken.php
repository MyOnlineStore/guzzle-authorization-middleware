<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;

final class CachedToken implements TokenManagerInterface
{
    /** @var CacheItemPoolInterface */
    private $cachePool;

    /** @var TokenManagerInterface */
    private $innerTokenManager;

    /** @var UriProviderInterface */
    private $uriProvider;

    public function __construct(
        CacheItemPoolInterface $cachePool,
        TokenManagerInterface $innerTokenManager,
        UriProviderInterface $uriProvider
    ) {
        $this->cachePool = $cachePool;
        $this->innerTokenManager = $innerTokenManager;
        $this->uriProvider = $uriProvider;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function getToken(): Token
    {
        $item  = $this->cachePool->getItem(
            \sprintf(
                'MyOnlineStore-GuzzleAuthorizationMiddleware-TokenManager-CachedToken-%s',
                \sha1((string) $this->uriProvider->getTokenUri())
            )
        );
        $token = $item->get();

        if (!$token instanceof Token || $token->isExpired()) {
            $token = $this->innerTokenManager->getToken();

            $item->set($token);
            $item->expiresAt($token->getExpiresAt());

            $this->cachePool->save($item);
        }

        return $token;
    }
}
