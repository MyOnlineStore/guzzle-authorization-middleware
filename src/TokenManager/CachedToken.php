<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Cache\CacheItemPoolInterface;

final class CachedToken implements TokenManagerInterface
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cachePool;

    /**
     * @var TokenManagerInterface
     */
    private $innerTokenManager;

    public function __construct(CacheItemPoolInterface $cachePool, TokenManagerInterface $innerTokenManager)
    {
        $this->cachePool = $cachePool;
        $this->innerTokenManager = $innerTokenManager;
    }

    public function getToken(): Token
    {
        $item = $this->cachePool->getItem(self::class);
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
