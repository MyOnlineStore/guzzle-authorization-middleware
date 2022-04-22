<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveTokenUri;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;

final class CachedToken implements TokenManagerInterface
{
    public function __construct(
        private CacheItemPoolInterface $cachePool,
        private TokenManagerInterface $innerTokenManager,
        private UriProviderInterface $uriProvider
    ) {
    }

    /**
     * @throws FailedToRetrieveToken
     */
    public function getToken(): Token
    {
        try {
            $item = $this->cachePool->getItem(
                \sprintf(
                    'MyOnlineStore-GuzzleAuthorizationMiddleware-TokenManager-CachedToken-%s',
                    \sha1((string) $this->uriProvider->getTokenUri())
                )
            );
        } catch (FailedToRetrieveTokenUri | InvalidArgumentException $exception) {
            throw FailedToRetrieveToken::dueTo('Unable to retrieve cache', $exception);
        }

        $token = $item->get();
        \assert($token instanceof Token || null === $token);

        if (!$token instanceof Token || $token->isExpired()) {
            $token = $this->innerTokenManager->getToken();

            $item->set($token);
            $item->expiresAt($token->getExpiresAt());

            $this->cachePool->save($item);
        }

        return $token;
    }
}
