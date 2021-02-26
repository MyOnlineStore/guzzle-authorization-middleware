<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\CachedToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\UriProviderInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\UriInterface;

final class CachedTokenTest extends TestCase
{
    /** @var CacheItemInterface&MockObject */
    private $cacheItem;

    /** @var CacheItemPoolInterface&MockObject */
    private $cachePool;

    /** @var CachedToken */
    private $cachedManager;

    /** @var TokenManagerInterface&MockObject */
    private $innerTokenManager;

    /** @var UriInterface */
    private $tokenUri;

    /** @var UriProviderInterface&MockObject */
    private $uriProvider;

    protected function setUp(): void
    {
        $this->cachedManager = new CachedToken(
            $this->cachePool = $this->createMock(CacheItemPoolInterface::class),
            $this->innerTokenManager = $this->createMock(TokenManagerInterface::class),
            $this->uriProvider = $this->createMock(UriProviderInterface::class)
        );

        $this->uriProvider->expects(self::once())
            ->method('getTokenUri')
            ->willReturn($this->tokenUri = $this->createMock(UriInterface::class));

        $this->tokenUri->expects(self::once())
            ->method('__toString')
            ->willReturn('token-uri');

        $this->cachePool->expects(self::once())
            ->method('getItem')
            ->with(\str_replace('\\', '-', CachedToken::class) . '-' . \sha1('token-uri'))
            ->willReturn($this->cacheItem = $this->createMock(CacheItemInterface::class));
    }

    public function testReturnsCachedTokenIfNotExpired(): void
    {
        $notExpired = new \DateTimeImmutable();
        $notExpired = $notExpired->add(new \DateInterval('PT30M'));
        $token = new Token('token', $notExpired);

        $this->cacheItem->expects(self::once())
            ->method('get')
            ->willReturn($token);

        $this->innerTokenManager->expects(self::never())->method('getToken');
        $this->cachePool->expects(self::never())->method('save');

        self::assertSame($token, $this->cachedManager->getToken());
    }

    public function testQueriesInnerManagerIfTokenIsExpired(): void
    {
        $expired = new \DateTimeImmutable();
        $expired = $expired->sub(new \DateInterval('PT30M'));
        $token = new Token('token', $expired);

        $this->cacheItem->expects(self::once())
            ->method('get')
            ->willReturn($token);

        $this->innerTokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn($newToken = new Token('new-token', $expiresAt = new \DateTimeImmutable()));

        $this->cacheItem->expects(self::once())
            ->method('set')
            ->with($newToken);

        $this->cacheItem->expects(self::once())
            ->method('expiresAt')
            ->with($expiresAt);

        $this->cachePool->expects(self::once())
            ->method('save')
            ->with($this->cacheItem);

        self::assertSame($newToken, $this->cachedManager->getToken());
    }

    public function testQueriesInnerManagerIfTokenNotFoundInCache(): void
    {
        $this->cacheItem->expects(self::once())
            ->method('get')
            ->willReturn(null);

        $this->innerTokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn($newToken = new Token('new-token', $expiresAt = new \DateTimeImmutable()));

        $this->cacheItem->expects(self::once())
            ->method('set')
            ->with($newToken);

        $this->cacheItem->expects(self::once())
            ->method('expiresAt')
            ->with($expiresAt);

        $this->cachePool->expects(self::once())
            ->method('save')
            ->with($this->cacheItem);

        self::assertSame($newToken, $this->cachedManager->getToken());
    }
}
