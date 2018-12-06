<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\TokenManager;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\CachedToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

final class CachedTokenTest extends TestCase
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cachePool;

    /**
     * @var CachedToken
     */
    private $cachedManager;

    /**
     * @var TokenManagerInterface
     */
    private $innerTokenManager;

    protected function setUp()
    {
        $this->cachedManager = new CachedToken(
            $this->cachePool = $this->createMock(CacheItemPoolInterface::class),
            $this->innerTokenManager = $this->createMock(TokenManagerInterface::class)
        );
    }

    public function testReturnsCachedTokenIfNotExpired()
    {
        $this->cachePool->expects(self::once())
            ->method('getItem')
            ->with(CachedToken::class)
            ->willReturn($item = $this->createMock(CacheItemInterface::class));

        $notExpired = new \DateTimeImmutable();
        $notExpired = $notExpired->add(new \DateInterval('PT30M'));
        $token = new Token('token', $notExpired);

        $item->expects(self::once())
            ->method('get')
            ->willReturn($token);

        $this->innerTokenManager->expects(self::never())->method('getToken');
        $this->cachePool->expects(self::never())->method('save');

        self::assertSame($token, $this->cachedManager->getToken());
    }

    public function testQueriesInnerManagerIfTokenIsExpired()
    {
        $this->cachePool->expects(self::once())
            ->method('getItem')
            ->with(CachedToken::class)
            ->willReturn($item = $this->createMock(CacheItemInterface::class));

        $expired = new \DateTimeImmutable();
        $expired = $expired->sub(new \DateInterval('PT30M'));
        $token = new Token('token', $expired);

        $item->expects(self::once())
            ->method('get')
            ->willReturn($token);

        $this->innerTokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn($newToken = new Token('new-token'));

        $item->expects(self::once())
            ->method('set')
            ->with($newToken);

        $item->expects(self::once())
            ->method('expiresAt')
            ->with(null);

        $this->cachePool->expects(self::once())
            ->method('save')
            ->with($item);

        self::assertSame($newToken, $this->cachedManager->getToken());
    }

    public function testQueriesInnerManagerIfTokenNotFoundInCache()
    {
        $this->cachePool->expects(self::once())
            ->method('getItem')
            ->with(CachedToken::class)
            ->willReturn($item = $this->createMock(CacheItemInterface::class));

        $item->expects(self::once())
            ->method('get')
            ->willReturn(null);

        $this->innerTokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn($newToken = new Token('new-token'));

        $item->expects(self::once())
            ->method('set')
            ->with($newToken);

        $item->expects(self::once())
            ->method('expiresAt')
            ->with(null);

        $this->cachePool->expects(self::once())
            ->method('save')
            ->with($item);

        self::assertSame($newToken, $this->cachedManager->getToken());
    }
}
