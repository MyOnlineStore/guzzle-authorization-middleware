<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware\BearerAuthorization;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class BearerAuthorizationTest extends TestCase
{
    /** @var BearerAuthorization */
    private $middleware;

    /** @var TokenManagerInterface&MockObject */
    private $tokenManager;

    protected function setUp(): void
    {
        $this->middleware = new BearerAuthorization(
            $this->tokenManager = $this->createMock(TokenManagerInterface::class)
        );
    }

    public function testPassesRequestWithAuthorizationBearerHeader(): void
    {
        $request = $this->createMock(RequestInterface::class);
        $options = [];
        $next = static function (): \stdClass {
            return new \stdClass();
        };

        $this->tokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn(new Token('auth-token', new \DateTimeImmutable()));

        $request->expects(self::once())
            ->method('withHeader')
            ->with('Authorization', 'bearer auth-token')
            ->willReturnSelf();

        ($this->middleware)($next)($request, $options);
    }
}
