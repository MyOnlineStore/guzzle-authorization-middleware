<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware\BearerAuthorization;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class BearerAuthorizationTest extends TestCase
{
    /**
     * @var BearerAuthorization
     */
    private $middleware;

    /**
     * @var TokenManagerInterface
     */
    private $tokenManager;

    protected function setUp()
    {
        $this->middleware = new BearerAuthorization(
            $this->tokenManager = $this->createMock(TokenManagerInterface::class)
        );
    }

    public function testPassesRequestWithAuthorizationBearerHeader()
    {
        $request = $this->createMock(RequestInterface::class);
        $next = $this->createPartialMock(\stdClass::class, ['__invoke']);
        $options = [];

        $this->tokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn(new Token('auth-token'));

        $request->expects(self::once())
            ->method('withHeader')
            ->with('Authorization', 'bearer auth-token')
            ->willReturnSelf();

        $next->expects(self::once())
            ->method('__invoke')
            ->with($request, $options)
            ->willReturnSelf();

        self::assertSame($next, ($this->middleware)($next)($request, $options));
    }
}
