<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware\BearerAuthorization;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\MessageInterface;
use Psr\Log\LoggerInterface;

final class BearerAuthorizationTest extends TestCase
{
    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var BearerAuthorization */
    private $middleware;

    /** @var TokenManagerInterface&MockObject */
    private $tokenManager;

    protected function setUp(): void
    {
        $this->middleware = new BearerAuthorization(
            $this->tokenManager = $this->createMock(TokenManagerInterface::class),
            $this->logger = $this->createMock(LoggerInterface::class)
        );
    }

    public function testPassesRequestWithAuthorizationBearerHeader(): void
    {
        $message = $this->createMock(MessageInterface::class);
        $options = [];
        $next = static function (): \stdClass {
            return new \stdClass();
        };

        $this->tokenManager->expects(self::once())
            ->method('getToken')
            ->willReturn(new Token('auth-token', new \DateTimeImmutable()));

        $message->expects(self::once())
            ->method('withHeader')
            ->with('Authorization', 'bearer auth-token')
            ->willReturnSelf();

        ($this->middleware)($next)($message, $options);
    }

    public function testPassesRequestWithoutAuthorizationBearerHeaderIfFailedToRetrieveToken(): void
    {
        $message = $this->createMock(MessageInterface::class);
        $options = [];
        $next = static function (): \stdClass {
            return new \stdClass();
        };

        $this->tokenManager->expects(self::once())
            ->method('getToken')
            ->willThrowException($exception = FailedToRetrieveToken::dueTo('failure'));

        $this->logger->expects(self::once())
            ->method('critical')
            ->with(
                'Failed to add authorization header.',
                [
                    'message' => $exception->getMessage(),
                    'previous' => $exception->getPrevious(),
                    'trace' => $exception->getTraceAsString(),
                ]
            );

        $message->expects(self::never())->method('withHeader');

        ($this->middleware)($next)($message, $options);
    }
}
