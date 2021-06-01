<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    public function testWithExpiresAt(): void
    {
        $expired = new \DateTimeImmutable();
        $expired = $expired->sub(new \DateInterval('PT30M'));
        $token = new Token('token', $expired);
        self::assertEquals('token', $token->getToken());
        self::assertEquals('token', $token->toString());
        self::assertEquals('token', (string) $token);
        self::assertSame($expired, $token->getExpiresAt());
        self::assertTrue($token->isExpired());

        $notExpired = new \DateTimeImmutable();
        $notExpired = $notExpired->add(new \DateInterval('PT30M'));
        $token = new Token('token', $notExpired);
        self::assertSame($notExpired, $token->getExpiresAt());
        self::assertFalse($token->isExpired());
    }
}
