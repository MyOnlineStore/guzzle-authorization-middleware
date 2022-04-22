<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware;

/**
 * @psalm-immutable
 */
final class Token
{
    public function __construct(
        private string $token,
        private \DateTimeImmutable $expiresAt
    ) {
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isExpired(): bool
    {
        return (new \DateTimeImmutable()) >= $this->expiresAt;
    }

    public function toString(): string
    {
        return $this->token;
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
