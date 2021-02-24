<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware;

final class Token
{
    /** @var string */
    private $token;

    /** @var \DateTimeImmutable */
    private $expiresAt;

    public function __construct(string $token, \DateTimeImmutable $expiresAt)
    {
        $this->token = $token;
        $this->expiresAt = $expiresAt;
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
        return (new \DateTimeImmutable()) > $this->expiresAt;
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
