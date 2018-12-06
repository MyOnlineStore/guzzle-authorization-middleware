<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware;

final class Token
{
    /**
     * @var string
     */
    private $token;

    /**
     * @var \DateTimeImmutable|null
     */
    private $expiresAt;

    public function __construct(string $token, \DateTimeImmutable $expiresAt = null)
    {
        $this->token = $token;
        $this->expiresAt = $expiresAt;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return \DateTimeImmutable|null
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    public function isExpired(): bool
    {
        if (null === $this->expiresAt) {
            return false;
        }

        return (new \DateTimeImmutable()) > $this->expiresAt;
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
