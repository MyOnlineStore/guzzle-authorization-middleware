<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Exception;

final class FailedToRetrieveTokenUri extends \RuntimeException implements AuthorizationMiddlewareException
{
    public static function dueTo(string $reason, ?\Throwable $previous = null): self
    {
        return new self($reason, 0, $previous);
    }
}
