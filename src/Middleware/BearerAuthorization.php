<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use Psr\Http\Message\MessageInterface;

final class BearerAuthorization
{
    /** @var TokenManagerInterface */
    private $tokenManager;

    public function __construct(TokenManagerInterface $tokenManager)
    {
        $this->tokenManager = $tokenManager;
    }

    /**
     * @param callable(MessageInterface, array): mixed $next
     *
     * @return callable(MessageInterface, array): mixed
     */
    public function __invoke(callable $next): callable
    {
        return function (
            MessageInterface $request,
            array $options = []
        ) use ($next) {
            return $next(
                $request->withHeader(
                    'Authorization',
                    'bearer ' . $this->tokenManager->getToken()->toString()
                ),
                $options
            );
        };
    }
}
