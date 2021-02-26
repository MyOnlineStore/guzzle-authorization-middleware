<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use Psr\Http\Message\RequestInterface;

final class BearerAuthorization
{
    /** @var TokenManagerInterface */
    private $tokenManager;

    public function __construct(TokenManagerInterface $tokenManager)
    {
        $this->tokenManager = $tokenManager;
    }

    /**
     * @param callable(RequestInterface, array): mixed $next
     *
     * @return callable(RequestInterface, array): mixed
     */
    public function __invoke(callable $next): callable
    {
        return function (
            RequestInterface $request,
            array $options = []
        ) use ($next) {
            return $next(
                $request->withHeader(
                    'Authorization',
                    'bearer ' . $this->tokenManager->getToken()->__toString()
                ),
                $options
            );
        };
    }
}
