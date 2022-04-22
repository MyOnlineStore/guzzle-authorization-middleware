<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Middleware;

use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\TokenManagerInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class BearerAuthorization
{
    private LoggerInterface $logger;

    public function __construct(
        private TokenManagerInterface $tokenManager,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
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
            try {
                return $next(
                    $request->withHeader(
                        'Authorization',
                        'bearer ' . $this->tokenManager->getToken()->toString()
                    ),
                    $options
                );
            } catch (FailedToRetrieveToken $exception) {
                $this->logger->critical(
                    'Failed to add authorization header.',
                    [
                        'message' => $exception->getMessage(),
                        'previous' => $exception->getPrevious(),
                        'trace' => $exception->getTraceAsString(),
                    ]
                );
            }

            return $next($request, $options);
        };
    }
}
