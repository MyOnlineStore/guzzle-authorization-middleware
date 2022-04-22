<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\UnencryptedToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveTokenUri;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class Jwt implements TokenManagerInterface
{
    private LoggerInterface $logger;

    public function __construct(
        private ClientInterface $httpClient,
        private Parser $jwtParser,
        private RequestFactoryInterface $requestFactory,
        private UriProviderInterface $uriProvider,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @throws FailedToRetrieveToken
     */
    public function getToken(): Token
    {
        $token = '';

        try {
            $response = $this->httpClient->send(
                $this->requestFactory->createRequest(
                    'GET',
                    $this->uriProvider->getTokenUri()
                )
            );

            $token = (string) (\json_decode($response->getBody()->getContents(), true)['accessToken'] ?? '');
        } catch (FailedToRetrieveTokenUri | GuzzleException | \RuntimeException $exception) {
            $this->logger->critical(
                'Unable to fetch JWT token',
                [
                    'message' => $exception->getMessage(),
                    'previous' => $exception->getPrevious(),
                    'trace' => $exception->getTraceAsString(),
                ]
            );
        }

        try {
            $parsedToken = $this->jwtParser->parse($token);
            \assert($parsedToken instanceof UnencryptedToken);

            $expiration = $parsedToken->claims()->get('exp');
        } catch (\RuntimeException $exception) {
            throw FailedToRetrieveToken::dueTo('Unable to parse token', $exception);
        }

        if (!$expiration instanceof \DateTimeImmutable) {
            throw FailedToRetrieveToken::dueTo('JWT does not contain an expiration');
        }

        return new Token($token, $expiration);
    }
}
