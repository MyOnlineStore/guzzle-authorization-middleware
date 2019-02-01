<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Lcobucci\JWT\Parser;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class Jwt implements TokenManagerInterface
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var Parser
     */
    private $jwtParser;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var UriProviderInterface
     */
    private $uriProvider;

    public function __construct(
        ClientInterface $httpClient,
        Parser $jwtParser,
        RequestFactoryInterface $requestFactory,
        UriProviderInterface $uriProvider,
        LoggerInterface $logger = null
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->uriProvider = $uriProvider;
        $this->jwtParser = $jwtParser;
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @throws \InvalidArgumentException If the token is not a valid JWT
     * @throws \OutOfBoundsException     If the token does not have an exp claim
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

            $token = \json_decode($response->getBody()->getContents(), true)['accessToken'] ?? '';
        } catch (GuzzleException $exception) {
            $this->logger->critical(
                'Unable to fetch JWT token',
                [
                    'message' => $exception->getMessage(),
                    'previous' => $exception->getPrevious(),
                    'trace' => $exception->getTraceAsString(),
                ]
            );
        }

        return new Token(
            $token,
            (new \DateTimeImmutable())->setTimestamp($this->jwtParser->parse($token)->getClaim('exp'))
        );
    }
}
