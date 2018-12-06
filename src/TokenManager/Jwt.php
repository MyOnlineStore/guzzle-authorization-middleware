<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Lcobucci\JWT\Parser;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use Psr\Http\Message\RequestFactoryInterface;

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
        UriProviderInterface $uriProvider
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->uriProvider = $uriProvider;
        $this->jwtParser = $jwtParser;
    }

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
        }

        $expiresAt = null;
        $jwtToken = $this->jwtParser->parse($token);

        if ($jwtToken->hasClaim('exp')) {
            $expiresAt = (new \DateTimeImmutable())->setTimestamp($jwtToken->getClaim('exp'));
        }

        return new Token($token, $expiresAt);
    }
}
