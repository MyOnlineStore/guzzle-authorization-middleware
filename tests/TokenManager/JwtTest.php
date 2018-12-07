<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\TokenManager;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\TransferException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token as JwtToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\Jwt;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\UriProviderInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

final class JwtTest extends TestCase
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var Jwt
     */
    private $jwtManager;

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

    protected function setUp()
    {
        $this->jwtManager = new Jwt(
            $this->httpClient = $this->createMock(ClientInterface::class),
            $this->jwtParser = $this->createMock(Parser::class),
            $this->requestFactory = $this->createMock(RequestFactoryInterface::class),
            $this->uriProvider = $this->createMock(UriProviderInterface::class)
        );
    }

    public function testGetToken()
    {
        $this->uriProvider->expects(self::once())
            ->method('getTokenUri')
            ->willReturn($tokenUri = $this->createMock(UriInterface::class));

        $this->requestFactory->expects(self::once())
            ->method('createRequest')
            ->with('GET', $tokenUri)
            ->willReturn($request = $this->createMock(RequestInterface::class));

        $this->httpClient->expects(self::once())
            ->method('send')
            ->with($request)
            ->willReturn($response = $this->createMock(ResponseInterface::class));

        $response->expects(self::once())
            ->method('getBody')
            ->willReturn($stream = $this->createMock(StreamInterface::class));

        $stream->expects(self::once())
            ->method('getContents')
            ->willReturn('{"accessToken":"access-token"}');

        $this->jwtParser->expects(self::once())
            ->method('parse')
            ->with('access-token')
            ->willReturn($jwtToken = $this->createMock(JwtToken::class));

        $jwtToken->expects(self::once())
            ->method('getClaim')
            ->with('exp')
            ->willReturn($timestamp = 1544094154);

        self::assertEquals(
            new Token(
                'access-token',
                (new \DateTimeImmutable())->setTimestamp($timestamp)
            ),
            $this->jwtManager->getToken()
        );
    }

    public function testGetTokenWithoutExpiresAt()
    {
        $this->uriProvider->expects(self::once())
            ->method('getTokenUri')
            ->willReturn($tokenUri = $this->createMock(UriInterface::class));

        $this->requestFactory->expects(self::once())
            ->method('createRequest')
            ->with('GET', $tokenUri)
            ->willReturn($request = $this->createMock(RequestInterface::class));

        $this->httpClient->expects(self::once())
            ->method('send')
            ->with($request)
            ->willReturn($response = $this->createMock(ResponseInterface::class));

        $response->expects(self::once())
            ->method('getBody')
            ->willReturn($stream = $this->createMock(StreamInterface::class));

        $stream->expects(self::once())
            ->method('getContents')
            ->willReturn('{"accessToken":"access-token"}');

        $this->jwtParser->expects(self::once())
            ->method('parse')
            ->with('access-token')
            ->willReturn($jwtToken = $this->createMock(JwtToken::class));

        $jwtToken->expects(self::once())
            ->method('getClaim')
            ->with('exp')
            ->willThrowException(new \OutOfBoundsException());

        $this->expectException(\OutOfBoundsException::class);

        $this->jwtManager->getToken();
    }

    public function testCatchesGuzzleException()
    {
        $this->uriProvider->expects(self::once())
            ->method('getTokenUri')
            ->willReturn($tokenUri = $this->createMock(UriInterface::class));

        $this->requestFactory->expects(self::once())
            ->method('createRequest')
            ->with('GET', $tokenUri)
            ->willReturn($request = $this->createMock(RequestInterface::class));

        $this->httpClient->expects(self::once())
            ->method('send')
            ->with($request)
            ->willThrowException(new TransferException());

        $this->jwtParser->expects(self::once())
            ->method('parse')
            ->with('')
            ->willThrowException(new \InvalidArgumentException());

        $this->expectException(\InvalidArgumentException::class);

        $this->jwtManager->getToken();
    }
}
