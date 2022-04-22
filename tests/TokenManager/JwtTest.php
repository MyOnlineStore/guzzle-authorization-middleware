<?php
declare(strict_types=1);

namespace MyOnlineStore\GuzzleAuthorizationMiddleware\Tests\TokenManager;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\TransferException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Exception\FailedToRetrieveToken;
use MyOnlineStore\GuzzleAuthorizationMiddleware\Token;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\Jwt;
use MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\UriProviderInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

final class JwtTest extends TestCase
{
    /** @var ClientInterface&MockObject */
    private ClientInterface $httpClient;

    private Jwt $jwtManager;

    /** @var Parser&MockObject */
    private Parser $jwtParser;

    /** @var LoggerInterface&MockObject */
    private LoggerInterface $logger;

    /** @var RequestFactoryInterface&MockObject */
    private RequestFactoryInterface $requestFactory;

    /** @var UriProviderInterface&MockObject */
    private UriProviderInterface $uriProvider;

    protected function setUp(): void
    {
        $this->jwtManager = new Jwt(
            $this->httpClient = $this->createMock(ClientInterface::class),
            $this->jwtParser = $this->createMock(Parser::class),
            $this->requestFactory = $this->createMock(RequestFactoryInterface::class),
            $this->uriProvider = $this->createMock(UriProviderInterface::class),
            $this->logger = $this->createMock(LoggerInterface::class)
        );
    }

    public function testGetToken(): void
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
            ->willReturn($jwtToken = $this->createMock(UnencryptedToken::class));

        $jwtToken->expects(self::once())
            ->method('claims')
            ->willReturn(new DataSet(['exp' => $expiration = new \DateTimeImmutable()], 'json'));

        self::assertEquals(new Token('access-token', $expiration), $this->jwtManager->getToken());
    }

    public function testGetTokenWithoutExpiresAt(): void
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
            ->willReturn($jwtToken = $this->createMock(UnencryptedToken::class));

        $jwtToken->expects(self::once())
            ->method('claims')
            ->willReturn(new DataSet([], ''));

        $this->expectException(FailedToRetrieveToken::class);

        $this->jwtManager->getToken();
    }

    public function testCatchesGuzzleException(): void
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

        $this->logger->expects(self::once())
            ->method('critical')
            ->with('Unable to fetch JWT token', self::isType('array'));

        $this->jwtParser->expects(self::once())
            ->method('parse')
            ->with('')
            ->willThrowException(new \InvalidArgumentException());

        $this->expectException(\InvalidArgumentException::class);

        $this->jwtManager->getToken();
    }

    public function testCatchesParseException(): void
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
            ->willThrowException(new \RuntimeException());

        $this->expectException(FailedToRetrieveToken::class);

        $this->jwtManager->getToken();
    }
}
