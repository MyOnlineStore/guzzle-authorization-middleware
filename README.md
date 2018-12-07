# Guzzle Authorization Middleware

Middleware that adds an Authorization bearer header to the request. The bearer token will be provided
via a `TokenManagerInterface` implementation.

## Requirements

An implementation for `MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\UriProviderInterface`
must be provided. This implementation must return an `UriInterface` with the uri to fetch the bearer
token.
