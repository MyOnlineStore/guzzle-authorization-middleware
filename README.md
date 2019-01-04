# Guzzle Authorization Middleware
[![Build Status](https://travis-ci.org/MyOnlineStore/guzzle-authorization-middleware.svg?branch=master)](https://travis-ci.org/MyOnlineStore/guzzle-authorization-middleware)
[![Coverage Status](https://coveralls.io/repos/github/MyOnlineStore/guzzle-authorization-middleware/badge.svg?branch=add-coveralls)](https://coveralls.io/github/MyOnlineStore/guzzle-authorization-middleware?branch=add-coveralls)

Middleware that adds an Authorization bearer header to the request. The bearer token will be provided
via a `TokenManagerInterface` implementation.

## Requirements

An implementation for `MyOnlineStore\GuzzleAuthorizationMiddleware\TokenManager\UriProviderInterface`
must be provided. This implementation must return an `UriInterface` with the uri to fetch the bearer
token.
