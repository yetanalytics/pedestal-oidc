# pedestal-oidc

[![CI](https://github.com/yetanalytics/pedestal-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/yetanalytics/pedestal-oidc/actions/workflows/ci.yml)

[![Clojars Version](https://img.shields.io/clojars/v/com.yetanalytics/pedestal-oidc)](https://clojars.org/com.yetanalytics/pedestal-oidc)

This lib provides a [pedestal](https://github.com/pedestal/pedestal) interceptor for decoding [OIDC](https://openid.net/connect/) tokens, utilities for retrieving and unsigning (inspired by [clj-jwt](https://gitlab.nsd.no/clojure/clj-jwt)) and for performing simple OIDC discovery.

## Usage

See [the demo](src/dev/com/yetanalytics/pedestal_oidc/service.clj) for a simple example of usage.

### Interceptor

Give `com.yetanalytics.pedestal-oidc.interceptor/decode-interceptor` a "get-keyset" function that returns either:

* a map of JWKS key IDs to the keys themselves.
* a function that takes such an ID and (maybe) returns a key. This may be useful if you need to maintain a cache.

Use the resulting interceptor in a pedestal route. Decoded claims will be placed on the request at `:com.yetanalytics.pedestal-oidc/claims`.

#### Failures

By default the `decode-interceptor` will respond to any failure with a 401. You can customize this behavior by providing a `:unauthorized` keyword arg which is a function that will recieve the pedestal context, a failure keyword and possibly an exception. The possible failure keywords are:

* `:header-missing` - The `Authorization` header (or whatever is provided for `check-header`) is not present. No exception.
* `:header-invalid` - The header does not start with `Bearer `. No exception.
* `:kid-not-found` - The indicated public key is not found by ID. An exception is passed with ex-data containing the `:kid`
* `:validation` - The token failed unsigning with `buddy-sign`. The provided exception contains the `:cause` in its ex-data.
* `:unknown` - An unknown exception was thrown. See the provided exception for more info.

The default `:unauthorized` function will add the failure keyword to the context as `:com.yetanalytics.pedestal-oidc/failure`. By default exceptions will not be retained.

### Getting Keysets

`com.yetanalytics.pedestal-oidc.jwt/get-keyset` will attempt to fetch a valid keyset from the given `jwks-uri`. How this is stored/cached is up to the lib consumer.

### Discovery Utils

`com.yetanalytics.pedestal-oidc.discovery` provides facilities for pulling config metadata (like the `jwks_uri`) from the IDP per [the spec](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

## Development

To run a demo instance of keycloak:

    make keycloak-demo

This will host a JWKS uri of http://0.0.0.0:8080/auth/realms/test/protocol/openid-connect/certs with the realm's public keyset.

You can then run the demo API:

    make run-dev

## Testing

Run the test suite:

    make test

## License

Copyright © 2022 Yet Analytics Inc.

Distributed under the Apache License version 2.0.
