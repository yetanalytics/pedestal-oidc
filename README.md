# pedestal-oidc

[![CI](https://github.com/yetanalytics/pedestal-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/yetanalytics/pedestal-oidc/actions/workflows/ci.yml)

This lib provides a [pedestal](https://github.com/pedestal/pedestal) interceptor for working with [OIDC](https://openid.net/connect/) tokens.

## Usage

Give `decode-interceptor` a function that returns a map of JWKS key IDs to the keys themselves and place it in your interceptor chain. Decoded claims will be placed on the request at `:com.yetanalytics.pedestal-oidc/claims`.

See [the demo](src/dev/com/yetanalytics/pedestal_oidc/service.clj) for a simple example.

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
