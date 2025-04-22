
# goliath - An colossal OIDC test bed

Standalone authorization server that implements a subset of OIDC and
related OAuth2 specification. Useful for testing your OIDC enabled
apps without setting up an actual IAM like Okta, Keycloak or Entra ID.

# Usage

```text
$ goliath \
    --port 8000 \
    --pkce
```

# Supported endpoints
- `/ping` for debugging purposes

# Planned endpoints & specifications

- `/.well-known/openid-configuration` [OpenID Connect Discovery 1.0
  incorporating errata set
  2](https://openid.net/specs/openid-connect-discovery-1_0.html)
- `/authorize` [OIDC Authorization Endpoint ](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
- `/token` [OIDC Token Endpoint ](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint)
- `/introspect` [OAuth 2.0 Token
  Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC7636 Proof Key for Code Exchange by OAuth Public
  Clients](https://www.rfc-editor.org/rfc/rfc7636)
