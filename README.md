
# goliath - The humongously small OIDC & OAuth authorization server

Standalone authorization server that implements a subset of OIDC and
related OAuth2 specifications. The goal is to make it useful for
testing your OIDC enabled apps without setting up an actual IAM like
Okta, Keycloak or Entra ID.

# Usage

```text
$ goliath \
    --port 8000 \
    --pkce
```

# Supported endpoints
- ✅ `/ping` for debugging purposes
- ✅ `/authorize` [OIDC Authorization Endpoint ](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
- ✅ `/token` [OIDC Token Endpoint ](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint)

# Planned endpoints & specifications

- `/.well-known/openid-configuration` [OpenID Connect Discovery 1.0
  incorporating errata set
  2](https://openid.net/specs/openid-connect-discovery-1_0.html)
- `/introspect` [OAuth 2.0 Token
  Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- PKCE, [RFC7636 Proof Key for Code Exchange by OAuth Public
  Clients](https://www.rfc-editor.org/rfc/rfc7636)

# Example usage

## 1) Initiate the code authorization flow

```ini
$ curl --include "http://localhost:8000/authorize?scope=openid&state=foo-state-from-client&redirect_uri=https://example.com/callback&nonce=random-nonce-${RANDOM}"
HTTP/1.1 200 OK
Location: https://example.com/callback?code=K4C6CIUMG4YXUVNQUSZXCLR5TI&state=foo-state-from-client
Date: Sun, 25 May 2025 13:32:56 GMT
Content-Length: 19
Content-Type: text/plain; charset=utf-8

Starting code flow
```

To extract the returned `code` and put it into a variable in the
shell, do:

```ini
$ code=$(
  curl --include 'http://localhost:8000/authorize?scope=openid&state=foo-state-from-client&redirect_uri=https://example.com/callback&nonce=2324' 2>&1 |
  sed -nr 's#.*Location: .*code=([^&]*)\&.*#\1#p')
```

You can use `$code` to refer to the server code in the step below.

## 2) Use the returned code to create an access token, id token and refresh token

```ini
$ curl \
  --verbose \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data code=$code \
  http://localhost:8000/token
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDgxOTAxMTIsImlhdCI6MTc0ODE4MjkxMiwiaXNzIjoiOi8vbG9jYWxob3N0OjgwMDAifQ.l2BAAx72K82RUiC5gJleAdzisGGK2EFWE6xSDdZZ4ic",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDgxOTAxMTIsImlhdCI6MTc0ODE4MjkxMiwiaXNzIjoiOi8vbG9jYWxob3N0OjgwMDAiLCJub25jZSI6IjIzMjQifQ.27rxUD5gd3fVJ4HYUZk4ZMuGHJvqAL4dyrtjSDVD5v0",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDgxOTAxMTIsImlhdCI6MTc0ODE4MjkxMiwiaXNzIjoiOi8vbG9jYWxob3N0OjgwMDAifQ.l2BAAx72K82RUiC5gJleAdzisGGK2EFWE6xSDdZZ4ic",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```
