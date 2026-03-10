# grant

A CLI tool for testing OAuth 2.0 / OpenID Connect grant flows against Keycloak (or any OIDC-compliant issuer). It supports device authorization, authorization code with confidential client, and authorization code with PKCE and signed JWT.

## Build and run

```bash
go build -o grant ./cmd/oauth
./grant --issuer <issuer-url> --client_id <client-id> --grant_type <flow>
```

Short form: `-i` (issuer), `-c` (client_id), `-f` (grant_type).

**Issuer** is your OIDC issuer URL (e.g. `https://keycloak.example.com/realms/my-realm`). **Grant type** is one of: `device`, `authcode`, `pkce`.

---

## Flows overview

| Flow        | Flag       | Client type    | Use case |
|------------|------------|----------------|----------|
| **Device** | `device`   | Public         | CLI / devices without a browser; user signs in elsewhere with a code. |
| **Auth code (confidential)** | `authcode` | Confidential | Standard browser redirect flow with `client_id` + `client_secret`. |
| **PKCE + signed JWT** | `pkce` | Confidential (JWT) | Browser redirect with PKCE and client authentication via signed JWT (no shared secret). |

Each flow has a dedicated README with setup and usage.

---

### Device flow (`device`)

[RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) device authorization grant. No client secret or redirect URI. The tool prints a verification URL and user code; you complete sign-in in a browser; the tool polls until tokens are returned. Suited for CLIs and headless devices.

```bash
grant -f device -i <issuer> -c <client-id>
```

→ **[README-device.md](README-device.md)** — Keycloak setup, usage, examples.

---

### Authorization code — confidential client (`authcode`)

Classic authorization code flow with a **confidential** client. You set `OAUTH_CLIENT_SECRET`; the tool opens a local callback server, prints the auth URL, and exchanges the code for tokens using `client_id` and `client_secret`.

```bash
export OAUTH_CLIENT_SECRET="your-secret"
grant -f authcode -i <issuer> -c <client-id>
```

→ **[README-authcode.md](README-authcode.md)** — Keycloak setup, env vars, usage.

---

### Authorization code — PKCE + signed JWT (`pkce`)

Authorization code flow with **PKCE** (S256) and client authentication by **signed JWT** (RSA key pair). No client secret; you set `OAUTH_PRIVATE_KEY_PATH` and configure the matching public key in Keycloak.

```bash
export OAUTH_PRIVATE_KEY_PATH=/path/to/private-key.pem
grant -f pkce -i <issuer> -c <client-id>
```

→ **[README-pkce.md](README-pkce.md)** — Key export, Keycloak client config, env vars, troubleshooting.

---

## Quick reference

| Flow     | Required env (besides CLI) | Keycloak |
|----------|----------------------------|----------|
| `device` | —                          | Device authorization enabled; public client. |
| `authcode` | `OAUTH_CLIENT_SECRET`    | Confidential client; redirect URI. |
| `pkce`   | `OAUTH_PRIVATE_KEY_PATH`   | Client with PKCE + public key for JWT. |

For optional env (e.g. `OAUTH_REDIRECT_URI`, `OAUTH_SCOPE`), see the flow-specific READMEs.
