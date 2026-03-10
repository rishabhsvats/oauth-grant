# Authorization Code Flow with Keycloak Confidential Client

This flow uses the standard OAuth 2.0 authorization code grant with a **confidential client** (client_id + client_secret). No PKCE or signed JWT is required.

## Prerequisites

- Keycloak realm with a **confidential** client
- Client secret from Keycloak
- A redirect URI configured on the client (e.g. `http://localhost:8080/callback`)

## Keycloak Setup

1. **Create or edit your client**
   - Keycloak Admin Console → your realm → **Clients** → your client

2. **Client authentication**
   - **Settings** tab → **Client authentication** → **ON**
   - **Credentials** tab → copy or regenerate the **Client secret**

3. **Redirect URI**
   - **Settings** tab → **Valid redirect URIs** → add `http://localhost:8080/callback` (or the URI you will use)

## Environment Variables

**Required:**

| Variable               | Description                          |
|------------------------|--------------------------------------|
| `OAUTH_CLIENT_SECRET`  | Client secret of the confidential client |

**Optional:**

| Variable               | Default                        | Description        |
|------------------------|--------------------------------|--------------------|
| `OAUTH_REDIRECT_URI`   | `http://localhost:8080/callback` | Callback URL       |
| `OAUTH_SCOPE`          | `openid email`                 | OAuth scopes       |

## Usage

1. **Set the client secret (required):**

   ```bash
   export OAUTH_CLIENT_SECRET="your-client-secret"
   ```

2. **Optional: set redirect URI and scope:**

   ```bash
   export OAUTH_REDIRECT_URI=http://localhost:8080/callback
   export OAUTH_SCOPE="openid email"
   ```

3. **Run the authcode flow:**

   ```bash
   grant --grant_type authcode --issuer <keycloak-issuer-url> --client_id <your-client-id>
   ```

   Short flags:

   ```bash
   grant -f authcode -i <keycloak-issuer-url> -c <your-client-id>
   ```

4. **Complete the flow**
   - The tool prints a URL; open it in a browser.
   - Sign in to Keycloak if prompted.
   - The browser is redirected to the callback URL; the local server receives the code and exchanges it for tokens.
   - The token response is printed to the terminal.

**Example:**

```bash
export OAUTH_CLIENT_SECRET="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
grant -f authcode -i https://keycloak.example.com/realms/my-realm -c my-confidential-client
```

## Notes

- Ensure no other service is listening on the host/port of `OAUTH_REDIRECT_URI` (e.g. 8080 for `http://localhost:8080/callback`).
- The issuer URL is typically `https://<keycloak-host>/realms/<realm-name>` (no trailing slash).
