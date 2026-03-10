# Keycloak Setup Guide for PKCE with Signed JWT

## Step 1: Export Public Key from Private Key

If you have the private key file, export the public key:

manually:
```bash
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

## Step 2: Configure Keycloak Client

### Option A: Using Keycloak Admin Console (UI)

1. **Navigate to your client:**
   - Go to Keycloak Admin Console
   - Select your realm
   - Go to **Clients** → Select your client

2. **Configure Client Authentication:**
   - Go to the **Credentials** tab
   - Under **Client Authenticator**, select **Signed JWT with Client Secret** or **Signed JWT**
   - In the **Public Key** field, paste the contents of your `public-key.pem` file
   - The public key should be in PEM format (starts with `-----BEGIN PUBLIC KEY-----`)

3. **Configure PKCE:**
   - Go to the **Advanced** tab
   - Under **Proof Key for Code Exchange Code Challenge Method**, select **S256** (or your preferred method)
   - Make sure **Proof Key for Code Exchange Code Challenge Method** is enabled

4. **Configure Redirect URI:**
   - Go to the **Settings** tab
   - Add your redirect URI (e.g., `http://localhost:8080/callback`) to **Valid Redirect URIs**

### Option B: Using Keycloak Admin REST API

You can also configure the client using the REST API. The public key needs to be added to the client's `attributes` or `credentials`.

## Step 3: Verify Public Key Format

The public key should be in PEM format:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

If Keycloak requires a different format, you may need to convert it.

## Step 4: Set Environment Variables

```bash
export OAUTH_PRIVATE_KEY_PATH=/path/to/private-key.pem
export OAUTH_REDIRECT_URI=http://localhost:8080/callback
export OAUTH_SCOPE="openid email"
export OAUTH_CODE_CHALLENGE_METHOD=S256

# Optional: Set JWT Key ID if you have multiple keys configured
export OAUTH_JWT_KID=your-key-id
```

## Step 5: Run the Application

```bash
grant --grant_type pkce --issuer <keycloak-issuer-url> --client_id <your-client-id>
```

## Troubleshooting "Unable to load public key" Error

### Common Issues:

1. **Public key not configured:**
   - Verify the public key is pasted correctly in Keycloak client settings
   - Make sure there are no extra spaces or line breaks
   - The entire PEM block should be copied (including BEGIN and END lines)

2. **Key format mismatch:**
   - Ensure the public key matches the private key
   - Verify the key algorithm is RSA (not EC or other algorithms)
   - Check that the key size is supported (typically 2048 or 4096 bits)

3. **Key ID (kid) mismatch:**
   - If Keycloak has multiple keys configured, you may need to set `OAUTH_JWT_KID`
   - The `kid` in the JWT header must match the key ID in Keycloak
   - If you only have one key, you can leave `kid` empty (it will be omitted from the JWT)

4. **JWT claims issues:**
   - Verify `iss` (issuer) matches your client ID
   - Verify `aud` (audience) matches the token endpoint URL
   - Check that the JWT is not expired (5-minute expiration by default)

5. **Algorithm mismatch:**
   - Ensure Keycloak expects RS256 (RSA with SHA-256)
   - The JWT is signed with RS256 by default

### Debug Steps:

1. **Verify public key extraction:**
   ```bash
   openssl rsa -in private-key.pem -pubout -out public-key.pem
   cat public-key.pem
   ```

2. **Check Keycloak client configuration:**
   - Verify the public key is correctly stored in Keycloak
   - Check the client authentication method is set correctly

3. **Test JWT generation:**
   - The application will generate a JWT with the required claims
   - You can decode the JWT at https://jwt.io to verify the claims

4. **Check Keycloak logs:**
   - Look for detailed error messages in Keycloak server logs
   - The error message should indicate what's wrong with the key

## Alternative: Using JWKS URL

If you prefer, you can configure Keycloak to use a JWKS (JSON Web Key Set) URL instead of directly storing the public key. This requires hosting your public key as a JWKS endpoint.

