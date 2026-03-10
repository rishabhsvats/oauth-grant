package flow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func OauthFlow(issuer, clientID, flow string) (string, error) {
	var provider *OauthProvider
	var token string
	provider, err := initializeOauthProvider(issuer)
	if err != nil {
		return "", err
	}
	switch flow {
	case "device":
		token, err = GetDeviceFlowToken(provider, clientID)
	case "pkce":
		token, err = GetPKCEFlowToken(provider, clientID)
	case "authcode":
		token, err = GetAuthCodeConfidentialFlowToken(provider, clientID)
	default:
		return "", fmt.Errorf("unsupported oauth flow: %s", flow)
	}
	if err != nil {
		return "", err
	} else {
		return token, nil
	}

}

func initializeOauthProvider(url string) (*OauthProvider, error) {
	var provider *OauthProvider
	res, err := http.Get(url + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(body, &provider); err != nil {
		return nil, err
	}
	return provider, nil
}

func GetDeviceFlowToken(provider *OauthProvider, clientID string) (string, error) {

	values := url.Values{}
	values.Add("client_id", clientID)
	values.Add("scope", "openid email")

	resp, err := http.PostForm(provider.DeviceAuthEndpoint, values)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %s ", resp.Status)
	}
	var dr DeviceResp
	if err := json.Unmarshal(b, &dr); err != nil {
		return "", fmt.Errorf("error while unmarshling token: %s", err)
	}
	uric := dr.VerificationURIComplete
	uri := dr.VerificationURI
	if uri == "" {
		uri = dr.VerificationURI
	}
	fmt.Printf("\nOpen link : %s in browser and enter verification code %s\n", uri, dr.UserCode)
	fmt.Printf("\nOr open link : %s directly in the browser\n", uric)

	fmt.Printf("\nCode will be valid for %d seconds\n", dr.ExpiresIn)

	for {
		values := url.Values{}
		values.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		values.Add("client_id", clientID)
		values.Add("device_code", dr.DeviceCode)
		values.Add("scope", "openid email")

		resp, err := http.PostForm(provider.TokenEndpoint, values)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		otr := OIDCTokenResponse{}
		if err := json.Unmarshal(b, &otr); err != nil {
			return "", err
		}

		if otr.AccessToken != "" {
			fmt.Println("\nTokens received!")
			val, err := json.MarshalIndent(otr, "", " ")
			if err != nil {
				return "", err
			}
			return string(val), nil

		}
		switch otr.Error {
		case "authorization_pending":
			//fmt.Printf("\n debug: authorization request is still pending as the you have not completed authentication. sleeping for interval: %d\n", dr.Interval)
			time.Sleep(time.Duration(dr.Interval) * time.Second)
		case "slow_down":
			time.Sleep(time.Duration(dr.Interval)*time.Second + 5*time.Second)
		case "access_denied":
			return "", fmt.Errorf("the authorization request was denied: %s", otr.Error)
		case "expired_token":
			return "", fmt.Errorf("device_code has expired as it is older than: %d", dr.ExpiresIn)
		default:
			return "", fmt.Errorf("unexpected error in the device flow: %s", otr.Error)
		}
	}
}

// GenerateCodeVerifier generates a random code verifier for PKCE
func GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateCodeChallenge generates a code challenge from code verifier using S256
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateState generates a random state parameter for CSRF protection
func GenerateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// LoadPrivateKey loads a private key from a file path
func LoadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	} else {
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	return key, nil
}

// GenerateSignedJWT generates a signed JWT assertion for client authentication
func GenerateSignedJWT(privateKey *rsa.PrivateKey, issuer, clientID, tokenEndpoint string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": clientID,                        // Issuer (client ID)
		"sub": clientID,                        // Subject (client ID)
		"aud": tokenEndpoint,                   // Audience (token endpoint)
		"jti": fmt.Sprintf("%d", now.Unix()),   // JWT ID
		"iat": now.Unix(),                      // Issued at
		"exp": now.Add(time.Minute * 5).Unix(), // Expiration (5 minutes)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set kid header only if provided via environment variable
	// Keycloak can work with or without kid, but if you have multiple keys, kid is required
	if kid := os.Getenv("OAUTH_JWT_KID"); kid != "" {
		token.Header["kid"] = kid
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

// GetAuthCodeConfidentialFlowToken implements the authorization code flow for
// a Keycloak confidential client using client_id and client_secret (no PKCE).
func GetAuthCodeConfidentialFlowToken(provider *OauthProvider, clientID string) (string, error) {
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	if clientSecret == "" {
		return "", fmt.Errorf("OAUTH_CLIENT_SECRET environment variable must be set for confidential client")
	}

	redirectURI := os.Getenv("OAUTH_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/callback"
	}

	scope := os.Getenv("OAUTH_SCOPE")
	if scope == "" {
		scope = "openid email"
	}

	state, err := GenerateState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	authURL := buildAuthorizationURLConfidential(provider.AuthorizationEndpoint, clientID, redirectURI, scope, state)

	fmt.Printf("\nPlease open the following URL in your browser:\n%s\n\n", authURL)
	fmt.Println("Waiting for authorization code...")

	authCode, err := receiveAuthorizationCode(redirectURI, state)
	if err != nil {
		return "", fmt.Errorf("failed to receive authorization code: %w", err)
	}

	fmt.Printf("\nAuthorization code received: %s\n", authCode)

	token, err := exchangeCodeForTokenConfidential(provider.TokenEndpoint, clientID, clientSecret, authCode, redirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

// buildAuthorizationURLConfidential builds the authorization URL for the confidential client flow (no PKCE).
func buildAuthorizationURLConfidential(authEndpoint, clientID, redirectURI, scope, state string) string {
	u, _ := url.Parse(authEndpoint)
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", scope)
	params.Add("state", state)
	u.RawQuery = params.Encode()
	return u.String()
}

// exchangeCodeForTokenConfidential exchanges the authorization code for tokens using client_id and client_secret.
func exchangeCodeForTokenConfidential(tokenEndpoint, clientID, clientSecret, authCode, redirectURI string) (string, error) {
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("code", authCode)
	values.Add("redirect_uri", redirectURI)

	resp, err := http.PostForm(tokenEndpoint, values)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(b, &errorResp); err == nil {
			if errorDesc, ok := errorResp["error_description"].(string); ok {
				return "", fmt.Errorf("token request failed with status %d: %s - %s", resp.StatusCode, errorResp["error"], errorDesc)
			}
		}
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(b))
	}

	var otr OIDCTokenResponse
	if err := json.Unmarshal(b, &otr); err != nil {
		return "", fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	if otr.Error != "" {
		return "", fmt.Errorf("token response error: %s", otr.Error)
	}

	fmt.Println("\nTokens received!")
	val, err := json.MarshalIndent(otr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal token response: %w", err)
	}

	return string(val), nil
}

// GetPKCEFlowToken implements the PKCE flow with signed JWT authentication
func GetPKCEFlowToken(provider *OauthProvider, clientID string) (string, error) {
	// Get configuration from environment or use defaults
	privateKeyPath := os.Getenv("OAUTH_PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		return "", fmt.Errorf("OAUTH_PRIVATE_KEY_PATH environment variable must be set")
	}

	redirectURI := os.Getenv("OAUTH_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/callback"
	}

	scope := os.Getenv("OAUTH_SCOPE")
	if scope == "" {
		scope = "openid email"
	}

	codeChallengeMethod := os.Getenv("OAUTH_CODE_CHALLENGE_METHOD")
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	// Step 1: Generate signed JWT
	privateKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	signedJWT, err := GenerateSignedJWT(privateKey, provider.Issuer, clientID, provider.TokenEndpoint)
	if err != nil {
		return "", fmt.Errorf("failed to generate signed JWT: %w", err)
	}

	// Step 3: Generate PKCE code verifier and challenge
	codeVerifier, err := GenerateCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := GenerateCodeChallenge(codeVerifier)
	state, err := GenerateState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Step 4: Generate authorization URL
	authURL, err := buildAuthorizationURL(provider.AuthorizationEndpoint, clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, state)
	if err != nil {
		return "", fmt.Errorf("failed to build authorization URL: %w", err)
	}

	fmt.Printf("\nPlease open the following URL in your browser:\n%s\n\n", authURL)
	fmt.Println("Waiting for authorization code...")

	// Step 5: Receive authorization code
	authCode, err := receiveAuthorizationCode(redirectURI, state)
	if err != nil {
		return "", fmt.Errorf("failed to receive authorization code: %w", err)
	}

	fmt.Printf("\nAuthorization code received: %s\n", authCode)

	// Step 6: Exchange code for token with signed JWT and code_verifier
	token, err := exchangeCodeForToken(provider.TokenEndpoint, clientID, authCode, redirectURI, signedJWT, codeVerifier)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

// buildAuthorizationURL builds the authorization URL with PKCE parameters
func buildAuthorizationURL(authEndpoint, clientID, redirectURI, scope, codeChallenge, codeChallengeMethod, state string) (string, error) {
	u, err := url.Parse(authEndpoint)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", scope)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", codeChallengeMethod)
	params.Add("state", state)

	u.RawQuery = params.Encode()
	return u.String(), nil
}

// receiveAuthorizationCode starts a local HTTP server to receive the authorization code
func receiveAuthorizationCode(redirectURI, expectedState string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}

	codeChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	server := &http.Server{
		Addr: u.Host,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			code := query.Get("code")
			state := query.Get("state")
			errMsg := query.Get("error")

			if errMsg != "" {
				errorChan <- fmt.Errorf("authorization error: %s", errMsg)
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "Authorization failed: %s", errMsg)
				return
			}

			if state != expectedState {
				errorChan <- fmt.Errorf("state mismatch: expected %s, got %s", expectedState, state)
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "State mismatch")
				return
			}

			if code == "" {
				errorChan <- fmt.Errorf("authorization code not found in callback")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "Authorization code not found")
				return
			}

			codeChan <- code
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Authorization successful! You can close this window.")
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	select {
	case code := <-codeChan:
		server.Shutdown(ctx)
		return code, nil
	case err := <-errorChan:
		server.Shutdown(ctx)
		return "", err
	case <-ctx.Done():
		server.Shutdown(ctx)
		return "", fmt.Errorf("timeout waiting for authorization code")
	}
}

// exchangeCodeForToken exchanges the authorization code for tokens using signed JWT and code_verifier
func exchangeCodeForToken(tokenEndpoint, clientID, authCode, redirectURI, signedJWT, codeVerifier string) (string, error) {
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("code", authCode)
	values.Add("redirect_uri", redirectURI)
	values.Add("code_verifier", codeVerifier)
	values.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	values.Add("client_assertion", signedJWT)

	resp, err := http.PostForm(tokenEndpoint, values)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error response
		var errorResp map[string]interface{}
		if err := json.Unmarshal(b, &errorResp); err == nil {
			if errorDesc, ok := errorResp["error_description"].(string); ok {
				return "", fmt.Errorf("token request failed with status %d: %s - %s", resp.StatusCode, errorResp["error"], errorDesc)
			}
		}
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(b))
	}

	var otr OIDCTokenResponse
	if err := json.Unmarshal(b, &otr); err != nil {
		return "", fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	if otr.Error != "" {
		return "", fmt.Errorf("token response error: %s", otr.Error)
	}

	fmt.Println("\nTokens received!")
	val, err := json.MarshalIndent(otr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal token response: %w", err)
	}

	return string(val), nil
}
