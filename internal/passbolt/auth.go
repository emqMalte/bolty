package passbolt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	passboltapi "github.com/emqmalte/bolty/generated/passbolt"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type AuthService struct {
	Store              SecretStore
	PGP                PGPService
	Now                func() time.Time
	PassphraseOverride string
}

type TokenSet struct {
	Version      string `json:"version,omitempty"`
	Domain       string `json:"domain,omitempty"`
	VerifyToken  string `json:"verify_token,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type jwtChallenge struct {
	Version           string `json:"version"`
	Domain            string `json:"domain"`
	VerifyToken       string `json:"verify_token"`
	VerifyTokenExpiry int64  `json:"verify_token_expiry"`
}

func NewAuthService(store SecretStore) AuthService {
	return AuthService{
		Store: store,
		PGP:   NewPGPService(),
		Now:   time.Now,
	}
}

func (s AuthService) Login(ctx context.Context, profile Profile, totp string, opts ...Option) (TokenSet, error) {
	if s.Store == nil {
		return TokenSet{}, errors.New("secret store is required")
	}
	client, err := NewClient(profile.ServerURL, opts...)
	if err != nil {
		return TokenSet{}, err
	}
	privateKey, err := s.unlockedPrivateKey(profile.Name)
	if err != nil {
		return TokenSet{}, err
	}
	defer privateKey.ClearPrivateParams()

	verify, err := client.ViewAuthVerifyWithResponse(ctx)
	if err != nil {
		return TokenSet{}, err
	}
	if verify.JSON200 == nil {
		return TokenSet{}, fmt.Errorf("failed to fetch Passbolt server public key: status %s", verify.Status())
	}
	serverKey, err := s.PGP.PublicKey(verify.JSON200.Body.Keydata)
	if err != nil {
		return TokenSet{}, fmt.Errorf("parse server public key: %w", err)
	}
	challengePayload := s.newChallenge(profile.ServerURL)
	challenge, err := s.PGP.EncryptAndSignJSON(challengePayload, serverKey, privateKey)
	if err != nil {
		return TokenSet{}, fmt.Errorf("create jwt challenge: %w", err)
	}
	userID, err := parseUUID(profile.UserID)
	if err != nil {
		return TokenSet{}, err
	}
	resp, err := client.AuthJwtLoginWithResponse(ctx, passboltapi.AuthJwtLoginJSONRequestBody{
		UserId:    userID,
		Challenge: challenge,
	})
	if err != nil {
		return TokenSet{}, err
	}
	if resp.JSON200 == nil {
		return TokenSet{}, fmt.Errorf("jwt login failed: status %s body %s", resp.Status(), string(resp.Body))
	}

	var tokens TokenSet
	if err := s.PGP.DecryptArmoredJSON(resp.JSON200.Body.Challenge, privateKey, &tokens); err != nil {
		return TokenSet{}, fmt.Errorf("decrypt jwt token response: %w", err)
	}
	if tokens.VerifyToken != "" && tokens.VerifyToken != challengePayload.VerifyToken {
		return TokenSet{}, errors.New("jwt login response verify token did not match the request")
	}
	if tokens.Domain != "" && normalizeBaseURL(tokens.Domain) != challengePayload.Domain {
		return TokenSet{}, fmt.Errorf("jwt login response domain %q did not match profile server url %q", tokens.Domain, challengePayload.Domain)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return TokenSet{}, errors.New("jwt token response did not include access and refresh tokens")
	}
	if strings.TrimSpace(totp) != "" {
		if err := s.verifyTOTPWithAccessToken(ctx, profile, totp, tokens.AccessToken, opts...); err != nil {
			return TokenSet{}, err
		}
	}
	if err := s.Store.Set(profile.Name, SecretAccessToken, tokens.AccessToken); err != nil {
		return TokenSet{}, err
	}
	if err := s.Store.Set(profile.Name, SecretRefreshToken, tokens.RefreshToken); err != nil {
		return TokenSet{}, err
	}
	return tokens, nil
}

func (s AuthService) VerifyTOTP(ctx context.Context, profile Profile, code string, opts ...Option) error {
	client, err := s.authenticatedClient(profile, opts...)
	if err != nil {
		return err
	}
	return s.verifyTOTP(ctx, client, code)
}

func (s AuthService) verifyTOTPWithAccessToken(ctx context.Context, profile Profile, code, accessToken string, opts ...Option) error {
	allOpts := append([]Option{WithBearerToken(accessToken)}, opts...)
	client, err := NewClient(profile.ServerURL, allOpts...)
	if err != nil {
		return err
	}
	return s.verifyTOTP(ctx, client, code)
}

func (s AuthService) verifyTOTP(ctx context.Context, client *Client, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("totp code is required")
	}
	attempt := passboltapi.MfaAttempt{}
	if err := attempt.FromMfaAttempt0(passboltapi.MfaAttempt0{Totp: code}); err != nil {
		return err
	}
	resp, err := client.MfaVerifyAttemptWithResponse(ctx, passboltapi.MfaVerifyAttemptParamsMfaProviderNameTotp, attempt)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("totp verification failed: status %s body %s", resp.Status(), string(resp.Body))
	}
	return nil
}

func (s AuthService) Refresh(ctx context.Context, profile Profile, opts ...Option) (string, error) {
	if s.Store == nil {
		return "", errors.New("secret store is required")
	}
	refreshToken, err := s.Store.Get(profile.Name, SecretRefreshToken)
	if err != nil {
		return "", err
	}
	client, err := NewClient(profile.ServerURL, opts...)
	if err != nil {
		return "", err
	}
	userID, err := parseUUID(profile.UserID)
	if err != nil {
		return "", err
	}
	refreshID, err := parseUUID(refreshToken)
	if err != nil {
		return "", fmt.Errorf("stored refresh token is invalid: %w", err)
	}
	resp, err := client.AuthJwtRefreshWithResponse(ctx, passboltapi.AuthJwtRefreshJSONRequestBody{
		UserId:       userID,
		RefreshToken: refreshID,
	})
	if err != nil {
		return "", err
	}
	if resp.JSON200 == nil {
		return "", fmt.Errorf("jwt refresh failed: status %s body %s", resp.Status(), string(resp.Body))
	}
	access := resp.JSON200.Body.AccessToken
	if access == "" {
		return "", errors.New("jwt refresh response did not include an access token")
	}
	refresh, err := refreshTokenFromResponse(resp.HTTPResponse)
	if err != nil {
		return "", err
	}
	if err := s.Store.Set(profile.Name, SecretAccessToken, access); err != nil {
		return "", err
	}
	if err := s.Store.Set(profile.Name, SecretRefreshToken, refresh); err != nil {
		return "", err
	}
	return access, nil
}

func (s AuthService) Logout(ctx context.Context, profile Profile, opts ...Option) error {
	refreshToken, err := s.Store.Get(profile.Name, SecretRefreshToken)
	if err == nil {
		if refreshID, parseErr := parseUUID(refreshToken); parseErr == nil {
			if client, clientErr := s.authenticatedClient(profile, opts...); clientErr == nil {
				_, _ = client.AuthJwtLogoutWithResponse(ctx, passboltapi.AuthJwtLogoutJSONRequestBody{RefreshToken: &refreshID})
			}
		}
	}
	for _, name := range []string{SecretAccessToken, SecretRefreshToken, SecretPrivateKeyPass, SecretMetadataSessionKey} {
		if err := s.Store.Delete(profile.Name, name); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
	}
	return nil
}

func (s AuthService) AuthenticatedClient(ctx context.Context, profile Profile, opts ...Option) (*Client, error) {
	client, err := s.authenticatedClient(profile, opts...)
	if err != nil {
		return nil, err
	}
	resp, err := client.ViewAuthIsAuthenticatedWithResponse(ctx)
	if err == nil && resp.StatusCode() != http.StatusUnauthorized {
		return client, nil
	}
	if _, refreshErr := s.Refresh(ctx, profile, opts...); refreshErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, refreshErr
	}
	return s.authenticatedClient(profile, opts...)
}

func (s AuthService) authenticatedClient(profile Profile, opts ...Option) (*Client, error) {
	access, err := s.Store.Get(profile.Name, SecretAccessToken)
	if err != nil {
		return nil, fmt.Errorf("profile %q is not logged in: %w", profile.Name, err)
	}
	allOpts := append([]Option{WithBearerToken(access)}, opts...)
	return NewClient(profile.ServerURL, allOpts...)
}

func (s AuthService) unlockedPrivateKey(profileName string) (*crypto.Key, error) {
	armored, err := s.Store.Get(profileName, SecretPrivateKey)
	if err != nil {
		return nil, err
	}
	passphrase := s.PassphraseOverride
	if passphrase == "" {
		passphrase, err = s.Store.Get(profileName, SecretPrivateKeyPass)
		if err != nil && !errors.Is(err, ErrSecretNotFound) {
			return nil, err
		}
	}
	return s.PGP.UnlockPrivateKey(armored, passphrase)
}

func (s AuthService) newChallenge(serverURL string) jwtChallenge {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return jwtChallenge{
		Version:           "1.0.0",
		Domain:            normalizeBaseURL(serverURL),
		VerifyToken:       uuid.NewString(),
		VerifyTokenExpiry: now().Add(10 * time.Minute).Unix(),
	}
}

func refreshTokenFromResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", errors.New("jwt refresh response is missing")
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "refresh_token" {
			if refresh := strings.TrimSpace(cookie.Value); refresh != "" {
				return refresh, nil
			}
		}
	}
	return "", errors.New("jwt refresh response did not include a refresh_token cookie")
}

func parseUUID(value string) (openapi_types.UUID, error) {
	var id openapi_types.UUID
	if err := id.UnmarshalText([]byte(value)); err != nil {
		return id, fmt.Errorf("invalid uuid %q: %w", value, err)
	}
	return id, nil
}
