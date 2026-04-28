package workos_test

import (
	"os"
	"strings"
	"testing"

	"github.com/accretional/proto-resource/auth/workos"
)

// creds returns (apiKey, clientID) and skips t if either is absent.
func creds(t *testing.T) (string, string) {
	t.Helper()
	apiKey := os.Getenv("WORKOS_API_KEY")
	clientID := os.Getenv("WORKOS_CLIENT_ID")
	if apiKey == "" || clientID == "" {
		t.Skip("WORKOS_API_KEY and WORKOS_CLIENT_ID required")
	}
	return apiKey, clientID
}

func newClient(t *testing.T) *workos.Client {
	t.Helper()
	apiKey, clientID := creds(t)
	c, err := workos.NewClient(apiKey, clientID)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// --- Client construction ---

func TestNewClient_FetchesJWKS(t *testing.T) {
	newClient(t) // just verifying it doesn't error
}

func TestNewClient_BadClientID_Fails(t *testing.T) {
	apiKey, _ := creds(t)
	_, err := workos.NewClient(apiKey, "bad-client-id-that-does-not-exist")
	if err == nil {
		t.Fatal("expected error for invalid client ID, got nil")
	}
}

func TestNewPublicClient_FetchesJWKS(t *testing.T) {
	_, clientID := creds(t)
	_, err := workos.NewPublicClient(clientID)
	if err != nil {
		t.Fatalf("NewPublicClient: %v", err)
	}
}

// --- GetUser ---

func TestGetUser(t *testing.T) {
	userID := os.Getenv("WORKOS_TEST_USER_ID")
	if userID == "" {
		t.Skip("WORKOS_TEST_USER_ID required")
	}
	c := newClient(t)
	user, err := c.GetUser(userID)
	if err != nil {
		t.Fatalf("GetUser(%s): %v", userID, err)
	}
	if user.ID != userID {
		t.Errorf("User.ID = %q, want %q", user.ID, userID)
	}
	if user.Email == "" {
		t.Error("User.Email is empty")
	}
	t.Logf("user: id=%s email=%s", user.ID, user.Email)
}

// --- SendMagicAuth ---

// TestSendMagicAuth requires WORKOS_TEST_EXISTING_EMAIL — an email address for
// a user who is already registered in WorkOS. Magic auth returns 500 for emails
// that only have a pending invitation (use TestListInvitations / invite flow for those).
func TestSendMagicAuth(t *testing.T) {
	email := os.Getenv("WORKOS_TEST_EXISTING_EMAIL")
	if email == "" {
		t.Skip("WORKOS_TEST_EXISTING_EMAIL required (must be a registered user)")
	}
	if os.Getenv("WORKOS_TEST_EXISTING_CODE") != "" {
		t.Skip("skipping send — WORKOS_TEST_EXISTING_CODE already set, use TestAuthenticateMagicAuth to verify it")
	}
	c := newClient(t)
	resp, err := c.SendMagicAuth(email)
	if err != nil {
		t.Fatalf("SendMagicAuth(%s): %v", email, err)
	}
	if resp.Email != email {
		t.Errorf("response Email = %q, want %q", resp.Email, email)
	}
	t.Logf("magic auth sent: id=%s email=%s", resp.ID, resp.Email)
}

// --- AuthenticateMagicAuth ---

// TestAuthenticateMagicAuth requires WORKOS_TEST_EMAIL and WORKOS_TEST_CODE.
// Workflow: run TestSendMagicAuth first to trigger the email, then set
// WORKOS_TEST_CODE to the 6-digit code you receive and re-run.
func TestAuthenticateMagicAuth(t *testing.T) {
	email := os.Getenv("WORKOS_TEST_EXISTING_EMAIL")
	code := os.Getenv("WORKOS_TEST_EXISTING_CODE")
	if email == "" || code == "" {
		t.Skip("WORKOS_TEST_EXISTING_EMAIL and WORKOS_TEST_EXISTING_CODE required")
	}
	c := newClient(t)
	resp, err := c.AuthenticateMagicAuth(email, code)
	if err != nil {
		t.Fatalf("AuthenticateMagicAuth: %v", err)
	}
	if resp.User == nil {
		t.Fatal("response has nil User")
	}
	if resp.User.Email != email {
		t.Errorf("User.Email = %q, want %q", resp.User.Email, email)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	preview := resp.AccessToken
	if len(preview) > 16 {
		preview = preview[:16]
	}
	t.Logf("authenticated: user=%s access_token=%s…", resp.User.ID, preview)
}

// --- VerifyAccessToken ---

func TestVerifyAccessToken(t *testing.T) {
	token := os.Getenv("WORKOS_TEST_ACCESS_TOKEN")
	if token == "" {
		t.Skip("WORKOS_TEST_ACCESS_TOKEN required")
	}
	c := newClient(t)
	claims, err := c.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Error("claims missing sub")
	}
	t.Logf("token claims: sub=%s", sub)
}

func TestVerifyAccessToken_Invalid(t *testing.T) {
	c := newClient(t)
	_, err := c.VerifyAccessToken("not.a.jwt")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

// --- RequestDeviceAuthorization ---

func TestRequestDeviceAuthorization(t *testing.T) {
	_, clientID := creds(t)
	c, err := workos.NewPublicClient(clientID)
	if err != nil {
		t.Fatalf("NewPublicClient: %v", err)
	}
	da, err := c.RequestDeviceAuthorization()
	if err != nil {
		t.Fatalf("RequestDeviceAuthorization: %v", err)
	}
	if da.DeviceCode == "" {
		t.Error("DeviceCode is empty")
	}
	if !strings.HasPrefix(da.VerificationURIComplete, "https://") {
		t.Errorf("VerificationURIComplete looks wrong: %q", da.VerificationURIComplete)
	}
	t.Logf("device auth: user_code=%s expires_in=%ds", da.UserCode, da.ExpiresIn)
}

// --- ListInvitations ---

func TestListInvitations(t *testing.T) {
	email := os.Getenv("WORKOS_TEST_EMAIL")
	if email == "" {
		t.Skip("WORKOS_TEST_EMAIL required")
	}
	c := newClient(t)
	invs, err := c.ListInvitations(email)
	if err != nil {
		t.Fatalf("ListInvitations(%s): %v", email, err)
	}
	t.Logf("found %d invitation(s) for %s", len(invs), email)
}

