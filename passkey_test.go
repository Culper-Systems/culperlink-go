package culperlink

// Passkey sign-in on the SDK surface (CULPER-469, decision 41; patent claims
// 2 and 5, the technical specification's §2.5 "Login (Every Connection)").
// The library carries the ceremony and does not run it: BeginPasskeyLogin
// returns the WebAuthn options as the server sent them, the application's
// platform authenticator signs them, and FinishPasskeyLogin installs the
// SAME token pair the API-key exchange installs. The wire shapes are pinned
// bytes; the core repository's conformance suite drives the same methods
// against the real server.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	pkBeginLogin  = "/sdk/v1/auth/passkey/begin-login"
	pkFinishLogin = "/sdk/v1/auth/passkey/finish-login"
	pkBeginReg    = "/sdk/v1/auth/passkey/begin-registration"
	pkFinishReg   = "/sdk/v1/auth/passkey/finish-registration"
	// pkRemove names a credential by the unpadded base64url id
	// finish-registration returned (CULPER-472).
	pkRemove     = "/sdk/v1/auth/passkey/credentials/Y3JlZC0y"
	pkCeremonyID = "1n5mAq3vCq8k2b7rX0dM9w"
	pkPublicKey  = `{"challenge":"q2Xf0vJ5yQ0qkz1o3Jt0sQ","timeout":120000,"rpId":"culperlink.internal.example","userVerification":"required"}`
)

var pkAssertion = &PasskeyAssertion{
	ID:                "Y3JlZC0x",
	RawID:             "Y3JlZC0x",
	Type:              "public-key",
	ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
	AuthenticatorData: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
	Signature:         "MEUCIQDsig",
	UserHandle:        "dXNlci0x",
}

// The finish-login body, byte for byte as the server reads it.
const pkFinishLoginBody = `{"ceremony_id":"1n5mAq3vCq8k2b7rX0dM9w","id":"Y3JlZC0x","rawId":"Y3JlZC0x","type":"public-key",` +
	`"response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ","signature":"MEUCIQDsig","userHandle":"dXNlci0x"}}`

// pkServer answers the four passkey routes on a fakeCP and records what
// reached them.
type pkServer struct {
	mu      sync.Mutex
	bodies  map[string][]string
	headers map[string][]http.Header
	// finish, when set, answers finish-login instead of issuing a pair.
	finish func(w http.ResponseWriter)
	// remove answers DELETE on a credential; nil answers 204.
	remove  func(w http.ResponseWriter)
	methods map[string][]string
	rawPath map[string][]string
}

func installPasskeys(cp *fakeCP) *pkServer {
	s := &pkServer{bodies: map[string][]string{}, headers: map[string][]http.Header{}, methods: map[string][]string{}, rawPath: map[string][]string{}}
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.URL.Path == pkBeginLogin, r.URL.Path == pkFinishLogin, r.URL.Path == pkBeginReg, r.URL.Path == pkFinishReg:
		case strings.HasPrefix(r.URL.Path, pkCredentialsPrefix):
			b, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], string(b))
			s.headers[r.URL.Path] = append(s.headers[r.URL.Path], r.Header.Clone())
			s.methods[r.URL.Path] = append(s.methods[r.URL.Path], r.Method)
			s.rawPath[r.URL.Path] = append(s.rawPath[r.URL.Path], r.URL.EscapedPath())
			remove := s.remove
			s.mu.Unlock()
			if !cp.bearer(r) {
				apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session")
				return true
			}
			if remove != nil {
				remove(w)
				return true
			}
			w.WriteHeader(http.StatusNoContent)
			return true
		default:
			return false
		}
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], string(b))
		s.headers[r.URL.Path] = append(s.headers[r.URL.Path], r.Header.Clone())
		finish := s.finish
		s.mu.Unlock()
		switch r.URL.Path {
		case pkBeginLogin:
			writeJSON(w, http.StatusOK, map[string]any{"public_key": json.RawMessage(pkPublicKey), "ceremony_id": pkCeremonyID})
		case pkFinishLogin:
			if finish != nil {
				finish(w)
				return true
			}
			cp.issue(w)
		case pkBeginReg:
			if !cp.bearer(r) {
				apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session")
				return true
			}
			writeJSON(w, http.StatusOK, map[string]any{"public_key": json.RawMessage(`{"challenge":"cmVnLWNoYWxsZW5nZQ"}`), "ceremony_id": "reg-ceremony-1"})
		case pkFinishReg:
			if !cp.bearer(r) {
				apiErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session")
				return true
			}
			writeJSON(w, http.StatusCreated, map[string]string{"credential_id": "Y3JlZC0y"})
		}
		return true
	})
	return s
}

const pkCredentialsPrefix = "/sdk/v1/auth/passkey/credentials/"

func (s *pkServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies[path])
}

func (s *pkServer) last(path string) (string, http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.bodies[path])
	if n == 0 {
		return "", nil
	}
	return s.bodies[path][n-1], s.headers[path][n-1]
}

func passkeyClient(t *testing.T, cp *fakeCP, apiKey string) *Client {
	t.Helper()
	return offClient(t, cp, func(o *Options) { o.APIKey = apiKey })
}

func signIn(t *testing.T, c *Client) *Session {
	t.Helper()
	ctx := context.Background()
	ch, err := c.BeginPasskeyLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The application's platform call goes here.
	s, err := c.FinishPasskeyLogin(ctx, ch.CeremonyID, pkAssertion)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAClientMayBeBuiltWithoutAnAPIKey(t *testing.T) {
	c, err := NewClient(Options{Endpoint: "https://x", Tunnel: TunnelOptions{Mode: TunnelOff}})
	if err != nil {
		t.Fatalf("NewClient without an API key: %v", err)
	}
	_, err = c.Verify(context.Background(), "h")
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("a call before any sign-in: %v, want ErrMissingAPIKey", err)
	}
	for _, want := range []string{"Options.APIKey", "BeginPasskeyLogin", "FinishPasskeyLogin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not name %s", err, want)
		}
	}
}

func TestBeginPasskeyLoginReturnsTheOptionsUntouched(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	ch, err := c.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(ch.PublicKey) != pkPublicKey || ch.CeremonyID != pkCeremonyID {
		t.Fatalf("challenge = %s / %q", ch.PublicKey, ch.CeremonyID)
	}
	body, h := s.last(pkBeginLogin)
	if body != "" || h.Get("Authorization") != "" || h.Get(dataTokenHeader) != "" {
		t.Fatalf("begin-login carried body %q, Authorization %q, data token %q", body, h.Get("Authorization"), h.Get(dataTokenHeader))
	}
}

func TestFinishPasskeyLoginInstallsThePairTheAPIKeyWould(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	sess := signIn(t, c)
	body, h := s.last(pkFinishLogin)
	if body != pkFinishLoginBody {
		t.Fatalf("finish-login body\n got %s\nwant %s", body, pkFinishLoginBody)
	}
	if h.Get("Authorization") != "" {
		t.Fatal("finish-login carried Authorization")
	}
	if sess == nil || sess.ID != "sess-1" || c.CurrentSession() == nil {
		t.Fatalf("session = %+v", sess)
	}
	ctx := context.Background()
	if ok, err := c.Verify(ctx, "proof-abc"); err != nil || !ok {
		t.Fatalf("Verify on the passkey session: %v %v", ok, err)
	}
	if _, err := c.Encrypt(ctx, []byte("p"), "ch"); err != nil {
		t.Fatalf("Encrypt on the passkey session: %v", err)
	}
	if n := cp.hit("/sdk/v1/auth/api-key"); n != 0 {
		t.Fatalf("the API-key route was hit %d times", n)
	}
	if v := cp.v.get(); len(v) > 0 {
		t.Fatal(v)
	}
}

func TestAnAbsentUserHandleIsSentEmpty(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	a := *pkAssertion
	a.UserHandle = ""
	if _, err := c.FinishPasskeyLogin(context.Background(), pkCeremonyID, &a); err != nil {
		t.Fatal(err)
	}
	body, _ := s.last(pkFinishLogin)
	if !strings.Contains(body, `"userHandle":""`) {
		t.Fatalf("body %s", body)
	}
}

func TestPasskeyRefusalsAreTyped(t *testing.T) {
	tests := []struct {
		name   string
		status int
		env    string
		want   error
		reason string
	}{
		{"replay", http.StatusUnauthorized, `{"code":"INVALID_PASSKEY","message":"passkey refused","reason":"sign_count_replay"}`, ErrPasskeyDeclined, "sign_count_replay"},
		{"expired ceremony", http.StatusUnauthorized, `{"code":"INVALID_PASSKEY","message":"passkey refused","reason":"challenge_expired"}`, ErrPasskeyDeclined, "challenge_expired"},
		{"no organization", http.StatusUnauthorized, `{"code":"INVALID_PASSKEY","message":"passkey refused","reason":"no_organization"}`, ErrPasskeyDeclined, "no_organization"},
		{"retired", http.StatusUnauthorized, `{"code":"INVALID_PASSKEY","message":"passkey refused","reason":"credential_retired"}`, ErrPasskeyDeclined, "credential_retired"},
		{"bare", http.StatusUnauthorized, `{"code":"INVALID_PASSKEY","message":"passkey refused"}`, ErrPasskeyDeclined, ""},
		{"license", http.StatusForbidden, `{"code":"LICENSE_EXPIRED","message":"renew the license"}`, ErrLicenseExpired, ""},
		{"rate limited", http.StatusTooManyRequests, `{"code":"RATE_LIMITED","message":"slow down","retry_after":60}`, ErrRateLimited, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := newFakeCP(t)
			s := installPasskeys(cp)
			s.finish = func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, `{"error":`+tt.env+`}`)
			}
			c := passkeyClient(t, cp, "")
			_, err := c.FinishPasskeyLogin(context.Background(), pkCeremonyID, pkAssertion)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			var api *APIError
			if !errors.As(err, &api) || api.StatusCode != tt.status || api.Reason != tt.reason {
				t.Fatalf("APIError = %+v, want status %d reason %q", api, tt.status, tt.reason)
			}
			if c.CurrentSession() != nil {
				t.Fatal("a refused finish installed a session")
			}
			if n := cp.hit(pkFinishLogin); n != 1 {
				t.Fatalf("finish-login sent %d times; a sent POST is never sent again", n)
			}
		})
	}
}

func TestFinishPasskeyLoginRefusesAnEmptyCeremonyBeforeSending(t *testing.T) {
	cp := newFakeCP(t)
	installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	if _, err := c.FinishPasskeyLogin(context.Background(), "", pkAssertion); err == nil || !strings.Contains(err.Error(), "ceremony") {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.FinishPasskeyLogin(context.Background(), pkCeremonyID, nil); err == nil {
		t.Fatal("a nil assertion was accepted")
	}
	if n := cp.hit(pkFinishLogin); n != 0 {
		t.Fatalf("sent %d", n)
	}
}

func TestAPasskeySessionRenewsAndNeverFallsBackToTheAPIKey(t *testing.T) {
	for _, key := range []string{"", testAPIKey} {
		t.Run("apikey="+key, func(t *testing.T) {
			cp := newFakeCP(t)
			cp.ttl = time.Minute // inside the refresh window
			installPasskeys(cp)
			c := passkeyClient(t, cp, key)
			signIn(t, c)
			ctx := context.Background()
			if _, err := c.Verify(ctx, "proof-abc"); err != nil {
				t.Fatalf("renewed call: %v", err)
			}
			if n := cp.hit("/sdk/v1/auth/renew"); n != 1 {
				t.Fatalf("renewals = %d, want 1", n)
			}
			// The installation revokes the session: renewal is refused.
			cp.mu.Lock()
			cp.sessions = map[string]bool{}
			cp.mu.Unlock()
			for i := 0; i < 2; i++ {
				_, err := c.Verify(ctx, "proof-abc")
				if !errors.Is(err, ErrInvalidSession) || !strings.Contains(err.Error(), "passkey") {
					t.Fatalf("call %d after a refused renewal: %v, want ErrInvalidSession naming the passkey", i, err)
				}
			}
			if n := cp.hit("/sdk/v1/auth/api-key"); n != 0 {
				t.Fatalf("the API key was presented %d times for a person's session", n)
			}
			if n := cp.hit("/sdk/v1/auth/renew"); n != 2 {
				t.Fatalf("renewals = %d, want 2 (no loop)", n)
			}
		})
	}
}

func TestPasskeyRegistrationRidesTheSessionToken(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	signIn(t, c)
	ctx := context.Background()
	ch, err := c.BeginPasskeyRegistration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(ch.PublicKey) != `{"challenge":"cmVnLWNoYWxsZW5nZQ"}` || ch.CeremonyID != "reg-ceremony-1" {
		t.Fatalf("challenge = %s / %q", ch.PublicKey, ch.CeremonyID)
	}
	if body, h := s.last(pkBeginReg); strings.Contains(body, "user_id") || h.Get("Authorization") != "Bearer st-1" {
		t.Fatalf("begin-registration body %q, Authorization %q", body, h.Get("Authorization"))
	}
	id, err := c.FinishPasskeyRegistration(ctx, ch.CeremonyID, &PasskeyAttestation{
		ID: "Y3JlZC0y", RawID: "Y3JlZC0y", Type: "public-key",
		ClientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0", AttestationObject: "o2NmbXRkbm9uZQ",
	})
	if err != nil || id != "Y3JlZC0y" {
		t.Fatalf("FinishPasskeyRegistration = %q, %v", id, err)
	}
	const want = `{"ceremony_id":"reg-ceremony-1","id":"Y3JlZC0y","rawId":"Y3JlZC0y","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZQ"}}`
	if body, _ := s.last(pkFinishReg); body != want {
		t.Fatalf("finish-registration body\n got %s\nwant %s", body, want)
	}
}

func TestPasskeyRegistrationUnderAnAPIKeySessionIsTheServers403(t *testing.T) {
	cp := newFakeCP(t)
	cp.setOverride(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != pkBeginReg {
			return false
		}
		apiErr(w, http.StatusForbidden, "FORBIDDEN", "registration needs a passkey-issued session")
		return true
	})
	c := offClient(t, cp)
	_, err := c.BeginPasskeyRegistration(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusForbidden || api.Code != "FORBIDDEN" {
		t.Fatalf("err = %v", err)
	}
}

func TestRemovePasskeySendsDeleteOnTheSessionToken(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	signIn(t, c)
	if err := c.RemovePasskey(context.Background(), "Y3JlZC0y"); err != nil {
		t.Fatalf("RemovePasskey: %v", err)
	}
	s.mu.Lock()
	methods := s.methods[pkRemove]
	s.mu.Unlock()
	if len(methods) != 1 || methods[0] != http.MethodDelete {
		t.Fatalf("methods = %v, want one DELETE", methods)
	}
	body, h := s.last(pkRemove)
	if body != "" || h.Get("Authorization") != "Bearer st-1" {
		t.Fatalf("body %q, Authorization %q", body, h.Get("Authorization"))
	}
	// The current session carries on: removal ends nothing on this side.
	if c.CurrentSession() == nil {
		t.Fatal("the session was dropped")
	}
}

func TestRemovePasskeySendsTheIDUnchanged(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	signIn(t, c)
	if err := c.RemovePasskey(context.Background(), "ab-_Cd0"); err != nil {
		t.Fatal(err)
	}
	const path = pkCredentialsPrefix + "ab-_Cd0"
	s.mu.Lock()
	raw := s.rawPath[path]
	s.mu.Unlock()
	if len(raw) != 1 || raw[0] != path {
		t.Fatalf("raw paths = %v, want [%s]", raw, path)
	}
}

func TestRemovePasskeyRefusalsAreTyped(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		code, msg  string
		notFound   bool
		wantStatus int
	}{
		{"unknown or someone else's", http.StatusNotFound, "NOT_FOUND", "passkey not found", true, 404},
		{"api-key session", http.StatusForbidden, "FORBIDDEN", "passkey removal needs a passkey-issued session", false, 403},
		{"malformed id", http.StatusUnprocessableEntity, "VALIDATION_ERROR", "bad id", false, 422},
		{"passkeys off", http.StatusServiceUnavailable, "PASSKEYS_NOT_CONFIGURED", "passkeys are not configured", false, 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := newFakeCP(t)
			s := installPasskeys(cp)
			s.remove = func(w http.ResponseWriter) { apiErr(w, tc.status, tc.code, tc.msg) }
			c := passkeyClient(t, cp, "")
			signIn(t, c)
			err := c.RemovePasskey(context.Background(), "Y3JlZC0y")
			if got := errors.Is(err, ErrPasskeyNotFound); got != tc.notFound {
				t.Fatalf("errors.Is(%v, ErrPasskeyNotFound) = %v, want %v", err, got, tc.notFound)
			}
			var api *APIError
			if !errors.As(err, &api) || api.StatusCode != tc.wantStatus || api.Code != tc.code {
				t.Fatalf("err = %v, want an *APIError %d %s", err, tc.wantStatus, tc.code)
			}
			if s.count(pkRemove) != 1 {
				t.Fatalf("sent %d times, want 1", s.count(pkRemove))
			}
		})
	}
}

// A NOT_FOUND from any other route is not ErrPasskeyNotFound: the sentinel
// is the removal's answer, not the code's.
func TestErrPasskeyNotFoundIsNotEveryNotFound(t *testing.T) {
	err := error(&APIError{StatusCode: http.StatusNotFound, Code: "NOT_FOUND", Message: "x"})
	if errors.Is(err, ErrPasskeyNotFound) {
		t.Fatal("a bare NOT_FOUND matched ErrPasskeyNotFound")
	}
}

func TestRemovePasskeyIsNotSentAgainAfterA5xx(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	s.remove = func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }
	c := passkeyClient(t, cp, "")
	signIn(t, c)
	if err := c.RemovePasskey(context.Background(), "Y3JlZC0y"); err == nil {
		t.Fatal("RemovePasskey succeeded on a 502")
	}
	if n := s.count(pkRemove); n != 1 {
		t.Fatalf("sent %d times, want 1", n)
	}
}

func TestRemovePasskeyRefusesAnEmptyIDBeforeSending(t *testing.T) {
	cp := newFakeCP(t)
	s := installPasskeys(cp)
	c := passkeyClient(t, cp, "")
	err := c.RemovePasskey(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "credential id required") {
		t.Fatalf("err = %v", err)
	}
	s.mu.Lock()
	n := len(s.bodies)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d routes reached", n)
	}
}

func TestTheOldPasskeySurfaceIsGone(t *testing.T) {
	ct := reflect.TypeOf(&Client{})
	for _, name := range []string{"BeginPasskeyAuth", "FinishPasskeyAuth"} {
		if _, ok := ct.MethodByName(name); ok {
			t.Errorf("Client still has %s", name)
		}
	}
	want := []string{"ID", "RawID", "Type", "ClientDataJSON", "AuthenticatorData", "Signature", "UserHandle"}
	pt := reflect.TypeOf(PasskeyAssertion{})
	var got []string
	for i := 0; i < pt.NumField(); i++ {
		got = append(got, pt.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PasskeyAssertion fields = %v, want %v", got, want)
	}
}
