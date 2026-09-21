package taptapoauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.Handler) *client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return newClient(Config{
		DeviceCodeEndpoint: srv.URL + "/device/code",
		TokenEndpoint:      srv.URL + "/token",
		UserInfoEndpoint:   srv.URL + "/userinfo",
		ClientID:           "test-client",
	}, srv.Client())
}

func TestStartDeviceCode(t *testing.T) {
	var gotForm url.Values
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/device/code" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		_ = r.ParseForm()
		gotForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"device_code":      "dc-1",
				"verification_url": "https://www.taptap.com/account/device",
				"user_code":        "UC1",
				"interval":         3,
				"expires_in":       300,
			},
		})
	}))

	auth, err := c.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotForm.Get("client_id") != "test-client" || gotForm.Get("response_type") != "device_code" {
		t.Errorf("form = %v", gotForm)
	}
	if !strings.Contains(gotForm.Get("info"), "device_id") {
		t.Errorf("info = %q", gotForm.Get("info"))
	}
	if auth.DeviceCode != "dc-1" || auth.UserCode != "UC1" || auth.Interval != 3*time.Second {
		t.Fatalf("auth = %+v", auth)
	}
	if auth.DeviceID == "" {
		t.Fatal("device id not generated")
	}
	if !strings.Contains(auth.VerificationURL, "user_code=UC1") || !strings.Contains(auth.VerificationURL, "qrcode=1") {
		t.Fatalf("scan url = %s", auth.VerificationURL)
	}
	if auth.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt not set")
	}
}

func TestStartBusinessError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"data":    map[string]string{"error": "invalid_client", "error_description": "bad client"},
		})
	}))
	if _, err := c.Start(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestPollAuthorizationPending(t *testing.T) {
	for _, code := range []string{
		"authorization_pending",
		"oauth2.tapapis.com.AUTHORIZATION_WAITING",
		"slow_down",
	} {
		c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/token" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"data": map[string]string{
					"error":             code,
					"error_description": "the end-user authorization is waiting",
				},
			})
		}))
		_, err := c.Poll(context.Background(), DeviceAuth{DeviceCode: "dc", DeviceID: "dev"})
		if !errors.Is(err, ErrAuthorizationPending) {
			t.Fatalf("code %q: err = %v, want ErrAuthorizationPending", code, err)
		}
	}
}

func TestPollSuccess(t *testing.T) {
	const macKey = "test-mac-key"
	var gotAuthz, gotRawQuery, gotMethod string

	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "device_token" || r.PostForm.Get("code") != "dc" {
				t.Errorf("token form = %v", r.PostForm)
			}
			if r.PostForm.Get("client_id") != "test-client" {
				t.Errorf("client_id = %q", r.PostForm.Get("client_id"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data":    map[string]string{"kid": "kid-1", "mac_key": macKey},
			})
		case "/userinfo":
			gotAuthz = r.Header.Get("Authorization")
			gotRawQuery = r.URL.RawQuery
			gotMethod = r.Method
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data":    map[string]string{"openid": "openid-1", "unionid": "union-1"},
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	tok, err := c.Poll(context.Background(), DeviceAuth{DeviceCode: "dc", DeviceID: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kid != "kid-1" || tok.MacKey != macKey || tok.OpenID != "openid-1" || tok.UnionID != "union-1" {
		t.Fatalf("token = %+v", tok)
	}
	if !strings.HasPrefix(gotAuthz, `MAC id="kid-1",ts="`) {
		t.Fatalf("authorization = %q", gotAuthz)
	}
	if gotRawQuery != "client_id=test-client" || gotMethod != http.MethodGet {
		t.Fatalf("query = %q method = %q", gotRawQuery, gotMethod)
	}
}

func TestPollHTTPError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]string{"kid": "k", "mac_key": "m"}})
	}))
	if _, err := c.Poll(context.Background(), DeviceAuth{DeviceCode: "dc", DeviceID: "dev"}); err == nil {
		t.Fatal("expected an error")
	}
}

// The MAC signature must cover exactly the documented string. This test
// recomputes the digest independently of the implementation.
func TestMACAuthorizationSignsDocumentedString(t *testing.T) {
	u, err := url.Parse("https://example.com/account/basic-info/v1?client_id=abc")
	if err != nil {
		t.Fatal(err)
	}
	got, err := macAuthorization("kid", "secret", "1000", "42", http.MethodGet, u)
	if err != nil {
		t.Fatal(err)
	}

	input := "1000\n42\nGET\n/account/basic-info/v1?client_id=abc\nexample.com\n443\n\n"
	m := hmac.New(sha1.New, []byte("secret"))
	m.Write([]byte(input))
	want := `MAC id="kid",ts="1000",nonce="42",mac="` + base64.StdEncoding.EncodeToString(m.Sum(nil)) + `"`
	if got != want {
		t.Fatalf("mac header =\n%q\nwant\n%q", got, want)
	}
}

func TestMACAuthorizationUsesPort(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8080/path")
	got, err := macAuthorization("kid", "secret", "1", "2", http.MethodGet, u)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha1.New, []byte("secret"))
	m.Write([]byte("1\n2\nGET\n/path\n127.0.0.1\n8080\n\n"))
	want := `MAC id="kid",ts="1",nonce="2",mac="` + base64.StdEncoding.EncodeToString(m.Sum(nil)) + `"`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
