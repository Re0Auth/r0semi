package taptapoauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/tapsign"
)

const (
	maxBody = 1 << 20
	// tapUserAgent matches the official TapTap Android SDK, which is what the
	// public device flow expects.
	tapUserAgent = "TapTapAndroidSDK/3.16.5"
)

type client struct {
	deviceCodeEndpoint string
	tokenEndpoint      string
	userInfoEndpoint   string
	clientID           string
	doer               httpclient.Doer
	now                func() time.Time
}

func newClient(cfg Config, doer httpclient.Doer) *client {
	return &client{
		deviceCodeEndpoint: cfg.DeviceCodeEndpoint,
		tokenEndpoint:      cfg.TokenEndpoint,
		userInfoEndpoint:   cfg.UserInfoEndpoint,
		clientID:           cfg.ClientID,
		doer:               doer,
		now:                time.Now,
	}
}

func (c *client) Start(ctx context.Context) (DeviceAuth, error) {
	deviceID, err := randomID()
	if err != nil {
		return DeviceAuth{}, err
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("response_type", "device_code")
	form.Set("scope", "basic_info")
	form.Set("version", "1.2.0")
	form.Set("platform", "unity")
	form.Set("info", fmt.Sprintf(`{"device_id":%q}`, deviceID))

	body, status, err := c.postForm(ctx, c.deviceCodeEndpoint, form)
	if err != nil {
		return DeviceAuth{}, err
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		return DeviceAuth{}, err
	}
	if !env.Success {
		return DeviceAuth{}, businessError("device code", env.Data)
	}
	if status < 200 || status >= 300 {
		return DeviceAuth{}, fmt.Errorf("taptapoauth: device code: HTTP %d", status)
	}

	var data struct {
		DeviceCode      string `json:"device_code"`
		VerificationURL string `json:"verification_url"`
		UserCode        string `json:"user_code"`
		Interval        int64  `json:"interval"`
		ExpiresIn       int64  `json:"expires_in"`
		QRCodeURL       string `json:"qrcode_url"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return DeviceAuth{}, fmt.Errorf("taptapoauth: decode device code: %w", err)
	}
	if data.DeviceCode == "" || data.VerificationURL == "" {
		return DeviceAuth{}, errors.New("taptapoauth: upstream omitted device_code or verification_url")
	}

	interval := time.Duration(data.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := time.Duration(data.ExpiresIn) * time.Second
	if expires <= 0 {
		expires = 5 * time.Minute
	}

	return DeviceAuth{
		DeviceID:        deviceID,
		DeviceCode:      data.DeviceCode,
		UserCode:        data.UserCode,
		VerificationURL: scanURL(data.VerificationURL, data.QRCodeURL, data.UserCode),
		QRCodeURL:       data.QRCodeURL,
		Interval:        interval,
		ExpiresAt:       c.now().Add(expires),
	}, nil
}

func (c *client) Poll(ctx context.Context, auth DeviceAuth) (tapsign.TapTapToken, error) {
	if auth.DeviceCode == "" || auth.DeviceID == "" {
		return tapsign.TapTapToken{}, errors.New("taptapoauth: device code and device id are required")
	}

	form := url.Values{}
	form.Set("grant_type", "device_token")
	form.Set("client_id", c.clientID)
	form.Set("secret_type", "hmac-sha-1")
	form.Set("code", auth.DeviceCode)
	form.Set("version", "1.0")
	form.Set("platform", "unity")
	form.Set("info", fmt.Sprintf(`{"device_id":%q}`, auth.DeviceID))

	body, status, err := c.postForm(ctx, c.tokenEndpoint, form)
	if err != nil {
		return tapsign.TapTapToken{}, err
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		return tapsign.TapTapToken{}, err
	}
	if !env.Success {
		return tapsign.TapTapToken{}, tokenBusinessError(env.Data)
	}
	if status < 200 || status >= 300 {
		return tapsign.TapTapToken{}, fmt.Errorf("taptapoauth: token: HTTP %d", status)
	}

	var tok struct {
		Kid    string `json:"kid"`
		MacKey string `json:"mac_key"`
	}
	if err := json.Unmarshal(env.Data, &tok); err != nil {
		return tapsign.TapTapToken{}, fmt.Errorf("taptapoauth: decode token: %w", err)
	}
	if tok.Kid == "" || tok.MacKey == "" {
		return tapsign.TapTapToken{}, errors.New("taptapoauth: upstream omitted kid or mac_key")
	}

	acct, err := c.fetchAccount(ctx, tok.Kid, tok.MacKey)
	if err != nil {
		return tapsign.TapTapToken{}, err
	}
	return tapsign.TapTapToken{
		Kid:     tok.Kid,
		MacKey:  tok.MacKey,
		OpenID:  acct.OpenID,
		UnionID: acct.UnionID,
	}, nil
}

type account struct {
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
}

func (c *client) fetchAccount(ctx context.Context, kid, macKey string) (account, error) {
	u, err := url.Parse(c.userInfoEndpoint)
	if err != nil {
		return account{}, fmt.Errorf("taptapoauth: invalid user-info endpoint: %w", err)
	}
	q := u.Query()
	q.Set("client_id", c.clientID)
	u.RawQuery = q.Encode()

	nonce, err := randomNonce()
	if err != nil {
		return account{}, err
	}
	authz, err := macAuthorization(kid, macKey, strconv.FormatInt(c.now().Unix(), 10), nonce, http.MethodGet, u)
	if err != nil {
		return account{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return account{}, fmt.Errorf("taptapoauth: build request: %w", err)
	}
	req.Header.Set("Authorization", authz)
	req.Header.Set("User-Agent", tapUserAgent)

	resp, err := c.doer.Do(req)
	if err != nil {
		return account{}, fmt.Errorf("taptapoauth: user info request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return account{}, fmt.Errorf("taptapoauth: read user info: %w", err)
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		return account{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return account{}, fmt.Errorf("taptapoauth: user info: HTTP %d", resp.StatusCode)
	}
	if !env.Success {
		return account{}, businessError("user info", env.Data)
	}
	var acct account
	if err := json.Unmarshal(env.Data, &acct); err != nil {
		return account{}, fmt.Errorf("taptapoauth: decode account: %w", err)
	}
	if acct.OpenID == "" {
		return account{}, errors.New("taptapoauth: upstream omitted openid")
	}
	return acct, nil
}

func (c *client) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("taptapoauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", tapUserAgent)

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("taptapoauth: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, 0, fmt.Errorf("taptapoauth: read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// macAuthorization builds the MAC header the account-info endpoint requires:
//
//	MAC id="{kid}",ts="{ts}",nonce="{nonce}",mac="{base64(hmac-sha1(...))}"
//
// The signed string is "{ts}\n{nonce}\n{method}\n{path?query}\n{host}\n{port}\n\n".
func macAuthorization(kid, macKey, ts, nonce, method string, u *url.URL) (string, error) {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	pathAndQuery := u.EscapedPath()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	if u.RawQuery != "" {
		pathAndQuery += "?" + u.RawQuery
	}

	input := strings.Join([]string{ts, nonce, method, pathAndQuery, u.Hostname(), port, "", ""}, "\n")
	mac := hmac.New(sha1.New, []byte(macKey))
	if _, err := mac.Write([]byte(input)); err != nil {
		return "", fmt.Errorf("taptapoauth: mac: %w", err)
	}
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf(`MAC id="%s",ts="%s",nonce="%s",mac="%s"`, kid, ts, nonce, sig), nil
}

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

func decodeEnvelope(body []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return envelope{}, fmt.Errorf("taptapoauth: decode response: %w", err)
	}
	return env, nil
}

type tapError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Msg              string `json:"msg"`
}

func parseTapError(data json.RawMessage) (code, message string) {
	var e tapError
	if err := json.Unmarshal(data, &e); err == nil && (e.Error != "" || e.ErrorDescription != "" || e.Msg != "") {
		message = e.ErrorDescription
		if message == "" {
			message = e.Msg
		}
		return e.Error, message
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return "", s
	}
	return "", strings.TrimSpace(string(data))
}

func businessError(stage string, data json.RawMessage) error {
	code, message := parseTapError(data)
	return fmt.Errorf("taptapoauth: %s failed: %s %s", stage, code, message)
}

func tokenBusinessError(data json.RawMessage) error {
	code, message := parseTapError(data)
	classifier := strings.ToLower(code + " " + message)
	if strings.Contains(classifier, "authorization_pending") ||
		strings.Contains(classifier, "authorization_waiting") ||
		strings.Contains(classifier, "slow_down") {
		return ErrAuthorizationPending
	}
	return fmt.Errorf("taptapoauth: token failed: %s %s", code, message)
}

func scanURL(verificationURL, qrcodeURL, userCode string) string {
	if qrcodeURL != "" {
		return qrcodeURL
	}
	if userCode == "" {
		return verificationURL
	}
	sep := "?"
	if strings.Contains(verificationURL, "?") {
		sep = "&"
	}
	return verificationURL + sep + "qrcode=1&user_code=" + url.QueryEscape(userCode)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("taptapoauth: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func randomNonce() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("taptapoauth: random: %w", err)
	}
	return strconv.FormatUint(uint64(binary.BigEndian.Uint32(b)), 10), nil
}
