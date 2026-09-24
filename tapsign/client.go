package tapsign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
)

// maxBody caps how much of an upstream response is read, so a hostile or broken
// peer cannot exhaust memory.
const maxBody = 1 << 20

type client struct {
	base   string
	appID  string
	appKey string
	doer   httpclient.Doer
	audit  audit.Logger
}

func newClient(cfg Config, doer httpclient.Doer, logger audit.Logger) *client {
	return &client{
		base:   strings.TrimRight(cfg.BaseURL, "/"),
		appID:  cfg.AppID,
		appKey: cfg.AppKey,
		doer:   doer,
		audit:  logger,
	}
}

func (c *client) Verify(ctx context.Context, cred Credential) error {
	if err := cred.Valid(); err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodGet, "/users/me", cred.SessionToken)
	if err != nil {
		return err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrInvalidCredential
	default:
		return fmt.Errorf("tapsign: verify: unexpected status %d", resp.StatusCode)
	}
}

func (c *client) Rotate(ctx context.Context, cred Credential) (Credential, error) {
	next, err := c.rotate(ctx, cred)
	return next, c.finish(ctx, "tapsign.rotate", cred, err)
}

func (c *client) Revoke(ctx context.Context, cred Credential) error {
	_, err := c.rotate(ctx, cred)
	if errors.Is(err, ErrInvalidCredential) {
		// The goal -- the old token is invalid -- is already achieved, so a
		// retry after an ambiguous failure converges instead of erroring.
		err = nil
	}
	// The replacement token is deliberately discarded: keeping it would hijack
	// the session and leave the user's own device logged out.
	return c.finish(ctx, "tapsign.revoke", cred, err)
}

// rotate performs the upstream call and returns the replacement token. The
// caller decides whether to keep it (Rotate) or discard it (Revoke).
func (c *client) rotate(ctx context.Context, cred Credential) (Credential, error) {
	if err := cred.Valid(); err != nil {
		return Credential{}, err
	}
	path := "/users/" + url.PathEscape(cred.ObjectID) + "/refreshSessionToken"
	resp, err := c.do(ctx, http.MethodPut, path, cred.SessionToken)
	if err != nil {
		return Credential{}, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			SessionToken string `json:"sessionToken"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
			return Credential{}, fmt.Errorf("tapsign: rotate: decode response: %w", err)
		}
		if out.SessionToken == "" {
			return Credential{}, errors.New("tapsign: rotate: upstream returned an empty sessionToken")
		}
		return Credential{SessionToken: out.SessionToken, ObjectID: cred.ObjectID}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return Credential{}, ErrInvalidCredential
	default:
		return Credential{}, fmt.Errorf("tapsign: rotate: unexpected status %d", resp.StatusCode)
	}
}

func (c *client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("tapsign: build request: %w", err)
	}
	req.Header.Set("X-LC-Id", c.appID)
	req.Header.Set("X-LC-Key", c.appKey)
	return req, nil
}

func (c *client) do(ctx context.Context, method, path, session string) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, nil)
	if err != nil {
		return nil, err
	}
	if session != "" {
		req.Header.Set("X-LC-Session", session)
	}
	return c.doer.Do(req)
}

func (c *client) doJSON(ctx context.Context, method, path string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("tapsign: encode request: %w", err)
	}
	req, err := c.newRequest(ctx, method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doer.Do(req)
}

// Redeem exchanges a TapTap OAuth token for a built-in-account Credential by
// logging in, or registering, the linked account. The response carries both the
// session token and the object id, so Rotate/Revoke become possible later.
func (c *client) Redeem(ctx context.Context, tok TapTapToken) (Credential, error) {
	identity := Credential{ObjectID: tok.OpenID}
	if tok.Kid == "" || tok.MacKey == "" || tok.OpenID == "" {
		return Credential{}, c.finish(ctx, "tapsign.redeem", identity, errors.New("tapsign: incomplete TapTap token"))
	}
	body := map[string]any{
		"authData": map[string]any{
			"taptap": map[string]any{
				"kid":           tok.Kid,
				"access_token":  tok.Kid,
				"token_type":    "mac",
				"mac_key":       tok.MacKey,
				"mac_algorithm": "hmac-sha-1",
				"openid":        tok.OpenID,
				"unionid":       tok.UnionID,
			},
		},
	}
	// redeemResult owns the body: it drains and closes it on the success path,
	// and on the error path resp is nil because doJSON returned no response.
	resp, err := c.doJSON(ctx, http.MethodPost, "/users", body) //nolint:bodyclose // closed inside redeemResult
	cred, rerr := redeemResult(resp, err)
	if rerr != nil {
		return Credential{}, c.finish(ctx, "tapsign.redeem", identity, rerr)
	}
	return cred, c.finish(ctx, "tapsign.redeem", cred, nil)
}

func redeemResult(resp *http.Response, err error) (Credential, error) {
	if err != nil {
		return Credential{}, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Credential{}, fmt.Errorf("tapsign: redeem: unexpected status %d", resp.StatusCode)
	}
	var out struct {
		SessionToken string `json:"sessionToken"`
		ObjectID     string `json:"objectId"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return Credential{}, fmt.Errorf("tapsign: redeem: decode response: %w", err)
	}
	if out.SessionToken == "" || out.ObjectID == "" {
		return Credential{}, errors.New("tapsign: redeem: upstream returned an incomplete account")
	}
	return Credential{SessionToken: out.SessionToken, ObjectID: out.ObjectID}, nil
}

// finish records the outcome and surfaces an audit failure alongside any
// operation error, so an unavailable audit log is never silent.
func (c *client) finish(ctx context.Context, action string, cred Credential, opErr error) error {
	if err := c.audit.Record(ctx, audit.Event{
		Action:   action,
		Subject:  cred.ObjectID,
		Provider: "taptap",
		Outcome:  outcomeOf(opErr),
	}); err != nil {
		aerr := fmt.Errorf("tapsign: audit: %w", err)
		if opErr != nil {
			return errors.Join(opErr, aerr)
		}
		return aerr
	}
	return opErr
}

func outcomeOf(err error) string {
	switch {
	case err == nil:
		return audit.OutcomeOK
	case errors.Is(err, ErrInvalidCredential):
		return audit.OutcomeDenied
	default:
		return audit.OutcomeError
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
}
