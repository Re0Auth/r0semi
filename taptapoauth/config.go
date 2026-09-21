package taptapoauth

import (
	"errors"
	"strings"
)

// Config locates the TapTap OAuth2 device-authorization endpoints.
//
// ClientID is the game's public TapTap / LeanCloud application id. The device
// flow identifies the client by it, so there is no separate OAuth client
// secret: obtaining a token still requires the end user to approve on TapTap.
type Config struct {
	DeviceCodeEndpoint string
	TokenEndpoint      string
	UserInfoEndpoint   string
	ClientID           string
}

func (c Config) validate() error {
	switch {
	case strings.TrimSpace(c.DeviceCodeEndpoint) == "":
		return errors.New("taptapoauth: DeviceCodeEndpoint is required")
	case strings.TrimSpace(c.TokenEndpoint) == "":
		return errors.New("taptapoauth: TokenEndpoint is required")
	case strings.TrimSpace(c.UserInfoEndpoint) == "":
		return errors.New("taptapoauth: UserInfoEndpoint is required")
	case strings.TrimSpace(c.ClientID) == "":
		return errors.New("taptapoauth: ClientID is required")
	}
	return nil
}
