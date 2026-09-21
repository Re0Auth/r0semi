package tapsign

import (
	"errors"
	"strings"
)

// Config locates the TapTap built-in-account (LeanCloud / TDS) service.
//
// BaseURL already includes the API version:
//
//	mainland: https://rak3ffdi.cloud.tds1.tapapis.cn/1.1
//	global:   https://kviehlel.cloud.ap-sg.tapapis.com/1.1
//
// AppID and AppKey are the game's X-LC-Id and X-LC-Key. They are embedded in the
// public game client and are not treated as cryptographic secrets; they are kept
// out of source anyway so a deployment can point at a different profile.
type Config struct {
	BaseURL string
	AppID   string
	AppKey  string
}

func (c Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("tapsign: BaseURL is required")
	}
	if strings.TrimSpace(c.AppID) == "" {
		return errors.New("tapsign: AppID is required")
	}
	if strings.TrimSpace(c.AppKey) == "" {
		return errors.New("tapsign: AppKey is required")
	}
	return nil
}
