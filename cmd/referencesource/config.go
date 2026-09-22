package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/upstreamkit"
)

// The reference source has its own configuration, deliberately separate from
// Re0Auth's: it is a different service with a different job, and the TapTap
// endpoints below are its business, not Re0Auth's.
//
// Same two rules as the server: secrets are named (`*_env`), never written, and
// every field has a default.

type file struct {
	Server serverSection            `toml:"server"`
	Client clientSection            `toml:"client"`
	Source sourceSection            `toml:"source"`
	TapTap *tapTapSection           `toml:"taptap"`
	Social map[string]socialSection `toml:"social"`
}

type serverSection struct {
	Addr string `toml:"addr"`
	// Issuer is this source's public base URL: it becomes the OAuth issuer in
	// the discovery document Re0Auth reads.
	Issuer string `toml:"issuer"`
	// Re0AuthBaseURL is where this source expects Re0Auth to live; the client
	// redirect URI is derived from it.
	Re0AuthBaseURL string `toml:"re0auth_base_url"`
}

type clientSection struct {
	// The one downstream client this source trusts.
	ID        string `toml:"id"`
	SecretEnv string `toml:"secret_env"`
}

type sourceSection struct {
	Game        string `toml:"game"`
	Source      string `toml:"source"`
	DisplayName string `toml:"display_name"`
	TokenClass  string `toml:"token_class"`
	Contact     string `toml:"contact"`
	// Provider namespaces this source's credentials in its own vault. It is the
	// source's account namespace, not a game account.
	Provider  string            `toml:"provider"`
	Resources []resourceSection `toml:"resources"`
}

type resourceSection struct {
	Name   string `toml:"name"`
	Schema string `toml:"schema"`
	Scope  string `toml:"scope"`
}

// tapTapSection configures the device-code (QR) login. The app id and leancloud
// app key are embedded in the public game client and are not cryptographic
// secrets, but they are still kept out of source so a deployment can select a
// region. The session token IS a secret and is never configured here.
type tapTapSection struct {
	ClientID           string `toml:"client_id"`
	AppKeyEnv          string `toml:"leancloud_app_key_env"`
	DeviceCodeEndpoint string `toml:"device_code_endpoint"`
	TokenEndpoint      string `toml:"token_endpoint"`
	UserInfoEndpoint   string `toml:"user_info_endpoint"`
	LeanCloudBaseURL   string `toml:"leancloud_base_url"`
}

type socialSection struct {
	ClientID        string `toml:"client_id"`
	ClientSecretEnv string `toml:"client_secret_env"`
	Issuer          string `toml:"issuer"`
}

// settings is the resolved form main consumes.
type settings struct {
	Addr           string
	Issuer         string
	Re0AuthBaseURL string
	ClientID       string
	ClientSecret   string
	Provider       string
	Discovery      upstreamkit.Config

	tapTap *tapTapSettings
	social []idp.Credentials
}

type tapTapSettings struct {
	ClientID           string
	AppKey             string
	DeviceCodeEndpoint string
	TokenEndpoint      string
	UserInfoEndpoint   string
	LeanCloudBaseURL   string
}

// knownSocial is the closed set of provider names accepted in [social.*].
var knownSocial = map[string]idp.Provider{
	"github":    idp.GitHub,
	"google":    idp.Google,
	"discord":   idp.Discord,
	"microsoft": idp.Microsoft,
	"qq":        idp.QQ,
}

const defaultConfigPath = "config/referencesource.toml"

func loadConfig(path string) (settings, error) {
	var f file
	if err := config.Read(path, &f); err != nil {
		return settings{}, err
	}

	cfg := settings{
		Addr:           config.FirstNonEmpty(os.Getenv("REFERENCE_SOURCE_ADDR"), f.Server.Addr, "127.0.0.1:8081"),
		Issuer:         strings.TrimRight(config.FirstNonEmpty(os.Getenv("REFERENCE_SOURCE_ISSUER"), f.Server.Issuer), "/"),
		Re0AuthBaseURL: strings.TrimRight(config.FirstNonEmpty(os.Getenv("RE0AUTH_BASE_URL"), f.Server.Re0AuthBaseURL, "http://127.0.0.1:8080"), "/"),
		ClientID:       config.FirstNonEmpty(f.Client.ID, "re0auth"),
		Provider:       config.FirstNonEmpty(f.Source.Provider, "phigros"),
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "http://" + cfg.Addr
	}
	if f.Client.SecretEnv != "" {
		value, err := config.Secret(f.Client.SecretEnv, "client.secret_env")
		if err != nil {
			return settings{}, err
		}
		cfg.ClientSecret = value
	}
	// Re0Auth is registered as a confidential client, so the secret is not
	// optional. Fail here with a config-shaped message rather than deep inside
	// the OAuth client constructor.
	if cfg.ClientSecret == "" {
		return settings{}, errors.New("client.secret_env is required: Re0Auth is a confidential client")
	}

	discovery := upstreamkit.Config{
		Game:        config.FirstNonEmpty(f.Source.Game, "phigros"),
		Source:      config.FirstNonEmpty(f.Source.Source, "taptap-reference"),
		DisplayName: config.FirstNonEmpty(f.Source.DisplayName, "Phigros (reference source)"),
		Issuer:      cfg.Issuer,
		TokenClass:  upstreamkit.TokenClass(config.FirstNonEmpty(f.Source.TokenClass, string(upstreamkit.TokenRevocable))),
		Contact:     f.Source.Contact,
	}
	for _, res := range f.Source.Resources {
		discovery.Resources = append(discovery.Resources, upstreamkit.Resource{
			Name: res.Name, Schema: res.Schema, Scope: res.Scope,
		})
	}
	if len(discovery.Resources) == 0 {
		return settings{}, errors.New("at least one [[source.resources]] entry is required (see config/referencesource.example.toml)")
	}
	// The Kit is the authority on what a valid discovery document is.
	if _, err := upstreamkit.NewDiscovery(discovery); err != nil {
		return settings{}, fmt.Errorf("source: %w", err)
	}
	cfg.Discovery = discovery

	if f.TapTap != nil {
		tap, err := loadTapTap(f.TapTap)
		if err != nil {
			return settings{}, err
		}
		cfg.tapTap = tap
	}

	credentials, err := loadSocial(f.Social)
	if err != nil {
		return settings{}, err
	}
	cfg.social = credentials
	return cfg, nil
}

func loadTapTap(section *tapTapSection) (*tapTapSettings, error) {
	tap := &tapTapSettings{
		ClientID:           config.FirstNonEmpty(os.Getenv("TAPTAP_CLIENT_ID"), section.ClientID),
		DeviceCodeEndpoint: section.DeviceCodeEndpoint,
		TokenEndpoint:      section.TokenEndpoint,
		UserInfoEndpoint:   section.UserInfoEndpoint,
		LeanCloudBaseURL:   section.LeanCloudBaseURL,
	}
	if tap.ClientID == "" {
		return nil, errors.New("taptap.client_id is required (or set TAPTAP_CLIENT_ID)")
	}
	if appKey := os.Getenv("TAPTAP_LEANCLOUD_APP_KEY"); appKey != "" {
		tap.AppKey = appKey
	} else if section.AppKeyEnv != "" {
		value, err := config.Secret(section.AppKeyEnv, "taptap.leancloud_app_key_env")
		if err != nil {
			return nil, err
		}
		tap.AppKey = value
	}
	if tap.AppKey == "" {
		return nil, errors.New("the TapTap LeanCloud app key is required: set taptap.leancloud_app_key_env")
	}
	if tap.DeviceCodeEndpoint == "" || tap.TokenEndpoint == "" || tap.UserInfoEndpoint == "" || tap.LeanCloudBaseURL == "" {
		return nil, errors.New("taptap needs device_code_endpoint, token_endpoint, user_info_endpoint and leancloud_base_url")
	}
	return tap, nil
}

func loadSocial(sections map[string]socialSection) ([]idp.Credentials, error) {
	if len(sections) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order, so startup logs are stable

	var out []idp.Credentials
	for _, name := range names {
		provider, ok := knownSocial[name]
		if !ok {
			return nil, fmt.Errorf("social.%s: unknown provider (known: %s)", name, strings.Join(knownSocialNames(), ", "))
		}
		section := sections[name]
		if section.ClientID == "" {
			return nil, fmt.Errorf("social.%s.client_id is required", name)
		}
		credential := idp.Credentials{Provider: provider, ClientID: section.ClientID, Issuer: section.Issuer}
		if section.ClientSecretEnv != "" {
			value, err := config.Secret(section.ClientSecretEnv, "social."+name+".client_secret_env")
			if err != nil {
				return nil, err
			}
			credential.ClientSecret = value
		}
		out = append(out, credential)
	}
	return out, nil
}

func knownSocialNames() []string {
	out := make([]string, 0, len(knownSocial))
	for name := range knownSocial {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
