package passbolt

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

const DefaultProfileName = "default"

var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type Profile struct {
	Name      string `mapstructure:"-"`
	ServerURL string `mapstructure:"server_url" json:"server_url" yaml:"server_url"`
	UserID    string `mapstructure:"user_id" json:"user_id" yaml:"user_id"`
	Username  string `mapstructure:"username,omitempty" json:"username,omitempty" yaml:"username,omitempty"`
}

type Config struct {
	DefaultProfile string             `mapstructure:"default_profile" json:"default_profile" yaml:"default_profile"`
	Profiles       map[string]Profile `mapstructure:"profiles" json:"profiles" yaml:"profiles"`
}

type ConfigStore struct {
	v *viper.Viper
}

func NewConfigStore(v *viper.Viper) ConfigStore {
	return ConfigStore{v: v}
}

func (s ConfigStore) Load() (Config, error) {
	cfg := Config{
		DefaultProfile: DefaultProfileName,
		Profiles:       map[string]Profile{},
	}
	if s.v == nil {
		return cfg, nil
	}
	if err := s.v.Unmarshal(&cfg); err != nil {
		return Config{}, err
	}
	if cfg.DefaultProfile == "" {
		cfg.DefaultProfile = DefaultProfileName
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	for name, profile := range cfg.Profiles {
		profile.Name = name
		cfg.Profiles[name] = profile
	}
	return cfg, nil
}

func (s ConfigStore) GetProfile(name string) (Profile, error) {
	cfg, err := s.Load()
	if err != nil {
		return Profile{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = cfg.DefaultProfile
	}
	profile, ok := cfg.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found", name)
	}
	profile.Name = name
	return profile, nil
}

func (s ConfigStore) UpsertProfile(profile Profile, setDefault bool) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	cfg.Profiles[profile.Name] = Profile{
		ServerURL: normalizeBaseURL(profile.ServerURL),
		UserID:    strings.TrimSpace(profile.UserID),
		Username:  strings.TrimSpace(profile.Username),
	}
	if cfg.DefaultProfile == "" || setDefault {
		cfg.DefaultProfile = profile.Name
	}
	return s.write(cfg)
}

func (s ConfigStore) SetDefaultProfile(name string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	cfg.DefaultProfile = name
	return s.write(cfg)
}

func (s ConfigStore) RemoveProfile(name string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(cfg.Profiles, name)
	if cfg.DefaultProfile == name {
		cfg.DefaultProfile = DefaultProfileName
		if _, ok := cfg.Profiles[cfg.DefaultProfile]; !ok {
			cfg.DefaultProfile = ""
			for existing := range cfg.Profiles {
				cfg.DefaultProfile = existing
				break
			}
		}
	}
	return s.write(cfg)
}

func (s ConfigStore) ProfileNames() ([]string, string, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, cfg.DefaultProfile, nil
}

func (s ConfigStore) write(cfg Config) error {
	if s.v == nil {
		return errors.New("config store is not initialized")
	}
	s.v.Set("default_profile", cfg.DefaultProfile)
	s.v.Set("profiles", cfg.Profiles)
	if s.v.ConfigFileUsed() == "" {
		if err := ensureDefaultConfigPath(s.v); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.v.ConfigFileUsed()), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.v.ConfigFileUsed()); errors.Is(err, os.ErrNotExist) {
		return s.v.SafeWriteConfigAs(s.v.ConfigFileUsed())
	}
	return s.v.WriteConfigAs(s.v.ConfigFileUsed())
}

func ensureDefaultConfigPath(v *viper.Viper) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	v.SetConfigFile(filepath.Join(home, ".config", "bolty", "config.yaml"))
	v.SetConfigType("yaml")
	return nil
}

func ValidateProfile(profile Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("profile name is required")
	}
	if !profileNameRE.MatchString(profile.Name) {
		return fmt.Errorf("profile name %q may only contain letters, numbers, dots, dashes, and underscores", profile.Name)
	}
	if strings.TrimSpace(profile.UserID) == "" {
		return errors.New("user id is required")
	}
	if strings.TrimSpace(profile.ServerURL) == "" {
		return errors.New("server url is required")
	}
	u, err := url.Parse(strings.TrimSpace(profile.ServerURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("server url %q is invalid", profile.ServerURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("server url scheme %q is not supported", u.Scheme)
	}
	return nil
}

func normalizeBaseURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}
