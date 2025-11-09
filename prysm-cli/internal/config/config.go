package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config represents CLI configuration sourced from config files, environment variables, and flags.
type Config struct {
	Profile        string `mapstructure:"-"`
	ConfigFile     string `mapstructure:"-"`
	APIBaseURL     string `mapstructure:"api_url" yaml:"api_url"`
	ComplianceURL  string `mapstructure:"compliance_url" yaml:"compliance_url"`
	DERPServerURL  string `mapstructure:"derp_url" yaml:"derp_url"`
	HomeDir        string `mapstructure:"home" yaml:"home"`
	OutputFormat   string `mapstructure:"format" yaml:"format"`
	Organization   string `mapstructure:"organization" yaml:"organization"`
	DefaultSession string `mapstructure:"session" yaml:"session"`
}

type fileConfig struct {
	Config   Config            `mapstructure:",squash"`
	Profiles map[string]Config `mapstructure:"profiles"`
}

// DefaultHomeDir returns the default configuration directory.
func DefaultHomeDir() (string, error) {
	base, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(base, ".prysm"), nil
}

// Load reads configuration from config file, environment variables, and defaults.
func Load(path, profile string) (*Config, error) {
	cfg := defaultConfig()
	cfg.ConfigFile = path

	fc, err := readFileConfig(path)
	if err != nil {
		return nil, err
	}

	cfg.merge(fc.Config)

	if profile == "" {
		profile = cfg.Profile
	}
	if profile == "" {
		profile = "default"
	}
	if profile != "default" {
		if fc.Profiles == nil {
			return nil, fmt.Errorf("profile %q not defined in %s", profile, path)
		}

		profileCfg, ok := fc.Profiles[profile]
		if !ok {
			return nil, fmt.Errorf("profile %q not defined in %s", profile, path)
		}
		cfg.merge(profileCfg)
	}

	applyEnvOverrides(&cfg)

	cfg.Profile = profile

	return &cfg, nil
}

func defaultConfig() Config {
	home, _ := DefaultHomeDir()
	return Config{
		APIBaseURL:    "https://api.prysm.sh/v1",
		ComplianceURL: "https://compliance.prysm.sh/v1/compliance",
		DERPServerURL: "wss://derp.prysm.sh/derp",
		HomeDir:       home,
		OutputFormat:  "table",
	}
}

// Default returns a default configuration with standard values.
func Default() *Config {
	cfg := defaultConfig()
	return &cfg
}

func readFileConfig(path string) (*fileConfig, error) {
	if path == "" {
		return &fileConfig{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &fileConfig{}, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	var fc fileConfig
	if err := v.Unmarshal(&fc); err != nil {
		return nil, fmt.Errorf("decode config file: %w", err)
	}

	return &fc, nil
}

func (c *Config) merge(other Config) {
	if other.APIBaseURL != "" {
		c.APIBaseURL = strings.TrimRight(other.APIBaseURL, "/")
	}
	if other.ComplianceURL != "" {
		c.ComplianceURL = strings.TrimRight(other.ComplianceURL, "/")
	}
	if other.DERPServerURL != "" {
		c.DERPServerURL = strings.TrimRight(other.DERPServerURL, "/")
	}
	if other.HomeDir != "" {
		c.HomeDir = other.HomeDir
	}
	if other.OutputFormat != "" {
		c.OutputFormat = other.OutputFormat
	}
	if other.Organization != "" {
		c.Organization = other.Organization
	}
	if other.DefaultSession != "" {
		c.DefaultSession = other.DefaultSession
	}
}

func applyEnvOverrides(cfg *Config) {
	if val := os.Getenv("PRYSM_API_URL"); val != "" {
		cfg.APIBaseURL = strings.TrimRight(val, "/")
	}
	if val := os.Getenv("PRYSM_COMPLIANCE_URL"); val != "" {
		cfg.ComplianceURL = strings.TrimRight(val, "/")
	}
	if val := os.Getenv("PRYSM_DERP_URL"); val != "" {
		cfg.DERPServerURL = strings.TrimRight(val, "/")
	}
	if val := os.Getenv("PRYSM_HOME"); val != "" {
		cfg.HomeDir = val
	}
	if val := os.Getenv("PRYSM_FORMAT"); val != "" {
		cfg.OutputFormat = val
	}
	if val := os.Getenv("PRYSM_ORG"); val != "" {
		cfg.Organization = val
	}
}
