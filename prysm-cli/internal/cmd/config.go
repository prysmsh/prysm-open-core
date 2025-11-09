package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/warp-run/prysm-cli/internal/config"
)

func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI configuration",
	}

	configCmd.AddCommand(
		newConfigShowCommand(),
		newConfigSetCommand(),
		newConfigResetCommand(),
	)

	return configCmd
}

func newConfigShowCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Display current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			cfg := app.Config

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(cfg)
			case "yaml":
				encoder := yaml.NewEncoder(os.Stdout)
				defer encoder.Close()
				return encoder.Encode(cfg)
			default:
				color.New(color.FgCyan, color.Bold).Println("Current Configuration:")
				fmt.Printf("\nGeneral:\n")
				fmt.Printf("  Home Directory: %s\n", cfg.HomeDir)
				fmt.Printf("  Output Format: %s\n", cfg.OutputFormat)
				
				fmt.Printf("\nAPI Endpoints:\n")
				fmt.Printf("  API URL: %s\n", cfg.APIBaseURL)
				fmt.Printf("  Compliance URL: %s\n", cfg.ComplianceURL)
				fmt.Printf("  DERP Server URL: %s\n", cfg.DERPServerURL)
				
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json|yaml)")
	return cmd
}

func newConfigSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: `Set a configuration value. Available keys:
  - api_url: API base URL
  - compliance_url: Compliance API URL
  - derp_url: DERP server URL
  - output_format: Default output format (json, yaml, table)
  - default_cluster: Default cluster ID`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			value := strings.TrimSpace(args[1])

			if value == "" {
				return errors.New("value cannot be empty")
			}

			app := MustApp()
			cfg := app.Config

			// Update the config value
			switch key {
			case "api_url", "api-url":
				cfg.APIBaseURL = value
			case "compliance_url", "compliance-url":
				cfg.ComplianceURL = value
			case "derp_url", "derp-url", "derp_server_url":
				cfg.DERPServerURL = value
			case "output_format", "output-format", "format":
				if !isValidFormat(value) {
					return fmt.Errorf("invalid format %q: must be json, yaml, or table", value)
				}
				cfg.OutputFormat = value
			default:
				return fmt.Errorf("unknown configuration key %q", key)
			}

			// Save the updated config
			cfgPath := cfgFile
			if cfgPath == "" {
				home, err := config.DefaultHomeDir()
				if err != nil {
					return fmt.Errorf("determine config directory: %w", err)
				}
				cfgPath = filepath.Join(home, "config.yaml")
			}

			if err := saveConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			color.New(color.FgGreen).Printf("✅ Configuration updated: %s = %s\n", key, value)
			return nil
		},
	}
}

func newConfigResetCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset configuration to defaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Println("This will reset all configuration to default values.")
				fmt.Print("Type 'yes' to confirm: ")
				var confirm string
				fmt.Scanln(&confirm)
				if !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
					color.New(color.FgYellow).Println("Reset cancelled.")
					return nil
				}
			}

			cfgPath := cfgFile
			if cfgPath == "" {
				home, err := config.DefaultHomeDir()
				if err != nil {
					return fmt.Errorf("determine config directory: %w", err)
				}
				cfgPath = filepath.Join(home, "config.yaml")
			}

			// Create default config
			defaultCfg := config.Default()

			// Save default config
			if err := saveConfig(cfgPath, defaultCfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			color.New(color.FgGreen).Println("✅ Configuration reset to defaults")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

func isValidFormat(format string) bool {
	switch strings.ToLower(format) {
	case "json", "yaml", "table":
		return true
	default:
		return false
	}
}

func saveConfig(path string, cfg *config.Config) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Marshal config to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

