package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func newHealthCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check API health status",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			// Health check endpoint
			var healthResp map[string]interface{}
			if _, err := app.API.Do(ctx, "GET", "/health", nil, &healthResp); err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(healthResp)
			default:
				status := "unknown"
				if s, ok := healthResp["status"].(string); ok {
					status = s
				}

				if strings.EqualFold(status, "healthy") {
					color.New(color.FgGreen, color.Bold).Printf("✅ API Status: %s\n", status)
				} else {
					color.New(color.FgRed, color.Bold).Printf("❌ API Status: %s\n", status)
				}

				// Print additional info if available
				for key, value := range healthResp {
					if key != "status" {
						fmt.Printf("  %s: %v\n", key, value)
					}
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	return cmd
}

func newWhoamiCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Display current user and session information",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			sess, err := app.Sessions.Load()
			if err != nil {
				return err
			}
			if sess == nil {
				color.New(color.FgYellow).Println("Not authenticated. Run `prysm login` to authenticate.")
				return nil
			}

			switch strings.ToLower(format) {
			case "json":
				output := map[string]interface{}{
					"user": map[string]interface{}{
						"id":          sess.User.ID,
						"name":        sess.User.Name,
						"email":       sess.Email,
						"role":        sess.User.Role,
						"mfa_enabled": sess.User.MFAEnabled,
					},
					"organization": map[string]interface{}{
						"id":   sess.Organization.ID,
						"name": sess.Organization.Name,
					},
					"session": map[string]interface{}{
						"id":          sess.SessionID,
						"api_url":     sess.APIBaseURL,
						"issued_at":   sess.SavedAt.Format(time.RFC3339),
						"expires_at":  sess.ExpiresAt().Format(time.RFC3339),
					},
				}
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(output)
			default:
				color.New(color.FgCyan, color.Bold).Printf("Logged in as: %s\n", sess.User.Name)
				fmt.Printf("\nUser Details:\n")
				fmt.Printf("  Email: %s\n", sess.Email)
				fmt.Printf("  Role: %s\n", sess.User.Role)
				fmt.Printf("  MFA Enabled: %v\n", sess.User.MFAEnabled)
				
				fmt.Printf("\nOrganization:\n")
				fmt.Printf("  Name: %s\n", sess.Organization.Name)
				fmt.Printf("  ID: %d\n", sess.Organization.ID)
				
				fmt.Printf("\nSession:\n")
				fmt.Printf("  ID: %s\n", sess.SessionID)
				fmt.Printf("  API Endpoint: %s\n", sess.APIBaseURL)
				fmt.Printf("  Issued: %s\n", sess.SavedAt.Format(time.RFC3339))
				
				expiry := sess.ExpiresAt()
				if !expiry.IsZero() {
					if sess.IsExpired(0) {
						color.New(color.FgRed).Printf("  Expired: %s\n", expiry.Format(time.RFC3339))
					} else if sess.IsExpired(5 * time.Minute) {
						color.New(color.FgYellow).Printf("  Expires: %s (soon)\n", expiry.Format(time.RFC3339))
					} else {
						color.New(color.FgGreen).Printf("  Expires: %s\n", expiry.Format(time.RFC3339))
					}
				}
				
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	return cmd
}

