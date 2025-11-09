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

	"github.com/warp-run/prysm-cli/internal/api"
	"github.com/warp-run/prysm-cli/internal/session"
)

func newSessionCommand() *cobra.Command {
	sessionCmd := &cobra.Command{
		Use:   "session",
		Short: "Manage authentication sessions",
	}

	sessionCmd.AddCommand(
		newSessionStatusCommand(),
		newSessionListCommand(),
		newSessionGetCommand(),
		newSessionEndCommand(),
		newSessionRevokeCommand(),
		newSessionRefreshCommand(),
	)

	return sessionCmd
}

func newSessionStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show information about the current session",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			sess, err := app.Sessions.Load()
			if err != nil {
				return err
			}
			if sess == nil {
				color.New(color.FgYellow).Println("No active session detected. Run `prysm login` to authenticate.")
				return nil
			}

			expiry := sess.ExpiresAt()
			statusColor := color.New(color.FgGreen)
			if sess.IsExpired(5 * time.Minute) {
				statusColor = color.New(color.FgRed)
			}

			fmt.Printf("Identity: %s (%s)\n", sess.User.Name, sess.Email)
			fmt.Printf("Organization: %s (ID %d)\n", sess.Organization.Name, sess.Organization.ID)
			fmt.Printf("Session ID: %s\n", sess.SessionID)
			fmt.Printf("API Endpoint: %s\n", sess.APIBaseURL)
			fmt.Printf("DERP Relay: %s\n", sess.DERPServerURL)
			fmt.Printf("Issued: %s\n", sess.SavedAt.Format(time.RFC3339))
			if !expiry.IsZero() {
				statusColor.Printf("Expires: %s\n", expiry.Format(time.RFC3339))
			}
			return nil
		},
	}
}

func newSessionRefreshCommand() *cobra.Command {
	var password string
	var totp string
	var backup string

	refreshCmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh the current session by re-authenticating",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			sess, err := app.Sessions.Load()
			if err != nil {
				return err
			}
			if sess == nil {
				return fmt.Errorf("no active session; run `prysm login`")
			}

			if password == "" {
				password, err = promptPassword("Password")
				if err != nil {
					return err
				}
			}

			req := api.LoginRequest{
				Email:      sess.Email,
				Password:   password,
				TOTPCode:   totp,
				BackupCode: backup,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			resp, err := app.API.Login(ctx, req)
			if err != nil {
				return err
			}

			newSess := *sess
			newSess.Token = resp.Token
			newSess.RefreshToken = resp.RefreshToken
			newSess.ExpiresAtUnix = resp.ExpiresAtUnix
			newSess.SessionID = resp.SessionID
			newSess.CSRFToken = resp.CSRFToken
			newSess.User = session.SessionUser{
				ID:         resp.User.ID,
				Name:       resp.User.Name,
				Email:      resp.User.Email,
				Role:       resp.User.Role,
				MFAEnabled: resp.User.MFAEnabled,
			}
			newSess.Organization = session.SessionOrg{
				ID:   resp.Organization.ID,
				Name: resp.Organization.Name,
			}

			if err := app.Sessions.Save(&newSess); err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Session refreshed — expires %s\n", newSess.ExpiresAt().Format(time.RFC3339))
			return nil
		},
	}

	refreshCmd.Flags().StringVarP(&password, "password", "p", "", "password")
	refreshCmd.Flags().StringVar(&totp, "totp", "", "TOTP code")
	refreshCmd.Flags().StringVar(&backup, "backup-code", "", "backup code")

	return refreshCmd
}

func newSessionListCommand() *cobra.Command {
	var format string
	var includeRedis bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active sessions and credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, err := app.API.ListSessions(ctx)
			if err != nil {
				return err
			}

			if resp == nil || len(resp.Sessions) == 0 {
				color.New(color.FgYellow).Println("No sessions found.")
				return nil
			}

			sessions := resp.Sessions
			if !includeRedis {
				filtered := sessions[:0]
				for _, s := range sessions {
					if !strings.EqualFold(s.Source, "redis") {
						filtered = append(filtered, s)
					}
				}
				sessions = filtered
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(sessions)
			default:
				return renderSessionsTable(sessions)
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	cmd.Flags().BoolVar(&includeRedis, "include-redis", false, "include Redis-backed sessions in the output")
	return cmd
}
func newSessionGetCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "get <session-id>",
		Short: "Get details for a specific session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := strings.TrimSpace(args[0])
			if sessionID == "" {
				return fmt.Errorf("session ID required")
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			session, err := app.API.GetSession(ctx, sessionID)
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(session)
			case "yaml":
				fmt.Printf("session_id: %s\n", session.SessionID)
				fmt.Printf("status: %s\n", session.Status)
				fmt.Printf("started_at: %s\n", session.StartedAt)
				if session.EndedAt != nil {
					fmt.Printf("ended_at: %s\n", *session.EndedAt)
				}
				if session.ExpiresAt != nil {
					fmt.Printf("expires_at: %s\n", *session.ExpiresAt)
				}
				fmt.Printf("credential_type: %s\n", session.CredentialType)
				fmt.Printf("source: %s\n", session.Source)
				return nil
			default:
				color.New(color.FgCyan, color.Bold).Printf("Session: %s\n", session.SessionID)
				fmt.Printf("  Status: %s\n", session.Status)
				fmt.Printf("  Started: %s\n", session.StartedAt)
				if session.EndedAt != nil {
					fmt.Printf("  Ended: %s\n", *session.EndedAt)
				}
				if session.ExpiresAt != nil {
					fmt.Printf("  Expires: %s\n", *session.ExpiresAt)
				}
				fmt.Printf("  Credential Type: %s\n", session.CredentialType)
				if session.CredentialRef != "" {
					fmt.Printf("  Credential Ref: %s\n", session.CredentialRef)
				}
				fmt.Printf("  Source: %s\n", session.Source)
				if session.IPAddress != "" {
					fmt.Printf("  IP Address: %s\n", session.IPAddress)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json|yaml)")
	return cmd
}

func newSessionEndCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "end <session-id>",
		Short: "End an active session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := strings.TrimSpace(args[0])
			if sessionID == "" {
				return fmt.Errorf("session ID required")
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			if err := app.API.EndSession(ctx, sessionID); err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Session %s ended\n", sessionID)
			return nil
		},
	}
}

func newSessionRevokeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <session-id>",
		Short: "Revoke a session by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := strings.TrimSpace(args[0])
			if sessionID == "" {
				return fmt.Errorf("session ID required")
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			if err := app.API.RevokeSession(ctx, sessionID); err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Session %s revoked\n", sessionID)
			return nil
		},
	}
}

func renderSessionsTable(sessions []api.CLISession) error {
	if len(sessions) == 0 {
		color.New(color.FgYellow).Println("No database-backed sessions.")
		return nil
	}

	fmt.Printf("Found %d session(s):\n", len(sessions))
	for _, s := range sessions {
		if strings.EqualFold(s.Source, "redis") {
			active := "inactive"
			if s.IsActive != nil && *s.IsActive {
				active = "active"
			}
			fmt.Printf("- Redis session (IP %s, %s)", s.IPAddress, active)
			if t := formatSessionTimePtr(s.CreatedAt); t != "" {
				fmt.Printf(" created %s", t)
			}
			if t := formatSessionTimePtr(s.LastAccessed); t != "" {
				fmt.Printf(", last access %s", t)
			}
			if s.UserAgent != "" {
				fmt.Printf(" — %s", s.UserAgent)
			}
			fmt.Println()
			continue
		}

		fmt.Printf("- %s (%s)\n", s.SessionID, s.Status)
		if s.CredentialType != "" {
			line := fmt.Sprintf("    Credential: %s", s.CredentialType)
			if s.CredentialRef != "" {
				line += fmt.Sprintf(" [%s]", s.CredentialRef)
			}
			fmt.Println(line)
		}
		if s.VaultPath != "" {
			fmt.Printf("    Vault Path: %s\n", s.VaultPath)
		}
		if t := formatSessionTimePtr(s.ExpiresAt); t != "" {
			fmt.Printf("    Expires: %s\n", t)
		}
	}
	return nil
}

func formatSessionTime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return value
}

func formatSessionTimePtr(value *string) string {
	if value == nil {
		return ""
	}
	return formatSessionTime(*value)
}
