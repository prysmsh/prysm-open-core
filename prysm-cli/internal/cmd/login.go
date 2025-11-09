package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/warp-run/prysm-cli/internal/api"
	"github.com/warp-run/prysm-cli/internal/session"
)

func newLoginCommand() *cobra.Command {
	var (
		email      string
		password   string
		totp       string
		backupCode string
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate to the Prysm control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()

			if email == "" {
				var err error
				email, err = promptInput("Email")
				if err != nil {
					return err
				}
			}
			email = strings.TrimSpace(email)
			if email == "" {
				return errors.New("email is required")
			}

			if password == "" {
				var err error
				password, err = promptPassword("Password")
				if err != nil {
					return err
				}
			}

			req := api.LoginRequest{
				Email:      email,
				Password:   password,
				TOTPCode:   totp,
				BackupCode: backupCode,
			}

			// Create context with timeout and signal handling
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			// Handle interrupt signals
			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				select {
				case <-signalChan:
					fmt.Fprintf(os.Stderr, "\nInterrupted, cancelling login...\n")
					cancel()
				case <-ctx.Done():
				}
			}()

			if app.Debug {
				fmt.Fprintf(os.Stderr, "[debug] Attempting login for %s\n", email)
			}

			resp, err := app.API.Login(ctx, req)
			if err != nil {
				if app.Debug {
					fmt.Fprintf(os.Stderr, "[debug] Login failed: %v\n", err)
				}
				return err
			}

			if app.Debug {
				fmt.Fprintf(os.Stderr, "[debug] Login successful for %s\n", resp.User.Email)
			}

			sess := &session.Session{
				Token:         resp.Token,
				RefreshToken:  resp.RefreshToken,
				Email:         resp.User.Email,
				SessionID:     resp.SessionID,
				CSRFToken:     resp.CSRFToken,
				ExpiresAtUnix: resp.ExpiresAtUnix,
				User: session.SessionUser{
					ID:         resp.User.ID,
					Name:       resp.User.Name,
					Email:      resp.User.Email,
					Role:       resp.User.Role,
					MFAEnabled: resp.User.MFAEnabled,
				},
				Organization: session.SessionOrg{
					ID:   resp.Organization.ID,
					Name: resp.Organization.Name,
				},
				APIBaseURL:    app.Config.APIBaseURL,
				ComplianceURL: app.Config.ComplianceURL,
				DERPServerURL: app.Config.DERPServerURL,
				OutputFormat:  app.OutputFormat,
			}

			if err := app.Sessions.Save(sess); err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Login successful — welcome, %s (%s)\n", resp.User.Name, resp.User.Email)
			return nil
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "email address")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password (not recommended to use via flag)")
	cmd.Flags().StringVar(&totp, "totp", "", "TOTP code for MFA")
	cmd.Flags().StringVar(&backupCode, "backup-code", "", "backup code for MFA")

	return cmd
}

func promptInput(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func promptPassword(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		bytes, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}
