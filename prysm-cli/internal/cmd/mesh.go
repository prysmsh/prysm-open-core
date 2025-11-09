package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/warp-run/prysm-cli/internal/derp"
)

func newMeshCommand() *cobra.Command {
	meshCmd := &cobra.Command{
		Use:   "mesh",
		Short: "Interact with the DERP mesh network",
	}

	meshCmd.AddCommand(
		newMeshConnectCommand(),
		newMeshPeersCommand(),
		newMeshRoutesCommand(),
		newMeshEnrollCommand(),
		newMeshConfigCommand(),
		newMeshProxyCommand(),
		newMeshUpCommand(),
		newMeshDownCommand(),
		newMeshStatusCommand(),
		newMeshDaemonCommand(),
		newMeshTestCommand(),
		newMeshVerifyCommand(),
	)

	return meshCmd
}

func newMeshConnectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "connect",
		Short: "Join the DERP mesh network and stream peer updates",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			sess, err := app.Sessions.Load()
			if err != nil {
				return err
			}
			if sess == nil {
				return fmt.Errorf("no active session; run `prysm login`")
			}

			relay := sess.DERPServerURL
			if relay == "" {
				relay = app.Config.DERPServerURL
			}
			if relay == "" {
				return fmt.Errorf("DERP relay URL not configured")
			}

			deviceID, err := derp.EnsureDeviceID(app.Config.HomeDir)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			capabilities := map[string]interface{}{
				"platform":   "cli",
				"features":   []string{"service_discovery", "health_check"},
				"registered": time.Now().UTC().Format(time.RFC3339),
			}

			registerPayload := map[string]interface{}{
				"device_id":    deviceID,
				"peer_type":    "client",
				"status":       "connected",
				"capabilities": capabilities,
			}

			if _, err := app.API.RegisterMeshNode(ctx, registerPayload); err != nil {
				return fmt.Errorf("register mesh node: %w", err)
			}

			headers := make(http.Header)
			headers.Set("Authorization", "Bearer "+sess.Token)
			headers.Set("X-Session-ID", sess.SessionID)
			headers.Set("X-Org-ID", fmt.Sprintf("%d", sess.Organization.ID))

			client := derp.NewClient(relay, deviceID,
				derp.WithHeaders(headers),
				derp.WithCapabilities(capabilities),
			)

			color.New(color.FgGreen).Printf("🔌 Joining DERP mesh as %s\n", deviceID)
			color.New(color.FgHiBlack).Printf("Relay: %s\n", relay)

			errCh := make(chan error, 1)
			go func() {
				errCh <- client.Run(ctx)
			}()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sigCh)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case sig := <-sigCh:
				color.New(color.FgYellow).Printf("Received %s, disconnecting...\n", sig)
				client.Close()
				return nil
			case err := <-errCh:
				client.Close()
				return err
			}
		},
	}
}

func newMeshPeersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "List mesh peers visible to your organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			nodes, err := app.API.ListMeshNodes(ctx)
			if err != nil {
				return err
			}
			if len(nodes) == 0 {
				color.New(color.FgYellow).Println("No mesh peers registered for your organization.")
				return nil
			}

			renderMeshNodes(nodes)
			return nil
		},
	}
}

func newMeshTestCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run basic mesh connectivity diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			color.New(color.FgYellow).Println("Mesh diagnostics coming soon.")
			color.New(color.FgHiBlack).Println("Tip: use `prysm mesh status` to view current mesh state.")
			return nil
		},
	}
}

func newMeshVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Validate local mesh prerequisites before connecting",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			status, err := app.Meshd.Status(ctx)
			if err != nil {
				return fmt.Errorf("check meshd: %w", err)
			}

			if status.State != "up" {
				color.New(color.FgYellow).Println("⚠️  meshd is not running. Start it with `prysm mesh daemon start`.")
			} else {
				color.New(color.FgGreen).Printf("✅ meshd is running (pid %d)\n", status.PID)
			}

			color.New(color.FgHiBlack).Printf("Socket: %s\n", status.Socket)
			color.New(color.FgHiBlack).Printf("Log file: %s\n", status.LogFile)
			color.New(color.FgGreen).Println("Mesh verification completed.")
			return nil
		},
	}
}
