package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/warp-run/prysm-cli/internal/daemon"
)

func newMeshDaemonCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the local prysm-meshd process",
	}

	cmd.PersistentFlags().String("socket", "", "path to the prysm-meshd Unix domain socket (default: Prysm home)")

	cmd.AddCommand(
		newMeshDaemonStartCommand(),
		newMeshDaemonStopCommand(),
		newMeshDaemonRestartCommand(),
		newMeshDaemonStatusCommand(),
	)

	return cmd
}

func newMeshDaemonStartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Ensure prysm-meshd is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			if err := manager.Start(ctx); err != nil {
				return err
			}

			running, pid, err := manager.IsRunning(cmd.Context())
			if err != nil {
				return err
			}
			if running && pid > 0 {
				color.New(color.FgGreen).Printf("✅ prysm-meshd running (pid %d)\n", pid)
			} else {
				color.New(color.FgGreen).Println("✅ prysm-meshd running")
			}
			color.New(color.FgHiBlack).Printf("Socket: %s\n", manager.Socket())
			color.New(color.FgHiBlack).Printf("Logs: %s\n", manager.LogFile())
			return nil
		},
	}
}

func newMeshDaemonStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the prysm-meshd daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			if err := manager.Stop(ctx); err != nil {
				return err
			}

			color.New(color.FgGreen).Println("🛑 prysm-meshd stopped")
			return nil
		},
	}
}

func newMeshDaemonRestartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the prysm-meshd daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			if err := manager.Restart(ctx); err != nil {
				return err
			}

			running, pid, err := manager.IsRunning(cmd.Context())
			if err != nil {
				return err
			}
			if running && pid > 0 {
				color.New(color.FgGreen).Printf("🔄 prysm-meshd restarted (pid %d)\n", pid)
			} else {
				color.New(color.FgGreen).Println("🔄 prysm-meshd restarted")
			}
			color.New(color.FgHiBlack).Printf("Socket: %s\n", manager.Socket())
			return nil
		},
	}
}

func newMeshDaemonStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show prysm-meshd health information",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			running, pid, err := manager.IsRunning(ctx)
			if err != nil {
				return err
			}

			if !running {
				color.New(color.FgYellow).Println("⚠️  prysm-meshd is not running")
				color.New(color.FgHiBlack).Printf("Socket: %s\n", manager.Socket())
				color.New(color.FgHiBlack).Printf("Logs: %s\n", manager.LogFile())
				return nil
			}

			color.New(color.FgGreen).Printf("✅ prysm-meshd running (pid %d)\n", pid)
			color.New(color.FgHiBlack).Printf("Socket: %s\n", manager.Socket())

			client := daemon.NewClient(manager.Socket())
			status, err := client.Status(ctx)
			if err != nil {
				color.New(color.FgYellow).Printf("Warning: failed to query daemon status: %v\n", err)
				return nil
			}

			color.New(color.FgHiBlack).Printf("Interface up: %t\n", status.InterfaceUp)
			color.New(color.FgHiBlack).Printf("Peers: %d\n", status.PeerCount)
			if !status.LastApply.IsZero() {
				color.New(color.FgHiBlack).Printf("Last apply: %s\n", status.LastApply.UTC().Format(time.RFC3339))
			}
			if len(status.Warnings) > 0 {
				fmt.Println()
				color.New(color.FgYellow).Println("Warnings:")
				for _, w := range status.Warnings {
					color.New(color.FgYellow).Printf("  • %s\n", w)
				}
			}
			return nil
		},
	}
}

func resolveMeshdManager(cmd *cobra.Command) (*daemon.Manager, error) {
	socket, err := cmd.Flags().GetString("socket")
	if err != nil {
		return nil, err
	}

	app := MustApp()
	if strings.TrimSpace(socket) == "" {
		if app.Meshd == nil {
			return nil, fmt.Errorf("meshd manager not initialized")
		}
		return app.Meshd, nil
	}

	return daemon.NewManager(app.Config.HomeDir, socket)
}
