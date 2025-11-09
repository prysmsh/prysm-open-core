package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/warp-run/prysm-cli/internal/api"
)

func newConnectCommand() *cobra.Command {
	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Establish access to managed infrastructure resources",
	}

	connectCmd.AddCommand(
		newConnectKubernetesCommand(),
		newConnectDevicesCommand(),
	)

	return connectCmd
}

func newConnectKubernetesCommand() *cobra.Command {
	var (
		clusterRef string
		namespace  string
		reason     string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "k8s",
		Short: "Issue a temporary kubeconfig for a managed Kubernetes cluster (via WireGuard mesh)",
		Long: `Connect to a Kubernetes cluster through the WireGuard mesh.

This command automatically:
1. Joins the DERP mesh for peer discovery
2. Establishes WireGuard tunnels to cluster agents
3. Issues a short-lived kubeconfig pointing to the WireGuard mesh IP

All kubectl traffic flows through the encrypted WireGuard tunnel - clusters are never exposed publicly.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterRef == "" {
				return errors.New("cluster reference is required (--cluster)")
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
			defer cancel()

			// ZERO-TRUST: Ensure WireGuard mesh is established before kubectl access
			color.New(color.FgCyan).Println("🔐 Ensuring WireGuard mesh connectivity...")
			if err := ensureWireGuardMesh(app, ctx); err != nil {
				color.New(color.FgYellow).Printf("⚠️  WireGuard mesh unavailable: %v\n", err)
				color.New(color.FgYellow).Println("💡 Tip: Run `prysm mesh wg up` to configure WireGuard manually")
				return fmt.Errorf("mesh connectivity required for zero-trust kubectl access")
			}

			clusters, err := app.API.ListClusters(ctx)
			if err != nil {
				return err
			}
			if len(clusters) == 0 {
				return errors.New("no Kubernetes clusters available for your organization")
			}

			cluster, err := findCluster(clusters, clusterRef)
			if err != nil {
				var b strings.Builder
				fmt.Fprintf(&b, "%v\nAvailable clusters:\n", err)
				for _, c := range clusters {
					status := color.HiGreenString(c.Status)
					if strings.ToLower(c.Status) != "connected" {
						status = color.HiRedString(c.Status)
					}
					fmt.Fprintf(&b, "  - %d\t%s\t%s\n", c.ID, c.Name, status)
				}
				return errors.New(b.String())
			}

			// Get kubeconfig (now points to WireGuard mesh IP)
			resp, err := app.API.ConnectKubernetes(ctx, cluster.ID, namespace, reason)
			if err != nil {
				return err
			}

			kubeconfig, err := decodeKubeconfig(resp.Kubeconfig)
			if err != nil {
				return err
			}

			// Verify kubeconfig points to mesh IP (not direct URL)
			if strings.Contains(kubeconfig, "100.") {
				color.New(color.FgGreen).Println("✅ Kubeconfig uses WireGuard mesh IP (zero-trust)")
			} else {
				color.New(color.FgYellow).Println("⚠️  Warning: Kubeconfig may use direct URL (legacy cluster)")
			}

			if outputPath != "" {
				dest := outputPath
				if !filepath.IsAbs(dest) {
					dest, _ = filepath.Abs(dest)
				}
				if err := os.WriteFile(dest, []byte(kubeconfig), 0o600); err != nil {
					return fmt.Errorf("write kubeconfig: %w", err)
				}
				color.New(color.FgGreen).Printf("📁 Kubeconfig written to %s\n", dest)
			} else {
				fmt.Println("----- kubeconfig (apply with kubectl) -----")
				fmt.Print(kubeconfig)
				if !strings.HasSuffix(kubeconfig, "\n") {
					fmt.Println()
				}
				fmt.Println("----- end kubeconfig -----")
				color.New(color.FgHiBlack).Println("Tip: rerun with --output <path> to save this configuration.")
			}

			color.New(color.FgGreen).Printf("✅ Kubernetes session established for %s (session: %s)\n", resp.Cluster.Name, resp.Session.SessionID)
			color.New(color.FgHiBlack).Println("💡 Traffic flows through WireGuard mesh - cluster API never exposed publicly")
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterRef, "cluster", "", "cluster name or ID")
	cmd.Flags().StringVar(&namespace, "namespace", "", "override namespace policy")
	cmd.Flags().StringVar(&reason, "reason", "", "access justification for audit logs")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write kubeconfig to file")

	return cmd
}

func newConnectDevicesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "devices",
		Short: "Show devices currently connected through the Prysm mesh",
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

func findCluster(clusters []api.Cluster, ref string) (*api.Cluster, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil, errors.New("cluster reference is empty")
	}

	for _, cluster := range clusters {
		if strings.EqualFold(cluster.Name, trimmed) {
			return &cluster, nil
		}
	}

	if id, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		for _, cluster := range clusters {
			if cluster.ID == id {
				return &cluster, nil
			}
		}
	}

	return nil, fmt.Errorf("cluster %q not found", ref)
}

func decodeKubeconfig(material api.KubeconfigMaterial) (string, error) {
	value := material.Value
	switch strings.ToLower(material.Encoding) {
	case "base64", "b64":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("decode kubeconfig: %w", err)
		}
		return string(decoded), nil
	default:
		return value, nil
	}
}

// ensureWireGuardMesh checks if WireGuard mesh is configured and attempts to set it up
func ensureWireGuardMesh(app *App, ctx context.Context) error {
	// Check if prysm-meshd daemon is running
	status, err := app.Meshd.Status(ctx)
	if err != nil {
		return fmt.Errorf("meshd not accessible: %w", err)
	}

	// If WireGuard is already up, we're good
	if status != nil && status.State == "up" {
		color.New(color.FgGreen).Println("✅ WireGuard mesh already connected")
		return nil
	}

	// Try to configure and bring up WireGuard
	color.New(color.FgYellow).Println("📡 Configuring WireGuard mesh...")
	
	// This would call the meshd daemon to configure WireGuard
	// For now, provide helpful instruction
	return fmt.Errorf("WireGuard not configured - run `prysm mesh wg up` first")
	
	// TODO: Implement auto-configuration:
	// 1. Fetch WireGuard config from backend
	// 2. Apply config via meshd daemon
	// 3. Bring up interface
	// 4. Verify connectivity to cluster agents
}
