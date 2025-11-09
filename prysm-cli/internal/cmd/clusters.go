package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/warp-run/prysm-cli/internal/api"
)

func newClustersCommand() *cobra.Command {
	clustersCmd := &cobra.Command{
		Use:   "clusters",
		Short: "Manage Kubernetes clusters",
	}

	clustersCmd.AddCommand(
		newClustersListCommand(),
		newClustersGetCommand(),
		newClustersUpdateCommand(),
		newClustersDeleteCommand(),
		newClustersPingCommand(),
		newClustersCheckCommand(),
	)

	return clustersCmd
}

func newClustersListCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all registered clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			clusters, err := app.API.ListClusters(ctx)
			if err != nil {
				return err
			}

			if len(clusters) == 0 {
				color.New(color.FgYellow).Println("No clusters found.")
				return nil
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(clusters)
			case "yaml":
				// Simple YAML-like output
				for _, cluster := range clusters {
					fmt.Printf("- id: %d\n", cluster.ID)
					fmt.Printf("  name: %s\n", cluster.Name)
					fmt.Printf("  description: %s\n", cluster.Description)
					fmt.Printf("  status: %s\n", cluster.Status)
					fmt.Printf("  namespace: %s\n", cluster.Namespace)
					fmt.Printf("  is_exit_router: %v\n", cluster.IsExitRouter)
					if cluster.LastPing != nil {
						fmt.Printf("  last_ping: %s\n", cluster.LastPing.Format(time.RFC3339))
					}
					fmt.Println()
				}
				return nil
			default:
				// Table format
				fmt.Printf("%-8s %-30s %-15s %-20s\n", "ID", "NAME", "STATUS", "LAST PING")
				fmt.Println(strings.Repeat("-", 80))
				for _, cluster := range clusters {
					statusColor := color.New(color.FgGreen)
					if !strings.EqualFold(cluster.Status, "connected") {
						statusColor = color.New(color.FgRed)
					}
					
					lastPing := "never"
					if cluster.LastPing != nil {
						lastPing = cluster.LastPing.Format("2006-01-02 15:04:05")
					}
					
					fmt.Printf("%-8d %-30s ", cluster.ID, cluster.Name)
					statusColor.Printf("%-15s ", cluster.Status)
					fmt.Printf("%-20s\n", lastPing)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json|yaml)")
	return cmd
}

func newClustersGetCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "get <cluster-id>",
		Short: "Get details for a specific cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := parseClusterID(args[0])
			if err != nil {
				return err
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			cluster, err := app.API.GetCluster(ctx, clusterID)
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(cluster)
			case "yaml":
				fmt.Printf("id: %d\n", cluster.ID)
				fmt.Printf("name: %s\n", cluster.Name)
				fmt.Printf("description: %s\n", cluster.Description)
				fmt.Printf("status: %s\n", cluster.Status)
				fmt.Printf("namespace: %s\n", cluster.Namespace)
				fmt.Printf("is_exit_router: %v\n", cluster.IsExitRouter)
				fmt.Printf("created_at: %s\n", cluster.CreatedAt.Format(time.RFC3339))
				fmt.Printf("updated_at: %s\n", cluster.UpdatedAt.Format(time.RFC3339))
				if cluster.LastPing != nil {
					fmt.Printf("last_ping: %s\n", cluster.LastPing.Format(time.RFC3339))
				}
				return nil
			default:
				// Detailed format
				color.New(color.FgCyan, color.Bold).Printf("Cluster: %s\n", cluster.Name)
				fmt.Printf("  ID: %d\n", cluster.ID)
				fmt.Printf("  Description: %s\n", cluster.Description)
				
				statusColor := color.New(color.FgGreen)
				if !strings.EqualFold(cluster.Status, "connected") {
					statusColor = color.New(color.FgRed)
				}
				fmt.Printf("  Status: ")
				statusColor.Println(cluster.Status)
				
				fmt.Printf("  Namespace: %s\n", cluster.Namespace)
				fmt.Printf("  Exit Router: %v\n", cluster.IsExitRouter)
				fmt.Printf("  Created: %s\n", cluster.CreatedAt.Format(time.RFC3339))
				fmt.Printf("  Updated: %s\n", cluster.UpdatedAt.Format(time.RFC3339))
				if cluster.LastPing != nil {
					fmt.Printf("  Last Ping: %s\n", cluster.LastPing.Format(time.RFC3339))
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json|yaml)")
	return cmd
}

func newClustersUpdateCommand() *cobra.Command {
	var (
		name        string
		description string
	)

	cmd := &cobra.Command{
		Use:   "update <cluster-id>",
		Short: "Update cluster properties",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := parseClusterID(args[0])
			if err != nil {
				return err
			}

			if name == "" && description == "" {
				return errors.New("at least one of --name or --description must be provided")
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			req := api.UpdateClusterRequest{
				Name:        name,
				Description: description,
			}

			cluster, err := app.API.UpdateCluster(ctx, clusterID, req)
			if err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Cluster %d updated successfully\n", cluster.ID)
			fmt.Printf("  Name: %s\n", cluster.Name)
			fmt.Printf("  Description: %s\n", cluster.Description)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "new cluster name")
	cmd.Flags().StringVar(&description, "description", "", "new cluster description")
	return cmd
}

func newClustersDeleteCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <cluster-id>",
		Short: "Delete a cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := parseClusterID(args[0])
			if err != nil {
				return err
			}

			if !force {
				fmt.Printf("Are you sure you want to delete cluster %d? This action cannot be undone.\n", clusterID)
				fmt.Print("Type 'yes' to confirm: ")
				var confirm string
				fmt.Scanln(&confirm)
				if !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
					color.New(color.FgYellow).Println("Deletion cancelled.")
					return nil
				}
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			if err := app.API.DeleteCluster(ctx, clusterID); err != nil {
				return err
			}

			color.New(color.FgGreen).Printf("✅ Cluster %d deleted successfully\n", clusterID)
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

func parseClusterID(arg string) (int64, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return 0, errors.New("cluster ID cannot be empty")
	}
	
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cluster ID %q: must be a number", arg)
	}
	
	if id <= 0 {
		return 0, fmt.Errorf("invalid cluster ID %d: must be positive", id)
	}
	
	return id, nil
}

func newClustersPingCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ping <cluster-id>",
		Short: "Ping a specific cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := parseClusterID(args[0])
			if err != nil {
				return err
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			start := time.Now()
			err = app.API.PingCluster(ctx, clusterID)
			elapsed := time.Since(start)

			if err != nil {
				color.New(color.FgRed).Printf("❌ Failed to ping cluster %d: %v\n", clusterID, err)
				return err
			}

			color.New(color.FgGreen).Printf("✅ Successfully pinged cluster %d (latency: %v)\n", clusterID, elapsed)
			return nil
		},
	}

	return cmd
}

func newClustersCheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <cluster-id>",
		Short: "Check connectivity and health of a cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := parseClusterID(args[0])
			if err != nil {
				return err
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			// First get cluster info
			cluster, err := app.API.GetCluster(ctx, clusterID)
			if err != nil {
				return err
			}

			color.New(color.FgCyan, color.Bold).Printf("Checking cluster: %s\n", cluster.Name)
			fmt.Println(strings.Repeat("-", 50))

			// Check API connectivity
			fmt.Print("API Connectivity: ")
			start := time.Now()
			err = app.API.PingCluster(ctx, clusterID)
			latency := time.Since(start)
			if err != nil {
				color.New(color.FgRed).Println("FAILED")
			} else {
				color.New(color.FgGreen).Printf("OK (%v)\n", latency)
			}

			// Check mesh connectivity
			fmt.Print("Mesh Connectivity: ")
			meshStatus, err := app.API.GetClusterMeshStatus(ctx, clusterID)
			if err != nil {
				color.New(color.FgRed).Println("FAILED")
			} else if meshStatus.Connected {
				color.New(color.FgGreen).Printf("CONNECTED (peers: %d)\n", meshStatus.PeerCount)
			} else {
				color.New(color.FgYellow).Println("DISCONNECTED")
			}

			// Check last telemetry
			fmt.Print("Last Telemetry: ")
			if cluster.LastPing != nil {
				age := time.Since(*cluster.LastPing)
				if age < 5*time.Minute {
					color.New(color.FgGreen).Printf("%s ago\n", age.Round(time.Second))
				} else if age < 30*time.Minute {
					color.New(color.FgYellow).Printf("%s ago\n", age.Round(time.Second))
				} else {
					color.New(color.FgRed).Printf("%s ago\n", age.Round(time.Second))
				}
			} else {
				color.New(color.FgRed).Println("NEVER")
			}

			// Show cluster status
			fmt.Print("Cluster Status: ")
			if strings.EqualFold(cluster.Status, "connected") {
				color.New(color.FgGreen).Println(cluster.Status)
			} else {
				color.New(color.FgRed).Println(cluster.Status)
			}

			return nil
		},
	}

	return cmd
}
