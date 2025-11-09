package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/warp-run/prysm-cli/internal/api"
)

func newAnalyticsCommand() *cobra.Command {
	analyticsCmd := &cobra.Command{
		Use:   "analytics",
		Short: "View analytics and metrics",
	}

	analyticsCmd.AddCommand(
		newAnalyticsClustersCommand(),
		newAnalyticsSecurityCommand(),
		newAnalyticsPerformanceCommand(),
	)

	return analyticsCmd
}

func newAnalyticsClustersCommand() *cobra.Command {
	var (
		startDate   string
		endDate     string
		granularity string
		format      string
	)

	cmd := &cobra.Command{
		Use:   "clusters <cluster-id>",
		Short: "Get analytics for a specific cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid cluster ID: %w", err)
			}

			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			opts := &api.AnalyticsOptions{
				StartDate:   startDate,
				EndDate:     endDate,
				Granularity: granularity,
			}

			analytics, err := app.API.GetClusterAnalytics(ctx, clusterID, opts)
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(analytics)
			default:
				color.New(color.FgCyan, color.Bold).Printf("Cluster Analytics: %d\n", analytics.ClusterID)
				fmt.Printf("\nPeriod:\n")
				fmt.Printf("  Start: %s\n", analytics.Period.Start)
				fmt.Printf("  End: %s\n", analytics.Period.End)
				
				fmt.Printf("\nMetrics:\n")
				for key, value := range analytics.Metrics {
					fmt.Printf("  %s: %v\n", key, value)
				}
				
				if len(analytics.Trends) > 0 {
					fmt.Printf("\nTrends (%d data points):\n", len(analytics.Trends))
					for i, trend := range analytics.Trends {
						if i >= 5 {
							fmt.Printf("  ... and %d more\n", len(analytics.Trends)-5)
							break
						}
						fmt.Printf("  - %s", trend.Timestamp.Format(time.RFC3339))
						if trend.AccessCount != nil {
							fmt.Printf(" | Access: %d", *trend.AccessCount)
						}
						if trend.ActiveSessions != nil {
							fmt.Printf(" | Sessions: %d", *trend.ActiveSessions)
						}
						fmt.Println()
					}
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&startDate, "start-date", "", "start date (ISO 8601)")
	cmd.Flags().StringVar(&endDate, "end-date", "", "end date (ISO 8601)")
	cmd.Flags().StringVar(&granularity, "granularity", "", "data granularity (hour, day, week)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	return cmd
}

func newAnalyticsSecurityCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "security",
		Short: "Get security analytics",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			analytics, err := app.API.GetSecurityAnalytics(ctx)
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(analytics)
			default:
				color.New(color.FgCyan, color.Bold).Println("Security Analytics")
				
				fmt.Printf("\nThreats:\n")
				fmt.Printf("  Total: %d\n", analytics.Threats.Total)
				fmt.Printf("  High Risk: ")
				if analytics.Threats.HighRisk > 0 {
					color.New(color.FgRed).Printf("%d\n", analytics.Threats.HighRisk)
				} else {
					fmt.Printf("%d\n", analytics.Threats.HighRisk)
				}
				fmt.Printf("  Medium Risk: ")
				if analytics.Threats.MediumRisk > 0 {
					color.New(color.FgYellow).Printf("%d\n", analytics.Threats.MediumRisk)
				} else {
					fmt.Printf("%d\n", analytics.Threats.MediumRisk)
				}
				fmt.Printf("  Low Risk: %d\n", analytics.Threats.LowRisk)
				
				fmt.Printf("\nAnomalies:\n")
				fmt.Printf("  Detected: %d\n", analytics.Anomalies.Detected)
				fmt.Printf("  Investigated: %d\n", analytics.Anomalies.Investigated)
				fmt.Printf("  Resolved: %d\n", analytics.Anomalies.Resolved)
				
				fmt.Printf("\nCompliance:\n")
				fmt.Printf("  SOC 2 Score: %d%%\n", analytics.Compliance.SOC2Score)
				fmt.Printf("  ISO 27001 Score: %d%%\n", analytics.Compliance.ISO27001Score)
				fmt.Printf("  Last Assessment: %s\n", analytics.Compliance.LastAssessment)
				
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	return cmd
}

func newAnalyticsPerformanceCommand() *cobra.Command {
	var (
		startDate string
		endDate   string
		format    string
	)

	cmd := &cobra.Command{
		Use:   "performance",
		Short: "Get performance analytics",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			opts := &api.AnalyticsOptions{
				StartDate: startDate,
				EndDate:   endDate,
			}

			analytics, err := app.API.GetPerformanceAnalytics(ctx, opts)
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(analytics)
			default:
				color.New(color.FgCyan, color.Bold).Println("Performance Analytics")
				
				fmt.Printf("\nKey Metrics:\n")
				fmt.Printf("  Average Response Time: %.2f ms\n", analytics.AverageResponseTime)
				fmt.Printf("  Error Rate: %.2f%%\n", analytics.ErrorRate*100)
				fmt.Printf("  Requests/Second: %.2f\n", analytics.RequestsPerSecond)
				
				if len(analytics.Details) > 0 {
					fmt.Printf("\nAdditional Details:\n")
					for key, value := range analytics.Details {
						fmt.Printf("  %s: %v\n", key, value)
					}
				}
				
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&startDate, "start-date", "", "start date (ISO 8601)")
	cmd.Flags().StringVar(&endDate, "end-date", "", "end date (ISO 8601)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table|json)")
	return cmd
}

