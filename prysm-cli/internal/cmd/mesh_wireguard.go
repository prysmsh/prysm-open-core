package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/warp-run/prysm-cli/internal/api"
	"github.com/warp-run/prysm-cli/internal/daemon"
	"github.com/warp-run/prysm-cli/internal/derp"
	"github.com/warp-run/prysm-cli/internal/meshproxy"
)

func newMeshEnrollCommand() *cobra.Command {
	var (
		deviceID string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device for WireGuard access",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()

			if deviceID == "" {
				if host, err := os.Hostname(); err == nil {
					deviceID = host
				}
			}

			deviceID = strings.TrimSpace(deviceID)
			if deviceID == "" {
				return errors.New("device identifier is required")
			}

			keyDir := filepath.Join(app.Config.HomeDir, "wireguard")
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				return fmt.Errorf("prepare wireguard directory: %w", err)
			}

			keyPath := filepath.Join(keyDir, fmt.Sprintf("%s.key", sanitizeFileSegment(deviceID)))
			if !force {
				if _, err := os.Stat(keyPath); err == nil {
					return fmt.Errorf("private key already exists at %s (use --force to overwrite)", keyPath)
				}
			}

			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("generate private key: %w", err)
			}

			if err := os.WriteFile(keyPath, []byte(privateKey.String()), 0o600); err != nil {
				return fmt.Errorf("write private key: %w", err)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			req := api.RegisterWireguardDeviceRequest{
				DeviceID:  deviceID,
				PublicKey: privateKey.PublicKey().String(),
				Capabilities: map[string]interface{}{
					"platform": runtime.GOOS,
					"arch":     runtime.GOARCH,
					"version":  version,
				},
				Metadata: map[string]interface{}{
					"hostname": deviceID,
					"created":  time.Now().UTC().Format(time.RFC3339),
				},
			}

			resp, err := app.API.RegisterWireguardDevice(ctx, req)
			if err != nil {
				return err
			}

			renderWireguardEnrollment(resp, keyPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&deviceID, "device-id", "", "custom device identifier (default: system hostname)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing private key material if present")
	return cmd
}

func newMeshConfigCommand() *cobra.Command {
	var (
		deviceID   string
		writePath  string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Fetch and render WireGuard configuration for an enrolled device",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()

			if deviceID == "" {
				if host, err := os.Hostname(); err == nil {
					deviceID = host
				}
			}

			deviceID = strings.TrimSpace(deviceID)
			if deviceID == "" {
				return errors.New("device identifier is required")
			}

			keyPath := filepath.Join(app.Config.HomeDir, "wireguard", fmt.Sprintf("%s.key", sanitizeFileSegment(deviceID)))
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read private key: %w (run `prysm mesh enroll` first)", err)
			}
			privateKey := strings.TrimSpace(string(keyBytes))
			if privateKey == "" {
				return fmt.Errorf("private key file %s is empty", keyPath)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			resp, err := app.API.GetWireguardConfig(ctx, deviceID)
			if err != nil {
				return err
			}

			if outputJSON {
				data, err := json.MarshalIndent(resp, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}

			configStr := buildWireguardConfig(privateKey, resp)

			if writePath != "" {
				dest := writePath
				if !filepath.IsAbs(dest) {
					dest = filepath.Join(app.Config.HomeDir, dest)
				}
				if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
					return fmt.Errorf("prepare config directory: %w", err)
				}
				if err := os.WriteFile(dest, []byte(configStr), 0o600); err != nil {
					return fmt.Errorf("write config: %w", err)
				}
				color.New(color.FgGreen).Printf("✅ WireGuard config written to %s\n", dest)
			} else {
				fmt.Println(configStr)
			}

			if len(resp.Warnings) > 0 {
				color.New(color.FgYellow).Println("\nWarnings:")
				for _, w := range resp.Warnings {
					color.New(color.FgYellow).Printf("  • %s\n", w)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&deviceID, "device-id", "", "device identifier (default: system hostname)")
	cmd.Flags().StringVar(&writePath, "write-config", "", "write WireGuard config to this path (default: stdout)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "output raw JSON response instead of wg-quick config")
	return cmd
}

func newMeshProxyCommand() *cobra.Command {
	var (
		bindAddr   string
		relayName  string
		deviceID   string
		configPath string
		daemonMode bool
		logPath    string
	)

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Bridge WireGuard UDP packets over HTTPS DERP",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()
			sess, err := app.Sessions.Load()
			if err != nil {
				return err
			}
			if sess == nil {
				return errors.New("no active session; run `prysm login`")
			}

			devID := strings.TrimSpace(deviceID)
			if devID == "" {
				devID, err = derp.EnsureDeviceID(app.Config.HomeDir)
				if err != nil {
					return err
				}
			}

			if daemonMode && os.Getenv("PRYSM_PROXY_DAEMON") != "1" {
				logFile := strings.TrimSpace(logPath)
				if logFile == "" {
					logDir := filepath.Join(app.Config.HomeDir, "logs")
					if err := os.MkdirAll(logDir, 0o700); err != nil {
						return fmt.Errorf("prepare log directory: %w", err)
					}
					logFile = filepath.Join(logDir, "mesh-proxy.log")
				}
				return launchProxyDaemon(logFile)
			}

			tunnelURL, err := app.API.DERPTunnelURL(strings.TrimSpace(relayName), devID, uint(sess.Organization.ID))
			if err != nil {
				return err
			}

			headers := app.API.WebsocketHeaders()
			headers.Set("X-Session-ID", sess.SessionID)
			headers.Set("X-Org-ID", fmt.Sprintf("%d", sess.Organization.ID))
			headers.Set("X-Device-ID", devID)
			if headers.Get("Authorization") == "" {
				headers.Set("Authorization", "Bearer "+sess.Token)
			}

			if configPath != "" {
				updated, err := rewriteWireguardConfigEndpoint(configPath, bindAddr)
				if err != nil {
					return err
				}
				if updated {
					log.Printf("✅ Updated WireGuard config %s to use endpoint %s", configPath, bindAddr)
				} else {
					log.Printf("ℹ️  WireGuard config %s already points to %s", configPath, bindAddr)
				}
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			logger, closer, err := proxyLogger(logPath)
			if err != nil {
				return err
			}
			if closer != nil {
				defer closer.Close()
			}
			proxyCfg := meshproxy.Config{
				BindAddr:  bindAddr,
				TunnelURL: tunnelURL,
				Headers:   headers,
				DeviceID:  devID,
				Logger:    logger,
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- meshproxy.Run(ctx, proxyCfg)
			}()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sigCh)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case sig := <-sigCh:
				logger.Printf("Received %s, shutting down proxy", sig)
				cancel()
				return <-errCh
			case err := <-errCh:
				return err
			}
		},
	}

	cmd.Flags().StringVar(&bindAddr, "bind", "127.0.0.1:51821", "local UDP address to listen on for WireGuard traffic")
	cmd.Flags().StringVar(&relayName, "relay", "", "prefer a specific relay/region for the DERP tunnel")
	cmd.Flags().StringVar(&deviceID, "device-id", "", "override device identifier (default: host-based)")
	cmd.Flags().StringVar(&configPath, "config", "", "optional WireGuard config to rewrite Endpoint to the proxy address")
	cmd.Flags().BoolVar(&daemonMode, "daemon", false, "run proxy in the background and return immediately")
	cmd.Flags().StringVar(&logPath, "log-file", "", "write proxy logs to this file (default: stdout / ~/.prysm/logs/mesh-proxy.log in daemon mode)")

	return cmd
}

func rewriteWireguardConfigEndpoint(path, endpoint string) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read config: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	changed := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Endpoint") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		current := strings.TrimSpace(parts[1])
		if current == endpoint {
			continue
		}
		prefix := strings.TrimRight(parts[0], " 	")
		lines[i] = fmt.Sprintf("%s = %s", prefix, endpoint)
		changed = true
	}

	if !changed {
		return false, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	backup := path + ".bak"
	if err := os.WriteFile(backup, data, info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("write backup: %w", err)
	}

	updated := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(updated), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("write config: %w", err)
	}
	return true, nil
}

func proxyLogger(path string) (*log.Logger, *os.File, error) {
	daemonLog := strings.TrimSpace(path)
	if daemonLog == "" {
		daemonLog = strings.TrimSpace(os.Getenv("PRYSM_PROXY_LOG_FILE"))
	}

	if daemonLog == "" {
		return log.New(os.Stdout, "", 0), nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(daemonLog), 0o700); err != nil {
		return nil, nil, fmt.Errorf("prepare log directory: %w", err)
	}
	file, err := os.OpenFile(daemonLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file: %w", err)
	}
	return log.New(file, "", 0), file, nil
}

func launchProxyDaemon(logPath string) error {
	args := filterDaemonArgs(os.Args)
	cmd := exec.Command(args[0], args[1:]...)
	env := append(os.Environ(),
		"PRYSM_PROXY_DAEMON=1",
		"PRYSM_PROXY_LOG_FILE="+logPath,
	)
	cmd.Env = env

	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return fmt.Errorf("prepare log directory: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start proxy daemon: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release proxy daemon: %w", err)
	}
	fmt.Printf("✅ mesh proxy daemon started (pid %d). Logs: %s\n", cmd.Process.Pid, logPath)
	return nil
}

func filterDaemonArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	skipNext := false
	for i, arg := range argv {
		if i == 0 {
			out = append(out, arg)
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--daemon" {
			continue
		}
		if strings.HasPrefix(arg, "--daemon=") {
			continue
		}
		if arg == "--log-file" {
			out = append(out, arg)
			skipNext = true
			continue
		}
		out = append(out, arg)
	}
	return out
}
func renderWireguardEnrollment(resp *api.WireguardConfigResponse, keyPath string) {
	color.New(color.FgGreen).Println("✅ Device enrolled successfully")
	color.New(color.FgHiBlack).Printf("Private key stored at %s\n", keyPath)

	color.New(color.FgCyan).Printf("\nAssigned address: %s (%s)\n", resp.Config.Address, resp.Config.CIDR)
	if len(resp.Config.DNS) > 0 {
		color.New(color.FgCyan).Printf("DNS servers: %s\n", strings.Join(resp.Config.DNS, ", "))
	}
	color.New(color.FgCyan).Printf("Peers discovered: %d\n", len(resp.Peers))

	if len(resp.Warnings) > 0 {
		color.New(color.FgYellow).Println("\nWarnings:")
		for _, w := range resp.Warnings {
			color.New(color.FgYellow).Printf("  • %s\n", w)
		}
	}

	color.New(color.FgHiBlack).Println("\nNext steps:")
	color.New(color.FgHiBlack).Printf("  1. Generate a WireGuard config: prysm mesh config --device-id \"%s\" --write-config wg0.conf\n", resp.Device.DeviceID)
	color.New(color.FgHiBlack).Println("  2. Install the Prysm mesh helper (coming soon) or import wg0.conf into WireGuard.")
}

func buildWireguardConfig(privateKey string, resp *api.WireguardConfigResponse) string {
	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "Address = %s\n", resp.Config.Address)
	if len(resp.Config.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(resp.Config.DNS, ", "))
	}
	if resp.Config.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", resp.Config.MTU)
	}
	if resp.Config.PersistentKeepaliveSec > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", resp.Config.PersistentKeepaliveSec)
	}

	for _, peer := range resp.Peers {
		fmt.Fprintln(&b, "\n[Peer]")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", peer.Endpoint)
		}
		if len(peer.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
		}
		if peer.PersistentKeepaliveSecs > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.PersistentKeepaliveSecs)
		}
		if peer.DERPRegion != "" {
			fmt.Fprintf(&b, "# DERP Region: %s\n", peer.DERPRegion)
		}
	}

	return strings.TrimSpace(b.String())
}

func buildDaemonApplyConfig(privateKey string, resp *api.WireguardConfigResponse) daemon.ApplyConfigRequest {
	cfg := daemon.ApplyConfigRequest{
		Interface: daemon.InterfaceConfig{
			PrivateKey: privateKey,
			Address:    resp.Config.Address,
			DNS:        resp.Config.DNS,
			MTU:        resp.Config.MTU,
		},
	}

	for _, peer := range resp.Peers {
		cfg.Peers = append(cfg.Peers, daemon.PeerConfig{
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: peer.AllowedIPs,
			Keepalive:  peer.PersistentKeepaliveSecs,
		})
	}

	if len(resp.Warnings) > 0 {
		cfg.Warnings = append(cfg.Warnings, resp.Warnings...)
	}

	return cfg
}

func newMeshUpCommand() *cobra.Command {
	var (
		deviceID   string
		socketPath string
		applyOnly  bool
	)

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Apply the latest WireGuard config and start the mesh tunnel via prysm-meshd",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := MustApp()

			if deviceID == "" {
				if host, err := os.Hostname(); err == nil {
					deviceID = host
				}
			}

			deviceID = strings.TrimSpace(deviceID)
			if deviceID == "" {
				return errors.New("device identifier is required")
			}

			keyPath := filepath.Join(app.Config.HomeDir, "wireguard", fmt.Sprintf("%s.key", sanitizeFileSegment(deviceID)))
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read private key: %w (run `prysm mesh enroll` first)", err)
			}

			privateKey := strings.TrimSpace(string(keyBytes))
			if privateKey == "" {
				return fmt.Errorf("private key file %s is empty", keyPath)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			resp, err := app.API.GetWireguardConfig(ctx, deviceID)
			if err != nil {
				return err
			}

			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ensureCtx, ensureCancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer ensureCancel()
			if err := manager.Start(ensureCtx); err != nil {
				return fmt.Errorf("start prysm-meshd: %w", err)
			}

			client := daemon.NewClient(manager.Socket())
			applyReq := buildDaemonApplyConfig(privateKey, resp)

			if err := client.Apply(ctx, applyReq); err != nil {
				return fmt.Errorf("apply config: %w", err)
			}

			if len(applyReq.Warnings) > 0 {
				color.New(color.FgYellow).Println("Warnings:")
				for _, w := range applyReq.Warnings {
					color.New(color.FgYellow).Printf("  • %s\n", w)
				}
			}

			color.New(color.FgGreen).Println("✅ Configuration applied to prysm-meshd")

			if applyOnly {
				return nil
			}

			startCtx, startCancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer startCancel()
			if err := client.Start(startCtx); err != nil {
				return fmt.Errorf("start tunnel: %w", err)
			}

			color.New(color.FgGreen).Println("🚀 Mesh tunnel started")
			return nil
		},
	}

	cmd.Flags().StringVar(&deviceID, "device-id", "", "device identifier (default: system hostname)")
	cmd.Flags().StringVar(&socketPath, "socket", "", "path to the prysm-meshd Unix domain socket (default: Prysm home)")
	cmd.Flags().BoolVar(&applyOnly, "apply-only", false, "apply configuration but do not start the tunnel")
	return cmd
}

func newMeshDownCommand() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop the mesh tunnel via prysm-meshd",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			running, _, err := manager.IsRunning(cmd.Context())
			if err != nil {
				return err
			}
			if !running {
				color.New(color.FgYellow).Println("⚠️  prysm-meshd is not running")
				return nil
			}

			client := daemon.NewClient(manager.Socket())
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			if err := client.Stop(ctx); err != nil {
				return fmt.Errorf("stop tunnel: %w", err)
			}

			color.New(color.FgGreen).Println("🛑 Mesh tunnel stopped")
			return nil
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "path to the prysm-meshd Unix domain socket (default: Prysm home)")
	return cmd
}

func newMeshStatusCommand() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show runtime status reported by prysm-meshd",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := resolveMeshdManager(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			running, _, err := manager.IsRunning(ctx)
			if err != nil {
				return err
			}
			if !running {
				color.New(color.FgYellow).Println("⚠️  prysm-meshd is not running")
				color.New(color.FgHiBlack).Printf("Socket: %s\n", manager.Socket())
				return nil
			}

			client := daemon.NewClient(manager.Socket())
			status, err := client.Status(ctx)
			if err != nil {
				return fmt.Errorf("query status: %w", err)
			}

			if status.InterfaceUp {
				color.New(color.FgGreen).Println("✅ Mesh interface is up")
			} else {
				color.New(color.FgYellow).Println("⚠️  Mesh interface is down")
			}

			if !status.LastApply.IsZero() {
				color.New(color.FgHiBlack).Printf("Last apply: %s\n", status.LastApply.UTC().Format(time.RFC3339))
			}
			color.New(color.FgHiBlack).Printf("Peers: %d\n", status.PeerCount)

			if len(status.Peers) > 0 {
				fmt.Println()
				color.New(color.FgCyan).Println("Peers")
				for _, peer := range status.Peers {
					color.New(color.FgHiBlack).Printf("  %s\n", peer.PublicKey)
					if peer.Endpoint != "" {
						color.New(color.FgHiBlack).Printf("    Endpoint: %s\n", peer.Endpoint)
					}
					if peer.LastHandshake != "" {
						color.New(color.FgHiBlack).Printf("    Last handshake: %s\n", peer.LastHandshake)
					}
					color.New(color.FgHiBlack).Printf("    RX: %d bytes • TX: %d bytes\n", peer.BytesReceived, peer.BytesSent)
				}
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

	cmd.Flags().StringVar(&socketPath, "socket", "", "path to the prysm-meshd Unix domain socket (default: Prysm home)")
	return cmd
}

func sanitizeFileSegment(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "device"
	}
	input = strings.ToLower(input)
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", "..", "-", "@", "-", "#", "-", "%", "-")
	return replacer.Replace(input)
}
