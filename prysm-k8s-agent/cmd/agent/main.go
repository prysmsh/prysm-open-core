package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	"prysm-agent/pkg/kubectl"
	"prysm-agent/pkg/logs"
	"prysm-agent/metrics"
	"prysm-agent/metrics/plugins"
)

// Prysm Agent - Reports cluster status to backend
type PrysmAgent struct {
	ClusterID      string
	clusterIDNum   uint64
	ClusterName    string
	AgentToken     string
	BackendURL     string
	HTTPClient     *http.Client
	LogCollector   *logs.LogCollector
	OrganizationID uint
	sinkSyncEvery  time.Duration
	overlayEnabled bool
	tunnelManager  *wireGuardManager
	logSinkEnabled bool
	derpManager    *derpManager
	derpServers    []string
	derpRegion     string
	derpSkipVerify bool
	Region         string

	kubeconfigPath   string
	clientset        *kubernetes.Clientset
	metricsClient    *metricsclient.Clientset
	discoveryConn    discovery.DiscoveryInterface
	lastTelemetry    time.Time
	metricsFramework *metrics.MetricsFramework
	metricsEnabled   bool

	// Zero-trust kubectl proxy on WireGuard interface
	kubectlProxy *kubectl.Proxy
}

type HeartbeatRequest struct {
	AgentToken     string `json:"agent_token"`
	Status         string `json:"status"`
	WireGuardIP    string `json:"wireguard_ip,omitempty"`     // Agent's WireGuard mesh IP
	WireGuardCIDR  string `json:"wireguard_cidr,omitempty"`   // Full CIDR allocation
	K8sAPIEndpoint string `json:"k8s_api_endpoint,omitempty"` // Internal K8s API for verification
}

func NewPrysmAgent() *PrysmAgent {
	// Parse organization ID from environment
	orgID, _ := strconv.ParseUint(getEnvOrDefault("ORGANIZATION_ID", "1"), 10, 32)
	kubeconfigPath := strings.TrimSpace(getEnvOrDefault("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml"))

	agent := &PrysmAgent{
		ClusterID:      getEnvOrDefault("CLUSTER_ID", ""),
		ClusterName:    getEnvOrDefault("CLUSTER_NAME", ""),
		AgentToken:     getEnvOrDefault("AGENT_TOKEN", ""),
		BackendURL:     getEnvOrDefault("BACKEND_URL", "http://kubeaccess-backend:8080"),
		OrganizationID: uint(orgID),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		sinkSyncEvery:  parseDuration(getEnvOrDefault("LOG_SINK_SYNC_INTERVAL", "10m")),
		overlayEnabled: getEnvOrDefault("ENABLE_WIREGUARD", "true") != "false",
		logSinkEnabled: getEnvOrDefault("ENABLE_LOGGING", "true") == "true",
		metricsEnabled: getEnvOrDefault("ENABLE_METRICS", "true") == "true",
		Region:         getEnvOrDefault("REGION", getEnvOrDefault("DERP_REGION", "")),
		kubeconfigPath: kubeconfigPath,
	}

	derpServers := strings.TrimSpace(getEnvOrDefault("DERP_SERVERS", ""))
	if derpServers == "" {
		derpServers = strings.TrimSpace(getEnvOrDefault("DERP_SERVER", ""))
	}
	if derpServers != "" {
		agent.derpServers = parseStringSlice(derpServers)
	}
	agent.derpRegion = getEnvOrDefault("DERP_REGION", getEnvOrDefault("REGION", ""))
	agent.derpSkipVerify = strings.EqualFold(getEnvOrDefault("DERP_SKIP_TLS_VERIFY", "false"), "true")

	if clusterNum, err := strconv.ParseUint(agent.ClusterID, 10, 64); err == nil {
		agent.clusterIDNum = clusterNum
	} else {
		log.Printf("Warning: unable to parse cluster ID %s: %v", agent.ClusterID, err)
	}

	// Initialize log collector if logging is enabled
	if agent.logSinkEnabled {
		resolvedIngestionURL := strings.TrimSpace(getEnvOrDefault("LOG_INGESTION_URL", ""))
		if resolvedIngestionURL == "" {
			resolvedIngestionURL = deriveDefaultIngestionURL(agent.BackendURL)
			log.Printf("LOG_INGESTION_URL not set, using derived ingestion endpoint: %s", resolvedIngestionURL)
		}

		logConfig := &logs.Config{
			AgentID:        getEnvOrDefault("AGENT_ID", agent.ClusterID+"-agent"),
			AgentToken:     agent.AgentToken,
			ClusterID:      agent.ClusterID,
			OrganizationID: agent.OrganizationID,
			IngestionURL:   resolvedIngestionURL,
			PrivateLinkURL: getEnvOrDefault("LOG_PRIVATE_LINK_URL", ""),
			PrivateLinkKey: getEnvOrDefault("LOG_PRIVATE_LINK_KEY", ""),
			UsePrivateLink: getEnvOrDefault("USE_PRIVATE_LINK", "false") == "true",
			DERPRegion:     getEnvOrDefault("DERP_REGION", ""),

			// Collection settings
			BatchSize:          parseInt(getEnvOrDefault("LOG_BATCH_SIZE", "100")),
			BatchTimeout:       parseDuration(getEnvOrDefault("LOG_BATCH_TIMEOUT", "30s")),
			CollectionInterval: parseDuration(getEnvOrDefault("LOG_COLLECTION_INTERVAL", "30s")),
			MaxRetries:         parseInt(getEnvOrDefault("LOG_MAX_RETRIES", "3")),
			MaxMessageSize:     parseInt(getEnvOrDefault("LOG_MAX_MESSAGE_SIZE", "32768")),

			// Log sources
			EnabledSources:    parseLogSources(getEnvOrDefault("LOG_SOURCES", "pod,event,system")),
			ExcludeNamespaces: parseStringSlice(getEnvOrDefault("LOG_EXCLUDE_NAMESPACES", "kube-system,kube-public")),
			IncludeLevels:     parseLogLevels(getEnvOrDefault("LOG_LEVELS", "info,warn,error,fatal")),
		}

		agent.LogCollector = logs.NewLogCollector(logConfig)
	}

	return agent
}

func deriveDefaultIngestionURL(backendBase string) string {
	// When running inside the cluster we can rely on internal DNS.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "http://log-ingestion-service:8090"
	}

	base := strings.TrimSpace(backendBase)
	if base == "" {
		return "http://localhost:8080/api/v1/logs/ingest"
	}

	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		trimmed := strings.TrimSuffix(base, "/")
		return fmt.Sprintf("%s/api/v1/logs/ingest", trimmed)
	}

	sanitized := strings.TrimSuffix(parsed.Path, "/")
	var segments []string
	if sanitized != "" && sanitized != "/" {
		for _, segment := range strings.Split(strings.TrimPrefix(sanitized, "/"), "/") {
			if segment != "" {
				segments = append(segments, segment)
			}
		}
	}

	if len(segments) >= 2 && segments[len(segments)-2] == "api" && segments[len(segments)-1] == "v1" {
		segments = append(segments, "logs", "ingest")
	} else {
		segments = append(segments, "api", "v1", "logs", "ingest")
	}

	parsed.Path = "/" + strings.Join(segments, "/")
	return parsed.String()
}

func (a *PrysmAgent) Start(ctx context.Context) error {
	if a.ClusterID == "" {
		return fmt.Errorf("CLUSTER_ID environment variable is required")
	}
	if a.AgentToken == "" {
		return fmt.Errorf("AGENT_TOKEN environment variable is required")
	}

	log.Printf("Starting Prysm agent for cluster: %s", a.ClusterID)
	log.Printf("Backend URL: %s", a.BackendURL)
	log.Printf("Organization ID: %d", a.OrganizationID)

	// Send initial heartbeat
	if err := a.sendHeartbeat("connected"); err != nil {
		log.Printf("Failed to send initial heartbeat: %v", err)
	}

	// Start log collector if enabled
	if a.LogCollector != nil {
		if err := a.LogCollector.Start(ctx); err != nil {
			log.Printf("Failed to start log collector: %v", err)
		} else {
			log.Printf("Log collector started successfully")
		}
	}

	// Initialize and start metrics collection if enabled
	if a.metricsEnabled {
		if err := a.initializeMetrics(ctx); err != nil {
			log.Printf("Warning: failed to initialize metrics collection: %v", err)
		} else {
			log.Printf("Metrics collection started successfully")
		}
	}

	if err := a.initKubernetesClients(); err != nil {
		log.Printf("Warning: unable to initialize Kubernetes telemetry: %v", err)
	} else {
		go a.clusterTelemetryLoop(ctx)
	}

	// Start periodic heartbeat
	go a.heartbeatLoop(ctx)

	// Start health monitoring
	go a.healthMonitor(ctx)

	// Manage log sinks automatically
	go a.manageLogSinks(ctx)

	if a.overlayEnabled {
		a.tunnelManager = newWireGuardManager(a)
		go a.tunnelManager.run(ctx)

		// ZERO-TRUST: Start K8s API proxy on WireGuard interface
		// This allows CLI to access K8s API through mesh without direct exposure
		go a.startKubectlProxy(ctx)
	}

	if len(a.derpServers) > 0 {
		if err := a.startDERP(ctx); err != nil {
			log.Printf("Failed to start DERP connectivity: %v", err)
		}
	} else {
		log.Printf("DERP connectivity disabled; no DERP servers configured")
	}

	log.Printf("Prysm agent started successfully")
	return nil
}

func (a *PrysmAgent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Heartbeat loop stopping...")
			// Send disconnected status before shutdown
			a.sendHeartbeat("disconnected")
			return
		case <-ticker.C:
			if err := a.sendHeartbeat("connected"); err != nil {
				log.Printf("Heartbeat failed: %v", err)
			}
		}
	}
}

func (a *PrysmAgent) sendHeartbeat(status string) error {
	// Build heartbeat payload with WireGuard mesh information
	payload := HeartbeatRequest{
		AgentToken: a.AgentToken,
		Status:     status,
	}

	// Include WireGuard IP so backend can generate kubeconfigs with mesh IP
	if wgIP := a.getWireGuardIP(); wgIP != "" {
		payload.WireGuardIP = wgIP
		payload.WireGuardCIDR = wgIP + "/32" // Single IP CIDR
	}

	// Include K8s API endpoint for backend verification
	if k8sAPI := a.getK8sAPIAddress(); k8sAPI != "" {
		payload.K8sAPIEndpoint = k8sAPI
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/clusters/%s/ping", a.BackendURL, a.ClusterID)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with status %d", resp.StatusCode)
	}

	log.Printf("Heartbeat sent successfully - Status: %s", status)
	if payload.WireGuardIP != "" {
		log.Printf("   WireGuard mesh IP: %s (reported to backend)", payload.WireGuardIP)
	}
	return nil
}

func (a *PrysmAgent) healthMonitor(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check cluster health (kubectl cluster-info, etc.)
			health := a.checkClusterHealth()
			log.Printf("Cluster health check: %s", health)
		}
	}
}

func (a *PrysmAgent) checkClusterHealth() string {
	// Comprehensive cluster health checks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var healthStatus []string

	// Check API server connectivity
	if err := a.checkAPIServer(ctx); err != nil {
		healthStatus = append(healthStatus, fmt.Sprintf("API server: unhealthy (%v)", err))
	} else {
		healthStatus = append(healthStatus, "API server: healthy")
	}

	// Check node status
	if nodeStatus, err := a.checkNodeStatus(ctx); err != nil {
		healthStatus = append(healthStatus, fmt.Sprintf("Nodes: error (%v)", err))
	} else {
		healthStatus = append(healthStatus, fmt.Sprintf("Nodes: %s", nodeStatus))
	}

	// Check critical system pods
	if podStatus, err := a.checkSystemPods(ctx); err != nil {
		healthStatus = append(healthStatus, fmt.Sprintf("System pods: error (%v)", err))
	} else {
		healthStatus = append(healthStatus, fmt.Sprintf("System pods: %s", podStatus))
	}

	// Return overall health summary
	if len(healthStatus) > 0 {
		return strings.Join(healthStatus, "; ")
	}
	return "healthy"
}

func (a *PrysmAgent) checkAPIServer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "kubectl", "cluster-info", "--request-timeout=10s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl cluster-info failed: %v, output: %s", err, output)
	}
	return nil
}

func (a *PrysmAgent) checkNodeStatus(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "--no-headers", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl get nodes failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	readyNodes := 0
	totalNodes := len(lines)

	for _, line := range lines {
		if strings.Contains(line, "Ready") {
			readyNodes++
		}
	}

	return fmt.Sprintf("%d/%d ready", readyNodes, totalNodes), nil
}

func (a *PrysmAgent) checkSystemPods(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", "kube-system", "--no-headers", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl get pods failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	runningPods := 0
	totalPods := len(lines)

	for _, line := range lines {
		if strings.Contains(line, "Running") {
			runningPods++
		}
	}

	return fmt.Sprintf("%d/%d running", runningPods, totalPods), nil
}

func (a *PrysmAgent) Stop() error {
	log.Println("Stopping Prysm agent...")

	// Stop log collector if running
	if a.LogCollector != nil {
		if err := a.LogCollector.Stop(); err != nil {
			log.Printf("Failed to stop log collector: %v", err)
		} else {
			log.Printf("Log collector stopped successfully")
		}
	}

	// Stop metrics framework if running
	if a.metricsFramework != nil {
		if err := a.metricsFramework.Stop(); err != nil {
			log.Printf("Failed to stop metrics framework: %v", err)
		} else {
			log.Printf("Metrics framework stopped successfully")
		}
	}

	// Send disconnected status
	if err := a.sendHeartbeat("disconnected"); err != nil {
		log.Printf("Failed to send disconnect status: %v", err)
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Helper functions for parsing configuration values

func parseInt(s string) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return 0
}

func parseDuration(s string) time.Duration {
	if val, err := time.ParseDuration(s); err == nil {
		return val
	}
	return 30 * time.Second
}

func parseFloat(s string) float64 {
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return val
	}
	return 0.0
}

func parseLogSources(s string) []logs.LogSource {
	var sources []logs.LogSource
	for _, source := range strings.Split(s, ",") {
		source = strings.TrimSpace(source)
		switch source {
		case "pod":
			sources = append(sources, logs.LogSourcePod)
		case "event":
			sources = append(sources, logs.LogSourceEvent)
		case "audit":
			sources = append(sources, logs.LogSourceAudit)
		case "system":
			sources = append(sources, logs.LogSourceSystem)
		case "ingress":
			sources = append(sources, logs.LogSourceIngress)
		case "network":
			sources = append(sources, logs.LogSourceNetwork)
		}
	}
	return sources
}

func parseLogLevels(s string) []logs.LogLevel {
	var levels []logs.LogLevel
	for _, level := range strings.Split(s, ",") {
		level = strings.TrimSpace(level)
		switch level {
		case "trace":
			levels = append(levels, logs.LogLevelTrace)
		case "debug":
			levels = append(levels, logs.LogLevelDebug)
		case "info":
			levels = append(levels, logs.LogLevelInfo)
		case "warn":
			levels = append(levels, logs.LogLevelWarn)
		case "error":
			levels = append(levels, logs.LogLevelError)
		case "fatal":
			levels = append(levels, logs.LogLevelFatal)
		}
	}
	return levels
}

type logSinkInfo struct {
	ID             uint       `json:"id"`
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	Mode           string     `json:"mode"`
	ClusterID      *uint      `json:"cluster_id"`
	IngestURL      string     `json:"ingest_url"`
	Status         string     `json:"status"`
	LastDeployedAt *time.Time `json:"last_deployed_at"`
	LastError      string     `json:"last_error"`
}

type logSinkListResponse struct {
	Sinks []logSinkInfo `json:"sinks"`
}

type logSinkManifestResponse struct {
	Sink      logSinkInfo       `json:"sink"`
	Token     string            `json:"token"`
	Manifest  string            `json:"manifest"`
	Manifests map[string]string `json:"manifests"`
}

type logSinkStatusUpdate struct {
	Status         string     `json:"status"`
	LastError      *string    `json:"last_error,omitempty"`
	LastDeployedAt *time.Time `json:"last_deployed_at,omitempty"`
}

type wireGuardPeerSpec struct {
	ClusterID   uint   `json:"cluster_id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	OverlayCIDR string `json:"overlay_cidr"`
	ListenPort  *int   `json:"listen_port"`
}

type wireGuardConfigResponse struct {
	ClusterID     uint                `json:"cluster_id"`
	Organization  uint                `json:"organization_id"`
	OverlayCIDR   string              `json:"overlay_cidr"`
	ListenPort    *int                `json:"listen_port"`
	Peers         []wireGuardPeerSpec `json:"peers"`
	DERPEndpoints []string            `json:"derp_endpoints"`
}

func (a *PrysmAgent) manageLogSinks(ctx context.Context) {
	if a.sinkSyncEvery <= 0 {
		a.sinkSyncEvery = 10 * time.Minute
	}

	// Run an initial sync immediately.
	a.syncLogSinks(ctx)

	ticker := time.NewTicker(a.sinkSyncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Log sink manager stopping...")
			return
		case <-ticker.C:
			a.syncLogSinks(ctx)
		}
	}
}

func (a *PrysmAgent) syncLogSinks(ctx context.Context) {
	sinks, err := a.fetchLogSinks(ctx)
	if err != nil {
		log.Printf("Log sink sync skipped: %v", err)
		return
	}

	for _, sink := range sinks {
		if strings.ToLower(sink.Mode) != "auto" {
			continue
		}

		if sink.ClusterID != nil && a.clusterIDNum != 0 && uint64(*sink.ClusterID) != a.clusterIDNum {
			continue
		}

		if strings.ToLower(sink.Status) == "active" {
			continue
		}

		manifestResp, err := a.fetchLogSinkManifest(ctx, sink.ID)
		if err != nil {
			log.Printf("Failed to fetch manifest for log sink %d: %v", sink.ID, err)
			a.reportLogSinkStatus(ctx, sink.ID, "error", err.Error())
			continue
		}

		manifest := manifestResp.Manifest
		if manifest == "" && len(manifestResp.Manifests) > 0 {
			if val, ok := manifestResp.Manifests[manifestResp.Sink.Type]; ok {
				manifest = val
			}
		}

		if strings.TrimSpace(manifest) == "" {
			errMsg := "received empty manifest payload"
			log.Printf("Log sink %d manifest empty", sink.ID)
			a.reportLogSinkStatus(ctx, sink.ID, "error", errMsg)
			continue
		}

		if err := a.applyManifest(manifest); err != nil {
			log.Printf("Failed to apply manifest for log sink %d: %v", sink.ID, err)
			a.reportLogSinkStatus(ctx, sink.ID, "error", err.Error())
			continue
		}

		log.Printf("Log sink %s (%d) manifest applied successfully", sink.Name, sink.ID)
		a.reportLogSinkStatus(ctx, sink.ID, "active", "")
	}
}

func (a *PrysmAgent) fetchLogSinks(ctx context.Context) ([]logSinkInfo, error) {
	url := fmt.Sprintf("%s/api/v1/agent/logging/sinks", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", a.AgentToken)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d fetching log sinks: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload logSinkListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return payload.Sinks, nil
}

func (a *PrysmAgent) fetchLogSinkManifest(ctx context.Context, sinkID uint) (*logSinkManifestResponse, error) {
	url := fmt.Sprintf("%s/api/v1/agent/logging/sinks/%d/manifest", a.BackendURL, sinkID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", a.AgentToken)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d fetching manifest: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload logSinkManifestResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

func (a *PrysmAgent) applyManifest(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %v, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (a *PrysmAgent) reportLogSinkStatus(ctx context.Context, sinkID uint, status string, lastError string) {
	update := logSinkStatusUpdate{
		Status: status,
	}

	if status == "active" {
		now := time.Now().UTC()
		update.LastDeployedAt = &now
	} else if strings.TrimSpace(lastError) != "" {
		errMsg := truncateString(lastError, 512)
		update.LastError = &errMsg
	}

	payload, err := json.Marshal(update)
	if err != nil {
		log.Printf("Failed to marshal log sink status payload for sink %d: %v", sinkID, err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/agent/logging/sinks/%d/status", a.BackendURL, sinkID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create status request for sink %d: %v", sinkID, err)
		return
	}
	req.Header.Set("X-Agent-Token", a.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		log.Printf("Failed to update log sink %d status: %v", sinkID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("Backend rejected status update for sink %d (%s): %s", sinkID, status, strings.TrimSpace(string(body)))
	}
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// WireGuard management

type wireGuardManager struct {
	agent          *PrysmAgent
	ifaceName      string
	stateDir       string
	configPath     string
	privKeyPath    string
	pubKeyPath     string
	hashPath       string
	syncEvery      time.Duration
	mu             sync.Mutex
	lastConfigHash string
}

func newWireGuardManager(agent *PrysmAgent) *wireGuardManager {
	stateDir := strings.TrimSpace(getEnvOrDefault("WIREGUARD_STATE_DIR", "/var/lib/prysm-agent"))
	ifaceName := strings.TrimSpace(getEnvOrDefault("WIREGUARD_INTERFACE", "wg-prysm"))
	syncEvery := parseDuration(getEnvOrDefault("WIREGUARD_SYNC_INTERVAL", "2m"))
	configPath := filepath.Join(stateDir, ifaceName+".conf")
	return &wireGuardManager{
		agent:       agent,
		ifaceName:   ifaceName,
		stateDir:    stateDir,
		configPath:  configPath,
		privKeyPath: filepath.Join(stateDir, ifaceName+".key"),
		pubKeyPath:  filepath.Join(stateDir, ifaceName+".pub"),
		hashPath:    filepath.Join(stateDir, ifaceName+".hash"),
		syncEvery:   syncEvery,
	}
}

func (m *wireGuardManager) run(ctx context.Context) {
	if err := m.ensureStateDir(); err != nil {
		log.Printf("WireGuard disabled: failed to prepare state dir: %v", err)
		return
	}

	if err := m.syncOnce(ctx); err != nil {
		log.Printf("WireGuard initial sync failed: %v", err)
	}

	ticker := time.NewTicker(m.syncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.syncOnce(ctx); err != nil {
				log.Printf("WireGuard sync failed: %v", err)
			}
		}
	}
}

func (m *wireGuardManager) syncOnce(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	priv, pub, err := m.ensureKey(ctx)
	if err != nil {
		return fmt.Errorf("ensure key: %w", err)
	}

	cfg, err := m.fetchConfig(ctx)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	if err := m.applyConfig(ctx, cfg, priv); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}

	m.reportStatus(ctx, "wireguard config applied", nil)

	// Ensure backend has our public key
	if err := m.sendPublicKey(ctx, pub); err != nil {
		log.Printf("Failed to report WireGuard public key: %v", err)
	}

	return nil
}

func (m *wireGuardManager) ensureStateDir() error {
	return os.MkdirAll(m.stateDir, 0o700)
}

func (m *wireGuardManager) ensureKey(ctx context.Context) (string, string, error) {
	return ensureKeyPair(m.privKeyPath, m.pubKeyPath)
}

func (m *wireGuardManager) fetchConfig(ctx context.Context) (*wireGuardConfigResponse, error) {
	endpoint := fmt.Sprintf("%s/api/v1/agent/network/config?cluster_id=%s", strings.TrimRight(m.agent.BackendURL, "/"), url.QueryEscape(m.agent.ClusterID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", m.agent.AgentToken)

	resp, err := m.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var cfg wireGuardConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (m *wireGuardManager) applyConfig(ctx context.Context, cfg *wireGuardConfigResponse, privKey string) error {
	if cfg.OverlayCIDR == "" {
		return fmt.Errorf("overlay cidr missing in config")
	}

	listenPort := 0
	if cfg.ListenPort != nil {
		listenPort = *cfg.ListenPort
	}
	if override := strings.TrimSpace(os.Getenv("WIREGUARD_LISTEN_PORT")); override != "" {
		if port, err := strconv.Atoi(override); err == nil {
			listenPort = port
		}
	}

	peerSections := buildPeerSections(cfg, m.agent.ClusterID)
	configStr := renderWireGuardConfig(privKey, cfg.OverlayCIDR, listenPort, peerSections)

	configHash := hashString(configStr)
	if configHash == m.lastConfigHash {
		return nil
	}

	if existing, err := os.ReadFile(m.hashPath); err == nil {
		if strings.TrimSpace(string(existing)) == configHash {
			m.lastConfigHash = configHash
			return nil
		}
	}

	if err := os.WriteFile(m.configPath, []byte(configStr), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(m.hashPath, []byte(configHash), 0o600); err != nil {
		return err
	}

	if err := m.reloadInterface(); err != nil {
		return err
	}

	m.lastConfigHash = configHash
	return nil
}

func buildPeerSections(cfg *wireGuardConfigResponse, selfClusterID string) string {
	var sections []string
	for _, peer := range cfg.Peers {
		if peer.PublicKey == "" || peer.OverlayCIDR == "" {
			continue
		}
		if strconv.FormatUint(uint64(peer.ClusterID), 10) == selfClusterID {
			continue
		}

		builder := &strings.Builder{}
		builder.WriteString("[Peer]\n")
		builder.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		builder.WriteString(fmt.Sprintf("AllowedIPs = %s\n", peer.OverlayCIDR))
		builder.WriteString("PersistentKeepalive = 25\n")
		if len(cfg.DERPEndpoints) > 0 {
			builder.WriteString(fmt.Sprintf("# DERP relay candidates: %s\n", strings.Join(cfg.DERPEndpoints, ", ")))
		}
		sections = append(sections, builder.String())
	}

	return strings.Join(sections, "\n")
}

func renderWireGuardConfig(privKey, overlayCIDR string, listenPort int, peerSections string) string {
	builder := &strings.Builder{}
	builder.WriteString("[Interface]\n")
	builder.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))
	builder.WriteString(fmt.Sprintf("Address = %s\n", overlayCIDR))
	if listenPort > 0 {
		builder.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))
	}
	builder.WriteString("Table = off\n")
	builder.WriteString("PreUp = sysctl -q net.ipv4.ip_forward=1\n")
	builder.WriteString("PostUp = sysctl -q net.ipv4.ip_forward=1\n")

	if peerSections != "" {
		builder.WriteString("\n")
		builder.WriteString(peerSections)
	}
	return builder.String()
}

func (m *wireGuardManager) reloadInterface() error {
	bin := strings.TrimSpace(getEnvOrDefault("WIREGUARD_APPLY_COMMAND", "wg-quick"))
	if bin == "" {
		bin = "wg-quick"
	}

	down := exec.Command(bin, "down", m.configPath)
	down.Env = os.Environ()
	if output, err := down.CombinedOutput(); err != nil {
		if !strings.Contains(err.Error(), "No such file") {
			log.Printf("wg-quick down failed: %v (%s)", err, strings.TrimSpace(string(output)))
		}
	}

	up := exec.Command(bin, "up", m.configPath)
	up.Env = os.Environ()
	if output, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up failed: %v (%s)", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func (m *wireGuardManager) sendPublicKey(ctx context.Context, pub string) error {
	payload := map[string]string{"public_key": pub}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/api/v1/agent/network/key?cluster_id=%s", strings.TrimRight(m.agent.BackendURL, "/"), url.QueryEscape(m.agent.ClusterID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Agent-Token", m.agent.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.agent.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d updating public key", resp.StatusCode)
	}

	return nil
}

func (m *wireGuardManager) reportStatus(ctx context.Context, message string, latency map[string]float64) {
	payload := map[string]any{
		"message":    message,
		"latency_ms": latency,
	}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/api/v1/agent/network/status?cluster_id=%s", strings.TrimRight(m.agent.BackendURL, "/"), url.QueryEscape(m.agent.ClusterID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to create status request: %v", err)
		return
	}
	req.Header.Set("X-Agent-Token", m.agent.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("Failed to send wireguard status: %v", err)
		return
	}
	resp.Body.Close()
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ensureKeyPair(privPath, pubPath string) (string, string, error) {
	if data, err := os.ReadFile(privPath); err == nil {
		priv := strings.TrimSpace(string(data))
		if priv != "" {
			if pubData, err := os.ReadFile(pubPath); err == nil {
				return priv, strings.TrimSpace(string(pubData)), nil
			}
		}
	}

	priv, pub, err := generateWireGuardKeyPair()
	if err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privPath, []byte(priv+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil {
		return "", "", err
	}

	return priv, pub, nil
}

func generateWireGuardKeyPair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	privKey := base64.StdEncoding.EncodeToString(priv[:])
	pubKey := base64.StdEncoding.EncodeToString(pub[:])
	return privKey, pubKey, nil
}

func parseStringSlice(s string) []string {
	var result []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--health-check" {
		cmd := exec.Command("kubectl", "version", "--client")
		if err := cmd.Run(); err != nil {
			log.Fatalf("Health check failed: %v", err)
		}
		fmt.Println("Health check passed")
		return
	}

	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		override := strings.TrimSpace(os.Getenv("KUBECONFIG_APISERVER"))
		placeholderPresent, err := kubeconfigHasPlaceholder(kubeconfig)
		if err != nil {
			log.Printf("Warning: unable to inspect kubeconfig at %s: %v", kubeconfig, err)
		}
		if override == "" && placeholderPresent {
			override = inferAPIServerEndpoint()
		}
		if override != "" {
			if err := rewriteKubeconfigServer(kubeconfig, override); err != nil {
				log.Printf("Warning: failed to rewrite kubeconfig server to %s: %v", override, err)
			} else {
				log.Printf("Kubeconfig server endpoint set to %s", override)
			}
		} else if placeholderPresent {
			log.Printf("Warning: kubeconfig server placeholder detected but no replacement endpoint could be determined")
		}
	}

	agent := NewPrysmAgent()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		log.Fatal("Failed to start agent:", err)
	}

	// Handle graceful shutdown
	// In production, add signal handling
	select {
	case <-ctx.Done():
		break
	}

	agent.Stop()
}

func rewriteKubeconfigServer(path, override string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	contents := string(data)
	if strings.Contains(contents, override) {
		return nil
	}

	target := "server: https://0.0.0.0:6443"
	replacement := "server: " + override
	updated := ""

	if strings.Contains(contents, target) {
		updated = strings.Replace(contents, target, replacement, 1)
	} else {
		lines := strings.Split(contents, "\n")
		replaced := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "server:") && !replaced {
				prefix := line[:strings.Index(line, "server:")]
				lines[i] = prefix + "server: " + override
				replaced = true
			}
		}
		if !replaced {
			return nil
		}
		updated = strings.Join(lines, "\n")
	}

	if updated == contents {
		return nil
	}

	return os.WriteFile(path, []byte(updated), 0600)
}

// initializeMetrics sets up and starts the metrics collection framework
func (a *PrysmAgent) initializeMetrics(ctx context.Context) error {
	// Create metrics configuration
	config := &metrics.Config{
		CollectionInterval: parseDuration(getEnvOrDefault("METRICS_COLLECTION_INTERVAL", "30s")),
		BatchSize:          parseInt(getEnvOrDefault("METRICS_BATCH_SIZE", "100")),
		BufferSize:         parseInt(getEnvOrDefault("METRICS_BUFFER_SIZE", "1000")),
		EnableSampling:     getEnvOrDefault("METRICS_ENABLE_SAMPLING", "true") == "true",
		SampleRate:         parseFloat(getEnvOrDefault("METRICS_SAMPLE_RATE", "1.0")),
		MaxConcurrency:     parseInt(getEnvOrDefault("METRICS_MAX_CONCURRENCY", "5")),
		RetentionPeriod:    parseDuration(getEnvOrDefault("METRICS_RETENTION_PERIOD", "1h")),
		CompactionInterval: parseDuration(getEnvOrDefault("METRICS_COMPACTION_INTERVAL", "10m")),
		EnableSecurity:     getEnvOrDefault("METRICS_ENABLE_SECURITY", "true") == "true",
		ThreatDetection:    getEnvOrDefault("METRICS_THREAT_DETECTION", "true") == "true",
		AnomalyThreshold:   parseFloat(getEnvOrDefault("METRICS_ANOMALY_THRESHOLD", "2.0")),
		EnableRay:          getEnvOrDefault("METRICS_ENABLE_RAY", "false") == "true",
		PluginConfigs:      make(map[string]interface{}),
	}

	// Initialize metrics framework
	a.metricsFramework = metrics.NewFramework(config)

	// Register batch handler to send metrics to backend
	a.metricsFramework.RegisterBatchHandler(a.sendMetricsBatch)

	// Register Kubernetes plugin
	kubernetesPlugin := plugins.NewKubernetesPlugin(a.kubeconfigPath, a.ClusterID)
	if err := a.metricsFramework.RegisterPlugin(kubernetesPlugin); err != nil {
		return fmt.Errorf("failed to register Kubernetes plugin: %w", err)
	}

	// Register eBPF plugin if enabled
	if getEnvOrDefault("METRICS_ENABLE_EBPF", "false") == "true" {
		ebpfPlugin := plugins.NewEBPFPlugin("node-1", a.ClusterID)
		if err := a.metricsFramework.RegisterPlugin(ebpfPlugin); err != nil {
			log.Printf("Warning: failed to register eBPF plugin: %v", err)
		}
	}

	// Register DERP plugin if DERP is enabled
	if len(a.derpServers) > 0 {
		derpPlugin := plugins.NewDERPPlugin("derp-server-1", a.Region)
		if err := a.metricsFramework.RegisterPlugin(derpPlugin); err != nil {
			log.Printf("Warning: failed to register DERP plugin: %v", err)
		}
	}

	// Start the metrics framework
	if err := a.metricsFramework.Start(); err != nil {
		return fmt.Errorf("failed to start metrics framework: %w", err)
	}

	log.Printf("Metrics framework initialized with %d plugins", len(config.PluginConfigs))
	return nil
}

// sendMetricsBatch handles sending metric batches to the backend
func (a *PrysmAgent) sendMetricsBatch(ctx context.Context, metricsBatch []metrics.Metric) error {
	if len(metricsBatch) == 0 {
		return nil
	}

	// Convert metrics to the format expected by backend
	metricsData := make([]map[string]interface{}, len(metricsBatch))
	for i, metric := range metricsBatch {
		metricsData[i] = map[string]interface{}{
			"name":        metric.Name,
			"value":       metric.Value,
			"timestamp":   metric.Timestamp.Unix(),
			"labels":      metric.Labels,
			"metric_type": metric.Type,
			"cluster_id":  a.ClusterID,
			"node":        getEnvOrDefault("NODE_NAME", "unknown"),
		}
	}

	// Create the request payload
	payload := map[string]interface{}{
		"agent_token": a.AgentToken,
		"cluster_id":  a.ClusterID,
		"timestamp":   time.Now().Unix(),
		"metrics":     metricsData,
	}

	// Send to backend
	return a.sendMetricsToBackend(payload)
}

// sendMetricsToBackend sends metrics data to the backend API
func (a *PrysmAgent) sendMetricsToBackend(payload map[string]interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/clusters/%s/metrics", a.BackendURL, a.ClusterID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("metrics submission failed with status %d", resp.StatusCode)
	}

	log.Printf("Successfully sent %d metrics to backend", len(payload["metrics"].([]map[string]interface{})))
	return nil
}

// Helper function to parse integer environment variables
func parseIntHelper(s string) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return 0
}


const kubeconfigPlaceholder = "server: https://0.0.0.0:6443"

func kubeconfigHasPlaceholder(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(data), kubeconfigPlaceholder), nil
}

func inferAPIServerEndpoint() string {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))

	if host != "" {
		if port == "" {
			port = "443"
		}
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			// Host already includes scheme; append port if missing.
			if port != "" && !strings.Contains(host, ":") {
				return fmt.Sprintf("%s:%s", host, port)
			}
			return host
		}
		return fmt.Sprintf("https://%s:%s", host, port)
	}

	return "https://kubernetes.default.svc"
}

// startKubectlProxy starts the zero-trust kubectl proxy on the WireGuard interface
func (a *PrysmAgent) startKubectlProxy(ctx context.Context) {
	// Wait for WireGuard to be configured
	time.Sleep(5 * time.Second)

	// Get WireGuard IP from tunnel manager
	wireguardIP := a.getWireGuardIP()
	if wireguardIP == "" {
		log.Printf("⚠️  No WireGuard IP configured, kubectl proxy disabled")
		return
	}

	// Get K8s API server address
	k8sAPIAddr := a.getK8sAPIAddress()
	if k8sAPIAddr == "" {
		log.Printf("⚠️  Unable to determine K8s API address, kubectl proxy disabled")
		return
	}

	// Create and start proxy
	a.kubectlProxy = kubectl.NewProxy(wireguardIP, k8sAPIAddr)
	
	log.Printf("🚀 Starting zero-trust kubectl proxy...")
	log.Printf("   WireGuard IP: %s:6443", wireguardIP)
	log.Printf("   K8s API: %s", k8sAPIAddr)
	
	if err := a.kubectlProxy.Start(ctx); err != nil {
		log.Printf("❌ kubectl proxy failed: %v", err)
	}
}

// getWireGuardIP extracts the WireGuard IP from cluster configuration
func (a *PrysmAgent) getWireGuardIP() string {
	// Try environment variable first
	if wgIP := strings.TrimSpace(os.Getenv("WIREGUARD_IP")); wgIP != "" {
		return wgIP
	}

	// Try to read from WireGuard config file
	configPath := "/etc/wireguard/prysm0.conf"
	if data, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "Address") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					addr := strings.TrimSpace(parts[1])
					// Extract IP from CIDR (e.g., "100.64.0.10/32" -> "100.64.0.10")
					if idx := strings.Index(addr, "/"); idx > 0 {
						return addr[:idx]
					}
					return addr
				}
			}
		}
	}

	// Fallback: Try to get from interface
	cmd := exec.Command("ip", "-4", "addr", "show", "prysm0")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet ") {
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "inet" && i+1 < len(fields) {
						addr := fields[i+1]
						if idx := strings.Index(addr, "/"); idx > 0 {
							return addr[:idx]
						}
						return addr
					}
				}
			}
		}
	}

	log.Printf("⚠️  Unable to determine WireGuard IP automatically")
	return ""
}

// getK8sAPIAddress determines the K8s API server address
func (a *PrysmAgent) getK8sAPIAddress() string {
	// Try environment variable first
	if k8sAPI := strings.TrimSpace(os.Getenv("KUBERNETES_API_ADDRESS")); k8sAPI != "" {
		return k8sAPI
	}

	// Try to infer from environment
	endpoint := inferAPIServerEndpoint()
	if endpoint != "" {
		// Remove https:// prefix if present
		endpoint = strings.TrimPrefix(endpoint, "https://")
		endpoint = strings.TrimPrefix(endpoint, "http://")
		return endpoint
	}

	// Default to common K8s API address
	return "kubernetes.default.svc:443"
}
