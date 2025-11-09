package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type derpManager struct {
	agent         *PrysmAgent
	servers       []string
	region        string
	clientID      string
	publicKey     string
	skipVerify    bool
	stateDir      string
	ifaceName     string
	connMu        sync.RWMutex
	conn          *websocket.Conn
	currentServer string
	writeMu       sync.Mutex
	nextIndex     int
}

type derpMessage struct {
	Type      string `json:"type"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Data      []byte `json:"data,omitempty"`
	Encrypted bool   `json:"encrypted,omitempty"`
	Metadata  []byte `json:"metadata,omitempty"`
}

func (a *PrysmAgent) startDERP(ctx context.Context) error {
	manager, err := newDERPManager(a)
	if err != nil {
		return err
	}

	a.derpManager = manager
	go manager.run(ctx)
	log.Printf("DERP connectivity enabled with %d relay candidate(s)", len(manager.servers))
	return nil
}

func newDERPManager(agent *PrysmAgent) (*derpManager, error) {
	if len(agent.derpServers) == 0 {
		return nil, fmt.Errorf("no DERP servers configured")
	}

	stateDir := strings.TrimSpace(getEnvOrDefault("WIREGUARD_STATE_DIR", "/var/lib/prysm-agent"))
	if stateDir == "" {
		stateDir = "/var/lib/prysm-agent"
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("ensure state directory: %w", err)
	}

	iface := strings.TrimSpace(getEnvOrDefault("WIREGUARD_INTERFACE", "wg-prysm"))
	privPath := filepath.Join(stateDir, iface+".key")
	pubPath := filepath.Join(stateDir, iface+".pub")
	_, pubKey, err := ensureKeyPair(privPath, pubPath)
	if err != nil {
		return nil, fmt.Errorf("ensure WireGuard keys: %w", err)
	}

	clientID, err := ensureDERPClientID(stateDir, agent.ClusterID)
	if err != nil {
		return nil, fmt.Errorf("ensure DERP client id: %w", err)
	}

	servers := make([]string, 0, len(agent.derpServers))
	for _, s := range agent.derpServers {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			servers = append(servers, trimmed)
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid DERP servers found after trimming")
	}

	return &derpManager{
		agent:      agent,
		servers:    servers,
		region:     agent.derpRegion,
		clientID:   clientID,
		publicKey:  pubKey,
		skipVerify: agent.derpSkipVerify,
		stateDir:   stateDir,
		ifaceName:  iface,
	}, nil
}

func (m *derpManager) run(ctx context.Context) {
	backoff := 5 * time.Second

	for {
		if ctx.Err() != nil {
			m.closeConnection()
			return
		}

		if err := m.connectAndServe(ctx); err != nil && ctx.Err() == nil {
			log.Printf("DERP connection error: %v", err)
		}

		select {
		case <-ctx.Done():
			m.closeConnection()
			return
		case <-time.After(backoff):
		}

		if backoff < 60*time.Second {
			backoff += 5 * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

func (m *derpManager) connectAndServe(ctx context.Context) error {
	var lastErr error

	for i := 0; i < len(m.servers); i++ {
		endpoint := m.nextEndpoint()
		if endpoint == "" {
			continue
		}

		if err := m.dialAndRun(ctx, endpoint); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("DERP dial attempt failed for %s: %v", endpoint, err)
			continue
		}

		// Successful run; reset backoff and continue loop to allow reconnection if needed
		return nil
	}

	if lastErr == nil {
		return fmt.Errorf("no DERP endpoints available")
	}
	return lastErr
}

func (m *derpManager) dialAndRun(ctx context.Context, endpoint string) error {
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: true,
	}

	if strings.HasPrefix(strings.ToLower(endpoint), "wss://") {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if m.skipVerify {
			// #nosec G402
			dialer.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	headers := http.Header{}
	headers.Set("User-Agent", "prysm-agent/derp")
	if m.agent.ClusterID != "" {
		headers.Set("X-Cluster-ID", m.agent.ClusterID)
	}
	if m.agent.AgentToken != "" {
		headers.Set("X-Agent-Token", m.agent.AgentToken)
	}

	conn, _, err := dialer.DialContext(ctx, endpoint, headers)
	if err != nil {
		return err
	}
	defer conn.Close()

	m.setConnection(conn, endpoint)
	defer m.clearConnection()

	defer func() {
		m.writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second))
		m.writeMu.Unlock()
	}()

	if err := m.sendRegister(conn); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	return m.serveConnection(ctx, conn)
}

func (m *derpManager) serveConnection(ctx context.Context, conn *websocket.Conn) error {
	log.Printf("DERP connected to %s as %s", m.currentServer, m.clientID)

	errCh := make(chan error, 1)
	registeredCh := make(chan struct{}, 1)

	go m.readLoop(conn, errCh, registeredCh)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case <-registeredCh:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("timeout waiting for DERP registration acknowledgement")
	}

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	discoveryTicker := time.NewTicker(5 * time.Minute)
	defer discoveryTicker.Stop()

	if err := m.sendDiscovery(conn); err != nil {
		log.Printf("DERP discovery request failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-heartbeatTicker.C:
			if err := m.sendHeartbeat(conn); err != nil {
				return err
			}
		case <-discoveryTicker.C:
			if err := m.sendDiscovery(conn); err != nil {
				log.Printf("DERP discovery refresh failed: %v", err)
			}
		}
	}
}

func (m *derpManager) readLoop(conn *websocket.Conn, errCh chan<- error, registeredCh chan<- struct{}) {
	for {
		var msg derpMessage
		if err := conn.ReadJSON(&msg); err != nil {
			errCh <- err
			return
		}

		if msg.Type == "registered" {
			select {
			case registeredCh <- struct{}{}:
			default:
			}
		}

		m.handleMessage(&msg)
	}
}

func (m *derpManager) handleMessage(msg *derpMessage) {
	switch msg.Type {
	case "welcome":
		log.Printf("DERP welcome: %s", strings.TrimSpace(string(msg.Data)))
	case "registered":
		log.Printf("DERP registration confirmed by %s", m.currentServer)
	case "heartbeat_ack":
		// No-op; successful heartbeat
	case "discovery_response":
		var payload struct {
			Peers []map[string]interface{} `json:"peers"`
		}
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Printf("DERP discovery response decode error: %v", err)
			return
		}
		log.Printf("DERP discovery: %d peer(s) available in cluster %s", len(payload.Peers), m.agent.ClusterID)
	case "error":
		log.Printf("DERP error from server: %s", strings.TrimSpace(string(msg.Data)))
	default:
		log.Printf("DERP message type=%s size=%d bytes", msg.Type, len(msg.Data))
	}
}

func (m *derpManager) sendRegister(conn *websocket.Conn) error {
	payload := map[string]string{
		"public_key":      m.publicKey,
		"cluster_id":      m.agent.ClusterID,
		"region":          m.region,
		"organization_id": fmt.Sprintf("%d", m.agent.OrganizationID),
		"agent_token":     m.agent.AgentToken,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "register",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) sendHeartbeat(conn *websocket.Conn) error {
	payload := map[string]string{
		"client_id": m.clientID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"region":    m.region,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "heartbeat",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) sendDiscovery(conn *websocket.Conn) error {
	clusterID := strings.TrimSpace(m.agent.ClusterID)
	if clusterID == "" {
		return nil
	}

	payload := map[string]string{
		"cluster_id": clusterID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "discovery",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) writeMessage(conn *websocket.Conn, msg derpMessage) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if conn == nil {
		return fmt.Errorf("DERP connection not established")
	}

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	if err := conn.WriteJSON(msg); err != nil {
		return err
	}

	return nil
}

func (m *derpManager) nextEndpoint() string {
	if len(m.servers) == 0 {
		return ""
	}

	idx := m.nextIndex % len(m.servers)
	m.nextIndex = (idx + 1) % len(m.servers)
	return m.servers[idx]
}

func (m *derpManager) setConnection(conn *websocket.Conn, endpoint string) {
	m.connMu.Lock()
	m.conn = conn
	m.currentServer = endpoint
	m.connMu.Unlock()
}

func (m *derpManager) clearConnection() {
	m.connMu.Lock()
	m.conn = nil
	m.currentServer = ""
	m.connMu.Unlock()
}

func (m *derpManager) closeConnection() {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.conn != nil {
		m.writeMu.Lock()
		_ = m.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second))
		m.writeMu.Unlock()
		_ = m.conn.Close()
		m.conn = nil
		m.currentServer = ""
	}
}

func ensureDERPClientID(stateDir, clusterID string) (string, error) {
	path := filepath.Join(stateDir, "derp-client.id")

	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}

	prefix := sanitizeIdentifier(clusterID)
	if prefix == "" {
		prefix = "agent"
	}

	var randomBytes [6]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}

	id := fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(randomBytes[:]))
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}

	return id, nil
}

func sanitizeIdentifier(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}

	var b strings.Builder
	lastDash := false
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == ' ':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	return out
}
