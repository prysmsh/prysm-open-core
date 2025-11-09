package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

// DERP (Designated Encrypted Relay for Packets) Server
// Provides firewall-friendly relay for WireGuard mesh networking

type DERPServer struct {
	clients             map[string]*DERPClient
	clientsMu           sync.RWMutex
	routes              map[string]*Route
	routesMu            sync.RWMutex
	upgrader            websocket.Upgrader
	upnpMapping         *UPnPPortMapping
	backendURL          string
	backendToken        string
	controlToken        string
	httpClient          *http.Client
	connectionMu        sync.Mutex
	connections         map[string]int
	maxConnectionsPerIP int
	metricsMu           sync.RWMutex
	totalConnections    uint64
	messagesRelayed     uint64
	bytesTransferred    uint64
	startTime           time.Time
}

type DERPClient struct {
	ID             string
	Conn           *websocket.Conn
	PublicKey      [32]byte
	LastSeen       time.Time
	OrganizationID string
	ClusterID      string
	ClusterName    string
	Region         string
	RemoteIP       string
	Registered     bool
	send           chan DERPMessage
	closeOnce      sync.Once
}

func (c *DERPClient) Close() {
	c.closeOnce.Do(func() {
		close(c.send)
	})
}

type DERPMessage struct {
	Type      string          `json:"type"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Data      []byte          `json:"data"`
	Encrypted bool            `json:"encrypted"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type derpVerificationResponse struct {
	OrganizationID uint     `json:"organization_id"`
	ClusterID      *uint    `json:"cluster_id"`
	ClusterName    string   `json:"cluster_name"`
	Permissions    []string `json:"permissions"`
}

func (s *DERPServer) verifyAgentRegistration(agentToken, clusterID string) (*derpVerificationResponse, error) {
	if strings.TrimSpace(agentToken) == "" {
		return nil, fmt.Errorf("agent token is required")
	}
	if s.backendURL == "" {
		return nil, fmt.Errorf("backend API URL is not configured")
	}
	if s.backendToken == "" {
		return nil, fmt.Errorf("DERP server token is not configured")
	}
	if s.httpClient == nil {
		return nil, fmt.Errorf("DERP server HTTP client not initialized")
	}

	payload := map[string]string{
		"agent_token": agentToken,
	}
	if trimmed := strings.TrimSpace(clusterID); trimmed != "" {
		payload["cluster_id"] = trimmed
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode verification request: %w", err)
	}

	req, err := http.NewRequest("POST", s.backendURL+"/internal/derp/verify", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DERP-Token", s.backendToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verification request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verification failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var verification derpVerificationResponse
	if err := json.Unmarshal(responseBody, &verification); err != nil {
		return nil, fmt.Errorf("failed to parse verification response: %w", err)
	}

	return &verification, nil
}

// Route represents an active traffic route through the mesh
type Route struct {
	ID             string    `json:"id"`
	SourceClient   string    `json:"source_client"`
	TargetClient   string    `json:"target_client"`
	OrganizationID string    `json:"organization_id"`
	ExternalPort   int       `json:"external_port"`
	TargetPort     int       `json:"target_port"`
	Protocol       string    `json:"protocol"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

// RouteRequest represents a request to create a new route
type RouteRequest struct {
	Type           string `json:"type"`
	RouteID        string `json:"route_id"`
	TargetClient   string `json:"target_client"`
	OrganizationID string `json:"organization_id"`
	ExternalPort   int    `json:"external_port"`
	TargetPort     int    `json:"target_port"`
	Protocol       string `json:"protocol"`
}

// UPnP port mapping management
type UPnPPortMapping struct {
	client       *internetgateway2.WANIPConnection1
	externalPort int
	internalPort int
	protocol     string
	description  string
	mu           sync.Mutex
}

func NewDERPServer() *DERPServer {
	server := &DERPServer{
		clients: make(map[string]*DERPClient),
		routes:  make(map[string]*Route),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					// Non-browser clients (e.g., agents) won't send Origin
					return true
				}
				allowed := getAllowedOrigins()
				if len(allowed) == 1 && allowed[0] == "*" {
					return true
				}
				for _, a := range allowed {
					if origin == a {
						return true
					}
				}
				log.Printf("Rejected connection from origin: %s", origin)
				return false
			},
		},
		connections: make(map[string]int),
		startTime:   time.Now(),
	}

	server.backendURL = strings.TrimSpace(os.Getenv("BACKEND_API_URL"))
	if server.backendURL == "" {
		server.backendURL = "http://backend:8080/api/v1"
	}
	server.backendURL = strings.TrimSuffix(server.backendURL, "/")
	server.backendToken = strings.TrimSpace(os.Getenv("DERP_SERVER_TOKEN"))
	if server.backendToken == "" {
		log.Println("Warning: DERP_SERVER_TOKEN is not set; agent registrations will be rejected")
	}

	controlToken := strings.TrimSpace(os.Getenv("DERP_CONTROL_TOKEN"))
	if controlToken == "" {
		controlToken = server.backendToken
	}
	if controlToken == "" {
		log.Println("Warning: DERP_CONTROL_TOKEN is not set; REST control endpoints will reject requests")
	}
	server.controlToken = controlToken

	server.httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	maxConns := 8
	if val := strings.TrimSpace(os.Getenv("DERP_MAX_CONNECTIONS_PER_IP")); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			maxConns = parsed
		}
	}
	server.maxConnectionsPerIP = maxConns

	// Initialize UPnP port mapping
	upnpMapping, err := initializeUPnP()
	if err != nil {
		log.Printf("UPnP initialization failed: %v", err)
	} else {
		server.upnpMapping = upnpMapping
		log.Println("UPnP port mapping initialized successfully")
	}

	return server
}

func (s *DERPServer) authorizeHTTPRequest(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(s.controlToken) == "" {
		http.Error(w, "DERP control token not configured", http.StatusServiceUnavailable)
		return false
	}

	headerToken := strings.TrimSpace(r.Header.Get("X-DERP-Token"))
	if headerToken == "" {
		http.Error(w, "Missing DERP authentication token", http.StatusUnauthorized)
		return false
	}

	if subtle.ConstantTimeCompare([]byte(headerToken), []byte(s.controlToken)) != 1 {
		http.Error(w, "Invalid DERP authentication token", http.StatusUnauthorized)
		return false
	}

	return true
}

func (s *DERPServer) reserveConnection(ip string) bool {
	if s.maxConnectionsPerIP <= 0 {
		return true
	}

	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	current := s.connections[ip]
	if current >= s.maxConnectionsPerIP {
		return false
	}

	s.connections[ip] = current + 1
	return true
}

func (s *DERPServer) releaseConnection(ip string) {
	if s.maxConnectionsPerIP <= 0 {
		return
	}

	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if current, ok := s.connections[ip]; ok {
		if current <= 1 {
			delete(s.connections, ip)
		} else {
			s.connections[ip] = current - 1
		}
	}
}

func (s *DERPServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	reserved := false
	if s.maxConnectionsPerIP > 0 {
		if !s.reserveConnection(remoteIP) {
			http.Error(w, "Too many connections from this IP", http.StatusTooManyRequests)
			return
		}
		reserved = true
	}
	defer func() {
		if reserved {
			s.releaseConnection(remoteIP)
		}
	}()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	clientID := generateClientID()

	client := &DERPClient{
		ID:         clientID,
		Conn:       conn,
		LastSeen:   time.Now(),
		Registered: false,
		RemoteIP:   remoteIP,
		send:       make(chan DERPMessage, 256),
	}

	s.clientsMu.Lock()
	s.clients[clientID] = client
	s.clientsMu.Unlock()

	s.metricsMu.Lock()
	s.totalConnections++
	s.metricsMu.Unlock()

	const maxMessageSize = 1 << 20
	const (
		writeWait  = 10 * time.Second
		pongWait   = 60 * time.Second
		pingPeriod = pongWait * 9 / 10
	)
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	go s.writePump(client, writeWait, pingPeriod)

	welcome := DERPMessage{
		Type: "welcome",
		From: "server",
		To:   clientID,
		Data: []byte(fmt.Sprintf(`{"client_id":"%s","server_time":"%s"}`,
			clientID, time.Now().Format(time.RFC3339))),
	}
	s.enqueue(client, welcome)

	for {
		var msg DERPMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("Client %s disconnected: %v", clientID, err)
			break
		}

		client.LastSeen = time.Now()
		if !client.Registered && msg.Type != "register" && msg.Type != "heartbeat" {
			s.sendError(client, "registration_required", "client must register before sending messages")
			continue
		}
		s.handleMessage(client, &msg)
	}

	client.Close()
	s.clientsMu.Lock()
	delete(s.clients, clientID)
	s.clientsMu.Unlock()
}

func (s *DERPServer) handleMessage(sender *DERPClient, msg *DERPMessage) {
	switch msg.Type {
	case "register":
		s.handleRegistration(sender, msg)
	case "relay":
		s.handleRelay(sender, msg)
	case "heartbeat":
		s.handleHeartbeat(sender, msg)
	case "discovery":
		s.handleDiscovery(sender, msg)
	case "route_request":
		s.handleRouteRequest(sender, msg)
	case "route_response":
		s.handleRouteResponse(sender, msg)
	case "traffic_data":
		s.handleTrafficData(sender, msg)
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

func (s *DERPServer) handleRegistration(client *DERPClient, msg *DERPMessage) {
	var regData struct {
		PublicKey      string `json:"public_key"`
		ClusterID      string `json:"cluster_id"`
		Region         string `json:"region"`
		OrganizationID string `json:"organization_id"`
		AgentToken     string `json:"agent_token"`
	}

	if err := json.Unmarshal(msg.Data, &regData); err != nil {
		log.Printf("Invalid registration data: %v", err)
		s.sendError(client, "invalid_registration", "malformed registration payload")
		_ = client.Conn.Close()
		return
	}

	if strings.TrimSpace(regData.AgentToken) == "" {
		log.Printf("Registration rejected for client %s: missing agent_token", client.ID)
		s.sendError(client, "invalid_registration", "agent_token is required")
		_ = client.Conn.Close()
		return
	}

	verification, err := s.verifyAgentRegistration(regData.AgentToken, regData.ClusterID)
	if err != nil {
		log.Printf("Registration rejected for client %s: token verification failed: %v", client.ID, err)
		s.sendError(client, "authentication_failed", "agent token verification failed")
		_ = client.Conn.Close()
		return
	}

	// Store client metadata
	if pk, err := decodePublicKey(regData.PublicKey); err == nil {
		client.PublicKey = pk
	} else {
		log.Printf("Invalid public key for client %s: %v", client.ID, err)
	}
	client.OrganizationID = strconv.FormatUint(uint64(verification.OrganizationID), 10)
	if verification.ClusterID == nil {
		log.Printf("Registration rejected for client %s: verification response missing cluster binding", client.ID)
		s.sendError(client, "authentication_failed", "agent token is not bound to a cluster")
		_ = client.Conn.Close()
		return
	}
	client.ClusterID = strconv.FormatUint(uint64(*verification.ClusterID), 10)
	client.ClusterName = verification.ClusterName
	client.Region = regData.Region
	client.Registered = true

	// Send registration confirmation
	response := DERPMessage{
		Type: "registered",
		From: "server",
		To:   client.ID,
		Data: []byte(fmt.Sprintf(`{"status":"success","client_id":"%s"}`, client.ID)),
	}
	s.enqueue(client, response)

	log.Printf("Client registered: %s (cluster: %s - %s, region: %s)",
		client.ID, client.ClusterID, client.ClusterName, client.Region)
}

func (s *DERPServer) handleRelay(sender *DERPClient, msg *DERPMessage) {
	s.clientsMu.RLock()
	target, exists := s.clients[msg.To]
	s.clientsMu.RUnlock()

	if !exists {
		s.sendError(sender, "target_not_found", fmt.Sprintf("target '%s' is not connected", msg.To))
		return
	}

	if sender.OrganizationID == "" || target.OrganizationID == "" || sender.OrganizationID != target.OrganizationID {
		s.sendError(sender, "forbidden", "cross-organization relay is not permitted")
		return
	}

	// Forward message to target
	relayMsg := DERPMessage{
		Type:      "message",
		From:      sender.ID,
		To:        target.ID,
		Data:      msg.Data,
		Encrypted: msg.Encrypted,
		Metadata:  msg.Metadata,
	}
	s.enqueue(target, relayMsg)
	s.recordTraffic(len(msg.Data))
}

func (s *DERPServer) handleHeartbeat(client *DERPClient, msg *DERPMessage) {
	client.LastSeen = time.Now()

	// Send heartbeat response
	response := DERPMessage{
		Type: "heartbeat_ack",
		From: "server",
		To:   client.ID,
		Data: []byte(fmt.Sprintf(`{"timestamp":"%s"}`, time.Now().Format(time.RFC3339))),
	}
	s.enqueue(client, response)
}

func (s *DERPServer) handleDiscovery(client *DERPClient, msg *DERPMessage) {
	var discoveryReq struct {
		ClusterID string `json:"cluster_id"`
	}

	if err := json.Unmarshal(msg.Data, &discoveryReq); err != nil {
		return
	}

	// Find clients in the same cluster
	s.clientsMu.RLock()
	var peers []map[string]interface{}
	for _, c := range s.clients {
		if c.ClusterID == discoveryReq.ClusterID &&
			c.OrganizationID == client.OrganizationID &&
			c.ID != client.ID {
			peers = append(peers, map[string]interface{}{
				"client_id":       c.ID,
				"public_key":      c.PublicKey,
				"region":          c.Region,
				"organization_id": c.OrganizationID,
				"last_seen":       c.LastSeen,
			})
		}
	}
	s.clientsMu.RUnlock()

	response := DERPMessage{
		Type: "discovery_response",
		From: "server",
		To:   client.ID,
		Data: marshalJSON(map[string]interface{}{
			"peers": peers,
		}),
	}
	s.enqueue(client, response)
}

// Route management handlers
func (s *DERPServer) handleRouteRequest(client *DERPClient, msg *DERPMessage) {
	var routeReq RouteRequest
	if err := json.Unmarshal(msg.Data, &routeReq); err != nil {
		log.Printf("Failed to unmarshal route request: %v", err)
		return
	}

	// Validate request
	if strings.TrimSpace(routeReq.OrganizationID) == "" {
		s.sendError(client, "invalid_request", "organization_id is required")
		return
	}
	if client.OrganizationID == "" || client.OrganizationID != routeReq.OrganizationID {
		s.sendError(client, "forbidden", "route request organization mismatch")
		return
	}
	if routeReq.RouteID == "" {
		routeReq.RouteID = fmt.Sprintf("route_%d", time.Now().UnixNano())
	}
	if routeReq.ExternalPort <= 0 || routeReq.ExternalPort > 65535 || routeReq.TargetPort <= 0 || routeReq.TargetPort > 65535 {
		s.sendError(client, "invalid_port", "external_port and target_port must be 1-65535")
		return
	}
	proto := strings.ToUpper(routeReq.Protocol)
	if proto == "" {
		proto = "TCP"
	}
	if proto != "TCP" && proto != "UDP" {
		s.sendError(client, "invalid_protocol", "protocol must be TCP or UDP")
		return
	}

	// Create new route
	route := &Route{
		ID:             routeReq.RouteID,
		SourceClient:   client.ID,
		TargetClient:   routeReq.TargetClient,
		OrganizationID: routeReq.OrganizationID,
		ExternalPort:   routeReq.ExternalPort,
		TargetPort:     routeReq.TargetPort,
		Protocol:       proto,
		Status:         "pending",
		CreatedAt:      time.Now(),
	}

	// Store route
	s.routesMu.Lock()
	s.routes[route.ID] = route
	s.routesMu.Unlock()

	// Find target client
	s.clientsMu.RLock()
	targetClient, exists := s.clients[routeReq.TargetClient]
	s.clientsMu.RUnlock()

	if !exists {
		route.Status = "failed"
		log.Printf("Target client %s not found for route %s", routeReq.TargetClient, route.ID)
		s.sendError(client, "target_not_found", fmt.Sprintf("target '%s' is not connected", routeReq.TargetClient))
		return
	}
	if targetClient.OrganizationID != client.OrganizationID {
		route.Status = "failed"
		log.Printf("Route %s denied: org mismatch source=%s target=%s", route.ID, client.OrganizationID, targetClient.OrganizationID)
		s.sendError(client, "forbidden", "target client belongs to a different organization")
		return
	}

	// Forward route request to target client
	forwardMsg := DERPMessage{
		Type: "route_setup",
		From: client.ID,
		To:   targetClient.ID,
		Data: marshalJSON(map[string]interface{}{
			"route_id":        route.ID,
			"external_port":   route.ExternalPort,
			"target_port":     route.TargetPort,
			"protocol":        route.Protocol,
			"organization_id": route.OrganizationID,
		}),
	}

	s.enqueue(targetClient, forwardMsg)

	log.Printf("Route %s created: %s:%d -> %s:%d", route.ID, client.ID, route.ExternalPort, targetClient.ID, route.TargetPort)
}

func (s *DERPServer) handleRouteResponse(client *DERPClient, msg *DERPMessage) {
	var response struct {
		RouteID string `json:"route_id"`
		Status  string `json:"status"`
		Error   string `json:"error,omitempty"`
	}

	if err := json.Unmarshal(msg.Data, &response); err != nil {
		log.Printf("Failed to unmarshal route response: %v", err)
		return
	}

	// Update route status and enforce organization ownership
	s.routesMu.Lock()
	route, exists := s.routes[response.RouteID]
	if !exists {
		s.routesMu.Unlock()
		s.sendError(client, "unknown_route", fmt.Sprintf("route '%s' not found", response.RouteID))
		return
	}

	if client.OrganizationID == "" || client.OrganizationID != route.OrganizationID {
		s.routesMu.Unlock()
		s.sendError(client, "forbidden", "route response organization mismatch")
		return
	}

	route.Status = response.Status
	log.Printf("Route %s status updated to: %s", response.RouteID, response.Status)
	sourceClientID := route.SourceClient
	s.routesMu.Unlock()

	// Forward response to source client (same organization)
	s.clientsMu.RLock()
	sourceClient, ok := s.clients[sourceClientID]
	s.clientsMu.RUnlock()
	if !ok || sourceClient.OrganizationID != client.OrganizationID {
		s.sendError(client, "target_not_found", "source client unavailable for route response")
		return
	}

	responseMsg := DERPMessage{
		Type: "route_response",
		From: client.ID,
		To:   sourceClient.ID,
		Data: msg.Data,
	}
	s.enqueue(sourceClient, responseMsg)
}

func (s *DERPServer) handleTrafficData(sender *DERPClient, msg *DERPMessage) {
	// Handle traffic data routing between clients
	var trafficData struct {
		RouteID string `json:"route_id"`
		Data    []byte `json:"data"`
	}

	if err := json.Unmarshal(msg.Data, &trafficData); err != nil {
		log.Printf("Failed to unmarshal traffic data: %v", err)
		return
	}

	// Find the route and forward traffic
	s.routesMu.RLock()
	route, exists := s.routes[trafficData.RouteID]
	s.routesMu.RUnlock()

	if !exists {
		log.Printf("Route %s not found for traffic data", trafficData.RouteID)
		return
	}

	if sender.OrganizationID == "" || sender.OrganizationID != route.OrganizationID {
		s.sendError(sender, "forbidden", "traffic sender not authorized for this route")
		return
	}

	// Determine target client (opposite of sender)
	var targetClientID string
	if sender.ID == route.SourceClient {
		targetClientID = route.TargetClient
	} else if sender.ID == route.TargetClient {
		targetClientID = route.SourceClient
	} else {
		log.Printf("Traffic sender %s not authorized for route %s", sender.ID, route.ID)
		return
	}

	// Forward traffic to target
	s.clientsMu.RLock()
	targetClient, exists := s.clients[targetClientID]
	s.clientsMu.RUnlock()

	if !exists {
		log.Printf("Target client %s not found for traffic forwarding", targetClientID)
		return
	}
	if targetClient.OrganizationID != sender.OrganizationID {
		s.sendError(sender, "forbidden", "target client belongs to a different organization")
		return
	}

	forwardMsg := DERPMessage{
		Type: "traffic_data",
		From: sender.ID,
		To:   targetClient.ID,
		Data: msg.Data,
	}

	s.enqueue(targetClient, forwardMsg)
	s.recordTraffic(len(trafficData.Data))
}

// Cleanup disconnected clients
func (s *DERPServer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.clientsMu.Lock()
			now := time.Now()
			for id, client := range s.clients {
				if now.Sub(client.LastSeen) > 5*time.Minute { // Align with backend timeout
					_ = client.Conn.Close()
					client.Close()
					delete(s.clients, id)
					log.Printf("Cleaned up stale client: %s", id)
				}
			}
			s.clientsMu.Unlock()
		}
	}
}

func generateClientID() string {
	var bytes [16]byte
	rand.Read(bytes[:])
	return fmt.Sprintf("%x", bytes)
}

func marshalJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

func (s *DERPServer) recordTraffic(bytes int) {
	if bytes <= 0 {
		return
	}
	s.metricsMu.Lock()
	s.messagesRelayed++
	s.bytesTransferred += uint64(bytes)
	s.metricsMu.Unlock()
}

// Non-blocking enqueue to client's send channel
func (s *DERPServer) enqueue(c *DERPClient, msg DERPMessage) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Attempted to send to closed channel for client %s: %v", c.ID, r)
		}
	}()
	select {
	case c.send <- msg:
	default:
		// Channel full - drop message to avoid blocking server
		log.Printf("Send buffer full for client %s, dropping message of type %s", c.ID, msg.Type)
	}
}

// Sends a typed error back to a client
func (s *DERPServer) sendError(c *DERPClient, code, detail string) {
	errPayload := map[string]string{"error": code, "detail": detail}
	s.enqueue(c, DERPMessage{Type: "error", From: "server", To: c.ID, Data: marshalJSON(errPayload)})
}

// writePump manages outgoing messages and periodic pings
func (s *DERPServer) writePump(c *DERPClient, writeWait, pingPeriod time.Duration) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.Conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(writeWait))
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Channel closed
				return
			}
			if err := c.Conn.WriteJSON(msg); err != nil {
				log.Printf("Write to client %s failed: %v", c.ID, err)
				return
			}
		case <-ticker.C:
			_ = c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// HTTP handlers
func (s *DERPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeHTTPRequest(w, r) {
		return
	}

	s.clientsMu.RLock()
	clientCount := len(s.clients)
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "healthy",
		"client_count": clientCount,
		"server_time":  time.Now().Format(time.RFC3339),
		"service":      "derp-relay",
	})
}

func (s *DERPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeHTTPRequest(w, r) {
		return
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	metrics := map[string]interface{}{
		"total_clients":           len(s.clients),
		"clients_by_region":       make(map[string]int),
		"clients_by_cluster":      make(map[string]int),
		"clients_by_organization": make(map[string]int),
	}

	s.metricsMu.RLock()
	metrics["messages_relayed"] = s.messagesRelayed
	metrics["bytes_transferred"] = s.bytesTransferred
	metrics["total_connections"] = s.totalConnections
	metrics["uptime_seconds"] = int(time.Since(s.startTime).Seconds())
	s.metricsMu.RUnlock()
	metrics["last_updated"] = time.Now().UTC().Format(time.RFC3339)

	for _, client := range s.clients {
		if region := client.Region; region != "" {
			metrics["clients_by_region"].(map[string]int)[region]++
		}
		if cluster := client.ClusterID; cluster != "" {
			metrics["clients_by_cluster"].(map[string]int)[cluster]++
		}
		if org := client.OrganizationID; org != "" {
			metrics["clients_by_organization"].(map[string]int)[org]++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (s *DERPServer) handleUPnPInfo(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeHTTPRequest(w, r) {
		return
	}

	upnpInfo := map[string]interface{}{
		"upnp_enabled": s.upnpMapping != nil,
		"status":       "disabled",
	}

	if s.upnpMapping != nil {
		upnpInfo["status"] = "enabled"
		upnpInfo["external_port"] = s.upnpMapping.externalPort
		upnpInfo["internal_port"] = s.upnpMapping.internalPort
		upnpInfo["protocol"] = s.upnpMapping.protocol
		upnpInfo["description"] = s.upnpMapping.description

		// Try to get external IP
		if externalIP, err := s.upnpMapping.getExternalIP(); err == nil {
			upnpInfo["external_ip"] = externalIP
			upnpInfo["external_address"] = fmt.Sprintf("%s:%d", externalIP, s.upnpMapping.externalPort)
		} else {
			upnpInfo["external_ip_error"] = err.Error()
		}

		// Get local IP
		if localIP, err := getLocalIP(); err == nil {
			upnpInfo["local_ip"] = localIP
			upnpInfo["local_address"] = fmt.Sprintf("%s:%d", localIP, s.upnpMapping.internalPort)
		} else {
			upnpInfo["local_ip_error"] = err.Error()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(upnpInfo)
}

func (s *DERPServer) handleRouteAPI(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeHTTPRequest(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// List active routes, optionally scoped to an organization
		orgFilter := strings.TrimSpace(r.URL.Query().Get("organization_id"))
		s.routesMu.RLock()
		routes := make([]*Route, 0, len(s.routes))
		for _, route := range s.routes {
			if orgFilter != "" && route.OrganizationID != orgFilter {
				continue
			}
			routes = append(routes, route)
		}
		s.routesMu.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": routes,
			"count":  len(routes),
		})

	case "POST":
		// Create new route via HTTP API
		var routeReq RouteRequest
		if err := json.NewDecoder(r.Body).Decode(&routeReq); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(routeReq.OrganizationID) == "" {
			http.Error(w, "organization_id is required", http.StatusBadRequest)
			return
		}

		// Generate route ID if not provided
		if routeReq.RouteID == "" {
			routeReq.RouteID = fmt.Sprintf("route_%d", time.Now().Unix())
		}

		// For HTTP API, we assume the source client will connect later
		route := &Route{
			ID:             routeReq.RouteID,
			SourceClient:   "external", // Will be updated when client connects
			TargetClient:   routeReq.TargetClient,
			OrganizationID: routeReq.OrganizationID,
			ExternalPort:   routeReq.ExternalPort,
			TargetPort:     routeReq.TargetPort,
			Protocol:       routeReq.Protocol,
			Status:         "pending",
			CreatedAt:      time.Now(),
		}

		s.routesMu.Lock()
		s.routes[route.ID] = route
		s.routesMu.Unlock()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(route)

	case "DELETE":
		// Extract route ID from URL path
		path := r.URL.Path
		if path == "/routes" || path == "/routes/" {
			http.Error(w, "Route ID required", http.StatusBadRequest)
			return
		}

		routeID := path[len("/routes/"):]

		orgFilter := strings.TrimSpace(r.URL.Query().Get("organization_id"))

		s.routesMu.Lock()
		if existing, exists := s.routes[routeID]; exists {
			if orgFilter != "" && existing.OrganizationID != orgFilter {
				s.routesMu.Unlock()
				http.Error(w, "Route not found", http.StatusNotFound)
				return
			}
			delete(s.routes, routeID)
			s.routesMu.Unlock()

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"message":  "Route deleted successfully",
				"route_id": routeID,
			})
		} else {
			s.routesMu.Unlock()
			http.Error(w, "Route not found", http.StatusNotFound)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	server := NewDERPServer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown with UPnP cleanup
	defer func() {
		if server.upnpMapping != nil {
			if err := server.upnpMapping.cleanup(); err != nil {
				log.Printf("Failed to cleanup UPnP mapping: %v", err)
			}
		}
	}()

	// Start cleanup routine
	go server.cleanupLoop(ctx)

	// Setup HTTP routes
	http.HandleFunc("/derp", server.handleWebSocket)
	http.HandleFunc("/health", server.handleHealth)
	http.HandleFunc("/metrics", server.handleMetrics)
	http.HandleFunc("/upnp", server.handleUPnPInfo)
	http.HandleFunc("/routes", server.handleRouteAPI)
	http.HandleFunc("/routes/", server.handleRouteAPI)

	// Serve static files that look like a normal website (firewall evasion)
	http.Handle("/", http.FileServer(http.Dir("/app/static/")))

	log.Println("DERP relay server starting on :443 (HTTPS)")
	log.Printf("WebSocket endpoint: wss://%s/derp", getServerDomain())

	// In production, use proper TLS certificates
	// Use alternate port for testing since 443 is in use
	port := os.Getenv("DERP_PORT")
	if port == "" {
		port = "8443"
	}

	certPath := os.Getenv("CERT_PATH")
	if certPath == "" {
		certPath = "/app/certs/cert.pem"
	}

	keyPath := os.Getenv("KEY_PATH")
	if keyPath == "" {
		keyPath = "/app/certs/key.pem"
	}

	log.Printf("Starting DERP server on port %s", port)
	log.Printf("Using cert: %s, key: %s", certPath, keyPath)

	srv := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServeTLS(certPath, keyPath))
}

func getServerDomain() string {
	domain := os.Getenv("DERP_DOMAIN")
	if domain == "" {
		domain = "derp.kubeaccess.com"
	}
	return domain
}

func getAllowedOrigins() []string {
	raw := os.Getenv("DERP_ALLOWED_ORIGINS")
	if strings.TrimSpace(raw) == "" {
		// Secure defaults: production domains and common local dev ports
		return []string{
			"https://kubeaccess.com",
			"https://app.kubeaccess.com",
			"http://localhost:3000",
			"http://localhost:3003",
			"http://localhost:8080",
			"http://localhost:8083",
		}
	}
	// Allow "*" to mean any origin (not recommended for prod)
	if raw == "*" {
		return []string{"*"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

// UPnP functions for automatic port forwarding
func initializeUPnP() (*UPnPPortMapping, error) {
	log.Println("Discovering UPnP devices...")

	// Try multiple UPnP service types
	log.Println("Trying WANIPConnection1...")
	clients1, urls1, err1 := internetgateway2.NewWANIPConnection1Clients()
	log.Printf("WANIPConnection1: found %d clients, %d URLs, error: %v", len(clients1), len(urls1), err1)

	log.Println("Trying WANIPConnection2...")
	clients2, urls2, err2 := internetgateway2.NewWANIPConnection2Clients()
	log.Printf("WANIPConnection2: found %d clients, %d URLs, error: %v", len(clients2), len(urls2), err2)

	log.Println("Trying WANPPPConnection1...")
	clientsPPP1, urlsPPP1, err3 := internetgateway2.NewWANPPPConnection1Clients()
	log.Printf("WANPPPConnection1: found %d clients, %d URLs, error: %v", len(clientsPPP1), len(urlsPPP1), err3)

	// Use the first available client from any service type
	var client *internetgateway2.WANIPConnection1
	var serviceType string

	if len(clients1) > 0 {
		client = clients1[0]
		serviceType = "WANIPConnection1"
		log.Printf("Using WANIPConnection1 client: %v", urls1[0])
	} else if len(clients2) > 0 {
		// Note: WANIPConnection2 has the same interface as WANIPConnection1
		client = (*internetgateway2.WANIPConnection1)(clients2[0])
		serviceType = "WANIPConnection2"
		log.Printf("Using WANIPConnection2 client: %v", urls2[0])
	} else {
		return nil, fmt.Errorf("no UPnP devices found (tried WANIPConnection1, WANIPConnection2, WANPPPConnection1)")
	}

	// Get the port from environment or use default
	portStr := os.Getenv("DERP_PORT")
	if portStr == "" {
		portStr = "8443"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	mapping := &UPnPPortMapping{
		client:       client,
		externalPort: port,
		internalPort: port,
		protocol:     "TCP",
		description:  fmt.Sprintf("DERP Relay Server (%s)", serviceType),
	}

	// Get local IP address
	localIP, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP: %v", err)
	}

	log.Printf("Adding UPnP port mapping: %s:%d -> %s:%d",
		"0.0.0.0", mapping.externalPort, localIP, mapping.internalPort)

	// Add the port mapping
	err = client.AddPortMapping(
		"",                           // Remote host (empty for any)
		uint16(mapping.externalPort), // External port
		mapping.protocol,             // Protocol
		uint16(mapping.internalPort), // Internal port
		localIP,                      // Internal client IP
		true,                         // Enabled
		mapping.description,          // Description
		0,                            // Lease duration (0 = permanent)
	)

	if err != nil {
		return nil, fmt.Errorf("failed to add UPnP port mapping: %v", err)
	}

	log.Printf("UPnP port mapping added successfully for port %d", port)
	return mapping, nil
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func (u *UPnPPortMapping) cleanup() error {
	if u == nil || u.client == nil {
		return nil
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	log.Printf("Removing UPnP port mapping for port %d", u.externalPort)

	err := u.client.DeletePortMapping(
		"",                     // Remote host
		uint16(u.externalPort), // External port
		u.protocol,             // Protocol
	)

	if err != nil {
		return fmt.Errorf("failed to remove UPnP port mapping: %v", err)
	}

	log.Printf("UPnP port mapping removed successfully for port %d", u.externalPort)
	return nil
}

func (u *UPnPPortMapping) getExternalIP() (string, error) {
	if u == nil || u.client == nil {
		return "", fmt.Errorf("UPnP not initialized")
	}

	ip, err := u.client.GetExternalIPAddress()
	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %v", err)
	}

	return ip, nil
}

// decodePublicKey attempts to decode a 32-byte public key from common encodings
func decodePublicKey(s string) ([32]byte, error) {
	var out [32]byte
	str := strings.TrimSpace(s)
	if str == "" {
		return out, fmt.Errorf("empty public key")
	}
	// Try hex
	if len(str) == 64 {
		b, err := hex.DecodeString(str)
		if err == nil && len(b) == 32 {
			copy(out[:], b)
			return out, nil
		}
	}
	// Try base64 (std)
	if b, err := base64.StdEncoding.DecodeString(str); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out, nil
	}
	// Try base64url (no padding)
	if b, err := base64.RawURLEncoding.DecodeString(str); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out, nil
	}
	return out, fmt.Errorf("unsupported public key format")
}
