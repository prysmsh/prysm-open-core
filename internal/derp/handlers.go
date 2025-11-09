package derp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

var (
	derpUpgrader = websocket.Upgrader{
		ReadBufferSize:  64 << 10,
		WriteBufferSize: 64 << 10,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	wsBinaryCounter uint64
	derpStartTime   = time.Now()
)

// HandleGetDERPPeers returns all DERP peers
func HandleGetDERPPeers(c *gin.Context) {
	// DERP peers would come from the DERP server
	// For now, return placeholder
	c.JSON(http.StatusOK, gin.H{
		"peers": []interface{}{},
		"total": 0,
		"note":  "DERP peer information",
	})
}

// HandleGetDERPStatus returns DERP server status
func HandleGetDERPStatus(c *gin.Context) {
	stats, err := CollectMeshPeerStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"network_status":    stats.NetworkStatus(),
		"connected_clients": stats.activeConnections,
		"total_clients":     stats.totalPeers,
		"relays":            stats.relayCount,
		"uptime_seconds":    stats.UptimeSeconds(),
	})
}

// HandleGetDERPMetrics returns DERP metrics
func HandleGetDERPMetrics(c *gin.Context) {
	stats, err := CollectMeshPeerStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"bytes_transferred": stats.bytesTransferred,
		"messages_relayed":  stats.messagesRelayed,
		"avg_latency_ms":    stats.AverageLatency(),
		"uptime_seconds":    stats.UptimeSeconds(),
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	})
}

// HandleVerify handles DERP relay verification requests
func HandleVerify(c *gin.Context) {
	// For now, just return success
	c.JSON(http.StatusOK, gin.H{
		"status": "verified",
		"relay":  "active",
	})
}

// HandleTunnel upgrades a WebSocket connection and relays WireGuard packets over HTTP.
func HandleTunnel(c *gin.Context) {
	if !derpTunnelEnabled() {
		c.JSON(http.StatusNotFound, gin.H{"error": "derp tunnel disabled"})
		return
	}

	orgID := c.GetUint("organization_id")
	if orgID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing organization context"})
		return
	}
	if _, ok := c.Get("user_id"); !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
		return
	}

	deviceID := strings.TrimSpace(c.Query("device_id"))
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id query parameter is required"})
		return
	}

	relayName := strings.TrimSpace(c.Query("relay"))
	endpoint, relayMeta, err := resolveRelayEndpoint(orgID, relayName)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	conn, err := derpUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	udpConn, err := net.Dial("udp", endpoint)
	if err != nil {
		conn.WriteJSON(gin.H{"error": fmt.Sprintf("udp dial failed: %v", err)})
		conn.Close()
		return
	}

	readyPayload := gin.H{
		"type":            "ready",
		"endpoint":        endpoint,
		"relay":           relayMeta,
		"organization_id": orgID,
		"device_id":       deviceID,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	conn.WriteJSON(readyPayload)

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		errCh <- copyWebsocketToUDP(ctx, conn, udpConn)
	}()

	go func() {
		errCh <- copyUDPToWebsocket(ctx, udpConn, conn)
	}()

	select {
	case <-ctx.Done():
	case <-errCh:
	}

	udpConn.Close()
	conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "tunnel closed"))
	conn.Close()
}

func resolveRelayEndpoint(orgID uint, relayName string) (string, map[string]interface{}, error) {
	var relay models.WireguardRelay
	query := database.DB.Where("organization_id = ? OR organization_id IS NULL", orgID)
	if relayName != "" {
		query = query.Where("LOWER(name) = ?", strings.ToLower(relayName))
	}
	if err := query.Order("organization_id DESC").First(&relay).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil, fmt.Errorf("load relay: %w", err)
		}
	}

	endpoint := strings.TrimSpace(relay.Endpoint)
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("DERP_BRIDGE_ENDPOINT"))
	}
	if endpoint == "" {
		return "", nil, fmt.Errorf("no wireguard relay endpoint configured")
	}

	meta := map[string]interface{}{
		"name":   relay.Name,
		"region": relay.DERPRegion,
	}

	return endpoint, meta, nil
}

func derpTunnelEnabled() bool {
	val := strings.TrimSpace(os.Getenv("DERP_TUNNEL_ENABLED"))
	if val == "" {
		return true
	}
	return !strings.EqualFold(val, "false")
}

type MeshPeerStats struct {
	totalPeers        int
	connectedPeers    int
	activeConnections int
	bytesTransferred  float64
	messagesRelayed   float64
	latencySum        float64
	latencySamples    int
	relayCount        int
}

func (s *MeshPeerStats) UptimeSeconds() int64 {
	seconds := int64(time.Since(derpStartTime).Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *MeshPeerStats) AverageLatency() float64 {
	if s.latencySamples == 0 {
		return 0
	}
	return s.latencySum / float64(s.latencySamples)
}

func (s *MeshPeerStats) NetworkStatus() string {
	if s.totalPeers == 0 {
		return "initializing"
	}
	if s.connectedPeers == 0 {
		return "degraded"
	}
	if s.connectedPeers == s.totalPeers {
		return "healthy"
	}
	if s.connectedPeers >= (s.totalPeers/2)+1 {
		return "stable"
	}
	return "warning"
}

func CollectMeshPeerStats() (*MeshPeerStats, error) {
	stats := &MeshPeerStats{}

	var peers []models.MeshPeer
	if err := database.DB.Find(&peers).Error; err != nil {
		return nil, err
	}

	for _, peer := range peers {
		stats.totalPeers++
		if strings.EqualFold(peer.Status, "connected") || strings.EqualFold(peer.Status, "healthy") {
			stats.connectedPeers++
		}

		health := jsonMap(peer.LastHealth)
		stats.activeConnections += int(extractPositiveFloat(health, "active_connections", "connections", "connected_clients"))
		stats.bytesTransferred += extractPositiveFloat(health, "bytes_transferred", "bytes_total", "bytes", "byte_count")
		stats.messagesRelayed += extractPositiveFloat(health, "messages_relayed", "packets", "packets_relayed", "messages")

		if latency := extractPositiveFloat(health, "latency_ms", "latency"); latency > 0 {
			stats.latencySum += latency
			stats.latencySamples++
		}
	}

	var relayCount int64
	if err := database.DB.Model(&models.WireguardRelay{}).Count(&relayCount).Error; err == nil {
		stats.relayCount = int(relayCount)
	}

	return stats, nil
}

func jsonMap(data models.JSON) map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func extractPositiveFloat(data map[string]interface{}, keys ...string) float64 {
	if data == nil {
		return 0
	}
	for _, key := range keys {
		if val, ok := data[key]; ok {
			switch v := val.(type) {
			case float64:
				if v > 0 {
					return v
				}
			case float32:
				f := float64(v)
				if f > 0 {
					return f
				}
			case int:
				if v > 0 {
					return float64(v)
				}
			case int64:
				if v > 0 {
					return float64(v)
				}
			case string:
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && parsed > 0 {
					return parsed
				}
			}
		}
	}
	return 0
}

func copyWebsocketToUDP(ctx context.Context, ws *websocket.Conn, udp net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgType, payload, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		udp.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := udp.Write(payload); err != nil {
			return err
		}
		atomic.AddUint64(&wsBinaryCounter, 1)
	}
}

func copyUDPToWebsocket(ctx context.Context, udp net.Conn, ws *websocket.Conn) error {
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		udp.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := udp.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}

		ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			return err
		}
	}
}
