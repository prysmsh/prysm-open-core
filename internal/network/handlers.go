package network

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleRegisterMeshNode registers a node in the mesh network
func HandleRegisterMeshNode(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		NodeID    string                 `json:"node_id" binding:"required"`
		NodeType  string                 `json:"node_type"`
		PublicKey string                 `json:"public_key"`
		ClusterID *uint                  `json:"cluster_id"`
		Metadata  map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement mesh node registration
	c.JSON(http.StatusCreated, gin.H{
		"message":         "Mesh node registered (placeholder)",
		"node_id":         req.NodeID,
		"organization_id": orgID,
	})
}

// HandleListMeshNodes lists all mesh nodes
func HandleListMeshNodes(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var peers []models.MeshPeer
	if err := database.DB.Where("organization_id = ?", orgID).Find(&peers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch mesh nodes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes": peers,
		"total": len(peers),
	})
}

// HandleUpdateMeshNodeExit updates mesh node exit router settings
func HandleUpdateMeshNodeExit(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	nodeID := c.Param("id")

	var req struct {
		IsExitNode bool `json:"is_exit_node"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Update mesh node exit settings
	c.JSON(http.StatusOK, gin.H{
		"message":         "Exit node updated (placeholder)",
		"node_id":         nodeID,
		"is_exit_node":    req.IsExitNode,
		"organization_id": orgID,
	})
}

// HandleDisableMeshNodeExit disables exit router for a mesh node
func HandleDisableMeshNodeExit(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	nodeID := c.Param("id")

	// TODO: Disable exit node
	c.JSON(http.StatusOK, gin.H{
		"message":         "Exit node disabled (placeholder)",
		"node_id":         nodeID,
		"organization_id": orgID,
	})
}

// HandleGetMeshClients returns all mesh clients (dashboard integration)
func HandleGetMeshClients(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var peers []models.MeshPeer
	if err := database.DB.Where("organization_id = ?", orgID).Find(&peers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch mesh clients"})
		return
	}

	clusterNames := map[uint]string{}
	clusterIDs := make([]uint, 0)
	for _, peer := range peers {
		if peer.ClusterID != nil {
			clusterIDs = append(clusterIDs, *peer.ClusterID)
		}
	}
	if len(clusterIDs) > 0 {
		var clusters []models.Cluster
		if err := database.DB.Where("id IN ?", clusterIDs).Select("id", "name").Find(&clusters).Error; err == nil {
			for _, cluster := range clusters {
				clusterNames[cluster.ID] = cluster.Name
			}
		}
	}

	now := time.Now().UTC()
	clients := make([]gin.H, 0, len(peers))
	for _, peer := range peers {
		status := normalizeMeshStatus(peer.Status, peer.LastPing)
		clusterName := ""
		if peer.ClusterID != nil {
			clusterName = clusterNames[*peer.ClusterID]
		}

		clients = append(clients, gin.H{
			"id":             peer.DeviceID,
			"type":           normalizePeerType(peer.PeerType),
			"name":           peer.DeviceID,
			"mesh_ip":        deriveMeshIP(peer),
			"docker_ip":      "",
			"region":         deriveRegion(peer),
			"status":         status,
			"last_seen":      deriveLastSeen(peer, now),
			"cluster_id":     peer.ClusterID,
			"cluster_name":   clusterName,
			"platform":       "",
			"version":        "",
			"capabilities":   capabilitiesToStrings(peer.Capabilities),
			"uptime_seconds": int(now.Sub(peer.CreatedAt).Seconds()),
			"cpu_usage":      nil,
			"memory_usage":   nil,
			"node_count":     nil,
			"pod_count":      nil,
		})
	}

	c.JSON(http.StatusOK, clients)
}

// HandleGetMeshStats returns mesh network statistics
func HandleGetMeshStats(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var peers []models.MeshPeer
	if err := database.DB.Where("organization_id = ?", orgID).Find(&peers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch mesh stats"})
		return
	}

	typeCounts := map[string]int{
		"agent":   0,
		"cli":     0,
		"gateway": 0,
	}
	activeClients := 0
	regions := map[string]struct{}{}
	now := time.Now().UTC()

	for _, peer := range peers {
		status := normalizeMeshStatus(peer.Status, peer.LastPing)
		if status == "connected" {
			activeClients++
		}

		ptype := normalizePeerType(peer.PeerType)
		if _, exists := typeCounts[ptype]; exists {
			typeCounts[ptype]++
		} else {
			typeCounts[ptype] = 1
		}

		for _, region := range peer.ExitRegions.ToSlice() {
			region = strings.TrimSpace(region)
			if region != "" {
				regions[region] = struct{}{}
			}
		}
	}

	regionList := make([]string, 0, len(regions))
	for region := range regions {
		regionList = append(regionList, region)
	}
	sort.Strings(regionList)

	networkStatus := "healthy"
	if len(peers) == 0 {
		networkStatus = "healthy"
	} else if activeClients == 0 {
		networkStatus = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"total_clients":  len(peers),
		"active_clients": activeClients,
		"agents":         typeCounts["agent"],
		"cli_clients":    typeCounts["cli"],
		"gateways":       typeCounts["gateway"],
		"regions":        regionList,
		"network_status": networkStatus,
		"timestamp":      now,
	})
}

// HandleGetMeshTopology returns mesh network topology
func HandleGetMeshTopology(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var peers []models.MeshPeer
	if err := database.DB.Where("organization_id = ?", orgID).Find(&peers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch mesh topology"})
		return
	}

	// TODO: Build topology graph
	c.JSON(http.StatusOK, gin.H{
		"nodes": peers,
		"edges": []gin.H{},
		"total": len(peers),
	})
}

func normalizeMeshStatus(status string, lastPing *time.Time) string {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	case "connected", "ready", "online", "healthy":
		return "connected"
	case "connecting":
		return "connecting"
	case "disconnected", "offline", "error":
		return "disconnected"
	}
	if lastPing != nil && time.Since(*lastPing) < 2*time.Minute {
		return "connected"
	}
	if lastPing != nil && time.Since(*lastPing) < 10*time.Minute {
		return "connecting"
	}
	return "disconnected"
}

func normalizePeerType(peerType string) string {
	switch strings.ToLower(strings.TrimSpace(peerType)) {
	case "agent", "cluster", "worker":
		return "agent"
	case "cli", "client":
		return "cli"
	case "gateway", "exit":
		return "gateway"
	default:
		return "agent"
	}
}

func capabilitiesToStrings(raw models.JSON) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err == nil {
		out := make([]string, 0, len(obj))
		for key := range obj {
			out = append(out, key)
		}
		sort.Strings(out)
		return out
	}

	return []string{}
}

func deriveRegion(peer models.MeshPeer) string {
	if len(peer.ExitRegions) > 0 {
		return strings.TrimSpace(peer.ExitRegions[0])
	}
	return "global"
}

func deriveMeshIP(peer models.MeshPeer) string {
	if peer.LastHealth != nil {
		var payload map[string]interface{}
		if err := json.Unmarshal(peer.LastHealth, &payload); err == nil {
			if ip, ok := payload["mesh_ip"].(string); ok && ip != "" {
				return ip
			}
			if ip, ok := payload["ip"].(string); ok && ip != "" {
				return ip
			}
		}
	}
	return ""
}

func deriveLastSeen(peer models.MeshPeer, now time.Time) string {
	if peer.LastPing != nil {
		return peer.LastPing.UTC().Format(time.RFC3339)
	}
	if peer.LastSeen != nil {
		return peer.LastSeen.UTC().Format(time.RFC3339)
	}
	return now.UTC().Format(time.RFC3339)
}
