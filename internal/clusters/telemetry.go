package clusters

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HandleClusterPing handles cluster ping requests
func HandleClusterPing(c *gin.Context) {
	// Get authenticated cluster from context (set by AgentAuth middleware)
	cluster, exists := c.Get("cluster")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cluster context not found"})
		return
	}

	clusterModel := cluster.(*models.Cluster)

	// Update last ping time and status
	now := time.Now()
	clusterModel.LastPing = &now
	clusterModel.Status = "connected"

	if err := database.DB.Save(&clusterModel).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster"})
		return
	}

	updateMeshPeerStatus(clusterModel.ID, "connected")

	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"timestamp":  now,
		"cluster_id": clusterModel.ID,
	})
}

// HandleClusterMetrics handles cluster metrics submissions
func HandleClusterMetrics(c *gin.Context) {
	// Get authenticated cluster from context
	cluster, exists := c.Get("cluster")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cluster context not found"})
		return
	}

	clusterModel := cluster.(*models.Cluster)

	var metricsPayload map[string]interface{}
	if err := c.ShouldBindJSON(&metricsPayload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metrics data"})
		return
	}

	now := time.Now()
	clusterModel.LastPing = &now

	updates := map[string]interface{}{
		"last_ping":        &now,
		"last_data_update": &now,
	}

	if len(metricsPayload) > 0 {
		if serialized, err := json.Marshal(metricsPayload); err == nil {
			updates["metrics"] = models.JSON(serialized)
		} else {
			log.Printf("Failed to serialize cluster %d metrics: %v", clusterModel.ID, err)
		}
	}

	if err := database.DB.Model(clusterModel).Updates(updates).Error; err != nil {
		log.Printf("Failed to persist cluster %d metrics: %v", clusterModel.ID, err)
	}

	updateMeshPeerStatus(clusterModel.ID, "connected")

	c.JSON(http.StatusAccepted, gin.H{
		"status":     "accepted",
		"cluster_id": clusterModel.ID,
		"timestamp":  now,
	})
}

// HandleClusterData handles cluster data submissions
func HandleClusterData(c *gin.Context) {
	// Get authenticated cluster from context
	cluster, exists := c.Get("cluster")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cluster context not found"})
		return
	}

	clusterModel := cluster.(*models.Cluster)

	var data map[string]interface{}
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data format"})
		return
	}

	now := time.Now()
	clusterModel.LastPing = &now

	updates := map[string]interface{}{
		"last_ping":        &now,
		"last_data_update": &now,
	}

	if clusterInfo, ok := data["cluster_info"]; ok {
		if payload, err := json.Marshal(clusterInfo); err == nil {
			updates["cluster_info"] = models.JSON(payload)
		}
	}
	if services, ok := data["services"]; ok {
		if payload, err := json.Marshal(services); err == nil {
			updates["services"] = models.JSON(payload)
		}
	}
	if metricsPayload, ok := data["metrics"]; ok {
		if payload, err := json.Marshal(metricsPayload); err == nil {
			updates["metrics"] = models.JSON(payload)
		}
	}

	if err := database.DB.Model(clusterModel).Updates(updates).Error; err != nil {
		log.Printf("Failed to persist cluster %d data update: %v", clusterModel.ID, err)
	}

	updateMeshPeerStatus(clusterModel.ID, "connected")

	c.JSON(http.StatusAccepted, gin.H{
		"status":     "accepted",
		"cluster_id": clusterModel.ID,
		"timestamp":  now,
	})
}

func updateMeshPeerStatus(clusterID uint, status string) {
	var meshPeer models.MeshPeer
	if err := database.DB.Where("cluster_id = ?", clusterID).First(&meshPeer).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load mesh peer for cluster %d: %v", clusterID, err)
		}
		return
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"status":    status,
		"last_ping": &now,
	}

	if err := database.DB.Model(&meshPeer).Updates(updates).Error; err != nil {
		log.Printf("Failed to update mesh peer %d status: %v", meshPeer.ID, err)
	}
}

// HandleAgentNetworkConfig handles agent network config requests
func HandleAgentNetworkConfig(c *gin.Context) {
	// Get DERP relay configuration from environment
	derpURL := os.Getenv("DERP_URL")
	if derpURL == "" {
		derpURL = "https://derp.prysm.sh:8443"
	}

	// Return actual DERP configuration
	c.JSON(http.StatusOK, gin.H{
		"config": gin.H{
			"version": "1.0.0",
			"derp": gin.H{
				"urls":    []string{derpURL},
				"region":  "us-west",
				"enabled": true,
			},
			"wireguard": gin.H{
				"enabled":   true,
				"port":      51820,
				"interface": "wg0",
			},
			"endpoints": []string{
				"wss://api.prysm.sh/mesh",
				derpURL,
			},
		},
	})
}

// HandleGetMeshStatus returns the mesh connectivity status for a cluster
func HandleGetMeshStatus(c *gin.Context) {
	clusterIDStr := c.Param("id")
	clusterID, err := strconv.ParseInt(clusterIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	// Get cluster from database
	var cluster models.Cluster
	if err := database.DB.First(&cluster, clusterID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}

	// Check mesh peer status
	var meshPeer models.MeshPeer
	connected := false
	var peerCount int64

	if err := database.DB.Where("cluster_id = ?", clusterID).First(&meshPeer).Error; err == nil {
		connected = meshPeer.Status == "connected"
		// Count active peers in the same organization
		database.DB.Model(&models.MeshPeer{}).
			Where("organization_id = ? AND status = ?", cluster.OrganizationID, "connected").
			Count(&peerCount)
	}

	response := gin.H{
		"connected":  connected,
		"peer_count": int(peerCount),
		"cluster_id": clusterID,
	}

	// Add last seen if we have a last ping
	if cluster.LastPing != nil {
		response["last_seen"] = *cluster.LastPing
	}

	// Add DERP relay URL
	derpURL := os.Getenv("DERP_URL")
	if derpURL == "" {
		derpURL = "https://derp.prysm.sh:8443"
	}
	response["relay_url"] = derpURL

	// Add device ID if mesh peer exists
	if meshPeer.DeviceID != "" {
		response["device_id"] = meshPeer.DeviceID
	}

	c.JSON(http.StatusOK, response)
}
