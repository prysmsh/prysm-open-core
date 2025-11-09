package services

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetServices returns all services across all clusters
func HandleGetServices(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var clusters []models.Cluster
	database.DB.Where("organization_id = ?", orgID).Find(&clusters)

	allServices := make(map[string]map[string]interface{})
	totalServices := 0

	for _, cluster := range clusters {
		if cluster.Services != nil {
			var services map[string]interface{}
			if err := json.Unmarshal([]byte(cluster.Services), &services); err == nil {
				clusterKey := fmt.Sprintf("cluster_%d", cluster.ID)
				allServices[clusterKey] = services
				totalServices += len(services)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"services": allServices,
		"total":    totalServices,
	})
}

// HandleGetServicesByCluster returns services for a specific cluster
func HandleGetServicesByCluster(c *gin.Context) {
	clusterID := c.Param("id")
	orgID := c.GetUint("organization_id")

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, orgID).First(&cluster).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}

	services := make(map[string]interface{})
	if cluster.Services != nil {
		if err := json.Unmarshal([]byte(cluster.Services), &services); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse services"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_id": clusterID,
		"services":   services,
		"total":      len(services),
	})
}

