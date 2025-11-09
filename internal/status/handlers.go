package status

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetStatusSummary returns overall system status summary
func HandleGetStatusSummary(c *gin.Context) {
	// This is a public endpoint, no auth required
	var clusterCount, activeClusterCount int64

	if database.DB != nil {
		database.DB.Model(&models.Cluster{}).Count(&clusterCount)
		database.DB.Model(&models.Cluster{}).Where("status = ?", "connected").Count(&activeClusterCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":           "operational",
		"total_clusters":   clusterCount,
		"active_clusters":  activeClusterCount,
		"timestamp":        time.Now(),
		"service":          "prysm-api",
	})
}

