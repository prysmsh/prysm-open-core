package status

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetStatusSummary returns overall system status summary
func HandleGetStatusSummaryHandler(c *gin.Context) {
	var clusterCount, activeClusterCount int64

	if database.DB != nil {
		database.DB.Model(&models.Cluster{}).Count(&clusterCount)
		database.DB.Model(&models.Cluster{}).Where("status = ?", "connected").Count(&activeClusterCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":           "operational",
		"total_clusters":   clusterCount,
		"active_clusters":  activeClusterCount,
		"service":          "prysm-api",
	})
}

