package usage

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetUsageRecords returns usage records for the organization
func HandleGetUsageRecords(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var records []models.UsageRecord
	if err := database.DB.Where("organization_id = ?", orgID).Order("created_at DESC").Limit(100).Find(&records).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch usage records"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"records": records,
		"total":   len(records),
	})
}

// HandleGetCurrentUsage returns current usage statistics
func HandleGetCurrentUsage(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	// Count resources
	var clusterCount, userCount, connectedClusters int64
	database.DB.Model(&models.Cluster{}).Where("organization_id = ?", orgID).Count(&clusterCount)
	database.DB.Model(&models.Cluster{}).Where("organization_id = ? AND status = ?", orgID, "connected").Count(&connectedClusters)
	database.DB.Model(&models.OrganizationMember{}).Where("organization_id = ? AND status = ?", orgID, "active").Count(&userCount)
	serviceCount := countServicesForOrg(orgID)

	c.JSON(http.StatusOK, gin.H{
		"organization_id":    orgID,
		"clusters":           clusterCount,
		"connected_clusters": connectedClusters,
		"service_count":      serviceCount,
		"users":              userCount,
		"period":             "current",
	})
}

// HandleGetUsageStats returns detailed usage statistics (from usage.go)
func HandleGetUsageStats(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	// Count various resources
	var clusterCount, userCount, recordCount, connectedClusters int64
	database.DB.Model(&models.Cluster{}).Where("organization_id = ?", orgID).Count(&clusterCount)
	database.DB.Model(&models.Cluster{}).Where("organization_id = ? AND status = ?", orgID, "connected").Count(&connectedClusters)
	database.DB.Model(&models.OrganizationMember{}).Where("organization_id = ?", orgID).Count(&userCount)
	database.DB.Model(&models.UsageRecord{}).Where("organization_id = ?", orgID).Count(&recordCount)
	serviceCount := countServicesForOrg(orgID)

	c.JSON(http.StatusOK, gin.H{
		"organization_id":    orgID,
		"total_clusters":     clusterCount,
		"connected_clusters": connectedClusters,
		"users":              userCount,
		"usage_records":      recordCount,
		"service_count":      serviceCount,
		"period":             "all_time",
	})
}

func countServicesForOrg(orgID uint) int {
	var clusters []models.Cluster
	if err := database.DB.Where("organization_id = ?", orgID).Select("services").Find(&clusters).Error; err != nil {
		return 0
	}
	total := 0
	for _, cluster := range clusters {
		if len(cluster.Services) == 0 {
			continue
		}
		var services map[string]interface{}
		if err := json.Unmarshal(cluster.Services, &services); err != nil {
			continue
		}
		total += len(services)
	}
	return total
}
