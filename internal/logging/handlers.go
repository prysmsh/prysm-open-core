package logging

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleListLogSinks returns all log sinks for the organization
func HandleListLogSinks(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var sinks []models.LogSink
	if err := database.DB.Where("organization_id = ?", orgID).Find(&sinks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log sinks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sinks": sinks,
		"total": len(sinks),
	})
}

// HandleCreateLogSink creates a new log sink
func HandleCreateLogSink(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var sink models.LogSink
	if err := c.ShouldBindJSON(&sink); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sink.OrganizationID = orgID
	sink.CreatedBy = userID
	sink.Status = "active"

	if err := database.DB.Create(&sink).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create log sink"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"sink":    sink,
		"message": "Log sink created successfully",
	})
}

// HandleDeleteLogSink deletes a log sink
func HandleDeleteLogSink(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.LogSink{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete log sink"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log sink not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Log sink deleted successfully",
	})
}

// HandleGetLogSinkManifest returns the manifest for a log sink (for agent installation)
func HandleGetLogSinkManifest(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var sink models.LogSink
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&sink).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Log sink not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log sink"})
		}
		return
	}

	// TODO: Generate actual Kubernetes manifest
	manifest := gin.H{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": gin.H{
			"name":      "log-sink-" + id,
			"namespace": "prysm-system",
		},
		"data": gin.H{
			"sink-config": "# Log sink configuration placeholder",
		},
	}

	c.JSON(http.StatusOK, manifest)
}

// HandleUpdateLogSinkStatus updates the status of a log sink (agent heartbeat)
func HandleUpdateLogSinkStatus(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var req struct {
		Status string                 `json:"status"`
		Stats  map[string]interface{} `json:"stats"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var sink models.LogSink
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&sink).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Log sink not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log sink"})
		}
		return
	}

	if req.Status != "" {
		sink.Status = req.Status
	}

	if err := database.DB.Save(&sink).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update log sink status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Log sink status updated",
		"status":  sink.Status,
	})
}

