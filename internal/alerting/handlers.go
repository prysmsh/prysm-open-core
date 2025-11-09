package alerting

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleCreateLogAlert creates a new log alert
func HandleCreateLogAlert(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var alert models.LogAlert
	if err := c.ShouldBindJSON(&alert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	alert.OrganizationID = orgID
	alert.CreatedBy = userID

	if err := database.DB.Create(&alert).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create log alert"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"alert":   alert,
		"message": "Log alert created successfully",
	})
}

// HandleGetLogAlerts returns all log alerts
func HandleGetLogAlerts(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var alerts []models.LogAlert
	if err := database.DB.Where("organization_id = ?", orgID).Find(&alerts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// HandleGetLogAlert returns a specific log alert
func HandleGetLogAlert(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var alert models.LogAlert
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&alert).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Log alert not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log alert"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alert": alert,
	})
}

// HandleUpdateLogAlert updates a log alert
func HandleUpdateLogAlert(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var alert models.LogAlert
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&alert).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Log alert not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log alert"})
		}
		return
	}

	var updates models.LogAlert
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&alert).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update log alert"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alert":   alert,
		"message": "Log alert updated successfully",
	})
}

// HandleDeleteLogAlert deletes a log alert
func HandleDeleteLogAlert(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.LogAlert{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete log alert"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log alert not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Log alert deleted successfully",
	})
}

// HandleGetLogAlertInstances returns alert instances/triggers
func HandleGetLogAlertInstances(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	alertID := c.Param("id")

	id, err := strconv.ParseUint(alertID, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
		return
	}

	var instances []models.LogAlertInstance
	if err := database.DB.Where("organization_id = ? AND alert_id = ?", orgID, id).
		Order("COALESCE(last_triggered, first_triggered, created_at) DESC").
		Preload("Alert").
		Find(&instances).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alert instances"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_id":        alertID,
		"instances":       instances,
		"total":           len(instances),
		"organization_id": orgID,
	})
}

// HandleListLogAlertInstances returns the most recent alert executions for the org
func HandleListLogAlertInstances(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limitVal := 10
	if parsed, err := strconv.Atoi(c.DefaultQuery("limit", "10")); err == nil && parsed > 0 {
		if parsed > 100 {
			parsed = 100
		}
		limitVal = parsed
	}
	var instances []models.LogAlertInstance
	if err := database.DB.Where("organization_id = ?", orgID).
		Order("COALESCE(last_triggered, first_triggered, created_at) DESC").
		Limit(limitVal).
		Preload("Alert").
		Find(&instances).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alert instances"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"instances": instances,
		"total":     len(instances),
	})
}

// HandleAcknowledgeLogAlert acknowledges a log alert
func HandleAcknowledgeLogAlert(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")
	userID := c.GetUint("user_id")

	var alert models.LogAlert
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&alert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log alert not found"})
		return
	}

	now := time.Now()
	alert.LastTriggered = &now
	alert.TriggerCount++
	if err := database.DB.Save(&alert).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert"})
		return
	}

	if err := database.DB.Model(&models.LogAlertInstance{}).
		Where("alert_id = ? AND organization_id = ? AND acknowledged_at IS NULL", alert.ID, orgID).
		Updates(map[string]interface{}{
			"acknowledged_at": now,
			"acknowledged_by": userID,
			"status":          "acknowledged",
		}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to acknowledge alert instances"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "Alert acknowledged",
		"alert_id":        id,
		"acknowledged_by": userID,
	})
}

// HandleCreateNotificationChannel creates a notification channel (duplicate from notifications package)
func HandleCreateNotificationChannel(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var channel models.NotificationChannel
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	channel.OrganizationID = orgID
	channel.CreatedBy = userID

	if err := database.DB.Create(&channel).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notification channel"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"channel": channel,
	})
}

// HandleGetNotificationChannels returns notification channels (duplicate from notifications package)
func HandleGetNotificationChannels(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var channels []models.NotificationChannel
	if err := database.DB.Where("organization_id = ?", orgID).Find(&channels).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notification channels"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"channels": channels,
		"total":    len(channels),
	})
}
