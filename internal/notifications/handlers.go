package notifications

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleCreateNotificationChannel creates a new notification channel
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
		"message": "Notification channel created successfully",
	})
}

// HandleListNotificationChannels returns all notification channels
func HandleListNotificationChannels(c *gin.Context) {
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

// HandleUpdateNotificationChannel updates a notification channel
func HandleUpdateNotificationChannel(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var channel models.NotificationChannel
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&channel).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Notification channel not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notification channel"})
		}
		return
	}

	var updates models.NotificationChannel
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&channel).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update notification channel"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"channel": channel,
		"message": "Notification channel updated successfully",
	})
}

// HandleDeleteNotificationChannel deletes a notification channel
func HandleDeleteNotificationChannel(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.NotificationChannel{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete notification channel"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification channel not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Notification channel deleted successfully",
	})
}

// HandleTestNotificationChannel tests a notification channel
func HandleTestNotificationChannel(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var channel models.NotificationChannel
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&channel).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Notification channel not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notification channel"})
		}
		return
	}

	// TODO: Implement actual notification sending logic based on channel type
	c.JSON(http.StatusOK, gin.H{
		"message":    "Test notification sent successfully",
		"channel_id": id,
		"type":       channel.Type,
	})
}

// HandleListNotifications returns all notifications
func HandleListNotifications(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limit := c.DefaultQuery("limit", "50")

	var notifications []models.Notification
	if err := database.DB.Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Limit(50).
		Find(&notifications).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"notifications": notifications,
		"total":         len(notifications),
		"limit":         limit,
	})
}

// HandleGetNotificationStats returns notification statistics
func HandleGetNotificationStats(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var totalCount, sentCount, failedCount int64
	database.DB.Model(&models.Notification{}).Where("organization_id = ?", orgID).Count(&totalCount)
	database.DB.Model(&models.Notification{}).Where("organization_id = ? AND status = ?", orgID, "sent").Count(&sentCount)
	database.DB.Model(&models.Notification{}).Where("organization_id = ? AND status = ?", orgID, "failed").Count(&failedCount)

	c.JSON(http.StatusOK, gin.H{
		"total":  totalCount,
		"sent":   sentCount,
		"failed": failedCount,
	})
}

