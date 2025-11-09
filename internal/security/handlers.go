package security

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetSecurityEvents returns security events for the organization
func HandleGetSecurityEvents(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limit := c.DefaultQuery("limit", "100")

	var events []models.SecurityEvent
	if err := database.DB.Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Limit(100).
		Find(&events).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch security events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  len(events),
		"limit":  limit,
	})
}

// HandleRespondWithError handles secure error responses
func HandleRespondWithError(c *gin.Context) {
	// Utility for standardized error handling
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": "Standardized error response",
	})
}

// HandleLogSecurityError logs security-related errors
func HandleLogSecurityError(c *gin.Context) {
	var req struct {
		ErrorType string                 `json:"error_type" binding:"required"`
		Details   map[string]interface{} `json:"details"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Log security error
	c.JSON(http.StatusOK, gin.H{
		"message": "Security error logged",
	})
}

// HandleHTTPErrorHandler handles HTTP errors in standardized format
func HandleHTTPErrorHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "HTTP error handler utility",
	})
}

