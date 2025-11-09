package webhooks

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleList returns all webhooks for the organization
func HandleList(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	// TODO: When Webhook model exists, use it
	// For now, return placeholder
	c.JSON(http.StatusOK, gin.H{
		"webhooks":        []gin.H{},
		"total":           0,
		"message":         "Webhook management will be implemented",
		"organization_id": orgID,
	})
}

// HandleCreate creates a new webhook
func HandleCreate(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		URL    string   `json:"url" binding:"required,url"`
		Events []string `json:"events" binding:"required"`
		Secret string   `json:"secret"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Create webhook in database when model exists
	c.JSON(http.StatusCreated, gin.H{
		"message":         "Webhook created (placeholder)",
		"organization_id": orgID,
		"webhook": gin.H{
			"url":    req.URL,
			"events": req.Events,
		},
	})
}

// HandleDelete deletes a webhook
func HandleDelete(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	// TODO: Delete from database when model exists
	c.JSON(http.StatusOK, gin.H{
		"message":         "Webhook deleted (placeholder)",
		"id":              id,
		"organization_id": orgID,
	})
}

// HandleTest tests a webhook by sending a test event
func HandleTest(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	// TODO: Send test webhook when implemented
	c.JSON(http.StatusOK, gin.H{
		"message":         "Test webhook sent (placeholder)",
		"id":              id,
		"organization_id": orgID,
	})
}

