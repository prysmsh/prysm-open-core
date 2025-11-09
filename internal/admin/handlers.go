package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// IsUserAdmin checks if the current user is an admin
func IsUserAdmin(c *gin.Context) bool {
	role := c.GetString("role")
	return role == "admin" || role == "superadmin"
}

// HandleGetAdminStats returns admin statistics
func HandleGetAdminStats(c *gin.Context) {
	if !IsUserAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// TODO: Gather admin statistics
	c.JSON(http.StatusOK, gin.H{
		"stats": gin.H{
			"total_users":         0,
			"total_organizations": 0,
			"total_clusters":      0,
		},
	})
}

// UserIsAdminFromMain checks admin status (from main.go)
func UserIsAdminFromMain(c *gin.Context) bool {
	role := c.GetString("role")
	return role == "admin" || role == "superadmin" || role == "owner"
}

