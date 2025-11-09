package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetRoutes returns all routing rules for the organization
func HandleGetRoutes(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var routes []models.RoutingRule
	if err := database.DB.Where("organization_id = ?", orgID).Preload("Cluster").Find(&routes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch routes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"routes": routes,
		"total":  len(routes),
	})
}

// HandleCreateRoute creates a new routing rule
func HandleCreateRoute(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		ClusterID    uint   `json:"cluster_id" binding:"required"`
		ExternalPort int    `json:"external_port" binding:"required"`
		InternalPort int    `json:"internal_port" binding:"required"`
		Protocol     string `json:"protocol" binding:"required"`
		Hostname     string `json:"hostname"`
		Description  string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify cluster belongs to organization
	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", req.ClusterID, orgID).First(&cluster).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}

	// Check if port is already in use
	var existing models.RoutingRule
	if err := database.DB.Where("external_port = ? AND organization_id = ?", req.ExternalPort, orgID).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "External port already in use"})
		return
	}

	route := models.RoutingRule{
		ClusterID:      req.ClusterID,
		OrganizationID: orgID,
		ExternalPort:   req.ExternalPort,
		InternalPort:   req.InternalPort,
		Protocol:       req.Protocol,
		Hostname:       req.Hostname,
		Description:    req.Description,
		Active:         true,
	}

	if err := database.DB.Create(&route).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create route"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"route":   route,
		"message": "Route created successfully",
	})
}

// HandleUpdateRoute updates a routing rule
func HandleUpdateRoute(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var route models.RoutingRule
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&route).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch route"})
		}
		return
	}

	var updates models.RoutingRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&route).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update route"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"route":   route,
		"message": "Route updated successfully",
	})
}

// HandleDeleteRoute deletes a routing rule
func HandleDeleteRoute(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.RoutingRule{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete route"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Route deleted successfully",
	})
}

// HandleToggleRouteStatus toggles a route's active status
func HandleToggleRouteStatus(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var route models.RoutingRule
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&route).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch route"})
		}
		return
	}

	route.Active = !route.Active
	if err := database.DB.Save(&route).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle route status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"route":   route,
		"message": fmt.Sprintf("Route %s successfully", map[bool]string{true: "enabled", false: "disabled"}[route.Active]),
	})
}

// HandleGetRouteMetrics returns metrics for a routing rule
func HandleGetRouteMetrics(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var route models.RoutingRule
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&route).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch route"})
		}
		return
	}

	// Return placeholder metrics
	c.JSON(http.StatusOK, gin.H{
		"route_id": id,
		"metrics": gin.H{
			"connections": 0,
			"bytes_in":    0,
			"bytes_out":   0,
			"errors":      0,
		},
	})
}

// HandleSuggestExternalPort suggests an available external port
func HandleSuggestExternalPort(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	startPort, _ := strconv.Atoi(c.DefaultQuery("start_port", "30000"))

	// Find first available port starting from startPort
	for port := startPort; port < 65535; port++ {
		var existing models.RoutingRule
		if err := database.DB.Where("external_port = ? AND organization_id = ?", port, orgID).First(&existing).Error; err != nil {
			// Port is available
			c.JSON(http.StatusOK, gin.H{
				"suggested_port": port,
				"available":      true,
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "No available ports found in range",
		"available": false,
	})
}

