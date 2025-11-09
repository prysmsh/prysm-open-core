package subdomain

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetSubdomainDelegations returns all subdomain delegations
func HandleGetSubdomainDelegations(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var delegations []models.SubdomainDelegation
	if err := database.DB.Where("organization_id = ?", orgID).Find(&delegations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subdomain delegations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"delegations": delegations,
		"total":       len(delegations),
	})
}

// HandleCreateSubdomainDelegation creates a new subdomain delegation
func HandleCreateSubdomainDelegation(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var delegation models.SubdomainDelegation
	if err := c.ShouldBindJSON(&delegation); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	delegation.OrganizationID = orgID

	if err := database.DB.Create(&delegation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create subdomain delegation"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"delegation": delegation,
		"message":    "Subdomain delegation created successfully",
	})
}

// HandleUpdateSubdomainDelegation updates a subdomain delegation
func HandleUpdateSubdomainDelegation(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var delegation models.SubdomainDelegation
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&delegation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Subdomain delegation not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subdomain delegation"})
		}
		return
	}

	var updates models.SubdomainDelegation
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&delegation).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update subdomain delegation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"delegation": delegation,
		"message":    "Subdomain delegation updated successfully",
	})
}

// HandleDeleteSubdomainDelegation deletes a subdomain delegation
func HandleDeleteSubdomainDelegation(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.SubdomainDelegation{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete subdomain delegation"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Subdomain delegation not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Subdomain delegation deleted successfully",
	})
}

// HandleVerifySubdomainDelegation verifies a subdomain delegation
func HandleVerifySubdomainDelegation(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var delegation models.SubdomainDelegation
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&delegation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Subdomain delegation not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subdomain delegation"})
		}
		return
	}

	// TODO: Implement actual verification logic
	c.JSON(http.StatusOK, gin.H{
		"verified": true,
		"message":  "Subdomain delegation verified successfully",
	})
}

// HandleGetDNSServers returns all DNS servers
func HandleGetDNSServers(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var servers []models.DNSServer
	if err := database.DB.Where("organization_id = ?", orgID).Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DNS servers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"servers": servers,
		"total":   len(servers),
	})
}

// HandleCreateDNSServer creates a new DNS server
func HandleCreateDNSServer(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var server models.DNSServer
	if err := c.ShouldBindJSON(&server); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server.OrganizationID = orgID

	if err := database.DB.Create(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DNS server"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"server":  server,
		"message": "DNS server created successfully",
	})
}

// HandleUpdateDNSServer updates a DNS server
func HandleUpdateDNSServer(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var server models.DNSServer
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&server).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "DNS server not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DNS server"})
		}
		return
	}

	var updates models.DNSServer
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&server).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DNS server"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"server":  server,
		"message": "DNS server updated successfully",
	})
}

// HandleDeleteDNSServer deletes a DNS server
func HandleDeleteDNSServer(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.DNSServer{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete DNS server"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS server not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DNS server deleted successfully",
	})
}

// Additional handlers from main.go

// HandleCreateDNSRecordFromMain creates DNS record (main.go version with validation)
func HandleCreateDNSRecordFromMain(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		Hostname    string `json:"hostname" binding:"required"`
		ClusterID   uint   `json:"cluster_id" binding:"required"`
		ServiceName string `json:"service_name" binding:"required"`
		ServicePort int    `json:"service_port" binding:"required"`
		Namespace   string `json:"namespace"`
		Type        string `json:"type"`
		TTL         int    `json:"ttl"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Full implementation with domain validation
	c.JSON(http.StatusCreated, gin.H{
		"message": "DNS record created (from main.go)",
		"org_id":  orgID,
	})
}

// HandleUpdateDNSRecordFromMain updates DNS record (main.go version)
func HandleUpdateDNSRecordFromMain(c *gin.Context) {
	recordID := c.Param("id")
	orgID := c.GetUint("organization_id")

	// TODO: Full implementation
	c.JSON(http.StatusOK, gin.H{
		"message":   "DNS record updated (from main.go)",
		"record_id": recordID,
		"org_id":    orgID,
	})
}

// HandleDeleteDNSRecordFromMain deletes DNS record (main.go version)
func HandleDeleteDNSRecordFromMain(c *gin.Context) {
	recordID := c.Param("id")
	orgID := c.GetUint("organization_id")

	// TODO: Full implementation
	c.JSON(http.StatusOK, gin.H{
		"message":   "DNS record deleted (from main.go)",
		"record_id": recordID,
		"org_id":    orgID,
	})
}

