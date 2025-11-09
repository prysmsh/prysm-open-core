package dns

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetDNSRecords returns all DNS records for the organization
func HandleGetDNSRecords(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var records []models.DNSRecord
	if err := database.DB.Where("organization_id = ?", orgID).Find(&records).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DNS records"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"records": records,
		"total":   len(records),
	})
}

// HandleCreateDNSRecord creates a new DNS record
func HandleCreateDNSRecord(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var record models.DNSRecord
	if err := c.ShouldBindJSON(&record); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record.OrganizationID = orgID

	if err := database.DB.Create(&record).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DNS record"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"record":  record,
		"message": "DNS record created successfully",
	})
}

// HandleUpdateDNSRecord updates a DNS record
func HandleUpdateDNSRecord(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var record models.DNSRecord
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&record).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "DNS record not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DNS record"})
		}
		return
	}

	var updates models.DNSRecord
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&record).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DNS record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"record":  record,
		"message": "DNS record updated successfully",
	})
}

// HandleDeleteDNSRecord deletes a DNS record
func HandleDeleteDNSRecord(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.DNSRecord{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete DNS record"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DNS record deleted successfully",
	})
}

// HandleGetRoutingRules returns all routing rules
func HandleGetRoutingRules(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var rules []models.RoutingRule
	if err := database.DB.Where("organization_id = ?", orgID).Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch routing rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// HandleCreateRoutingRule creates a new routing rule
func HandleCreateRoutingRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var rule models.RoutingRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule.OrganizationID = orgID

	if err := database.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create routing rule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"rule":    rule,
		"message": "Routing rule created successfully",
	})
}

// HandleUpdateRoutingRule updates a routing rule
func HandleUpdateRoutingRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var rule models.RoutingRule
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&rule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Routing rule not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch routing rule"})
		}
		return
	}

	var updates models.RoutingRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&rule).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update routing rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rule":    rule,
		"message": "Routing rule updated successfully",
	})
}

// HandleDeleteRoutingRule deletes a routing rule
func HandleDeleteRoutingRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.RoutingRule{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete routing rule"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Routing rule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Routing rule deleted successfully",
	})
}

