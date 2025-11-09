package exports

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleCreateLogExport creates a new log export job
func HandleCreateLogExport(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var export models.LogExportJob
	if err := c.ShouldBindJSON(&export); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	export.OrganizationID = orgID
	export.CreatedBy = userID
	export.Status = "pending"

	if err := database.DB.Create(&export).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create log export"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"export":  export,
		"message": "Log export job created successfully",
	})
}

// HandleGetLogExportStatus returns the status of a log export job
func HandleGetLogExportStatus(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var export models.LogExportJob
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&export).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Log export not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log export"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"export": export,
	})
}

// HandleDownloadLogExport downloads an exported log file
func HandleDownloadLogExport(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var export models.LogExportJob
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&export).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log export not found"})
		return
	}

	if export.Status != "completed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Export is not ready for download"})
		return
	}

	// TODO: Implement actual file download
	c.JSON(http.StatusOK, gin.H{
		"message":      "Download link",
		"download_url": "/downloads/export-" + id + ".json",
	})
}

// HandleListLogExports returns all log exports
func HandleListLogExports(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var exports []models.LogExportJob
	if err := database.DB.Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Find(&exports).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log exports"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"exports": exports,
		"total":   len(exports),
	})
}

// HandleDeleteLogExport deletes a log export job
func HandleDeleteLogExport(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.LogExportJob{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete log export"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log export not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Log export deleted successfully",
	})
}

