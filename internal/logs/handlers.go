package logs

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleIngestLogs handles log ingestion requests
func HandleIngestLogs(c *gin.Context) {
	// For now, just accept the logs and return success
	// TODO: Implement actual log processing
	c.Status(http.StatusNoContent)
}

// HandleGetCorrelatedLogs returns log correlation records for dashboards.
func HandleGetCorrelatedLogs(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limitVal, err := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if err != nil || limitVal <= 0 {
		limitVal = 100
	}
	if limitVal > 500 {
		limitVal = 500
	}

	query := database.DB.Where("organization_id = ?", orgID).Order("created_at DESC")
	if traceID := strings.TrimSpace(c.Query("trace_id")); traceID != "" {
		query = query.Where("trace_id = ?", traceID)
	}

	var correlations []models.LogCorrelation
	if err := query.Limit(limitVal).Find(&correlations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log correlations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"correlations": correlations,
		"total":        len(correlations),
	})
}
