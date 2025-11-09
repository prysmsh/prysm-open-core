package tracing

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetTraces returns traces for the organization
func HandleGetTraces(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limit := c.DefaultQuery("limit", "100")

	var traces []models.TraceRecord
	if err := database.DB.Where("organization_id = ?", orgID).
		Order("timestamp DESC").
		Limit(100).
		Find(&traces).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch traces"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"traces": traces,
		"total":  len(traces),
		"limit":  limit,
	})
}

// HandleGetTraceByID returns a specific trace by ID
func HandleGetTraceByID(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	traceID := c.Param("id")

	var trace models.TraceRecord
	if err := database.DB.Where("id = ? AND organization_id = ?", traceID, orgID).
		Preload("Spans").
		First(&trace).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Trace not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"trace": trace,
	})
}

// HandleGetLogCorrelation returns log correlation for a trace
func HandleGetLogCorrelation(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	traceID := c.Param("id")

	var correlations []models.LogCorrelation
	if err := database.DB.Where("trace_id = ? AND organization_id = ?", traceID, orgID).
		Find(&correlations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log correlations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"correlations": correlations,
		"total":        len(correlations),
	})
}

