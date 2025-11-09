package analytics

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// Data Source Management

// HandleGetClusterAnalytics summarizes cluster state for dashboards.
func HandleGetClusterAnalytics(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var clusters []models.Cluster
	if err := database.DB.Where("organization_id = ?", orgID).Find(&clusters).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clusters"})
		return
	}

	statusCounts := make(map[string]int)
	serviceTotal := 0
	for _, cluster := range clusters {
		status := strings.ToLower(strings.TrimSpace(cluster.Status))
		if status == "" {
			status = "unknown"
		}
		statusCounts[status]++
		serviceTotal += countServices(cluster.Services)
	}

	c.JSON(http.StatusOK, gin.H{
		"organization_id":    orgID,
		"total_clusters":     len(clusters),
		"connected_clusters": statusCounts["connected"],
		"status_counts":      statusCounts,
		"service_count":      serviceTotal,
		"clusters":           clusters,
	})
}

// HandleGetPerformanceOverview aggregates runtime metrics across clusters.
func HandleGetPerformanceOverview(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var clusters []models.Cluster
	if err := database.DB.Where("organization_id = ?", orgID).Find(&clusters).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clusters"})
		return
	}

	var (
		totalCPU, totalMemory, totalLatency, totalErrorRate, totalRequests float64
		sampleCount                                                        float64
	)

	for _, cluster := range clusters {
		if len(cluster.Metrics) == 0 {
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(cluster.Metrics, &payload); err != nil {
			continue
		}
		sampleCount++
		totalCPU += toFloat(payload["cpu_usage"])
		totalMemory += toFloat(payload["memory_usage"])
		totalLatency += toFloat(payload["latency_ms"])
		totalErrorRate += toFloat(payload["error_rate"])
		totalRequests += toFloat(payload["requests_per_second"])
	}

	if sampleCount == 0 {
		sampleCount = 1 // Avoid division by zero; values remain zero.
	}

	connected := 0
	for _, cluster := range clusters {
		if strings.EqualFold(cluster.Status, "connected") {
			connected++
		}
	}
	uptimePct := 0.0
	if len(clusters) > 0 {
		uptimePct = (float64(connected) / float64(len(clusters))) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"organization_id":     orgID,
		"uptime_percentage":   uptimePct,
		"cpu_usage":           totalCPU / sampleCount,
		"memory_usage":        totalMemory / sampleCount,
		"latency_ms":          totalLatency / sampleCount,
		"error_rate":          totalErrorRate / sampleCount,
		"requests_per_second": totalRequests / sampleCount,
	})
}

// HandleGetLogStats returns a roll-up of log alerting activity for dashboards.
func HandleGetLogStats(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var alertCount, activeAlertCount, sinkCount, correlationCount, instanceCount, openInstanceCount int64
	database.DB.Model(&models.LogAlert{}).Where("organization_id = ?", orgID).Count(&alertCount)
	database.DB.Model(&models.LogAlert{}).Where("organization_id = ? AND active = ?", orgID, true).Count(&activeAlertCount)
	database.DB.Model(&models.LogSink{}).Where("organization_id = ?", orgID).Count(&sinkCount)
	database.DB.Model(&models.LogCorrelation{}).Where("organization_id = ?", orgID).Count(&correlationCount)
	database.DB.Model(&models.LogAlertInstance{}).Where("organization_id = ?", orgID).Count(&instanceCount)
	database.DB.Model(&models.LogAlertInstance{}).
		Where("organization_id = ? AND (status = ? OR status = ?)", orgID, "firing", "investigating").
		Count(&openInstanceCount)

	c.JSON(http.StatusOK, gin.H{
		"organization_id":  orgID,
		"alerts_total":     alertCount,
		"alerts_active":    activeAlertCount,
		"log_sinks":        sinkCount,
		"log_correlations": correlationCount,
		"alert_instances":  instanceCount,
		"open_alerts":      openInstanceCount,
	})
}

// HandleGetDataSources returns all data sources for the organization
func HandleGetDataSources(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var dataSources []models.DataSource
	if err := database.DB.Where("organization_id = ?", orgID).Find(&dataSources).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data sources"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data_sources": dataSources,
		"total":        len(dataSources),
	})
}

// HandleCreateDataSource creates a new data source
func HandleCreateDataSource(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var dataSource models.DataSource
	if err := c.ShouldBindJSON(&dataSource); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dataSource.OrganizationID = orgID
	dataSource.CreatedBy = userID

	if err := database.DB.Create(&dataSource).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create data source"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data_source": dataSource,
		"message":     "Data source created successfully",
	})
}

// HandleUpdateDataSource updates a data source
func HandleUpdateDataSource(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var dataSource models.DataSource
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&dataSource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Data source not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data source"})
		}
		return
	}

	var updates models.DataSource
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&dataSource).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update data source"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data_source": dataSource,
		"message":     "Data source updated successfully",
	})
}

// HandleDeleteDataSource deletes a data source
func HandleDeleteDataSource(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.DataSource{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete data source"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Data source not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Data source deleted successfully",
	})
}

// Query Management

// HandleGetQueries returns all queries for the organization
func HandleGetQueries(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var queries []models.Query
	if err := database.DB.Where("organization_id = ?", orgID).Find(&queries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch queries"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"queries": queries,
		"total":   len(queries),
	})
}

// HandleCreateQuery creates a new query
func HandleCreateQuery(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var query models.Query
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query.OrganizationID = orgID
	query.CreatedBy = userID

	if err := database.DB.Create(&query).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create query"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"query":   query,
		"message": "Query created successfully",
	})
}

// HandleUpdateQuery updates a query
func HandleUpdateQuery(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var query models.Query
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&query).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Query not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch query"})
		}
		return
	}

	var updates models.Query
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&query).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update query"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"query":   query,
		"message": "Query updated successfully",
	})
}

// HandleDeleteQuery deletes a query
func HandleDeleteQuery(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.Query{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete query"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Query not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Query deleted successfully",
	})
}

// HandleExecuteQuery executes a saved query
func HandleExecuteQuery(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var query models.Query
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&query).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Query not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch query"})
		}
		return
	}

	// TODO: Implement actual query execution against data source
	// For now, return mock results
	results := gin.H{
		"query_id":          query.ID,
		"query_name":        query.Name,
		"executed_at":       time.Now(),
		"rows":              []gin.H{},
		"row_count":         0,
		"execution_time_ms": 0,
	}

	c.JSON(http.StatusOK, results)
}

// Dashboard Management

// HandleGetDashboards returns all dashboards for the organization
func HandleGetDashboards(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var dashboards []models.Dashboard
	if err := database.DB.Where("organization_id = ?", orgID).Find(&dashboards).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboards"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"dashboards": dashboards,
		"total":      len(dashboards),
	})
}

// HandleCreateDashboard creates a new dashboard
func HandleCreateDashboard(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var dashboard models.Dashboard
	if err := c.ShouldBindJSON(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dashboard.OrganizationID = orgID
	dashboard.CreatedBy = userID

	if err := database.DB.Create(&dashboard).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dashboard"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"dashboard": dashboard,
		"message":   "Dashboard created successfully",
	})
}

// HandleUpdateDashboard updates a dashboard
func HandleUpdateDashboard(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var dashboard models.Dashboard
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&dashboard).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Dashboard not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboard"})
		}
		return
	}

	var updates models.Dashboard
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&dashboard).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update dashboard"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"dashboard": dashboard,
		"message":   "Dashboard updated successfully",
	})
}

// HandleDeleteDashboard deletes a dashboard
func HandleDeleteDashboard(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.Dashboard{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dashboard"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dashboard not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Dashboard deleted successfully",
	})
}

// HandleExportDashboard exports a dashboard configuration
func HandleExportDashboard(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var dashboard models.Dashboard
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&dashboard).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Dashboard not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboard"})
		}
		return
	}

	exportData := gin.H{
		"version":     "1.0",
		"dashboard":   dashboard,
		"exported_at": time.Now(),
	}

	c.JSON(http.StatusOK, exportData)
}

// HandleDuplicateDashboard duplicates a dashboard
func HandleDuplicateDashboard(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")
	id := c.Param("id")

	var original models.Dashboard
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&original).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Dashboard not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboard"})
		}
		return
	}

	// Create duplicate
	duplicate := models.Dashboard{
		OrganizationID: orgID,
		Name:           original.Name + " (Copy)",
		Description:    original.Description,
		Config:         original.Config,
		CreatedBy:      userID,
	}

	if err := database.DB.Create(&duplicate).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to duplicate dashboard"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"dashboard": duplicate,
		"message":   "Dashboard duplicated successfully",
	})
}

// HandleGetLogMetrics returns log metrics for a data source
func HandleGetLogMetrics(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	dataSourceID := c.Param("dataSourceId")

	var dataSource models.DataSource
	if err := database.DB.Where("id = ? AND organization_id = ?", dataSourceID, orgID).First(&dataSource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Data source not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data source"})
		}
		return
	}

	// TODO: Implement actual metrics calculation
	// For now, return mock metrics
	metrics := gin.H{
		"data_source_id":    dataSource.ID,
		"total_logs":        0,
		"error_rate":        0.0,
		"avg_response_time": 0.0,
		"period_start":      time.Now().Add(-24 * time.Hour),
		"period_end":        time.Now(),
	}

	c.JSON(http.StatusOK, metrics)
}

func toFloat(v interface{}) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		f, _ := value.Float64()
		return f
	default:
		return 0
	}
}

func countServices(raw models.JSON) int {
	if len(raw) == 0 {
		return 0
	}
	var services map[string]interface{}
	if err := json.Unmarshal(raw, &services); err != nil {
		return 0
	}
	return len(services)
}
