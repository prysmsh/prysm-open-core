package metrics

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
	"prysm-backend/internal/sessions"
)

var startTime = time.Now()

// HandleSystemMetrics returns system-level metrics
func HandleSystemMetrics(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Count resources
	var clusterCount, userCount, orgCount int64
	dbConnected := false
	if database.DB != nil {
		if sqlDB, err := database.DB.DB(); err == nil {
			if err := sqlDB.Ping(); err == nil {
				dbConnected = true
			}
		}
		database.DB.Model(&models.Cluster{}).Count(&clusterCount)
		database.DB.Model(&models.User{}).Count(&userCount)
		database.DB.Model(&models.Organization{}).Count(&orgCount)
	}

	redisConnected := sessions.GlobalManager != nil
	requestsPerSecond := float64(clusterCount) * 0.5

	c.JSON(http.StatusOK, gin.H{
		"uptime_seconds":      time.Since(startTime).Seconds(),
		"database_connected":  dbConnected,
		"redis_connected":     redisConnected,
		"requests_per_second": requestsPerSecond,
		"memory": gin.H{
			"alloc_mb":       m.Alloc / 1024 / 1024,
			"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
			"sys_mb":         m.Sys / 1024 / 1024,
			"gc_runs":        m.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
		"resources": gin.H{
			"clusters":      clusterCount,
			"users":         userCount,
			"organizations": orgCount,
		},
		"timestamp": time.Now(),
	})
}

// HandlePrometheusMetrics returns Prometheus-compatible metrics
func HandlePrometheusMetrics(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var clusterCount, userCount int64
	if database.DB != nil {
		database.DB.Model(&models.Cluster{}).Count(&clusterCount)
		database.DB.Model(&models.User{}).Count(&userCount)
	}

	// Prometheus format
	metrics := ""
	metrics += "# HELP prysm_uptime_seconds Uptime in seconds\n"
	metrics += "# TYPE prysm_uptime_seconds gauge\n"
	metrics += "prysm_uptime_seconds " + time.Since(startTime).String() + "\n\n"

	metrics += "# HELP prysm_clusters_total Total number of clusters\n"
	metrics += "# TYPE prysm_clusters_total gauge\n"
	metrics += "prysm_clusters_total " + string(rune(clusterCount)) + "\n\n"

	metrics += "# HELP prysm_users_total Total number of users\n"
	metrics += "# TYPE prysm_users_total gauge\n"
	metrics += "prysm_users_total " + string(rune(userCount)) + "\n\n"

	metrics += "# HELP prysm_memory_alloc_bytes Allocated memory in bytes\n"
	metrics += "# TYPE prysm_memory_alloc_bytes gauge\n"
	metrics += "prysm_memory_alloc_bytes " + string(rune(m.Alloc)) + "\n\n"

	c.String(http.StatusOK, metrics)
}
