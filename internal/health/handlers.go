package health

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
)

var startTime = time.Now()

// HandleHealthCheck returns basic health status
func HandleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "prysm-api",
		"timestamp": time.Now(),
		"uptime":    time.Since(startTime).String(),
	})
}

// HandleSystemReady returns readiness status
func HandleSystemReady(c *gin.Context) {
	// Check database connection
	dbReady := false
	if database.DB != nil {
		sqlDB, err := database.DB.DB()
		if err == nil {
			if err := sqlDB.Ping(); err == nil {
				dbReady = true
			}
		}
	}

	status := http.StatusOK
	if !dbReady {
		status = http.StatusServiceUnavailable
	}

	c.JSON(status, gin.H{
		"ready":    dbReady,
		"database": dbReady,
		"service":  "prysm-api",
	})
}

