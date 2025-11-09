package utils

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/errors"
)

// SendErrorResponse sends a standardized error response
func SendErrorResponse(c *gin.Context, statusCode int, appErr *errors.AppError) {
	if appErr == nil {
		appErr = &errors.AppError{Code: "UNKNOWN_ERROR", Message: "An unexpected error occurred"}
	}

	c.JSON(statusCode, gin.H{
		"error":   appErr.Code,
		"message": appErr.Message,
		"details": appErr.Details,
	})

	if statusCode >= http.StatusInternalServerError {
		extras := map[string]interface{}{
			"status_code": statusCode,
			"error_code":  appErr.Code,
			"details":     appErr.Details,
		}
		if c != nil && c.FullPath() != "" {
			extras["route"] = c.FullPath()
		}
		CaptureSentryError(c, appErr.Err, fmt.Sprintf("SendErrorResponse:%s", appErr.Code), extras)
	}
}

// HandleError logs an error with context
func HandleError(err error, context string) {
	if err != nil {
		log.Printf("Error in %s: %v", context, err)
		CaptureSentryError(nil, err, context, nil)
	}
}

// GetClientIP extracts the client IP from the request
func GetClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	forwarded := c.GetHeader("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (common in nginx)
	realIP := c.GetHeader("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Fall back to remote address
	return c.ClientIP()
}

// GetValidatedString retrieves a validated string from the context
func GetValidatedString(c *gin.Context, key string) string {
	if value, exists := c.Get(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
