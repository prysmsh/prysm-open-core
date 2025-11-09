package errors

import (
	"github.com/gin-gonic/gin"
)

// SendErrorResponse sends a standardized error response
func SendErrorResponse(c *gin.Context, statusCode int, appErr *AppError) {
	c.JSON(statusCode, gin.H{
		"error":   appErr.Code,
		"message": appErr.Message,
		"details": appErr.Details,
	})
}

