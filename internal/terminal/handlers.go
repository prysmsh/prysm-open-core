package terminal

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleTerminal handles terminal/shell access requests
func HandleTerminal(c *gin.Context) {
	// Terminal access requires special permissions
	// TODO: Implement WebSocket-based terminal session
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "Terminal access not yet implemented",
		"message": "This feature requires WebSocket support",
	})
}

