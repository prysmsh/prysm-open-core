package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ValidateLoginInput validates login request input
func ValidateLoginInput() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("ValidateLoginInput: Starting validation")
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("ValidateLoginInput: Failed to read body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}
		log.Printf("ValidateLoginInput: Read %d bytes from body", len(bodyBytes))

		// Restore body for further processing
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var payload struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		// Validate email
		email := strings.TrimSpace(payload.Email)
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
			c.Abort()
			return
		}

		// Basic email validation
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			c.Abort()
			return
		}

		// Validate password
		if payload.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
			c.Abort()
			return
		}

		// Store validated values in context
		c.Set("validated_email", strings.ToLower(email))
		c.Set("validated_password", payload.Password)
		c.Set("validated_raw_body", bodyBytes)

		c.Next()
	}
}