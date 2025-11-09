package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// AgentAuth middleware validates agent tokens for cluster telemetry endpoints
func AgentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}

		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		token := parts[1]
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Empty token"})
			c.Abort()
			return
		}

		// Hash the token to compare with stored hash
		hash := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(hash[:])

		// Extract token prefix for efficient lookup
		tokenPrefix := token
		if len(token) >= 8 {
			tokenPrefix = token[:8]
		}

		// Find the agent token in database
		var agentToken models.AgentToken
		err := database.DB.Where("token_prefix = ? AND token_hash = ? AND active = ?",
			tokenPrefix, tokenHash, true).First(&agentToken).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive token"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			c.Abort()
			return
		}

		// Extract cluster ID from path if present
		clusterID := c.Param("id")
		if clusterID != "" {
			// Verify that the token belongs to this cluster
			var cluster models.Cluster
			err := database.DB.Where("id = ? AND organization_id = ?",
				clusterID, agentToken.OrganizationID).First(&cluster).Error

			if err != nil {
				if err == gorm.ErrRecordNotFound {
					c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this cluster"})
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
				}
				c.Abort()
				return
			}

			if strings.ToLower(cluster.AgentTokenHash) != strings.ToLower(tokenHash) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Token not authorized for this cluster"})
				c.Abort()
				return
			}

			// Set cluster context
			c.Set("cluster_id", cluster.ID)
			c.Set("cluster", &cluster)
		}

		// Set agent token context
		c.Set("agent_token_id", agentToken.ID)
		c.Set("organization_id", agentToken.OrganizationID)
		c.Set("agent_token", &agentToken)

		c.Next()
	}
}

// OptionalAgentAuth allows requests with or without agent authentication
// Used for endpoints that support both authenticated and unauthenticated access
func OptionalAgentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth header, continue without authentication
			c.Next()
			return
		}

		// Try to authenticate, but don't fail if it doesn't work
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" && parts[1] != "" {
			token := parts[1]

			// Hash the token
			hash := sha256.Sum256([]byte(token))
			tokenHash := hex.EncodeToString(hash[:])

			tokenPrefix := token
			if len(token) >= 8 {
				tokenPrefix = token[:8]
			}

			var agentToken models.AgentToken
			err := database.DB.Where("token_prefix = ? AND token_hash = ? AND active = ?",
				tokenPrefix, tokenHash, true).First(&agentToken).Error

			if err == nil {
				// Valid token found, set context
				c.Set("agent_token_id", agentToken.ID)
				c.Set("organization_id", agentToken.OrganizationID)
				c.Set("agent_token", &agentToken)
			}
		}

		c.Next()
	}
}
