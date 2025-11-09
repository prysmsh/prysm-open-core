package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	
	"prysm-backend/internal/models"
)

// Middleware provides authentication middleware
func Middleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow OPTIONS requests to pass through for CORS preflight
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}
		
		authHeader := c.GetHeader("Authorization")
		var tokenString string

		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				tokenString = parts[1]
			}
		} else {
			var err error
			tokenString, err = c.Cookie(AuthCookieName)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization token provided"})
				c.Abort()
				return
			}
		}

		if IsTokenBlacklisted(db, tokenString) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
			c.Abort()
			return
		}

		claims, err := ParseToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		var user models.User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		if !user.Active {
			c.JSON(http.StatusForbidden, gin.H{"error": "User account is disabled"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("organization_id", claims.OrganizationID)
		c.Set("role", claims.Role)
		c.Set("user", user)

		c.Next()
	}
}

// AdminMiddleware restricts access to admin users only
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireCSRF middleware for CSRF validation
func RequireCSRF(csrfCookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		
		// Skip CSRF for safe methods
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		// Skip if using Bearer token
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			c.Next()
			return
		}

		headerToken := strings.TrimSpace(c.GetHeader("X-CSRF-Token"))
		if headerToken == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing CSRF token"})
			c.Abort()
			return
		}

		cookieToken, err := c.Cookie(csrfCookieName)
		if err != nil || cookieToken == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing CSRF cookie"})
			c.Abort()
			return
		}

		if headerToken != cookieToken {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

