package agents

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
	"prysm-backend/internal/tokens"
)

var defaultTokenPermissions = []string{"ping", "register", "update_data"}

func sanitizeAgentToken(token models.AgentToken) gin.H {
	response := gin.H{
		"id":          token.ID,
		"name":        token.Name,
		"prefix":      token.TokenPrefix,
		"permissions": token.Permissions,
		"active":      token.Active,
		"expires_at":  token.ExpiresAt,
		"created_at":  token.CreatedAt,
		"updated_at":  token.UpdatedAt,
		"last_used":   token.LastUsedAt,
		"created_by":  token.CreatedBy,
	}

	if token.ClusterID != nil {
		response["cluster_id"] = token.ClusterID
	}

	return response
}

func tokenPrefix(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

// HandleListTokens returns all agent tokens for the organization
func HandleListTokens(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var tokens []models.AgentToken
	if err := database.DB.Where("organization_id = ?", orgID).Order("created_at DESC").Find(&tokens).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tokens": func() []gin.H {
			sanitized := make([]gin.H, len(tokens))
			for i, token := range tokens {
				sanitized[i] = sanitizeAgentToken(token)
			}
			return sanitized
		}(),
		"total": len(tokens),
	})
}

// HandleCreateToken creates a new agent token
func HandleCreateToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var req struct {
		Name        string     `json:"name" binding:"required"`
		Permissions []string   `json:"permissions"`
		ExpiresAt   *time.Time `json:"expires_at"`
		ClusterID   *uint      `json:"cluster_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token name is required"})
		return
	}

	perms := req.Permissions
	if len(perms) == 0 {
		perms = append([]string(nil), defaultTokenPermissions...)
	}

	tokenValue, tokenHash, err := tokens.GenerateOrgScopedToken(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	agentToken := models.AgentToken{
		Name:           name,
		TokenHash:      tokenHash,
		TokenPrefix:    tokenPrefix(tokenValue),
		OrganizationID: orgID,
		ClusterID:      req.ClusterID,
		Permissions:    perms,
		ExpiresAt:      req.ExpiresAt,
		Active:         true,
		CreatedBy:      userID,
	}

	if err := database.DB.Create(&agentToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":      "Agent token created successfully",
		"token":        tokenValue,
		"token_id":     agentToken.ID,
		"token_prefix": agentToken.TokenPrefix,
		"agent_token":  sanitizeAgentToken(agentToken),
	})
}

// HandleGetToken returns a specific agent token (without secret)
func HandleGetToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	tokenID := c.Param("id")

	var token models.AgentToken
	if err := database.DB.Where("id = ? AND organization_id = ?", tokenID, orgID).First(&token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": sanitizeAgentToken(token)})
}

// HandleRevokeToken revokes an agent token
func HandleRevokeToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	tokenID := c.Param("id")

	var token models.AgentToken
	if err := database.DB.Where("id = ? AND organization_id = ?", tokenID, orgID).First(&token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch token"})
		}
		return
	}

	token.Active = false
	if err := database.DB.Save(&token).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Token revoked successfully",
		"agent_token": sanitizeAgentToken(token),
	})
}

// HandleDeleteToken deletes an agent token
func HandleDeleteToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	tokenID := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", tokenID, orgID).Delete(&models.AgentToken{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token deleted successfully",
	})
}

// HandleUpdateToken updates an agent token's properties
func HandleUpdateToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	tokenID := c.Param("id")

	var req struct {
		Name        *string    `json:"name"`
		Permissions *[]string  `json:"permissions"`
		Active      *bool      `json:"active"`
		ExpiresAt   *time.Time `json:"expires_at"`
		ClusterID   *uint      `json:"cluster_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var token models.AgentToken
	if err := database.DB.Where("id = ? AND organization_id = ?", tokenID, orgID).First(&token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch token"})
		}
		return
	}

	if req.Name != nil {
		token.Name = strings.TrimSpace(*req.Name)
	}
	if req.Permissions != nil {
		token.Permissions = *req.Permissions
	}
	if req.Active != nil {
		token.Active = *req.Active
	}
	if req.ExpiresAt != nil {
		token.ExpiresAt = req.ExpiresAt
	}
	if req.ClusterID != nil {
		token.ClusterID = req.ClusterID
	}

	if err := database.DB.Save(&token).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Token updated successfully",
		"agent_token": sanitizeAgentToken(token),
	})
}

// HandleRotateToken generates a fresh secret for an existing token record.
func HandleRotateToken(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	tokenID := c.Param("id")

	var token models.AgentToken
	if err := database.DB.Where("id = ? AND organization_id = ?", tokenID, orgID).First(&token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch token"})
		return
	}

	newToken, hash, err := tokens.GenerateOrgScopedToken(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	token.TokenHash = hash
	token.TokenPrefix = tokenPrefix(newToken)
	token.Active = true
	if err := database.DB.Save(&token).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Token rotated successfully",
		"token":        newToken,
		"token_id":     token.ID,
		"token_prefix": token.TokenPrefix,
		"agent_token":  sanitizeAgentToken(token),
	})
}
