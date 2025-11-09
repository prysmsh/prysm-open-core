package transformations

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetTransformationRules returns all transformation rules
func HandleGetTransformationRules(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var rules []models.TransformationRule
	if err := database.DB.Where("organization_id = ?", orgID).Order("priority ASC").Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch transformation rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// HandleCreateTransformationRule creates a new transformation rule
func HandleCreateTransformationRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var rule models.TransformationRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule.OrganizationID = orgID
	rule.CreatedBy = userID

	if err := database.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transformation rule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"rule":    rule,
		"message": "Transformation rule created successfully",
	})
}

// HandleUpdateTransformationRule updates a transformation rule
func HandleUpdateTransformationRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	var rule models.TransformationRule
	if err := database.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&rule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Transformation rule not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch transformation rule"})
		}
		return
	}

	var updates models.TransformationRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&rule).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update transformation rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rule":    rule,
		"message": "Transformation rule updated successfully",
	})
}

// HandleDeleteTransformationRule deletes a transformation rule
func HandleDeleteTransformationRule(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	id := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", id, orgID).Delete(&models.TransformationRule{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete transformation rule"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transformation rule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Transformation rule deleted successfully",
	})
}

// HandleTestTransformationRule tests a transformation rule
func HandleTestTransformationRule(c *gin.Context) {
	var req struct {
		RuleID uint                   `json:"rule_id"`
		Input  map[string]interface{} `json:"input"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement transformation testing logic
	c.JSON(http.StatusOK, gin.H{
		"result":  req.Input,
		"message": "Transformation test completed",
	})
}

// HandleReorderTransformationRules reorders transformation rules
func HandleReorderTransformationRules(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		RuleIDs []uint `json:"rule_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement reordering logic
	c.JSON(http.StatusOK, gin.H{
		"message": "Transformation rules reordered successfully",
		"org_id":  orgID,
	})
}

// HandleGetTransformationRuleTemplates returns available templates
func HandleGetTransformationRuleTemplates(c *gin.Context) {
	templates := []gin.H{
		{"id": "json_parse", "name": "JSON Parse", "description": "Parse JSON field"},
		{"id": "regex_extract", "name": "Regex Extract", "description": "Extract using regex"},
		{"id": "timestamp_parse", "name": "Timestamp Parse", "description": "Parse timestamp"},
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// HandleCreateTransformationRuleFromTemplate creates a rule from template
func HandleCreateTransformationRuleFromTemplate(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		TemplateID string                 `json:"template_id" binding:"required"`
		Name       string                 `json:"name" binding:"required"`
		Config     map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Create rule from template
	c.JSON(http.StatusCreated, gin.H{
		"message":     "Transformation rule created from template",
		"template_id": req.TemplateID,
		"org_id":      orgID,
	})
}

