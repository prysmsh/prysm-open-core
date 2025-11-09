package teams

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetOrganizationMembers returns all members of the organization
func HandleGetOrganizationMembers(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var members []models.OrganizationMember
	if err := database.DB.Where("organization_id = ?", orgID).Preload("User").Find(&members).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch members"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"members": members,
		"total":   len(members),
	})
}

// HandleInviteMember sends an invitation to join the organization
func HandleInviteMember(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	var req struct {
		Email string `json:"email" binding:"required,email"`
		Role  string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user is already a member
	var existingMember models.OrganizationMember
	var existingUser models.User
	if err := database.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		if err := database.DB.Where("organization_id = ? AND user_id = ?", orgID, existingUser.ID).First(&existingMember).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "User is already a member"})
			return
		}
	}

	// Check for existing invitation
	var existingInvite models.Invitation
	if err := database.DB.Where("organization_id = ? AND email = ? AND status = ?", orgID, req.Email, "pending").First(&existingInvite).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Invitation already sent"})
		return
	}

	// Create invitation
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	invitation := models.Invitation{
		OrganizationID: orgID,
		Email:          req.Email,
		Role:           req.Role,
		InvitedBy:      userID,
		Status:         "pending",
		ExpiresAt:      &expiresAt,
	}

	if err := database.DB.Create(&invitation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create invitation"})
		return
	}

	// TODO: Send invitation email

	c.JSON(http.StatusCreated, gin.H{
		"invitation": invitation,
		"message":    "Invitation sent successfully",
	})
}

// HandleGetInvitations returns all pending invitations
func HandleGetInvitations(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var invitations []models.Invitation
	if err := database.DB.Where("organization_id = ? AND status = ?", orgID, "pending").Find(&invitations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invitations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitations": invitations,
		"total":       len(invitations),
	})
}

// HandleAcceptInvitation accepts an invitation
func HandleAcceptInvitation(c *gin.Context) {
	userID := c.GetUint("user_id")
	inviteID := c.Param("id")

	var invitation models.Invitation
	if err := database.DB.Where("id = ? AND status = ?", inviteID, "pending").First(&invitation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invitation not found or expired"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invitation"})
		}
		return
	}

	// Check if invitation expired
	if invitation.ExpiresAt != nil && time.Now().After(*invitation.ExpiresAt) {
		invitation.Status = "expired"
		database.DB.Save(&invitation)
		c.JSON(http.StatusGone, gin.H{"error": "Invitation has expired"})
		return
	}

	// Verify user email matches invitation
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.Email != invitation.Email {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invitation is for a different email"})
		return
	}

	// Create organization member
	now := time.Now()
	member := models.OrganizationMember{
		OrganizationID: invitation.OrganizationID,
		UserID:         userID,
		Role:           invitation.Role,
		Status:         "active",
		JoinedAt:       &now,
	}

	if err := database.DB.Create(&member).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add member"})
		return
	}

	// Update invitation status
	invitation.Status = "accepted"
	database.DB.Save(&invitation)

	c.JSON(http.StatusOK, gin.H{
		"message": "Invitation accepted successfully",
		"member":  member,
	})
}

// HandleRevokeInvitation revokes a pending invitation
func HandleRevokeInvitation(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	inviteID := c.Param("id")

	var invitation models.Invitation
	if err := database.DB.Where("id = ? AND organization_id = ?", inviteID, orgID).First(&invitation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invitation not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invitation"})
		}
		return
	}

	invitation.Status = "revoked"
	if err := database.DB.Save(&invitation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke invitation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Invitation revoked successfully",
	})
}

// HandleRemoveMember removes a member from the organization
func HandleRemoveMember(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	memberID := c.Param("id")

	result := database.DB.Where("id = ? AND organization_id = ?", memberID, orgID).Delete(&models.OrganizationMember{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove member"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Member not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Member removed successfully",
	})
}

// HandleUpdateMemberRole updates a member's role
func HandleUpdateMemberRole(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	memberID := c.Param("id")

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var member models.OrganizationMember
	if err := database.DB.Where("id = ? AND organization_id = ?", memberID, orgID).First(&member).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Member not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch member"})
		}
		return
	}

	member.Role = req.Role
	if err := database.DB.Save(&member).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update member role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Member role updated successfully",
		"member":  member,
	})
}

