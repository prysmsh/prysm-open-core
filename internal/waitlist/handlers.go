package waitlist

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleJoinWaitlist adds a user to the waitlist
func HandleJoinWaitlist(c *gin.Context) {
	var req struct {
		Email       string `json:"email" binding:"required,email"`
		Name        string `json:"name"`
		Company     string `json:"company"`
		UseCase     string `json:"use_case"`
		ReferralSource string `json:"referral_source"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if already on waitlist
	var existing models.Waitlist
	if err := database.DB.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "You're already on the waitlist",
			"status":  existing.Status,
		})
		return
	}

	waitlistEntry := models.Waitlist{
		Email:    req.Email,
		Name:     req.Name,
		Company:  req.Company,
		UseCase:  req.UseCase,
		Referral: req.ReferralSource,
		Status:   "pending",
	}

	if err := database.DB.Create(&waitlistEntry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to join waitlist"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Successfully joined the waitlist",
		"entry":   waitlistEntry,
	})
}

// HandleListWaitlist returns all waitlist entries (admin only)
func HandleListWaitlist(c *gin.Context) {
	status := c.DefaultQuery("status", "")

	query := database.DB.Model(&models.Waitlist{}).Order("created_at DESC")
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var entries []models.Waitlist
	if err := query.Find(&entries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch waitlist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   len(entries),
	})
}

// HandleApproveWaitlistUser approves a waitlist user (admin only)
func HandleApproveWaitlistUser(c *gin.Context) {
	id := c.Param("id")

	var entry models.Waitlist
	if err := database.DB.Where("id = ?", id).First(&entry).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Waitlist entry not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch waitlist entry"})
		}
		return
	}

	entry.Status = "approved"
	if err := database.DB.Save(&entry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve user"})
		return
	}

	// TODO: Send approval email with invitation link

	c.JSON(http.StatusOK, gin.H{
		"message": "User approved successfully",
		"entry":   entry,
	})
}

// HandleRejectWaitlistUser rejects a waitlist user (admin only)
func HandleRejectWaitlistUser(c *gin.Context) {
	id := c.Param("id")

	var entry models.Waitlist
	if err := database.DB.Where("id = ?", id).First(&entry).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Waitlist entry not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch waitlist entry"})
		}
		return
	}

	entry.Status = "rejected"
	if err := database.DB.Save(&entry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reject user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User rejected",
		"entry":   entry,
	})
}

