package billing

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// HandleGetPlans returns all active billing plans
func HandleGetPlans(c *gin.Context) {
	var plans []models.Plan
	if err := database.DB.Where("active = ?", true).Find(&plans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch plans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

// HandleGetCurrentSubscription returns the user's current subscription
func HandleGetCurrentSubscription(c *gin.Context) {
	userID := c.GetUint("user_id")
	var organization models.Organization
	if err := database.DB.Where("owner_id = ?", userID).Order("id DESC").First(&organization).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	var subscription models.Subscription
	if err := database.DB.Preload("Plan").Where("organization_id = ?", organization.ID).First(&subscription).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active subscription"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"subscription": subscription})
}

// HandleGetInvoices returns billing invoices for the organization
func HandleGetInvoices(c *gin.Context) {
	userID := c.GetUint("user_id")
	var organization models.Organization
	if err := database.DB.Where("owner_id = ?", userID).Order("id DESC").First(&organization).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	var invoices []models.Invoice
	if err := database.DB.Where("organization_id = ?", organization.ID).Order("created_at DESC").Find(&invoices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invoices"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"invoices": invoices})
}

// HandleGetPaymentMethods returns payment methods for the organization
func HandleGetPaymentMethods(c *gin.Context) {
	userID := c.GetUint("user_id")
	var organization models.Organization
	if err := database.DB.Where("owner_id = ?", userID).Order("id DESC").First(&organization).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	var paymentMethods []models.PaymentMethod
	if err := database.DB.Where("organization_id = ?", organization.ID).Find(&paymentMethods).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch payment methods"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payment_methods": paymentMethods})
}

// HandleGetPlanComparison returns a comparison of all available plans
func HandleGetPlanComparison(c *gin.Context) {
	var plans []models.Plan
	if err := database.DB.Where("active = ?", true).Order("price ASC").Find(&plans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch plans"})
		return
	}

	// Format plans for comparison
	comparison := make([]gin.H, len(plans))
	for i, plan := range plans {
		comparison[i] = gin.H{
			"id":                  plan.ID,
			"name":                plan.Name,
			"display_name":        plan.DisplayName,
			"description":         plan.Description,
			"price":               plan.Price,
			"interval":            plan.Interval,
			"max_clusters":        plan.MaxClusters,
			"max_users":           plan.MaxUsers,
			"max_session_minutes": plan.MaxSessionMinutes,
			"features":            plan.Features,
			"trial_days":          plan.TrialDays,
			"recommended":         plan.DisplayName == "Professional", // Pro plan recommended
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"plans":      comparison,
		"currency":   "usd",
		"trial_days": 14,
	})
}

// TODO: The following handlers require Stripe integration and are more complex:
// - HandleCreateSubscription (requires Stripe customer creation, payment method attach, subscription creation)
// - HandleCancelSubscription (requires Stripe subscription cancellation)
// - HandleAddPaymentMethod (requires Stripe payment method operations)
// - HandleDeletePaymentMethod (requires Stripe payment method detach)
// - HandleSetDefaultPaymentMethod (requires Stripe customer update)
// - HandleChangeSubscriptionPlan (requires Stripe subscription update)
//
// These will be implemented when we create a proper billing service layer with Stripe integration.

