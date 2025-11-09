package billing

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleCreateSubscription creates a new subscription (from billing.go)
func HandleCreateSubscription(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		PlanID          uint   `json:"plan_id" binding:"required"`
		PaymentMethodID string `json:"payment_method_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement Stripe subscription creation
	c.JSON(http.StatusCreated, gin.H{
		"message": "Subscription created successfully",
		"org_id":  orgID,
	})
}

// HandleCancelSubscription cancels a subscription (from billing.go)
func HandleCancelSubscription(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	// TODO: Implement Stripe subscription cancellation
	c.JSON(http.StatusOK, gin.H{
		"message": "Subscription cancelled successfully",
		"org_id":  orgID,
	})
}

// HandleChangeSubscriptionPlan changes subscription plan (from billing.go)
func HandleChangeSubscriptionPlan(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		NewPlanID uint `json:"new_plan_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement plan change
	c.JSON(http.StatusOK, gin.H{
		"message": "Subscription plan changed successfully",
		"org_id":  orgID,
	})
}

// HandleAddPaymentMethod adds a payment method (from billing.go)
func HandleAddPaymentMethod(c *gin.Context) {
	orgID := c.GetUint("organization_id")

	var req struct {
		PaymentMethodID string `json:"payment_method_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement adding payment method via Stripe
	c.JSON(http.StatusCreated, gin.H{
		"message": "Payment method added successfully",
		"org_id":  orgID,
	})
}

// HandleDeletePaymentMethod deletes a payment method (from billing.go)
func HandleDeletePaymentMethod(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	pmID := c.Param("id")

	// TODO: Implement payment method deletion
	c.JSON(http.StatusOK, gin.H{
		"message": "Payment method deleted successfully",
		"pm_id":   pmID,
		"org_id":  orgID,
	})
}

// HandleSetDefaultPaymentMethod sets default payment method (from billing.go)
func HandleSetDefaultPaymentMethod(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	pmID := c.Param("id")

	// TODO: Implement setting default payment method
	c.JSON(http.StatusOK, gin.H{
		"message": "Default payment method updated",
		"pm_id":   pmID,
		"org_id":  orgID,
	})
}

