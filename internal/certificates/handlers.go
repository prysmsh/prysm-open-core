package certificates

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleGetKubernetesCA returns the Kubernetes CA certificate
func HandleGetKubernetesCA(c *gin.Context) {
	// TODO: Return actual CA certificate
	c.JSON(http.StatusOK, gin.H{
		"ca_certificate": "placeholder-ca-cert",
		"message":        "CA certificate",
	})
}

