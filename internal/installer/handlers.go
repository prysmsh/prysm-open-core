package installer

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleServeAgentInstaller serves the agent installer script
func HandleServeAgentInstaller(c *gin.Context) {
	// TODO: Serve actual installer script
	installerScript := `#!/bin/bash
# Prysm Agent Installer
echo "Installing Prysm Agent..."
# Installation logic here
`

	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, installerScript)
}

