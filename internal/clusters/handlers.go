package clusters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
	"prysm-backend/internal/tokens"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var (
	errAgentTokenMissing    = errors.New("agent token missing")
	errAgentTokenInvalid    = errors.New("agent token invalid")
	errAgentTokenExpired    = errors.New("agent token expired")
	errAgentTokenForbidden  = errors.New("agent token forbidden")
	errAgentTokenPermission = errors.New("agent token missing permission")
	errClusterNotFound      = errors.New("cluster not found")
	errInvalidClusterID     = errors.New("invalid cluster id")
)

var allowedClusterStatuses = map[string]struct{}{
	"connected":    {},
	"connecting":   {},
	"degraded":     {},
	"disconnected": {},
	"error":        {},
	"pending":      {},
	"updating":     {},
}

const (
	agentPermissionPing       = "ping"
	agentPermissionUpdateData = "update_data"
)

// HandleList returns all clusters for the current organization
func HandleList(c *gin.Context) {
	organizationID := c.GetUint("organization_id")

	var clusters []models.Cluster
	if err := database.DB.Where("organization_id = ?", organizationID).Find(&clusters).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to fetch clusters",
			"details": err.Error(),
		})
		return
	}

	// Load mesh peers for clusters
	peerByCluster := make(map[uint]models.MeshPeer)
	var meshPeers []models.MeshPeer
	if err := database.DB.Where("organization_id = ? AND cluster_id IS NOT NULL", organizationID).Find(&meshPeers).Error; err != nil {
		log.Printf("Failed to load mesh peers for organization %d: %v", organizationID, err)
	} else {
		for _, peer := range meshPeers {
			if peer.ClusterID != nil {
				peerCopy := peer
				peerByCluster[*peer.ClusterID] = peerCopy
			}
		}
	}

	// Convert to response format
	var clusterList []gin.H
	for _, cluster := range clusters {
		clusterData := gin.H{
			"id":               cluster.ID,
			"name":             cluster.Name,
			"description":      cluster.Description,
			"status":           cluster.Status,
			"created_at":       cluster.CreatedAt,
			"last_data_update": cluster.LastDataUpdate,
			"organization_id":  cluster.OrganizationID,
		}

		// Add last ping info if available
		if cluster.LastPing != nil {
			clusterData["last_ping"] = cluster.LastPing
		}

		// Exit router configuration
		clusterData["is_exit_router"] = cluster.IsExitRouter
		clusterData["exit_priority"] = cluster.ExitPriority
		clusterData["exit_regions"] = cluster.ExitRegions.ToSlice()
		clusterData["exit_notes"] = cluster.ExitNotes
		if cluster.ExitPeerID != nil {
			clusterData["exit_peer_id"] = cluster.ExitPeerID
		}
		if cluster.ExitUpdatedAt != nil {
			clusterData["exit_updated_at"] = cluster.ExitUpdatedAt
		}

		// WireGuard overlay configuration
		if strings.TrimSpace(cluster.WGOverlayCIDR) != "" {
			clusterData["wg_overlay_cidr"] = cluster.WGOverlayCIDR
			clusterData["wg_public_key_set"] = strings.TrimSpace(cluster.WGPublicKey) != ""
			if cluster.WGUpdatedAt != nil {
				clusterData["wg_updated_at"] = cluster.WGUpdatedAt
			}
		}

		// Exit CIDRs
		if cluster.ExitCIDRs != nil {
			var exitCIDRs []string
			if err := json.Unmarshal(cluster.ExitCIDRs, &exitCIDRs); err != nil {
				log.Printf("Failed to parse exit CIDRs for cluster %d: %v", cluster.ID, err)
				exitCIDRs = []string{}
			}
			clusterData["exit_cidrs"] = exitCIDRs
		} else {
			clusterData["exit_cidrs"] = []string{}
		}

		// Exit health data
		if cluster.ExitLastHealth != nil {
			var healthData interface{}
			if err := json.Unmarshal(cluster.ExitLastHealth, &healthData); err != nil {
				log.Printf("Failed to parse exit health for cluster %d: %v", cluster.ID, err)
			} else {
				clusterData["exit_last_health"] = healthData
			}
		}

		// Cluster info
		clusterInfo := parseClusterInfoJSON(cluster.ClusterInfo)
		if clusterInfo != nil {
			clusterData["cluster_info"] = clusterInfo
		}

		// Services
		serviceCount := 0
		if services := parseServicesJSON(cluster.Services); services != nil {
			clusterData["services"] = services
			serviceCount = len(services)
		} else {
			clusterData["services"] = map[string]interface{}{}
		}

		if clusterInfo != nil {
			if val, ok := numericToInt(clusterInfo["service_count"]); ok && val > serviceCount {
				serviceCount = val
			}
			if _, exists := clusterInfo["service_count"]; !exists {
				clusterInfo["service_count"] = serviceCount
			}
		}

		clusterData["service_count"] = serviceCount

		// Add mesh peer if exists
		if peer, ok := peerByCluster[cluster.ID]; ok {
			clusterData["mesh_peer"] = peer
		}

		clusterList = append(clusterList, clusterData)
	}

	c.JSON(http.StatusOK, gin.H{"clusters": clusterList})
}

// HandleGet returns a single cluster by ID
func HandleGet(c *gin.Context) {
	organizationID := c.GetUint("organization_id")
	clusterIDParam := c.Param("id")

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to fetch cluster",
				"details": err.Error(),
			})
		}
		return
	}

	// Build response with all cluster data
	clusterData := gin.H{
		"id":               cluster.ID,
		"name":             cluster.Name,
		"description":      cluster.Description,
		"status":           cluster.Status,
		"namespace":        cluster.Namespace,
		"is_exit_router":   cluster.IsExitRouter,
		"created_at":       cluster.CreatedAt,
		"updated_at":       cluster.UpdatedAt,
		"last_data_update": cluster.LastDataUpdate,
		"organization_id":  cluster.OrganizationID,
	}

	if cluster.LastPing != nil {
		clusterData["last_ping"] = cluster.LastPing
	}

	// Add cluster info if available
	if clusterInfo := parseClusterInfoJSON(cluster.ClusterInfo); clusterInfo != nil {
		clusterData["cluster_info"] = clusterInfo
	}

	// Add services if available
	if services := parseServicesJSON(cluster.Services); services != nil {
		clusterData["services"] = services
	}

	c.JSON(http.StatusOK, clusterData)
}

// HandleUpdate updates a cluster's information
func HandleUpdate(c *gin.Context) {
	organizationID := c.GetUint("organization_id")
	clusterIDParam := c.Param("id")

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	var req struct {
		Name        *string           `json:"name"`
		Description *string           `json:"description"`
		Labels      map[string]string `json:"labels"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find cluster
	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cluster"})
		}
		return
	}

	// Update fields if provided
	updates := make(map[string]interface{})
	if req.Name != nil && *req.Name != "" {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}

	if len(updates) > 0 {
		if err := database.DB.Model(&cluster).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update cluster",
				"details": err.Error(),
			})
			return
		}
	}

	// Reload cluster to get updated values
	if err := database.DB.First(&cluster, clusterID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload cluster"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          cluster.ID,
		"name":        cluster.Name,
		"description": cluster.Description,
		"status":      cluster.Status,
		"namespace":   cluster.Namespace,
		"created_at":  cluster.CreatedAt,
		"updated_at":  cluster.UpdatedAt,
	})
}

// HandleCreate creates a new cluster
func HandleCreate(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	organizationID := c.GetUint("organization_id")

	// TODO: Check if organization can create another cluster (quota check)
	// if err := trackClusterCreation(organizationID); err != nil {
	// 	c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	// 	return
	// }

	// Create cluster record
	cluster := models.Cluster{
		Name:           req.Name,
		Description:    req.Description,
		OrganizationID: organizationID,
		Status:         "pending",
	}

	if err := database.DB.Create(&cluster).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cluster"})
		return
	}

	// Create mesh peer entry for DERP connectivity
	clusterIDPtr := &cluster.ID
	meshPeer := models.MeshPeer{
		ClusterID:      clusterIDPtr,
		OrganizationID: organizationID,
		DeviceID:       fmt.Sprintf("cluster-%d", cluster.ID),
		DERPClientID:   fmt.Sprintf("derp-cluster-%d", cluster.ID),
		PeerType:       "cluster",
		Status:         "pending",
	}
	if err := database.DB.Create(&meshPeer).Error; err != nil {
		log.Printf("Failed to create mesh peer for cluster %d: %v", cluster.ID, err)
	}

	// Generate agent token for cluster authentication (embedding org ID)
	token, tokenHash, err := tokens.GenerateOrgScopedToken(organizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate agent token"})
		return
	}
	agentToken := models.AgentToken{
		Name:           fmt.Sprintf("Agent for %s", cluster.Name),
		TokenHash:      tokenHash,
		TokenPrefix:    token[:8],
		ClusterID:      clusterIDPtr,
		OrganizationID: organizationID,
		Permissions:    []string{"ping", "register", "update_data"},
		Active:         true,
	}
	if err := database.DB.Create(&agentToken).Error; err != nil {
		log.Printf("Failed to create agent token for cluster %d: %v", cluster.ID, err)
	}

	// Persist token hash on cluster for quick lookup
	if err := database.DB.Model(&cluster).Update("agent_token", tokenHash).Error; err != nil {
		log.Printf("Failed to persist agent token hash on cluster %d: %v", cluster.ID, err)
	} else {
		cluster.AgentTokenHash = tokenHash
	}

	// Get DERP URL
	derpURL := os.Getenv("DERP_URL")
	if derpURL == "" {
		derpURL = "https://derp.prysm.sh:8443"
	}

	// Provide friendlier onboarding context for agents
	agentAPIBase := database.GetEnvDefault("AGENT_API_BASE_URL", "")
	if agentAPIBase == "" {
		agentAPIBase = "https://api.prysm.sh/api/v1"
	}
	agentAPIBase = strings.TrimSuffix(agentAPIBase, "/")

	clusterBaseURL := fmt.Sprintf("%s/clusters/%d", agentAPIBase, cluster.ID)
	endpoints := map[string]string{
		"ping":    fmt.Sprintf("%s/ping", clusterBaseURL),
		"metrics": fmt.Sprintf("%s/metrics", clusterBaseURL),
		"data":    fmt.Sprintf("%s/data", clusterBaseURL),
	}

	agentDownloadURL := database.GetEnvDefault("AGENT_DOWNLOAD_URL", "https://downloads.prysm.sh/agent/latest")
	setupNotes := []string{
		fmt.Sprintf("Set PRYSM_CLUSTER_ID=%d in your agent configuration.", cluster.ID),
		"Store the agent token securely. It is shown only once.",
		fmt.Sprintf("Agents should reach the API at %s unless overridden.", agentAPIBase),
		"Restart the agent after updating its configuration so it begins reporting telemetry.",
	}
	sampleEnv := fmt.Sprintf("PRYSM_CLUSTER_ID=%d\nPRYSM_AGENT_TOKEN=%s\nPRYSM_API_BASE=%s\n", cluster.ID, token, agentAPIBase)
	curlExample := fmt.Sprintf("curl -sSf -X POST %q -H 'Content-Type: application/json' -d '{\"status\":\"connected\"}'", endpoints["ping"])

	c.JSON(http.StatusCreated, gin.H{
		"message": "Cluster registered successfully",
		"cluster": gin.H{
			"id":                 cluster.ID,
			"name":               cluster.Name,
			"description":        cluster.Description,
			"status":             cluster.Status,
			"wg_overlay_cidr":    cluster.WGOverlayCIDR,
			"mesh_device_id":     meshPeer.DeviceID,
			"created_at":         cluster.CreatedAt,
			"agent_token_prefix": token[:8],
		},
		"onboarding": gin.H{
			"token":              token,
			"token_prefix":       token[:8],
			"token_warning":      "Store this token securely. You will not be able to view it again.",
			"api_base_url":       agentAPIBase,
			"cluster_endpoints":  endpoints,
			"derp_url":           derpURL,
			"agent_download_url": agentDownloadURL,
			"setup_notes":        setupNotes,
			"sample_environment": sampleEnv,
			"curl_check":         curlExample,
		},
	})
}

// HandleDelete deletes a cluster
func HandleDelete(c *gin.Context) {
	clusterID := c.Param("id")

	// TODO: Implement actual deletion logic
	// - Remove from database
	// - Clean up WireGuard configs
	// - Remove mesh peers
	// - Clean up any associated resources

	c.JSON(http.StatusOK, gin.H{
		"message":    "Cluster deleted successfully",
		"cluster_id": clusterID,
	})
}

// HandleRegisterCluster handles agent-initiated cluster registration (from main.go)
func HandleRegisterCluster(c *gin.Context) {
	var req struct {
		ClusterName string                 `json:"cluster_name" binding:"required"`
		AgentToken  string                 `json:"agent_token" binding:"required"`
		AgentType   string                 `json:"agent_type"`
		ClusterInfo map[string]interface{} `json:"cluster_info"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the provided token
	hash := sha256.Sum256([]byte(req.AgentToken))
	tokenHash := hex.EncodeToString(hash[:])

	tokenPrefix := req.AgentToken
	if len(req.AgentToken) >= 8 {
		tokenPrefix = req.AgentToken[:8]
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
		return
	}

	// Check if a cluster with this name already exists for this organization
	var existingCluster models.Cluster
	err = database.DB.Where("name = ? AND organization_id = ?",
		req.ClusterName, agentToken.OrganizationID).First(&existingCluster).Error

	if err == nil {
		// Cluster already exists, return its info
		c.JSON(http.StatusOK, gin.H{
			"message":    "Cluster already registered",
			"cluster_id": existingCluster.ID,
			"status":     existingCluster.Status,
		})
		return
	}

	// Create new cluster
	newCluster := models.Cluster{
		Name:           req.ClusterName,
		OrganizationID: agentToken.OrganizationID,
		Status:         "pending",
	}

	if err := database.DB.Create(&newCluster).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cluster"})
		return
	}

	// Associate agent token with this cluster for future validation
	if agentToken.ClusterID == nil || *agentToken.ClusterID != newCluster.ID {
		if err := database.DB.Model(&agentToken).Update("cluster_id", newCluster.ID).Error; err != nil {
			log.Printf("Failed to associate agent token %d with cluster %d: %v", agentToken.ID, newCluster.ID, err)
		}
	}

	// Store the token hash on the cluster for quick lookups
	if err := database.DB.Model(&newCluster).Update("agent_token", tokenHash).Error; err != nil {
		log.Printf("Failed to persist agent token hash on cluster %d: %v", newCluster.ID, err)
	}

	// Create a mesh peer for the cluster
	clusterID := newCluster.ID
	meshPeer := models.MeshPeer{
		OrganizationID: agentToken.OrganizationID,
		ClusterID:      &clusterID,
		DeviceID:       fmt.Sprintf("cluster-%d", newCluster.ID),
		DERPClientID:   fmt.Sprintf("derp-cluster-%d", newCluster.ID),
		PeerType:       "cluster",
		Status:         "pending",
	}

	if err := database.DB.Create(&meshPeer).Error; err != nil {
		log.Printf("Failed to create mesh peer for cluster %d: %v", newCluster.ID, err)
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":         "Cluster registered successfully",
		"cluster_id":      newCluster.ID,
		"organization_id": agentToken.OrganizationID,
		"status":          newCluster.Status,
	})
}

// HandleUpdateClusterStatus updates cluster status via agent ping (from main.go)
func HandleUpdateClusterStatus(c *gin.Context) {
	clusterID := c.Param("id")

	var req struct {
		Status     string `json:"status"`
		AgentToken string `json:"agent_token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cluster, agentToken, err := validateAgentTokenForCluster(clusterID, req.AgentToken, agentPermissionPing)
	if err != nil {
		handleAgentTokenError(c, err)
		return
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "connected"
	}
	if _, ok := allowedClusterStatuses[status]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster status"})
		return
	}

	now := time.Now().UTC()
	lastPing := now
	updatePayload := map[string]interface{}{
		"status":    status,
		"last_ping": &lastPing,
	}

	if err := database.DB.Model(cluster).Updates(updatePayload).Error; err != nil {
		log.Printf("Failed to update cluster %d status: %v", cluster.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster status"})
		return
	}

	if err := markAgentTokenUsed(agentToken); err != nil {
		log.Printf("Failed to record agent token usage: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Cluster status updated",
		"cluster_id": cluster.ID,
		"status":     status,
		"timestamp":  now,
	})
}

// HandleUpdateClusterExitRouter updates exit router configuration (from main.go)
func HandleUpdateClusterExitRouter(c *gin.Context) {
	clusterID := c.Param("id")
	orgID := c.GetUint("organization_id")

	var req struct {
		Enable       *bool     `json:"enable"`
		ExitPriority *int      `json:"exit_priority"`
		ExitRegions  *[]string `json:"exit_regions"`
		ExitCIDRs    *[]string `json:"exit_cidrs"`
		ExitNotes    *string   `json:"exit_notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement exit router configuration
	c.JSON(http.StatusOK, gin.H{
		"message":    "Exit router configuration updated",
		"cluster_id": clusterID,
		"org_id":     orgID,
	})
}

// HandleDisableClusterExitRouter disables exit router for a cluster (from main.go)
func HandleDisableClusterExitRouter(c *gin.Context) {
	clusterID := c.Param("id")
	orgID := c.GetUint("organization_id")

	// TODO: Disable exit router
	c.JSON(http.StatusOK, gin.H{
		"message":    "Exit router disabled",
		"cluster_id": clusterID,
		"org_id":     orgID,
	})
}

// HandleUpdateClusterData handles agent-initiated cluster data update (from main.go)
func HandleUpdateClusterData(c *gin.Context) {
	clusterID := c.Param("id")

	var req struct {
		AgentToken  string                   `json:"agent_token"`
		ClusterInfo map[string]interface{}   `json:"cluster_info"`
		Services    map[string]interface{}   `json:"services"`
		Metrics     []map[string]interface{} `json:"metrics"`
		Timestamp   string                   `json:"timestamp"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cluster, agentToken, err := validateAgentTokenForCluster(clusterID, req.AgentToken, agentPermissionUpdateData)
	if err != nil {
		handleAgentTokenError(c, err)
		return
	}

	updatePayload := make(map[string]interface{})

	if len(req.ClusterInfo) > 0 {
		payload, err := json.Marshal(req.ClusterInfo)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster_info payload"})
			return
		}
		updatePayload["cluster_info"] = models.JSON(payload)
	}

	if len(req.Services) > 0 {
		payload, err := json.Marshal(req.Services)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid services payload"})
			return
		}
		updatePayload["services"] = models.JSON(payload)
	}

	if len(req.Metrics) > 0 {
		payload, err := json.Marshal(req.Metrics)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metrics payload"})
			return
		}
		updatePayload["metrics"] = models.JSON(payload)
	}

	timestamp := time.Now().UTC()
	if req.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, req.Timestamp); err == nil {
			timestamp = parsed
		}
	}
	updatePayload["last_data_update"] = &timestamp
	updatePayload["last_ping"] = &timestamp

	if err := database.DB.Model(cluster).Updates(updatePayload).Error; err != nil {
		log.Printf("Failed to update cluster %d data: %v", cluster.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster data"})
		return
	}

	if err := markAgentTokenUsed(agentToken); err != nil {
		log.Printf("Failed to record agent token usage: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Cluster data updated successfully",
		"cluster_id": cluster.ID,
		"updated_at": timestamp,
	})
}

func validateAgentTokenForCluster(clusterIDParam, rawToken, requiredPermission string) (*models.Cluster, *models.AgentToken, error) {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return nil, nil, errAgentTokenMissing
	}

	if database.DB == nil {
		return nil, nil, fmt.Errorf("database not initialized")
	}

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		return nil, nil, errInvalidClusterID
	}

	var cluster models.Cluster
	if err := database.DB.First(&cluster, clusterID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errClusterNotFound
		}
		return nil, nil, fmt.Errorf("query cluster: %w", err)
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	tokenPrefix := token
	if len(token) >= 8 {
		tokenPrefix = token[:8]
	}

	var agentToken models.AgentToken
	if err := database.DB.Where("token_prefix = ? AND token_hash = ? AND active = ?", tokenPrefix, tokenHash, true).
		First(&agentToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errAgentTokenInvalid
		}
		return nil, nil, fmt.Errorf("query agent token: %w", err)
	}

	if agentToken.ExpiresAt != nil && time.Now().After(*agentToken.ExpiresAt) {
		return nil, nil, errAgentTokenExpired
	}

	if agentToken.OrganizationID != cluster.OrganizationID {
		return nil, nil, errAgentTokenForbidden
	}

	if agentToken.ClusterID != nil && *agentToken.ClusterID != cluster.ID {
		return nil, nil, errAgentTokenForbidden
	}

	if requiredPermission != "" && !tokenHasPermission(agentToken.Permissions, requiredPermission) {
		return nil, nil, errAgentTokenPermission
	}

	return &cluster, &agentToken, nil
}

func markAgentTokenUsed(agentToken *models.AgentToken) error {
	if agentToken == nil || database.DB == nil {
		return nil
	}
	now := time.Now().UTC()
	agentToken.LastUsedAt = &now
	return database.DB.Model(agentToken).Update("last_used_at", now).Error
}

func handleAgentTokenError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errInvalidClusterID):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
	case errors.Is(err, errClusterNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
	case errors.Is(err, errAgentTokenMissing):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent token is required"})
	case errors.Is(err, errAgentTokenInvalid):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive agent token"})
	case errors.Is(err, errAgentTokenExpired):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Agent token has expired"})
	case errors.Is(err, errAgentTokenForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "Agent token not authorized for this cluster"})
	case errors.Is(err, errAgentTokenPermission):
		c.JSON(http.StatusForbidden, gin.H{"error": "Agent token lacks required permission"})
	default:
		log.Printf("Agent token validation failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to validate agent token"})
	}
}

func tokenHasPermission(perms models.StringArray, required string) bool {
	if required == "" {
		return true
	}

	for _, perm := range perms {
		if strings.EqualFold(strings.TrimSpace(perm), required) {
			return true
		}
	}
	return false
}

// Helper functions

func parseClusterInfoJSON(data []byte) map[string]interface{} {
	if data == nil || len(data) == 0 {
		return nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

func parseServicesJSON(data []byte) map[string]interface{} {
	if data == nil || len(data) == 0 {
		return nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

func numericToInt(val interface{}) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	default:
		return 0, false
	}
}

// ExitRouterRequest represents exit router configuration
type ExitRouterRequest struct {
	Enable       *bool                  `json:"enable"`
	ExitPriority *int                   `json:"exit_priority"`
	ExitRegions  *[]string              `json:"exit_regions"`
	ExitCIDRs    *[]string              `json:"exit_cidrs"`
	ExitNotes    *string                `json:"exit_notes"`
	Capabilities map[string]interface{} `json:"capabilities"`
	Status       *string                `json:"status"`
}

// HandleUpdateExitRouter configures a cluster as an exit router
func HandleUpdateExitRouter(c *gin.Context) {
	var req ExitRouterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Enable == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enable field is required"})
		return
	}

	organizationID := c.GetUint("organization_id")
	clusterIDParam := c.Param("id")

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	// Find cluster
	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cluster"})
		}
		return
	}

	// Update exit router configuration
	updates := make(map[string]interface{})
	updates["is_exit_router"] = *req.Enable

	if req.ExitPriority != nil {
		updates["exit_priority"] = *req.ExitPriority
	}
	if req.ExitRegions != nil {
		updates["exit_regions"] = *req.ExitRegions
	}
	if req.ExitNotes != nil {
		updates["exit_notes"] = *req.ExitNotes
	}
	if req.ExitCIDRs != nil {
		cidrsJSON, _ := json.Marshal(*req.ExitCIDRs)
		updates["exit_cidrs"] = cidrsJSON
	}

	if err := database.DB.Model(&cluster).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update exit router configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Exit router configuration updated",
		"cluster_id":     cluster.ID,
		"is_exit_router": *req.Enable,
	})
}

// HandleDisableExitRouter disables exit router for a cluster
func HandleDisableExitRouter(c *gin.Context) {
	organizationID := c.GetUint("organization_id")
	clusterIDParam := c.Param("id")

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cluster"})
		}
		return
	}

	// Disable exit router
	updates := map[string]interface{}{
		"is_exit_router": false,
		"exit_priority":  0,
	}

	if err := database.DB.Model(&cluster).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable exit router"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Exit router disabled successfully",
		"cluster_id": cluster.ID,
	})
}

// HandleUpdateStatus updates a cluster's status (agent heartbeat)
func HandleUpdateStatus(c *gin.Context) {
	organizationID := c.GetUint("organization_id")
	clusterIDParam := c.Param("id")

	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	var req struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cluster"})
		}
		return
	}

	// Update status
	updates := map[string]interface{}{
		"status": req.Status,
	}

	if err := database.DB.Model(&cluster).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Cluster status updated successfully",
		"status":  req.Status,
	})
}

// HandleUpdateData updates cluster data from agent (comprehensive update)
func HandleUpdateData(c *gin.Context) {
	clusterIDParam := c.Param("id")

	var req struct {
		AgentToken  string                 `json:"agent_token" binding:"required"`
		ClusterInfo map[string]interface{} `json:"cluster_info"`
		Services    map[string]interface{} `json:"services"`
		Status      string                 `json:"status"`
		Namespace   string                 `json:"namespace"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cluster, agentToken, err := validateAgentTokenForCluster(clusterIDParam, req.AgentToken, agentPermissionUpdateData)
	if err != nil {
		handleAgentTokenError(c, err)
		return
	}

	// Update cluster data
	now := time.Now().UTC()
	updates := map[string]interface{}{
		"last_ping":        &now,
		"last_data_update": &now,
	}

	if req.Status != "" {
		status := strings.ToLower(strings.TrimSpace(req.Status))
		if _, ok := allowedClusterStatuses[status]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster status"})
			return
		}
		updates["status"] = status
		cluster.Status = status
	}
	if req.Namespace != "" {
		namespace := strings.TrimSpace(req.Namespace)
		updates["namespace"] = namespace
		cluster.Namespace = namespace
	}
	if req.ClusterInfo != nil {
		clusterInfoJSON, err := json.Marshal(req.ClusterInfo)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster_info payload"})
			return
		}
		updates["cluster_info"] = models.JSON(clusterInfoJSON)
	}
	if req.Services != nil {
		servicesJSON, err := json.Marshal(req.Services)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid services payload"})
			return
		}
		updates["services"] = models.JSON(servicesJSON)
	}

	if err := database.DB.Model(cluster).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster data"})
		return
	}

	if err := markAgentTokenUsed(agentToken); err != nil {
		log.Printf("Failed to record agent token usage: %v", err)
	}

	responseStatus := cluster.Status
	if status, ok := updates["status"].(string); ok && status != "" {
		responseStatus = status
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Cluster data updated successfully",
		"cluster_id": cluster.ID,
		"status":     responseStatus,
		"updated_at": now,
	})
}

// HandleGetAnalytics returns analytics data for a cluster
func HandleGetAnalytics(c *gin.Context) {
	clusterIDParam := c.Param("id")
	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	organizationID := c.GetUint("organization_id")

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}

	// TODO: Implement actual analytics aggregation
	// For now, return basic cluster info
	analytics := gin.H{
		"cluster_id":   cluster.ID,
		"cluster_name": cluster.Name,
		"status":       cluster.Status,
		"uptime":       "N/A",
		"requests":     0,
		"errors":       0,
		"latency_p50":  0,
		"latency_p95":  0,
		"latency_p99":  0,
	}

	c.JSON(http.StatusOK, analytics)
}

// HandleGetServices returns services running in a cluster
func HandleGetServices(c *gin.Context) {
	clusterIDParam := c.Param("id")
	clusterID, err := strconv.ParseUint(clusterIDParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	organizationID := c.GetUint("organization_id")

	var cluster models.Cluster
	if err := database.DB.Where("id = ? AND organization_id = ?", clusterID, organizationID).First(&cluster).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}

	// Parse services from cluster
	services := parseServicesJSON(cluster.Services)
	if services == nil {
		services = map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_id": cluster.ID,
		"services":   services,
	})
}
