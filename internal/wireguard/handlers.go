package wireguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

const (
	defaultWireguardCIDR        = "100.64.0.0/16"
	defaultWireguardDNS         = "100.64.0.1"
	defaultWireguardMTU         = 1420
	defaultWireguardKeepalive   = 15
	wireguardReservedHostOffset = 10
)

var (
	errInvalidCIDR         = errors.New("invalid wireguard cidr")
	errAddressExhausted    = errors.New("wireguard address space exhausted")
	errInvalidDeviceData   = errors.New("invalid wireguard device data")
	errDeviceUnauthorized  = errors.New("wireguard device belongs to another user")
	errOrganizationMissing = errors.New("organization context missing")
)

// HandleRegisterDevice registers a new WireGuard device for the authenticated user.
func HandleRegisterDevice(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")
	if orgID == 0 || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
		return
	}

	var req registerDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := req.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settings := loadWireguardSettings()

	var (
		device *models.WireguardDevice
	)
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var txErr error
		device, txErr = upsertWireguardDevice(tx, orgID, userID, req, settings)
		return txErr
	})
	if err != nil {
		handleWireguardError(c, err)
		return
	}

	if err := persistDeviceVaultRecord(device); err != nil {
		log.Printf("WireGuard vault sync failed: %v", err)
	}

	resp, err := buildWireguardResponse(device, orgID, settings)
	if err != nil {
		handleWireguardError(c, err)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// HandleGetConfig returns WireGuard configuration for a device owned by the user.
func HandleGetConfig(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")
	if orgID == 0 || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
		return
	}

	deviceID := strings.TrimSpace(c.Query("device_id"))
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id query parameter is required"})
		return
	}

	device, err := findWireguardDevice(orgID, userID, deviceID, hasAdminRole(c))
	if err != nil {
		handleWireguardError(c, err)
		return
	}

	resp, err := buildWireguardResponse(device, orgID, loadWireguardSettings())
	if err != nil {
		handleWireguardError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// HandleRotateDevice rotates the public key for a device and returns updated config.
func HandleRotateDevice(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")
	if orgID == 0 || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
		return
	}

	deviceID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || deviceID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device id"})
		return
	}

	var req rotateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if len(req.PublicKey) < 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public_key must be provided"})
		return
	}

	var device models.WireguardDevice
	if err := database.DB.First(&device, deviceID).Error; err != nil {
		handleWireguardError(c, err)
		return
	}

	if device.OrganizationID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "device not part of your organization"})
		return
	}

	if device.UserID != userID && !hasAdminRole(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "device belongs to another user"})
		return
	}

	updates := map[string]interface{}{
		"public_key":     req.PublicKey,
		"config_version": gorm.Expr("config_version + 1"),
		"status":         "active",
		"updated_at":     time.Now(),
	}

	if err := database.DB.Model(&device).Updates(updates).Error; err != nil {
		handleWireguardError(c, err)
		return
	}

	if err := database.DB.First(&device, deviceID).Error; err != nil {
		handleWireguardError(c, err)
		return
	}

	if err := persistDeviceVaultRecord(&device); err != nil {
		log.Printf("WireGuard vault sync failed: %v", err)
	}

	resp, err := buildWireguardResponse(&device, orgID, loadWireguardSettings())
	if err != nil {
		handleWireguardError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// HandleDeleteDevice removes a WireGuard device.
func HandleDeleteDevice(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")
	if orgID == 0 || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
		return
	}

	deviceID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || deviceID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device id"})
		return
	}

	var device models.WireguardDevice
	if err := database.DB.First(&device, deviceID).Error; err != nil {
		handleWireguardError(c, err)
		return
	}

	if device.OrganizationID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "device not part of your organization"})
		return
	}

	if device.UserID != userID && !hasAdminRole(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "device belongs to another user"})
		return
	}

	if err := database.DB.Delete(&models.WireguardDevice{}, deviceID).Error; err != nil {
		handleWireguardError(c, err)
		return
	}

	if err := deleteDeviceVaultSecret(device.VaultPath); err != nil {
		log.Printf("WireGuard vault cleanup failed: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "device revoked",
		"device_id": deviceID,
	})
}

// --- request types ----------------------------------------------------------------

type registerDeviceRequest struct {
	DeviceID     string                 `json:"device_id" binding:"required"`
	PublicKey    string                 `json:"public_key" binding:"required"`
	Capabilities map[string]interface{} `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
}

func (r *registerDeviceRequest) validate() error {
	r.DeviceID = strings.TrimSpace(r.DeviceID)
	r.PublicKey = strings.TrimSpace(r.PublicKey)

	if r.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if len(r.DeviceID) > 128 {
		return errors.New("device_id too long")
	}
	if len(r.PublicKey) < 32 {
		return errors.New("public_key appears invalid")
	}
	return nil
}

type rotateDeviceRequest struct {
	PublicKey string `json:"public_key" binding:"required"`
}

// --- response objects -------------------------------------------------------------

type wireguardDeviceDTO struct {
	ID            uint    `json:"id"`
	DeviceID      string  `json:"device_id"`
	PublicKey     string  `json:"public_key"`
	Address       string  `json:"address"`
	Status        string  `json:"status"`
	ConfigVersion uint64  `json:"config_version"`
	VaultPath     string  `json:"vault_path"`
	LastSeenAt    *string `json:"last_seen_at,omitempty"`
}

type wireguardClientConfigDTO struct {
	Address                string   `json:"address"`
	CIDR                   string   `json:"cidr"`
	DNS                    []string `json:"dns"`
	MTU                    int      `json:"mtu"`
	PersistentKeepaliveSec int      `json:"persistent_keepalive"`
	GeneratedAt            string   `json:"generated_at"`
}

type wireguardPeerDTO struct {
	Name                    string   `json:"name"`
	PublicKey               string   `json:"public_key"`
	Endpoint                string   `json:"endpoint"`
	AllowedIPs              []string `json:"allowed_ips"`
	DERPRegion              string   `json:"derp_region"`
	PersistentKeepaliveSecs int      `json:"persistent_keepalive"`
}

type wireguardConfigResponse struct {
	Device   wireguardDeviceDTO       `json:"device"`
	Config   wireguardClientConfigDTO `json:"config"`
	Peers    []wireguardPeerDTO       `json:"peers"`
	Warnings []string                 `json:"warnings"`
	Tunnel   *wireguardTunnelInfo     `json:"tunnel,omitempty"`
}

type wireguardTunnelInfo struct {
	URL            string   `json:"url"`
	Mode           string   `json:"mode"`
	OrganizationID uint     `json:"organization_id"`
	Notes          []string `json:"notes,omitempty"`
}

// --- core helpers ----------------------------------------------------------------

func upsertWireguardDevice(tx *gorm.DB, orgID, userID uint, req registerDeviceRequest, settings wireguardSettings) (*models.WireguardDevice, error) {
	var device models.WireguardDevice
	err := tx.Where("organization_id = ? AND device_id = ?", orgID, req.DeviceID).First(&device).Error
	if err == nil {
		updates := map[string]interface{}{
			"public_key":     req.PublicKey,
			"status":         "active",
			"config_version": gorm.Expr("config_version + 1"),
			"updated_at":     time.Now(),
		}

		if capabilities, err := marshalOptionalMap(req.Capabilities); err == nil && capabilities != nil {
			updates["capabilities"] = capabilities
		}
		if metadata, err := marshalOptionalMap(req.Metadata); err == nil && metadata != nil {
			updates["metadata"] = metadata
		}

		if err := tx.Model(&device).Updates(updates).Error; err != nil {
			return nil, err
		}
		if err := tx.Where("id = ?", device.ID).First(&device).Error; err != nil {
			return nil, err
		}
		return &device, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	allocation, err := getOrCreateAllocation(tx, orgID, userID, settings.CIDR)
	if err != nil {
		return nil, err
	}

	ip, err := allocateAddress(tx, allocation)
	if err != nil {
		return nil, err
	}

	device = models.WireguardDevice{
		OrganizationID: orgID,
		UserID:         userID,
		DeviceID:       req.DeviceID,
		PublicKey:      req.PublicKey,
		Address:        ip,
		Status:         "active",
		ConfigVersion:  1,
		VaultPath:      fmt.Sprintf("secret/wireguard/org-%d/device/%s", orgID, sanitizeDeviceID(req.DeviceID)),
	}

	if capabilities, err := marshalOptionalMap(req.Capabilities); err == nil {
		device.Capabilities = capabilities
	}
	if metadata, err := marshalOptionalMap(req.Metadata); err == nil {
		device.Metadata = metadata
	}

	if err := tx.Create(&device).Error; err != nil {
		return nil, err
	}

	return &device, nil
}

func findWireguardDevice(orgID, userID uint, deviceID string, allowOrgWide bool) (*models.WireguardDevice, error) {
	var device models.WireguardDevice
	query := database.DB.Where("organization_id = ? AND device_id = ?", orgID, deviceID)
	if err := query.First(&device).Error; err != nil {
		return nil, err
	}

	if device.UserID != userID && !allowOrgWide {
		return nil, errDeviceUnauthorized
	}

	return &device, nil
}

func buildWireguardResponse(device *models.WireguardDevice, orgID uint, settings wireguardSettings) (*wireguardConfigResponse, error) {
	allocation, err := getAllocationRecord(orgID)
	if err != nil {
		return nil, err
	}

	peers, peerWarnings, err := listWireguardPeers(orgID, settings)
	if err != nil {
		return nil, err
	}

	address := strings.TrimSpace(device.Address)
	if address == "" {
		return nil, errInvalidDeviceData
	}

	lastSeen := (*string)(nil)
	if device.LastSeenAt != nil {
		formatted := device.LastSeenAt.UTC().Format(time.RFC3339)
		lastSeen = &formatted
	}

	resp := &wireguardConfigResponse{
		Device: wireguardDeviceDTO{
			ID:            device.ID,
			DeviceID:      device.DeviceID,
			PublicKey:     device.PublicKey,
			Address:       address,
			Status:        device.Status,
			ConfigVersion: device.ConfigVersion,
			VaultPath:     device.VaultPath,
			LastSeenAt:    lastSeen,
		},
		Config: wireguardClientConfigDTO{
			Address:                fmt.Sprintf("%s/32", address),
			CIDR:                   allocation.CIDR,
			DNS:                    settings.DNS,
			MTU:                    settings.MTU,
			PersistentKeepaliveSec: settings.Keepalive,
			GeneratedAt:            time.Now().UTC().Format(time.RFC3339),
		},
		Peers:    peers,
		Warnings: peerWarnings,
	}

	if tunnelURL := tunnelEndpointURL(); tunnelURL != "" {
		resp.Tunnel = &wireguardTunnelInfo{
			URL:            tunnelURL,
			Mode:           "websocket",
			OrganizationID: orgID,
			Notes: []string{
				"Run `prysm mesh proxy` to bridge WireGuard over HTTPS when UDP is blocked.",
			},
		}
	}

	return resp, nil
}

// --- allocation helpers ----------------------------------------------------------

func getOrCreateAllocation(tx *gorm.DB, orgID, userID uint, cidr string) (*models.WireguardAllocation, error) {
	var allocation models.WireguardAllocation
	err := tx.Where("organization_id = ?", orgID).First(&allocation).Error
	if err == nil {
		return &allocation, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	firstHost, _, err := cidrBounds(cidr)
	if err != nil {
		return nil, err
	}

	allocation = models.WireguardAllocation{
		OrganizationID: orgID,
		CIDR:           cidr,
		NextIP:         uint64(firstHost),
	}
	if userID > 0 {
		allocation.UpdatedBy = &userID
	}

	if err := tx.Create(&allocation).Error; err != nil {
		return nil, err
	}

	return &allocation, nil
}

func allocateAddress(tx *gorm.DB, allocation *models.WireguardAllocation) (string, error) {
	var locked models.WireguardAllocation
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", allocation.ID).First(&locked).Error; err != nil {
		return "", err
	}

	current := locked.NextIP
	if current == 0 {
		firstHost, _, err := cidrBounds(locked.CIDR)
		if err != nil {
			return "", err
		}
		current = uint64(firstHost)
	}

	_, lastHost, err := cidrBounds(locked.CIDR)
	if err != nil {
		return "", err
	}

	if current > uint64(lastHost) {
		return "", errAddressExhausted
	}

	ip := uintToIP(uint32(current))
	locked.LastIssuedIP = ip
	locked.NextIP = current + 1
	if err := tx.Save(&locked).Error; err != nil {
		return "", err
	}

	*allocation = locked
	return ip, nil
}

func getAllocationRecord(orgID uint) (*models.WireguardAllocation, error) {
	if orgID == 0 {
		return nil, errOrganizationMissing
	}
	var allocation models.WireguardAllocation
	if err := database.DB.Where("organization_id = ?", orgID).First(&allocation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("wireguard not provisioned for organization")
		}
		return nil, err
	}
	return &allocation, nil
}

// --- peers -----------------------------------------------------------------------

func listWireguardPeers(orgID uint, settings wireguardSettings) ([]wireguardPeerDTO, []string, error) {
	var relays []models.WireguardRelay
	if err := database.DB.
		Where("organization_id = ? OR organization_id IS NULL", orgID).
		Find(&relays).Error; err != nil {
		return nil, nil, err
	}

	if len(relays) == 0 {
		return nil, []string{"No WireGuard relays available; contact Prysm support to configure mesh relays."}, nil
	}

	peers := make([]wireguardPeerDTO, 0, len(relays))
	for _, relay := range relays {
		allowed := jsonToStringSlice(relay.AllowedIPs)
		if len(allowed) == 0 {
			allowed = []string{settings.CIDR}
		}
		endpoint := relay.Endpoint
		if endpoint == "" && relay.Hostname != "" {
			endpoint = fmt.Sprintf("%s:%d", relay.Hostname, relay.Port)
		}
		if endpoint == "" {
			endpoint = "mesh.prysm.sh:51820"
		}
		peer := wireguardPeerDTO{
			Name:                    relay.Name,
			PublicKey:               relay.PublicKey,
			Endpoint:                endpoint,
			AllowedIPs:              allowed,
			DERPRegion:              fallback(relay.DERPRegion, "global"),
			PersistentKeepaliveSecs: settings.Keepalive,
		}
		peers = append(peers, peer)
	}

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})
	return peers, nil, nil
}

// --- utility helpers -------------------------------------------------------------

type wireguardSettings struct {
	CIDR      string
	DNS       []string
	MTU       int
	Keepalive int
}

func loadWireguardSettings() wireguardSettings {
	cidr := fallback(strings.TrimSpace(os.Getenv("WIREGUARD_DEFAULT_CIDR")), defaultWireguardCIDR)

	dnsEnv := strings.TrimSpace(os.Getenv("WIREGUARD_DNS_SERVERS"))
	dns := []string{defaultWireguardDNS}
	if dnsEnv != "" {
		var cleaned []string
		for _, part := range strings.Split(dnsEnv, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				cleaned = append(cleaned, trimmed)
			}
		}
		if len(cleaned) > 0 {
			dns = cleaned
		}
	}

	mtu := parseEnvInt("WIREGUARD_MTU", defaultWireguardMTU)
	keepalive := parseEnvInt("WIREGUARD_KEEPALIVE", defaultWireguardKeepalive)

	return wireguardSettings{
		CIDR:      cidr,
		DNS:       dns,
		MTU:       mtu,
		Keepalive: keepalive,
	}
}

func parseEnvInt(key string, fallbackVal int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallbackVal
	}
	if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
		return parsed
	}
	return fallbackVal
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func marshalOptionalMap(values map[string]interface{}) (models.JSON, error) {
	if len(values) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return models.JSON(data), nil
}

func jsonToStringSlice(data models.JSON) []string {
	if len(data) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func sanitizeDeviceID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	var b strings.Builder
	for _, r := range id {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	result := b.String()
	return strings.Trim(result, "-")
}

func hasAdminRole(c *gin.Context) bool {
	if roleVal, exists := c.Get("role"); exists {
		if role, ok := roleVal.(string); ok {
			return role == "admin"
		}
	}
	return false
}

func handleWireguardError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
	case errors.Is(err, errDeviceUnauthorized):
		c.JSON(http.StatusForbidden, gin.H{"error": "device belongs to another user"})
	case errors.Is(err, errOrganizationMissing):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context missing"})
	case errors.Is(err, errInvalidCIDR):
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wireguard configuration invalid"})
	case errors.Is(err, errAddressExhausted):
		c.JSON(http.StatusConflict, gin.H{"error": "wireguard address pool exhausted"})
	case errors.Is(err, errInvalidDeviceData):
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wireguard device missing required data"})
	default:
		log.Printf("WireGuard handler error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal WireGuard error"})
	}
}

func persistDeviceVaultRecord(device *models.WireguardDevice) error {
	if device == nil || strings.TrimSpace(device.VaultPath) == "" {
		return nil
	}

	updatedAt := device.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now()
	}

	payload := map[string]interface{}{
		"device_id":       device.DeviceID,
		"public_key":      device.PublicKey,
		"address":         device.Address,
		"status":          device.Status,
		"config_version":  device.ConfigVersion,
		"organization_id": device.OrganizationID,
		"user_id":         device.UserID,
		"updated_at":      updatedAt.UTC().Format(time.RFC3339),
	}

	if !device.CreatedAt.IsZero() {
		payload["created_at"] = device.CreatedAt.UTC().Format(time.RFC3339)
	}

	if device.LastSeenAt != nil {
		payload["last_seen_at"] = device.LastSeenAt.UTC().Format(time.RFC3339)
	}
	if caps := jsonToGenericMap(device.Capabilities); len(caps) > 0 {
		payload["capabilities"] = caps
	}
	if meta := jsonToGenericMap(device.Metadata); len(meta) > 0 {
		payload["metadata"] = meta
	}

	return writeVaultSecret(device.VaultPath, payload)
}

func deleteDeviceVaultSecret(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	addr, token, ok := vaultConnectionInfo()
	if !ok {
		return nil
	}

	dataPath := buildVaultDataPath(path)
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/%s", addr, dataPath), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("vault delete %s: %s", dataPath, resp.Status)
	}

	metadataPath := buildVaultMetadataPath(path)
	reqMeta, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/%s", addr, metadataPath), nil)
	if err == nil {
		reqMeta.Header.Set("X-Vault-Token", token)
		if respMeta, err := client.Do(reqMeta); err == nil {
			io.Copy(io.Discard, respMeta.Body)
			respMeta.Body.Close()
		}
	}

	return nil
}

func writeVaultSecret(path string, data map[string]interface{}) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	addr, token, ok := vaultConnectionInfo()
	if !ok {
		return nil
	}

	payload := map[string]interface{}{
		"data": data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	dataPath := buildVaultDataPath(path)
	url := fmt.Sprintf("%s/v1/%s", addr, dataPath)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("vault write %s: %s %s", dataPath, resp.Status, strings.TrimSpace(string(msg)))
	}

	return nil
}

func vaultConnectionInfo() (string, string, bool) {
	if strings.EqualFold(os.Getenv("VAULT_ENABLED"), "false") {
		return "", "", false
	}

	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	if addr == "" {
		return "", "", false
	}

	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		if tokenFile := strings.TrimSpace(os.Getenv("VAULT_TOKEN_FILE")); tokenFile != "" {
			if data, err := os.ReadFile(tokenFile); err == nil {
				token = strings.TrimSpace(string(data))
			}
		}
	}
	if token == "" {
		return "", "", false
	}

	return addr, token, true
}

func buildVaultDataPath(secretPath string) string {
	secretPath = strings.TrimPrefix(secretPath, "/")
	if strings.Contains(secretPath, "/data/") {
		return secretPath
	}
	parts := strings.SplitN(secretPath, "/", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s/data/%s", parts[0], parts[1])
	}
	return fmt.Sprintf("secret/data/%s", secretPath)
}

func buildVaultMetadataPath(secretPath string) string {
	secretPath = strings.TrimPrefix(secretPath, "/")
	if strings.Contains(secretPath, "/metadata/") {
		return secretPath
	}
	parts := strings.SplitN(secretPath, "/", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s/metadata/%s", parts[0], parts[1])
	}
	return fmt.Sprintf("secret/metadata/%s", secretPath)
}

func jsonToGenericMap(data models.JSON) map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func tunnelEndpointURL() string {
	if strings.EqualFold(os.Getenv("DERP_TUNNEL_ENABLED"), "false") {
		return ""
	}
	if url := strings.TrimSpace(os.Getenv("DERP_TUNNEL_URL")); url != "" {
		return url
	}
	if base := strings.TrimSpace(os.Getenv("API_BASE_URL")); base != "" {
		return strings.TrimRight(base, "/") + "/api/v1/mesh/derp/tunnel"
	}
	return ""
}

// --- CIDR helpers ----------------------------------------------------------------

func cidrBounds(cidr string) (uint32, uint32, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, errInvalidCIDR
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return 0, 0, errInvalidCIDR
	}
	totalHosts := uint32(1 << (bits - ones))
	if totalHosts < 4 {
		return 0, 0, errInvalidCIDR
	}
	base := ipToUint(network.IP)
	first := base + uint32(wireguardReservedHostOffset)
	if first <= base {
		first = base + 1
	}
	last := base + totalHosts - 2
	if last <= base {
		return 0, 0, errInvalidCIDR
	}
	if first > last {
		first = base + 1
	}
	return first, last, nil
}

func ipToUint(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uintToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(v>>24)&0xFF,
		(v>>16)&0xFF,
		(v>>8)&0xFF,
		v&0xFF,
	)
}
