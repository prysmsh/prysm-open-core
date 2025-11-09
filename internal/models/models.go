package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type User struct {
	ID                  uint       `json:"id" gorm:"primaryKey"`
	Email               string     `json:"email" gorm:"uniqueIndex"`
	Password            string     `json:"-"`
	Name                string     `json:"name"`
	Role                string     `json:"role" gorm:"default:'user'"`
	Active              bool       `json:"active" gorm:"default:true"`
	EmailVerified       bool       `json:"email_verified" gorm:"default:false"`
	EmailVerifyToken    string     `json:"-"`
	PasswordResetToken  string     `json:"-"`
	PasswordResetExpiry *time.Time `json:"-"`
	StripeCustomerID    string     `json:"-"`
	TrialEndsAt         *time.Time `json:"trial_ends_at"`
	FailedLoginAttempts int        `json:"-" gorm:"default:0"`
	LockedUntil         *time.Time `json:"-"`
	LastFailedLogin     *time.Time `json:"-"`
	// MFA fields
	MFAEnabled     bool        `json:"mfa_enabled" gorm:"default:false"`
	MFASecret      string      `json:"-"`
	MFABackupCodes StringArray `json:"-" gorm:"type:text[]"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

type Organization struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	OwnerID          uint      `json:"owner_id" gorm:"index"`
	StripeCustomerID string    `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	// Note: All relationships removed temporarily to fix migration order
	// Will add back relationships once tables are created
}

// TokenBlacklist represents blacklisted JWT tokens
type TokenBlacklist struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	TokenHash string    `json:"-" gorm:"uniqueIndex;not null"`
	UserID    uint      `json:"user_id" gorm:"index"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason" gorm:"default:'logout'"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentToken represents secure, organization-scoped agent tokens
type AgentToken struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name"`
	TokenHash      string       `json:"-" gorm:"uniqueIndex"`      // SHA-256 hash of the token
	TokenPrefix    string       `json:"token_prefix" gorm:"index"` // First 8 chars for identification
	OrganizationID uint         `json:"organization_id" gorm:"index"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	ClusterID      *uint        `json:"cluster_id"` // Optional: bind to specific cluster
	Cluster        *Cluster     `json:"cluster,omitempty" gorm:"foreignKey:ClusterID"`
	Permissions    StringArray  `json:"permissions" gorm:"type:text[]"` // e.g., ["ping", "register", "update_data"]
	ExpiresAt      *time.Time   `json:"expires_at"`
	LastUsedAt     *time.Time   `json:"last_used_at"`
	Active         bool         `json:"active"`
	CreatedBy      uint         `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type Cluster struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	Config         string       `json:"-"`
	Status         string       `json:"status" gorm:"default:'disconnected'"`
	Namespace      string       `json:"namespace" gorm:"default:'default'"`
	OrganizationID uint         `json:"organization_id" gorm:"index"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	AgentTokenHash string       `json:"-" gorm:"column:agent_token;index"` // Stores SHA-256 hash of the agent token
	AgentToken     string       `json:"agent_token,omitempty" gorm:"-"`
	LastPing       *time.Time   `json:"last_ping"`
	LastSeen       *time.Time   `json:"last_seen" gorm:"-"`
	IsExitRouter   bool         `json:"is_exit_router" gorm:"default:false"`
	ExitPeerID     *uint        `json:"exit_peer_id" gorm:"index"`
	ExitPriority   int          `json:"exit_priority" gorm:"default:100"`
	ExitRegions    StringArray  `json:"exit_regions" gorm:"type:text[]"`
	ExitCIDRs      JSON         `json:"exit_cidrs,omitempty" gorm:"type:json"`
	ExitNotes      string       `json:"exit_notes"`
	ExitLastHealth JSON         `json:"exit_last_health,omitempty" gorm:"type:json"`
	ExitUpdatedAt  *time.Time   `json:"exit_updated_at"`

	// Agent data
	ClusterInfo    JSON       `json:"cluster_info,omitempty" gorm:"type:json"`
	Services       JSON       `json:"services,omitempty" gorm:"type:json"`
	Metrics        JSON       `json:"metrics,omitempty" gorm:"type:json"`
	LastDataUpdate *time.Time `json:"last_data_update"`

	// Security and validation
	RequiredLabels map[string]string `json:"required_labels" gorm:"type:jsonb;serializer:json"` // Labels that must be present
	AllowedIPs     StringArray       `json:"allowed_ips" gorm:"type:text[]"`                    // IP whitelist for agent access

	// WireGuard overlay configuration
	WGPublicKey   string     `json:"wg_public_key" gorm:"column:wg_public_key;size:128"`
	WGOverlayCIDR string     `json:"wg_overlay_cidr" gorm:"column:wg_overlay_cidr;size:64"`
	WGListenPort  *int       `json:"wg_listen_port" gorm:"column:wg_listen_port"`
	WGPeers       JSON       `json:"wg_peers,omitempty" gorm:"column:wg_peers;type:json"`
	WGConfigHash  string     `json:"wg_config_hash" gorm:"column:wg_config_hash;size:128"`
	WGUpdatedAt   *time.Time `json:"wg_updated_at" gorm:"column:wg_updated_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an interactive access session against a managed resource
type Session struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	UserID         *uint     `json:"user_id,omitempty" gorm:"index"`
	ClusterID      *uint     `json:"cluster_id,omitempty" gorm:"index"`
	OrganizationID uint      `json:"organization_id" gorm:"index"`
	SessionID      string    `json:"session_id" gorm:"uniqueIndex"`
	Status         string    `json:"status" gorm:"default:'active'"`
	StartTime      time.Time `json:"start_time"`
	EndTime        *time.Time
	Duration       int64  `json:"duration" gorm:"default:0"`
	MinutesUsed    int64  `json:"minutes_used" gorm:"default:0"`
	CommandsRun    int64  `json:"commands_run" gorm:"default:0"`
	RecordingPath  string `json:"recording_path"`
	CredentialType string `json:"credential_type" gorm:"size:64"`
	CredentialRef  string `json:"credential_ref" gorm:"size:255"`
	VaultLeaseID   string `json:"vault_lease_id" gorm:"size:255"`
	VaultPath      string `json:"vault_path" gorm:"size:255"`
	ExpiresAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TableName ensures gorm uses the existing sessions table name.
func (Session) TableName() string {
	return "sessions"
}

// MeshPeer represents any node (cluster agent or client device) participating in the mesh network
type MeshPeer struct {
	ID             uint        `json:"id" gorm:"primaryKey"`
	OrganizationID uint        `json:"organization_id" gorm:"index"`
	ClusterID      *uint       `json:"cluster_id" gorm:"index"`
	UserID         *uint       `json:"user_id" gorm:"index"`
	DeviceID       string      `json:"device_id" gorm:"index"`
	DERPClientID   string      `json:"derp_client_id" gorm:"index;size:255"`
	PeerType       string      `json:"peer_type" gorm:"default:'client';index"`
	Status         string      `json:"status" gorm:"default:'disconnected'"`
	Capabilities   JSON        `json:"capabilities,omitempty" gorm:"type:json"`
	ExitEnabled    bool        `json:"exit_enabled" gorm:"default:false"`
	ExitPriority   int         `json:"exit_priority" gorm:"default:100"`
	ExitRegions    StringArray `json:"exit_regions" gorm:"type:text[]"`
	ExitCIDRs      JSON        `json:"exit_cidrs,omitempty" gorm:"type:json"`
	ExitNotes      string      `json:"exit_notes"`
	LastPing       *time.Time  `json:"last_ping"`
	LastSeen       *time.Time  `json:"last_seen" gorm:"-"`
	LastHealth     JSON        `json:"last_health,omitempty" gorm:"type:json"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// WireguardDevice represents an enrolled WireGuard-capable client.
type WireguardDevice struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	OrganizationID uint         `json:"organization_id" gorm:"index"`
	Organization   Organization `json:"-" gorm:"foreignKey:OrganizationID"`
	UserID         uint         `json:"user_id" gorm:"index"`
	User           User         `json:"-" gorm:"foreignKey:UserID"`
	DeviceID       string       `json:"device_id" gorm:"index;size:128"`
	PublicKey      string       `json:"public_key" gorm:"size:256"`
	Address        string       `json:"address" gorm:"size:64"`
	Status         string       `json:"status" gorm:"default:'active'"`
	ConfigVersion  uint64       `json:"config_version" gorm:"default:1"`
	VaultPath      string       `json:"vault_path" gorm:"size:255"`
	Capabilities   JSON         `json:"capabilities,omitempty" gorm:"type:json"`
	Metadata       JSON         `json:"metadata,omitempty" gorm:"type:json"`
	LastSeenAt     *time.Time   `json:"last_seen_at"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// WireguardAllocation keeps track of IP space usage for an organization.
type WireguardAllocation struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	OrganizationID uint         `json:"organization_id" gorm:"uniqueIndex"`
	Organization   Organization `json:"-" gorm:"foreignKey:OrganizationID"`
	CIDR           string       `json:"cidr" gorm:"size:64"`
	NextIP         uint64       `json:"next_ip" gorm:"type:bigint"`
	LastIssuedIP   string       `json:"last_issued_ip" gorm:"size:64"`
	UpdatedBy      *uint        `json:"updated_by" gorm:"index"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// WireguardRelay stores DERP-backed relay metadata exposed to clients.
type WireguardRelay struct {
	ID             uint          `json:"id" gorm:"primaryKey"`
	OrganizationID *uint         `json:"organization_id" gorm:"index"`
	Organization   *Organization `json:"-" gorm:"foreignKey:OrganizationID"`
	Name           string        `json:"name" gorm:"size:128"`
	Region         string        `json:"region" gorm:"size:64"`
	PublicKey      string        `json:"public_key" gorm:"size:256"`
	Hostname       string        `json:"hostname" gorm:"size:255"`
	Port           int           `json:"port" gorm:"default:51820"`
	Endpoint       string        `json:"endpoint" gorm:"size:255"`
	AllowedIPs     JSON          `json:"allowed_ips,omitempty" gorm:"type:json"`
	DERPRegion     string        `json:"derp_region" gorm:"size:64"`
	HealthStatus   string        `json:"health_status" gorm:"default:'unknown'"`
	Metadata       JSON          `json:"metadata,omitempty" gorm:"type:json"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// DNS and Routing models for Magic DNS feature
type DNSRecord struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Hostname       string       `json:"hostname" gorm:"uniqueIndex"`
	ClusterID      uint         `json:"cluster_id"`
	Cluster        Cluster      `json:"cluster" gorm:"foreignKey:ClusterID"`
	ServiceName    string       `json:"service_name"`
	ServicePort    int          `json:"service_port"`
	Namespace      string       `json:"namespace" gorm:"default:'default'"`
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Type           string       `json:"type" gorm:"default:'CNAME'"` // A, CNAME, AAAA
	TTL            int          `json:"ttl" gorm:"default:300"`
	Active         bool         `json:"active"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type RoutingRule struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Hostname       string       `json:"hostname"`
	Path           string       `json:"path" gorm:"default:'/'"`
	ClusterID      uint         `json:"cluster_id"`
	Cluster        Cluster      `json:"cluster" gorm:"foreignKey:ClusterID"`
	ServiceName    string       `json:"service_name"`
	ServicePort    int          `json:"service_port"`
	ExternalPort   int          `json:"external_port"`
	InternalPort   int          `json:"internal_port"`
	Namespace      string       `json:"namespace" gorm:"default:'default'"`
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Protocol       string       `json:"protocol" gorm:"default:'HTTP'"`             // HTTP, HTTPS, TCP, UDP
	LoadBalancer   string       `json:"load_balancer" gorm:"default:'round-robin'"` // round-robin, least-conn, ip-hash
	HealthCheck    string       `json:"health_check"`                               // Health check URL
	Description    string       `json:"description"`
	TLSEnabled     bool         `json:"tls_enabled" gorm:"default:false"`
	TLSCert        string       `json:"tls_cert"`
	TLSKey         string       `json:"tls_key"`
	Active         bool         `json:"active" gorm:"default:true"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// SubdomainDelegation for subdomain delegation DNS management
type SubdomainDelegation struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	ParentDomain   string       `json:"parent_domain"` // e.g., "example.com"
	Subdomain      string       `json:"subdomain"`     // e.g., "kubeaccess"
	FullDomain     string       `json:"full_domain"`   // e.g., "kubeaccess.example.com"
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	NSRecords      StringArray  `json:"ns_records" gorm:"type:text[]"` // Name servers for the subdomain
	Active         bool         `json:"active" gorm:"default:true"`
	VerifiedAt     *time.Time   `json:"verified_at"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// DNSServer configuration for custom DNS server
type DNSServer struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name"`
	Host           string       `json:"host"` // DNS server hostname/IP
	Port           int          `json:"port" gorm:"default:53"`
	Protocol       string       `json:"protocol" gorm:"default:'UDP'"` // UDP, TCP, DoT, DoH
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Active         bool         `json:"active" gorm:"default:true"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// LogSink represents a managed log shipping configuration
type LogSink struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	OrganizationID uint       `json:"organization_id" gorm:"index"`
	ClusterID      *uint      `json:"cluster_id" gorm:"index"`
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	Mode           string     `json:"mode"`
	IngestURL      string     `json:"ingest_url"`
	TokenHash      string     `json:"-"`
	TokenPrefix    string     `json:"token_prefix"`
	Config         JSON       `json:"config" gorm:"type:json"`
	Status         string     `json:"status"`
	LastDeployedAt *time.Time `json:"last_deployed_at"`
	LastError      string     `json:"last_error"`
	CreatedBy      uint       `json:"created_by" gorm:"index"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Permission struct {
	ID         uint       `json:"id" gorm:"primaryKey"`
	UserID     uint       `json:"user_id"`
	User       User       `json:"user" gorm:"foreignKey:UserID"`
	ClusterID  uint       `json:"cluster_id"`
	Cluster    Cluster    `json:"cluster" gorm:"foreignKey:ClusterID"`
	Permission string     `json:"permission"`
	Namespace  string     `json:"namespace" gorm:"default:'*'"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type AuditLog struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	UserID     uint      `json:"user_id"`
	User       User      `json:"user" gorm:"foreignKey:UserID"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID uint      `json:"resource_id"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Timestamp  time.Time `json:"timestamp"`
	CreatedAt  time.Time `json:"created_at"`
}

// Subscription plans
type Plan struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	Name              string    `json:"name" gorm:"uniqueIndex"`
	DisplayName       string    `json:"display_name"`
	Description       string    `json:"description"`
	Price             int64     `json:"price"`                           // Price in cents
	Interval          string    `json:"interval" gorm:"default:'month'"` // month, year
	StripePriceID     string    `json:"stripe_price_id"`
	StripeProductID   string    `json:"stripe_product_id"`
	MaxClusters       int       `json:"max_clusters"`
	MaxUsers          int       `json:"max_users"`
	MaxSessionMinutes int       `json:"max_session_minutes"` // per month
	Features          Features  `json:"features" gorm:"type:jsonb"`
	Active            bool      `json:"active" gorm:"default:true"`
	TrialDays         int       `json:"trial_days" gorm:"default:14"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Features is a JSON field for plan features
type Features map[string]interface{}

// Value implements the driver.Valuer interface
func (f Features) Value() (driver.Value, error) {
	return json.Marshal(f)
}

// Scan implements the sql.Scanner interface
func (f *Features) Scan(value interface{}) error {
	if value == nil {
		*f = make(Features)
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, f)
	case string:
		return json.Unmarshal([]byte(v), f)
	default:
		return errors.New("cannot scan into Features")
	}
}

// StringArray is a custom type for PostgreSQL text[] arrays
type StringArray []string

// Value implements the driver.Valuer interface for StringArray
func (sa StringArray) Value() (driver.Value, error) {
	if len(sa) == 0 {
		return nil, nil
	}
	// Format as PostgreSQL array literal
	var quoted []string
	for _, s := range sa {
		quoted = append(quoted, `"`+strings.ReplaceAll(s, `"`, `\"`)+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}", nil
}

// Scan implements the sql.Scanner interface for StringArray
func (sa *StringArray) Scan(value interface{}) error {
	if value == nil {
		*sa = StringArray{}
		return nil
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			*sa = StringArray{}
			return nil
		}
		// Handle PostgreSQL array format: {item1,item2,item3}
		if strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}") {
			content := v[1 : len(v)-1] // Remove { and }
			if content == "" {
				*sa = StringArray{}
				return nil
			}
			rawEntries := strings.Split(content, ",")
			clean := make([]string, 0, len(rawEntries))
			for _, entry := range rawEntries {
				entry = strings.TrimSpace(entry)
				entry = strings.Trim(entry, `"`)
				entry = strings.ReplaceAll(entry, `\"`, `"`)
				clean = append(clean, entry)
			}
			*sa = StringArray(clean)
		} else {
			// Fallback for comma-separated format
			rawEntries := strings.Split(v, ",")
			clean := make([]string, 0, len(rawEntries))
			for _, entry := range rawEntries {
				entry = strings.TrimSpace(entry)
				entry = strings.Trim(entry, `"`)
				entry = strings.ReplaceAll(entry, `\"`, `"`)
				if entry != "" {
					clean = append(clean, entry)
				}
			}
			*sa = StringArray(clean)
		}
		return nil
	case []byte:
		if len(v) == 0 {
			*sa = StringArray{}
			return nil
		}
		return sa.Scan(string(v))
	default:
		return errors.New("cannot scan into StringArray")
	}
}

// ToSlice returns a copy of the underlying slice.
func (sa StringArray) ToSlice() []string {
	if len(sa) == 0 {
		return []string{}
	}
	out := make([]string, len(sa))
	copy(out, sa)
	return out
}

// JSON is a generic JSON field type
type JSON []byte

// Value implements the driver.Valuer interface
func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return []byte(j), nil
}

// Scan implements the sql.Scanner interface
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		*j = JSON(v)
		return nil
	case string:
		*j = JSON(v)
		return nil
	default:
		return errors.New("cannot scan into JSON")
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (j *JSON) UnmarshalJSON(data []byte) error {
	*j = JSON(data)
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (j JSON) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}
	return []byte(j), nil
}

// Subscription represents a customer subscription
type Subscription struct {
	ID                   uint         `json:"id" gorm:"primaryKey"`
	OrganizationID       uint         `json:"organization_id"`
	Organization         Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	PlanID               uint         `json:"plan_id"`
	Plan                 Plan         `json:"plan" gorm:"foreignKey:PlanID"`
	StripeSubscriptionID string       `json:"stripe_subscription_id" gorm:"uniqueIndex"`
	Status               string       `json:"status"` // active, canceled, incomplete, etc.
	CurrentPeriodStart   time.Time    `json:"current_period_start"`
	CurrentPeriodEnd     time.Time    `json:"current_period_end"`
	TrialStart           *time.Time   `json:"trial_start"`
	TrialEnd             *time.Time   `json:"trial_end"`
	CanceledAt           *time.Time   `json:"canceled_at"`

	// Dunning management fields
	PaymentFailureCount int        `json:"payment_failure_count" gorm:"default:0"`
	LastPaymentFailure  *time.Time `json:"last_payment_failure"`
	NextRetryDate       *time.Time `json:"next_retry_date"`
	GracePeriodEnd      *time.Time `json:"grace_period_end"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Invoice represents billing invoices
type Invoice struct {
	ID              uint         `json:"id" gorm:"primaryKey"`
	OrganizationID  uint         `json:"organization_id"`
	Organization    Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	SubscriptionID  uint         `json:"subscription_id"`
	Subscription    Subscription `json:"subscription" gorm:"foreignKey:SubscriptionID"`
	StripeInvoiceID string       `json:"stripe_invoice_id" gorm:"uniqueIndex"`
	Status          string       `json:"status"`      // paid, open, void, etc.
	AmountPaid      int64        `json:"amount_paid"` // in cents
	AmountDue       int64        `json:"amount_due"`  // in cents
	Subtotal        int64        `json:"subtotal"`    // in cents
	Total           int64        `json:"total"`       // in cents
	Tax             int64        `json:"tax"`         // in cents
	PeriodStart     time.Time    `json:"period_start"`
	PeriodEnd       time.Time    `json:"period_end"`
	DueDate         *time.Time   `json:"due_date"`
	PaidAt          *time.Time   `json:"paid_at"`
	InvoiceURL      string       `json:"invoice_url"`
	InvoicePDF      string       `json:"invoice_pdf"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

// UsageRecord tracks usage for billing
type UsageRecord struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	MetricType     string       `json:"metric_type"` // session_minutes, clusters, users
	Quantity       int64        `json:"quantity"`
	PeriodStart    time.Time    `json:"period_start"`
	PeriodEnd      time.Time    `json:"period_end"`
	CreatedAt      time.Time    `json:"created_at"`
}

// PaymentMethod represents customer payment methods
type PaymentMethod struct {
	ID                    uint         `json:"id" gorm:"primaryKey"`
	OrganizationID        uint         `json:"organization_id"`
	Organization          Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	StripePaymentMethodID string       `json:"stripe_payment_method_id" gorm:"uniqueIndex"`
	Type                  string       `json:"type"` // card, bank_account, etc.
	CardBrand             string       `json:"card_brand"`
	CardLast4             string       `json:"card_last4"`
	CardExpMonth          int          `json:"card_exp_month"`
	CardExpYear           int          `json:"card_exp_year"`
	IsDefault             bool         `json:"is_default" gorm:"default:false"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at"`
}

// OrganizationMember represents team members
type OrganizationMember struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	UserID         uint         `json:"user_id"`
	User           User         `json:"user" gorm:"foreignKey:UserID"`
	Role           string       `json:"role" gorm:"default:'member'"`   // owner, admin, member
	Status         string       `json:"status" gorm:"default:'active'"` // active, pending, suspended
	InvitedBy      uint         `json:"invited_by"`
	InvitedAt      *time.Time   `json:"invited_at"`
	JoinedAt       *time.Time   `json:"joined_at"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// Invitation for team members
type Invitation struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	OrganizationID uint         `json:"organization_id"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Email          string       `json:"email"`
	Role           string       `json:"role" gorm:"default:'member'"`
	Token          string       `json:"token" gorm:"uniqueIndex"`
	InvitedBy      uint         `json:"invited_by"`
	Inviter        User         `json:"inviter" gorm:"foreignKey:InvitedBy"`
	Status         string       `json:"status" gorm:"default:'pending'"` // pending, accepted, expired
	ExpiresAt      *time.Time   `json:"expires_at"`
	AcceptedAt     *time.Time   `json:"accepted_at"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// Analytics Models

// DataSource represents a log data source configuration
type DataSource struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name" gorm:"not null"`
	Description    string       `json:"description"`
	Type           string       `json:"type" gorm:"not null"` // logs, metrics, events, audit
	OrganizationID uint         `json:"organization_id" gorm:"index;not null"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Config         JSON         `json:"config" gorm:"type:json"`
	Status         string       `json:"status" gorm:"default:'active'"` // active, inactive, error
	CreatedBy      uint         `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	LastSyncAt     *time.Time   `json:"last_sync_at,omitempty"`
}

// Query represents a saved query configuration
type Query struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name" gorm:"not null"`
	Description    string       `json:"description"`
	DataSourceID   uint         `json:"data_source_id" gorm:"not null"`
	DataSource     DataSource   `json:"data_source" gorm:"foreignKey:DataSourceID"`
	OrganizationID uint         `json:"organization_id" gorm:"index;not null"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	QueryConfig    JSON         `json:"query_config" gorm:"type:json"`
	CreatedBy      uint         `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	LastExecutedAt *time.Time   `json:"last_executed_at,omitempty"`
	ExecutionCount int          `json:"execution_count" gorm:"default:0"`
}

// Dashboard represents a dashboard configuration
type Dashboard struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	Name           string       `json:"name" gorm:"not null"`
	Description    string       `json:"description"`
	OrganizationID uint         `json:"organization_id" gorm:"index;not null"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Config         JSON         `json:"config" gorm:"type:json"`
	IsPublic       bool         `json:"is_public" gorm:"default:false"`
	CreatedBy      uint         `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	LastViewedAt   *time.Time   `json:"last_viewed_at,omitempty"`
	ViewCount      int          `json:"view_count" gorm:"default:0"`
}

// Tracing and Log Correlation Models

// TraceRecord represents a distributed trace
type TraceRecord struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	TraceID        string       `json:"trace_id" gorm:"uniqueIndex;not null"`
	RequestID      string       `json:"request_id" gorm:"index"`
	OrganizationID uint         `json:"organization_id" gorm:"index;not null"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	UserID         *uint        `json:"user_id,omitempty" gorm:"index"`
	User           *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	SessionID      string       `json:"session_id,omitempty" gorm:"index"`
	Status         string       `json:"status" gorm:"default:'pending'"` // pending, success, error, partial
	StartTime      time.Time    `json:"start_time" gorm:"index"`
	EndTime        *time.Time   `json:"end_time,omitempty"`
	Duration       int64        `json:"duration"` // microseconds
	Services       StringArray  `json:"services" gorm:"type:text[]"`
	Tags           JSON         `json:"tags,omitempty" gorm:"type:json"`
	Metadata       JSON         `json:"metadata,omitempty" gorm:"type:json"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	Spans          []TraceSpan  `json:"spans,omitempty" gorm:"foreignKey:TraceID;references:TraceID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// TraceSpan represents a span within a trace
type TraceSpan struct {
	ID             uint         `json:"id" gorm:"primaryKey"`
	SpanID         string       `json:"span_id" gorm:"uniqueIndex;not null"`
	TraceID        string       `json:"trace_id" gorm:"index;not null"`
	ParentSpanID   *string      `json:"parent_span_id,omitempty" gorm:"index"`
	OrganizationID uint         `json:"organization_id" gorm:"index;not null"`
	Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	OperationName  string       `json:"operation_name" gorm:"not null"`
	ServiceName    string       `json:"service_name" gorm:"index;not null"`
	StartTime      time.Time    `json:"start_time" gorm:"index"`
	Duration       int64        `json:"duration"`                        // microseconds
	Status         string       `json:"status" gorm:"default:'success'"` // success, error, warning
	Tags           JSON         `json:"tags,omitempty" gorm:"type:json"`
	Logs           JSON         `json:"logs,omitempty" gorm:"type:json"`
	ClusterID      string       `json:"cluster_id,omitempty" gorm:"index"`
	Namespace      string       `json:"namespace,omitempty" gorm:"index"`
	Pod            string       `json:"pod,omitempty" gorm:"index"`
	Container      string       `json:"container,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// LogCorrelation represents correlated logs for a request
type LogCorrelation struct {
	ID               uint         `json:"id" gorm:"primaryKey"`
	TraceID          string       `json:"trace_id" gorm:"index;not null"`
	RequestID        string       `json:"request_id" gorm:"uniqueIndex;not null"`
	OrganizationID   uint         `json:"organization_id" gorm:"index;not null"`
	Organization     Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	UserID           *uint        `json:"user_id,omitempty" gorm:"index"`
	User             *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	SessionID        string       `json:"session_id,omitempty" gorm:"index"`
	Status           string       `json:"status" gorm:"default:'pending'"` // pending, success, error, partial
	StartTime        time.Time    `json:"start_time" gorm:"index"`
	EndTime          *time.Time   `json:"end_time,omitempty"`
	Duration         int64        `json:"duration"` // microseconds
	Services         StringArray  `json:"services" gorm:"type:text[]"`
	LogCount         int          `json:"log_count" gorm:"default:0"`
	ErrorCount       int          `json:"error_count" gorm:"default:0"`
	WarningCount     int          `json:"warning_count" gorm:"default:0"`
	CorrelatedLogs   JSON         `json:"correlated_logs,omitempty" gorm:"type:json"`
	StorageReference JSON         `json:"storage_reference,omitempty" gorm:"type:json"`
	Metadata         JSON         `json:"metadata,omitempty" gorm:"type:json"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

// Waitlist represents users waiting for approval
type Waitlist struct {
	ID         uint       `json:"id" gorm:"primaryKey"`
	Email      string     `json:"email" gorm:"uniqueIndex;not null"`
	Name       string     `json:"name"`
	Company    string     `json:"company"`
	UseCase    string     `json:"use_case"`
	Referral   string     `json:"referral_source"`
	Notes      string     `json:"notes"`
	Status     string     `json:"status" gorm:"default:'pending'"` // pending, approved, rejected
	Token      string     `json:"-" gorm:"uniqueIndex"`            // approval token
	ApprovedBy *uint      `json:"approved_by,omitempty"`           // admin user ID who approved
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	RejectedBy *uint      `json:"rejected_by,omitempty"` // admin user ID who rejected
	RejectedAt *time.Time `json:"rejected_at,omitempty"`
	AdminNotes string     `json:"admin_notes"` // internal admin notes
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// SecurityEvent represents a security event emitted by telemetry subsystems.
type SecurityEvent struct {
	ID             uint        `json:"id" gorm:"primaryKey"`
	OrganizationID uint        `json:"organization_id" gorm:"index"`
	Timestamp      time.Time   `json:"timestamp" gorm:"index"`
	Level          string      `json:"level"`
	Message        string      `json:"message"`
	Source         string      `json:"source"`
	Node           string      `json:"node"`
	Namespace      string      `json:"namespace"`
	Pod            string      `json:"pod"`
	Container      string      `json:"container"`
	Tags           StringArray `json:"tags" gorm:"type:text[]"`
	Metadata       JSON        `json:"metadata" gorm:"type:json"`
	CreatedAt      time.Time   `json:"created_at"`
}

// LogExportJob tracks asynchronous log export operations.
type LogExportJob struct {
	ID             string     `json:"id" gorm:"primaryKey"`
	CreatedBy      uint       `json:"created_by" gorm:"index"`
	UserID         uint       `json:"user_id" gorm:"index"`
	OrganizationID uint       `json:"organization_id" gorm:"index"`
	DataSourceID   uint       `json:"data_source_id" gorm:"index"`
	Status         string     `json:"status"`
	Format         string     `json:"format"`
	Filters        JSON       `json:"filters" gorm:"type:json"`
	Progress       int        `json:"progress"`
	TotalRecords   int        `json:"total_records"`
	FilePath       string     `json:"file_path"`
	FileSize       int64      `json:"file_size"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Error          string     `json:"error"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at"`
}

// LogAlert defines alerting rules for incoming log streams.
type LogAlert struct {
	ID                   uint       `json:"id" gorm:"primaryKey"`
	Name                 string     `json:"name" gorm:"not null"`
	Description          string     `json:"description"`
	UserID               uint       `json:"user_id" gorm:"index"`
	OrganizationID       uint       `json:"organization_id" gorm:"index"`
	DataSourceID         uint       `json:"data_source_id" gorm:"index"`
	Conditions           JSON       `json:"conditions" gorm:"type:json"`
	Severity             string     `json:"severity"`
	Threshold            int        `json:"threshold"`
	TimeWindow           int        `json:"time_window"`
	NotificationChannels JSON       `json:"notification_channels" gorm:"type:json"`
	Active               bool       `json:"active" gorm:"default:true"`
	CreatedBy            uint       `json:"created_by" gorm:"index"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	LastTriggered        *time.Time `json:"last_triggered"`
	TriggerCount         int        `json:"trigger_count"`
}

// LogAlertInstance captures alert trigger state over time.
type LogAlertInstance struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	AlertID        uint       `json:"alert_id" gorm:"index"`
	Alert          LogAlert   `json:"alert" gorm:"foreignKey:AlertID"`
	Status         string     `json:"status"`
	TriggerCount   int        `json:"trigger_count"`
	FirstTriggered time.Time  `json:"first_triggered"`
	LastTriggered  time.Time  `json:"last_triggered"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	AcknowledgedBy *uint      `json:"acknowledged_by"`
	MatchingLogs   JSON       `json:"matching_logs" gorm:"type:json"`
	OrganizationID uint       `json:"organization_id" gorm:"index"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// NotificationChannel represents destinations for alert notifications.
type NotificationChannel struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	Name           string     `json:"name" gorm:"not null"`
	Type           string     `json:"type"`
	Configuration  JSON       `json:"configuration" gorm:"type:json"`
	OrganizationID uint       `json:"organization_id" gorm:"index"`
	CreatedBy      uint       `json:"created_by" gorm:"index"`
	Active         bool       `json:"active" gorm:"default:true"`
	LastUsed       *time.Time `json:"last_used"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Notification represents delivered notification records.
type Notification struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	OrganizationID uint       `json:"organization_id" gorm:"index"`
	ChannelID      *uint      `json:"channel_id" gorm:"index"`
	Title          string     `json:"title"`
	Message        string     `json:"message"`
	Status         string     `json:"status"`
	Priority       string     `json:"priority"`
	Metadata       JSON       `json:"metadata" gorm:"type:json"`
	Error          string     `json:"error"`
	SentAt         *time.Time `json:"sent_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TransformationRule defines structured log transformation logic.
type TransformationRule struct {
	ID               uint         `json:"id" gorm:"primaryKey"`
	Name             string       `json:"name" gorm:"not null"`
	Description      string       `json:"description"`
	DataSourceID     uint         `json:"data_source_id" gorm:"not null"`
	DataSource       DataSource   `json:"data_source" gorm:"foreignKey:DataSourceID"`
	OrganizationID   uint         `json:"organization_id" gorm:"index;not null"`
	Organization     Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
	Type             string       `json:"type"`
	Enabled          bool         `json:"enabled" gorm:"default:true"`
	Order            int          `json:"order"`
	Config           JSON         `json:"config" gorm:"type:json"`
	Conditions       JSON         `json:"conditions" gorm:"type:json"`
	Actions          JSON         `json:"actions" gorm:"type:json"`
	CreatedBy        uint         `json:"created_by"`
	LastAppliedAt    *time.Time   `json:"last_applied_at"`
	ApplicationCount int          `json:"application_count"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}
