package api

import (
	"context"
)

// CLISession represents a sanitized session payload returned from the backend.
type CLISession struct {
	SessionID      string  `json:"session_id"`
	Status         string  `json:"status"`
	StartedAt      string  `json:"started_at"`
	EndedAt        *string `json:"ended_at"`
	ExpiresAt      *string `json:"expires_at"`
	CredentialType string  `json:"credential_type"`
	CredentialRef  string  `json:"credential_ref"`
	VaultPath      string  `json:"vault_path"`
	VaultLeaseID   string  `json:"vault_lease_id"`
	ClusterID      *int64  `json:"cluster_id"`
	OrganizationID int64   `json:"organization_id"`
	Source         string  `json:"source"`
	CreatedAt      *string `json:"created_at"`
	LastAccessed   *string `json:"last_accessed"`
	IPAddress      string  `json:"ip_address"`
	UserAgent      string  `json:"user_agent"`
	IsActive       *bool   `json:"is_active"`
}

// SessionListResponse wraps the /user-sessions payload.
type SessionListResponse struct {
	Count    int          `json:"count"`
	Sessions []CLISession `json:"sessions"`
}

// ListSessions fetches the current user's sessions (Redis + database-backed).
func (c *Client) ListSessions(ctx context.Context) (*SessionListResponse, error) {
	var resp SessionListResponse
	if _, err := c.Do(ctx, "GET", "/user-sessions", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeSession deletes a specific session by ID.
func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	endpoint := "/user-sessions/" + sessionID
	_, err := c.Do(ctx, "DELETE", endpoint, nil, nil)
	return err
}

// GetSession retrieves details for a specific session.
func (c *Client) GetSession(ctx context.Context, sessionID string) (*CLISession, error) {
	endpoint := "/user-sessions/" + sessionID
	var resp CLISession
	if _, err := c.Do(ctx, "GET", endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EndSession terminates an active session.
func (c *Client) EndSession(ctx context.Context, sessionID string) error {
	endpoint := "/user-sessions/" + sessionID + "/end"
	_, err := c.Do(ctx, "POST", endpoint, nil, nil)
	return err
}
