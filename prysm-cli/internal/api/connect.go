package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Cluster represents a Kubernetes cluster registered with Prysm.
type Cluster struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Status       string     `json:"status"`
	Namespace    string     `json:"namespace"`
	IsExitRouter bool       `json:"is_exit_router"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastPing     *time.Time `json:"last_ping"`
}

// KubeconfigMaterial contains the encoded kubeconfig from connect response.
type KubeconfigMaterial struct {
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
}

// KubernetesSessionInfo captures session state returned by the API.
type KubernetesSessionInfo struct {
	ID        int64      `json:"id"`
	SessionID string     `json:"session_id"`
	Status    string     `json:"status"`
	StartedAt *time.Time `json:"started_at"`
}

// ClusterConnectResponse is the payload from /connect/k8s.
type ClusterConnectResponse struct {
	Cluster      Cluster                `json:"cluster"`
	Session      KubernetesSessionInfo  `json:"session"`
	Kubeconfig   KubeconfigMaterial     `json:"kubeconfig"`
	Recording    map[string]interface{} `json:"recording"`
	PolicyChecks map[string]interface{} `json:"policy_checks"`
	IssuedAt     time.Time              `json:"issued_at"`
}

type listClustersResponse struct {
	Clusters  []Cluster `json:"clusters"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// ListClusters retrieves clusters the authenticated user can access.
func (c *Client) ListClusters(ctx context.Context) ([]Cluster, error) {
	var resp listClustersResponse
	if _, err := c.Do(ctx, "GET", "/connect/k8s/clusters", nil, &resp); err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			// Fallback to legacy endpoint used by the dashboard/API.
			if _, legacyErr := c.Do(ctx, "GET", "/clusters", nil, &resp); legacyErr != nil {
				return nil, legacyErr
			}
			if resp.Count == 0 {
				resp.Count = len(resp.Clusters)
			}
			if resp.Timestamp.IsZero() {
				resp.Timestamp = time.Now().UTC()
			}
			return resp.Clusters, nil
		}
		return nil, err
	}
	return resp.Clusters, nil
}

// ConnectKubernetes issues a short-lived kubeconfig for the requested cluster.
func (c *Client) ConnectKubernetes(ctx context.Context, clusterID int64, namespace, reason string) (*ClusterConnectResponse, error) {
	payload := map[string]interface{}{
		"cluster_id": clusterID,
	}
	if namespace != "" {
		payload["namespace"] = namespace
	}
	if reason != "" {
		payload["reason"] = reason
	}

	var resp ClusterConnectResponse
	if _, err := c.Do(ctx, "POST", "/connect/k8s", payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCluster retrieves details for a specific cluster.
func (c *Client) GetCluster(ctx context.Context, clusterID int64) (*Cluster, error) {
	endpoint := fmt.Sprintf("/clusters/%d", clusterID)
	var resp Cluster
	if _, err := c.Do(ctx, "GET", endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateClusterRequest contains fields for updating a cluster.
type UpdateClusterRequest struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// UpdateCluster updates an existing cluster's properties.
func (c *Client) UpdateCluster(ctx context.Context, clusterID int64, req UpdateClusterRequest) (*Cluster, error) {
	endpoint := fmt.Sprintf("/clusters/%d", clusterID)
	var resp Cluster
	if _, err := c.Do(ctx, "PUT", endpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteCluster removes a cluster by ID.
func (c *Client) DeleteCluster(ctx context.Context, clusterID int64) error {
	endpoint := fmt.Sprintf("/clusters/%d", clusterID)
	_, err := c.Do(ctx, "DELETE", endpoint, nil, nil)
	return err
}

// PingCluster pings a specific cluster
func (c *Client) PingCluster(ctx context.Context, clusterID int64) error {
	endpoint := fmt.Sprintf("/clusters/%d/ping", clusterID)
	_, err := c.Do(ctx, "POST", endpoint, nil, nil)
	return err
}

// ClusterMeshStatus represents the mesh connectivity status of a cluster
type ClusterMeshStatus struct {
	Connected bool      `json:"connected"`
	PeerCount int       `json:"peer_count"`
	LastSeen  time.Time `json:"last_seen"`
	RelayURL  string    `json:"relay_url"`
	PublicKey string    `json:"public_key"`
}

// GetClusterMeshStatus retrieves the mesh connectivity status for a cluster
func (c *Client) GetClusterMeshStatus(ctx context.Context, clusterID int64) (*ClusterMeshStatus, error) {
	endpoint := fmt.Sprintf("/clusters/%d/mesh-status", clusterID)
	var resp ClusterMeshStatus
	if _, err := c.Do(ctx, "GET", endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
