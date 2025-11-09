package kubectl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// AuditLogger sends kubectl command audit logs to the backend
type AuditLogger struct {
	backendURL string
	clusterID  string
	orgID      string
	agentToken string
}

// KubectlAuditLog represents a kubectl command audit entry
type KubectlAuditLog struct {
	Timestamp   time.Time `json:"timestamp"`
	ClusterID   string    `json:"cluster_id"`
	OrgID       string    `json:"organization_id"`
	Method      string    `json:"method"`      // HTTP method
	Path        string    `json:"path"`        // K8s API path
	SourceIP    string    `json:"source_ip"`   // WireGuard IP of CLI
	StatusCode  int       `json:"status_code"` // Response status
	Latency     int64     `json:"latency_ms"`  // Request duration
	BytesRx     uint64    `json:"bytes_rx"`    // Bytes received
	BytesTx     uint64    `json:"bytes_tx"`    // Bytes sent
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(backendURL, clusterID, orgID, agentToken string) *AuditLogger {
	return &AuditLogger{
		backendURL: backendURL,
		clusterID:  clusterID,
		orgID:      orgID,
		agentToken: agentToken,
	}
}

// LogCommand sends a kubectl command audit log to the backend
func (a *AuditLogger) LogCommand(auditLog KubectlAuditLog) {
	// Send asynchronously to not block the proxy
	go func() {
		if err := a.sendAuditLog(auditLog); err != nil {
			log.Printf("⚠️  Failed to send audit log: %v", err)
		}
	}()
}

func (a *AuditLogger) sendAuditLog(auditLog KubectlAuditLog) error {
	// Set cluster and org context
	auditLog.ClusterID = a.clusterID
	auditLog.OrgID = a.orgID
	
	payload, err := json.Marshal(auditLog)
	if err != nil {
		return fmt.Errorf("marshal audit log: %w", err)
	}
	
	url := fmt.Sprintf("%s/api/v1/audit/kubectl", a.backendURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.agentToken))
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	
	return nil
}

// AuditingProxy wraps the Proxy with audit logging capabilities
type AuditingProxy struct {
	*Proxy
	auditor *AuditLogger
}

// NewAuditingProxy creates a proxy with audit logging
func NewAuditingProxy(wireguardIP, k8sAPIAddress string, auditor *AuditLogger) *AuditingProxy {
	return &AuditingProxy{
		Proxy:   NewProxy(wireguardIP, k8sAPIAddress),
		auditor: auditor,
	}
}

// TODO: Implement HTTP parsing layer to extract method/path from kubectl requests
// This would require parsing the TLS-encrypted HTTP/2 stream, which is complex.
// For now, audit logs will be at connection level (IP, bytes, duration).
// Future enhancement: Use eBPF or service mesh for deep packet inspection.

