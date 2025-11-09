package kubectl

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// AdvancedProxy provides HTTP-aware proxying with audit logging
// This version terminates TLS from kubectl, reads the HTTP request for auditing,
// then re-encrypts to K8s API using the agent's ServiceAccount credentials
type AdvancedProxy struct {
	wireguardIP   string
	k8sAPIAddress string
	listener      net.Listener

	// Agent's credentials for K8s API
	serviceAccountToken string
	k8sCACert           []byte

	mu              sync.RWMutex
	activeConns     map[string]*proxyConnection
	totalConns      uint64
	activeConnCount uint32
	bytesProxied    uint64

	// Audit logging
	auditLog chan AuditEntry
}

// AuditEntry represents a kubectl command for audit logging
type AuditEntry struct {
	Timestamp  time.Time
	SourceIP   string
	Method     string
	Path       string
	UserAgent  string
	StatusCode int
	Latency    time.Duration
}

// NewAdvancedProxy creates an HTTP-aware proxy with audit logging
func NewAdvancedProxy(wireguardIP, k8sAPIAddress string) (*AdvancedProxy, error) {
	// Load ServiceAccount credentials (agent runs as pod inside K8s)
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("failed to load ServiceAccount token: %w", err)
	}

	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to load K8s CA cert: %w", err)
	}

	return &AdvancedProxy{
		wireguardIP:         wireguardIP,
		k8sAPIAddress:       k8sAPIAddress,
		serviceAccountToken: string(token),
		k8sCACert:           caCert,
		activeConns:         make(map[string]*proxyConnection),
		auditLog:            make(chan AuditEntry, 1000),
	}, nil
}

// Start begins the HTTP-aware proxy
func (p *AdvancedProxy) Start(ctx context.Context) error {
	// Generate self-signed cert for accepting kubectl TLS connections
	cert, err := p.generateProxyCertificate()
	if err != nil {
		return fmt.Errorf("failed to generate proxy certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listenAddr := fmt.Sprintf("%s:6443", p.wireguardIP)
	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	p.listener = ln
	log.Printf("🔐 Advanced kubectl proxy listening on %s (HTTP-aware, auditing enabled)", listenAddr)
	log.Printf("   Authenticating to K8s API with ServiceAccount token")

	// Start audit log processor
	go p.processAuditLogs(ctx)

	go p.acceptLoop(ctx)

	<-ctx.Done()
	ln.Close()
	return nil
}

func (p *AdvancedProxy) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		clientConn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go p.handleHTTPConnection(ctx, clientConn)
	}
}

func (p *AdvancedProxy) handleHTTPConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("📥 New kubectl connection from %s (WireGuard mesh)", clientAddr)

	// Parse HTTP request from kubectl
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("❌ Failed to parse HTTP request: %v", err)
		return
	}

	startTime := time.Now()

	// Log the kubectl command for audit
	log.Printf("🔍 kubectl: %s %s (from %s)", req.Method, req.URL.Path, clientAddr)

	// Create TLS connection to K8s API with ServiceAccount auth
	k8sCertPool := x509.NewCertPool()
	k8sCertPool.AppendCertsFromPEM(p.k8sCACert)

	k8sDialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs:    k8sCertPool,
			MinVersion: tls.VersionTLS12,
			// NOTE: For in-cluster access, K8s API uses service name which may not match cert
			InsecureSkipVerify: true, // TODO: Properly validate K8s API cert
		},
	}

	k8sConn, err := k8sDialer.DialContext(ctx, "tcp", p.k8sAPIAddress)
	if err != nil {
		log.Printf("❌ Failed to dial K8s API: %v", err)
		return
	}
	defer k8sConn.Close()

	// Forward HTTP request to K8s API with ServiceAccount token
	req.Header.Set("Authorization", "Bearer "+p.serviceAccountToken)

	if err := req.Write(k8sConn); err != nil {
		log.Printf("❌ Failed to write request to K8s API: %v", err)
		return
	}

	// Read response from K8s API
	k8sReader := bufio.NewReader(k8sConn)
	resp, err := http.ReadResponse(k8sReader, req)
	if err != nil {
		log.Printf("❌ Failed to read K8s API response: %v", err)
		return
	}
	defer resp.Body.Close()

	// Send response back to kubectl
	if err := resp.Write(clientConn); err != nil {
		log.Printf("❌ Failed to write response to client: %v", err)
		return
	}

	latency := time.Since(startTime)
	log.Printf("✅ kubectl %s %s → %d (%v)", req.Method, req.URL.Path, resp.StatusCode, latency)

	// Send to audit log
	p.auditLog <- AuditEntry{
		Timestamp:  startTime,
		SourceIP:   clientAddr,
		Method:     req.Method,
		Path:       req.URL.Path,
		UserAgent:  req.UserAgent(),
		StatusCode: resp.StatusCode,
		Latency:    latency,
	}
}

func (p *AdvancedProxy) processAuditLogs(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-p.auditLog:
			// TODO: Send to backend for storage
			log.Printf("📋 AUDIT: %s %s from %s → %d (%v)",
				entry.Method, entry.Path, entry.SourceIP, entry.StatusCode, entry.Latency)
		}
	}
}

func (p *AdvancedProxy) generateProxyCertificate() (tls.Certificate, error) {
	// TODO: Generate proper self-signed certificate for accepting kubectl TLS
	// For now, return empty and rely on simple TCP proxy
	return tls.Certificate{}, fmt.Errorf("not yet implemented - use simple TCP proxy instead")
}
