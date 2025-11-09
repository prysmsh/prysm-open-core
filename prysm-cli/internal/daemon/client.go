package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultSocket = "/var/run/prysm/meshd.sock"

// Client communicates with prysm-meshd via a Unix domain socket.
type Client struct {
	socket string
	client *http.Client
}

// NewClient constructs a daemon client.
func NewClient(socket string) *Client {
	if strings.TrimSpace(socket) == "" {
		if env := os.Getenv("PRYSM_MESHD_SOCKET"); strings.TrimSpace(env) != "" {
			socket = env
		} else {
			socket = defaultSocket
		}
	}

	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}

	return &Client{
		socket: socket,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}
}

// Apply pushes a new WireGuard configuration to the daemon.
func (c *Client) Apply(ctx context.Context, cfg ApplyConfigRequest) error {
	return c.do(ctx, http.MethodPost, "/apply", cfg, nil)
}

// Start brings the tunnel up.
func (c *Client) Start(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/start", nil, nil)
}

// Stop tears the tunnel down.
func (c *Client) Stop(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/stop", nil, nil)
}

// Status retrieves runtime state from the daemon.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var resp StatusResponse
	err := c.do(ctx, http.MethodGet, "/status", nil, &resp)
	return resp, err
}

func (c *Client) do(ctx context.Context, method, path string, payload interface{}, out interface{}) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "prysm-meshd"

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		data, _ := io.ReadAll(res.Body)
		return fmt.Errorf("daemon error (%s): %s", res.Status, strings.TrimSpace(string(data)))
	}

	if out != nil {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	} else {
		io.Copy(io.Discard, res.Body)
	}

	return nil
}

// SocketPath returns the configured socket path.
func (c *Client) SocketPath() string {
	return c.socket
}
