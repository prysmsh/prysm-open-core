package meshproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Config controls the DERP HTTP proxy behavior.
type Config struct {
	BindAddr  string
	TunnelURL string
	Headers   http.Header
	DeviceID  string
	Logger    *log.Logger
}

// Run starts the UDP <-> WebSocket bridge and blocks until ctx is cancelled or an error occurs.
func Run(ctx context.Context, cfg Config) error {
	if cfg.TunnelURL == "" {
		return errors.New("tunnel url is required")
	}

	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:51821"
	}

	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", 0)
	}

	local, err := net.ListenPacket("udp", cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.BindAddr, err)
	}
	defer local.Close()

	actualAddr := local.LocalAddr().String()
	cfg.Logger.Printf("🔁 WireGuard proxy listening on %s", actualAddr)
	cfg.Logger.Printf("   Update your WireGuard peer endpoint to %s to route via HTTPS DERP.", actualAddr)

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 15 * time.Second,
	}

	wsConn, resp, err := dialer.DialContext(ctx, cfg.TunnelURL, cfg.Headers)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return fmt.Errorf("connect DERP tunnel: %w", err)
	}
	defer wsConn.Close()

	cfg.Logger.Printf("🌐 Connected to DERP tunnel %s", cfg.TunnelURL)

	wsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	msgType, payload, err := wsConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("await tunnel readiness: %w", err)
	}
	wsConn.SetReadDeadline(time.Time{})

	if msgType == websocket.TextMessage {
		var ready map[string]interface{}
		if err := json.Unmarshal(payload, &ready); err == nil {
			if endpoint, ok := ready["endpoint"].(string); ok {
				cfg.Logger.Printf("   Relay endpoint: %s", endpoint)
			}
			if relayMeta, ok := ready["relay"].(map[string]interface{}); ok {
				if name, ok := relayMeta["name"].(string); ok && name != "" {
					cfg.Logger.Printf("   Relay: %s", name)
				}
				if region, ok := relayMeta["region"].(string); ok && region != "" {
					cfg.Logger.Printf("   Region: %s", region)
				}
			}
		}
	}

	var lastPeer atomic.Value // net.Addr
	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 64<<10)
		for {
			local.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, addr, err := local.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if ctx.Err() != nil {
						errCh <- ctx.Err()
						return
					}
					continue
				}
				errCh <- err
				return
			}
			lastPeer.Store(addr)
			wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			msgType, payload, err := wsConn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					errCh <- context.Canceled
					return
				}
				errCh <- err
				return
			}
			if msgType != websocket.BinaryMessage {
				continue
			}
			if peer, ok := lastPeer.Load().(net.Addr); ok && peer != nil {
				local.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := local.WriteTo(payload, peer); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "client shutdown"))
			local.Close()
		case <-stop:
		}
	}()

	select {
	case <-ctx.Done():
		close(stop)
		return nil
	case err := <-errCh:
		close(stop)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}
