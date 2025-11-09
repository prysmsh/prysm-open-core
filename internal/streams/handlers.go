package streams

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"prysm-backend/internal/database"
	"prysm-backend/internal/derp"
	"prysm-backend/internal/models"
)

var (
	wsUpgrader = websocket.Upgrader{
		ReadBufferSize:  64 << 10,
		WriteBufferSize: 64 << 10,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	cpuSampleMu    sync.Mutex
	lastCPUTime    time.Duration
	lastSampleTime time.Time
)

// HandleSystemMetricsWebSocket streams runtime/system metrics to the dashboard.
func HandleSystemMetricsWebSocket(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	if orgID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}

	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		payload, err := buildSystemMetricsPayload(orgID)
		if err != nil {
			conn.WriteJSON(gin.H{
				"type":    "system_metrics",
				"error":   err.Error(),
				"details": "failed to build system metrics",
			})
		} else {
			if err := conn.WriteJSON(payload); err != nil {
				return
			}
		}

		select {
		case <-ticker.C:
			continue
		case <-c.Request.Context().Done():
			return
		}
	}
}

// HandleClusterStatusWebSocket streams live cluster health summaries.
func HandleClusterStatusWebSocket(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	if orgID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}

	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		payload, err := buildClusterMetricsPayload(orgID)
		if err != nil {
			conn.WriteJSON(gin.H{
				"type":    "cluster_metrics",
				"error":   err.Error(),
				"details": "failed to build cluster summary",
			})
		} else {
			if err := conn.WriteJSON(payload); err != nil {
				return
			}
		}

		select {
		case <-ticker.C:
			continue
		case <-c.Request.Context().Done():
			return
		}
	}
}

func buildSystemMetricsPayload(orgID uint) (map[string]interface{}, error) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	cpuUsage := sampleCPUPercent()
	memUsage := 0.0
	if mem.Sys > 0 {
		memUsage = math.Min(100, (float64(mem.Alloc)/float64(mem.Sys))*100)
	}

	stats, err := derp.CollectMeshPeerStats()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"type":            "system_metrics",
		"organization_id": orgID,
		"cpu_usage":       math.Round(cpuUsage*10) / 10,
		"memory_usage":    math.Round(memUsage*10) / 10,
		"network_status":  stats.NetworkStatus(),
		"uptime_seconds":  stats.UptimeSeconds(),
		"timestamp":       time.Now().UTC(),
	}, nil
}

func buildClusterMetricsPayload(orgID uint) (map[string]interface{}, error) {
	if database.DB == nil {
		return nil, errors.New("database not initialized")
	}

	var clusters []models.Cluster
	query := database.DB.Where("organization_id = ?", orgID)
	if err := query.Find(&clusters).Error; err != nil {
		return nil, fmt.Errorf("query clusters: %w", err)
	}

	healthy := 0
	totalServices := 0
	clusterSummaries := make([]map[string]interface{}, 0, len(clusters))

	for _, cluster := range clusters {
		status := normalizeStatus(cluster.Status)
		if status == "connected" || status == "healthy" || status == "online" {
			healthy++
		}

		info := jsonObject(cluster.ClusterInfo)
		metrics := jsonObject(cluster.Metrics)

		cpu := coalesceNumber(metrics, info, "cpu_usage", "cpu")
		memory := coalesceNumber(metrics, info, "memory_usage", "memory")
		storage := coalesceNumber(metrics, info, "storage_usage", "storage")
		pods := coalesceNumber(info, nil, "pod_count", "pods")
		nodeCount := coalesceNumber(info, nil, "node_count", "nodes")

		serviceCount := countServices(cluster.Services)
		if serviceCount == 0 {
			serviceCount = int(coalesceNumber(info, nil, "service_count", "services"))
		}
		totalServices += serviceCount

		clusterSummaries = append(clusterSummaries, map[string]interface{}{
			"id":             cluster.ID,
			"name":           cluster.Name,
			"status":         status,
			"services":       serviceCount,
			"pods":           int(pods),
			"cpu":            math.Round(cpu*10) / 10,
			"memory":         math.Round(memory*10) / 10,
			"storage":        math.Round(storage*10) / 10,
			"nodes":          int(nodeCount),
			"last_ping":      cluster.LastPing,
			"organization":   cluster.OrganizationID,
			"is_exit_router": cluster.IsExitRouter,
		})
	}

	return map[string]interface{}{
		"type":            "cluster_metrics",
		"organization_id": orgID,
		"summary": map[string]interface{}{
			"healthy":  healthy,
			"total":    len(clusters),
			"services": totalServices,
		},
		"clusters":  clusterSummaries,
		"timestamp": time.Now().UTC(),
	}, nil
}

func normalizeStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "connected", "healthy", "online":
		return "connected"
	case "warning", "degraded":
		return "warning"
	case "pending":
		return "pending"
	case "disconnected", "offline":
		return "disconnected"
	default:
		return "unknown"
	}
}

func countServices(data models.JSON) int {
	if len(data) == 0 {
		return 0
	}
	var array []interface{}
	if err := json.Unmarshal(data, &array); err == nil {
		return len(array)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		if v, ok := obj["services"]; ok {
			switch t := v.(type) {
			case []interface{}:
				return len(t)
			case float64:
				if t > 0 {
					return int(t)
				}
			case int:
				if t > 0 {
					return t
				}
			}
		}
	}
	return 0
}

func jsonObject(data models.JSON) map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func coalesceNumber(primary map[string]interface{}, fallback map[string]interface{}, keys ...string) float64 {
	extract := func(source map[string]interface{}, key string) (float64, bool) {
		if source == nil {
			return 0, false
		}
		if value, ok := source[key]; ok {
			switch v := value.(type) {
			case float64:
				return v, true
			case float32:
				return float64(v), true
			case int:
				return float64(v), true
			case int64:
				return float64(v), true
			case json.Number:
				if parsed, err := v.Float64(); err == nil {
					return parsed, true
				}
			case string:
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					return parsed, true
				}
			}
		}
		return 0, false
	}

	for _, key := range keys {
		if value, ok := extract(primary, key); ok {
			return value
		}
		if value, ok := extract(fallback, key); ok {
			return value
		}
	}
	return 0
}

func sampleCPUPercent() float64 {
	cpuSampleMu.Lock()
	defer cpuSampleMu.Unlock()

	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}

	user := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	system := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	total := user + system
	now := time.Now()

	if lastSampleTime.IsZero() {
		lastSampleTime = now
		lastCPUTime = total
		return 0
	}

	deltaCPU := total - lastCPUTime
	deltaTime := now.Sub(lastSampleTime)
	lastSampleTime = now
	lastCPUTime = total

	if deltaTime <= 0 {
		return 0
	}

	usageFraction := float64(deltaCPU) / float64(deltaTime)
	usageFraction = usageFraction / float64(runtime.NumCPU())
	percent := usageFraction * 100

	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}
