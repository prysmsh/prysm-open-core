package api

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// AnalyticsOptions contains query parameters for analytics requests.
type AnalyticsOptions struct {
	StartDate   string
	EndDate     string
	Granularity string
	Metrics     []string
}

// ClusterAnalyticsResponse represents analytics data for a cluster.
type ClusterAnalyticsResponse struct {
	ClusterID int64                  `json:"cluster_id"`
	Period    AnalyticsPeriod        `json:"period"`
	Metrics   map[string]interface{} `json:"metrics"`
	Trends    []AnalyticsTrend       `json:"trends,omitempty"`
}

// AnalyticsPeriod represents the time range for analytics data.
type AnalyticsPeriod struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// AnalyticsTrend represents a data point in analytics trends.
type AnalyticsTrend struct {
	Timestamp     time.Time              `json:"timestamp"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
	AccessCount   *int                   `json:"access_count,omitempty"`
	ActiveSessions *int                  `json:"active_sessions,omitempty"`
}

// SecurityAnalyticsResponse represents security analytics data.
type SecurityAnalyticsResponse struct {
	Threats    ThreatMetrics      `json:"threats"`
	Anomalies  AnomalyMetrics     `json:"anomalies"`
	Compliance ComplianceMetrics  `json:"compliance"`
}

// ThreatMetrics contains threat-related metrics.
type ThreatMetrics struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
}

// AnomalyMetrics contains anomaly detection metrics.
type AnomalyMetrics struct {
	Detected     int `json:"detected"`
	Investigated int `json:"investigated"`
	Resolved     int `json:"resolved"`
}

// ComplianceMetrics contains compliance scores.
type ComplianceMetrics struct {
	SOC2Score        int    `json:"soc2_score"`
	ISO27001Score    int    `json:"iso27001_score"`
	LastAssessment   string `json:"last_assessment"`
}

// PerformanceAnalyticsResponse represents performance analytics data.
type PerformanceAnalyticsResponse struct {
	AverageResponseTime float64                `json:"avg_response_time"`
	ErrorRate           float64                `json:"error_rate"`
	RequestsPerSecond   float64                `json:"requests_per_second"`
	Details             map[string]interface{} `json:"details,omitempty"`
}

// GetClusterAnalytics retrieves analytics for a specific cluster.
func (c *Client) GetClusterAnalytics(ctx context.Context, clusterID int64, opts *AnalyticsOptions) (*ClusterAnalyticsResponse, error) {
	endpoint := fmt.Sprintf("/analytics/clusters/%d", clusterID)
	
	if opts != nil {
		params := url.Values{}
		if opts.StartDate != "" {
			params.Set("start_date", opts.StartDate)
		}
		if opts.EndDate != "" {
			params.Set("end_date", opts.EndDate)
		}
		if opts.Granularity != "" {
			params.Set("granularity", opts.Granularity)
		}
		if len(params) > 0 {
			endpoint = endpoint + "?" + params.Encode()
		}
	}
	
	var resp ClusterAnalyticsResponse
	if _, err := c.Do(ctx, "GET", endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSecurityAnalytics retrieves security analytics.
func (c *Client) GetSecurityAnalytics(ctx context.Context) (*SecurityAnalyticsResponse, error) {
	var resp SecurityAnalyticsResponse
	if _, err := c.Do(ctx, "GET", "/analytics/security", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPerformanceAnalytics retrieves performance analytics.
func (c *Client) GetPerformanceAnalytics(ctx context.Context, opts *AnalyticsOptions) (*PerformanceAnalyticsResponse, error) {
	endpoint := "/analytics/performance"
	
	if opts != nil {
		params := url.Values{}
		if opts.StartDate != "" {
			params.Set("start_date", opts.StartDate)
		}
		if opts.EndDate != "" {
			params.Set("end_date", opts.EndDate)
		}
		if len(params) > 0 {
			endpoint = endpoint + "?" + params.Encode()
		}
	}
	
	var resp PerformanceAnalyticsResponse
	if _, err := c.Do(ctx, "GET", endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

