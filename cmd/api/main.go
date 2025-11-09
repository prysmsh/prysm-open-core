package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"prysm-backend/internal/agents"
	"prysm-backend/internal/alerting"
	"prysm-backend/internal/analytics"
	"prysm-backend/internal/auth"
	"prysm-backend/internal/billing"
	"prysm-backend/internal/bootstrap"
	"prysm-backend/internal/clusters"
	"prysm-backend/internal/database"
	"prysm-backend/internal/derp"
	"prysm-backend/internal/health"
	loggingHandlers "prysm-backend/internal/logging"
	"prysm-backend/internal/logs"
	"prysm-backend/internal/metrics"
	"prysm-backend/internal/middleware"
	"prysm-backend/internal/models"
	"prysm-backend/internal/network"
	"prysm-backend/internal/services"
	"prysm-backend/internal/sessions"
	"prysm-backend/internal/status"
	logStream "prysm-backend/internal/streaming"
	streams "prysm-backend/internal/streams"
	"prysm-backend/internal/usage"
	"prysm-backend/internal/waitlist"
	"prysm-backend/internal/wireguard"
	"prysm-backend/pkg/utils"
)

func main() {
	log.Println("🚀 Starting Prysm API Server (Refactored)")
	startedAt := time.Now()

	// Initialize Sentry before other subsystems so we capture initialization errors
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		dsn = "https://ffef86a43bb2bfa8216902a332621734@sentry.prysm.sh/2"
	}
	if dsn != "" {
		env := os.Getenv("SENTRY_ENVIRONMENT")
		release := os.Getenv("SENTRY_RELEASE")
		if release == "" {
			release = os.Getenv("GIT_COMMIT")
		}
		host, _ := os.Hostname()

		opts := sentry.ClientOptions{
			Dsn:         dsn,
			Environment: env,
			Release:     release,
		}
		if host != "" {
			opts.ServerName = host
		}

		if err := sentry.Init(opts); err != nil {
			log.Printf("Sentry initialization failed: %v", err)
		} else {
			sentry.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetTag("service", "prysm-backend")
			})
			defer sentry.Flush(2 * time.Second)
		}
	}

	// Initialize database
	if err := database.InitDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Run database migrations
	if database.DB != nil {
		log.Println("Running database migrations...")
		// Migrate core models (add more incrementally)
		if err := database.DB.AutoMigrate(
			&models.User{},
			&models.Organization{},
			&models.TokenBlacklist{},
			&models.Cluster{},
			&models.AgentToken{},
			&models.Session{},
			&models.Plan{},
			&models.Subscription{},
			&models.OrganizationMember{},
			&models.Invitation{},
			&models.UsageRecord{},
			&models.PaymentMethod{},
			&models.Invoice{},
			&models.Permission{},
			&models.AuditLog{},
			&models.MeshPeer{},
			&models.WireguardDevice{},
			&models.WireguardAllocation{},
			&models.WireguardRelay{},
			&models.DNSRecord{},
			&models.RoutingRule{},
			&models.SubdomainDelegation{},
			&models.DNSServer{},
			&models.LogSink{},
			&models.DataSource{},
			&models.Query{},
			&models.Dashboard{},
			&models.TraceRecord{},
			&models.TraceSpan{},
			&models.LogCorrelation{},
			&models.Waitlist{},
		); err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
		log.Println("✅ Database migrations completed")
		bootstrap.Run(database.DB)
	}

	// Initialize auth components
	auth.InitJWT()
	auth.InitOAuth()

	// Start background tasks
	middleware.StartCleanup()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			auth.CleanupTokenBlacklist(database.DB)
		}
	}()

	// Set up router
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(sentrygin.New(sentrygin.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         2 * time.Second,
	}))
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	if os.Getenv("ENABLE_SENTRY_DEBUG_ENDPOINT") == "true" {
		router.GET("/internal/sentry-test", func(c *gin.Context) {
			const msg = "Sentry debug endpoint hit"
			utils.CaptureSentryError(c, nil, msg, nil)
			_ = sentry.Flush(2 * time.Second)
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	// CORS - MUST be first to handle OPTIONS requests
	corsConfig := middleware.SecureCORSConfig()
	router.Use(cors.New(corsConfig))

	// Security middleware - after CORS
	securityConfig := middleware.GetSecurityConfig()
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestSizeLimit(securityConfig.MaxRequestSize))
	router.Use(middleware.SecurityMonitoring())
	router.Use(middleware.GeneralRateLimit())
	router.Use(middleware.InputSanitization())
	router.Use(middleware.IPWhitelist(securityConfig.AllowedIPs, securityConfig.EnforceIPWhitelist))

	// Health check endpoints
	router.GET("/health", health.HandleHealthCheck)
	router.GET("/metrics", metrics.HandleSystemMetrics)

	// API routes
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		log.Printf("API v1 route hit: %s %s from %s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
		c.Next()
	})
	{
		// Public routes
		api.GET("/plans", billing.HandleGetPlans)

		// Public auth routes
		authRoutes := api.Group("/auth")
		authRoutes.Use(func(c *gin.Context) {
			log.Printf("Auth route hit: %s %s from %s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
			c.Next()
		})
		{
			authRoutes.GET("/csrf-token", auth.HandleGetCSRFToken)
			authRoutes.POST("/login", func(c *gin.Context) {
				log.Printf("Login endpoint hit from %s", c.ClientIP())
				c.Next()
			}, middleware.LoginRateLimit(), middleware.ValidateLoginInput(), auth.HandleLogin)
			authRoutes.POST("/register", middleware.RegisterRateLimit(), auth.HandleRegister)
			authRoutes.POST("/logout", auth.HandleLogout)
		}

		// CSRF token endpoint (alternative path)
		api.GET("/csrf-token", auth.HandleGetCSRFToken)

		// Protected routes
		protected := api.Group("")
		protected.Use(auth.Middleware(database.DB))
		{
			// Profile management
			protected.GET("/profile", auth.HandleGetProfile)
			protected.PUT("/profile", auth.HandleUpdateProfile)
			protected.PUT("/profile/password", auth.HandleChangePassword)

			// System health + telemetry
			protected.GET("/health", health.HandleHealthCheck)
			protected.GET("/ready", health.HandleSystemReady)
			protected.GET("/metrics", metrics.HandleSystemMetrics)
			protected.GET("/status", status.HandleGetStatusSummary)
			protected.GET("/usage", usage.HandleGetCurrentUsage)

			// Cluster management
			protected.GET("/clusters", clusters.HandleList)
			protected.GET("/clusters/:id", clusters.HandleGet)
			protected.POST("/clusters", clusters.HandleCreate)
			protected.PUT("/clusters/:id", clusters.HandleUpdate)
			protected.DELETE("/clusters/:id", clusters.HandleDelete)
			protected.GET("/clusters/:id/mesh-status", clusters.HandleGetMeshStatus)

			// Services inventory
			protected.GET("/services", services.HandleGetServices)
			protected.GET("/services/:id", services.HandleGetServicesByCluster)

			// Billing & subscription
			protected.GET("/subscription", billing.HandleGetCurrentSubscription)
			protected.GET("/invoices", billing.HandleGetInvoices)
			protected.GET("/payment-methods", billing.HandleGetPaymentMethods)
			protected.GET("/plans/compare", billing.HandleGetPlanComparison)

			// Mesh management
			protected.GET("/mesh/nodes", network.HandleListMeshNodes)
			protected.PUT("/mesh/nodes/:id/exit", network.HandleUpdateMeshNodeExit)
			protected.DELETE("/mesh/nodes/:id/exit", network.HandleDisableMeshNodeExit)
			protected.GET("/mesh/clients", network.HandleGetMeshClients)
			protected.GET("/mesh/stats", network.HandleGetMeshStats)
			protected.GET("/mesh/topology", network.HandleGetMeshTopology)
			protected.POST("/mesh/nodes/register", network.HandleRegisterMeshNode)

			// WireGuard device management
			protected.POST("/mesh/wireguard/devices", wireguard.HandleRegisterDevice)
			protected.GET("/mesh/wireguard/config", wireguard.HandleGetConfig)
			protected.POST("/mesh/wireguard/devices/:id/rotate", wireguard.HandleRotateDevice)
			protected.DELETE("/mesh/wireguard/devices/:id", wireguard.HandleDeleteDevice)

			// HTTP DERP tunnel for WireGuard fallback
			protected.GET("/mesh/derp/tunnel", derp.HandleTunnel)
			protected.GET("/derp/status", derp.HandleGetDERPStatus)
			protected.GET("/derp/peers", derp.HandleGetDERPPeers)
			protected.GET("/derp/metrics", derp.HandleGetDERPMetrics)
			protected.GET("/derp/security/metrics", derp.HandleGetDERPMetrics)

			// Agent tokens
			tokenRoutes := protected.Group("/tokens")
			{
				tokenRoutes.GET("", agents.HandleListTokens)
				tokenRoutes.POST("", agents.HandleCreateToken)
				tokenRoutes.GET("/:id", agents.HandleGetToken)
				tokenRoutes.PUT("/:id", agents.HandleUpdateToken)
				tokenRoutes.DELETE("/:id", agents.HandleDeleteToken)
				tokenRoutes.POST("/:id/rotate", agents.HandleRotateToken)
				tokenRoutes.POST("/:id/revoke", agents.HandleRevokeToken)
			}

			// Session management
			sessionRoutes := protected.Group("/user-sessions")
			{
				sessionRoutes.GET("", sessions.HandleGetUserActiveSessions)
				sessionRoutes.GET("/:sessionId", sessions.HandleGetUserSession)
				sessionRoutes.DELETE("/:sessionId", sessions.HandleEndUserSession)
				sessionRoutes.DELETE("", sessions.HandleRevokeAllSessions)
			}

			// Analytics + observability
			analyticsRoutes := protected.Group("/analytics")
			{
				analyticsRoutes.GET("/clusters", analytics.HandleGetClusterAnalytics)
				analyticsRoutes.GET("/usage", usage.HandleGetUsageStats)
				analyticsRoutes.GET("/performance", analytics.HandleGetPerformanceOverview)
				analyticsRoutes.GET("/log-stats", analytics.HandleGetLogStats)

				// Data sources
				analyticsRoutes.GET("/data-sources", analytics.HandleGetDataSources)
				analyticsRoutes.POST("/data-sources", analytics.HandleCreateDataSource)
				analyticsRoutes.PUT("/data-sources/:id", analytics.HandleUpdateDataSource)
				analyticsRoutes.DELETE("/data-sources/:id", analytics.HandleDeleteDataSource)

				// Queries
				analyticsRoutes.GET("/queries", analytics.HandleGetQueries)
				analyticsRoutes.POST("/queries", analytics.HandleCreateQuery)
				analyticsRoutes.PUT("/queries/:id", analytics.HandleUpdateQuery)
				analyticsRoutes.DELETE("/queries/:id", analytics.HandleDeleteQuery)
				analyticsRoutes.POST("/queries/:id/execute", analytics.HandleExecuteQuery)

				// Dashboards
				analyticsRoutes.GET("/dashboards", analytics.HandleGetDashboards)
				analyticsRoutes.POST("/dashboards", analytics.HandleCreateDashboard)
				analyticsRoutes.PUT("/dashboards/:id", analytics.HandleUpdateDashboard)
				analyticsRoutes.DELETE("/dashboards/:id", analytics.HandleDeleteDashboard)
				analyticsRoutes.POST("/dashboards/:id/duplicate", analytics.HandleDuplicateDashboard)
				analyticsRoutes.GET("/dashboards/:id/export", analytics.HandleExportDashboard)

				analyticsRoutes.GET("/log-metrics/:dataSourceId", analytics.HandleGetLogMetrics)
			}

			// Logging + alerts
			logRoutes := protected.Group("/logs")
			{
				logRoutes.GET("/alerts", alerting.HandleGetLogAlerts)
				logRoutes.POST("/alerts", alerting.HandleCreateLogAlert)
				logRoutes.GET("/alerts/:id", alerting.HandleGetLogAlert)
				logRoutes.PUT("/alerts/:id", alerting.HandleUpdateLogAlert)
				logRoutes.DELETE("/alerts/:id", alerting.HandleDeleteLogAlert)
				logRoutes.POST("/alerts/:id/ack", alerting.HandleAcknowledgeLogAlert)
				logRoutes.GET("/alerts/:id/instances", alerting.HandleGetLogAlertInstances)
				logRoutes.GET("/alert-instances", alerting.HandleListLogAlertInstances)
				logRoutes.GET("/correlation", logs.HandleGetCorrelatedLogs)
				logRoutes.GET("/stream/stats", logStream.HandleGetLogStreamStats)
			}

			// Log sinks / ingestion targets
			loggingRoutes := protected.Group("/logging")
			{
				loggingRoutes.GET("/sinks", loggingHandlers.HandleListLogSinks)
				loggingRoutes.POST("/sinks", loggingHandlers.HandleCreateLogSink)
				loggingRoutes.DELETE("/sinks/:id", loggingHandlers.HandleDeleteLogSink)
				loggingRoutes.GET("/sinks/:id/manifest", loggingHandlers.HandleGetLogSinkManifest)
				loggingRoutes.POST("/sinks/:id/status", loggingHandlers.HandleUpdateLogSinkStatus)
			}

			// Additional routes to be added incrementally
		}

		// Waitlist (public)
		api.POST("/waitlist", waitlist.HandleJoinWaitlist)

		// Log ingestion (no auth required for agents)
		api.POST("/logs/ingest/v1/logs", logs.HandleIngestLogs)

		// Cluster registration endpoint (token in body)
		api.POST("/clusters/register", clusters.HandleRegisterCluster)

		// Agent endpoints with token authentication
		agentRoutes := api.Group("")
		agentRoutes.Use(middleware.AgentAuth())
		{
			// Cluster telemetry endpoints (require agent auth)
			agentRoutes.POST("/clusters/:id/ping", clusters.HandleClusterPing)
			agentRoutes.POST("/clusters/:id/metrics", clusters.HandleClusterMetrics)
			agentRoutes.POST("/clusters/:id/data", clusters.HandleClusterData)
		}

		// Agent network config (optional auth for backwards compatibility)
		api.GET("/agent/network/config", middleware.OptionalAgentAuth(), clusters.HandleAgentNetworkConfig)

		// Internal endpoints
		api.POST("/internal/derp/verify", derp.HandleVerify)
	}

	// Status metrics endpoint (outside API group)
	router.GET("/status/metrics", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"uptime":   time.Since(startedAt).Seconds(),
			"version":  "1.0.0",
			"status":   "healthy",
			"started":  startedAt,
			"database": database.DB != nil,
		})
	})

	// Real-time WebSocket streams
	router.GET("/ws/metrics", auth.Middleware(database.DB), streams.HandleSystemMetricsWebSocket)
	router.GET("/ws/cluster-status", auth.Middleware(database.DB), streams.HandleClusterStatusWebSocket)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("✅ Server starting on port %s", port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// All handlers now extracted to their respective packages
