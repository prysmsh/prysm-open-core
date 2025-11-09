import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/api/api_client.dart';
import '../../../../core/models/cluster_models.dart';

// Dashboard State
class DashboardState {
  final bool isLoading;
  final List<ClusterInfo> clusters;
  final List<DashboardAlert> alerts;
  final Map<String, dynamic> analytics;
  final String? error;

  const DashboardState({
    this.isLoading = false,
    this.clusters = const [],
    this.alerts = const [],
    this.analytics = const {},
    this.error,
  });

  DashboardState copyWith({
    bool? isLoading,
    List<ClusterInfo>? clusters,
    List<DashboardAlert>? alerts,
    Map<String, dynamic>? analytics,
    String? error,
  }) {
    return DashboardState(
      isLoading: isLoading ?? this.isLoading,
      clusters: clusters ?? this.clusters,
      alerts: alerts ?? this.alerts,
      analytics: analytics ?? this.analytics,
      error: error,
    );
  }
}

// Dashboard Alert Model
class DashboardAlert {
  final String id;
  final String type;
  final String severity;
  final String title;
  final String message;
  final String? clusterId;
  final DateTime timestamp;

  DashboardAlert({
    required this.id,
    required this.type,
    required this.severity,
    required this.title,
    required this.message,
    this.clusterId,
    required this.timestamp,
  });

  factory DashboardAlert.fromJson(Map<String, dynamic> json) {
    return DashboardAlert(
      id: json['id'],
      type: json['type'],
      severity: json['severity'],
      title: json['title'],
      message: json['message'],
      clusterId: json['cluster_id'],
      timestamp: DateTime.parse(json['timestamp']),
    );
  }

  bool get isCritical => severity == 'critical';
  bool get isWarning => severity == 'warning';
}

// Dashboard Provider
class DashboardNotifier extends StateNotifier<DashboardState> {
  final ApiClient _apiClient = ApiClient();

  DashboardNotifier() : super(const DashboardState());

  Future<void> loadDashboardData() async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      // Load clusters data
      final clusters = await _apiClient.getClusters();
      
      // Load cluster health for each cluster
      final clustersWithHealth = <ClusterInfo>[];
      for (final cluster in clusters) {
        try {
          final health = await _apiClient.getClusterHealth(cluster.id);
          clustersWithHealth.add(ClusterInfo(
            id: cluster.id,
            name: cluster.name,
            description: cluster.description,
            status: cluster.status,
            kubernetesVersion: cluster.kubernetesVersion,
            nodeCount: cluster.nodeCount,
            endpoint: cluster.endpoint,
            createdAt: cluster.createdAt,
            lastSeen: cluster.lastSeen,
            metadata: cluster.metadata,
            health: health,
          ));
        } catch (e) {
          // If health check fails, add cluster without health data
          clustersWithHealth.add(cluster);
        }
      }

      // Load analytics data (mock for now)
      final analytics = await _loadAnalyticsData();

      // Generate alerts based on cluster health
      final alerts = _generateAlerts(clustersWithHealth);

      state = state.copyWith(
        isLoading: false,
        clusters: clustersWithHealth,
        alerts: alerts,
        analytics: analytics,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  Future<void> refreshClusterHealth(String clusterId) async {
    try {
      final health = await _apiClient.getClusterHealth(clusterId);
      final updatedClusters = state.clusters.map((cluster) {
        if (cluster.id == clusterId) {
          return ClusterInfo(
            id: cluster.id,
            name: cluster.name,
            description: cluster.description,
            status: cluster.status,
            kubernetesVersion: cluster.kubernetesVersion,
            nodeCount: cluster.nodeCount,
            endpoint: cluster.endpoint,
            createdAt: cluster.createdAt,
            lastSeen: cluster.lastSeen,
            metadata: cluster.metadata,
            health: health,
          );
        }
        return cluster;
      }).toList();

      state = state.copyWith(clusters: updatedClusters);
    } catch (e) {
      // Handle error silently for individual cluster refresh
    }
  }

  Future<Map<String, dynamic>> _loadAnalyticsData() async {
    // Mock analytics data - in real implementation, this would come from the analytics API
    return {
      'totalRequests': 15420,
      'avgResponseTime': 245.6,
      'errorRate': 0.8,
      'uptime': 99.95,
      'activeUsers': 142,
      'dataTransfer': 2.4, // GB
    };
  }

  List<DashboardAlert> _generateAlerts(List<ClusterInfo> clusters) {
    final alerts = <DashboardAlert>[];
    
    for (final cluster in clusters) {
      final health = cluster.health;
      if (health == null) continue;

      // CPU usage alert
      if (health.cpuUsage > 80) {
        alerts.add(DashboardAlert(
          id: '${cluster.id}_cpu',
          type: 'resource',
          severity: health.cpuUsage > 90 ? 'critical' : 'warning',
          title: 'High CPU Usage',
          message: 'Cluster ${cluster.name} CPU usage is at ${health.cpuUsage.toStringAsFixed(1)}%',
          clusterId: cluster.id,
          timestamp: DateTime.now(),
        ));
      }

      // Memory usage alert
      if (health.memoryUsage > 80) {
        alerts.add(DashboardAlert(
          id: '${cluster.id}_memory',
          type: 'resource',
          severity: health.memoryUsage > 90 ? 'critical' : 'warning',
          title: 'High Memory Usage',
          message: 'Cluster ${cluster.name} memory usage is at ${health.memoryUsage.toStringAsFixed(1)}%',
          clusterId: cluster.id,
          timestamp: DateTime.now(),
        ));
      }

      // Node readiness alert
      if (health.totalNodes > 0 && health.readyNodes < health.totalNodes) {
        alerts.add(DashboardAlert(
          id: '${cluster.id}_nodes',
          type: 'availability',
          severity: health.readyNodes == 0 ? 'critical' : 'warning',
          title: 'Node Issues',
          message: 'Cluster ${cluster.name} has ${health.totalNodes - health.readyNodes} nodes not ready',
          clusterId: cluster.id,
          timestamp: DateTime.now(),
        ));
      }

      // Pod health alert
      if (health.totalPods > 0 && health.runningPods < health.totalPods) {
        final failedPods = health.totalPods - health.runningPods;
        if (failedPods > health.totalPods * 0.1) { // More than 10% failed
          alerts.add(DashboardAlert(
            id: '${cluster.id}_pods',
            type: 'availability',
            severity: failedPods > health.totalPods * 0.5 ? 'critical' : 'warning',
            title: 'Pod Failures',
            message: 'Cluster ${cluster.name} has $failedPods pods not running',
            clusterId: cluster.id,
            timestamp: DateTime.now(),
          ));
        }
      }

      // Cluster offline alert
      if (!cluster.isOnline) {
        alerts.add(DashboardAlert(
          id: '${cluster.id}_offline',
          type: 'connectivity',
          severity: 'critical',
          title: 'Cluster Offline',
          message: 'Cluster ${cluster.name} has been offline for more than 5 minutes',
          clusterId: cluster.id,
          timestamp: DateTime.now(),
        ));
      }
    }

    return alerts;
  }

  void clearError() {
    if (state.error != null) {
      state = state.copyWith(error: null);
    }
  }
}

// Providers
final dashboardProvider = StateNotifierProvider<DashboardNotifier, DashboardState>((ref) {
  return DashboardNotifier();
});

// Helper providers
final healthyClustersProvider = Provider<List<ClusterInfo>>((ref) {
  return ref.watch(dashboardProvider).clusters.where((c) => c.isHealthy).toList();
});

final criticalAlertsProvider = Provider<List<DashboardAlert>>((ref) {
  return ref.watch(dashboardProvider).alerts.where((a) => a.isCritical).toList();
});

final clusterMetricsProvider = Provider<Map<String, double>>((ref) {
  final clusters = ref.watch(dashboardProvider).clusters;
  if (clusters.isEmpty) return {};

  double totalCpu = 0;
  double totalMemory = 0;
  double totalDisk = 0;
  int count = 0;

  for (final cluster in clusters) {
    if (cluster.health != null) {
      totalCpu += cluster.health!.cpuUsage;
      totalMemory += cluster.health!.memoryUsage;
      totalDisk += cluster.health!.diskUsage;
      count++;
    }
  }

  if (count == 0) return {};

  return {
    'avgCpu': totalCpu / count,
    'avgMemory': totalMemory / count,
    'avgDisk': totalDisk / count,
  };
});