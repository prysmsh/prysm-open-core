class ClusterInfo {
  final String id;
  final String name;
  final String? description;
  final String status;
  final String kubernetesVersion;
  final int nodeCount;
  final String endpoint;
  final DateTime createdAt;
  final DateTime lastSeen;
  final Map<String, dynamic>? metadata;
  final ClusterHealth? health;

  ClusterInfo({
    required this.id,
    required this.name,
    this.description,
    required this.status,
    required this.kubernetesVersion,
    required this.nodeCount,
    required this.endpoint,
    required this.createdAt,
    required this.lastSeen,
    this.metadata,
    this.health,
  });

  factory ClusterInfo.fromJson(Map<String, dynamic> json) {
    return ClusterInfo(
      id: json['id'],
      name: json['name'],
      description: json['description'],
      status: json['status'],
      kubernetesVersion: json['kubernetes_version'],
      nodeCount: json['node_count'] ?? 0,
      endpoint: json['endpoint'],
      createdAt: DateTime.parse(json['created_at']),
      lastSeen: DateTime.parse(json['last_seen']),
      metadata: json['metadata'],
      health: json['health'] != null 
          ? ClusterHealth.fromJson(json['health'])
          : null,
    );
  }

  bool get isHealthy => status == 'healthy' || status == 'active';
  bool get isOnline => DateTime.now().difference(lastSeen).inMinutes < 5;
  
  String get statusDisplay {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'active':
        return 'Healthy';
      case 'degraded':
        return 'Degraded';
      case 'unhealthy':
        return 'Unhealthy';
      case 'offline':
        return 'Offline';
      default:
        return status;
    }
  }
}

class ClusterHealth {
  final String overall;
  final int totalNodes;
  final int readyNodes;
  final int totalPods;
  final int runningPods;
  final double cpuUsage;
  final double memoryUsage;
  final double diskUsage;
  final List<ClusterCondition> conditions;
  final DateTime lastChecked;

  ClusterHealth({
    required this.overall,
    required this.totalNodes,
    required this.readyNodes,
    required this.totalPods,
    required this.runningPods,
    required this.cpuUsage,
    required this.memoryUsage,
    required this.diskUsage,
    required this.conditions,
    required this.lastChecked,
  });

  factory ClusterHealth.fromJson(Map<String, dynamic> json) {
    return ClusterHealth(
      overall: json['overall'],
      totalNodes: json['total_nodes'] ?? 0,
      readyNodes: json['ready_nodes'] ?? 0,
      totalPods: json['total_pods'] ?? 0,
      runningPods: json['running_pods'] ?? 0,
      cpuUsage: (json['cpu_usage'] ?? 0.0).toDouble(),
      memoryUsage: (json['memory_usage'] ?? 0.0).toDouble(),
      diskUsage: (json['disk_usage'] ?? 0.0).toDouble(),
      conditions: (json['conditions'] as List? ?? [])
          .map((condition) => ClusterCondition.fromJson(condition))
          .toList(),
      lastChecked: DateTime.parse(json['last_checked']),
    );
  }

  bool get isHealthy => overall == 'healthy';
  double get nodeReadyPercentage => totalNodes > 0 ? (readyNodes / totalNodes) * 100 : 0;
  double get podRunningPercentage => totalPods > 0 ? (runningPods / totalPods) * 100 : 0;
}

class ClusterCondition {
  final String type;
  final String status;
  final String? reason;
  final String? message;
  final DateTime lastTransition;

  ClusterCondition({
    required this.type,
    required this.status,
    this.reason,
    this.message,
    required this.lastTransition,
  });

  factory ClusterCondition.fromJson(Map<String, dynamic> json) {
    return ClusterCondition(
      type: json['type'],
      status: json['status'],
      reason: json['reason'],
      message: json['message'],
      lastTransition: DateTime.parse(json['last_transition']),
    );
  }

  bool get isTrue => status == 'True';
}

class ClusterMetrics {
  final String clusterId;
  final DateTime timestamp;
  final double cpuUsage;
  final double memoryUsage;
  final double diskUsage;
  final double networkInBytes;
  final double networkOutBytes;
  final int activeConnections;
  final Map<String, dynamic>? additionalMetrics;

  ClusterMetrics({
    required this.clusterId,
    required this.timestamp,
    required this.cpuUsage,
    required this.memoryUsage,
    required this.diskUsage,
    required this.networkInBytes,
    required this.networkOutBytes,
    required this.activeConnections,
    this.additionalMetrics,
  });

  factory ClusterMetrics.fromJson(Map<String, dynamic> json) {
    return ClusterMetrics(
      clusterId: json['cluster_id'],
      timestamp: DateTime.parse(json['timestamp']),
      cpuUsage: (json['cpu_usage'] ?? 0.0).toDouble(),
      memoryUsage: (json['memory_usage'] ?? 0.0).toDouble(),
      diskUsage: (json['disk_usage'] ?? 0.0).toDouble(),
      networkInBytes: (json['network_in_bytes'] ?? 0.0).toDouble(),
      networkOutBytes: (json['network_out_bytes'] ?? 0.0).toDouble(),
      activeConnections: json['active_connections'] ?? 0,
      additionalMetrics: json['additional_metrics'],
    );
  }
}

class NodeInfo {
  final String name;
  final String status;
  final String? nodeType;
  final String kubernetesVersion;
  final String operatingSystem;
  final String architecture;
  final Map<String, String> labels;
  final DateTime createdAt;

  NodeInfo({
    required this.name,
    required this.status,
    this.nodeType,
    required this.kubernetesVersion,
    required this.operatingSystem,
    required this.architecture,
    required this.labels,
    required this.createdAt,
  });

  factory NodeInfo.fromJson(Map<String, dynamic> json) {
    return NodeInfo(
      name: json['name'],
      status: json['status'],
      nodeType: json['node_type'],
      kubernetesVersion: json['kubernetes_version'],
      operatingSystem: json['operating_system'],
      architecture: json['architecture'],
      labels: Map<String, String>.from(json['labels'] ?? {}),
      createdAt: DateTime.parse(json['created_at']),
    );
  }

  bool get isReady => status == 'Ready';
}