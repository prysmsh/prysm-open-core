class ServiceInfo {
  final String id;
  final String name;
  final String namespace;
  final String clusterId;
  final String type;
  final Map<String, int> ports;
  final String? externalIP;
  final String? loadBalancerIP;
  final Map<String, String> labels;
  final Map<String, String> annotations;
  final DateTime createdAt;
  final ServiceStatus status;

  ServiceInfo({
    required this.id,
    required this.name,
    required this.namespace,
    required this.clusterId,
    required this.type,
    required this.ports,
    this.externalIP,
    this.loadBalancerIP,
    required this.labels,
    required this.annotations,
    required this.createdAt,
    required this.status,
  });

  factory ServiceInfo.fromJson(Map<String, dynamic> json) {
    return ServiceInfo(
      id: json['id'],
      name: json['name'],
      namespace: json['namespace'],
      clusterId: json['cluster_id'],
      type: json['type'],
      ports: Map<String, int>.from(json['ports'] ?? {}),
      externalIP: json['external_ip'],
      loadBalancerIP: json['load_balancer_ip'],
      labels: Map<String, String>.from(json['labels'] ?? {}),
      annotations: Map<String, String>.from(json['annotations'] ?? {}),
      createdAt: DateTime.parse(json['created_at']),
      status: ServiceStatus.fromJson(json['status'] ?? {}),
    );
  }

  String get displayName => '$namespace/$name';
  bool get isExposed => externalIP != null || loadBalancerIP != null;
  
  String get typeDisplay {
    switch (type) {
      case 'ClusterIP':
        return 'Cluster IP';
      case 'NodePort':
        return 'Node Port';
      case 'LoadBalancer':
        return 'Load Balancer';
      case 'ExternalName':
        return 'External Name';
      default:
        return type;
    }
  }
}

class ServiceStatus {
  final String phase;
  final int readyEndpoints;
  final int totalEndpoints;
  final DateTime lastChecked;

  ServiceStatus({
    required this.phase,
    required this.readyEndpoints,
    required this.totalEndpoints,
    required this.lastChecked,
  });

  factory ServiceStatus.fromJson(Map<String, dynamic> json) {
    return ServiceStatus(
      phase: json['phase'] ?? 'Unknown',
      readyEndpoints: json['ready_endpoints'] ?? 0,
      totalEndpoints: json['total_endpoints'] ?? 0,
      lastChecked: json['last_checked'] != null 
          ? DateTime.parse(json['last_checked'])
          : DateTime.now(),
    );
  }

  bool get isHealthy => phase == 'Active' && readyEndpoints > 0;
  double get healthPercentage => totalEndpoints > 0 
      ? (readyEndpoints / totalEndpoints) * 100 
      : 0;
}

class ServiceExposure {
  final String id;
  final String serviceId;
  final String exposureType;
  final int externalPort;
  final String? customDomain;
  final bool authRequired;
  final List<String> allowedOrigins;
  final DateTime createdAt;
  final bool isActive;

  ServiceExposure({
    required this.id,
    required this.serviceId,
    required this.exposureType,
    required this.externalPort,
    this.customDomain,
    required this.authRequired,
    required this.allowedOrigins,
    required this.createdAt,
    required this.isActive,
  });

  factory ServiceExposure.fromJson(Map<String, dynamic> json) {
    return ServiceExposure(
      id: json['id'],
      serviceId: json['service_id'],
      exposureType: json['exposure_type'],
      externalPort: json['external_port'],
      customDomain: json['custom_domain'],
      authRequired: json['auth_required'] ?? false,
      allowedOrigins: List<String>.from(json['allowed_origins'] ?? []),
      createdAt: DateTime.parse(json['created_at']),
      isActive: json['is_active'] ?? true,
    );
  }

  String get typeDisplay {
    switch (exposureType) {
      case 'http':
        return 'HTTP';
      case 'tcp':
        return 'TCP';
      case 'udp':
        return 'UDP';
      default:
        return exposureType.toUpperCase();
    }
  }
}

class PodInfo {
  final String name;
  final String namespace;
  final String status;
  final String? podIP;
  final String nodeName;
  final DateTime createdAt;
  final DateTime? startTime;
  final List<ContainerInfo> containers;
  final Map<String, String> labels;

  PodInfo({
    required this.name,
    required this.namespace,
    required this.status,
    this.podIP,
    required this.nodeName,
    required this.createdAt,
    this.startTime,
    required this.containers,
    required this.labels,
  });

  factory PodInfo.fromJson(Map<String, dynamic> json) {
    return PodInfo(
      name: json['name'],
      namespace: json['namespace'],
      status: json['status'],
      podIP: json['pod_ip'],
      nodeName: json['node_name'],
      createdAt: DateTime.parse(json['created_at']),
      startTime: json['start_time'] != null 
          ? DateTime.parse(json['start_time'])
          : null,
      containers: (json['containers'] as List? ?? [])
          .map((container) => ContainerInfo.fromJson(container))
          .toList(),
      labels: Map<String, String>.from(json['labels'] ?? {}),
    );
  }

  bool get isRunning => status == 'Running';
  bool get isPending => status == 'Pending';
  bool get isFailed => status == 'Failed';
  
  String get displayName => '$namespace/$name';
}

class ContainerInfo {
  final String name;
  final String image;
  final String status;
  final int restartCount;
  final bool ready;

  ContainerInfo({
    required this.name,
    required this.image,
    required this.status,
    required this.restartCount,
    required this.ready,
  });

  factory ContainerInfo.fromJson(Map<String, dynamic> json) {
    return ContainerInfo(
      name: json['name'],
      image: json['image'],
      status: json['status'],
      restartCount: json['restart_count'] ?? 0,
      ready: json['ready'] ?? false,
    );
  }

  bool get isRunning => status == 'Running';
}