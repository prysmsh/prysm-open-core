class MeshPeer {
  final int id;
  final int organizationId;
  final int? clusterId;
  final int? userId;
  final String deviceId;
  final String peerType;
  final String status;
  final Map<String, dynamic>? capabilities;
  final bool exitEnabled;
  final int exitPriority;
  final List<String> exitRegions;
  final Map<String, dynamic>? exitCIDRs;
  final String? exitNotes;
  final DateTime? lastPing;
  final Map<String, dynamic>? lastHealth;
  final DateTime createdAt;
  final DateTime updatedAt;

  MeshPeer({
    required this.id,
    required this.organizationId,
    this.clusterId,
    this.userId,
    required this.deviceId,
    required this.peerType,
    required this.status,
    this.capabilities,
    required this.exitEnabled,
    required this.exitPriority,
    required this.exitRegions,
    this.exitCIDRs,
    this.exitNotes,
    this.lastPing,
    this.lastHealth,
    required this.createdAt,
    required this.updatedAt,
  });

  factory MeshPeer.fromJson(Map<String, dynamic> json) {
    if (json.isEmpty) {
      final now = DateTime.now();
      return MeshPeer(
        id: 0,
        organizationId: 0,
        deviceId: 'unknown',
        peerType: 'client',
        status: 'unknown',
        exitEnabled: false,
        exitPriority: 100,
        exitRegions: const [],
        createdAt: now,
        updatedAt: now,
      );
    }

    final now = DateTime.now();

    Map<String, dynamic>? toNullableMap(dynamic value) {
      if (value is Map<String, dynamic>) {
        return value;
      }
      if (value is Map) {
        return value.map((key, val) => MapEntry(key.toString(), val));
      }
      return null;
    }

    final hasLegacyShape = json.containsKey('id') && json.containsKey('organization_id');

    if (hasLegacyShape) {
      return MeshPeer(
        id: json['id'] ?? 0,
        organizationId: json['organization_id'] ?? 0,
        clusterId: json['cluster_id'],
        userId: json['user_id'],
        deviceId: json['device_id']?.toString() ?? 'unknown',
        peerType: json['peer_type']?.toString() ?? 'client',
        status: json['status']?.toString() ?? 'unknown',
        capabilities: toNullableMap(json['capabilities']),
        exitEnabled: json['exit_enabled'] ?? false,
        exitPriority: json['exit_priority'] ?? 100,
        exitRegions: List<String>.from(json['exit_regions'] ?? const <String>[]),
        exitCIDRs: toNullableMap(json['exit_cidrs']),
        exitNotes: json['exit_notes']?.toString(),
        lastPing: json['last_ping'] != null ? DateTime.tryParse(json['last_ping'].toString()) : null,
        lastHealth: toNullableMap(json['last_health']),
        createdAt: DateTime.tryParse(json['created_at'].toString()) ?? now,
        updatedAt: DateTime.tryParse(json['updated_at'].toString()) ?? now,
      );
    }

    final deviceId = json['device_id']?.toString() ?? json['client_id']?.toString() ?? 'unknown';
    final organizationId = json['organization_id'] is int
        ? json['organization_id'] as int
        : int.tryParse(json['organization_id']?.toString() ?? '') ?? 0;
    final region = json['region']?.toString();
    final lastSeenRaw = json['last_seen']?.toString();

    return MeshPeer(
      id: 0,
      organizationId: organizationId,
      clusterId: json['cluster_id'] is int ? json['cluster_id'] as int : null,
      userId: null,
      deviceId: deviceId,
      peerType: json['peer_type']?.toString() ?? 'client',
      status: json['status']?.toString() ?? 'connected',
      capabilities: toNullableMap(json['capabilities']),
      exitEnabled: false,
      exitPriority: 100,
      exitRegions: region != null ? [region] : const [],
      exitCIDRs: null,
      exitNotes: null,
      lastPing: lastSeenRaw != null ? DateTime.tryParse(lastSeenRaw) : null,
      lastHealth: null,
      createdAt: now,
      updatedAt: now,
    );
  }

  bool get isOnline => status == 'connected' && 
      lastPing != null && 
      DateTime.now().difference(lastPing!).inMinutes < 5;
  
  bool get isCluster => peerType == 'cluster';
  bool get isClient => peerType == 'client';
  bool get isExitNode => exitEnabled;
  
  String get displayName {
    if (isCluster && clusterId != null) {
      return 'Cluster $clusterId';
    }
    return deviceId;
  }
}

class DERPServer {
  final String id;
  final String name;
  final String url;
  final String region;
  final bool isActive;
  final int latency;
  final DateTime lastSeen;

  DERPServer({
    required this.id,
    required this.name,
    required this.url,
    required this.region,
    required this.isActive,
    required this.latency,
    required this.lastSeen,
  });

  factory DERPServer.fromJson(Map<String, dynamic> json) {
    return DERPServer(
      id: json['id'],
      name: json['name'],
      url: json['url'],
      region: json['region'],
      isActive: json['is_active'] ?? false,
      latency: json['latency'] ?? 0,
      lastSeen: DateTime.parse(json['last_seen']),
    );
  }

  bool get isHealthy => isActive && latency < 500;
}

class MeshConnection {
  final String peerId;
  final String connectionType;
  final String status;
  final int latency;
  final int bytesSent;
  final int bytesReceived;
  final DateTime connectedAt;
  final DateTime lastActivity;

  MeshConnection({
    required this.peerId,
    required this.connectionType,
    required this.status,
    required this.latency,
    required this.bytesSent,
    required this.bytesReceived,
    required this.connectedAt,
    required this.lastActivity,
  });

  factory MeshConnection.fromJson(Map<String, dynamic> json) {
    return MeshConnection(
      peerId: json['peer_id'],
      connectionType: json['connection_type'],
      status: json['status'],
      latency: json['latency'] ?? 0,
      bytesSent: json['bytes_sent'] ?? 0,
      bytesReceived: json['bytes_received'] ?? 0,
      connectedAt: DateTime.parse(json['connected_at']),
      lastActivity: DateTime.parse(json['last_activity']),
    );
  }

  bool get isActive => status == 'connected';
  bool get isDirect => connectionType == 'direct';
  bool get isRelayed => connectionType == 'relay';
}

class MeshMessage {
  final String id;
  final String fromPeer;
  final String toPeer;
  final String messageType;
  final Map<String, dynamic> payload;
  final Map<String, dynamic>? metadata;
  final DateTime timestamp;

  MeshMessage({
    required this.id,
    required this.fromPeer,
    required this.toPeer,
    required this.messageType,
    required this.payload,
    this.metadata,
    required this.timestamp,
  });

  factory MeshMessage.fromJson(Map<String, dynamic> json) {
    Map<String, dynamic> toMap(dynamic value) {
      if (value is Map<String, dynamic>) {
        return value;
      }
      if (value is Map) {
        return value.map((key, val) => MapEntry(key.toString(), val));
      }
      return {};
    }

    final metadata = toMap(json['metadata']);
    final payload = toMap(json['payload'] ?? json['data']);
    final timestampRaw = json['timestamp'] ?? metadata?['timestamp'];
    final timestamp = timestampRaw != null
        ? DateTime.tryParse(timestampRaw.toString()) ?? DateTime.now()
        : DateTime.now();

    return MeshMessage(
      id: json['id']?.toString() ??
          metadata?['id']?.toString() ??
          '${DateTime.now().millisecondsSinceEpoch}',
      fromPeer: json['from_peer']?.toString() ?? json['from']?.toString() ?? '',
      toPeer: json['to_peer']?.toString() ?? json['to']?.toString() ?? '',
      messageType: json['message_type']?.toString() ??
          metadata?['message_type']?.toString() ??
          payload['message_type']?.toString() ??
          'unknown',
      payload: payload,
      metadata: metadata.isEmpty ? null : metadata,
      timestamp: timestamp,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'from_peer': fromPeer,
      'to_peer': toPeer,
      'message_type': messageType,
      'payload': payload,
      'metadata': metadata,
      'timestamp': timestamp.toIso8601String(),
    };
  }

  Map<String, dynamic> toDerpDataPayload() {
    return {
      'id': id,
      'message_type': messageType,
      'payload': payload,
      'timestamp': timestamp.toIso8601String(),
    };
  }

  Map<String, dynamic> toDerpMetadata() {
    return {
      'id': id,
      'message_type': messageType,
      if (metadata != null) ...metadata!,
    };
  }
}

class ServiceDiscovery {
  final String serviceName;
  final String clusterId;
  final String namespace;
  final String serviceType;
  final List<ServiceEndpoint> endpoints;
  final Map<String, String> labels;
  final DateTime discoveredAt;
  final DateTime lastSeen;

  ServiceDiscovery({
    required this.serviceName,
    required this.clusterId,
    required this.namespace,
    required this.serviceType,
    required this.endpoints,
    required this.labels,
    required this.discoveredAt,
    required this.lastSeen,
  });

  factory ServiceDiscovery.fromJson(Map<String, dynamic> json) {
    return ServiceDiscovery(
      serviceName: json['service_name'],
      clusterId: json['cluster_id'],
      namespace: json['namespace'],
      serviceType: json['service_type'],
      endpoints: (json['endpoints'] as List)
          .map((ep) => ServiceEndpoint.fromJson(ep))
          .toList(),
      labels: Map<String, String>.from(json['labels'] ?? {}),
      discoveredAt: DateTime.parse(json['discovered_at']),
      lastSeen: DateTime.parse(json['last_seen']),
    );
  }

  factory ServiceDiscovery.fromClusterEntry({
    required String serviceKey,
    required Map<String, dynamic> payload,
    required String clusterId,
  }) {
    final now = DateTime.now();
    final keyParts = serviceKey.split('/');
    final inferredNamespace = payload['namespace']?.toString() ??
        (keyParts.length > 1 ? keyParts.first : 'default');
    final inferredName = payload['service_name']?.toString() ??
        payload['name']?.toString() ??
        (keyParts.length > 1 ? keyParts.last : serviceKey);

    final endpoints = _parseEndpoints(
      payload['endpoints'] ?? payload['targets'] ?? payload['ports'],
      payload,
    );

    final labels = _stringMap(payload['labels']);

    return ServiceDiscovery(
      serviceName: inferredName,
      clusterId: clusterId,
      namespace: inferredNamespace,
      serviceType: payload['service_type']?.toString() ??
          payload['type']?.toString() ??
          'ClusterIP',
      endpoints: endpoints,
      labels: labels,
      discoveredAt: _parseTimestamp(payload['discovered_at']) ?? now,
      lastSeen: _parseTimestamp(payload['last_seen']) ?? now,
    );
  }

  static List<ServiceDiscovery> fromClusterServicesPayload(
    Map<String, dynamic>? services,
    String clusterId,
  ) {
    if (services == null || services.isEmpty) {
      return [];
    }

    final List<ServiceDiscovery> results = [];
    services.forEach((key, value) {
      if (value is Map) {
        results.add(
          ServiceDiscovery.fromClusterEntry(
            serviceKey: key,
            payload: Map<String, dynamic>.from(value),
            clusterId: clusterId,
          ),
        );
      } else {
        final now = DateTime.now();
        results.add(
          ServiceDiscovery(
            serviceName: key,
            clusterId: clusterId,
            namespace: 'default',
            serviceType: 'ClusterIP',
            endpoints: const <ServiceEndpoint>[],
            labels: const <String, String>{},
            discoveredAt: now,
            lastSeen: now,
          ),
        );
      }
    });

    return results;
  }

  static DateTime? _parseTimestamp(dynamic value) {
    if (value == null) {
      return null;
    }
    if (value is DateTime) {
      return value;
    }
    if (value is int) {
      return DateTime.fromMillisecondsSinceEpoch(value);
    }
    return DateTime.tryParse(value.toString());
  }

  static Map<String, String> _stringMap(dynamic input) {
    if (input is Map) {
      return input.map((key, value) => MapEntry(
            key.toString(),
            value?.toString() ?? '',
          ));
    }
    return const {};
  }

  static List<ServiceEndpoint> _parseEndpoints(
    dynamic raw,
    Map<String, dynamic> payload,
  ) {
    final clusterIP = payload['cluster_ip'] ??
        payload['clusterIP'] ??
        payload['ip'] ??
        '0.0.0.0';

    final endpoints = <ServiceEndpoint>[];
    if (raw is List) {
      for (final entry in raw) {
        final map = entry is Map
            ? Map<String, dynamic>.from(entry)
            : <String, dynamic>{};
        map.putIfAbsent('ip', () => clusterIP);
        map.putIfAbsent(
            'port', () => map['target_port'] ?? map['service_port'] ?? 0);
        endpoints.add(ServiceEndpoint.fromJson(map));
      }
    } else if (raw is Map) {
      raw.forEach((key, value) {
        if (value is Map) {
          final map = Map<String, dynamic>.from(value);
          map.putIfAbsent('ip', () => value['ip'] ?? key);
          map.putIfAbsent(
              'port', () => value['port'] ?? value['target_port'] ?? 0);
          endpoints.add(ServiceEndpoint.fromJson(map));
        } else {
          endpoints.add(
            ServiceEndpoint.fromJson({
              'ip': key,
              'port': value,
            }),
          );
        }
      });
    } else if (raw != null) {
      endpoints.add(ServiceEndpoint.fromJson(raw));
    }

    if (endpoints.isEmpty) {
      endpoints.add(
        ServiceEndpoint(
          ip: clusterIP.toString(),
          port: 0,
          protocol: 'TCP',
          ready: true,
        ),
      );
    }

    return endpoints;
  }

  String get fqdn => '$serviceName.$namespace.svc.cluster.local';
  bool get isActive => DateTime.now().difference(lastSeen).inMinutes < 10;
}

class ServiceEndpoint {
  final String ip;
  final int port;
  final String protocol;
  final bool ready;

  ServiceEndpoint({
    required this.ip,
    required this.port,
    required this.protocol,
    required this.ready,
  });

  factory ServiceEndpoint.fromJson(dynamic json) {
    if (json is ServiceEndpoint) {
      return json;
    }
    if (json is String) {
      final parts = json.split('/');
      final address = parts.first;
      final protocol = parts.length > 1 ? parts.last.toUpperCase() : 'TCP';
      final addressParts = address.split(':');
      final ip = addressParts.first;
      final port =
          addressParts.length > 1 ? int.tryParse(addressParts[1]) ?? 0 : 0;
      return ServiceEndpoint(
        ip: ip,
        port: port,
        protocol: protocol,
        ready: true,
      );
    }

    final map = json is Map
        ? json.map((key, value) => MapEntry(key.toString(), value))
        : <String, dynamic>{};
    final ip = map['ip']?.toString() ?? map['host']?.toString() ?? '0.0.0.0';
    final port = int.tryParse(map['port']?.toString() ?? '') ??
        int.tryParse(map['target_port']?.toString() ?? '') ??
        int.tryParse(map['service_port']?.toString() ?? '') ??
        0;
    final protocol =
        (map['protocol'] ?? map['proto'] ?? 'TCP').toString().toUpperCase();
    final readyRaw = map['ready'] ?? map['healthy'] ?? map['available'] ?? true;
    final ready = readyRaw is bool
        ? readyRaw
        : readyRaw.toString().toLowerCase() != 'false';

    return ServiceEndpoint(
      ip: ip,
      port: port,
      protocol: protocol,
      ready: ready,
    );
  }

  String get address => '$ip:$port';
}

class MeshStats {
  final int totalPeers;
  final int connectedPeers;
  final int activeClusters;
  final int totalServices;
  final int messagesSent;
  final int messagesReceived;
  final int bytesTransferred;
  final double avgLatency;
  final DateTime lastUpdated;

  MeshStats({
    required this.totalPeers,
    required this.connectedPeers,
    required this.activeClusters,
    required this.totalServices,
    required this.messagesSent,
    required this.messagesReceived,
    required this.bytesTransferred,
    required this.avgLatency,
    required this.lastUpdated,
  });

  factory MeshStats.fromJson(Map<String, dynamic> json) {
    return MeshStats(
      totalPeers: json['total_peers'] ?? 0,
      connectedPeers: json['connected_peers'] ?? 0,
      activeClusters: json['active_clusters'] ?? 0,
      totalServices: json['total_services'] ?? 0,
      messagesSent: json['messages_sent'] ?? 0,
      messagesReceived: json['messages_received'] ?? 0,
      bytesTransferred: json['bytes_transferred'] ?? 0,
      avgLatency: (json['avg_latency'] ?? 0.0).toDouble(),
      lastUpdated: DateTime.parse(json['last_updated']),
    );
  }

  double get connectionRate => totalPeers > 0 ? (connectedPeers / totalPeers) * 100 : 0;
}
