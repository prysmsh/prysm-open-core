import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';

import '../api/api_client.dart';
import '../models/mesh_models.dart';
import '../storage/storage_service.dart';

enum DERPConnectionState {
  disconnected,
  connecting,
  connected,
  reconnecting,
  error,
}

class DERPClient {
  static final DERPClient _instance = DERPClient._internal();
  factory DERPClient() => _instance;
  DERPClient._internal();

  final ApiClient _apiClient = ApiClient();

  DERPConnectionState _state = DERPConnectionState.disconnected;
  final _stateController = StreamController<DERPConnectionState>.broadcast();
  final _messageController = StreamController<MeshMessage>.broadcast();
  final _peersController = StreamController<List<MeshPeer>>.broadcast();
  final _servicesController = StreamController<List<ServiceDiscovery>>.broadcast();

  String? _organizationId;
  String? _deviceId;
  List<MeshPeer> _peers = [];
  List<ServiceDiscovery> _services = [];
  MeshStats? _stats;
  Timer? _refreshTimer;
  bool _refreshing = false;

  int _messagesSent = 0;
  int _messagesReceived = 0;
  int _bytesTransferred = 0;

  static const Duration _refreshInterval = Duration(seconds: 30);

  // Streams
  Stream<DERPConnectionState> get stateStream => _stateController.stream;
  Stream<MeshMessage> get messageStream => _messageController.stream;
  Stream<List<MeshPeer>> get peersStream => _peersController.stream;
  Stream<List<ServiceDiscovery>> get servicesStream => _servicesController.stream;

  // Getters
  DERPConnectionState get state => _state;
  List<MeshPeer> get peers => List.unmodifiable(_peers);
  List<ServiceDiscovery> get services => List.unmodifiable(_services);
  MeshStats? get stats => _stats;
  bool get isConnected => _state == DERPConnectionState.connected;

  Future<void> initialize({required String organizationId}) async {
    _organizationId = organizationId;
    _deviceId = await _getOrCreateDeviceId();
  }

  Future<void> connect() async {
    if (_state == DERPConnectionState.connecting ||
        _state == DERPConnectionState.connected) {
      return;
    }

    if (_organizationId == null || _organizationId!.isEmpty) {
      throw Exception('Organization context is required for mesh connectivity');
    }

    _setState(DERPConnectionState.connecting);

    try {
      await _refreshMeshData();
      _refreshTimer?.cancel();
      _refreshTimer = Timer.periodic(
        _refreshInterval,
        (_) => _refreshMeshData(),
      );
      _setState(DERPConnectionState.connected);
    } catch (e, stack) {
      debugPrint('Mesh sync failed: $e');
      debugPrint(stack.toString());
      _setState(DERPConnectionState.error);
      rethrow;
    }
  }

  Future<void> disconnect() async {
    _refreshTimer?.cancel();
    _refreshTimer = null;
    _setState(DERPConnectionState.disconnected);
  }

  Future<void> discoverServices(String clusterId) async {
    if (!isConnected) return;

    try {
      final services = await _apiClient.getClusterServices(clusterId);
      _services = services;
      _servicesController.add(_services);
      _updateStats();

      final payload = {
        'cluster_id': clusterId,
        'service_count': services.length,
        'services': services
            .map((service) => {
                  'name': service.serviceName,
                  'namespace': service.namespace,
                  'type': service.serviceType,
                  'endpoints':
                      service.endpoints.map((endpoint) => endpoint.address).toList(),
                })
            .toList(),
      };

      final message = MeshMessage(
        id: _generateMessageId(),
        fromPeer: 'cluster-$clusterId',
        toPeer: _deviceId ?? 'desktop',
        messageType: 'service_discovery',
        payload: payload,
        timestamp: DateTime.now(),
      );

      _recordMessage(message);
    } catch (e) {
      debugPrint('Service discovery failed: $e');
      rethrow;
    }
  }

  Future<void> executeRemoteCommand(String clusterId, String command) async {
    if (!isConnected) return;

    try {
      final response = await _apiClient.executeCommand(clusterId, command);
      final message = MeshMessage(
        id: _generateMessageId(),
        fromPeer: 'cluster-$clusterId',
        toPeer: _deviceId ?? 'desktop',
        messageType: 'command_result',
        payload: response,
        timestamp: DateTime.now(),
      );
      _recordMessage(message);
    } catch (e) {
      debugPrint('Remote command failed: $e');
      rethrow;
    }
  }

  Future<void> requestClusterMetrics(String clusterId) async {
    if (!isConnected) return;

    try {
      final response = await _apiClient.getClusterMeshStatus(clusterId);
      final message = MeshMessage(
        id: _generateMessageId(),
        fromPeer: 'cluster-$clusterId',
        toPeer: _deviceId ?? 'desktop',
        messageType: 'mesh_status',
        payload: response,
        timestamp: DateTime.now(),
      );
      _recordMessage(message);
    } catch (e) {
      debugPrint('Cluster metrics request failed: $e');
      rethrow;
    }
  }

  Future<void> sendMessage(MeshMessage message) async {
    _messagesSent++;
    _updateStats();
    throw UnsupportedError(
      'Custom DERP messaging is not available via the HTTP mesh API',
    );
  }

  void dispose() {
    _refreshTimer?.cancel();
    _stateController.close();
    _messageController.close();
    _peersController.close();
    _servicesController.close();
  }

  Future<void> _refreshMeshData() async {
    if (_refreshing) {
      return;
    }

    _refreshing = true;
    try {
      final nodes = await _apiClient.getMeshNodes();
      _peers = nodes;
      _peersController.add(_peers);
      _updateStats();
    } finally {
      _refreshing = false;
    }
  }

  void _recordMessage(MeshMessage message) {
    _messagesReceived++;
    final encoded = jsonEncode(message.toJson());
    _bytesTransferred += encoded.length;
    _messageController.add(message);
    _updateStats();
  }

  void _updateStats() {
    final connectedPeers = _peers.where((peer) => peer.isOnline).length;
    final activeClusters = _peers
        .where((peer) => peer.isCluster && peer.clusterId != null)
        .map((peer) => peer.clusterId)
        .whereType<int>()
        .toSet()
        .length;

    _stats = MeshStats(
      totalPeers: _peers.length,
      connectedPeers: connectedPeers,
      activeClusters: activeClusters,
      totalServices: _services.length,
      messagesSent: _messagesSent,
      messagesReceived: _messagesReceived,
      bytesTransferred: _bytesTransferred,
      avgLatency: 0,
      lastUpdated: DateTime.now(),
    );
  }

  void _setState(DERPConnectionState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(_state);
    }
  }

  String _generateMessageId() {
    return '${DateTime.now().millisecondsSinceEpoch}_${Random().nextInt(10000)}';
  }

  Future<String> _getOrCreateDeviceId() async {
    String? deviceId = StorageService.instance.getSetting('device_id');
    if (deviceId == null) {
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final random = Random().nextInt(100000);
      deviceId = 'flutter_${Platform.operatingSystem}_${timestamp}_$random';
      await StorageService.instance.setSetting('device_id', deviceId);
    }
    return deviceId;
  }
}
