import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/networking/derp_client.dart';
import '../../../../core/models/mesh_models.dart';
import '../../../../shared/providers/auth_provider.dart';

// Mesh State
class MeshState {
  final DERPConnectionState connectionState;
  final List<MeshPeer> peers;
  final List<ServiceDiscovery> services;
  final List<MeshMessage> recentMessages;
  final MeshStats? stats;
  final String? error;
  final DateTime lastUpdated;

  const MeshState({
    this.connectionState = DERPConnectionState.disconnected,
    this.peers = const [],
    this.services = const [],
    this.recentMessages = const [],
    this.stats,
    this.error,
    required this.lastUpdated,
  });

  MeshState copyWith({
    DERPConnectionState? connectionState,
    List<MeshPeer>? peers,
    List<ServiceDiscovery>? services,
    List<MeshMessage>? recentMessages,
    MeshStats? stats,
    String? error,
    DateTime? lastUpdated,
  }) {
    return MeshState(
      connectionState: connectionState ?? this.connectionState,
      peers: peers ?? this.peers,
      services: services ?? this.services,
      recentMessages: recentMessages ?? this.recentMessages,
      stats: stats ?? this.stats,
      error: error,
      lastUpdated: lastUpdated ?? this.lastUpdated,
    );
  }

  bool get isConnected => connectionState == DERPConnectionState.connected;
  bool get isConnecting => connectionState == DERPConnectionState.connecting;
  bool get isReconnecting => connectionState == DERPConnectionState.reconnecting;
  bool get hasError => error != null;

  List<MeshPeer> get onlinePeers => peers.where((p) => p.isOnline).toList();
  List<MeshPeer> get clusterPeers => peers.where((p) => p.isCluster).toList();
  List<MeshPeer> get clientPeers => peers.where((p) => p.isClient).toList();
  List<ServiceDiscovery> get activeServices => services.where((s) => s.isActive).toList();
}

// Mesh Provider
class MeshNotifier extends StateNotifier<MeshState> {
  MeshNotifier(this._ref) : super(MeshState(lastUpdated: DateTime.now())) {
    _initializeSubscriptions();
  }

  final Ref _ref;
  final DERPClient _derpClient = DERPClient();
  StreamSubscription? _stateSubscription;
  StreamSubscription? _peersSubscription;
  StreamSubscription? _servicesSubscription;
  StreamSubscription? _messagesSubscription;

  @override
  void dispose() {
    _stateSubscription?.cancel();
    _peersSubscription?.cancel();
    _servicesSubscription?.cancel();
    _messagesSubscription?.cancel();
    _derpClient.dispose();
    super.dispose();
  }

  Future<void> connect() async {
    try {
      final authState = _ref.read(authProvider);
      final organizationId = authState.organization?.id;

      if (organizationId == null || organizationId.isEmpty) {
        throw Exception('Organization context unavailable for DERP connection');
      }

      await _derpClient.initialize(organizationId: organizationId);
      await _derpClient.connect();
    } catch (e) {
      state = state.copyWith(
        error: e.toString(),
        lastUpdated: DateTime.now(),
      );
    }
  }

  Future<void> disconnect() async {
    await _derpClient.disconnect();
  }

  Future<void> reconnect() async {
    await disconnect();
    await connect();
  }

  Future<void> discoverServices(String clusterId) async {
    try {
      await _derpClient.discoverServices(clusterId);
    } catch (e) {
      state = state.copyWith(
        error: 'Failed to discover services: $e',
        lastUpdated: DateTime.now(),
      );
    }
  }

  Future<void> executeRemoteCommand(String clusterId, String command) async {
    try {
      await _derpClient.executeRemoteCommand(clusterId, command);
    } catch (e) {
      state = state.copyWith(
        error: 'Failed to execute command: $e',
        lastUpdated: DateTime.now(),
      );
    }
  }

  Future<void> requestClusterMetrics(String clusterId) async {
    try {
      await _derpClient.requestClusterMetrics(clusterId);
    } catch (e) {
      state = state.copyWith(
        error: 'Failed to request metrics: $e',
        lastUpdated: DateTime.now(),
      );
    }
  }

  Future<void> sendCustomMessage(String toPeer, String messageType, Map<String, dynamic> payload) async {
    try {
      final message = MeshMessage(
        id: '${DateTime.now().millisecondsSinceEpoch}',
        fromPeer: 'flutter_client', // This will be set by DERP client
        toPeer: toPeer,
        messageType: messageType,
        payload: payload,
        timestamp: DateTime.now(),
      );

      await _derpClient.sendMessage(message);
    } catch (e) {
      state = state.copyWith(
        error: 'Failed to send message: $e',
        lastUpdated: DateTime.now(),
      );
    }
  }

  void clearError() {
    if (state.hasError) {
      state = state.copyWith(error: null, lastUpdated: DateTime.now());
    }
  }

  void _initializeSubscriptions() {
    // Listen to connection state changes
    _stateSubscription = _derpClient.stateStream.listen((connectionState) {
      state = state.copyWith(
        connectionState: connectionState,
        error: null, // Clear error when state changes
        lastUpdated: DateTime.now(),
      );
    });

    // Listen to peer updates
    _peersSubscription = _derpClient.peersStream.listen((peers) {
      state = state.copyWith(
        peers: peers,
        lastUpdated: DateTime.now(),
      );
    });

    // Listen to service discovery updates
    _servicesSubscription = _derpClient.servicesStream.listen((services) {
      state = state.copyWith(
        services: services,
        lastUpdated: DateTime.now(),
      );
    });

    // Listen to incoming messages
    _messagesSubscription = _derpClient.messageStream.listen((message) {
      final updatedMessages = [...state.recentMessages, message];
      
      // Keep only last 100 messages
      if (updatedMessages.length > 100) {
        updatedMessages.removeRange(0, updatedMessages.length - 100);
      }

      state = state.copyWith(
        recentMessages: updatedMessages,
        lastUpdated: DateTime.now(),
      );
    });
  }
}

// Providers
final meshProvider = StateNotifierProvider<MeshNotifier, MeshState>((ref) {
  return MeshNotifier(ref);
});

// Helper providers
final meshConnectionStateProvider = Provider<DERPConnectionState>((ref) {
  return ref.watch(meshProvider).connectionState;
});

final onlinePeersProvider = Provider<List<MeshPeer>>((ref) {
  return ref.watch(meshProvider).onlinePeers;
});

final clusterPeersProvider = Provider<List<MeshPeer>>((ref) {
  return ref.watch(meshProvider).clusterPeers;
});

final activeServicesProvider = Provider<List<ServiceDiscovery>>((ref) {
  return ref.watch(meshProvider).activeServices;
});

final meshStatsProvider = Provider<MeshStats?>((ref) {
  return ref.watch(meshProvider).stats;
});

final recentMessagesProvider = Provider<List<MeshMessage>>((ref) {
  return ref.watch(meshProvider).recentMessages;
});

// Filtered providers
final servicesByClusterProvider = Provider.family<List<ServiceDiscovery>, String>((ref, clusterId) {
  return ref.watch(meshProvider).services
      .where((service) => service.clusterId == clusterId)
      .toList();
});

final peerByIdProvider = Provider.family<MeshPeer?, String>((ref, peerId) {
  return ref.watch(meshProvider).peers
      .cast<MeshPeer?>()
      .firstWhere((peer) => peer?.deviceId == peerId, orElse: () => null);
});

// Connection status helpers
final isConnectedToMeshProvider = Provider<bool>((ref) {
  return ref.watch(meshProvider).isConnected;
});

final meshHealthProvider = Provider<Map<String, dynamic>>((ref) {
  final meshState = ref.watch(meshProvider);
  final stats = meshState.stats;
  
  return {
    'connected': meshState.isConnected,
    'totalPeers': meshState.peers.length,
    'onlinePeers': meshState.onlinePeers.length,
    'activeClusters': meshState.clusterPeers.where((p) => p.isOnline).length,
    'activeServices': meshState.activeServices.length,
    'connectionRate': stats?.connectionRate ?? 0.0,
    'avgLatency': stats?.avgLatency ?? 0.0,
    'lastUpdated': meshState.lastUpdated,
  };
});
