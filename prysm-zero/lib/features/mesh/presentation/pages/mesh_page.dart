import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/networking/derp_client.dart';
import '../providers/mesh_provider.dart';
import '../widgets/connection_status_card.dart';
import '../widgets/peers_list.dart';
import '../widgets/services_list.dart';
import '../widgets/mesh_stats_card.dart';
import '../widgets/recent_messages.dart';

class MeshPage extends ConsumerStatefulWidget {
  const MeshPage({Key? key}) : super(key: key);

  @override
  ConsumerState<MeshPage> createState() => _MeshPageState();
}

class _MeshPageState extends ConsumerState<MeshPage> with TickerProviderStateMixin {
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    
    // Auto-connect on page load
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final meshState = ref.read(meshProvider);
      if (meshState.connectionState == DERPConnectionState.disconnected) {
        ref.read(meshProvider.notifier).connect();
      }
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final meshState = ref.watch(meshProvider);
    final meshHealth = ref.watch(meshHealthProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Mesh Network'),
        actions: [
          // Connection status indicator
          Container(
            margin: const EdgeInsets.symmetric(horizontal: 8),
            child: Chip(
              avatar: Icon(
                _getConnectionIcon(meshState.connectionState),
                size: 16,
                color: _getConnectionColor(meshState.connectionState),
              ),
              label: Text(
                _getConnectionText(meshState.connectionState),
                style: TextStyle(
                  color: _getConnectionColor(meshState.connectionState),
                  fontWeight: FontWeight.w500,
                ),
              ),
              backgroundColor: _getConnectionColor(meshState.connectionState).withOpacity(0.1),
            ),
          ),
          // Refresh button
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              ref.read(meshProvider.notifier).reconnect();
            },
          ),
          // Connection toggle
          PopupMenuButton<String>(
            onSelected: (value) async {
              switch (value) {
                case 'connect':
                  await ref.read(meshProvider.notifier).connect();
                  break;
                case 'disconnect':
                  await ref.read(meshProvider.notifier).disconnect();
                  break;
                case 'reconnect':
                  await ref.read(meshProvider.notifier).reconnect();
                  break;
              }
            },
            itemBuilder: (context) => [
              if (!meshState.isConnected)
                const PopupMenuItem(
                  value: 'connect',
                  child: ListTile(
                    leading: Icon(Icons.power),
                    title: Text('Connect'),
                    contentPadding: EdgeInsets.zero,
                  ),
                ),
              if (meshState.isConnected)
                const PopupMenuItem(
                  value: 'disconnect',
                  child: ListTile(
                    leading: Icon(Icons.power_off),
                    title: Text('Disconnect'),
                    contentPadding: EdgeInsets.zero,
                  ),
                ),
              const PopupMenuItem(
                value: 'reconnect',
                child: ListTile(
                  leading: Icon(Icons.refresh),
                  title: Text('Reconnect'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: [
            Tab(
              text: 'Overview',
              icon: Badge(
                isLabelVisible: meshHealth['onlinePeers'] > 0,
                label: Text('${meshHealth['onlinePeers']}'),
                child: const Icon(Icons.dashboard),
              ),
            ),
            Tab(
              text: 'Peers',
              icon: Badge(
                isLabelVisible: meshState.peers.isNotEmpty,
                label: Text('${meshState.peers.length}'),
                child: const Icon(Icons.devices),
              ),
            ),
            Tab(
              text: 'Services',
              icon: Badge(
                isLabelVisible: meshState.activeServices.isNotEmpty,
                label: Text('${meshState.activeServices.length}'),
                child: const Icon(Icons.dns),
              ),
            ),
            Tab(
              text: 'Messages',
              icon: Badge(
                isLabelVisible: meshState.recentMessages.isNotEmpty,
                label: Text('${meshState.recentMessages.length}'),
                child: const Icon(Icons.message),
              ),
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          // Error banner
          if (meshState.hasError)
            Container(
              width: double.infinity,
              color: Theme.of(context).colorScheme.errorContainer,
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  Icon(
                    Icons.error_outline,
                    color: Theme.of(context).colorScheme.error,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      meshState.error!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () {
                      ref.read(meshProvider.notifier).clearError();
                    },
                    iconSize: 20,
                  ),
                ],
              ),
            ),
          
          // Tab content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                // Overview Tab
                SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Connection Status
                      ConnectionStatusCard(
                        connectionState: meshState.connectionState,
                        onConnect: () => ref.read(meshProvider.notifier).connect(),
                        onDisconnect: () => ref.read(meshProvider.notifier).disconnect(),
                      ),
                      const SizedBox(height: 16),
                      
                      // Mesh Stats
                      if (meshState.stats != null)
                        MeshStatsCard(stats: meshState.stats!),
                      
                      const SizedBox(height: 16),
                      
                      // Quick Stats Grid
                      GridView.count(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        crossAxisCount: 2,
                        childAspectRatio: 2,
                        crossAxisSpacing: 16,
                        mainAxisSpacing: 16,
                        children: [
                          _buildQuickStatCard(
                            'Total Peers',
                            '${meshState.peers.length}',
                            Icons.devices,
                            Theme.of(context).colorScheme.primary,
                          ),
                          _buildQuickStatCard(
                            'Online Peers',
                            '${meshState.onlinePeers.length}',
                            Icons.power,
                            Colors.green,
                          ),
                          _buildQuickStatCard(
                            'Active Clusters',
                            '${meshState.clusterPeers.where((p) => p.isOnline).length}',
                            Icons.cloud,
                            Theme.of(context).colorScheme.secondary,
                          ),
                          _buildQuickStatCard(
                            'Discovered Services',
                            '${meshState.activeServices.length}',
                            Icons.dns,
                            Colors.orange,
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                
                // Peers Tab
                PeersList(peers: meshState.peers),
                
                // Services Tab
                ServicesList(services: meshState.services),
                
                // Messages Tab
                RecentMessages(messages: meshState.recentMessages),
              ],
            ),
          ),
        ],
      ),
      floatingActionButton: meshState.isConnected ? FloatingActionButton(
        onPressed: () => _showServiceDiscoveryDialog(context),
        tooltip: 'Discover Services',
        child: const Icon(Icons.search),
      ) : null,
    );
  }

  Widget _buildQuickStatCard(String title, String value, IconData icon, Color color) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      value,
                      style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                        color: color,
                      ),
                    ),
                    Text(
                      title,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
                Icon(
                  icon,
                  size: 32,
                  color: color.withOpacity(0.7),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  IconData _getConnectionIcon(DERPConnectionState state) {
    switch (state) {
      case DERPConnectionState.connected:
        return Icons.check_circle;
      case DERPConnectionState.connecting:
      case DERPConnectionState.reconnecting:
        return Icons.sync;
      case DERPConnectionState.error:
        return Icons.error;
      case DERPConnectionState.disconnected:
        return Icons.radio_button_unchecked;
    }
  }

  Color _getConnectionColor(DERPConnectionState state) {
    switch (state) {
      case DERPConnectionState.connected:
        return Colors.green;
      case DERPConnectionState.connecting:
      case DERPConnectionState.reconnecting:
        return Colors.orange;
      case DERPConnectionState.error:
        return Colors.red;
      case DERPConnectionState.disconnected:
        return Colors.grey;
    }
  }

  String _getConnectionText(DERPConnectionState state) {
    switch (state) {
      case DERPConnectionState.connected:
        return 'Connected';
      case DERPConnectionState.connecting:
        return 'Connecting';
      case DERPConnectionState.reconnecting:
        return 'Reconnecting';
      case DERPConnectionState.error:
        return 'Error';
      case DERPConnectionState.disconnected:
        return 'Disconnected';
    }
  }

  void _showServiceDiscoveryDialog(BuildContext context) {
    final clusterPeers = ref.read(clusterPeersProvider);
    
    if (clusterPeers.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('No clusters available for service discovery'),
        ),
      );
      return;
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Discover Services'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Select a cluster to discover services from:'),
            const SizedBox(height: 16),
            ...clusterPeers.map((peer) => ListTile(
              leading: Icon(
                peer.isOnline ? Icons.cloud : Icons.cloud_off,
                color: peer.isOnline ? Colors.green : Colors.grey,
              ),
              title: Text(peer.displayName),
              subtitle: Text('Device ID: ${peer.deviceId}'),
              enabled: peer.isOnline,
              onTap: peer.isOnline ? () {
                Navigator.of(context).pop();
                ref.read(meshProvider.notifier).discoverServices(peer.deviceId);
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Discovering services from ${peer.displayName}...'),
                  ),
                );
              } : null,
            )),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
}