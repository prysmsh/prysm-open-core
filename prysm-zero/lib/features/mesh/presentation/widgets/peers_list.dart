import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../../core/models/mesh_models.dart';

class PeersList extends StatelessWidget {
  final List<MeshPeer> peers;

  const PeersList({
    Key? key,
    required this.peers,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (peers.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.devices_outlined,
              size: 64,
              color: Colors.grey,
            ),
            SizedBox(height: 16),
            Text(
              'No peers discovered',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w500,
              ),
            ),
            SizedBox(height: 8),
            Text(
              'Connect to the mesh network to discover peers',
              style: TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }

    // Group peers by type
    final clusterPeers = peers.where((p) => p.isCluster).toList();
    final clientPeers = peers.where((p) => p.isClient).toList();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (clusterPeers.isNotEmpty) ...[
          _buildSectionHeader(
            context,
            'Cluster Agents',
            clusterPeers.length,
            Icons.cloud,
            Colors.blue,
          ),
          const SizedBox(height: 8),
          ...clusterPeers.map((peer) => _buildPeerCard(context, peer)),
          const SizedBox(height: 24),
        ],
        
        if (clientPeers.isNotEmpty) ...[
          _buildSectionHeader(
            context,
            'Client Devices',
            clientPeers.length,
            Icons.devices,
            Colors.green,
          ),
          const SizedBox(height: 8),
          ...clientPeers.map((peer) => _buildPeerCard(context, peer)),
        ],
      ],
    );
  }

  Widget _buildSectionHeader(
    BuildContext context,
    String title,
    int count,
    IconData icon,
    Color color,
  ) {
    return Row(
      children: [
        Icon(icon, color: color, size: 20),
        const SizedBox(width: 8),
        Text(
          '$title ($count)',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
      ],
    );
  }

  Widget _buildPeerCard(BuildContext context, MeshPeer peer) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: peer.isOnline ? Colors.green : Colors.grey,
          child: Icon(
            peer.isCluster ? Icons.cloud : Icons.devices,
            color: Colors.white,
            size: 20,
          ),
        ),
        title: Text(
          peer.displayName,
          style: const TextStyle(fontWeight: FontWeight.w500),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Device ID: ${peer.deviceId}'),
            const SizedBox(height: 4),
            Row(
              children: [
                _buildStatusChip(peer.status, peer.isOnline),
                const SizedBox(width: 8),
                if (peer.isExitNode)
                  const Chip(
                    label: Text('Exit Node'),
                    backgroundColor: Colors.orange,
                    labelStyle: TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                    ),
                  ),
              ],
            ),
            if (peer.lastPing != null) ...[
              const SizedBox(height: 4),
              Text(
                'Last seen: ${_formatTimestamp(peer.lastPing!)}',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (value) => _handlePeerAction(context, peer, value),
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'copy_id',
              child: ListTile(
                leading: Icon(Icons.copy),
                title: Text('Copy Device ID'),
                contentPadding: EdgeInsets.zero,
              ),
            ),
            if (peer.isCluster) ...[
              const PopupMenuItem(
                value: 'discover_services',
                child: ListTile(
                  leading: Icon(Icons.search),
                  title: Text('Discover Services'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem(
                value: 'request_metrics',
                child: ListTile(
                  leading: Icon(Icons.analytics),
                  title: Text('Request Metrics'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
            const PopupMenuItem(
              value: 'ping',
              child: ListTile(
                leading: Icon(Icons.network_ping),
                title: Text('Ping'),
                contentPadding: EdgeInsets.zero,
              ),
            ),
          ],
        ),
        isThreeLine: true,
      ),
    );
  }

  Widget _buildStatusChip(String status, bool isOnline) {
    return Chip(
      label: Text(
        status.toUpperCase(),
        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
      ),
      backgroundColor: isOnline ? Colors.green : Colors.grey,
      labelStyle: const TextStyle(color: Colors.white),
    );
  }

  String _formatTimestamp(DateTime timestamp) {
    final now = DateTime.now();
    final difference = now.difference(timestamp);

    if (difference.inSeconds < 60) {
      return '${difference.inSeconds}s ago';
    } else if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h ago';
    } else {
      return '${difference.inDays}d ago';
    }
  }

  void _handlePeerAction(BuildContext context, MeshPeer peer, String action) {
    switch (action) {
      case 'copy_id':
        Clipboard.setData(ClipboardData(text: peer.deviceId));
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Device ID copied to clipboard'),
            duration: Duration(seconds: 2),
          ),
        );
        break;
      case 'discover_services':
        // This would trigger service discovery
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Discovering services from ${peer.displayName}...'),
          ),
        );
        break;
      case 'request_metrics':
        // This would request metrics from the cluster
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Requesting metrics from ${peer.displayName}...'),
          ),
        );
        break;
      case 'ping':
        // This would send a ping to the peer
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Pinging ${peer.displayName}...'),
          ),
        );
        break;
    }
  }
}