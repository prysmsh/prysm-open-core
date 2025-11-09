import 'package:flutter/material.dart';

import '../../../../core/networking/derp_client.dart';

class ConnectionStatusCard extends StatelessWidget {
  final DERPConnectionState connectionState;
  final VoidCallback onConnect;
  final VoidCallback onDisconnect;

  const ConnectionStatusCard({
    Key? key,
    required this.connectionState,
    required this.onConnect,
    required this.onDisconnect,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  _getStatusIcon(),
                  size: 32,
                  color: _getStatusColor(),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'DERP Mesh Network',
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        _getStatusText(),
                        style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                          color: _getStatusColor(),
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ),
                _buildActionButton(),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              _getStatusDescription(),
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            if (connectionState == DERPConnectionState.connecting ||
                connectionState == DERPConnectionState.reconnecting) ...[
              const SizedBox(height: 16),
              const LinearProgressIndicator(),
            ],
          ],
        ),
      ),
    );
  }

  IconData _getStatusIcon() {
    switch (connectionState) {
      case DERPConnectionState.connected:
        return Icons.cloud_done;
      case DERPConnectionState.connecting:
      case DERPConnectionState.reconnecting:
        return Icons.cloud_sync;
      case DERPConnectionState.error:
        return Icons.cloud_off;
      case DERPConnectionState.disconnected:
        return Icons.cloud_outlined;
    }
  }

  Color _getStatusColor() {
    switch (connectionState) {
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

  String _getStatusText() {
    switch (connectionState) {
      case DERPConnectionState.connected:
        return 'Connected';
      case DERPConnectionState.connecting:
        return 'Connecting...';
      case DERPConnectionState.reconnecting:
        return 'Reconnecting...';
      case DERPConnectionState.error:
        return 'Connection Error';
      case DERPConnectionState.disconnected:
        return 'Disconnected';
    }
  }

  String _getStatusDescription() {
    switch (connectionState) {
      case DERPConnectionState.connected:
        return 'Successfully connected to DERP mesh network. You can now discover services and communicate with cluster agents.';
      case DERPConnectionState.connecting:
        return 'Establishing secure connection to DERP relay server...';
      case DERPConnectionState.reconnecting:
        return 'Connection lost. Attempting to reconnect to DERP mesh network...';
      case DERPConnectionState.error:
        return 'Failed to connect to DERP mesh network. Check your network connection and authentication.';
      case DERPConnectionState.disconnected:
        return 'Not connected to DERP mesh network. Connect to discover services and manage clusters.';
    }
  }

  Widget _buildActionButton() {
    switch (connectionState) {
      case DERPConnectionState.connected:
        return ElevatedButton.icon(
          onPressed: onDisconnect,
          icon: const Icon(Icons.power_off),
          label: const Text('Disconnect'),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.red,
            foregroundColor: Colors.white,
          ),
        );
      case DERPConnectionState.connecting:
      case DERPConnectionState.reconnecting:
        return const SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        );
      case DERPConnectionState.error:
      case DERPConnectionState.disconnected:
        return ElevatedButton.icon(
          onPressed: onConnect,
          icon: const Icon(Icons.power),
          label: const Text('Connect'),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.green,
            foregroundColor: Colors.white,
          ),
        );
    }
  }
}