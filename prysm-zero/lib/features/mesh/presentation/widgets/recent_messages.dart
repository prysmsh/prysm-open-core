import 'package:flutter/material.dart';

import '../../../../core/models/mesh_models.dart';

class RecentMessages extends StatelessWidget {
  final List<MeshMessage> messages;

  const RecentMessages({
    Key? key,
    required this.messages,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (messages.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.message_outlined,
              size: 64,
              color: Colors.grey,
            ),
            SizedBox(height: 16),
            Text(
              'No messages yet',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w500,
              ),
            ),
            SizedBox(height: 8),
            Text(
              'Mesh messages will appear here',
              style: TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }

    // Sort messages by timestamp, newest first
    final sortedMessages = List<MeshMessage>.from(messages)
      ..sort((a, b) => b.timestamp.compareTo(a.timestamp));

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: sortedMessages.length,
      itemBuilder: (context, index) {
        final message = sortedMessages[index];
        return _buildMessageCard(context, message);
      },
    );
  }

  Widget _buildMessageCard(BuildContext context, MeshMessage message) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ExpansionTile(
        leading: CircleAvatar(
          backgroundColor: _getMessageTypeColor(message.messageType),
          child: Icon(
            _getMessageTypeIcon(message.messageType),
            color: Colors.white,
            size: 20,
          ),
        ),
        title: Text(
          message.messageType.replaceAll('_', ' ').toUpperCase(),
          style: const TextStyle(fontWeight: FontWeight.w500),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('From: ${message.fromPeer}'),
            Text('To: ${message.toPeer}'),
            Text('Time: ${_formatTimestamp(message.timestamp)}'),
          ],
        ),
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text(
                      'Message ID: ',
                      style: TextStyle(fontWeight: FontWeight.w500),
                    ),
                    Expanded(
                      child: Text(
                        message.id,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                if (message.payload.isNotEmpty) ...[
                  const Text(
                    'Payload:',
                    style: TextStyle(fontWeight: FontWeight.w500),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surface,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: Theme.of(context).colorScheme.outline,
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: message.payload.entries.map((entry) =>
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 2),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              SizedBox(
                                width: 100,
                                child: Text(
                                  '${entry.key}:',
                                  style: const TextStyle(fontWeight: FontWeight.w500),
                                ),
                              ),
                              Expanded(
                                child: Text(
                                  entry.value.toString(),
                                  style: const TextStyle(fontFamily: 'monospace'),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ).toList(),
                    ),
                  ),
                ],
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    TextButton.icon(
                      onPressed: () => _copyMessageToClipboard(context, message),
                      icon: const Icon(Icons.copy),
                      label: const Text('Copy'),
                    ),
                    const SizedBox(width: 8),
                    TextButton.icon(
                      onPressed: () => _showMessageDetails(context, message),
                      icon: const Icon(Icons.info),
                      label: const Text('Details'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Color _getMessageTypeColor(String messageType) {
    switch (messageType) {
      case 'service_discovery_request':
      case 'service_discovery':
        return Colors.blue;
      case 'remote_command':
        return Colors.green;
      case 'metrics_request':
      case 'metrics_response':
        return Colors.orange;
      case 'ping':
      case 'pong':
        return Colors.purple;
      case 'error':
        return Colors.red;
      default:
        return Colors.grey;
    }
  }

  IconData _getMessageTypeIcon(String messageType) {
    switch (messageType) {
      case 'service_discovery_request':
      case 'service_discovery':
        return Icons.search;
      case 'remote_command':
        return Icons.terminal;
      case 'metrics_request':
      case 'metrics_response':
        return Icons.analytics;
      case 'ping':
      case 'pong':
        return Icons.network_ping;
      case 'error':
        return Icons.error;
      default:
        return Icons.message;
    }
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
      return '${timestamp.day}/${timestamp.month} ${timestamp.hour}:${timestamp.minute.toString().padLeft(2, '0')}';
    }
  }

  void _copyMessageToClipboard(BuildContext context, MeshMessage message) {
    // Copy message details to clipboard
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Message copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _showMessageDetails(BuildContext context, MeshMessage message) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Message Details'),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildDetailRow('ID', message.id),
              _buildDetailRow('Type', message.messageType),
              _buildDetailRow('From Peer', message.fromPeer),
              _buildDetailRow('To Peer', message.toPeer),
              _buildDetailRow('Timestamp', message.timestamp.toString()),
              if (message.payload.isNotEmpty) ...[
                const SizedBox(height: 16),
                const Text(
                  'Payload:',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    message.payload.toString(),
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                ),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(
              '$label:',
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );
  }
}