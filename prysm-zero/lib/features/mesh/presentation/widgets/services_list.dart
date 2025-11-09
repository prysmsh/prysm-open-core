import 'package:flutter/material.dart';

import '../../../../core/models/mesh_models.dart';

class ServicesList extends StatelessWidget {
  final List<ServiceDiscovery> services;

  const ServicesList({
    Key? key,
    required this.services,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (services.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.dns_outlined,
              size: 64,
              color: Colors.grey,
            ),
            SizedBox(height: 16),
            Text(
              'No services discovered',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w500,
              ),
            ),
            SizedBox(height: 8),
            Text(
              'Use service discovery to find cluster services',
              style: TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }

    // Group services by cluster
    final servicesByCluster = <String, List<ServiceDiscovery>>{};
    for (final service in services) {
      servicesByCluster.putIfAbsent(service.clusterId, () => []).add(service);
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: servicesByCluster.entries.map((entry) {
        final clusterId = entry.key;
        final clusterServices = entry.value;
        
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildClusterHeader(context, clusterId, clusterServices.length),
            const SizedBox(height: 8),
            ...clusterServices.map((service) => _buildServiceCard(context, service)),
            const SizedBox(height: 24),
          ],
        );
      }).toList(),
    );
  }

  Widget _buildClusterHeader(BuildContext context, String clusterId, int count) {
    return Row(
      children: [
        Icon(Icons.cloud, color: Colors.blue, size: 20),
        const SizedBox(width: 8),
        Text(
          'Cluster $clusterId ($count services)',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.bold,
            color: Colors.blue,
          ),
        ),
      ],
    );
  }

  Widget _buildServiceCard(BuildContext context, ServiceDiscovery service) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: service.isActive ? Colors.green : Colors.grey,
          child: Icon(
            Icons.dns,
            color: Colors.white,
            size: 20,
          ),
        ),
        title: Text(
          service.serviceName,
          style: const TextStyle(fontWeight: FontWeight.w500),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Namespace: ${service.namespace}'),
            Text('Type: ${service.serviceType}'),
            const SizedBox(height: 4),
            Wrap(
              spacing: 4,
              children: service.endpoints.map((endpoint) => 
                Chip(
                  label: Text(
                    endpoint.address,
                    style: const TextStyle(fontSize: 12),
                  ),
                  backgroundColor: endpoint.ready ? Colors.green.withOpacity(0.2) : Colors.grey.withOpacity(0.2),
                )
              ).toList(),
            ),
            const SizedBox(height: 4),
            Text(
              'FQDN: ${service.fqdn}',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            Text(
              'Last seen: ${_formatTimestamp(service.lastSeen)}',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (value) => _handleServiceAction(context, service, value),
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'copy_fqdn',
              child: ListTile(
                leading: Icon(Icons.copy),
                title: Text('Copy FQDN'),
                contentPadding: EdgeInsets.zero,
              ),
            ),
            const PopupMenuItem(
              value: 'test_connection',
              child: ListTile(
                leading: Icon(Icons.network_ping),
                title: Text('Test Connection'),
                contentPadding: EdgeInsets.zero,
              ),
            ),
            const PopupMenuItem(
              value: 'view_details',
              child: ListTile(
                leading: Icon(Icons.info),
                title: Text('View Details'),
                contentPadding: EdgeInsets.zero,
              ),
            ),
          ],
        ),
        isThreeLine: true,
      ),
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

  void _handleServiceAction(BuildContext context, ServiceDiscovery service, String action) {
    switch (action) {
      case 'copy_fqdn':
        // Copy FQDN to clipboard
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('FQDN copied to clipboard'),
            duration: Duration(seconds: 2),
          ),
        );
        break;
      case 'test_connection':
        // Test connection to service
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Testing connection to ${service.serviceName}...'),
          ),
        );
        break;
      case 'view_details':
        _showServiceDetails(context, service);
        break;
    }
  }

  void _showServiceDetails(BuildContext context, ServiceDiscovery service) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(service.serviceName),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildDetailRow('Cluster', service.clusterId),
              _buildDetailRow('Namespace', service.namespace),
              _buildDetailRow('Type', service.serviceType),
              _buildDetailRow('FQDN', service.fqdn),
              _buildDetailRow('Discovered', service.discoveredAt.toString()),
              _buildDetailRow('Last Seen', service.lastSeen.toString()),
              const SizedBox(height: 16),
              const Text(
                'Endpoints:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              ...service.endpoints.map((endpoint) => Card(
                child: ListTile(
                  leading: Icon(
                    endpoint.ready ? Icons.check_circle : Icons.error,
                    color: endpoint.ready ? Colors.green : Colors.red,
                  ),
                  title: Text(endpoint.address),
                  subtitle: Text('Protocol: ${endpoint.protocol}'),
                  trailing: Text(endpoint.ready ? 'Ready' : 'Not Ready'),
                ),
              )),
              if (service.labels.isNotEmpty) ...[
                const SizedBox(height: 16),
                const Text(
                  'Labels:',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                ...service.labels.entries.map((entry) => 
                  Chip(label: Text('${entry.key}: ${entry.value}'))
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
            child: Text(value),
          ),
        ],
      ),
    );
  }
}