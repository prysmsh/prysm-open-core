import 'package:flutter/material.dart';

class StatusOverview extends StatelessWidget {
  final int totalClusters;
  final int healthyClusters;
  final int totalServices;
  final int activeAlerts;

  const StatusOverview({
    Key? key,
    required this.totalClusters,
    required this.healthyClusters,
    required this.totalServices,
    required this.activeAlerts,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return GridView.count(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      crossAxisCount: 4,
      childAspectRatio: 1.5,
      crossAxisSpacing: 16,
      mainAxisSpacing: 16,
      children: [
        _buildStatusCard(
          context,
          'Clusters',
          '$healthyClusters/$totalClusters',
          Icons.cloud,
          healthyClusters == totalClusters ? Colors.green : Colors.orange,
        ),
        _buildStatusCard(
          context,
          'Services',
          '$totalServices',
          Icons.dns,
          Colors.blue,
        ),
        _buildStatusCard(
          context,
          'Health',
          totalClusters > 0 
              ? '${((healthyClusters / totalClusters) * 100).toStringAsFixed(0)}%'
              : '0%',
          Icons.favorite,
          healthyClusters == totalClusters ? Colors.green : Colors.red,
        ),
        _buildStatusCard(
          context,
          'Alerts',
          '$activeAlerts',
          Icons.warning,
          activeAlerts == 0 ? Colors.green : Colors.red,
        ),
      ],
    );
  }

  Widget _buildStatusCard(
    BuildContext context,
    String title,
    String value,
    IconData icon,
    Color color,
  ) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              icon,
              size: 32,
              color: color,
            ),
            const SizedBox(height: 8),
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
      ),
    );
  }
}