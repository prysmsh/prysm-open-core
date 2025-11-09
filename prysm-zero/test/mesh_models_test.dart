import 'package:flutter_test/flutter_test.dart';
import 'package:prysm_flutter/core/models/mesh_models.dart';

void main() {
  group('ServiceDiscovery.fromClusterServicesPayload', () {
    test('parses structured service map entries', () {
      final payload = {
        'prod/api': {
          'namespace': 'prod',
          'service_type': 'ClusterIP',
          'endpoints': [
            {
              'ip': '10.10.0.5',
              'port': 8080,
              'protocol': 'tcp',
              'ready': true,
            },
          ],
          'labels': {'app': 'api'},
          'discovered_at': '2025-01-01T00:00:00Z',
          'last_seen': '2025-01-01T00:05:00Z',
        },
      };

      final services =
          ServiceDiscovery.fromClusterServicesPayload(payload, 'cluster-01');

      expect(services, hasLength(1));
      final service = services.first;
      expect(service.serviceName, 'api');
      expect(service.namespace, 'prod');
      expect(service.clusterId, 'cluster-01');
      expect(service.endpoints, hasLength(1));
      expect(service.endpoints.first.address, '10.10.0.5:8080');
      expect(service.labels['app'], 'api');
    });

    test('infers defaults when service payload is not detailed', () {
      final payload = {
        'default/web': {
          'cluster_ip': '10.96.0.10',
          'ports': [
            {'port': 443, 'protocol': 'TCP'},
          ],
        },
      };

      final services =
          ServiceDiscovery.fromClusterServicesPayload(payload, 'cluster-99');

      expect(services, hasLength(1));
      final service = services.single;
      expect(service.serviceType, 'ClusterIP');
      expect(service.endpoints.single.address, '10.96.0.10:443');
      expect(service.namespace, 'default');
    });

    test('handles non-map service entries gracefully', () {
      final payload = {
        'orphan-service': 'unstructured',
      };

      final services =
          ServiceDiscovery.fromClusterServicesPayload(payload, 'cluster-7');

      expect(services, hasLength(1));
      expect(services.first.serviceName, 'orphan-service');
      expect(services.first.namespace, 'default');
    });
  });

  group('ServiceEndpoint.fromJson', () {
    test('parses string endpoint notation', () {
      final endpoint = ServiceEndpoint.fromJson('10.0.0.1:8443/TCP');
      expect(endpoint.ip, '10.0.0.1');
      expect(endpoint.port, 8443);
      expect(endpoint.protocol, 'TCP');
      expect(endpoint.ready, isTrue);
    });

    test('parses map-based endpoint notation', () {
      final endpoint = ServiceEndpoint.fromJson({
        'ip': 'fd00::1',
        'port': 7000,
        'protocol': 'udp',
        'ready': false,
      });

      expect(endpoint.ip, 'fd00::1');
      expect(endpoint.port, 7000);
      expect(endpoint.protocol, 'UDP');
      expect(endpoint.ready, isFalse);
    });
  });
}
