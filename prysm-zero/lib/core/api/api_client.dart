import 'package:dio/dio.dart';

import '../config/app_config.dart';
import '../models/auth_models.dart';
import '../models/cluster_models.dart';
import '../models/mesh_models.dart';
import '../models/service_models.dart';
import '../storage/storage_service.dart';

class ApiClient {
  static final ApiClient _instance = ApiClient._internal();
  factory ApiClient() => _instance;
  ApiClient._internal();

  late Dio _dio;

  void init() {
    final baseUrl = StorageService.instance.getApiBaseUrl();
    final normalizedBaseUrl = baseUrl.endsWith('/')
        ? baseUrl.substring(0, baseUrl.length - 1)
        : baseUrl;
    final apiBaseUrl = '$normalizedBaseUrl${AppConfig.apiPath}';

    _dio = Dio(BaseOptions(
      baseUrl: apiBaseUrl,
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    // Request interceptor for adding auth token
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          final token = await StorageService.instance.getSecure(AppConfig.jwtTokenKey);
          if (token != null) {
            options.headers['Authorization'] = 'Bearer $token';
          }
          handler.next(options);
        },
        onError: (error, handler) async {
          if (error.response?.statusCode == 401) {
            // Token expired, try to refresh
            await _handleTokenExpiry();
          }
          handler.next(error);
        },
      ),
    );

    if (AppConfig.isDebug) {
      _dio.interceptors.add(LogInterceptor(
        requestBody: true,
        responseBody: true,
        logPrint: (obj) => print('[API] $obj'),
      ));
    }
  }

  // Authentication
  Future<AuthResponse> login(String email, String password) async {
    final response = await _dio.post('/auth/login', data: {
      'email': email,
      'password': password,
    });
    return AuthResponse.fromJson(response.data);
  }

  Future<AuthResponse> register(String email, String password, String organizationName) async {
    final response = await _dio.post('/auth/register', data: {
      'email': email,
      'password': password,
      'organization_name': organizationName,
    });
    return AuthResponse.fromJson(response.data);
  }

  Future<void> logout() async {
    await _dio.post('/auth/logout');
    await StorageService.instance.deleteSecure(AppConfig.jwtTokenKey);
    await StorageService.instance.deleteSecure(AppConfig.refreshTokenKey);
  }

  Future<UserProfile> getProfile() async {
    final response = await _dio.get('/auth/profile');
    return UserProfile.fromJson(response.data);
  }

  // Clusters
  Future<List<ClusterInfo>> getClusters() async {
    final response = await _dio.get('/clusters');
    return (response.data as List)
        .map((cluster) => ClusterInfo.fromJson(cluster))
        .toList();
  }

  Future<ClusterInfo> getCluster(String clusterId) async {
    final response = await _dio.get('/clusters/$clusterId');
    return ClusterInfo.fromJson(response.data);
  }

  Future<ClusterHealth> getClusterHealth(String clusterId) async {
    final response = await _dio.get('/clusters/$clusterId/health');
    return ClusterHealth.fromJson(response.data);
  }

  // Services
  Future<List<ServiceInfo>> getServices(String clusterId) async {
    final response = await _dio.get('/clusters/$clusterId/services');
    return (response.data as List)
        .map((service) => ServiceInfo.fromJson(service))
        .toList();
  }

  Future<ServiceInfo> getService(String clusterId, String serviceId) async {
    final response = await _dio.get('/clusters/$clusterId/services/$serviceId');
    return ServiceInfo.fromJson(response.data);
  }

  Future<List<MeshPeer>> getMeshNodes() async {
    final response = await _dio.get('/mesh/nodes');
    final body = response.data;
    dynamic nodesRaw;
    if (body is Map<String, dynamic>) {
      nodesRaw = body['nodes'] ?? body['data'];
    } else {
      nodesRaw = body;
    }

    final nodesList = nodesRaw is List ? nodesRaw : <dynamic>[];
    return nodesList
        .whereType<Map>()
        .map((node) => MeshPeer.fromJson(Map<String, dynamic>.from(node)))
        .toList();
  }

  Future<List<ServiceDiscovery>> getClusterServices(String clusterId) async {
    final response = await _dio.get('/clusters/$clusterId/services');
    Map<String, dynamic>? services;

    final body = response.data;
    if (body is Map) {
      final raw = body['services'];
      if (raw is Map) {
        services = raw.map((key, value) => MapEntry(key.toString(), value));
      }
    }

    return ServiceDiscovery.fromClusterServicesPayload(services, clusterId);
  }

  // Terminal
  Future<Map<String, dynamic>> executeCommand(
    String clusterId,
    String command,
  ) async {
    final response = await _dio.post('/clusters/$clusterId/terminal', data: {
      'command': command,
    });
    return response.data;
  }

  Future<Map<String, dynamic>> getClusterMeshStatus(String clusterId) async {
    final response = await _dio.get('/clusters/$clusterId/mesh-status');
    final data = response.data;
    if (data is Map<String, dynamic>) {
      return Map<String, dynamic>.from(data);
    }
    return {'cluster_id': clusterId, 'status': data};
  }

  // Agent Tokens
  Future<String> createAgentToken(String name, List<String> permissions) async {
    final permissionSet = <String>{
      ...permissions.map((p) => p.trim()).where((p) => p.isNotEmpty),
      'ping',
      'register',
      'derp_access',
    };

    final response = await _dio.post('/tokens', data: {
      'name': name,
      'permissions': permissionSet.toList(),
    });

    final tokenData = response.data['token'];
    if (tokenData is Map && tokenData['token'] != null) {
      return tokenData['token'];
    }
    if (tokenData is String && tokenData.isNotEmpty) {
      return tokenData;
    }
    if (response.data is Map && response.data['token'] is String && response.data['token'].isNotEmpty) {
      return response.data['token'];
    }
    throw Exception('Agent token response missing token value');
  }

  Future<List<AgentToken>> getAgentTokens() async {
    final response = await _dio.get('/tokens');
    final body = response.data;

    dynamic tokensRaw;
    if (body is Map<String, dynamic>) {
      tokensRaw = body['tokens'] ?? body['data'];
    } else {
      tokensRaw = body;
    }

    final tokensList = tokensRaw is List ? tokensRaw : <dynamic>[];

    return tokensList
        .whereType<Map>()
        .map((token) => AgentToken.fromJson(token.map((key, value) => MapEntry(key.toString(), value))))
        .toList();
  }

  Future<void> revokeAgentToken(String tokenId) async {
    await _dio.delete('/tokens/$tokenId');
  }

  // Analytics
  Future<Map<String, dynamic>> getAnalytics(String clusterId) async {
    final analyticsClient = Dio(BaseOptions(
      baseUrl: AppConfig.analyticsBaseUrl,
    ));
    
    final token = await StorageService.instance.getSecure(AppConfig.jwtTokenKey);
    final response = await analyticsClient.get(
      '/analytics/$clusterId',
      options: Options(
        headers: {'Authorization': 'Bearer $token'},
      ),
    );
    return response.data;
  }

  // Private methods
  Future<void> _handleTokenExpiry() async {
    try {
      final refreshToken = await StorageService.instance.getSecure(AppConfig.refreshTokenKey);
      if (refreshToken == null) return;

      final response = await _dio.post('/auth/refresh', data: {
        'refresh_token': refreshToken,
      });

      final newToken = response.data['token'];
      await StorageService.instance.setSecure(AppConfig.jwtTokenKey, newToken);
    } catch (e) {
      // Refresh failed, user needs to login again
      await StorageService.instance.deleteSecure(AppConfig.jwtTokenKey);
      await StorageService.instance.deleteSecure(AppConfig.refreshTokenKey);
    }
  }
}
