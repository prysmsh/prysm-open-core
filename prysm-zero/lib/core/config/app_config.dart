class AppConfig {
  static const String appName = 'prysm.sh';
  static const String appVersion = '1.0.0';
  
  // API Configuration
  static const String baseUrl = 'http://localhost:8080';
  static const String apiPath = '/api/v1';
  static const String wsPath = '/ws';
  
  // Analytics API (separate service)
  static const String analyticsBaseUrl = 'http://localhost:8081';
  
  // DERP Configuration
  static const String derpServerUrl = 'wss://derp.prysm.sh/derp';
  
  // Storage Keys
  static const String jwtTokenKey = 'jwt_token';
  static const String refreshTokenKey = 'refresh_token';
  static const String userDataKey = 'user_data';
  static const String organizationKey = 'organization';
  static const String settingsKey = 'app_settings';
  static const String derpAgentTokenKey = 'derp_agent_token';
  static const String derpPublicKeyKey = 'derp_public_key';
  
  // Authentication
  static const Duration tokenRefreshThreshold = Duration(minutes: 5);
  static const Duration tokenExpiry = Duration(hours: 8);
  
  // WebSocket
  static const Duration wsReconnectDelay = Duration(seconds: 5);
  static const int maxReconnectAttempts = 10;
  
  // Terminal
  static const List<String> allowedKubectlCommands = [
    'get',
    'describe',
    'logs',
    'version',
    'explain',
    'top',
  ];
  
  // Environment Detection
  static bool get isDebug {
    bool inDebugMode = false;
    assert(inDebugMode = true);
    return inDebugMode;
  }
  
  static String get apiBaseUrl => '$baseUrl$apiPath';
  static String get wsUrl => baseUrl.replaceFirst('http', 'ws') + wsPath;
}
