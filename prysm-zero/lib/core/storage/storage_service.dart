import 'package:hive_flutter/hive_flutter.dart';

import '../config/app_config.dart';

class StorageService {
  static final StorageService _instance = StorageService._internal();
  factory StorageService() => _instance;
  StorageService._internal();
  
  static StorageService get instance => _instance;
  
  late Box _settingsBox;
  late Box _cacheBox;
  late Box _secureBox;

  Future<void> init() async {
    // Initialize Hive boxes
    _settingsBox = await Hive.openBox('settings');
    _cacheBox = await Hive.openBox('cache');
    _secureBox = await Hive.openBox('secure');
  }

  // Secure Storage (for sensitive data like tokens)
  Future<void> setSecure(String key, String value) async {
    await _secureBox.put(key, value);
  }

  Future<String?> getSecure(String key) async {
    return _secureBox.get(key);
  }

  Future<void> deleteSecure(String key) async {
    await _secureBox.delete(key);
  }

  Future<void> clearSecure() async {
    await _secureBox.clear();
  }

  // Settings Storage (for app preferences)
  Future<void> setSetting(String key, dynamic value) async {
    await _settingsBox.put(key, value);
  }

  T? getSetting<T>(String key, {T? defaultValue}) {
    return _settingsBox.get(key, defaultValue: defaultValue) as T?;
  }

  Future<void> deleteSetting(String key) async {
    await _settingsBox.delete(key);
  }

  // Cache Storage (for temporary data)
  Future<void> setCache(String key, dynamic value, {Duration? ttl}) async {
    final data = {
      'value': value,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'ttl': ttl?.inMilliseconds,
    };
    await _cacheBox.put(key, data);
  }

  T? getCache<T>(String key) {
    final data = _cacheBox.get(key);
    if (data == null) return null;

    final timestamp = data['timestamp'] as int;
    final ttl = data['ttl'] as int?;
    
    if (ttl != null) {
      final expiryTime = timestamp + ttl;
      if (DateTime.now().millisecondsSinceEpoch > expiryTime) {
        // Data expired, delete it
        deleteCache(key);
        return null;
      }
    }

    return data['value'] as T?;
  }

  Future<void> deleteCache(String key) async {
    await _cacheBox.delete(key);
  }

  Future<void> clearCache() async {
    await _cacheBox.clear();
  }

  // Bulk operations
  Future<void> clearAll() async {
    await clearSecure();
    await _settingsBox.clear();
    await _cacheBox.clear();
  }

  // App-specific storage helpers
  Future<void> saveAuthToken(String token) async {
    await setSecure(AppConfig.jwtTokenKey, token);
  }

  Future<String?> getAuthToken() async {
    return await getSecure(AppConfig.jwtTokenKey);
  }

  Future<void> saveRefreshToken(String token) async {
    await setSecure(AppConfig.refreshTokenKey, token);
  }

  Future<String?> getRefreshToken() async {
    return await getSecure(AppConfig.refreshTokenKey);
  }

  Future<void> saveDerpAgentToken(String token) async {
    await setSecure(AppConfig.derpAgentTokenKey, token);
  }

  Future<String?> getDerpAgentToken() async {
    return await getSecure(AppConfig.derpAgentTokenKey);
  }

  Future<void> saveDerpPublicKey(String publicKey) async {
    await setSecure(AppConfig.derpPublicKeyKey, publicKey);
  }

  Future<String?> getDerpPublicKey() async {
    return await getSecure(AppConfig.derpPublicKeyKey);
  }

  Future<void> saveUserData(Map<String, dynamic> userData) async {
    await setSetting(AppConfig.userDataKey, userData);
  }

  Map<String, dynamic>? getUserData() {
    return getSetting<Map<String, dynamic>>(AppConfig.userDataKey);
  }

  Future<void> saveAppSettings(Map<String, dynamic> settings) async {
    await setSetting(AppConfig.settingsKey, settings);
  }

  Map<String, dynamic> getAppSettings() {
    return getSetting<Map<String, dynamic>>(AppConfig.settingsKey) ?? {};
  }

  Future<void> setDerpServerUrl(String url) async {
    await setSetting('derp_server_url', url);
  }

  String getDerpServerUrl() {
    return getSetting<String>('derp_server_url') ?? AppConfig.derpServerUrl;
  }

  // Theme settings
  Future<void> setThemeMode(String mode) async {
    await setSetting('theme_mode', mode);
  }

  String getThemeMode() {
    return getSetting<String>('theme_mode') ?? 'system';
  }

  // Window settings (for desktop)
  Future<void> setWindowSize(double width, double height) async {
    await setSetting('window_width', width);
    await setSetting('window_height', height);
  }

  Map<String, double> getWindowSize() {
    return {
      'width': getSetting<double>('window_width') ?? 1200.0,
      'height': getSetting<double>('window_height') ?? 800.0,
    };
  }

  Future<void> setWindowPosition(double x, double y) async {
    await setSetting('window_x', x);
    await setSetting('window_y', y);
  }

  Map<String, double>? getWindowPosition() {
    final x = getSetting<double>('window_x');
    final y = getSetting<double>('window_y');
    if (x != null && y != null) {
      return {'x': x, 'y': y};
    }
    return null;
  }

  // Connection settings
  Future<void> setApiBaseUrl(String url) async {
    await setSetting('api_base_url', url);
  }

  String getApiBaseUrl() {
    return getSetting<String>('api_base_url') ?? AppConfig.baseUrl;
  }

  Future<void> setAutoConnect(bool autoConnect) async {
    await setSetting('auto_connect', autoConnect);
  }

  bool getAutoConnect() {
    return getSetting<bool>('auto_connect') ?? true;
  }

  // Recent clusters/connections
  Future<void> addRecentCluster(Map<String, dynamic> cluster) async {
    final recent = getRecentClusters();
    
    // Remove if already exists
    recent.removeWhere((c) => c['id'] == cluster['id']);
    
    // Add to beginning
    recent.insert(0, cluster);
    
    // Keep only last 10
    if (recent.length > 10) {
      recent.removeRange(10, recent.length);
    }
    
    await setSetting('recent_clusters', recent);
  }

  List<Map<String, dynamic>> getRecentClusters() {
    final recent = getSetting<List>('recent_clusters') ?? [];
    return recent.cast<Map<String, dynamic>>();
  }
}
