import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api/api_client.dart';
import '../../core/config/app_config.dart';
import '../../core/models/auth_models.dart';
import '../../core/storage/storage_service.dart';

// Auth State
class AuthState {
  final bool isAuthenticated;
  final bool isLoading;
  final UserProfile? user;
  final Organization? organization;
  final String? error;

  const AuthState({
    this.isAuthenticated = false,
    this.isLoading = false,
    this.user,
    this.organization,
    this.error,
  });

  AuthState copyWith({
    bool? isAuthenticated,
    bool? isLoading,
    UserProfile? user,
    Organization? organization,
    String? error,
  }) {
    return AuthState(
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
      isLoading: isLoading ?? this.isLoading,
      user: user ?? this.user,
      organization: organization ?? this.organization,
      error: error,
    );
  }
}

// Auth Provider
class AuthNotifier extends StateNotifier<AuthState> {
  final ApiClient _apiClient = ApiClient();

  AuthNotifier() : super(const AuthState()) {
    _init();
  }

  Future<void> _init() async {
    state = state.copyWith(isLoading: true);
    
    try {
      // Check if user has valid token
      final token = await StorageService.instance.getSecure(AppConfig.jwtTokenKey);
      if (token != null) {
        // Try to get user profile to validate token
        final user = await _apiClient.getProfile();
        state = state.copyWith(
          isAuthenticated: true,
          isLoading: false,
          user: user,
        );
      } else {
        state = state.copyWith(isLoading: false);
      }
    } catch (e) {
      // Token invalid or expired
      await _clearStorage();
      state = state.copyWith(isLoading: false);
    }
  }

  Future<bool> login(String email, String password) async {
    state = state.copyWith(isLoading: true, error: null);
    
    try {
      final response = await _apiClient.login(email, password);
      
      // Store tokens
      await StorageService.instance.setSecure(AppConfig.jwtTokenKey, response.token);
      if (response.refreshToken != null) {
        await StorageService.instance.setSecure(AppConfig.refreshTokenKey, response.refreshToken!);
      }
      
      state = state.copyWith(
        isAuthenticated: true,
        isLoading: false,
        user: response.user,
        organization: response.organization,
      );
      
      return true;
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      return false;
    }
  }

  Future<bool> register(String email, String password, String organizationName) async {
    state = state.copyWith(isLoading: true, error: null);
    
    try {
      final response = await _apiClient.register(email, password, organizationName);
      
      // Store tokens
      await StorageService.instance.setSecure(AppConfig.jwtTokenKey, response.token);
      if (response.refreshToken != null) {
        await StorageService.instance.setSecure(AppConfig.refreshTokenKey, response.refreshToken!);
      }
      
      state = state.copyWith(
        isAuthenticated: true,
        isLoading: false,
        user: response.user,
        organization: response.organization,
      );
      
      return true;
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      return false;
    }
  }

  Future<void> logout() async {
    state = state.copyWith(isLoading: true);
    
    try {
      await _apiClient.logout();
    } catch (e) {
      // Logout from server failed, but still clear local data
    }
    
    await _clearStorage();
    state = const AuthState();
  }

  Future<void> refreshProfile() async {
    if (!state.isAuthenticated) return;
    
    try {
      final user = await _apiClient.getProfile();
      state = state.copyWith(user: user);
    } catch (e) {
      // Profile refresh failed, might need to re-authenticate
      await logout();
    }
  }

  Future<void> _clearStorage() async {
    await StorageService.instance.deleteSecure(AppConfig.jwtTokenKey);
    await StorageService.instance.deleteSecure(AppConfig.refreshTokenKey);
    await StorageService.instance.deleteSecure(AppConfig.userDataKey);
    await StorageService.instance.deleteSecure(AppConfig.organizationKey);
    await StorageService.instance.deleteSecure(AppConfig.derpAgentTokenKey);
    await StorageService.instance.deleteSecure(AppConfig.derpPublicKeyKey);
  }

  void clearError() {
    if (state.error != null) {
      state = state.copyWith(error: null);
    }
  }
}

// Providers
final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier();
});

// Helper providers
final isAuthenticatedProvider = Provider<bool>((ref) {
  return ref.watch(authProvider).isAuthenticated;
});

final currentUserProvider = Provider<UserProfile?>((ref) {
  return ref.watch(authProvider).user;
});

final currentOrganizationProvider = Provider<Organization?>((ref) {
  return ref.watch(authProvider).organization;
});
