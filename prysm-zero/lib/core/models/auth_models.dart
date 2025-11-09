class AuthResponse {
  final String token;
  final String? refreshToken;
  final UserProfile user;
  final Organization organization;

  AuthResponse({
    required this.token,
    this.refreshToken,
    required this.user,
    required this.organization,
  });

  factory AuthResponse.fromJson(Map<String, dynamic> json) {
    return AuthResponse(
      token: json['token'],
      refreshToken: json['refresh_token'],
      user: UserProfile.fromJson(json['user']),
      organization: Organization.fromJson(json['organization']),
    );
  }
}

class UserProfile {
  final String id;
  final String email;
  final String? firstName;
  final String? lastName;
  final String role;
  final bool isActive;
  final DateTime createdAt;
  final DateTime? lastLoginAt;

  UserProfile({
    required this.id,
    required this.email,
    this.firstName,
    this.lastName,
    required this.role,
    required this.isActive,
    required this.createdAt,
    this.lastLoginAt,
  });

  factory UserProfile.fromJson(Map<String, dynamic> json) {
    return UserProfile(
      id: json['id'],
      email: json['email'],
      firstName: json['first_name'],
      lastName: json['last_name'],
      role: json['role'],
      isActive: json['is_active'] ?? true,
      createdAt: DateTime.parse(json['created_at']),
      lastLoginAt: json['last_login_at'] != null 
          ? DateTime.parse(json['last_login_at'])
          : null,
    );
  }

  String get displayName {
    if (firstName != null && lastName != null) {
      return '$firstName $lastName';
    }
    return email;
  }

  bool get isAdmin => role == 'admin';
  bool get isManager => role == 'manager' || isAdmin;
}

class Organization {
  final String id;
  final String name;
  final String? description;
  final DateTime createdAt;
  final Map<String, dynamic>? settings;

  Organization({
    required this.id,
    required this.name,
    this.description,
    required this.createdAt,
    this.settings,
  });

  factory Organization.fromJson(Map<String, dynamic> json) {
    return Organization(
      id: json['id'],
      name: json['name'],
      description: json['description'],
      createdAt: DateTime.parse(json['created_at']),
      settings: json['settings'],
    );
  }
}

class AgentToken {
  final String id;
  final String name;
  final String tokenHash;
  final List<String> permissions;
  final DateTime createdAt;
  final DateTime? expiresAt;
  final String? ipAllowlist;
  final bool isActive;

  AgentToken({
    required this.id,
    required this.name,
    required this.tokenHash,
    required this.permissions,
    required this.createdAt,
    this.expiresAt,
    this.ipAllowlist,
    required this.isActive,
  });

  factory AgentToken.fromJson(Map<String, dynamic> json) {
    List<String> parsePermissions(dynamic value) {
      if (value is List<String>) {
        return value;
      }
      if (value is List) {
        return value.map((item) => item.toString()).toList();
      }
      return const [];
    }

    final createdAtRaw = json['created_at']?.toString();
    final expiresAtRaw = json['expires_at']?.toString();

    return AgentToken(
      id: json['id'],
      name: json['name'],
      tokenHash: json['token_hash']?.toString() ?? json['token_prefix']?.toString() ?? '',
      permissions: parsePermissions(json['permissions']),
      createdAt: createdAtRaw != null ? DateTime.tryParse(createdAtRaw) ?? DateTime.now() : DateTime.now(),
      expiresAt: expiresAtRaw != null ? DateTime.tryParse(expiresAtRaw) : null,
      ipAllowlist: json['ip_allowlist'],
      isActive: json['is_active'] ?? json['active'] ?? true,
    );
  }

  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(expiresAt!);
  }
}

class LoginRequest {
  final String email;
  final String password;
  final String? totpCode;

  LoginRequest({
    required this.email,
    required this.password,
    this.totpCode,
  });

  Map<String, dynamic> toJson() {
    return {
      'email': email,
      'password': password,
      if (totpCode != null) 'totp_code': totpCode,
    };
  }
}

class RegisterRequest {
  final String email;
  final String password;
  final String organizationName;
  final String? firstName;
  final String? lastName;

  RegisterRequest({
    required this.email,
    required this.password,
    required this.organizationName,
    this.firstName,
    this.lastName,
  });

  Map<String, dynamic> toJson() {
    return {
      'email': email,
      'password': password,
      'organization_name': organizationName,
      if (firstName != null) 'first_name': firstName,
      if (lastName != null) 'last_name': lastName,
    };
  }
}
