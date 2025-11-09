import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:hive_flutter/hive_flutter.dart';

import 'core/config/app_config.dart';
import 'core/storage/storage_service.dart';
import 'core/theme/app_theme.dart';
import 'core/api/api_client.dart';
import 'features/auth/presentation/pages/login_page.dart';
import 'features/dashboard/presentation/pages/dashboard_page.dart';
import 'features/clusters/presentation/pages/clusters_page.dart';
import 'features/terminal/presentation/pages/terminal_page.dart';
import 'features/mesh/presentation/pages/mesh_page.dart';
import 'features/settings/presentation/pages/settings_page.dart';
import 'shared/providers/auth_provider.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Initialize Hive for local storage
  await Hive.initFlutter();
  await StorageService.instance.init();

  final envApiUrl = (Platform.environment['PRYSM_API_URL'] ??
          Platform.environment['PRYSM_API_BASE_URL'])
      ?.trim();
  if (envApiUrl != null && envApiUrl.isNotEmpty) {
    await StorageService.instance.setApiBaseUrl(envApiUrl);
  }

  final envDerpUrl = Platform.environment['PRYSM_DERP_URL']?.trim();
  if (envDerpUrl != null && envDerpUrl.isNotEmpty) {
    await StorageService.instance.setDerpServerUrl(envDerpUrl);
  }
  
  // Initialize API client
  ApiClient().init();
  
  runApp(
    ProviderScope(
      child: PrysmApp(),
    ),
  );
}

class PrysmApp extends ConsumerWidget {
  PrysmApp({Key? key}) : super(key: key);

  final GoRouter _router = GoRouter(
    initialLocation: '/login',
    routes: [
      GoRoute(
        path: '/login',
        builder: (context, state) => const LoginPage(),
      ),
      GoRoute(
        path: '/dashboard',
        builder: (context, state) => const DashboardPage(),
      ),
      GoRoute(
        path: '/clusters',
        builder: (context, state) => const ClustersPage(),
      ),
      GoRoute(
        path: '/terminal',
        builder: (context, state) => const TerminalPage(),
      ),
      GoRoute(
        path: '/mesh',
        builder: (context, state) => const MeshPage(),
      ),
      GoRoute(
        path: '/settings',
        builder: (context, state) => const SettingsPage(),
      ),
    ],
    redirect: (context, state) {
      // Add authentication redirect logic here
      return null;
    },
  );

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      title: 'Prysm',
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: ThemeMode.system,
      routerConfig: _router,
      debugShowCheckedModeBanner: false,
    );
  }
}
