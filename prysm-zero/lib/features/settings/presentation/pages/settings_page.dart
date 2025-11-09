import 'package:flutter/material.dart';

import '../../../../core/api/api_client.dart';
import '../../../../core/config/app_config.dart';
import '../../../../core/storage/storage_service.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({Key? key}) : super(key: key);

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final TextEditingController _apiController;
  late final TextEditingController _derpController;
  bool _isSaving = false;
  String? _statusMessage;

  @override
  void initState() {
    super.initState();
    final storage = StorageService.instance;
    _apiController = TextEditingController(text: storage.getApiBaseUrl());
    _derpController = TextEditingController(text: storage.getDerpServerUrl());
  }

  @override
  void dispose() {
    _apiController.dispose();
    _derpController.dispose();
    super.dispose();
  }

  Future<void> _saveSettings() async {
    setState(() {
      _isSaving = true;
      _statusMessage = null;
    });

    try {
      final apiUrl = _apiController.text.trim();
      final derpUrl = _derpController.text.trim();

      if (apiUrl.isNotEmpty) {
        await StorageService.instance.setApiBaseUrl(apiUrl);
      }
      if (derpUrl.isNotEmpty) {
        await StorageService.instance.setDerpServerUrl(derpUrl);
      }

      ApiClient().init();

      setState(() {
        _statusMessage = 'Configuration saved. Reconnect mesh sessions to apply changes.';
      });
    } catch (e) {
      setState(() {
        _statusMessage = 'Failed to save settings: $e';
      });
    } finally {
      setState(() {
        _isSaving = false;
      });
    }
  }

  Future<void> _resetDerpIdentity() async {
    setState(() {
      _isSaving = true;
      _statusMessage = null;
    });

    try {
      await StorageService.instance.deleteSecure(AppConfig.derpAgentTokenKey);
      await StorageService.instance.deleteSecure(AppConfig.derpPublicKeyKey);
      setState(() {
        _statusMessage = 'DERP identity reset. A new token will be issued on next connect.';
      });
    } catch (e) {
      setState(() {
        _statusMessage = 'Failed to reset DERP identity: $e';
      });
    } finally {
      setState(() {
        _isSaving = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Connectivity',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _apiController,
                decoration: const InputDecoration(
                  labelText: 'API Base URL',
                  hintText: 'https://api.prysm.sh',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _derpController,
                decoration: const InputDecoration(
                  labelText: 'DERP Relay URL',
                  hintText: 'wss://derp.prysm.sh/derp',
                ),
              ),
              const SizedBox(height: 24),
              Row(
                children: [
                  ElevatedButton.icon(
                    onPressed: _isSaving ? null : _saveSettings,
                    icon: _isSaving
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.save),
                    label: const Text('Save'),
                  ),
                  const SizedBox(width: 16),
                  OutlinedButton.icon(
                    onPressed: _isSaving ? null : _resetDerpIdentity,
                    icon: const Icon(Icons.refresh),
                    label: const Text('Reset DERP Identity'),
                  ),
                ],
              ),
              if (_statusMessage != null) ...[
                const SizedBox(height: 16),
                Text(
                  _statusMessage!,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
