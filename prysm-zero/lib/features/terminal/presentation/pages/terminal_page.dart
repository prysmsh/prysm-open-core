import 'package:flutter/material.dart';

class TerminalPage extends StatelessWidget {
  const TerminalPage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Terminal'),
      ),
      body: const Center(
        child: Text('Terminal page - Coming soon'),
      ),
    );
  }
}