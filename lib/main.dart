// lib/main.dart
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() {
  runApp(const NmapScannerApp());
}

class NmapScannerApp extends StatelessWidget {
  const NmapScannerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Advanced Vulnerability Scanner',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.dark,
      ),
      themeMode: ThemeMode.system,
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({Key? key}) : super(key: key);

  @override
  _HomePageState createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with SingleTickerProviderStateMixin {
  final TextEditingController _ipController = TextEditingController();
  final TextEditingController _optionsController = TextEditingController(text: "-sV");
  String _scanResults = '';
  bool _isLoading = false;
  late TabController _tabController;
  String _vulnerabilityResults = '';
  bool _isVulnScanRunning = false;
  int _selectedScanLevel = 1;
  bool _enableScriptScan = false;
  bool _enableOsScan = false;
  bool _enableVersionDetection = true;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    _ipController.dispose();
    _optionsController.dispose();
    super.dispose();
  }
  
  Future<void> _runScan() async {
    setState(() {
      _isLoading = true;
      _scanResults = 'Scanning...';
    });
    
    try {
      final response = await http.post(
        Uri.parse('http://127.0.0.1:8000/scan'), // For Android emulator, use 10.0.2.2 to reach localhost
        headers: {"Content-Type": "application/json"},
        body: json.encode({
          "target": _ipController.text,
          "options": _optionsController.text,
        }),
      );
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          _scanResults = data['results'];
        });
      } else {
        setState(() {
          _scanResults = 'Error: ${response.statusCode}\n${response.body}';
        });
      }
    } catch (e) {
      setState(() {
        _scanResults = 'Error: $e';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _runVulnerabilityScan() async {
    if (_ipController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a target IP or hostname')),
      );
      return;
    }
    
    setState(() {
      _isVulnScanRunning = true;
      _vulnerabilityResults = 'Running vulnerability scan. This may take several minutes...';
    });
    
    try {
      // Build scan options based on UI settings
      Map<String, dynamic> requestData = {
        "target": _ipController.text,
        "scan_level": _selectedScanLevel,
        "enable_script_scan": _enableScriptScan,
        "enable_os_scan": _enableOsScan,
        "enable_version_detection": _enableVersionDetection,
      };
      
      final response = await http.post(
        Uri.parse('http://10.0.2.2:8000/vulnerability_scan'),
        headers: {"Content-Type": "application/json"},
        body: json.encode(requestData),
      );
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          _vulnerabilityResults = data['results'];
        });
      } else {
        setState(() {
          _vulnerabilityResults = 'Error: ${response.statusCode}\n${response.body}';
        });
      }
    } catch (e) {
      setState(() {
        _vulnerabilityResults = 'Error: $e';
      });
    } finally {
      setState(() {
        _isVulnScanRunning = false;
      });
    }
  }

  Widget _buildBasicScanTab() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _ipController,
            decoration: const InputDecoration(
              labelText: 'IP Address or Hostname',
              hintText: 'e.g., 192.168.1.1 or example.com',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _optionsController,
            decoration: const InputDecoration(
              labelText: 'Nmap Options',
              hintText: 'e.g., -sV -p 1-1000',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _isLoading ? null : _runScan,
            child: _isLoading
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                      strokeWidth: 2,
                    ),
                  )
                : const Text('Run Basic Scan'),
          ),
          const SizedBox(height: 16),
          const Text('Results:', style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Expanded(
            child: Container(
              padding: const EdgeInsets.all(8.0),
              decoration: BoxDecoration(
                border: Border.all(color: Colors.grey),
                borderRadius: BorderRadius.circular(4.0),
              ),
              child: SingleChildScrollView(
                child: Text(_scanResults),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildVulnerabilityTab() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Vulnerability Scan Settings', 
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Card(
            elevation: 2,
            child: Padding(
              padding: const EdgeInsets.all(12.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Scan Intensity Level:', style: TextStyle(fontWeight: FontWeight.bold)),
                  Slider(
                    value: _selectedScanLevel.toDouble(),
                    min: 1,
                    max: 5,
                    divisions: 4,
                    label: _selectedScanLevel.toString(),
                    onChanged: (value) {
                      setState(() {
                        _selectedScanLevel = value.toInt();
                      });
                    },
                  ),
                  Text(
                    'Level $_selectedScanLevel: ${_getScanLevelDescription(_selectedScanLevel)}',
                    style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
                  ),
                  const SizedBox(height: 16),
                  SwitchListTile(
                    title: const Text('Script Scanning (--script=vuln)'),
                    subtitle: const Text('Use NSE vulnerability detection scripts'),
                    value: _enableScriptScan,
                    onChanged: (bool value) {
                      setState(() {
                        _enableScriptScan = value;
                      });
                    },
                  ),
                  SwitchListTile(
                    title: const Text('OS Detection (-O)'),
                    subtitle: const Text('Enable operating system detection'),
                    value: _enableOsScan,
                    onChanged: (bool value) {
                      setState(() {
                        _enableOsScan = value;
                      });
                    },
                  ),
                  SwitchListTile(
                    title: const Text('Version Detection (-sV)'),
                    subtitle: const Text('Detect service versions'),
                    value: _enableVersionDetection,
                    onChanged: (bool value) {
                      setState(() {
                        _enableVersionDetection = value;
                      });
                    },
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _isVulnScanRunning ? null : _runVulnerabilityScan,
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.redAccent,
            ),
            child: _isVulnScanRunning
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                      strokeWidth: 2,
                    ),
                  )
                : const Text('Run Vulnerability Scan'),
          ),
          const SizedBox(height: 16),
          const Text('Vulnerability Analysis:', style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Expanded(
            child: Container(
              padding: const EdgeInsets.all(8.0),
              decoration: BoxDecoration(
                border: Border.all(color: Colors.grey),
                borderRadius: BorderRadius.circular(4.0),
              ),
              child: SingleChildScrollView(
                child: Text(_vulnerabilityResults),
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _getScanLevelDescription(int level) {
    switch (level) {
      case 1:
        return 'Quick scan (fewer ports)';
      case 2:
        return 'Default scan';
      case 3:
        return 'Moderate scan intensity';
      case 4:
        return 'Aggressive scan';
      case 5:
        return 'Intense scan (all ports, all scripts)';
      default:
        return 'Custom scan';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Advanced Vulnerability Scanner'),
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'Basic Scan', icon: Icon(Icons.radar)),
            Tab(text: 'Vulnerability Scan', icon: Icon(Icons.security)),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildBasicScanTab(),
          _buildVulnerabilityTab(),
        ],
      ),
    );
  }
}
