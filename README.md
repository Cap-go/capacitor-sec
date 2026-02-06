# 🔒 Capsec - Capacitor Security Scanner

 <a href="https://capgo.app/"><img src='https://raw.githubusercontent.com/Cap-go/capgo/main/assets/capgo_banner.png' alt='Capgo - Instant updates for capacitor'/></a>

<div align="center">
  <h2><a href="https://capgo.app/?ref=repo_capgo_sec"> ➡️ Get Instant updates for your App with Capgo</a></h2>
  <h2><a href="https://capgo.app/consulting/?ref=repo_capgo_sec"> Missing a feature? We’ll build the plugin for you</a></h2>
</div>

[![npm version](https://badge.fury.io/js/capsec.svg)](https://www.npmjs.com/package/capsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Zero-config security scanner for **Capacitor** and **Ionic** apps. Detect vulnerabilities, hardcoded secrets, and security misconfigurations with a single command.

🌐 **Website:** [capacitor-sec.dev](https://capacitor-sec.dev)

## Features

- **🚀 Zero Configuration** - Works out of the box with any Capacitor/Ionic project
- **🔐 Local Processing** - Your code never leaves your machine
- **📱 Platform-Specific** - Android and iOS security checks
- **🔑 Secret Detection** - Detects 30+ types of API keys and secrets
- **⚡ Fast** - Scans 1000+ files in seconds
- **📊 Multiple Outputs** - CLI, JSON, and HTML reports
- **🔄 CI/CD Ready** - GitHub Actions, GitLab CI support

## Quick Start

```bash
# Run directly with bunx (no installation needed)
bunx capsec scan

# Or install globally
bun add -g capsec
capsec scan
```

## Security Rules

Capsec includes **63+ security rules** across 13 categories:

| Category | Rules | Description |
|----------|-------|-------------|
| 🔑 Secrets | 2 | API keys, tokens, credentials |
| 💾 Storage | 6 | Preferences, localStorage, SQLite |
| 🌐 Network | 8 | HTTP, SSL/TLS, WebSocket |
| ⚡ Capacitor | 10 | Config, plugins, native bridge |
| 🤖 Android | 8 | Manifest, WebView, permissions |
| 🍎 iOS | 8 | ATS, Keychain, entitlements |
| 🔐 Authentication | 6 | JWT, OAuth, biometrics |
| 🖼️ WebView | 5 | XSS, CSP, iframe security |
| 🔒 Cryptography | 4 | Algorithms, keys, IV generation |
| 📝 Logging | 2 | Sensitive data in logs |
| 🐛 Debug | 3 | Test credentials, dev URLs |

## Usage

### Basic Scan

```bash
# Scan current directory
capsec scan

# Scan specific path
capsec scan ./my-capacitor-app
```

### Output Formats

```bash
# CLI output (default)
capsec scan

# JSON output
capsec scan --output json --output-file report.json

# HTML report
capsec scan --output html --output-file report.html
```

### Filtering

```bash
# Only critical and high severity
capsec scan --severity high

# Only specific categories
capsec scan --categories storage,secrets,network

# Exclude patterns
capsec scan --exclude "**/test/**,**/demo/**"
```

### CI/CD Mode

```bash
# Exit with code 1 if high/critical issues found
capsec scan --ci
```

### List Rules

```bash
# List all rules
capsec rules

# Filter by category
capsec rules --category android

# Filter by severity
capsec rules --severity critical
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Bun
        uses: oven-sh/setup-bun@v1

      - name: Run Security Scan
        run: bunx capsec scan --ci
```

### GitLab CI

```yaml
security-scan:
  image: oven/bun:latest
  script:
    - bunx capsec scan --ci
  only:
    - merge_requests
    - main
```

## Configuration

Create a `capsec.config.json` file:

```json
{
  "exclude": [
    "**/node_modules/**",
    "**/dist/**"
  ],
  "severity": "low",
  "categories": [],
  "rules": {}
}
```

Or initialize with:

```bash
capsec init
```

## Programmatic Usage

```typescript
import { SecurityScanner } from 'capsec';

const scanner = new SecurityScanner({
  path: './my-app',
  severity: 'medium',
  categories: ['secrets', 'network']
});

const result = await scanner.scan();
console.log(result.summary);
```

## Rule Categories

### Secrets (SEC)
- **SEC001** - Hardcoded API Keys & Secrets
- **SEC002** - Exposed .env File

### Storage (STO)
- **STO001** - Unencrypted Sensitive Data in Preferences
- **STO002** - localStorage Usage for Sensitive Data
- **STO003** - SQLite Database Without Encryption
- **STO004** - Filesystem Storage of Sensitive Data
- **STO005** - Insecure Data Caching
- **STO006** - Keychain/Keystore Not Used for Credentials

### Network (NET)
- **NET001** - HTTP Cleartext Traffic
- **NET002** - SSL/TLS Certificate Pinning Missing
- **NET003** - Capacitor Server Cleartext Enabled
- **NET004** - Insecure WebSocket Connection
- **NET005** - CORS Wildcard Configuration
- **NET006** - Insecure Deep Link Validation
- **NET007** - Capacitor HTTP Plugin Misuse
- **NET008** - Sensitive Data in URL Parameters

### Capacitor (CAP)
- **CAP001** - WebView Debug Mode Enabled
- **CAP002** - Insecure Plugin Configuration
- **CAP003** - Verbose Logging in Production
- **CAP004** - Insecure allowNavigation
- **CAP005** - Native Bridge Exposure
- **CAP006** - Eval Usage with User Input
- **CAP007** - Missing Root/Jailbreak Detection
- **CAP008** - Insecure Plugin Import
- **CAP009** - Live Update Security
- **CAP010** - Insecure postMessage Handler

### Android (AND)
- **AND001** - Android Cleartext Traffic Allowed
- **AND002** - Android Debug Mode Enabled
- **AND003** - Insecure Android Permissions
- **AND004** - Android Backup Allowed
- **AND005** - Exported Components Without Permission
- **AND006** - WebView JavaScript Enabled Without Safeguards
- **AND007** - Insecure WebView addJavascriptInterface
- **AND008** - Hardcoded Signing Key

### iOS (IOS)
- **IOS001** - App Transport Security Disabled
- **IOS002** - Insecure Keychain Access
- **IOS003** - URL Scheme Without Validation
- **IOS004** - iOS Pasteboard Sensitive Data
- **IOS005** - Insecure iOS Entitlements
- **IOS006** - Background App Refresh Data Exposure
- **IOS007** - Missing iOS Jailbreak Detection
- **IOS008** - Screenshots Not Disabled for Sensitive Screens

### Authentication (AUTH)
- **AUTH001** - Weak JWT Validation
- **AUTH002** - Insecure Biometric Implementation
- **AUTH003** - Weak Random Number Generation
- **AUTH004** - Missing Session Timeout
- **AUTH005** - OAuth State Parameter Missing
- **AUTH006** - Hardcoded Credentials in Auth

### WebView (WEB)
- **WEB001** - WebView JavaScript Injection
- **WEB002** - Unsafe iframe Configuration
- **WEB003** - External Script Loading
- **WEB004** - Content Security Policy Missing
- **WEB005** - Target _blank Without noopener

### Cryptography (CRY)
- **CRY001** - Weak Cryptographic Algorithm
- **CRY002** - Hardcoded Encryption Key
- **CRY003** - Insecure Random IV Generation
- **CRY004** - Weak Password Hashing

### Logging (LOG)
- **LOG001** - Sensitive Data in Console Logs
- **LOG002** - Console Logs in Production

### Debug (DBG)
- **DBG001** - Debugger Statement
- **DBG002** - Test Credentials in Code
- **DBG003** - Development URL in Production

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related

- [Capgo](https://capgo.app) - Live updates for Capacitor apps
- [Capacitor](https://capacitorjs.com) - Build cross-platform apps
- [Ionic](https://ionicframework.com) - Mobile UI framework

---

Built with ❤️ by the [Capgo](https://capgo.app) team

## Compatibility

| Plugin version | Capacitor compatibility | Maintained |
| -------------- | ----------------------- | ---------- |
| v8.\*.\*       | v8.\*.\*                | ✅          |
| v7.\*.\*       | v7.\*.\*                | On demand   |
| v6.\*.\*       | v6.\*.\*                | ❌          |
| v5.\*.\*       | v5.\*.\*                | ❌          |

> **Note:** The major version of this plugin follows the major version of Capacitor. Use the version that matches your Capacitor installation (e.g., plugin v8 for Capacitor 8). Only the latest major version is actively maintained.
