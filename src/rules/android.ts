import type { Rule, Finding } from '../types.js';

export const androidRules: Rule[] = [
  {
    id: 'AND001',
    name: 'Android Cleartext Traffic Allowed',
    description: 'Detects usesCleartextTraffic enabled in Android manifest',
    severity: 'critical',
    category: 'android',
    filePatterns: ['**/AndroidManifest.xml', '**/network_security_config.xml'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      if (filePath.includes('AndroidManifest.xml')) {
        const cleartextPattern = /usesCleartextTraffic\s*=\s*["']true["']/i;
        if (cleartextPattern.test(content)) {
          const match = content.match(cleartextPattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'AND001',
              ruleName: 'Android Cleartext Traffic Allowed',
              severity: 'critical',
              category: 'android',
              message: 'usesCleartextTraffic="true" allows unencrypted HTTP traffic',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Set usesCleartextTraffic="false" and use HTTPS exclusively.',
              references: ['https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic']
            });
          }
        }
      }

      if (filePath.includes('network_security_config.xml')) {
        const cleartextDomainPattern = /cleartextTrafficPermitted\s*=\s*["']true["']/i;
        if (cleartextDomainPattern.test(content)) {
          const match = content.match(cleartextDomainPattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'AND001',
              ruleName: 'Android Cleartext Traffic Allowed',
              severity: 'critical',
              category: 'android',
              message: 'Network security config allows cleartext traffic for specific domains',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Remove cleartext traffic permissions. Use HTTPS for all domains.',
              references: ['https://developer.android.com/training/articles/security-config']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Disable cleartext traffic and enforce HTTPS.'
  },
  {
    id: 'AND002',
    name: 'Android Debug Mode Enabled',
    description: 'Detects debuggable flag enabled in Android manifest',
    severity: 'critical',
    category: 'android',
    filePatterns: ['**/AndroidManifest.xml', '**/build.gradle', '**/build.gradle.kts'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      if (filePath.includes('AndroidManifest.xml')) {
        const debugPattern = /android:debuggable\s*=\s*["']true["']/i;
        if (debugPattern.test(content)) {
          const match = content.match(debugPattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'AND002',
              ruleName: 'Android Debug Mode Enabled',
              severity: 'critical',
              category: 'android',
              message: 'android:debuggable="true" allows debugging and code inspection',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Remove android:debuggable or set to false for release builds.',
              references: ['https://developer.android.com/guide/topics/manifest/application-element#debug']
            });
          }
        }
      }

      if (filePath.includes('build.gradle')) {
        // Check for debuggable true in release build type
        const releaseDebugPattern = /release\s*\{[^}]*debuggable\s*(?:=\s*)?true/i;
        if (releaseDebugPattern.test(content)) {
          const match = content.match(releaseDebugPattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'AND002',
              ruleName: 'Android Debug Mode Enabled',
              severity: 'critical',
              category: 'android',
              message: 'Release build has debuggable=true enabled',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Set debuggable false for release build type.',
              references: ['https://developer.android.com/studio/build/build-variants']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Disable debugging in release builds.'
  },
  {
    id: 'AND003',
    name: 'Insecure Android Permissions',
    description: 'Detects dangerous or unnecessary Android permissions',
    severity: 'high',
    category: 'android',
    filePatterns: ['**/AndroidManifest.xml'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const dangerousPermissions = [
        { name: 'READ_CONTACTS', severity: 'medium' as const },
        { name: 'WRITE_CONTACTS', severity: 'medium' as const },
        { name: 'READ_CALL_LOG', severity: 'high' as const },
        { name: 'WRITE_CALL_LOG', severity: 'high' as const },
        { name: 'READ_SMS', severity: 'high' as const },
        { name: 'SEND_SMS', severity: 'high' as const },
        { name: 'RECEIVE_SMS', severity: 'high' as const },
        { name: 'RECORD_AUDIO', severity: 'high' as const },
        { name: 'READ_EXTERNAL_STORAGE', severity: 'medium' as const },
        { name: 'WRITE_EXTERNAL_STORAGE', severity: 'medium' as const },
        { name: 'ACCESS_FINE_LOCATION', severity: 'medium' as const },
        { name: 'ACCESS_BACKGROUND_LOCATION', severity: 'high' as const },
        { name: 'CAMERA', severity: 'medium' as const },
        { name: 'SYSTEM_ALERT_WINDOW', severity: 'high' as const },
        { name: 'REQUEST_INSTALL_PACKAGES', severity: 'critical' as const },
        { name: 'BIND_ACCESSIBILITY_SERVICE', severity: 'critical' as const }
      ];

      for (const perm of dangerousPermissions) {
        const pattern = new RegExp(`uses-permission[^>]*android.permission.${perm.name}`, 'i');
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'AND003',
              ruleName: 'Insecure Android Permissions',
              severity: perm.severity,
              category: 'android',
              message: `Dangerous permission ${perm.name} declared`,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Only request permissions that are strictly necessary. Review if this permission is required.',
              references: ['https://developer.android.com/guide/topics/permissions/overview']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Review and minimize permission requests to only what is necessary.'
  },
  {
    id: 'AND004',
    name: 'Android Backup Allowed',
    description: 'Detects when Android auto-backup is enabled for app data',
    severity: 'medium',
    category: 'android',
    filePatterns: ['**/AndroidManifest.xml'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check if allowBackup is explicitly set to true or not set (defaults to true)
      const allowBackupTrue = /android:allowBackup\s*=\s*["']true["']/i;
      const allowBackupSet = /android:allowBackup\s*=\s*["'](?:true|false)["']/i;

      if (allowBackupTrue.test(content)) {
        const match = content.match(allowBackupTrue);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'AND004',
            ruleName: 'Android Backup Allowed',
            severity: 'medium',
            category: 'android',
            message: 'android:allowBackup="true" allows backup of app data including sensitive information',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Set android:allowBackup="false" or configure backup_rules to exclude sensitive data.',
            references: ['https://developer.android.com/guide/topics/data/autobackup']
          });
        }
      } else if (!allowBackupSet.test(content) && content.includes('<application')) {
        // Not set at all - defaults to true
        findings.push({
          ruleId: 'AND004',
          ruleName: 'Android Backup Allowed',
          severity: 'medium',
          category: 'android',
          message: 'android:allowBackup not set (defaults to true), allowing backup of app data',
          filePath,
          line: 1,
          remediation: 'Explicitly set android:allowBackup="false" or configure backup rules.',
          references: ['https://developer.android.com/guide/topics/data/autobackup']
        });
      }

      return findings;
    },
    remediation: 'Disable auto-backup or configure backup rules to exclude sensitive data.'
  },
  {
    id: 'AND005',
    name: 'Exported Components Without Permission',
    description: 'Detects exported activities/services/receivers without proper permission protection',
    severity: 'high',
    category: 'android',
    filePatterns: ['**/AndroidManifest.xml'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for exported components without permission
      const componentTypes = ['activity', 'service', 'receiver', 'provider'];

      for (const type of componentTypes) {
        const exportedPattern = new RegExp(`<${type}[^>]*android:exported\\s*=\\s*["']true["'][^>]*>`, 'gi');
        let match;

        while ((match = exportedPattern.exec(content)) !== null) {
          const component = match[0];
          const hasPermission = /android:permission\s*=/.test(component);

          if (!hasPermission) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            findings.push({
              ruleId: 'AND005',
              ruleName: 'Exported Components Without Permission',
              severity: 'high',
              category: 'android',
              message: `Exported ${type} without permission protection`,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: `Add android:permission to protect the exported ${type} or set exported="false" if external access is not needed.`,
              references: ['https://developer.android.com/guide/components/intents-filters']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Protect exported components with appropriate permissions.'
  },
  {
    id: 'AND006',
    name: 'WebView JavaScript Enabled Without Safeguards',
    description: 'Detects WebView with JavaScript enabled but without proper security measures',
    severity: 'high',
    category: 'android',
    filePatterns: ['**/*.java', '**/*.kt'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const jsEnabledPattern = /setJavaScriptEnabled\s*\(\s*true\s*\)/g;

      let match;
      while ((match = jsEnabledPattern.exec(content)) !== null) {
        const context = content.substring(Math.max(0, match.index - 500), match.index + 500);

        // Check for security measures (MASVS-PLATFORM-2)
        const hasFileAccess = /setAllowFileAccess\s*\(\s*false\s*\)/.test(context);
        const hasContentAccess = /setAllowContentAccess\s*\(\s*false\s*\)/.test(context);
        const hasUniversalFileAccess = /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/.test(context);
        const hasFileAccessFromFile = /setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)/.test(context);

        if (!hasFileAccess || !hasContentAccess || hasUniversalFileAccess || hasFileAccessFromFile) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          let message = 'WebView has JavaScript enabled without disabling file/content access';
          if (hasUniversalFileAccess) {
            message = 'WebView enables setAllowUniversalAccessFromFileURLs(true) — allows cross-origin file access';
          } else if (hasFileAccessFromFile) {
            message = 'WebView enables setAllowFileAccessFromFileURLs(true) — risky with untrusted content';
          }
          findings.push({
            ruleId: 'AND006',
            ruleName: 'WebView JavaScript Enabled Without Safeguards',
            severity: 'high',
            category: 'android',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation:
              'Call setAllowFileAccess(false) and setAllowContentAccess(false). Never enable universal/file URL access with untrusted content.',
            references: [
              'https://developer.android.com/reference/android/webkit/WebSettings',
              'https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Disable file and content access in WebView when JavaScript is enabled.'
  },
  {
    id: 'AND007',
    name: 'Insecure WebView addJavascriptInterface',
    description: 'Detects addJavascriptInterface usage which can be exploited on older Android versions',
    severity: 'high',
    category: 'android',
    filePatterns: ['**/*.java', '**/*.kt'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const jsInterfacePattern = /addJavascriptInterface\s*\(/g;

      let match;
      while ((match = jsInterfacePattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'AND007',
          ruleName: 'Insecure WebView addJavascriptInterface',
          severity: 'high',
          category: 'android',
          message: 'addJavascriptInterface exposes native methods to WebView JS — minimize surface and prefer WebMessageListener',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Ensure minSdkVersion is >= 17 (Android 4.2) or use @JavascriptInterface annotation.',
          references: ['https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface']
        });
      }

      return findings;
    },
    remediation: 'Minimize JS bridge surface; use @JavascriptInterface and prefer WebMessageListener on modern Android.'
  },
  {
    id: 'AND008',
    name: 'Hardcoded Signing Key',
    description: 'Detects hardcoded signing key passwords or keystores in build files',
    severity: 'critical',
    category: 'android',
    filePatterns: ['**/build.gradle', '**/build.gradle.kts'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for hardcoded signing config
      const patterns = [
        /storePassword\s*(?:=|:)\s*['"][^'"]+['"]/i,
        /keyPassword\s*(?:=|:)\s*['"][^'"]+['"]/i,
        /storeFile\s*(?:=|:)\s*file\s*\(['"][^'"]+\.jks['"]\)/i
      ];

      for (const pattern of patterns) {
        const matches = content.match(pattern);
        if (matches) {
          const match = matches[0];
          const lineNum = content.substring(0, content.indexOf(match)).split('\n').length;
          findings.push({
            ruleId: 'AND008',
            ruleName: 'Hardcoded Signing Key',
            severity: 'critical',
            category: 'android',
            message: 'Signing key credentials appear to be hardcoded in build file',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim().replace(/['"][^'"]{5,}['"]/g, '"***REDACTED***"'),
            remediation: 'Use environment variables or keystore.properties file excluded from version control.',
            references: ['https://developer.android.com/studio/publish/app-signing']
          });
        }
      }

      return findings;
    },
    remediation: 'Move signing credentials to environment variables or excluded properties files.'
  },
{
    id: 'AND009',
    name: 'Insecure WebView File URL Access',
    description: 'Detects WebView settings that allow file:// origin to access other files or universal URLs',
    severity: 'critical',
    category: 'android',
    filePatterns: ['**/*.java', '**/*.kt'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const patterns = [
        {
          pattern: /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/g,
          message: 'setAllowUniversalAccessFromFileURLs(true) enables same-origin bypass via file://'
        },
        {
          pattern: /setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)/g,
          message: 'setAllowFileAccessFromFileURLs(true) allows file:// pages to read other local files'
        }
      ];

      for (const { pattern, message } of patterns) {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AND009',
            ruleName: 'Insecure WebView File URL Access',
            severity: 'critical',
            category: 'android',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation:
              'Keep both flags false. Load local assets via https://localhost or Capacitor WebView defaults, not file:// with broad access.',
            references: [
              'https://developer.android.com/reference/android/webkit/WebSettings',
              'https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Disable WebView file URL access flags; avoid loading untrusted content via file://.'
  },
  {
    id: 'AND010',
    name: 'Network Security Config Cleartext Permitted',
    description: 'Detects cleartextTrafficPermitted="true" in Android network security config',
    severity: 'critical',
    category: 'android',
    filePatterns: [
      '**/network_security_config.xml',
      '**/network-security-config.xml',
      '**/res/xml/*.xml'
    ],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      if (!/cleartextTrafficPermitted|network-security-config|domain-config|base-config/i.test(content)) {
        return findings;
      }

      const pattern = /cleartextTrafficPermitted\s*=\s*["']true["']/gi;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'AND010',
          ruleName: 'Network Security Config Cleartext Permitted',
          severity: 'critical',
          category: 'android',
          message: 'Network security config permits cleartext (HTTP) traffic',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation:
            'Set cleartextTrafficPermitted="false" and use HTTPS only. Prefer certificate pinning for sensitive APIs.',
          references: [
            'https://developer.android.com/privacy-and-security/security-config',
            'https://mas.owasp.org/MASVS/'
          ]
        });
      }

      return findings;
    },
    remediation: 'Disable cleartext in network_security_config.xml for production builds.'
  }
];
