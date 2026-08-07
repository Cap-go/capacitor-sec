import type { Rule, Finding } from '../types.js';

export const iosRules: Rule[] = [
  {
    id: 'IOS001',
    name: 'App Transport Security Disabled',
    description: 'Detects when App Transport Security (ATS) is disabled or has exceptions',
    severity: 'critical',
    category: 'ios',
    filePatterns: ['**/Info.plist'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for ATS disabled
      const atsDisabledPatterns = [
        { pattern: /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/, message: 'App Transport Security is completely disabled' },
        { pattern: /<key>NSAllowsArbitraryLoadsInWebContent<\/key>\s*<true\s*\/>/, message: 'ATS disabled for WebView content' },
        { pattern: /<key>NSAllowsLocalNetworking<\/key>\s*<true\s*\/>/, message: 'ATS allows local networking' },
        { pattern: /<key>NSExceptionAllowsInsecureHTTPLoads<\/key>\s*<true\s*\/>/, message: 'ATS exception allows insecure HTTP' }
      ];

      for (const { pattern, message } of atsDisabledPatterns) {
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'IOS001',
              ruleName: 'App Transport Security Disabled',
              severity: 'critical',
              category: 'ios',
              message,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Enable App Transport Security and use HTTPS. Add specific exceptions only for domains that truly require them.',
              references: ['https://developer.apple.com/documentation/security/preventing_insecure_network_connections']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Enable ATS and use HTTPS exclusively. Minimize domain exceptions.'
  },
  {
    id: 'IOS002',
    name: 'Insecure Keychain Access',
    description: 'Detects insecure Keychain access configuration',
    severity: 'high',
    category: 'ios',
    filePatterns: ['**/*.swift', '**/*.m', '**/*.ts', '**/*.tsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for insecure Keychain accessibility
      const insecurePatterns = [
        { pattern: /kSecAttrAccessibleAlways/, message: 'Keychain item accessible when device is locked' },
        { pattern: /kSecAttrAccessibleAlwaysThisDeviceOnly/, message: 'Keychain item accessible when device is locked' },
        { pattern: /kSecAttrAccessibleAfterFirstUnlock/, message: 'Keychain item accessible after first unlock - consider more restrictive option' }
      ];

      for (const { pattern, message } of insecurePatterns) {
        let match;
        const regex = new RegExp(pattern.source, 'g');
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'IOS002',
            ruleName: 'Insecure Keychain Access',
            severity: 'high',
            category: 'ios',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for sensitive data.',
            references: ['https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values']
          });
        }
      }

      return findings;
    },
    remediation: 'Use the most restrictive Keychain accessibility that meets your needs.'
  },
  {
    id: 'IOS003',
    name: 'URL Scheme Without Validation',
    description: 'Detects custom URL scheme handlers without proper validation',
    severity: 'high',
    category: 'ios',
    filePatterns: ['**/Info.plist', '**/*.swift', '**/AppDelegate.swift'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      if (filePath.includes('Info.plist')) {
        // Check for URL schemes
        if (/<key>CFBundleURLSchemes<\/key>/.test(content)) {
          findings.push({
            ruleId: 'IOS003',
            ruleName: 'URL Scheme Without Validation',
            severity: 'info',
            category: 'ios',
            message: 'Custom URL scheme detected - ensure proper validation in handler',
            filePath,
            line: 1,
            remediation: 'Validate all URL scheme inputs before processing. Implement Universal Links for better security.',
            references: ['https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app']
          });
        }
      }

      if (filePath.includes('.swift') || filePath.includes('AppDelegate')) {
        // Check for URL handler without validation
        const urlHandlerPattern = /func\s+application.*open\s+url:\s*URL/g;
        if (urlHandlerPattern.test(content)) {
          const hasValidation = /url\.scheme\s*==|url\.host\s*==|validateURL|isValidURL/.test(content);
          if (!hasValidation) {
            findings.push({
              ruleId: 'IOS003',
              ruleName: 'URL Scheme Without Validation',
              severity: 'high',
              category: 'ios',
              message: 'URL scheme handler without apparent validation',
              filePath,
              line: 1,
              remediation: 'Validate URL scheme, host, and parameters before processing.',
              references: ['https://capacitor-sec.dev/docs/rules/url-schemes']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Validate all components of incoming URLs before processing.'
  },
  {
    id: 'IOS004',
    name: 'iOS Pasteboard Sensitive Data',
    description: 'Detects potential exposure of sensitive data through pasteboard',
    severity: 'medium',
    category: 'ios',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for clipboard usage with sensitive data
      const clipboardPattern = /(?:Clipboard|Pasteboard)\.(?:write|set)/gi;
      const sensitiveData = /(?:password|token|secret|key|auth|credential|credit.?card|ssn)/i;

      let match;
      while ((match = clipboardPattern.exec(content)) !== null) {
        const context = content.substring(Math.max(0, match.index - 100), match.index + 200);
        if (sensitiveData.test(context)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'IOS004',
            ruleName: 'iOS Pasteboard Sensitive Data',
            severity: 'medium',
            category: 'ios',
            message: 'Sensitive data may be written to pasteboard where other apps can access it',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Avoid writing sensitive data to clipboard. If necessary, use expiring clipboard items on iOS 16+.',
            references: ['https://capacitor-sec.dev/docs/rules/pasteboard']
          });
        }
      }

      return findings;
    },
    remediation: 'Avoid copying sensitive data to clipboard.'
  },
  {
    id: 'IOS005',
    name: 'Insecure iOS Entitlements',
    description: 'Detects potentially dangerous iOS entitlements',
    severity: 'high',
    category: 'ios',
    filePatterns: ['**/*.entitlements'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const dangerousEntitlements = [
        { key: 'get-task-allow', message: 'get-task-allow entitlement should be false in release builds' },
        { key: 'com.apple.developer.associated-domains', message: 'Review associated domains for security implications' }
      ];

      for (const { key, message } of dangerousEntitlements) {
        const pattern = new RegExp(`<key>${key}</key>\\s*<true\\s*/>`);
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'IOS005',
              ruleName: 'Insecure iOS Entitlements',
              severity: key === 'get-task-allow' ? 'critical' : 'info',
              category: 'ios',
              message,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Review entitlements for release builds. Disable debugging entitlements.',
              references: ['https://developer.apple.com/documentation/bundleresources/entitlements']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Review and minimize iOS entitlements for production.'
  },
  {
    id: 'IOS006',
    name: 'Background App Refresh Data Exposure',
    description: 'Detects background refresh that may expose sensitive operations',
    severity: 'low',
    category: 'ios',
    filePatterns: ['**/Info.plist'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for background modes
      const backgroundPattern = /<key>UIBackgroundModes<\/key>/;
      if (backgroundPattern.test(content)) {
        findings.push({
          ruleId: 'IOS006',
          ruleName: 'Background App Refresh Data Exposure',
          severity: 'info',
          category: 'ios',
          message: 'App has background modes enabled - ensure sensitive operations are protected',
          filePath,
          line: 1,
          remediation: 'Review background operations for sensitive data handling. Encrypt data in background tasks.',
          references: ['https://capacitor-sec.dev/docs/rules/background']
        });
      }

      return findings;
    },
    remediation: 'Secure sensitive operations running in background.'
  },
  {
    id: 'IOS007',
    name: 'Missing iOS Jailbreak Detection',
    description: 'No jailbreak detection found for sensitive iOS application',
    severity: 'medium',
    category: 'ios',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.swift'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      // Only check main entry files
      if (!filePath.includes('App.') && !filePath.includes('main.') && !filePath.includes('AppDelegate')) {
        return findings;
      }

      const hasSensitiveOps = /(?:payment|banking|wallet|crypto|biometric|auth)/i.test(content);
      const hasJailbreakDetection = /(?:isJailbroken|jailbreak|Cydia|checkra1n|unc0ver|freeRASP)/i.test(content);

      if (hasSensitiveOps && !hasJailbreakDetection) {
        findings.push({
          ruleId: 'IOS007',
          ruleName: 'Missing iOS Jailbreak Detection',
          severity: 'medium',
          category: 'ios',
          message: 'Sensitive operations without jailbreak detection',
          filePath,
          line: 1,
          remediation: 'Implement jailbreak detection for sensitive apps using @niclas-niclas/capacitor-freerasp.',
          references: [
            'https://github.com/niclas-niclas/capacitor-freerasp',
            'https://capacitor-sec.dev/docs/rules/jailbreak'
          ]
        });
      }

      return findings;
    },
    remediation: 'Add jailbreak detection for sensitive applications.'
  },
  {
    id: 'IOS008',
    name: 'Screenshots Not Disabled for Sensitive Screens',
    description: 'Detects when screenshot protection is missing for sensitive UI',
    severity: 'low',
    category: 'ios',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      // Check for password/PIN input without screenshot protection
      const sensitiveUI = /(?:password|pin|otp|cvv|credit.?card).*(?:input|field|form)/i.test(content);
      const hasScreenshotProtection = /(?:preventScreenCapture|secureWindow|isSecure)/i.test(content);

      if (sensitiveUI && !hasScreenshotProtection) {
        findings.push({
          ruleId: 'IOS008',
          ruleName: 'Screenshots Not Disabled for Sensitive Screens',
          severity: 'low',
          category: 'ios',
          message: 'Sensitive input UI without screenshot protection',
          filePath,
          line: 1,
          remediation: 'Consider preventing screenshots on screens with sensitive data entry.',
          references: ['https://capacitor-sec.dev/docs/rules/screenshots']
        });
      }

      return findings;
    },
    remediation: 'Implement screenshot protection for sensitive UI screens.'
  },
  {
    id: 'IOS009',
    name: 'iOS File Sharing Exposes App Documents',
    description: 'Detects UIFileSharingEnabled or LSSupportsOpeningDocumentsInPlace which expose Documents via Finder/Files',
    severity: 'medium',
    category: 'ios',
    filePatterns: ['**/Info.plist'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const patterns = [
        {
          pattern: /<key>UIFileSharingEnabled<\/key>\s*<true\s*\/>/,
          message: 'UIFileSharingEnabled exposes Documents directory over USB/Finder'
        },
        {
          pattern: /<key>LSSupportsOpeningDocumentsInPlace<\/key>\s*<true\s*\/>/,
          message: 'LSSupportsOpeningDocumentsInPlace allows external apps to open Documents in place'
        },
        {
          pattern: /<key>UISupportsDocumentBrowser<\/key>\s*<true\s*\/>/,
          message: 'UISupportsDocumentBrowser broadens document access surface — ensure no secrets in Documents'
        }
      ];

      for (const { pattern, message } of patterns) {
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (!match) continue;
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'IOS009',
            ruleName: 'iOS File Sharing Exposes App Documents',
            severity: 'medium',
            category: 'ios',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation:
              'Disable file sharing unless required. Never store tokens, keys, or PII in Documents when sharing is enabled — use Keychain.',
            references: [
              'https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/about_app_file_management',
              'https://mas.owasp.org/MASVS/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Turn off UIFileSharingEnabled unless the product requires user document exchange.'
  }
];
