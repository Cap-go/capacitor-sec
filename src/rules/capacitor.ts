import type { Rule, Finding } from '../types.js';

export const capacitorRules: Rule[] = [
  {
    id: 'CAP001',
    name: 'WebView Debug Mode Enabled',
    description: 'Detects web debugging enabled in production Capacitor configuration',
    severity: 'critical',
    category: 'capacitor',
    filePatterns: ['**/capacitor.config.ts', '**/capacitor.config.js', '**/capacitor.config.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const debugPattern = /webContentsDebuggingEnabled\s*:\s*true/i;

      if (debugPattern.test(content)) {
        const match = content.match(debugPattern);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'CAP001',
            ruleName: 'WebView Debug Mode Enabled',
            severity: 'critical',
            category: 'capacitor',
            message: 'WebView debugging is enabled, allowing remote code inspection',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Set webContentsDebuggingEnabled to false for production builds.',
            references: ['https://capacitorjs.com/docs/config']
          });
        }
      }

      return findings;
    },
    remediation: 'Disable WebView debugging in production: webContentsDebuggingEnabled: false'
  },
  {
    id: 'CAP002',
    name: 'Insecure Plugin Configuration',
    description: 'Detects insecure Capacitor plugin configurations',
    severity: 'high',
    category: 'capacitor',
    filePatterns: ['**/capacitor.config.ts', '**/capacitor.config.js', '**/capacitor.config.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for AllowMixedContent on Android
      if (/allowMixedContent\s*:\s*true/i.test(content)) {
        const match = content.match(/allowMixedContent\s*:\s*true/i);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'CAP002',
            ruleName: 'Insecure Plugin Configuration',
            severity: 'high',
            category: 'capacitor',
            message: 'allowMixedContent enables loading HTTP resources over HTTPS',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Remove allowMixedContent: true. All content should be served over HTTPS.',
            references: ['https://capacitorjs.com/docs/config/android']
          });
        }
      }

      // Check for capture input (keyboard capture)
      if (/captureInput\s*:\s*true/i.test(content)) {
        const match = content.match(/captureInput\s*:\s*true/i);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'CAP002',
            ruleName: 'Insecure Plugin Configuration',
            severity: 'medium',
            category: 'capacitor',
            message: 'captureInput is enabled, which captures all keyboard input',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Only enable captureInput if specifically required for your use case.',
            references: ['https://capacitorjs.com/docs/config/android']
          });
        }
      }

      return findings;
    },
    remediation: 'Review and secure Capacitor plugin configurations.'
  },
  {
    id: 'CAP003',
    name: 'Verbose Logging in Production',
    description: 'Detects verbose logging configuration that may expose sensitive data',
    severity: 'medium',
    category: 'capacitor',
    filePatterns: ['**/capacitor.config.ts', '**/capacitor.config.js', '**/capacitor.config.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const loggingPattern = /loggingBehavior\s*:\s*['"](?:debug|verbose)['"]/i;

      if (loggingPattern.test(content)) {
        const match = content.match(loggingPattern);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'CAP003',
            ruleName: 'Verbose Logging in Production',
            severity: 'medium',
            category: 'capacitor',
            message: 'Verbose logging is enabled which may expose sensitive information',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Set loggingBehavior to "production" or "none" for production builds.',
            references: ['https://capacitorjs.com/docs/config']
          });
        }
      }

      return findings;
    },
    remediation: 'Use production-appropriate logging levels.'
  },
  {
    id: 'CAP004',
    name: 'Insecure allowNavigation',
    description: 'Detects overly permissive navigation allowlist',
    severity: 'high',
    category: 'capacitor',
    filePatterns: ['**/capacitor.config.ts', '**/capacitor.config.js', '**/capacitor.config.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for wildcard or overly broad navigation patterns
      const patterns = [
        { pattern: /allowNavigation.*\*\.\*/, message: 'Wildcard navigation pattern allows any domain' },
        { pattern: /allowNavigation.*http:\/\//, message: 'HTTP URLs in allowNavigation are insecure' },
        { pattern: /allowNavigation.*\['"\*['"]/, message: 'Wildcard * allows navigation to any URL' }
      ];

      for (const { pattern, message } of patterns) {
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'CAP004',
              ruleName: 'Insecure allowNavigation',
              severity: 'high',
              category: 'capacitor',
              message,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Specify exact HTTPS domains in allowNavigation.',
              references: ['https://capacitorjs.com/docs/config']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Use explicit domain allowlists for navigation.'
  },
  {
    id: 'CAP005',
    name: 'Native Bridge Exposure',
    description: 'Detects potential exposure of native bridge to untrusted content',
    severity: 'critical',
    category: 'capacitor',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for exposing Capacitor to window
      const exposurePatterns = [
        /window\.Capacitor\s*=/,
        /globalThis\.Capacitor\s*=/,
        /eval\s*\([^)]*Capacitor/,
        /Function\s*\([^)]*Capacitor/
      ];

      for (const pattern of exposurePatterns) {
        let match;
        const regex = new RegExp(pattern.source, 'gi');
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CAP005',
            ruleName: 'Native Bridge Exposure',
            severity: 'critical',
            category: 'capacitor',
            message: 'Capacitor native bridge may be exposed to untrusted code',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Never expose the Capacitor bridge to dynamically loaded or untrusted content.',
            references: ['https://capacitor-sec.dev/docs/rules/native-bridge']
          });
        }
      }

      return findings;
    },
    remediation: 'Keep native bridge access restricted to trusted code only.'
  },
  {
    id: 'CAP006',
    name: 'Eval Usage with User Input',
    description: 'Detects usage of eval() or similar functions that could execute arbitrary code',
    severity: 'critical',
    category: 'capacitor',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip node_modules
      if (filePath.includes('node_modules')) {
        return findings;
      }

      const evalPatterns = [
        /\beval\s*\(/g,
        /new\s+Function\s*\(/g,
        /setTimeout\s*\(\s*['"`][^'"`]+['"`]/g,
        /setInterval\s*\(\s*['"`][^'"`]+['"`]/g
      ];

      for (const pattern of evalPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CAP006',
            ruleName: 'Eval Usage with User Input',
            severity: 'critical',
            category: 'capacitor',
            message: 'Usage of eval() or equivalent can lead to code injection attacks',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Avoid eval() and new Function(). Use safer alternatives like JSON.parse() for data.',
            references: [
              'https://owasp.org/www-community/attacks/Code_Injection',
              'https://capacitor-sec.dev/docs/rules/eval'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Remove all usage of eval() and new Function(). Use JSON.parse() for data parsing.'
  },
  {
    id: 'CAP007',
    name: 'Missing Root/Jailbreak Detection',
    description: 'No root or jailbreak detection found for sensitive operations',
    severity: 'medium',
    category: 'capacitor',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      // Only check entry points or main files
      if (!filePath.includes('App.') && !filePath.includes('main.') && !filePath.includes('index.')) {
        return findings;
      }

      // Check for sensitive operations
      const hasSensitiveOps = /(?:payment|banking|wallet|crypto|biometric|auth)/i.test(content);

      // Check for root/jailbreak detection
      const hasRootDetection = /(?:isRooted|isJailbroken|rootDetection|jailbreakDetection|freeRASP|appIntegrity)/i.test(content);

      if (hasSensitiveOps && !hasRootDetection) {
        findings.push({
          ruleId: 'CAP007',
          ruleName: 'Missing Root/Jailbreak Detection',
          severity: 'medium',
          category: 'capacitor',
          message: 'Sensitive operations detected without root/jailbreak detection',
          filePath,
          line: 1,
          remediation: 'Implement root/jailbreak detection for apps handling sensitive data. Consider using @niclas-niclas/capacitor-freerasp.',
          references: [
            'https://github.com/niclas-niclas/capacitor-freerasp',
            'https://capacitor-sec.dev/docs/rules/root-detection'
          ]
        });
      }

      return findings;
    },
    remediation: 'Add root/jailbreak detection for sensitive applications.'
  },
  {
    id: 'CAP008',
    name: 'Insecure Plugin Import',
    description: 'Detects import of known insecure or deprecated Capacitor plugins',
    severity: 'medium',
    category: 'capacitor',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/package.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // List of deprecated or insecure plugins
      const insecurePlugins = [
        { name: '@capacitor/browser', check: /webview|iframe/i, message: 'Using Browser plugin for sensitive content may be insecure' },
        { name: 'cordova-plugin-', check: /cordova-plugin-/i, message: 'Cordova plugins may have security issues in Capacitor context' }
      ];

      for (const plugin of insecurePlugins) {
        if (plugin.check.test(content)) {
          const match = content.match(plugin.check);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'CAP008',
              ruleName: 'Insecure Plugin Import',
              severity: 'low',
              category: 'capacitor',
              message: plugin.message,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Review plugin security implications. Prefer Capacitor-native plugins.',
              references: ['https://capacitor-sec.dev/docs/rules/plugins']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Use official Capacitor plugins when available.'
  },
  {
    id: 'CAP009',
    name: 'Live Update Security',
    description: 'Detects insecure live update configurations',
    severity: 'high',
    category: 'capacitor',
    filePatterns: ['**/capacitor.config.ts', '**/capacitor.config.js', '**/capacitor.config.json', '**/*.ts', '**/*.tsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for Capgo/live update without encryption
      const liveUpdatePattern = /(?:@capgo\/capacitor-updater|CapacitorUpdater)/i;

      if (liveUpdatePattern.test(content)) {
        // Check for encryption configuration
        const hasEncryption = /(?:privateKey|encryptionKey)/i.test(content);

        if (!hasEncryption) {
          const match = content.match(liveUpdatePattern);
          if (match) {
            const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
            findings.push({
              ruleId: 'CAP009',
              ruleName: 'Live Update Security',
              severity: 'high',
              category: 'capacitor',
              message: 'Live update configured without encryption',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Enable encryption for live updates to prevent tampering. Use Capgo end-to-end encryption.',
              references: [
                'https://capgo.app/docs/cli/encryption/',
                'https://capgo.app/docs/plugin/cloud-mode/hybrid-update/',
                'https://capacitor-sec.dev/docs/rules/live-update'
              ]
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Enable end-to-end encryption for live updates with Capgo.'
  },
  {
    id: 'CAP010',
    name: 'Insecure postMessage Handler',
    description: 'Detects insecure postMessage handlers that could accept malicious messages',
    severity: 'high',
    category: 'capacitor',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for postMessage listener without origin validation
      const postMessagePattern = /addEventListener\s*\(\s*['"]message['"]/g;

      let match;
      while ((match = postMessagePattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 500));
        const hasOriginCheck = /event\.origin|e\.origin|origin\s*[!=]==?\s*['"]/.test(context);

        if (!hasOriginCheck) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CAP010',
            ruleName: 'Insecure postMessage Handler',
            severity: 'high',
            category: 'capacitor',
            message: 'postMessage handler without origin validation',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Always validate event.origin before processing postMessage data.',
            references: ['https://capacitor-sec.dev/docs/rules/postmessage']
          });
        }
      }

      return findings;
    },
    remediation: 'Validate message origin before processing postMessage events.'
  },
{
    id: 'CAP011',
    name: 'Insecure Capacitor Server URL',
    description: 'Detects capacitor.config server.url using HTTP or wildcard hosts in production config',
    severity: 'critical',
    category: 'capacitor',
    filePatterns: [
      '**/capacitor.config.ts',
      '**/capacitor.config.js',
      '**/capacitor.config.json',
      '**/capacitor.config.mjs',
      '**/capacitor.config.cjs'
    ],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Match url under a nearby server block (TS/JS/JSON). Optional quotes for JSON keys.
      const patterns = [
        {
          pattern:
            /server\s*:\s*\{[\s\S]{0,400}?["']?url["']?\s*:\s*["']http:\/\/(?!localhost(?:[:/?#"']|$)|127\.0\.0\.1(?:[:/?#"']|$))[^"']+["']/gi,
          message: 'server.url uses HTTP — traffic and bridge content can be intercepted',
          severity: 'critical' as const
        },
        {
          pattern:
            /["']url["']\s*:\s*["']http:\/\/(?!localhost(?:[:/?#"']|$)|127\.0\.0\.1(?:[:/?#"']|$))[^"']+["']/gi,
          message: 'server.url uses HTTP — traffic and bridge content can be intercepted',
          severity: 'critical' as const,
          requireServerContext: true
        },
        {
          pattern: /server\s*:\s*\{[\s\S]{0,400}?["']?url["']?\s*:\s*["']https?:\/\/\*[^"']*["']/gi,
          message: 'server.url contains a wildcard host',
          severity: 'high' as const
        },
        {
          pattern: /["']url["']\s*:\s*["']https?:\/\/\*[^"']*["']/gi,
          message: 'server.url contains a wildcard host',
          severity: 'high' as const,
          requireServerContext: true
        }
      ];

      const seen = new Set<number>();

      for (const { pattern, message, severity, requireServerContext } of patterns as Array<{
        pattern: RegExp;
        message: string;
        severity: 'critical' | 'high';
        requireServerContext?: boolean;
      }>) {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(content)) !== null) {
          if (requireServerContext) {
            const windowStart = Math.max(0, match.index - 120);
            const around = content.substring(windowStart, match.index);
            if (!/["']?server["']?\s*:/.test(around)) {
              continue;
            }
          }
          const lineNum = content.substring(0, match.index).split('\n').length;
          if (seen.has(lineNum)) continue;
          seen.add(lineNum);
          findings.push({
            ruleId: 'CAP011',
            ruleName: 'Insecure Capacitor Server URL',
            severity,
            category: 'capacitor',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation:
              'Use HTTPS endpoints only. Remove server.url from production builds unless intentionally loading a remote, pinned HTTPS origin.',
            references: [
              'https://capacitorjs.com/docs/config',
              'https://capacitorjs.com/docs/guides/security/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Serve the app over HTTPS; avoid cleartext remote server.url in production.'
  }
];
