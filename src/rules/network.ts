import type { Rule, Finding } from '../types.js';

export const networkRules: Rule[] = [
  {
    id: 'NET001',
    name: 'HTTP Cleartext Traffic',
    description: 'Detects usage of HTTP instead of HTTPS for network requests',
    severity: 'high',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/capacitor.config.*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test files and mocks
      if (filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__mocks__')) {
        return findings;
      }

      // Check for HTTP URLs (excluding localhost for development)
      const httpPattern = /['"`]http:\/\/(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[^'"`]+['"`]/g;

      let match;
      while ((match = httpPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'NET001',
          ruleName: 'HTTP Cleartext Traffic',
          severity: 'high',
          category: 'network',
          message: `Insecure HTTP URL detected: ${match[0].substring(0, 50)}...`,
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Use HTTPS for all network communications to prevent man-in-the-middle attacks.',
          references: ['https://capacitor-sec.dev/docs/rules/https']
        });
      }

      return findings;
    },
    remediation: 'Always use HTTPS. Configure proper SSL/TLS certificates.'
  },
  {
    id: 'NET002',
    name: 'SSL/TLS Certificate Pinning Missing',
    description: 'Detects network requests without certificate pinning for sensitive APIs',
    severity: 'medium',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for API calls to sensitive endpoints without pinning context
      const apiCallPattern = /(?:fetch|axios|http\.(?:get|post|put|delete))\s*\(\s*['"`][^'"`]*(?:api|auth|login|payment|bank)[^'"`]*['"`]/gi;

      // Check if certificate pinning is configured in the file or imports
      const hasPinning = /(?:certificatePinning|ssl-pinning|pinned|TrustKit|cert)/i.test(content);

      if (!hasPinning) {
        let match;
        while ((match = apiCallPattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'NET002',
            ruleName: 'SSL/TLS Certificate Pinning Missing',
            severity: 'medium',
            category: 'network',
            message: 'Sensitive API call without certificate pinning detected',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Implement SSL certificate pinning for sensitive API endpoints using capacitor-ssl-pinning or similar.',
            references: [
              'https://github.com/niclas-niclas/capacitor-ssl-pinning',
              'https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Implement certificate pinning for APIs handling sensitive data.'
  },
  {
    id: 'NET003',
    name: 'Capacitor Server Cleartext Enabled',
    description: 'Detects cleartext traffic enabled in Capacitor configuration',
    severity: 'critical',
    category: 'network',
    // Support any capacitor config extension (ts/js/json/mjs/cjs, etc).
    filePatterns: ['**/capacitor.config.*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for cleartext: true in server config
      // Works for TS/JS (`cleartext: true`) and JSON (`"cleartext": true`)
      const cleartextPattern = /\bcleartext\b["']?\s*:\s*true/i;

      if (cleartextPattern.test(content)) {
        const match = content.match(cleartextPattern);
        if (match) {
          const lineNum = content.substring(0, content.indexOf(match[0])).split('\n').length;
          findings.push({
            ruleId: 'NET003',
            ruleName: 'Capacitor Server Cleartext Enabled',
            severity: 'critical',
            category: 'network',
            message: 'Cleartext traffic is enabled in Capacitor configuration',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Remove cleartext: true from capacitor.config. Use HTTPS for all server communications.',
            references: ['https://capacitorjs.com/docs/config']
          });
        }
      }

      return findings;
    },
    remediation: 'Remove cleartext configuration and use HTTPS exclusively.'
  },
  {
    id: 'NET004',
    name: 'Insecure WebSocket Connection',
    description: 'Detects usage of ws:// instead of wss:// for WebSocket connections',
    severity: 'high',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip localhost connections
      const wsPattern = /['"`]ws:\/\/(?!localhost|127\.0\.0\.1)[^'"`]+['"`]/g;

      let match;
      while ((match = wsPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'NET004',
          ruleName: 'Insecure WebSocket Connection',
          severity: 'high',
          category: 'network',
          message: 'Insecure WebSocket (ws://) connection detected',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Use secure WebSocket connections (wss://) for all production traffic.',
          references: ['https://capacitor-sec.dev/docs/rules/websocket']
        });
      }

      return findings;
    },
    remediation: 'Use wss:// for all WebSocket connections.'
  },
  {
    id: 'NET005',
    name: 'CORS Wildcard Configuration',
    description: 'Detects overly permissive CORS configuration',
    severity: 'medium',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/capacitor.config.*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for wildcard in allowNavigation or CORS settings
      const wildcardPattern = /(?:allowNavigation|Access-Control-Allow-Origin|cors).*['"]\*['"]/gi;

      let match;
      while ((match = wildcardPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'NET005',
          ruleName: 'CORS Wildcard Configuration',
          severity: 'medium',
          category: 'network',
          message: 'Wildcard (*) CORS configuration detected',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Specify explicit allowed origins instead of using wildcards.',
          references: ['https://capacitor-sec.dev/docs/rules/cors']
        });
      }

      return findings;
    },
    remediation: 'Use specific domain allowlists instead of wildcard CORS.'
  },
  {
    id: 'NET006',
    name: 'Insecure Deep Link Validation',
    description: 'Detects deep link handlers without proper validation',
    severity: 'high',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for App.addListener for appUrlOpen without validation
      const deepLinkPattern = /App\.addListener\s*\(\s*['"]appUrlOpen['"]/g;
      const hasValidation = /(?:validate|verify|check|sanitize|parse).*url/i;

      let match;
      while ((match = deepLinkPattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 500));
        if (!hasValidation.test(context)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'NET006',
            ruleName: 'Insecure Deep Link Validation',
            severity: 'high',
            category: 'network',
            message: 'Deep link handler without URL validation detected',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Validate and sanitize all incoming deep link URLs before processing.',
            references: [
              'https://capacitorjs.com/docs/apis/app#addlistenerappurlopen-',
              'https://capacitor-sec.dev/docs/rules/deeplinks'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Always validate deep link URLs against an allowlist of expected schemes and hosts.'
  },
  {
    id: 'NET007',
    name: 'Capacitor HTTP Plugin Misuse',
    description: 'Detects potential security issues with Capacitor HTTP plugin usage',
    severity: 'medium',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for CapacitorHttp without timeout
      const httpPattern = /CapacitorHttp\.(?:get|post|put|delete|patch)\s*\(\s*\{/g;
      const hasTimeout = /timeout\s*:/;

      let match;
      while ((match = httpPattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 300));
        if (!hasTimeout.test(context)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'NET007',
            ruleName: 'Capacitor HTTP Plugin Misuse',
            severity: 'low',
            category: 'network',
            message: 'HTTP request without timeout configuration',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Set appropriate timeout values for HTTP requests to prevent hanging connections.',
            references: ['https://capacitorjs.com/docs/apis/http']
          });
        }
      }

      return findings;
    },
    remediation: 'Configure appropriate timeouts and error handling for HTTP requests.'
  },
  {
    id: 'NET008',
    name: 'Sensitive Data in URL Parameters',
    description: 'Detects sensitive data passed in URL query parameters',
    severity: 'high',
    category: 'network',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for sensitive params in URLs
      const sensitiveParamPattern = /['"`][^'"`]*\?[^'"`]*(?:password|token|secret|key|auth|apikey|api_key)=[^'"`]*['"`]/gi;

      let match;
      while ((match = sensitiveParamPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'NET008',
          ruleName: 'Sensitive Data in URL Parameters',
          severity: 'high',
          category: 'network',
          message: 'Sensitive data found in URL query parameters',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim().substring(0, 80),
          remediation: 'Pass sensitive data in request headers or body, not in URL parameters.',
          references: ['https://capacitor-sec.dev/docs/rules/url-params']
        });
      }

      return findings;
    },
    remediation: 'Use request headers or body for sensitive data transmission.'
  }
];
