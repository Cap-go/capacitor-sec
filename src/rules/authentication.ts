import type { Rule, Finding } from '../types.js';

export const authenticationRules: Rule[] = [
  {
    id: 'AUTH001',
    name: 'Weak JWT Validation',
    description: 'Detects JWT handling without proper validation',
    severity: 'high',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for JWT decode without verify
      const jwtDecodePattern = /jwt\.decode\s*\(|jwtDecode\s*\(|atob\s*\([^)]*\.split\s*\(['"]\.['"]|JSON\.parse.*base64/gi;

      let match;
      while ((match = jwtDecodePattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 300));
        const hasVerify = /verify|validate|check.*signature/i.test(context);

        if (!hasVerify) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AUTH001',
            ruleName: 'Weak JWT Validation',
            severity: 'high',
            category: 'authentication',
            message: 'JWT decoded without signature verification',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Always verify JWT signature before trusting claims. Use jwt.verify() instead of jwt.decode().',
            references: [
              'https://capacitor-sec.dev/docs/rules/jwt',
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Verify JWT signature on the backend. Never trust client-side JWT validation alone.'
  },
  {
    id: 'AUTH002',
    name: 'Insecure Biometric Implementation',
    description: 'Detects weak biometric authentication implementation',
    severity: 'high',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for biometric without proper cryptographic backing
      const biometricPattern = /(?:NativeBiometric|BiometricAuth|FingerprintAIO)\.(?:verifyIdentity|authenticate)/gi;

      let match;
      while ((match = biometricPattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 500));

        // Check for cryptographic operations after biometric
        const hasCryptoOp = /getCredentials|decrypt|sign|keychain|keystore/i.test(context);

        if (!hasCryptoOp) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AUTH002',
            ruleName: 'Insecure Biometric Implementation',
            severity: 'high',
            category: 'authentication',
            message: 'Biometric auth not backed by cryptographic operation',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Back biometric authentication with cryptographic keys stored in secure enclave.',
            references: ['https://capacitor-sec.dev/docs/rules/biometric']
          });
        }
      }

      return findings;
    },
    remediation: 'Use cryptographically-backed biometric authentication.'
  },
  {
    id: 'AUTH003',
    name: 'Weak Random Number Generation',
    description: 'Detects use of Math.random() for security-sensitive operations',
    severity: 'high',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test files
      if (filePath.includes('.test.') || filePath.includes('.spec.')) {
        return findings;
      }

      // Check for Math.random in security context
      const randomPattern = /Math\.random\s*\(\)/g;

      let match;
      while ((match = randomPattern.exec(content)) !== null) {
        const context = content.substring(Math.max(0, match.index - 200), match.index + 200);
        const securityContext = /(?:token|key|secret|nonce|salt|iv|session|auth|password|otp|code)/i.test(context);

        if (securityContext) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AUTH003',
            ruleName: 'Weak Random Number Generation',
            severity: 'high',
            category: 'authentication',
            message: 'Math.random() used in security context - not cryptographically secure',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive operations.',
            references: ['https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues']
          });
        }
      }

      return findings;
    },
    remediation: 'Use crypto.getRandomValues() for secure random number generation.'
  },
  {
    id: 'AUTH004',
    name: 'Missing Session Timeout',
    description: 'Detects authentication without session timeout handling',
    severity: 'medium',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      // Only check auth-related files
      if (!/auth|login|session/i.test(filePath) && !/auth|login|session/i.test(content)) {
        return findings;
      }

      const hasLogin = /(?:login|signIn|authenticate)\s*\(/i.test(content);
      const hasTimeout = /(?:timeout|expire|ttl|maxAge|expiresIn|expiresAt)/i.test(content);

      if (hasLogin && !hasTimeout) {
        findings.push({
          ruleId: 'AUTH004',
          ruleName: 'Missing Session Timeout',
          severity: 'medium',
          category: 'authentication',
          message: 'Authentication flow without apparent session timeout',
          filePath,
          line: 1,
          remediation: 'Implement session timeouts with automatic logout for inactive sessions.',
          references: ['https://capacitor-sec.dev/docs/rules/session-timeout']
        });
      }

      return findings;
    },
    remediation: 'Implement session timeout and automatic logout.'
  },
  {
    id: 'AUTH005',
    name: 'OAuth State Parameter Missing',
    description: 'Detects OAuth flows without state parameter for CSRF protection',
    severity: 'high',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for OAuth URLs without state parameter
      const oauthPattern = /(?:authorize|oauth|auth).*(?:client_id|response_type)/gi;

      let match;
      while ((match = oauthPattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 300));
        const hasState = /state\s*[:=]/.test(context);

        if (!hasState) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AUTH005',
            ruleName: 'OAuth State Parameter Missing',
            severity: 'high',
            category: 'authentication',
            message: 'OAuth flow without state parameter for CSRF protection',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Always include a unique state parameter in OAuth flows and validate it on callback.',
            references: ['https://datatracker.ietf.org/doc/html/rfc6749#section-10.12', 'https://capacitorjs.com/docs/guides/security/']
          });
        }
      }

      return findings;
    },
    remediation: 'Add state parameter to OAuth flows for CSRF protection.'
  },
  {
    id: 'AUTH006',
    name: 'Hardcoded Credentials in Auth',
    description: 'Detects hardcoded credentials in authentication code',
    severity: 'critical',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test files
      if (filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__mocks__')) {
        return findings;
      }

      // Check for hardcoded auth credentials
      const patterns = [
        /password\s*[:=]\s*['"][^'"]{4,}['"]/gi,
        /username\s*[:=]\s*['"][^'"@]+['"]/gi,
        /clientSecret\s*[:=]\s*['"][^'"]{8,}['"]/gi
      ];

      for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          // Skip obvious examples/placeholders
          if (/example|placeholder|your|xxx|changeme/i.test(match[0])) {
            continue;
          }

          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'AUTH006',
            ruleName: 'Hardcoded Credentials in Auth',
            severity: 'critical',
            category: 'authentication',
            message: 'Hardcoded credentials detected in authentication code',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim().replace(/['"][^'"]+['"]/g, '"***REDACTED***"'),
            remediation: 'Remove hardcoded credentials. Use secure configuration or environment variables.',
            references: ['https://capacitor-sec.dev/docs/rules/hardcoded-creds']
          });
        }
      }

      return findings;
    },
    remediation: 'Remove hardcoded credentials and use secure configuration.'
  },
  {
    id: 'AUTH007',
    name: 'OAuth PKCE Missing',
    description: 'Detects OAuth2 / OpenID Connect flows without PKCE (required for Capacitor/native apps)',
    severity: 'critical',
    category: 'authentication',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const oauthFlow =
        /(?:response_type\s*[:=]\s*['"]code['"]|authorization[_-]?code|oauth2?|OpenID|oidc|Auth\.authorize|signInWithOAuth)/i.test(
          content
        ) || /(?:authorize\?|\/oauth\/|\/authorize)/i.test(content);

      if (!oauthFlow) {
        return findings;
      }

      const hasPkce = /(?:code_challenge|code_verifier|codeChallenge|codeVerifier|pkce|PKCE)/i.test(
        content
      );

      if (!hasPkce) {
        const anchor =
          content.match(/response_type\s*[:=]\s*['"]code['"]/i) ||
          content.match(/signInWithOAuth|Auth\.authorize|authorization[_-]?code/i) ||
          content.match(/oauth2?/i);
        const index = anchor?.index ?? 0;
        const lineNum = content.substring(0, index).split('\n').length;
        findings.push({
          ruleId: 'AUTH007',
          ruleName: 'OAuth PKCE Missing',
          severity: 'critical',
          category: 'authentication',
          message:
            'OAuth2 authorization-code flow without PKCE — required for Capacitor apps to prevent token interception via custom URL schemes',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation:
            'Use PKCE (code_verifier + code_challenge) for all OAuth2 authorization-code flows. Prefer Universal Links / App Links over custom schemes.',
          references: [
            'https://capacitorjs.com/docs/guides/security/',
            'https://datatracker.ietf.org/doc/html/rfc7636',
            'https://datatracker.ietf.org/doc/html/rfc8252'
          ]
        });
      }

      return findings;
    },
    remediation: 'Enable PKCE on every OAuth2 authorization-code flow used by the mobile app.'
  }
];
