import type { Rule, Finding } from '../types.js';

export const cryptographyRules: Rule[] = [
  {
    id: 'CRY001',
    name: 'Weak Cryptographic Algorithm',
    description: 'Detects usage of weak or deprecated cryptographic algorithms',
    severity: 'high',
    category: 'cryptography',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const weakAlgorithms = [
        { pattern: /md5|['"]MD5['"]/gi, name: 'MD5', message: 'MD5 is cryptographically broken' },
        { pattern: /sha1|['"]SHA-?1['"]/gi, name: 'SHA-1', message: 'SHA-1 is deprecated and vulnerable to collision attacks' },
        { pattern: /des|['"]DES['"]/gi, name: 'DES', message: 'DES uses 56-bit keys, too weak for modern security' },
        { pattern: /rc4|['"]RC4['"]/gi, name: 'RC4', message: 'RC4 has known biases and should not be used' },
        { pattern: /blowfish/gi, name: 'Blowfish', message: 'Blowfish has a small block size, prefer AES' },
        { pattern: /(?:3des|triple\s*des|tripledes|des-ede3|DESede)/gi, name: '3DES', message: '3DES is deprecated; use AES-256-GCM' },
        { pattern: /ECB/g, name: 'ECB mode', message: 'ECB mode does not hide data patterns' },
        { pattern: /RSA(?:ES)?[_-]?PKCS1(?:_?v1_?5)?|PKCS1Padding/gi, name: 'RSA PKCS#1 v1.5', message: 'Prefer RSA-OAEP; PKCS#1 v1.5 encryption is obsolete' }
      ];

      for (const { pattern, name, message } of weakAlgorithms) {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(content)) !== null) {
          // Skip if it's in a comment
          const lineStart = content.lastIndexOf('\n', match.index) + 1;
          const lineContent = content.substring(lineStart, match.index);
          if (/\/\/|\/\*|\*/.test(lineContent)) continue;

          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CRY001',
            ruleName: 'Weak Cryptographic Algorithm',
            severity: 'high',
            category: 'cryptography',
            message: `${name}: ${message}`,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use AES-256-GCM for encryption, SHA-256 or SHA-3 for hashing, and Argon2 for password hashing.',
            references: [
              'https://capacitor-sec.dev/docs/rules/weak-crypto',
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography',
              'https://mas.owasp.org/MASVS/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Use modern algorithms: AES-256-GCM, SHA-256/SHA-3, Argon2.'
  },
  {
    id: 'CRY002',
    name: 'Hardcoded Encryption Key',
    description: 'Detects hardcoded encryption keys or IVs in source code',
    severity: 'critical',
    category: 'cryptography',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test files
      if (filePath.includes('.test.') || filePath.includes('.spec.')) {
        return findings;
      }

      const keyPatterns = [
        /(?:encrypt(?:ion)?Key|aesKey|secretKey|privateKey)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi,
        /(?:iv|initVector|initialVector)\s*[:=]\s*['"][A-Za-z0-9+/=]{12,}['"]/gi,
        /Buffer\.from\s*\(\s*['"][A-Fa-f0-9]{32,}['"]/g
      ];

      for (const pattern of keyPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CRY002',
            ruleName: 'Hardcoded Encryption Key',
            severity: 'critical',
            category: 'cryptography',
            message: 'Hardcoded encryption key or IV detected',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim().replace(/['"][A-Za-z0-9+/=]{8,}['"]/g, '"***KEY***"'),
            remediation: 'Generate keys securely at runtime. Store keys in secure storage (Keychain/Keystore).',
            references: ['https://capacitor-sec.dev/docs/rules/hardcoded-keys']
          });
        }
      }

      return findings;
    },
    remediation: 'Never hardcode encryption keys. Use secure key derivation and storage.'
  },
  {
    id: 'CRY003',
    name: 'Insecure Random IV Generation',
    description: 'Detects non-random or predictable IV generation',
    severity: 'high',
    category: 'cryptography',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for static or predictable IVs
      const staticIvPatterns = [
        { pattern: /iv\s*[:=]\s*(?:new\s+Uint8Array\s*\(\s*\d+\s*\)|Buffer\.alloc\s*\()/, message: 'IV initialized with zeros - must be random' },
        { pattern: /iv\s*[:=]\s*['"][0-9a-fA-F]+['"]/, message: 'Static IV detected - IV must be unique per encryption' }
      ];

      for (const { pattern, message } of staticIvPatterns) {
        let match;
        const regex = new RegExp(pattern.source, 'gi');
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'CRY003',
            ruleName: 'Insecure Random IV Generation',
            severity: 'high',
            category: 'cryptography',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use crypto.getRandomValues() to generate a unique IV for each encryption operation.',
            references: ['https://capacitor-sec.dev/docs/rules/iv-generation']
          });
        }
      }

      return findings;
    },
    remediation: 'Generate unique random IVs using crypto.getRandomValues().'
  },
  {
    id: 'CRY004',
    name: 'Weak Password Hashing',
    description: 'Detects weak password hashing schemes',
    severity: 'critical',
    category: 'cryptography',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for password with weak hashing
      const passwordContext = /password/i.test(content);

      if (passwordContext) {
        const weakPatterns = [
          { pattern: /(?:sha256|sha512|createHash).*password/gi, message: 'Using raw SHA for password hashing - use bcrypt/argon2' },
          { pattern: /password.*(?:sha256|sha512|createHash)/gi, message: 'Using raw SHA for password hashing - use bcrypt/argon2' },
          { pattern: /md5.*password|password.*md5/gi, message: 'MD5 is completely unsuitable for password hashing' }
        ];

        for (const { pattern, message } of weakPatterns) {
          let match;
          while ((match = pattern.exec(content)) !== null) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            findings.push({
              ruleId: 'CRY004',
              ruleName: 'Weak Password Hashing',
              severity: 'critical',
              category: 'cryptography',
              message,
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Use Argon2, bcrypt, or scrypt for password hashing with appropriate work factors.',
              references: [
                'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
                'https://capacitor-sec.dev/docs/rules/password-hashing'
              ]
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Use Argon2id, bcrypt, or scrypt for password hashing.'
  }
];
