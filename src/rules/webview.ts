import type { Rule, Finding } from '../types.js';

export const webviewRules: Rule[] = [
  {
    id: 'WEB001',
    name: 'WebView JavaScript Injection',
    description: 'Detects potential JavaScript injection vulnerabilities in WebView',
    severity: 'critical',
    category: 'webview',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/*.html'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for innerHTML with user input
      const dangerousPatterns = [
        { pattern: /innerHTML\s*=\s*(?!['"`]<)/, message: 'innerHTML assignment with potential user input' },
        { pattern: /document\.write\s*\(/, message: 'document.write can inject arbitrary content' },
        { pattern: /outerHTML\s*=\s*(?!['"`]<)/, message: 'outerHTML assignment with potential user input' },
        { pattern: /insertAdjacentHTML\s*\(/, message: 'insertAdjacentHTML can inject HTML/scripts' }
      ];

      for (const { pattern, message } of dangerousPatterns) {
        let match;
        const regex = new RegExp(pattern.source, 'gi');
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB001',
            ruleName: 'WebView JavaScript Injection',
            severity: 'high',
            category: 'webview',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use textContent for text or create elements with DOM APIs. Sanitize any HTML input.',
            references: [
              'https://owasp.org/www-community/attacks/xss/',
              'https://capacitor-sec.dev/docs/rules/xss'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Use textContent or sanitize HTML input before insertion.'
  },
  {
    id: 'WEB002',
    name: 'Unsafe iframe Configuration',
    description: 'Detects iframes without proper sandboxing',
    severity: 'high',
    category: 'webview',
    filePatterns: ['**/*.html', '**/*.tsx', '**/*.jsx', '**/*.vue'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for iframes without sandbox
      const iframePattern = /<iframe[^>]*>/gi;

      let match;
      while ((match = iframePattern.exec(content)) !== null) {
        const iframeTag = match[0];
        const hasSandbox = /sandbox\s*=/.test(iframeTag);
        const hasAllowScripts = /allow-scripts/.test(iframeTag);
        const hasAllowSameOrigin = /allow-same-origin/.test(iframeTag);

        if (!hasSandbox) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB002',
            ruleName: 'Unsafe iframe Configuration',
            severity: 'high',
            category: 'webview',
            message: 'iframe without sandbox attribute',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Add sandbox attribute to iframe with minimal required permissions.',
            references: ['https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox']
          });
        } else if (hasAllowScripts && hasAllowSameOrigin) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB002',
            ruleName: 'Unsafe iframe Configuration',
            severity: 'medium',
            category: 'webview',
            message: 'iframe with allow-scripts and allow-same-origin is nearly equivalent to no sandbox',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Avoid combining allow-scripts with allow-same-origin if possible.',
            references: ['https://capacitor-sec.dev/docs/rules/iframe']
          });
        }
      }

      return findings;
    },
    remediation: 'Use sandbox attribute with minimal permissions on iframes.'
  },
  {
    id: 'WEB003',
    name: 'External Script Loading',
    description: 'Detects loading of scripts from external sources without integrity',
    severity: 'medium',
    category: 'webview',
    filePatterns: ['**/*.html', '**/index.html'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for external scripts without integrity
      const scriptPattern = /<script[^>]*src\s*=\s*['"]https?:\/\/[^'"]+['"][^>]*>/gi;

      let match;
      while ((match = scriptPattern.exec(content)) !== null) {
        const scriptTag = match[0];
        const hasIntegrity = /integrity\s*=/.test(scriptTag);
        const hasCrossorigin = /crossorigin/.test(scriptTag);

        if (!hasIntegrity) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB003',
            ruleName: 'External Script Loading',
            severity: 'medium',
            category: 'webview',
            message: 'External script loaded without Subresource Integrity (SRI)',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Add integrity and crossorigin attributes to external scripts.',
            references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity']
          });
        }
      }

      return findings;
    },
    remediation: 'Add SRI (integrity) attribute to external script tags.'
  },
  {
    id: 'WEB004',
    name: 'Content Security Policy Missing',
    description: 'Detects missing or weak Content Security Policy',
    severity: 'medium',
    category: 'webview',
    filePatterns: ['**/index.html', '**/capacitor.config.*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      if (filePath.includes('index.html')) {
        const hasCSP = /<meta[^>]*http-equiv\s*=\s*['"]Content-Security-Policy['"][^>]*>/i.test(content);
        const hasUnsafeInline = /unsafe-inline|unsafe-eval/i.test(content);

        if (!hasCSP) {
          findings.push({
            ruleId: 'WEB004',
            ruleName: 'Content Security Policy Missing',
            severity: 'medium',
            category: 'webview',
            message: 'No Content Security Policy meta tag found',
            filePath,
            line: 1,
            remediation: 'Add a Content Security Policy meta tag to restrict resource loading.',
            references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', 'https://capacitorjs.com/docs/guides/security/']
          });
        } else if (hasUnsafeInline) {
          findings.push({
            ruleId: 'WEB004',
            ruleName: 'Content Security Policy Missing',
            severity: 'medium',
            category: 'webview',
            message: 'CSP contains unsafe-inline or unsafe-eval which weakens protection',
            filePath,
            line: 1,
            remediation: 'Remove unsafe-inline and unsafe-eval. Use nonces or hashes for inline scripts.',
            references: ['https://capacitor-sec.dev/docs/rules/csp']
          });
        }
      }

      return findings;
    },
    remediation: 'Implement a strict Content Security Policy.'
  },
  {
    id: 'WEB005',
    name: 'Target _blank Without noopener',
    description: 'Detects links with target="_blank" missing rel="noopener"',
    severity: 'low',
    category: 'webview',
    filePatterns: ['**/*.html', '**/*.tsx', '**/*.jsx', '**/*.vue'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for target="_blank" without noopener
      const linkPattern = /<a[^>]*target\s*=\s*['"]_blank['"][^>]*>/gi;

      let match;
      while ((match = linkPattern.exec(content)) !== null) {
        const linkTag = match[0];
        const hasNoopener = /rel\s*=\s*['"][^'"]*noopener[^'"]*['"]/.test(linkTag);

        if (!hasNoopener) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB005',
            ruleName: 'Target _blank Without noopener',
            severity: 'low',
            category: 'webview',
            message: 'Link with target="_blank" missing rel="noopener" (Tabnabbing vulnerability)',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Add rel="noopener noreferrer" to links with target="_blank".',
            references: ['https://owasp.org/www-community/attacks/Reverse_Tabnabbing']
          });
        }
      }

      return findings;
    },
    remediation: 'Add rel="noopener noreferrer" to external links.'
  },
  {
    id: 'WEB006',
    name: 'Dynamic WebView Script or HTML Injection',
    description: 'Detects evaluateJavaScript / loadHTMLString / loadData with dynamic or concatenated content',
    severity: 'high',
    category: 'webview',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/*.java', '**/*.kt', '**/*.swift', '**/*.m'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const patterns = [
        {
          pattern: /evaluateJavaScript\s*\(\s*(?!['"`])/g,
          message: 'evaluateJavaScript called with non-literal script — treat as untrusted input'
        },
        {
          pattern: /loadHTMLString\s*\(/g,
          message: 'loadHTMLString can execute injected HTML/JS if content is not fully trusted'
        },
        {
          pattern: /loadData(?:WithBaseURL)?\s*\(/g,
          message: 'loadData/loadDataWithBaseURL can execute injected HTML if content is attacker-controlled'
        },
        {
          pattern: /\$\{[^}]+\}.*(?:evaluateJavaScript|loadHTMLString)|(?:evaluateJavaScript|loadHTMLString).*\$\{/g,
          message: 'Template string used to build WebView script/HTML — injection risk'
        }
      ];

      for (const { pattern, message } of patterns) {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'WEB006',
            ruleName: 'Dynamic WebView Script or HTML Injection',
            severity: 'high',
            category: 'webview',
            message,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation:
              'Never pass attacker-controlled data into evaluateJavaScript or loadHTMLString. Validate URLs against an allowlist; prefer safe DOM APIs and strict CSP.',
            references: [
              'https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0034/',
              'https://capacitorjs.com/docs/guides/security/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Validate and escape all data before injecting into WebView HTML or JavaScript.'
  }
];
