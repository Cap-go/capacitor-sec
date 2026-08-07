import type { Rule, Finding } from '../types.js';

// API Key and Secret patterns - 30+ patterns
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: 'critical' | 'high' | 'medium' }> = [
  // AWS
  { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Access Key', pattern: /(?:aws)?_?(?:secret)?_?(?:access)?_?key['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, severity: 'critical' },

  // Google
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { name: 'Google OAuth Client ID', pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, severity: 'high' },
  { name: 'Firebase API Key', pattern: /(?:firebase|fcm).*['"][A-Za-z0-9_-]{20,}['"]/gi, severity: 'high' },

  // Stripe
  { name: 'Stripe Live Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'Stripe Test Secret Key', pattern: /sk_test_[0-9a-zA-Z]{24,}/g, severity: 'medium' },
  { name: 'Stripe Publishable Key', pattern: /pk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: 'high' },
  { name: 'Stripe Restricted Key', pattern: /rk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: 'critical' },

  // OpenAI / Anthropic / Hugging Face
  { name: 'OpenAI API Key', pattern: /\bsk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b/g, severity: 'critical' },
  { name: 'Anthropic API Key', pattern: /\bsk-ant-api03-[a-zA-Z0-9_-]{93}AA\b/g, severity: 'critical' },
  { name: 'Anthropic Admin API Key', pattern: /\bsk-ant-admin01-[a-zA-Z0-9_-]{93}AA\b/g, severity: 'critical' },
  { name: 'Hugging Face Token', pattern: /\bhf_[A-Za-z0-9]{34,}\b/g, severity: 'critical' },

  // GitHub/GitLab
  { name: 'GitHub Token', pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'GitHub Fine-grained PAT', pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g, severity: 'critical' },
  { name: 'GitHub OAuth', pattern: /github.*['"][0-9a-zA-Z]{35,40}['"]/gi, severity: 'critical' },
  { name: 'GitLab Token', pattern: /glpat-[A-Za-z0-9_-]{20,}/g, severity: 'critical' },

  // Slack / Discord
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: 'critical' },
  { name: 'Slack Webhook', pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g, severity: 'high' },
  { name: 'Discord Bot Token', pattern: /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{25,}\b/g, severity: 'critical' },

  // Twilio
  { name: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/g, severity: 'high' },
  { name: 'Twilio Account SID', pattern: /AC[0-9a-fA-F]{32}/g, severity: 'high' },

  // SendGrid / Mailgun
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: 'critical' },
  { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'high' },

  // DigitalOcean / Heroku / NPM
  { name: 'DigitalOcean Token', pattern: /dop_v1_[a-f0-9]{64}/g, severity: 'critical' },
  { name: 'DigitalOcean OAuth', pattern: /doo_v1_[a-f0-9]{64}/g, severity: 'critical' },
  { name: 'Heroku API Key', pattern: /heroku.*['"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]/gi, severity: 'critical' },
  { name: 'NPM Token', pattern: /npm_[A-Za-z0-9]{36}/g, severity: 'critical' },

  // Cloudflare / Postman / Linear
  { name: 'Cloudflare API Token', pattern: /(?:cloudflare|cf)[_-]?(?:api)?[_-]?(?:token|key)['"]?\s*[:=]\s*['"][A-Za-z0-9_-]{37,}['"]/gi, severity: 'critical' },
  { name: 'Postman API Key', pattern: /PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}/g, severity: 'critical' },
  { name: 'Linear API Key', pattern: /lin_api_[A-Za-z0-9]{40,}/g, severity: 'critical' },

  // Supabase JWT-shaped keys (service role often shipped as JWT)
  { name: 'Supabase Service Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'high' },

  // Private Keys
  { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'PKCS8 Private Key', pattern: /-----BEGIN PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'SSH Private Key', pattern: /-----BEGIN (?:DSA|EC|OPENSSH) PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: 'critical' },

  // Generic patterns
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret)['"]?\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]/gi, severity: 'high' },
  { name: 'Generic Secret', pattern: /(?:secret|password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'high' },
  { name: 'Generic Token', pattern: /(?:access[_-]?token|auth[_-]?token|bearer)['"]?\s*[:=]\s*['"][A-Za-z0-9_.-]{20,}['"]/gi, severity: 'high' },

  // Database URLs
  { name: 'Database URL with Credentials', pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s/'"]+/gi, severity: 'critical' },
];

export const secretsRules: Rule[] = [
  {
    id: 'SEC001',
    name: 'Hardcoded API Keys & Secrets',
    description: 'Detects hardcoded API keys, tokens, and secrets in source code (AWS, Stripe, OpenAI, Anthropic, GitHub, Discord, and more)',
    severity: 'critical',
    category: 'secrets',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/*.json', '**/*.env*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip node_modules and common false positives
      if (filePath.includes('node_modules') || filePath.includes('.lock')) {
        return findings;
      }

      for (const secretPattern of SECRET_PATTERNS) {
        let match;
        const pattern = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags);

        while ((match = pattern.exec(content)) !== null) {
          // Find line number
          let lineNum = 1;
          let charCount = 0;
          for (let i = 0; i < lines.length; i++) {
            charCount += lines[i].length + 1;
            if (charCount > match.index) {
              lineNum = i + 1;
              break;
            }
          }

          // Mask the secret for display
          const maskedValue = match[0].substring(0, 10) + '***REDACTED***';

          findings.push({
            ruleId: 'SEC001',
            ruleName: 'Hardcoded API Keys & Secrets',
            severity: secretPattern.severity,
            category: 'secrets',
            message: `Found ${secretPattern.name}: ${maskedValue}`,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim().substring(0, 100),
            remediation: 'Move secrets to a secure secrets manager or server-side. Never embed secrets in Capacitor app code (see Capacitor Security guide).',
            references: [
              'https://capacitor-sec.dev/docs/rules/secrets',
              'https://owasp.org/www-project-mobile-top-10/',
              'https://mas.owasp.org/MASVS/'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Use environment variables or a secure secrets manager. Consider using @capgo/capacitor-social-login for OAuth flows.',
    references: ['https://owasp.org/www-project-mobile-top-10/',
              'https://mas.owasp.org/MASVS/']
  },
  {
    id: 'SEC002',
    name: 'Exposed .env File',
    description: 'Detects .env files that may contain sensitive configuration',
    severity: 'critical',
    category: 'secrets',
    filePatterns: ['**/.env', '**/.env.*', '!**/.env.example', '!**/.env.template'],
    check: (content: string, filePath: string): Finding[] => {
      if (filePath.includes('.example') || filePath.includes('.template')) {
        return [];
      }

      const findings: Finding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        if (line.trim() && !line.startsWith('#') && line.includes('=')) {
          const [key] = line.split('=');
          if (key && /(?:key|secret|password|token|auth|credential)/i.test(key)) {
            findings.push({
              ruleId: 'SEC002',
              ruleName: 'Exposed .env File',
              severity: 'critical',
              category: 'secrets',
              message: `Sensitive variable "${key.trim()}" found in .env file`,
              filePath,
              line: index + 1,
              codeSnippet: `${key.trim()}=***REDACTED***`,
              remediation: 'Ensure .env files are in .gitignore and never committed to version control.',
              references: ['https://capacitor-sec.dev/docs/rules/env-files']
            });
          }
        }
      });

      return findings;
    },
    remediation: 'Add .env files to .gitignore. Use .env.example for documentation with placeholder values.'
  }
];
