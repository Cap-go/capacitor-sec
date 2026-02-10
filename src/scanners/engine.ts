import fg from 'fast-glob';
import path from 'node:path';
import { parse } from '@babel/parser';
import { allRules, ruleCount } from '../rules/index.js';
import type { Rule, Finding, ScanResult, ScanOptions, RuleCategory, Severity, CapacitorConfig } from '../types.js';
import type * as t from '@babel/types';

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
  '**/vendor/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/android/app/build/**',
  '**/ios/Pods/**',
  '**/ios/build/**'
];

export class SecurityScanner {
  private rules: Rule[];
  private options: ScanOptions;

  constructor(options: ScanOptions) {
    this.options = options;
    this.rules = this.filterRules(allRules);
  }

  private filterRules(rules: Rule[]): Rule[] {
    let filtered = rules;

    // Filter by severity
    if (this.options.severity) {
      const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      const minIndex = severityOrder.indexOf(this.options.severity);
      filtered = filtered.filter(rule => {
        const ruleIndex = severityOrder.indexOf(rule.severity);
        return ruleIndex <= minIndex;
      });
    }

    // Filter by category
    if (this.options.categories && this.options.categories.length > 0) {
      filtered = filtered.filter(rule => this.options.categories!.includes(rule.category));
    }

    return filtered;
  }

  async scan(): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    const configDetails = await this.getCapacitorConfigDetails();

    // Get all files to scan (include native projects referenced from capacitor.config)
    const files = await this.getFiles(configDetails);
    const scanContext = this.buildScanContext(files, configDetails);

    // Process each file
    for (const file of files) {
      const fileFindings = await this.scanFile(file);
      findings.push(...fileFindings);
    }

    const duration = Date.now() - startTime;

    return {
      projectPath: this.options.path,
      timestamp: new Date().toISOString(),
      duration,
      filesScanned: files.length,
      scanContext,
      findings: this.sortFindings(findings),
      summary: this.generateSummary(findings)
    };
  }

  private buildScanContext(
    files: string[],
    configDetails: {
      configFiles: string[];
      configUsed?: string;
      platformPaths?: {
        android?: { configured?: string; resolved?: string };
        ios?: { configured?: string; resolved?: string };
      };
    }
  ) {
    const norm = (p: string) => p.replace(/\\/g, '/');
    const normalized = files.map(norm);

    const capacitorConfigFiles = configDetails.configFiles.map(norm);
    const androidManifestFiles = normalized.filter(p =>
      /\/AndroidManifest\.xml$/i.test(p)
    );
    const androidNetworkSecurityConfigFiles = normalized.filter(p =>
      /\/network_security_config\.xml$/i.test(p)
    );
    const iosInfoPlistFiles = normalized.filter(p =>
      /\/Info\.plist$/i.test(p)
    );

    return {
      capacitorConfigFiles,
      capacitorConfigUsed: configDetails.configUsed ? norm(configDetails.configUsed) : undefined,
      platformPaths: configDetails.platformPaths,
      androidManifestFiles,
      androidNetworkSecurityConfigFiles,
      iosInfoPlistFiles
    };
  }

  private async getFiles(configDetails: {
    platformPaths?: {
      android?: { configured?: string; resolved?: string };
      ios?: { configured?: string; resolved?: string };
    };
  }): Promise<string[]> {
    const excludePatterns = [...DEFAULT_EXCLUDE, ...(this.options.exclude || [])];

    // Collect all unique file patterns from rules
    const patterns = new Set<string>();
    for (const rule of this.rules) {
      if (rule.filePatterns) {
        rule.filePatterns.forEach(p => patterns.add(p));
      }
    }

    // If no patterns, use common source files
    if (patterns.size === 0) {
      patterns.add('**/*.ts');
      patterns.add('**/*.tsx');
      patterns.add('**/*.js');
      patterns.add('**/*.jsx');
      patterns.add('**/*.json');
      patterns.add('**/*.html');
      patterns.add('**/AndroidManifest.xml');
      patterns.add('**/Info.plist');
    }

    // If capacitor.config specifies custom native project locations, prefer scanning those.
    // This matters for monorepos where native projects live outside the scanned folder.
    const androidConfigured = configDetails.platformPaths?.android?.configured;
    const iosConfigured = configDetails.platformPaths?.ios?.configured;

    if (androidConfigured) {
      for (const p of Array.from(patterns)) {
        if (/AndroidManifest\.xml$/i.test(p) || /network_security_config\.xml$/i.test(p)) patterns.delete(p);
      }
      patterns.add(`${this.normalizeGlobPrefix(androidConfigured)}/**/AndroidManifest.xml`);
      patterns.add(`${this.normalizeGlobPrefix(androidConfigured)}/**/network_security_config.xml`);
    }

    if (iosConfigured) {
      for (const p of Array.from(patterns)) {
        if (/Info\.plist$/i.test(p)) patterns.delete(p);
      }
      patterns.add(`${this.normalizeGlobPrefix(iosConfigured)}/**/Info.plist`);
    }

    const files = await fg(Array.from(patterns), {
      cwd: this.options.path,
      ignore: excludePatterns,
      absolute: true,
      onlyFiles: true
    });

    return files;
  }

  private async scanFile(filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const content = await Bun.file(filePath).text();
      const relPath = this.normalizePath(path.relative(this.options.path, filePath));
      const absPath = this.normalizePath(filePath);

      // Get rules that match this file
      const applicableRules = this.rules.filter(rule => {
        if (!rule.filePatterns) return true;
        return rule.filePatterns.some(pattern => {
          // Convert glob pattern to regex for matching
          // First escape dots, then handle glob patterns
          const regexPattern = pattern
            .replace(/\./g, '\\.')
            .replace(/\*\*/g, '.*')
            .replace(/(?<!\.)(\*)/g, '[^/]*');
          const rx = new RegExp(regexPattern);
          // Match against both relative and absolute paths.
          // Relative paths preserve leading ../ segments for monorepos, which is important when
          // filePatterns come from capacitor.config android.path / ios.path.
          return rx.test(relPath) || rx.test(absPath);
        });
      });

      // Apply each rule
      for (const rule of applicableRules) {
        if (rule.check) {
          const ruleFindings = rule.check(content, filePath);
          findings.push(...ruleFindings);
        } else if (rule.patterns) {
          // Simple pattern matching
          for (const pattern of rule.patterns) {
            let match;
            const regex = new RegExp(pattern.source, pattern.flags);
            const lines = content.split('\n');

            while ((match = regex.exec(content)) !== null) {
              const lineNum = content.substring(0, match.index).split('\n').length;
              findings.push({
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                category: rule.category,
                message: rule.description,
                filePath,
                line: lineNum,
                codeSnippet: lines[lineNum - 1]?.trim(),
                remediation: rule.remediation,
                references: rule.references
              });
            }
          }
        }
      }
    } catch (error) {
      if (this.options.verbose) {
        console.error(`Error scanning ${filePath}:`, error);
      }
    }

    return findings;
  }

  private normalizePath(p: string): string {
    return p.replace(/\\/g, '/');
  }

  private normalizeGlobPrefix(p: string): string {
    // fast-glob expects POSIX separators in patterns; keep ../ segments intact.
    return this.normalizePath(p).replace(/\/+$/, '');
  }

  private async getCapacitorConfigDetails(): Promise<{
    configFiles: string[];
    configUsed?: string;
    platformPaths?: {
      android?: { configured?: string; resolved?: string };
      ios?: { configured?: string; resolved?: string };
    };
  }> {
    const excludePatterns = [...DEFAULT_EXCLUDE, ...(this.options.exclude || [])];

    const configFiles = await fg(['**/capacitor.config.*'], {
      cwd: this.options.path,
      ignore: excludePatterns,
      absolute: true,
      onlyFiles: true
    });

    const configUsed = this.pickPreferredCapacitorConfig(configFiles);
    if (!configUsed) return { configFiles };

    const cfg = await this.parseCapacitorConfig(configUsed);
    const androidPath = typeof cfg?.android?.path === 'string' ? cfg.android.path : undefined;
    const iosPath = typeof cfg?.ios?.path === 'string' ? cfg.ios.path : undefined;

    const platformPaths = (androidPath || iosPath) ? {
      android: androidPath ? { configured: this.normalizeGlobPrefix(androidPath), resolved: path.resolve(this.options.path, androidPath) } : undefined,
      ios: iosPath ? { configured: this.normalizeGlobPrefix(iosPath), resolved: path.resolve(this.options.path, iosPath) } : undefined
    } : undefined;

    return { configFiles, configUsed, platformPaths };
  }

  private pickPreferredCapacitorConfig(files: string[]): string | undefined {
    if (!files || files.length === 0) return undefined;
    const byName = (name: string) => files.find(f => this.normalizePath(f).toLowerCase().endsWith(`/${name}`));
    return (
      byName('capacitor.config.ts') ??
      byName('capacitor.config.js') ??
      byName('capacitor.config.mjs') ??
      byName('capacitor.config.cjs') ??
      byName('capacitor.config.json') ??
      files[0]
    );
  }

  private async parseCapacitorConfig(filePath: string): Promise<CapacitorConfig | undefined> {
    try {
      const content = await Bun.file(filePath).text();
      const lower = filePath.toLowerCase();

      if (lower.endsWith('.json')) {
        return JSON.parse(content) as CapacitorConfig;
      }

      // For TS/JS configs, parse the module and extract the exported object literal when possible.
      const ast = parse(content, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx']
      }) as unknown as t.File;

      const env = this.collectTopLevelBindings(ast);
      const exported = this.findDefaultExport(ast);
      const value = this.evalConfigExpression(exported, env);

      return (value && typeof value === 'object') ? (value as CapacitorConfig) : undefined;
    } catch (e) {
      if (this.options.verbose) console.error(`Failed to parse capacitor config at ${filePath}:`, e);
      return undefined;
    }
  }

  private collectTopLevelBindings(ast: t.File): Record<string, t.Expression> {
    const env: Record<string, t.Expression> = {};
    for (const stmt of ast.program.body) {
      if (stmt.type !== 'VariableDeclaration') continue;
      for (const decl of stmt.declarations) {
        if (decl.id.type !== 'Identifier') continue;
        if (!decl.init) continue;
        // Only store expressions we can potentially evaluate later.
        if (decl.init.type.endsWith('Expression') || decl.init.type.endsWith('Literal') || decl.init.type === 'ObjectExpression' || decl.init.type === 'ArrayExpression' || decl.init.type === 'Identifier') {
          env[decl.id.name] = decl.init as t.Expression;
        }
      }
    }
    return env;
  }

  private findDefaultExport(ast: t.File): t.Expression | undefined {
    for (const stmt of ast.program.body) {
      if (stmt.type === 'ExportDefaultDeclaration') {
        const d = stmt.declaration;
        // Could be an expression or a declaration; we only handle expressions/calls/identifiers.
        if (d.type === 'Identifier') return d;
        if (d.type === 'ObjectExpression') return d;
        if (d.type === 'CallExpression') return d;
        if (d.type.endsWith('Expression')) return d as unknown as t.Expression;
      }
    }
    return undefined;
  }

  private evalConfigExpression(
    expr: t.Expression | undefined,
    env: Record<string, t.Expression>,
    depth = 0
  ): any {
    if (!expr) return undefined;
    if (depth > 5) return undefined;

    switch (expr.type) {
      case 'ObjectExpression': {
        const out: Record<string, any> = {};
        for (const prop of expr.properties) {
          if (prop.type !== 'ObjectProperty') continue;
          const key = this.objectKeyToString(prop.key);
          if (!key) continue;
          out[key] = this.evalConfigExpression(prop.value as t.Expression, env, depth + 1);
        }
        return out;
      }
      case 'ArrayExpression':
        return expr.elements.map(el => (el && el.type !== 'SpreadElement') ? this.evalConfigExpression(el as t.Expression, env, depth + 1) : undefined);
      case 'StringLiteral':
        return expr.value;
      case 'BooleanLiteral':
        return expr.value;
      case 'NumericLiteral':
        return expr.value;
      case 'NullLiteral':
        return null;
      case 'Identifier': {
        const bound = env[expr.name];
        if (!bound) return undefined;
        return this.evalConfigExpression(bound, env, depth + 1);
      }
      case 'CallExpression': {
        // Handle defineConfig({ ... }) and similar wrappers.
        const arg0 = expr.arguments[0];
        if (arg0 && arg0.type !== 'SpreadElement' && (arg0.type === 'ObjectExpression' || arg0.type === 'Identifier')) {
          return this.evalConfigExpression(arg0 as t.Expression, env, depth + 1);
        }
        return undefined;
      }
      default:
        return undefined;
    }
  }

  private objectKeyToString(key: t.ObjectProperty['key']): string | undefined {
    if (key.type === 'Identifier') return key.name;
    if (key.type === 'StringLiteral') return key.value;
    return undefined;
  }

  private sortFindings(findings: Finding[]): Finding[] {
    const severityOrder: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };

    return findings.sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      return a.filePath.localeCompare(b.filePath);
    });
  }

  private generateSummary(findings: Finding[]) {
    const byCategory: Record<RuleCategory, number> = {
      storage: 0,
      network: 0,
      authentication: 0,
      secrets: 0,
      cryptography: 0,
      logging: 0,
      capacitor: 0,
      debug: 0,
      android: 0,
      ios: 0,
      config: 0,
      webview: 0,
      permissions: 0
    };

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    for (const finding of findings) {
      byCategory[finding.category]++;

      switch (finding.severity) {
        case 'critical': critical++; break;
        case 'high': high++; break;
        case 'medium': medium++; break;
        case 'low': low++; break;
        case 'info': info++; break;
      }
    }

    return {
      total: findings.length,
      critical,
      high,
      medium,
      low,
      info,
      byCategory
    };
  }

  static getRuleCount(): number {
    return ruleCount;
  }
}
