export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RuleCategory =
  | 'storage'
  | 'network'
  | 'authentication'
  | 'secrets'
  | 'cryptography'
  | 'logging'
  | 'capacitor'
  | 'debug'
  | 'android'
  | 'ios'
  | 'config'
  | 'webview'
  | 'permissions';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: RuleCategory;
  patterns?: RegExp[];
  filePatterns?: string[];
  check?: (content: string, filePath: string, ast?: any) => Finding[];
  remediation: string;
  references?: string[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: RuleCategory;
  message: string;
  filePath: string;
  line?: number;
  column?: number;
  codeSnippet?: string;
  remediation: string;
  references?: string[];
}

export interface ScanResult {
  projectPath: string;
  timestamp: string;
  duration: number;
  filesScanned: number;
  scanContext?: {
    capacitorConfigFiles: string[];
    capacitorConfigUsed?: string;
    platformPaths?: {
      android?: { configured?: string; resolved?: string };
      ios?: { configured?: string; resolved?: string };
    };
    androidManifestFiles: string[];
    androidNetworkSecurityConfigFiles: string[];
    iosInfoPlistFiles: string[];
  };
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    byCategory: Record<RuleCategory, number>;
  };
}

export interface ScanOptions {
  path: string;
  output?: 'cli' | 'json' | 'html';
  outputFile?: string;
  severity?: Severity;
  categories?: RuleCategory[];
  exclude?: string[];
  changedOnly?: boolean;
  ci?: boolean;
  verbose?: boolean;
}

export interface CapacitorConfig {
  appId?: string;
  appName?: string;
  webDir?: string;
  plugins?: Record<string, any>;
  android?: {
    path?: string;
    allowMixedContent?: boolean;
    captureInput?: boolean;
    webContentsDebuggingEnabled?: boolean;
    loggingBehavior?: string;
  };
  ios?: {
    path?: string;
    allowsLinkPreview?: boolean;
    scrollEnabled?: boolean;
    webContentsDebuggingEnabled?: boolean;
    loggingBehavior?: string;
  };
  server?: {
    url?: string;
    cleartext?: boolean;
    allowNavigation?: string[];
  };
}
