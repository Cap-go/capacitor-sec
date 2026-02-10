import type { ScanResult, Finding, Severity } from '../types.js';

const SEVERITY_COLORS = {
  critical: '\x1b[41m\x1b[37m', // Red background, white text
  high: '\x1b[31m',             // Red
  medium: '\x1b[33m',           // Yellow
  low: '\x1b[36m',              // Cyan
  info: '\x1b[90m'              // Gray
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

export function formatCliReport(result: ScanResult): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(`${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}║              CAPSEC Security Scan Report                     ║${RESET}`);
  lines.push(`${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}`);
  lines.push('');

  // Summary
  lines.push(`${BOLD}Summary${RESET}`);
  lines.push(`${'─'.repeat(60)}`);
  lines.push(`Project: ${result.projectPath}`);
  lines.push(`Scanned: ${result.filesScanned} files in ${result.duration}ms`);
  lines.push(`Time: ${result.timestamp}`);
  if (result.scanContext) {
    lines.push('');
    lines.push(`${BOLD}Scan Context${RESET}`);
    lines.push(`${'─'.repeat(60)}`);
    const used = result.scanContext.capacitorConfigUsed ? ` (used: ${result.scanContext.capacitorConfigUsed})` : '';
    lines.push(`Capacitor config: ${formatPathList(result.scanContext.capacitorConfigFiles)}${used}`);
    if (result.scanContext.platformPaths?.android) {
      lines.push(`Android path:     ${formatConfiguredResolved(result.scanContext.platformPaths.android)}`);
    }
    if (result.scanContext.platformPaths?.ios) {
      lines.push(`iOS path:         ${formatConfiguredResolved(result.scanContext.platformPaths.ios)}`);
    }
    lines.push(`Android manifest: ${formatPathList(result.scanContext.androidManifestFiles)}`);
    lines.push(`Android netsec:  ${formatPathList(result.scanContext.androidNetworkSecurityConfigFiles)}`);
    lines.push(`iOS Info.plist:  ${formatPathList(result.scanContext.iosInfoPlistFiles)}`);
  }
  lines.push('');

  // Severity breakdown
  lines.push(`${BOLD}Findings by Severity${RESET}`);
  lines.push(`${'─'.repeat(60)}`);

  if (result.summary.critical > 0) {
    lines.push(`${SEVERITY_COLORS.critical} CRITICAL ${RESET} ${result.summary.critical}`);
  }
  if (result.summary.high > 0) {
    lines.push(`${SEVERITY_COLORS.high}● HIGH${RESET}     ${result.summary.high}`);
  }
  if (result.summary.medium > 0) {
    lines.push(`${SEVERITY_COLORS.medium}● MEDIUM${RESET}   ${result.summary.medium}`);
  }
  if (result.summary.low > 0) {
    lines.push(`${SEVERITY_COLORS.low}● LOW${RESET}      ${result.summary.low}`);
  }
  if (result.summary.info > 0) {
    lines.push(`${SEVERITY_COLORS.info}● INFO${RESET}     ${result.summary.info}`);
  }

  lines.push('');
  lines.push(`${BOLD}Total: ${result.summary.total} findings${RESET}`);
  lines.push('');

  // Findings
  if (result.findings.length > 0) {
    lines.push(`${BOLD}Detailed Findings${RESET}`);
    lines.push(`${'═'.repeat(60)}`);
    lines.push('');

    let currentSeverity: Severity | null = null;

    for (const finding of result.findings) {
      if (finding.severity !== currentSeverity) {
        currentSeverity = finding.severity;
        lines.push(`${SEVERITY_COLORS[finding.severity]}${BOLD}── ${finding.severity.toUpperCase()} ──${RESET}`);
        lines.push('');
      }

      lines.push(formatFinding(finding));
    }
  } else {
    lines.push(`${BOLD}\x1b[32m✓ No security issues found!${RESET}`);
    lines.push('');
  }

  // Footer
  lines.push(`${'─'.repeat(60)}`);
  lines.push(`${DIM}Powered by capsec - https://capacitor-sec.dev${RESET}`);
  lines.push('');

  return lines.join('\n');
}

function formatPathList(paths: string[]): string {
  if (!paths || paths.length === 0) return 'not found';
  if (paths.length <= 2) return paths.join(', ');
  return `${paths.slice(0, 2).join(', ')} (+${paths.length - 2} more)`;
}

function formatConfiguredResolved(v: { configured?: string; resolved?: string }): string {
  const c = v.configured ?? 'n/a';
  const r = v.resolved ?? 'n/a';
  return `${c} -> ${r}`;
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const severityColor = SEVERITY_COLORS[finding.severity];

  lines.push(`${severityColor}[${finding.ruleId}]${RESET} ${BOLD}${finding.ruleName}${RESET}`);
  lines.push(`  ${DIM}File:${RESET} ${finding.filePath}${finding.line ? `:${finding.line}` : ''}`);
  lines.push(`  ${DIM}Issue:${RESET} ${finding.message}`);

  if (finding.codeSnippet) {
    lines.push(`  ${DIM}Code:${RESET} ${finding.codeSnippet.substring(0, 80)}${finding.codeSnippet.length > 80 ? '...' : ''}`);
  }

  lines.push(`  ${DIM}Fix:${RESET} ${finding.remediation}`);

  if (finding.references && finding.references.length > 0) {
    lines.push(`  ${DIM}Refs:${RESET} ${finding.references[0]}`);
  }

  lines.push('');

  return lines.join('\n');
}

export function formatJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatHtmlReport(result: ScanResult): string {
  const severityClasses: Record<Severity, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-red-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-500 text-white'
  };

  const findingsHtml = result.findings.map(finding => `
    <div class="finding border-l-4 ${finding.severity === 'critical' ? 'border-red-600' : finding.severity === 'high' ? 'border-red-500' : finding.severity === 'medium' ? 'border-yellow-500' : finding.severity === 'low' ? 'border-blue-500' : 'border-gray-500'} bg-white shadow-md rounded-r-lg p-4 mb-4">
      <div class="flex items-center gap-2 mb-2">
        <span class="px-2 py-1 rounded text-xs font-bold ${severityClasses[finding.severity]}">${finding.severity.toUpperCase()}</span>
        <span class="text-gray-500 text-sm">${finding.ruleId}</span>
        <span class="font-semibold">${finding.ruleName}</span>
      </div>
      <p class="text-gray-700 mb-2">${finding.message}</p>
      <p class="text-sm text-gray-500 mb-2">
        <span class="font-mono">${finding.filePath}${finding.line ? `:${finding.line}` : ''}</span>
      </p>
      ${finding.codeSnippet ? `<pre class="bg-gray-100 p-2 rounded text-sm overflow-x-auto mb-2"><code>${escapeHtml(finding.codeSnippet)}</code></pre>` : ''}
      <p class="text-sm"><strong>Remediation:</strong> ${finding.remediation}</p>
      ${finding.references && finding.references.length > 0 ? `<p class="text-sm text-blue-600 mt-2"><a href="${finding.references[0]}" target="_blank" rel="noopener">Learn more →</a></p>` : ''}
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Capsec Security Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="container mx-auto px-4 py-8 max-w-4xl">
    <header class="bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg shadow-lg p-8 mb-8">
      <h1 class="text-3xl font-bold mb-2">🔒 Capsec Security Report</h1>
      <p class="opacity-80">Capacitor Security Scanner</p>
    </header>

    <section class="bg-white rounded-lg shadow-md p-6 mb-8">
      <h2 class="text-xl font-bold mb-4">Summary</h2>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div class="text-center p-4 bg-gray-50 rounded">
          <div class="text-2xl font-bold">${result.filesScanned}</div>
          <div class="text-gray-500 text-sm">Files Scanned</div>
        </div>
        <div class="text-center p-4 bg-gray-50 rounded">
          <div class="text-2xl font-bold">${result.summary.total}</div>
          <div class="text-gray-500 text-sm">Total Findings</div>
        </div>
        <div class="text-center p-4 bg-gray-50 rounded">
          <div class="text-2xl font-bold">${result.duration}ms</div>
          <div class="text-gray-500 text-sm">Scan Duration</div>
        </div>
        <div class="text-center p-4 bg-gray-50 rounded">
          <div class="text-2xl font-bold">${new Date(result.timestamp).toLocaleDateString()}</div>
          <div class="text-gray-500 text-sm">Scan Date</div>
        </div>
      </div>

      <div class="flex flex-wrap gap-2">
        ${result.summary.critical > 0 ? `<span class="px-3 py-1 rounded-full text-sm font-bold bg-red-600 text-white">${result.summary.critical} Critical</span>` : ''}
        ${result.summary.high > 0 ? `<span class="px-3 py-1 rounded-full text-sm font-bold bg-red-500 text-white">${result.summary.high} High</span>` : ''}
        ${result.summary.medium > 0 ? `<span class="px-3 py-1 rounded-full text-sm font-bold bg-yellow-500 text-black">${result.summary.medium} Medium</span>` : ''}
        ${result.summary.low > 0 ? `<span class="px-3 py-1 rounded-full text-sm font-bold bg-blue-500 text-white">${result.summary.low} Low</span>` : ''}
        ${result.summary.info > 0 ? `<span class="px-3 py-1 rounded-full text-sm font-bold bg-gray-500 text-white">${result.summary.info} Info</span>` : ''}
      </div>
    </section>

    <section>
      <h2 class="text-xl font-bold mb-4">Findings</h2>
      ${result.findings.length > 0 ? findingsHtml : '<p class="text-green-600 text-lg font-semibold">✓ No security issues found!</p>'}
    </section>

    <footer class="text-center text-gray-500 text-sm mt-8 pt-8 border-t">
      <p>Generated by <a href="https://capacitor-sec.dev" class="text-purple-600 hover:underline">capsec</a> - Capacitor Security Scanner</p>
      <p class="mt-2">Project: ${result.projectPath}</p>
    </footer>
  </div>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
