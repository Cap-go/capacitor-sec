#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { SecurityScanner } from '../scanners/engine.js';
import { formatCliReport, formatJsonReport, formatHtmlReport } from '../utils/reporter.js';
import type { ScanOptions, RuleCategory, Severity } from '../types.js';
import { ruleCount } from '../rules/index.js';

const program = new Command();

const VERSION = '1.0.0';

const BANNER = `
${chalk.hex('#7c3aed').bold('╔═══════════════════════════════════════════════════════════╗')}
${chalk.hex('#7c3aed').bold('║')}  ${chalk.white.bold('🔒 CAPSEC')} - Capacitor Security Scanner               ${chalk.hex('#7c3aed').bold('║')}
${chalk.hex('#7c3aed').bold('║')}  ${chalk.gray(`v${VERSION} • ${ruleCount} security rules • capacitor-sec.dev`)}  ${chalk.hex('#7c3aed').bold('║')}
${chalk.hex('#7c3aed').bold('╚═══════════════════════════════════════════════════════════╝')}
`;

program
  .name('capsec')
  .version(VERSION)
  .description('Security scanner for Capacitor apps - detect vulnerabilities, hardcoded secrets, and security misconfigurations')
  .addHelpText('before', BANNER);

program
  .command('scan')
  .description('Scan a Capacitor project for security issues')
  .argument('[path]', 'Path to the Capacitor project', '.')
  .option('-o, --output <format>', 'Output format: cli, json, html', 'cli')
  .option('-f, --output-file <file>', 'Write output to a file')
  .option('-s, --severity <level>', 'Minimum severity to report: critical, high, medium, low, info', 'low')
  .option('-c, --categories <categories>', 'Categories to scan (comma-separated)', '')
  .option('-e, --exclude <patterns>', 'Additional patterns to exclude (comma-separated)', '')
  .option('--ci', 'CI mode: exit with code 1 if high or critical issues found', false)
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (path: string, options: any) => {
    console.log(BANNER);

    const spinner = ora('Initializing security scan...').start();

    try {
      const scanOptions: ScanOptions = {
        path: path.startsWith('/') ? path : `${process.cwd()}/${path}`,
        output: options.output,
        outputFile: options.outputFile,
        severity: options.severity as Severity,
        categories: options.categories ? options.categories.split(',').map((c: string) => c.trim()) as RuleCategory[] : undefined,
        exclude: options.exclude ? options.exclude.split(',').map((e: string) => e.trim()) : undefined,
        ci: options.ci,
        verbose: options.verbose
      };

      spinner.text = `Scanning ${scanOptions.path}...`;

      const scanner = new SecurityScanner(scanOptions);
      const result = await scanner.scan();

      spinner.succeed(`Scanned ${result.filesScanned} files in ${result.duration}ms`);

      // Format output
      let output: string;
      switch (options.output) {
        case 'json':
          output = formatJsonReport(result);
          break;
        case 'html':
          output = formatHtmlReport(result);
          break;
        default:
          output = formatCliReport(result);
      }

      // Write to file or stdout
      if (options.outputFile) {
        writeFileSync(options.outputFile, output);
        console.log(chalk.green(`\n✓ Report saved to ${options.outputFile}`));
      } else {
        console.log(output);
      }

      // CI mode exit codes
      if (options.ci) {
        if (result.summary.critical > 0 || result.summary.high > 0) {
          console.log(chalk.red('\n✗ CI check failed: High or critical severity issues found'));
          process.exit(1);
        } else {
          console.log(chalk.green('\n✓ CI check passed'));
          process.exit(0);
        }
      }

    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red(`Error: ${(error as Error).message}`));
      if (options.verbose) {
        console.error(error);
      }
      process.exit(1);
    }
  });

program
  .command('rules')
  .description('List all security rules')
  .option('-c, --category <category>', 'Filter by category')
  .option('-s, --severity <severity>', 'Filter by severity')
  .action((options: any) => {
    console.log(BANNER);

    // Import rules dynamically
    import('../rules/index.js').then(({ allRules }) => {
      let rules = allRules;

      if (options.category) {
        rules = rules.filter(r => r.category === options.category);
      }

      if (options.severity) {
        rules = rules.filter(r => r.severity === options.severity);
      }

      console.log(chalk.bold(`\n${rules.length} Security Rules\n`));
      console.log('─'.repeat(60));

      const byCategory = new Map<string, typeof rules>();
      for (const rule of rules) {
        if (!byCategory.has(rule.category)) {
          byCategory.set(rule.category, []);
        }
        byCategory.get(rule.category)!.push(rule);
      }

      for (const [category, categoryRules] of byCategory) {
        console.log(chalk.bold.cyan(`\n${category.toUpperCase()} (${categoryRules.length})`));
        for (const rule of categoryRules) {
          const severityColor =
            rule.severity === 'critical' ? chalk.bgRed.white :
            rule.severity === 'high' ? chalk.red :
            rule.severity === 'medium' ? chalk.yellow :
            rule.severity === 'low' ? chalk.cyan :
            chalk.gray;

          console.log(`  ${chalk.gray(rule.id)} ${severityColor(`[${rule.severity}]`)} ${rule.name}`);
          console.log(chalk.gray(`       ${rule.description}`));
        }
      }

      console.log('\n');
    });
  });

program
  .command('init')
  .description('Initialize capsec configuration file')
  .action(async () => {
    console.log(BANNER);

    const configContent = `{
  "$schema": "https://capacitor-sec.dev/schema/capsec.json",
  "exclude": [
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**"
  ],
  "severity": "low",
  "categories": [],
  "rules": {}
}`;

    const configPath = `${process.cwd()}/capsec.config.json`;
    writeFileSync(configPath, configContent);
    console.log(chalk.green(`✓ Created ${configPath}`));
  });

// Default command is scan
if (process.argv.length === 2) {
  process.argv.push('scan');
}

program.parse();
