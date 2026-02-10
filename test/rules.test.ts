import { describe, expect, test } from 'bun:test';
import { allRules, ruleCount } from '../src/rules/index';
import { secretsRules } from '../src/rules/secrets';
import { storageRules } from '../src/rules/storage';
import { networkRules } from '../src/rules/network';
import { capacitorRules } from '../src/rules/capacitor';
import { androidRules } from '../src/rules/android';
import { iosRules } from '../src/rules/ios';
import { authenticationRules } from '../src/rules/authentication';
import { webviewRules } from '../src/rules/webview';
import { cryptographyRules } from '../src/rules/cryptography';
import { loggingRules, debugRules } from '../src/rules/logging';

describe('Security Rules', () => {
  test('should have correct total rule count', () => {
    expect(ruleCount).toBeGreaterThan(60);
    expect(allRules.length).toBe(ruleCount);
  });

  test('all rules should have required properties', () => {
    for (const rule of allRules) {
      expect(rule.id).toBeDefined();
      expect(rule.name).toBeDefined();
      expect(rule.description).toBeDefined();
      expect(rule.severity).toBeDefined();
      expect(rule.category).toBeDefined();
      expect(rule.remediation).toBeDefined();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
    }
  });

  test('all rules should have unique IDs', () => {
    const ids = allRules.map(r => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('secrets rules should detect hardcoded API keys', () => {
    const rule = secretsRules.find(r => r.id === 'SEC001');
    expect(rule).toBeDefined();

    const testCode = `const apiKey = "AKIA1234567890ABCDEF";`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('secrets rules should detect Firebase keys', () => {
    const rule = secretsRules.find(r => r.id === 'SEC001');
    expect(rule).toBeDefined();

    const testCode = `const firebase = "AIzaSyDOCAbC123dEf456GhI789jKl012mNo3456";`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('storage rules should detect sensitive data in Preferences', () => {
    const rule = storageRules.find(r => r.id === 'STO001');
    expect(rule).toBeDefined();

    const testCode = `Preferences.set({ key: 'userPassword', value: password });`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('high');
  });

  test('storage rules should detect localStorage for sensitive data', () => {
    const rule = storageRules.find(r => r.id === 'STO002');
    expect(rule).toBeDefined();

    const testCode = `localStorage.setItem("authToken", token);`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('network rules should detect HTTP URLs', () => {
    const rule = networkRules.find(r => r.id === 'NET001');
    expect(rule).toBeDefined();

    const testCode = `fetch("http://api.example.com/data");`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('high');
  });

  test('network rules should allow localhost HTTP', () => {
    const rule = networkRules.find(r => r.id === 'NET001');
    expect(rule).toBeDefined();

    const testCode = `fetch("http://localhost:3000/api");`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBe(0);
  });

  test('network rules should detect capacitor cleartext in JSON config', () => {
    const rule = networkRules.find(r => r.id === 'NET003');
    expect(rule).toBeDefined();

    const testJson = `{
      "server": {
        "cleartext": true
      }
    }`;
    const findings = rule!.check!(testJson, 'capacitor.config.json');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('capacitor rules should detect WebView debug mode', () => {
    const rule = capacitorRules.find(r => r.id === 'CAP001');
    expect(rule).toBeDefined();

    const testCode = `
      export default {
        webContentsDebuggingEnabled: true,
        appId: 'com.example.app'
      };
    `;
    const findings = rule!.check!(testCode, 'capacitor.config.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('capacitor rules should detect eval usage', () => {
    const rule = capacitorRules.find(r => r.id === 'CAP006');
    expect(rule).toBeDefined();

    const testCode = `const result = eval(userInput);`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('android rules should detect cleartext traffic', () => {
    const rule = androidRules.find(r => r.id === 'AND001');
    expect(rule).toBeDefined();

    const testXml = `
      <application
        android:usesCleartextTraffic="true"
        android:label="@string/app_name">
      </application>
    `;
    const findings = rule!.check!(testXml, 'AndroidManifest.xml');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('android rules should detect debug mode', () => {
    const rule = androidRules.find(r => r.id === 'AND002');
    expect(rule).toBeDefined();

    const testXml = `
      <application
        android:debuggable="true"
        android:label="@string/app_name">
      </application>
    `;
    const findings = rule!.check!(testXml, 'AndroidManifest.xml');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('ios rules should detect ATS disabled', () => {
    const rule = iosRules.find(r => r.id === 'IOS001');
    expect(rule).toBeDefined();

    const testPlist = `
      <key>NSAppTransportSecurity</key>
      <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true />
      </dict>
    `;
    const findings = rule!.check!(testPlist, 'Info.plist');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('authentication rules should detect weak JWT validation', () => {
    const rule = authenticationRules.find(r => r.id === 'AUTH001');
    expect(rule).toBeDefined();

    const testCode = `const claims = jwtDecode(token);`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('authentication rules should detect Math.random in security context', () => {
    const rule = authenticationRules.find(r => r.id === 'AUTH003');
    expect(rule).toBeDefined();

    const testCode = `const token = Math.random().toString(36);`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('webview rules should detect innerHTML usage', () => {
    const rule = webviewRules.find(r => r.id === 'WEB001');
    expect(rule).toBeDefined();

    const testCode = `element.innerHTML = userInput;`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('cryptography rules should detect weak algorithms', () => {
    const rule = cryptographyRules.find(r => r.id === 'CRY001');
    expect(rule).toBeDefined();

    const testCode = `const hash = crypto.createHash('md5').update(data).digest('hex');`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('logging rules should detect sensitive data in logs', () => {
    const rule = loggingRules.find(r => r.id === 'LOG001');
    expect(rule).toBeDefined();

    const testCode = `console.log('User password:', password);`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('debug rules should detect debugger statements', () => {
    const rule = debugRules.find(r => r.id === 'DBG001');
    expect(rule).toBeDefined();

    const testCode = `function test() { debugger; return 1; }`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
  });
});
