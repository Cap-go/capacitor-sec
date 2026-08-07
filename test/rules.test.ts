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

  test('secrets rules should detect OpenAI API keys', () => {
    const rule = secretsRules.find(r => r.id === 'SEC001');
    expect(rule).toBeDefined();

    // Assemble fixture so push protection does not treat it as a live secret
    const openAiLike = ['sk-', 'abcdefghijklmnopqrst', 'T3BlbkFJ', 'abcdefghijklmnopqrst'].join('');
    const testCode = `const key = "${openAiLike}";`;
    const findings = rule!.check!(testCode, 'test.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('authentication rules should detect OAuth without PKCE', () => {
    const rule = authenticationRules.find(r => r.id === 'AUTH007');
    expect(rule).toBeDefined();

    const testCode = `
      const url = 'https://auth.example.com/authorize?client_id=abc&response_type=code';
      window.location = url;
    `;
    const findings = rule!.check!(testCode, 'auth.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('authentication rules should allow OAuth with PKCE', () => {
    const rule = authenticationRules.find(r => r.id === 'AUTH007');
    expect(rule).toBeDefined();

    const testCode = `
      const codeChallenge = await pkceChallenge();
      const url = 'https://auth.example.com/authorize?client_id=abc&response_type=code&code_challenge=' + codeChallenge;
    `;
    const findings = rule!.check!(testCode, 'auth.ts');

    expect(findings.length).toBe(0);
  });

  test('android rules should detect cleartext in network security config', () => {
    const rule = androidRules.find(r => r.id === 'AND010');
    expect(rule).toBeDefined();

    const testXml = `
      <network-security-config>
        <base-config cleartextTrafficPermitted="true" />
      </network-security-config>
    `;
    const findings = rule!.check!(testXml, 'res/xml/network_security_config.xml');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('android rules should detect insecure file URL access', () => {
    const rule = androidRules.find(r => r.id === 'AND009');
    expect(rule).toBeDefined();

    const testCode = `settings.setAllowUniversalAccessFromFileURLs(true);`;
    const findings = rule!.check!(testCode, 'MainActivity.java');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('capacitor rules should detect HTTP server.url', () => {
    const rule = capacitorRules.find(r => r.id === 'CAP011');
    expect(rule).toBeDefined();

    const testCode = `
      const config = {
        server: {
          url: 'http://api.example.com'
        }
      };
    `;
    const findings = rule!.check!(testCode, 'capacitor.config.ts');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('ios rules should detect UIFileSharingEnabled', () => {
    const rule = iosRules.find(r => r.id === 'IOS009');
    expect(rule).toBeDefined();

    const testPlist = `
      <key>UIFileSharingEnabled</key>
      <true />
    `;
    const findings = rule!.check!(testPlist, 'Info.plist');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('webview rules should detect loadHTMLString', () => {
    const rule = webviewRules.find(r => r.id === 'WEB006');
    expect(rule).toBeDefined();

    const testCode = `webView.loadHTMLString(userHtml, baseURL: nil)`;
    const findings = rule!.check!(testCode, 'Bridge.swift');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('authentication rules should detect response_type=code query form without PKCE', () => {
    const rule = authenticationRules.find(r => r.id === 'AUTH007');
    expect(rule).toBeDefined();

    const testCode = `window.location = "https://idp.example.com/oauth/authorize?client_id=abc&response_type=code&redirect_uri=app://cb";`;
    const findings = rule!.check!(testCode, 'login.ts');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('cryptography rules should not flag RSA-OAEP as PKCS1 v1.5', () => {
    const rule = cryptographyRules.find(r => r.id === 'CRY001');
    expect(rule).toBeDefined();

    const testCode = `crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf);`;
    const findings = rule!.check!(testCode, 'crypto.ts');

    expect(findings.filter(f => /PKCS/.test(f.message)).length).toBe(0);
  });

  test('cryptography rules should not double-report 3DES as DES', () => {
    const rule = cryptographyRules.find(r => r.id === 'CRY001');
    expect(rule).toBeDefined();

    const testCode = `const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);`;
    const findings = rule!.check!(testCode, 'crypto.ts');
    const desFindings = findings.filter(f => f.message.startsWith('DES:'));
    const triple = findings.filter(f => f.message.startsWith('3DES:'));

    expect(desFindings.length).toBe(0);
    expect(triple.length).toBeGreaterThan(0);
  });

  test('capacitor rules should detect HTTP server.url in JSON config', () => {
    const rule = capacitorRules.find(r => r.id === 'CAP011');
    expect(rule).toBeDefined();

    const testJson = `{
      "server": {
        "url": "http://api.example.com"
      }
    }`;
    const findings = rule!.check!(testJson, 'capacitor.config.json');

    expect(findings.length).toBeGreaterThan(0);
  });

  test('webview rules should not flag literal loadHTMLString', () => {
    const rule = webviewRules.find(r => r.id === 'WEB006');
    expect(rule).toBeDefined();

    const testCode = `webView.loadHTMLString("<html><body>ok</body></html>", baseURL: nil)`;
    const findings = rule!.check!(testCode, 'Bridge.swift');

    expect(findings.length).toBe(0);
  });

});
