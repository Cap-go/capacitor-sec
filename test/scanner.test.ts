import { describe, expect, test, beforeAll, afterAll } from 'bun:test';
import { SecurityScanner } from '../src/scanners/engine';
import { mkdir, rm, mkdtemp } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';

const TEST_DIR = '/tmp/capsec-test-project';

describe('SecurityScanner', () => {
  beforeAll(async () => {
    // Create test project directory
    await mkdir(TEST_DIR, { recursive: true });
    await mkdir(join(TEST_DIR, 'src'), { recursive: true });
    await mkdir(join(TEST_DIR, 'android/app/src/main'), { recursive: true });
    await mkdir(join(TEST_DIR, 'ios/App'), { recursive: true });

    // Create test files with vulnerabilities using Bun.write
    await Bun.write(
      join(TEST_DIR, 'src/api.ts'),
      `
const API_KEY = "AKIA1234567890ABCDEF";
const secret = "my_secret_key_for_testing_purposes";

export async function fetchData() {
  return fetch("http://api.example.com/data");
}

export function processInput(input: string) {
  return eval(input);
}
`
    );

    await Bun.write(
      join(TEST_DIR, 'src/auth.ts'),
      `
import { jwtDecode } from 'jwt-decode';

export function getUserFromToken(token: string) {
  const user = jwtDecode(token);
  console.log('User token:', token);
  return user;
}

export function generateSessionId() {
  return Math.random().toString(36);
}
`
    );

    await Bun.write(
      join(TEST_DIR, 'capacitor.config.ts'),
      `
import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.example.app',
  appName: 'Test App',
  webDir: 'dist',
  server: {
    cleartext: true
  },
  android: {
    webContentsDebuggingEnabled: true,
    allowMixedContent: true
  }
};

export default config;
`
    );

    await Bun.write(
      join(TEST_DIR, 'android/app/src/main/AndroidManifest.xml'),
      `
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application
    android:usesCleartextTraffic="true"
    android:debuggable="true"
    android:allowBackup="true">
  </application>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.RECORD_AUDIO"/>
</manifest>
`
    );

    await Bun.write(
      join(TEST_DIR, 'ios/App/Info.plist'),
      `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true />
  </dict>
</dict>
</plist>
`
    );

    await Bun.write(
      join(TEST_DIR, 'src/storage.ts'),
      `
import { Preferences } from '@capacitor/preferences';

export async function saveCredentials(password: string) {
  await Preferences.set({ key: 'userPassword', value: password });
  localStorage.setItem('authToken', 'secret');
}
`
    );
  });

  afterAll(async () => {
    // Cleanup test directory
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  test('should scan project and find vulnerabilities', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.total).toBeGreaterThan(0);
  });

  test('should find critical severity issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    expect(result.summary.critical).toBeGreaterThan(0);
  });

  test('should find high severity issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    expect(result.summary.high).toBeGreaterThan(0);
  });

  test('should detect secrets in code', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      categories: ['secrets']
    });

    const result = await scanner.scan();

    const secretFindings = result.findings.filter(f => f.category === 'secrets');
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  test('should detect network issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      categories: ['network']
    });

    const result = await scanner.scan();

    const networkFindings = result.findings.filter(f => f.category === 'network');
    expect(networkFindings.length).toBeGreaterThan(0);
  });

  test('should detect capacitor config issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      categories: ['capacitor']
    });

    const result = await scanner.scan();

    const capFindings = result.findings.filter(f => f.category === 'capacitor');
    expect(capFindings.length).toBeGreaterThan(0);
  });

  test('should detect android issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      categories: ['android']
    });

    const result = await scanner.scan();

    const androidFindings = result.findings.filter(f => f.category === 'android');
    expect(androidFindings.length).toBeGreaterThan(0);
  });

  test('should detect iOS issues', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      categories: ['ios']
    });

    const result = await scanner.scan();

    const iosFindings = result.findings.filter(f => f.category === 'ios');
    expect(iosFindings.length).toBeGreaterThan(0);
  });

  test('should filter by severity', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR,
      severity: 'high'  // Show critical and high
    });

    const result = await scanner.scan();

    // All findings should be critical or high
    for (const finding of result.findings) {
      expect(['critical', 'high']).toContain(finding.severity);
    }
  });

  test('should return findings sorted by severity', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    let lastIndex = -1;

    for (const finding of result.findings) {
      const currentIndex = severityOrder.indexOf(finding.severity);
      expect(currentIndex).toBeGreaterThanOrEqual(lastIndex);
      lastIndex = currentIndex;
    }
  });

  test('should include remediation for all findings', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    for (const finding of result.findings) {
      expect(finding.remediation).toBeDefined();
      expect(finding.remediation.length).toBeGreaterThan(0);
    }
  });

  test('should provide correct summary counts', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    const countedTotal =
      result.summary.critical +
      result.summary.high +
      result.summary.medium +
      result.summary.low +
      result.summary.info;

    expect(countedTotal).toBe(result.summary.total);
    expect(result.summary.total).toBe(result.findings.length);
  });

  test('should have timing information', async () => {
    const scanner = new SecurityScanner({
      path: TEST_DIR
    });

    const result = await scanner.scan();

    expect(result.duration).toBeGreaterThan(0);
    expect(result.timestamp).toBeDefined();
  });

  test('getRuleCount should return correct count', () => {
    const count = SecurityScanner.getRuleCount();
    expect(count).toBeGreaterThan(60);
  });

  test('should scan native projects using capacitor config paths (monorepo)', async () => {
    const root = await mkdtemp(join(tmpdir(), 'capsec-monorepo-'));
    const uiDir = join(root, 'apps', 'ui');
    const androidDir = join(root, 'native', 'android');
    const iosDir = join(root, 'native', 'ios', 'App');

    await mkdir(join(uiDir, 'src'), { recursive: true });
    await mkdir(join(androidDir, 'app', 'src', 'main'), { recursive: true });
    await mkdir(iosDir, { recursive: true });

    // Point to native projects outside the UI folder.
    await Bun.write(
      join(uiDir, 'capacitor.config.ts'),
      `
export default {
  appId: 'com.example.monorepo',
  appName: 'Monorepo Test',
  android: { path: '../../native/android' },
  ios: { path: '../../native/ios/App' },
  server: { cleartext: true }
};
`
    );

    await Bun.write(
      join(androidDir, 'app', 'src', 'main', 'AndroidManifest.xml'),
      `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true" android:debuggable="true" />
</manifest>
`
    );

    await Bun.write(
      join(iosDir, 'Info.plist'),
      `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true />
  </dict>
</dict>
</plist>
`
    );

    const scanner = new SecurityScanner({ path: uiDir });
    const result = await scanner.scan();

    // It should discover and scan files outside uiDir via android.path / ios.path.
    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.scanContext?.capacitorConfigUsed).toContain('capacitor.config.ts');
    expect(result.scanContext?.androidManifestFiles.some(p => p.includes('/native/android/'))).toBe(true);
    expect(result.scanContext?.iosInfoPlistFiles.some(p => p.includes('/native/ios/'))).toBe(true);

    // And it should flag the expected misconfigurations.
    const ids = new Set(result.findings.map(f => f.ruleId));
    expect(ids.has('AND001')).toBe(true);
    expect(ids.has('AND002')).toBe(true);
    expect(ids.has('IOS001')).toBe(true);
    expect(ids.has('NET003')).toBe(true);

    await rm(root, { recursive: true, force: true });
  });
});
