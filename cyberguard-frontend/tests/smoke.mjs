import { chromium } from 'playwright';

const baseUrl = process.env.CYBERGUARD_FRONTEND_URL || 'http://127.0.0.1:5173';
const adminUsername = process.env.CYBERGUARD_HEAD_ADMIN_USERNAME;
const adminPassword = process.env.CYBERGUARD_HEAD_ADMIN_PASSWORD;
if (!adminUsername || !adminPassword) {
  throw new Error('Set CYBERGUARD_HEAD_ADMIN_USERNAME and CYBERGUARD_HEAD_ADMIN_PASSWORD for the smoke test.');
}
const browser = await chromium.launch({ headless: true });
let page = await browser.newPage();
const errors = [];
let expectingInvalidLogin = false;
const monitorPage = (target) => {
  target.on('console', (message) => {
    if (message.type() !== 'error') return;
    if (expectingInvalidLogin && message.text().includes('401 (Unauthorized)')) return;
    errors.push(message.text());
  });
  target.on('pageerror', (error) => errors.push(error.message));
};
monitorPage(page);

const runTextAnalysis = async (channel, payload) => {
  await page.getByRole('button', { name: channel, exact: true }).click();
  await page.locator('.inspector-form textarea').first().fill(payload);
  const responsePromise = page.waitForResponse((response) => (
    response.url().endsWith('/api/v1/analyze')
    && response.request().method() === 'POST'
  ));
  await page.getByRole('button', { name: 'Run Multi-Engine Inspection' }).click();
  const response = await responsePromise;
  if (!response.ok()) throw new Error(`${channel} analysis failed: ${response.status()}`);
  const result = await response.json();
  const scoring = result.assessment?.scoring;
  const allocatedRisk = (result.assessment?.indicators || []).reduce((total, indicator) => total + (indicator.contribution || 0), 0);
  if (scoring?.method !== 'evidence_weighted_attribution_v1' || allocatedRisk !== scoring.risk_score) {
    throw new Error(`${channel} analysis returned an invalid evidence attribution contract.`);
  }
  await page.getByText('FASTAPI ENGINE ASSESSMENT').waitFor();
  if (result.assessment?.indicators?.some((indicator) => indicator.feature_attribution?.status === 'available')) {
    await page.getByLabel('Local text model feature attribution').waitFor();
  }
};

const runFileAnalysis = async (channel, file) => {
  await page.getByRole('button', { name: channel, exact: true }).click();
  await page.locator('#mediaUpload').setInputFiles(file);
  const responsePromise = page.waitForResponse((response) => (
    response.url().endsWith('/api/v1/analyze/file')
    && response.request().method() === 'POST'
  ));
  await page.getByRole('button', { name: 'Run Multi-Engine Inspection' }).click();
  const response = await responsePromise;
  if (!response.ok()) throw new Error(`${channel} upload analysis failed: ${response.status()}`);
  const result = await response.json();
  const scoring = result.assessment?.scoring;
  const allocatedRisk = (result.assessment?.indicators || []).reduce((total, indicator) => total + (indicator.contribution || 0), 0);
  if (scoring?.method !== 'evidence_weighted_attribution_v1' || allocatedRisk !== scoring.risk_score) {
    throw new Error(`${channel} upload returned an invalid evidence attribution contract.`);
  }
  await page.getByText('FASTAPI ENGINE ASSESSMENT').waitFor();
};

const createTestWav = () => {
  const sampleRate = 16_000;
  const sampleCount = sampleRate;
  const dataSize = sampleCount * 2;
  const buffer = Buffer.alloc(44 + dataSize);
  buffer.write('RIFF', 0);
  buffer.writeUInt32LE(36 + dataSize, 4);
  buffer.write('WAVEfmt ', 8);
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(sampleRate, 24);
  buffer.writeUInt32LE(sampleRate * 2, 28);
  buffer.writeUInt16LE(2, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write('data', 36);
  buffer.writeUInt32LE(dataSize, 40);
  for (let index = 0; index < sampleCount; index += 1) {
    const sample = Math.round(Math.sin(2 * Math.PI * 440 * index / sampleRate) * 12_000);
    buffer.writeInt16LE(sample, 44 + index * 2);
  }
  return buffer;
};

try {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'See the signal before it spreads.' }).waitFor();
  await page.getByRole('button', { name: 'SOC Login' }).click();
  await page.getByRole('heading', { name: 'SOC Authentication' }).waitFor();
  const usernameField = page.locator('input[type="text"]').first();
  const passwordField = page.locator('input[type="password"]').first();
  await usernameField.fill('not-real@example.com');
  await passwordField.fill('wrong-password');
  expectingInvalidLogin = true;
  await page.getByRole('button', { name: 'Authenticate' }).click();
  await page.getByText(/Invalid username or password\.?/).waitFor();
  expectingInvalidLogin = false;

  await page.close();
  page = await browser.newPage();
  monitorPage(page);
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'See the signal before it spreads.' }).waitFor();
  await page.getByRole('button', { name: 'SOC Login' }).click();
  await page.getByRole('heading', { name: 'SOC Authentication' }).waitFor();
  const reloadedUsernameField = page.locator('input[type="text"]').first();
  const reloadedPasswordField = page.locator('input[type="password"]').first();
  await reloadedUsernameField.fill(adminUsername);
  await reloadedPasswordField.fill(adminPassword);
  await page.getByRole('button', { name: 'Authenticate' }).click();
  await page.getByText('[ CYBERGUARD WORKSPACE READY ]').waitFor();
  await page.getByRole('heading', { name: /Security Command Center/ }).waitFor();
  await page.getByRole('button', { name: 'Detection Studio' }).click();
  await page.getByRole('heading', { name: 'Detection Studio' }).waitFor();

  await page.locator('.inspector-form textarea').first().fill('Urgent: verify your account at https://secure-login.example immediately.');
  await page.getByRole('button', { name: 'Run Multi-Engine Inspection' }).click();
  await page.getByText('FASTAPI ENGINE ASSESSMENT').waitFor();

  await runTextAnalysis('Malicious URL', 'https://secure-login.xyz/auth?redirect=https://evil.example/login');
  await runTextAnalysis('SMS / Social', 'Urgent: your refund is ready; confirm your UPI PIN and OTP at this link now.');
  await runTextAnalysis('Credential / ATO', JSON.stringify({ failed_attempts: 12, total_attempts: 15, distinct_accounts: 8, distinct_countries: 2, impossible_travel: true, new_device: true, mfa_denials: 4 }));
  await runTextAnalysis('System Logs', JSON.stringify({ events: [{ event_id: 1102, event_type: 'audit_log_cleared' }] }));
  await runTextAnalysis('Network Traffic', JSON.stringify({ flows: [{ src_ip: '10.0.0.5', destination_ports: Array.from({ length: 12 }, (_, index) => 20 + index) }] }));
  await runFileAnalysis('EML Sender Inspection', {
    name: 'message.eml',
    mimeType: 'message/rfc822',
    buffer: Buffer.from('From: Finance <alerts@bput.ac.in>\r\nSubject: Account notice\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<div style="display:none"><a href="https://login.attacker.example">Review</a></div>'),
  });
  await page.getByText(/Sender identity:/i).waitFor();
  await runFileAnalysis('Malware Indicators', {
    name: 'eicar.com',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(String.raw`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`),
  });
  await page.getByText('YARA file scan').waitFor();
  await runFileAnalysis('Image Analysis', {
    name: 'notice.png',
    mimeType: 'image/png',
    buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jLe0AAAAASUVORK5CYII=', 'base64'),
  });
  await page.getByText(/Image OCR/i).waitFor();
  await runFileAnalysis('Voice Analysis', {
    name: 'tone.wav',
    mimeType: 'audio/wav',
    buffer: createTestWav(),
  });
  await page.getByText(/Audio waveform inspected/i).waitFor();

  await page.getByRole('button', { name: 'Impersonation', exact: true }).click();
  const contactName = `Playwright Contact ${Date.now()}`;
  await page.getByLabel('Contact name').fill(contactName);
  await page.getByLabel('Known identifiers').fill('jane@example.test');
  await page.getByLabel('Writing samples').fill([
    'Hi team, I will send the draft tomorrow. Please review the notes before lunch.',
    'Hello team, I will share the draft today. Please review the notes before lunch.',
    'Hi everyone, I will send the notes tomorrow. Please review the draft before lunch.',
  ].join('\n\n'));
  await page.getByRole('button', { name: 'Save contact profile' }).click();
  await page.getByLabel('Known contact').selectOption({ label: `${contactName} · 3 samples` });
  await page.locator('.inspector-form textarea').last().fill('From: jane@example.test <attacker@example.net>\n\nURGENT!!! wire transfer now!!! Buy gift cards immediately!!!');
  await page.getByRole('button', { name: 'Run Multi-Engine Inspection' }).click();
  await page.getByText(contactName, { exact: true }).waitFor();
  await page.getByText(/sender does not match/i).last().waitFor();
  await page.getByRole('button', { name: 'Delete selected contact profile' }).click();
  await page.getByRole('option', { name: `${contactName} · 3 samples` }).waitFor({ state: 'detached' });

  await page.getByRole('button', { name: 'XDR Fusion' }).click();
  await page.getByRole('heading', { name: 'Advanced SOC decision support' }).waitFor();
  await page.getByText('LIVE DATA', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Generate simulated canary plan' }).click();
  await page.getByText(/Honeytoken plan: simulation/).waitFor();

  await page.getByRole('button', { name: 'Attack Graph' }).click();
  await page.getByRole('button', { name: 'Supply Chain' }).click();
  await page.getByRole('button', { name: 'Calculate blast radius' }).click();
  await page.getByText(/2 downstream node\(s\) affected/).waitFor();

  if (errors.length) throw new Error(`Browser console errors: ${errors.join('; ')}`);
  console.log('Frontend authenticated analysis smoke test passed');
} finally {
  await browser.close();
}
