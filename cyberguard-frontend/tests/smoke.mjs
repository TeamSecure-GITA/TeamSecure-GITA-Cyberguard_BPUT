import { chromium } from 'playwright';

const baseUrl = process.env.CYBERGUARD_FRONTEND_URL || 'http://127.0.0.1:5173';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const errors = [];
page.on('console', (message) => {
  if (message.type() === 'error') errors.push(message.text());
});
page.on('pageerror', (error) => errors.push(error.message));
await page.goto(baseUrl, { waitUntil: 'networkidle' });
await page.getByRole('heading', { name: 'See the signal before it spreads.' }).waitFor();
await page.getByRole('button', { name: 'SOC Login' }).click();
await page.getByRole('heading', { name: 'SOC Authentication' }).waitFor();
await page.getByRole('textbox', { name: 'Enter your administrator username' }).fill('lead');
await page.getByRole('textbox').nth(1).fill('invalid');
await page.getByRole('button', { name: 'Authenticate' }).click();
await page.getByText('Invalid username or password').waitFor();
if (errors.length) throw new Error(`Browser console errors: ${errors.join('; ')}`);
await browser.close();
console.log('Frontend smoke test passed');
