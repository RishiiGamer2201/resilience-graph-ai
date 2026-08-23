/* Drive the whole demo path in a real browser, against a running instance.
 *
 * Every other check in this repo verifies the API or the build. None of them
 * open the page, and four defects survived to the day before a demo because of
 * that: the topbar title collapsed to one word per line once the pills grew,
 * prose was set in monospace, the primary button was 2.19:1 in dark, and a
 * dark-mode rule was firing in the default light state. All four are obvious in
 * a screenshot and invisible in a diff.
 *
 * Deliberately NOT part of `npm test` or CI: it needs a browser download and a
 * running server, and this repo's contract is that a fresh clone runs offline
 * with nine packages. Run it before a demo, not on every push.
 *
 *   pip install -e . && python -m uvicorn api.main:app --port 8080 &
 *   cd /tmp && npm i playwright && npx playwright install chromium
 *   node scripts/e2e_browser.mjs http://127.0.0.1:8080 [--shots DIR]
 *
 * Exit code is the number of failed steps, so it is usable as a gate.
 */
import { chromium } from 'playwright';

const base = process.argv[2] || 'http://127.0.0.1:8080';
const shotArg = process.argv.indexOf('--shots');
const shots = shotArg > 0 ? process.argv[shotArg + 1] : null;

const SCREENS = [
  ['scoreboard', '/scoreboard'], ['graph', '/graph'], ['incident', '/incident'],
  ['attackers', '/attackers'], ['metrics', '/metrics'], ['twin', '/digital-twin'],
  ['threat-radar', '/threat-radar'], ['overview', '/overview'],
  ['methodology', '/methodology'], ['threat-intel', '/threat-intel'],
  ['analyze', '/analyze'],
];

let failed = 0;
const problems = [];

const step = async (name, fn) => {
  try { await fn(); console.log(`  OK   ${name}`); }
  catch (e) {
    failed += 1;
    const msg = String(e).split('\n')[0].slice(0, 120);
    console.log(`  FAIL ${name} :: ${msg}`);
    problems.push(`${name}: ${msg}`);
  }
};

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await ctx.newPage();

// A page error or a console error is a failure, not a warning. The whole point
// of opening the browser is to see what the build cannot.
const runtime = [];
page.on('pageerror', (e) => runtime.push(`pageerror: ${String(e).slice(0, 140)}`));
page.on('console', (m) => {
  if (m.type() === 'error') runtime.push(`console: ${m.text().slice(0, 140)}`);
});

console.log(`demo path against ${base}`);

await step('login renders', async () => {
  await page.goto(`${base}/`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.getByRole('button', { name: /open the console/i }).waitFor({ timeout: 10000 });
});

await step('the notation legend is on the entry page', async () => {
  const text = await page.locator('body').innerText();
  for (const mark of ['Observed', 'Inferred', 'Disputed', 'Not measured']) {
    if (!text.includes(mark)) throw new Error(`legend is missing "${mark}"`);
  }
});

await step('enter the console', async () => {
  await page.getByRole('button', { name: /open the console/i }).click();
  await page.waitForURL('**/investigate', { timeout: 10000 });
});

await step('run an investigation', async () => {
  await page.getByRole('button', { name: /run investigation/i }).click();
  await page.waitForTimeout(7000);
});

await step('headline metrics rendered', async () => {
  const text = await page.locator('body').innerText();
  if (!/exposure|likelihood|confidence/i.test(text)) throw new Error('no headline metrics');
});

await step('the score says which scale it is on', async () => {
  const text = await page.locator('body').innerText();
  if (!/ranked-within-this-log|fixed-anchors/i.test(text)) {
    throw new Error('no calibration basis on screen: a bare score is an unqualified claim');
  }
});

if (shots) await page.screenshot({ path: `${shots}/investigate-run.png` });

for (const [name, path] of SCREENS) {
  await step(`screen ${name}`, async () => {
    await page.goto(base + path, { waitUntil: 'networkidle', timeout: 25000 });
    await page.waitForTimeout(900);
    const text = await page.locator('body').innerText();
    if (text.trim().length < 80) throw new Error('near-empty page');
    if (shots) await page.screenshot({ path: `${shots}/${name}.png` });
  });
}

await step('the theme toggle repaints', async () => {
  await page.getByRole('button', { name: /dark/i }).click();
  await page.waitForTimeout(600);
  const theme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  if (theme !== 'dark') throw new Error(`data-theme is ${theme}`);
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const [r, g, b] = bg.match(/\d+/g).map(Number);
  if (r + g + b > 240) throw new Error(`dark theme painted a light ground: ${bg}`);
  if (shots) await page.screenshot({ path: `${shots}/dark.png` });
});

await browser.close();

if (runtime.length) {
  failed += 1;
  console.log('\nruntime errors:');
  for (const r of [...new Set(runtime)]) console.log(`  ${r}`);
} else {
  console.log('\nno page or console errors across the whole path');
}

if (failed) {
  console.log(`\n${failed} failed step(s)`);
  process.exit(Math.min(failed, 125));
}
console.log('demo path is clean');
